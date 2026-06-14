"""
CyberCLI VAPT Scanner — Fixed Version
- Multiple SSL strategies (no verify, custom context, fallback)
- Increased timeouts with retry logic
- 404 filtering
- Confidence scoring on all findings
- Better error messages
"""
import asyncio, aiohttp, ssl, re, json, time, socket, logging, urllib.parse, html as html_lib
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger("cybercli.scanner")

# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class Finding:
    title: str
    severity: str
    confidence: str
    category: str
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""
    why_important: str = ""
    remediation: str = ""
    steps: List[str] = field(default_factory=list)
    cvss: float = 0.0
    cve: str = ""
    scanner: str = "active"
    ai_validated: bool = False
    ai_confidence: float = 0.0
    ai_analysis: str = ""
    false_positive: bool = False

    def to_dict(self):
        d = asdict(self)
        d['whyImportant'] = d.pop('why_important')
        return d

@dataclass
class Endpoint:
    path: str
    url: str
    method: str
    status: int
    content_type: str
    content_length: int
    params: List[str]
    issues: List[str]
    response_time: float
    headers: Dict[str, str] = field(default_factory=dict)
    body_snippet: str = ""

    def to_dict(self):
        return {
            "path": self.path, "url": self.url, "method": self.method,
            "status": self.status, "contentType": self.content_type,
            "contentLength": self.content_length, "params": self.params,
            "issues": self.issues, "responseTime": round(self.response_time, 3)
        }

@dataclass
class ScanResult:
    target: str; domain: str; start_time: str; end_time: str
    duration: str; total_requests: int
    findings: List[Finding]; endpoints: List[Endpoint]
    headers_analysis: List[dict]; graph: dict; stats: dict
    ai_provider: str = "none"

    def to_dict(self):
        return {
            "target": self.target, "domain": self.domain,
            "startTime": self.start_time, "endTime": self.end_time,
            "duration": self.duration, "totalRequests": self.total_requests,
            "findings": [f.to_dict() for f in self.findings],
            "endpoints": [e.to_dict() for e in self.endpoints],
            "graph": self.graph, "stats": self.stats, "aiProvider": self.ai_provider,
            "scanDate": self.start_time, "requests": self.total_requests,
        }

# ── SSL context factory — tries multiple strategies ───────────────────────────

def _make_ssl_ctx(verify=False):
    """Create SSL context. verify=False skips cert verification for pentest use."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    # Allow older TLS versions (some targets still use TLS 1.0/1.1)
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except Exception:
        pass
    return ctx

def _make_connector(timeout_sec: int, threads: int) -> aiohttp.TCPConnector:
    return aiohttp.TCPConnector(
        ssl=_make_ssl_ctx(verify=False),
        limit=threads,
        limit_per_host=4,
        enable_cleanup_closed=True,
        ttl_dns_cache=300,
        force_close=False,
    )

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

COMMON_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/login", "/signin", "/admin", "/administrator", "/admin/login",
    "/api", "/api/v1", "/api/v2", "/api/v3", "/graphql",
    "/users", "/user", "/profile", "/account", "/me",
    "/dashboard", "/panel", "/portal", "/console",
    "/health", "/status", "/ping", "/version", "/info",
    "/config", "/settings", "/.env", "/.env.local", "/.env.production",
    "/.git/config", "/.git/HEAD", "/backup", "/backup.zip",
    "/uploads", "/files", "/static", "/assets", "/media",
    "/wp-admin", "/wp-login.php", "/wp-config.php",
    "/phpinfo.php", "/info.php", "/test.php",
    "/server-status", "/server-info",
    "/actuator", "/actuator/health", "/actuator/env",
    "/swagger-ui.html", "/swagger-ui/", "/api-docs", "/openapi.json",
    "/debug", "/trace", "/metrics", "/.htaccess", "/.htpasswd",
]

SENSITIVE_PATHS = ['.env', '.git', 'phpinfo', 'server-status',
                   'actuator/env', 'backup', '.htaccess', 'wp-config']


class VAPTScanner:
    def __init__(self, target, on_log=None, on_finding=None, on_progress=None,
                 timeout=15, threads=10, filter_404=True):
        if not target.startswith("http"):
            target = "https://" + target
        self.target      = target.rstrip("/")
        self.domain      = urllib.parse.urlparse(target).hostname or target
        self.on_log      = on_log      or (lambda m, l="info": None)
        self.on_finding  = on_finding  or (lambda f: None)
        self.on_progress = on_progress or (lambda p, l: None)
        self.timeout     = timeout
        self.threads     = threads
        self.filter_404  = filter_404

        self.findings:  List[Finding]  = []
        self.endpoints: List[Endpoint] = []
        self._req_count  = 0
        self._session: Optional[aiohttp.ClientSession] = None
        self._main_headers: dict = {}
        self._main_body: str = ""
        self._connected = False  # Track if we actually reached the target

    def log(self, msg, level="info"):
        self.on_log(msg, level)

    def add_finding(self, f: Finding):
        self.findings.append(f)
        self.on_finding(f)

    # ── HTTP helper with retry ────────────────────────────────────────────────

    async def _get(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """GET with retry on timeout, trying different SSL strategies."""
        strategies = [
            {"ssl": _make_ssl_ctx(verify=False)},
            {"ssl": False},  # Completely skip SSL verification
        ]
        for attempt, ssl_opts in enumerate(strategies):
            try:
                to = aiohttp.ClientTimeout(
                    total=self.timeout,
                    connect=min(8, self.timeout//2),
                    sock_read=self.timeout
                )
                resp = await self._session.get(
                    url,
                    timeout=to,
                    allow_redirects=False,
                    **ssl_opts,
                    **{k: v for k, v in kwargs.items() if k not in ssl_opts}
                )
                self._req_count += 1
                self._connected = True
                return resp
            except asyncio.TimeoutError:
                if attempt == 0:
                    self.log(f"  [!] Timeout on {url[:60]} — retrying...", "dim")
                else:
                    self.log(f"  [!] Connection timeout: {url[:60]}", "warn")
            except aiohttp.ClientConnectorError as e:
                self.log(f"  [!] Cannot connect: {url[:50]} — {str(e)[:80]}", "warn")
                break
            except aiohttp.ClientSSLError as e:
                if attempt == 0:
                    self.log(f"  [!] SSL error on {url[:50]}, retrying without verify...", "dim")
                    continue
                self.log(f"  [!] SSL failed: {str(e)[:80]}", "warn")
                break
            except Exception as e:
                self.log(f"  [!] Request error: {str(e)[:100]}", "warn")
                break
        return None

    async def _post(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        try:
            to = aiohttp.ClientTimeout(total=self.timeout, connect=min(8, self.timeout//2))
            resp = await self._session.post(url, timeout=to, ssl=False,
                                            allow_redirects=False, **kwargs)
            self._req_count += 1
            return resp
        except Exception:
            return None

    # ── Main run ─────────────────────────────────────────────────────────────

    async def run(self) -> ScanResult:
        t0 = time.time()
        start_str = datetime.utcnow().isoformat()

        conn = _make_connector(self.timeout, self.threads)
        hdrs = {
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

        async with aiohttp.ClientSession(connector=conn, headers=hdrs) as session:
            self._session = session

            # Phase 1: Discovery
            self.on_progress(5, "Phase 1/6")
            self.log(f"[⬡] CyberCLI VAPT Engine v1.0", "info")
            self.log(f"[⬡] Target: {self.target}", "info")
            await self._phase_discovery()

            # Phase 2: Passive
            self.on_progress(28, "Phase 2/6")
            await self._phase_passive()

            # Phase 3: SSL
            self.on_progress(44, "Phase 3/6")
            await self._phase_ssl()

            # Phase 4: Active
            self.on_progress(55, "Phase 4/6")
            await self._phase_active()

            # Phase 5: Info
            self.on_progress(82, "Phase 5/6")
            await self._phase_info()

        self.on_progress(92, "Phase 6/6")

        # Filter out 404 endpoints unless --no-filter
        visible_endpoints = self.endpoints
        if self.filter_404:
            visible_endpoints = [e for e in self.endpoints if e.status != 404]

        dur = f"{time.time()-t0:.1f}s"
        sv = lambda s: sum(1 for f in self.findings if f.severity == s)
        stats = {
            "critical": sv("Critical"), "high": sv("High"),
            "medium": sv("Medium"), "low": sv("Low"),
            "info": sv("Informational"), "total": len(self.findings),
            "endpoints": len(visible_endpoints), "requests": self._req_count,
            "duration": dur, "aiValidated": False,
            "connected": self._connected,
        }

        return ScanResult(
            target=self.target, domain=self.domain,
            start_time=start_str, end_time=datetime.utcnow().isoformat(),
            duration=dur, total_requests=self._req_count,
            findings=self.findings, endpoints=visible_endpoints,
            headers_analysis=[], graph=self._build_graph(), stats=stats,
        )

    # ── Phase 1: Discovery ────────────────────────────────────────────────────

    async def _phase_discovery(self):
        self.log("[*] Phase 1: Endpoint discovery...", "white")
        sem = asyncio.Semaphore(self.threads)

        async def probe(path):
            url = self.target + path
            async with sem:
                t0 = time.time()
                resp = await self._get(url)
                if resp is None:
                    return
                elapsed = time.time() - t0
                try:
                    body = await resp.content.read(8192)
                except Exception:
                    body = b""
                body_str = body.decode("utf-8", "ignore")
                ct = resp.headers.get("Content-Type", "")
                params = self._extract_params(path)
                issues = self._quick_issues(path, resp.status, body_str, ct)

                ep = Endpoint(
                    path=path, url=url, method="GET", status=resp.status,
                    content_type=ct.split(";")[0].strip(),
                    content_length=int(resp.headers.get("Content-Length", len(body))),
                    params=params, issues=issues, response_time=round(elapsed, 3),
                    headers=dict(resp.headers), body_snippet=body_str[:600],
                )
                self.endpoints.append(ep)

                # Store main page headers
                if path == "/" and resp.status == 200:
                    self._main_headers = dict(resp.headers)
                    self._main_body    = body_str

                # Log only non-404s
                if resp.status != 404:
                    lv = "ok" if resp.status < 400 else "warn" if resp.status < 500 else "crit"
                    self.log(f"  {'✓' if resp.status < 400 else '→'} [{resp.status}] {path}", lv)

                # Flag sensitive exposures immediately
                if resp.status == 200 and any(s in path.lower() for s in SENSITIVE_PATHS):
                    self._flag_sensitive(path, url, body_str)

        tasks = [probe(p) for p in COMMON_PATHS]
        await asyncio.gather(*tasks, return_exceptions=True)
        await self._spider_links()

        visible = [e for e in self.endpoints if e.status != 404]
        total   = len(self.endpoints)
        self.log(f"[✓] Discovery: {len(visible)} reachable endpoints found ({total} probed)", "ok")

    def _quick_issues(self, path, status, body, ct):
        issues = []; pl = path.lower()
        if status == 200:
            if any(x in pl for x in ['.env', '.git', 'phpinfo', 'server-status', 'actuator/env']):
                issues.append("⚠ SENSITIVE EXPOSURE")
            if 'login' in pl or 'signin' in pl:
                issues.append("Auth endpoint")
            if 'admin' in pl:
                issues.append("Admin panel")
            if 'graphql' in pl:
                issues.append("GraphQL endpoint")
            if 'swagger' in pl or 'api-docs' in pl:
                issues.append("API docs exposed")
            if any(x in body.lower() for x in ['traceback', 'exception', 'fatal error', 'stack trace']):
                issues.append("Error disclosure")
        if status in (301, 302):
            issues.append("Redirect")
        return issues

    def _extract_params(self, path):
        params = []
        if "?" in path:
            qs = path.split("?", 1)[1]
            params = [p.split("=")[0] for p in qs.split("&") if "=" in p]
        for p in ["id", "q", "search", "user", "file", "url", "redirect", "page", "name"]:
            if p in path.lower() and p not in params:
                params.append(p)
                break
        return params[:6]

    def _flag_sensitive(self, path, url, body):
        SENS = {
            '.env':          ("Environment File Exposed (.env)", "Critical", 9.8,
                              "Contains DB passwords, API keys, secrets in plaintext. Full application takeover.",
                              "Remove from web root immediately. Use server environment variables."),
            '.git':          ("Git Repository Exposed (.git/config)", "Critical", 9.1,
                              "Full source code downloadable including hard-coded credentials.",
                              "Block .git via web server config: location /.git { deny all; }"),
            'phpinfo':       ("phpinfo() Exposed", "High", 7.5,
                              "Reveals PHP version, server paths, loaded modules, env vars.",
                              "Remove phpinfo() from production. Restrict to localhost."),
            'server-status': ("Apache Server-Status Exposed", "Medium", 5.3,
                              "Reveals active connections, request URIs, client IPs.",
                              "Restrict: Allow from 127.0.0.1 only."),
            'actuator':      ("Spring Boot Actuator Exposed", "High", 8.2,
                              "Exposes environment variables, beans, can reveal secrets.",
                              "Secure actuator endpoints. Require auth for all except /health."),
            'backup':        ("Backup File Accessible", "High", 7.8,
                              "May contain database dumps, source code with credentials.",
                              "Remove all backup files from web root."),
        }
        for key, (title, sev, cvss, why, fix) in SENS.items():
            if key in path.lower():
                self.add_finding(Finding(
                    title=title, severity=sev, confidence="High",
                    category="Info Disclosure", url=url, parameter=path,
                    evidence=f"HTTP 200 at {url}" + (f"\n{body[:150]}" if body else ""),
                    description=f"The resource '{path}' is publicly accessible.",
                    why_important=why, remediation=fix,
                    steps=["Block in web server config immediately",
                           "Move sensitive files outside web root",
                           "Audit entire web root for similar exposures",
                           "Rotate any exposed credentials immediately"],
                    cvss=cvss, scanner="passive"))
                break

    async def _spider_links(self):
        """Extract links from main page HTML and probe them."""
        if not self._main_body:
            # Try fetching main page separately
            resp = await self._get(self.target)
            if resp:
                try:
                    self._main_headers = dict(resp.headers)
                    self._main_body    = await resp.text(errors="ignore")
                except Exception:
                    return

        if not self._main_body:
            return

        found = set()
        for pat in [r'href=["\']([^"\'#>]+)["\']', r'action=["\']([^"\'#>]+)["\']',
                    r'["\'](/api/[^"\']{1,80})["\']', r'["\'](/v\d/[^"\']{1,80})["\']']:
            for m in re.finditer(pat, self._main_body, re.I):
                href = m.group(1)
                if href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                    continue
                if href.startswith("http"):
                    if self.domain not in href:
                        continue
                    path = "/" + "/".join(href.split("/")[3:])
                else:
                    path = href if href.startswith("/") else "/" + href
                path = path.split("?")[0].split("#")[0][:120]
                if path and path not in [e.path for e in self.endpoints]:
                    found.add(path)

        if found:
            self.log(f"  → Spidered {len(found)} additional links from HTML", "dim")
            sem = asyncio.Semaphore(5)
            tasks = []
            for p in list(found)[:25]:
                async def _probe(path=p):
                    url = self.target + path
                    async with sem:
                        resp = await self._get(url)
                        if not resp:
                            return
                        try:
                            body = await resp.content.read(4096)
                        except Exception:
                            body = b""
                        body_str = body.decode("utf-8", "ignore")
                        ct = resp.headers.get("Content-Type", "")
                        ep = Endpoint(
                            path=path, url=url, method="GET", status=resp.status,
                            content_type=ct.split(";")[0].strip(),
                            content_length=len(body), params=self._extract_params(path),
                            issues=self._quick_issues(path, resp.status, body_str, ct),
                            response_time=0.0, headers=dict(resp.headers),
                            body_snippet=body_str[:600],
                        )
                        self.endpoints.append(ep)
                        if resp.status not in (404, 410):
                            lv = "ok" if resp.status < 400 else "dim"
                            self.log(f"  {'✓' if resp.status<400 else '→'} [{resp.status}] {path}", lv)
                tasks.append(_probe())
            await asyncio.gather(*tasks, return_exceptions=True)

    # ── Phase 2: Passive ──────────────────────────────────────────────────────

    async def _phase_passive(self):
        self.log("[*] Phase 2: Passive scan — headers, cookies, info disclosure...", "white")

        if not self._main_headers:
            self.log("  → Fetching main page for passive analysis...", "dim")
            resp = await self._get(self.target)
            if resp:
                try:
                    self._main_headers = dict(resp.headers)
                    self._main_body    = await resp.text(errors="ignore")
                    self.log(f"  ✓ Fetched main page ({len(self._main_body)} bytes)", "ok")
                except Exception as e:
                    self.log(f"  [!] Could not read response body: {e}", "warn")
            else:
                self.log("  [!] Cannot reach target for passive scan — check connectivity", "warn")
                self.log("      Try: curl -I " + self.target, "dim")
                return

        self._check_headers()
        self._check_cookies()
        self._check_body()
        found = len([f for f in self.findings if f.scanner == "passive"])
        self.log(f"[✓] Passive scan: {found} findings", "ok")

    def _check_headers(self):
        h = lambda k: self._main_headers.get(k, self._main_headers.get(k.lower(), ""))

        CHECKS = [
            ("Strict-Transport-Security", "Medium", 5.4,
             "Without HSTS, browsers allow HTTP. Network attackers capture all traffic "
             "in plaintext — stealing sessions, credentials, personal data.",
             "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
             ["Add to web server config",
              "Set max-age=31536000 (1 year minimum)",
              "Add includeSubDomains if all subdomains use HTTPS",
              "Submit to HSTS preload list: hstspreload.org"]),

            ("Content-Security-Policy", "Medium", 6.1,
             "Without CSP, any XSS attack executes unrestricted — stealing cookies, "
             "impersonating users, logging keystrokes, redirecting to phishing.",
             "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
             ["Start with CSP-Report-Only header to audit violations",
              "Define all directives explicitly (script-src, style-src, img-src)",
              "Use nonces for inline scripts instead of unsafe-inline",
              "Test with Google CSP Evaluator"]),

            ("X-Frame-Options", "Low", 4.3,
             "Without frame protection attackers embed your pages in hidden iframes, "
             "tricking users into clicking invisible elements (clickjacking).",
             "X-Frame-Options: DENY",
             ["Add X-Frame-Options: DENY to server config",
              "Or use: Content-Security-Policy: frame-ancestors 'none'",
              "Test: embed page in <iframe> on another domain — should fail"]),

            ("X-Content-Type-Options", "Low", 3.1,
             "Browsers may MIME-sniff responses and execute uploaded files as scripts.",
             "X-Content-Type-Options: nosniff",
             ["Add nosniff to all responses",
              "Ensure correct Content-Type headers for all file types"]),

            ("Referrer-Policy", "Low", 2.4,
             "Sensitive URL tokens (reset links, session IDs) leak via Referer header "
             "to third-party analytics and external sites.",
             "Referrer-Policy: strict-origin-when-cross-origin",
             ["Add Referrer-Policy header",
              "Use no-referrer for pages with sensitive URL parameters"]),

            ("Permissions-Policy", "Low", 2.1,
             "Malicious iframe or XSS can access camera, microphone, "
             "geolocation without additional user permission.",
             "Permissions-Policy: geolocation=(), microphone=(), camera=()",
             ["List only APIs your app actually needs",
              "Deny all others explicitly"]),
        ]

        for hdr, sev, cvss, why, fix, steps in CHECKS:
            val = h(hdr)
            if not val:
                self.add_finding(Finding(
                    title=f"Missing Security Header: {hdr}",
                    severity=sev, confidence="High",
                    category="Headers", url=self.target, parameter=hdr,
                    evidence=f"Header '{hdr}' not present in HTTP response",
                    description=f"The {hdr} security header is not configured. "
                                f"This is a simple server configuration fix with significant security impact.",
                    why_important=why,
                    remediation=f"Add to server config: {fix}",
                    steps=steps, cvss=cvss, scanner="passive"))
                self.log(f"  ✗ [Missing] {hdr}", "warn")
            else:
                # Check for weak values
                if hdr == "Content-Security-Policy":
                    if "unsafe-inline" in val:
                        self.add_finding(Finding(
                            title="CSP Contains 'unsafe-inline' — XSS Protection Bypassed",
                            severity="Medium", confidence="High",
                            category="Headers", url=self.target, parameter=hdr,
                            evidence=f"Content-Security-Policy: {val[:150]}",
                            description="'unsafe-inline' allows all inline JavaScript, "
                                        "defeating CSP's XSS protection.",
                            why_important="Any injected inline <script> tag executes freely despite CSP.",
                            remediation="Replace unsafe-inline with nonce-based approach.",
                            steps=["Generate random nonce per request",
                                   "Apply nonce to inline scripts",
                                   "Add nonce to CSP: script-src 'nonce-{value}'",
                                   "Remove unsafe-inline"],
                            cvss=5.4, scanner="passive"))
                self.log(f"  ✓ {hdr}: present", "ok")

        # Server / tech disclosure
        server = h("Server")
        if server and re.search(r'apache|nginx|iis|php|litespeed|\d+\.\d+', server, re.I):
            self.add_finding(Finding(
                title=f"Server Version Disclosure: {server}",
                severity="Low", confidence="High",
                category="Info Disclosure", url=self.target,
                parameter="Server", evidence=f"Server: {server}",
                description="Server header reveals technology and version.",
                why_important="Version info lets attackers find known CVEs for your exact software in seconds.",
                remediation="Suppress version in server config.",
                steps=["Nginx: server_tokens off;",
                       "Apache: ServerTokens Prod + ServerSignature Off",
                       "IIS: Add removeServerHeader=true in web.config",
                       "Verify with: curl -I " + self.target],
                cvss=3.1, scanner="passive"))

        xpb = h("X-Powered-By")
        if xpb:
            self.add_finding(Finding(
                title=f"Technology Disclosure via X-Powered-By: {xpb}",
                severity="Low", confidence="High",
                category="Info Disclosure", url=self.target,
                parameter="X-Powered-By", evidence=f"X-Powered-By: {xpb}",
                description="X-Powered-By reveals server-side framework and version.",
                why_important="Framework version enables targeted CVE exploitation.",
                remediation="Remove X-Powered-By header.",
                steps=["PHP: expose_php = Off in php.ini",
                       "Express.js: app.disable('x-powered-by')",
                       "ASP.NET: remove via customHeaders in web.config"],
                cvss=2.1, scanner="passive"))

    def _check_cookies(self):
        sc = self._main_headers.get("Set-Cookie",
             self._main_headers.get("set-cookie", ""))
        if not sc:
            return
        cookies = sc if isinstance(sc, list) else [sc]
        for cookie in cookies:
            name  = cookie.split("=")[0].strip()
            lower = cookie.lower()
            is_sensitive = any(k in name.lower() for k in
                               ["session", "auth", "token", "sid", "csrf", "jwt", "access", "refresh"])
            if not is_sensitive:
                continue

            if "secure" not in lower:
                self.add_finding(Finding(
                    title=f"Cookie Missing Secure Flag: {name}",
                    severity="Medium", confidence="High",
                    category="Cookies", url=self.target, parameter=name,
                    evidence=cookie[:150],
                    description=f"Cookie '{name}' transmitted over HTTP due to missing Secure flag.",
                    why_important="Cookie sent in plaintext over HTTP. "
                                  "Network attacker on same Wi-Fi captures it with Wireshark and hijacks session.",
                    remediation=f"Set-Cookie: {name}=value; Secure; HttpOnly; SameSite=Strict; Path=/",
                    steps=["Add Secure attribute", "Add HttpOnly attribute",
                           "Set SameSite=Strict",
                           "Verify in DevTools: Application → Cookies"],
                    cvss=5.4, scanner="passive"))

            if "httponly" not in lower:
                self.add_finding(Finding(
                    title=f"Cookie Missing HttpOnly Flag: {name}",
                    severity="Medium", confidence="High",
                    category="Cookies", url=self.target, parameter=name,
                    evidence=cookie[:150],
                    description=f"Cookie '{name}' accessible via document.cookie JavaScript API.",
                    why_important="Any XSS escalates instantly to session hijacking. "
                                  "Attacker runs: fetch('/steal?c='+document.cookie)",
                    remediation=f"Set-Cookie: {name}=value; HttpOnly; Secure; SameSite=Strict",
                    steps=["Add HttpOnly to all session cookies",
                           "Verify: DevTools → Cookies → HttpOnly column shows ✓"],
                    cvss=4.3, scanner="passive"))

            if "samesite" not in lower:
                self.add_finding(Finding(
                    title=f"Cookie Missing SameSite Attribute: {name}",
                    severity="Low", confidence="High",
                    category="Cookies", url=self.target, parameter=name,
                    evidence=cookie[:150],
                    description=f"Cookie '{name}' sent with cross-site requests enabling CSRF.",
                    why_important="Browser sends this cookie when victim visits malicious site "
                                  "that triggers requests to your API — CSRF attack.",
                    remediation="Add SameSite=Strict (or Lax for OAuth flows).",
                    steps=["SameSite=Strict: most secure, never cross-site",
                           "SameSite=Lax: safe for GET nav, compatible with OAuth"],
                    cvss=3.5, scanner="passive"))

    def _check_body(self):
        body = self._main_body
        if not body:
            return
        PATTERNS = [
            (r'Traceback \(most recent call last\)', "Python Stack Trace Exposed",      "Medium", 5.3),
            (r'Exception in thread\s+\w+',           "Java Stack Trace Exposed",         "Medium", 5.3),
            (r'Fatal error:.*on line \d+|Parse error:',  "PHP Error Exposed",            "Medium", 5.3),
            (r'ORA-\d{5}:',                          "Oracle DB Error Exposed",          "High",   6.8),
            (r'You have an error in your SQL|mysql_fetch|mysqli_num_rows',
                                                     "MySQL Error Exposed",              "High",   7.2),
            (r'Microsoft OLE DB|Unclosed quotation mark', "MSSQL Error Exposed",         "High",   7.2),
        ]
        for pat, title, sev, cvss in PATTERNS:
            m = re.search(pat, body, re.I)
            if m:
                self.add_finding(Finding(
                    title=title, severity=sev, confidence="High",
                    category="Info Disclosure", url=self.target,
                    parameter="Response Body", evidence=m.group()[:200],
                    description="Application error or stack trace visible in HTTP response.",
                    why_important="Stack traces reveal internal file paths, class names, "
                                  "DB structure. Maps app internals for attackers.",
                    remediation="Show generic error pages in production. Log details server-side only.",
                    steps=["PHP: display_errors = Off",
                           "Return generic 500 page from catch blocks",
                           "Log to server log, never to HTTP response"],
                    cvss=cvss, scanner="passive"))

        ip_m = re.search(
            r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
            r'|192\.168\.\d{1,3}\.\d{1,3})\b', body)
        if ip_m:
            self.add_finding(Finding(
                title=f"Internal IP Disclosed: {ip_m.group()}",
                severity="Low", confidence="Medium",
                category="Info Disclosure", url=self.target,
                parameter="Response Body", evidence=ip_m.group(),
                description="Private IP address visible in response.",
                why_important="Reveals internal network topology for lateral movement planning.",
                remediation="Remove internal IP references from code. Use DNS names instead.",
                steps=["Search codebase for hardcoded IPs",
                       "Replace with environment variables or service discovery"],
                cvss=3.1, scanner="passive"))

    # ── Phase 3: SSL ──────────────────────────────────────────────────────────

    async def _phase_ssl(self):
        self.log("[*] Phase 3: SSL/TLS analysis...", "white")

        if not self.target.startswith("https"):
            self.add_finding(Finding(
                title="Target Not Using HTTPS — All Traffic Plaintext",
                severity="High", confidence="High",
                category="SSL/TLS", url=self.target,
                evidence=f"Protocol: {self.target.split(':')[0].upper()}",
                description="Site serves content over unencrypted HTTP.",
                why_important="ALL data transmitted in plaintext — passwords, sessions, "
                              "personal info readable by any network observer with Wireshark.",
                remediation="Deploy TLS certificate and redirect HTTP→HTTPS.",
                steps=["Install cert: sudo certbot --nginx -d yourdomain.com",
                       "Configure HTTP→HTTPS 301 redirect",
                       "Enable HSTS after confirming HTTPS works",
                       "Verify: curl -I http://yourdomain.com — must return 301"],
                cvss=7.5, scanner="ssl"))
        else:
            # Check if HTTP also serves without redirect
            http_url = self.target.replace("https://", "http://")
            resp = await self._get(http_url)
            if resp and resp.status == 200:
                self.add_finding(Finding(
                    title="HTTP Accessible Without Redirect to HTTPS",
                    severity="Medium", confidence="High",
                    category="SSL/TLS", url=http_url,
                    evidence=f"HTTP {resp.status} returned — no redirect to HTTPS",
                    description="Site responds to HTTP requests without forcing HTTPS.",
                    why_important="Users on HTTP are exposed to network interception. "
                                  "HSTS is ineffective without a proper HTTP redirect first.",
                    remediation="Add permanent 301 redirect from HTTP to HTTPS.",
                    steps=["Nginx: return 301 https://$host$request_uri;",
                           "Apache: Redirect permanent / https://yourdomain.com/",
                           "Verify: curl -I http://" + self.domain],
                    cvss=5.3, scanner="ssl"))
                self.log("  ⚠ HTTP accessible without redirect", "warn")
            elif resp and resp.status in (301, 302):
                self.log("  ✓ HTTP correctly redirects to HTTPS", "ok")
            else:
                self.log("  ✓ HTTP not accessible (HTTPS only)", "ok")

        self.log("[✓] SSL/TLS analysis complete", "ok")

    # ── Phase 4: Active ───────────────────────────────────────────────────────

    async def _phase_active(self):
        self.log("[*] Phase 4: Active vulnerability scan...", "white")
        await asyncio.gather(
            self._test_cors(),
            self._test_xss(),
            self._test_sqli(),
            self._test_ssrf(),
            self._test_lfi(),
            self._test_open_redirect(),
            self._test_auth(),
            self._test_graphql(),
            return_exceptions=True)
        active_count = len([f for f in self.findings if f.scanner == "active"])
        self.log(f"[✓] Active scan: {active_count} findings", "ok")

    async def _test_cors(self):
        try:
            resp = await self._get(self.target, headers={"Origin": "https://evil-attacker.com"})
            if not resp:
                return
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "*":
                self.add_finding(Finding(
                    title="Permissive CORS: Access-Control-Allow-Origin: *",
                    severity="Medium", confidence="High",
                    category="CORS", url=self.target, parameter="ACAO Header",
                    payload="Origin: https://evil-attacker.com",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    description="Any origin can read cross-origin API responses.",
                    why_important="Any website can make authenticated API calls using victim's cookies "
                                  "and read all responses. Critical for authenticated endpoints.",
                    remediation="Replace * with explicit allowlist of trusted origins.",
                    steps=["Build explicit ALLOWED_ORIGINS set",
                           "Validate Origin header against set server-side",
                           "Never use * for authenticated endpoints"],
                    cvss=5.4, scanner="active"))
            if acao and acao != "*" and acac.lower() == "true" and "evil-attacker.com" in acao:
                self.add_finding(Finding(
                    title="CRITICAL CORS: Reflected Origin + Credentials Allowed",
                    severity="Critical", confidence="High",
                    category="CORS", url=self.target, parameter="ACAO+ACAC",
                    payload="Origin: https://evil-attacker.com",
                    evidence=f"ACAO: {acao}\nACAC: {acac}",
                    description="Server reflects any Origin with credentials=true — full CORS bypass.",
                    why_important="Attacker hosts malicious page. Victim visits. Page reads all victim's "
                                  "private API data using their session. Full account data exposure.",
                    remediation="Validate Origin against strict allowlist before reflecting.",
                    steps=["if (ALLOWED_ORIGINS.has(origin)) setHeader('ACAO', origin)",
                           "Never reflect Origin without validation",
                           "Set ACAC:true only for explicitly trusted origins"],
                    cvss=9.1, scanner="active"))
        except Exception as e:
            logger.debug(f"CORS test: {e}")

    async def _test_xss(self):
        PAYLOADS = [
            "<script>alert(document.domain)</script>",
            '"><img src=x onerror=alert(1)>',
            "<svg/onload=alert(1)>",
        ]
        for ep in [e for e in self.endpoints if e.params and e.status == 200][:8]:
            for param in ep.params[:2]:
                for payload in PAYLOADS[:2]:
                    try:
                        tu = f"{ep.url}?{param}={urllib.parse.quote(payload)}"
                        resp = await self._get(tu)
                        if not resp:
                            continue
                        ct   = resp.headers.get("Content-Type", "")
                        body = await resp.text(errors="ignore")
                        if ("text/html" in ct and payload in body
                                and html_lib.escape(payload) not in body):
                            self.add_finding(Finding(
                                title=f"Reflected XSS — Parameter '{param}' Unencoded",
                                severity="High", confidence="High",
                                category="XSS", url=ep.url, parameter=param,
                                payload=payload,
                                evidence="Payload reflected without HTML encoding in text/html response",
                                description=f"Parameter '{param}' reflects user input unencoded in HTML.",
                                why_important="XSS executes attacker JavaScript in victim's browser — "
                                              "steals cookies, hijacks accounts, logs keystrokes. OWASP Top 10 #3.",
                                remediation="HTML-encode all user output. Implement strict CSP.",
                                steps=["PHP: htmlspecialchars($val, ENT_QUOTES, 'UTF-8')",
                                       ".NET: HtmlEncoder.Default.Encode(value)",
                                       "Add Content-Security-Policy header",
                                       "Use DOMPurify for rich text"],
                                cvss=7.4, scanner="active"))
                            return
                    except Exception:
                        pass

    async def _test_sqli(self):
        PAYLOADS = [
            ("'",            ["sql syntax", "mysql", "ora-", "sqlstate",
                               "unclosed quotation", "invalid sql", "you have an error",
                               "pg_query", "warning.*mysql", "valid mysql"]),
            ("' OR '1'='1",  ["sql syntax", "mysql", "database error"]),
        ]
        for ep in [e for e in self.endpoints if e.params and e.status == 200][:8]:
            for param in ep.params[:2]:
                for payload, patterns in PAYLOADS:
                    try:
                        tu   = f"{ep.url}?{param}={urllib.parse.quote(payload)}"
                        t0   = time.time()
                        resp = await self._get(tu)
                        if not resp:
                            continue
                        body    = (await resp.text(errors="ignore")).lower()
                        elapsed = time.time() - t0
                        for pat in patterns:
                            if pat in body:
                                self.add_finding(Finding(
                                    title=f"SQL Injection (Error-Based) — Parameter '{param}'",
                                    severity="Critical", confidence="High",
                                    category="SQLi", url=ep.url, parameter=param,
                                    payload=payload,
                                    evidence=f"DB error pattern '{pat}' found in response",
                                    description=f"Parameter '{param}' is directly injected into SQL query.",
                                    why_important="SQLi is OWASP #1. Reads entire DB — all credentials, "
                                                  "PII, financial data. May enable OS command execution.",
                                    remediation="Use parameterized queries for ALL DB operations.",
                                    steps=["PHP PDO: $stmt=$pdo->prepare('SELECT * WHERE id=?'); $stmt->execute([$id])",
                                           "Python: cursor.execute('SELECT * WHERE id=%s', (id,))",
                                           "Use ORM (Hibernate, SQLAlchemy, Prisma)",
                                           "Least-privilege DB user — no FILE, no DROP"],
                                    cvss=9.8, cve="CWE-89", scanner="active"))
                                return
                    except Exception:
                        pass

    async def _test_ssrf(self):
        SSRF_TARGETS = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1/",
            "http://localhost/",
        ]
        for ep in self.endpoints:
            url_params = [p for p in ep.params
                          if any(k in p.lower() for k in
                                 ["url","uri","src","dest","redirect","callback","fetch","proxy","href"])]
            for param in url_params:
                for ssrf_target in SSRF_TARGETS:
                    try:
                        tu   = f"{ep.url}?{param}={urllib.parse.quote(ssrf_target)}"
                        resp = await self._get(tu)
                        if not resp:
                            continue
                        body = await resp.text(errors="ignore")
                        if any(x in body for x in ["ami-id","instance-id","security-credentials","iam"]):
                            self.add_finding(Finding(
                                title=f"SSRF — Cloud Metadata via '{param}'",
                                severity="Critical", confidence="High",
                                category="SSRF", url=ep.url, parameter=param,
                                payload=ssrf_target, evidence=body[:300],
                                description="Cloud metadata endpoint reachable via SSRF.",
                                why_important="IAM credentials exposed → full cloud account takeover. "
                                              "Read all S3, databases, snapshots.",
                                remediation="Block metadata IPs. Validate URLs against strict allowlist.",
                                steps=["AWS: Enable IMDSv2 (requires session token)",
                                       "Block 169.254.169.254 at WAF/security group",
                                       "Validate user-supplied URLs against allowlist"],
                                cvss=9.8, cve="CWE-918", scanner="active"))
                            return
                    except Exception:
                        pass

    async def _test_lfi(self):
        PAYLOADS = ["../../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd"]
        for ep in self.endpoints:
            file_params = [p for p in ep.params
                           if any(k in p.lower() for k in
                                  ["file","path","page","include","template","doc","read","view"])]
            for param in file_params:
                for payload in PAYLOADS:
                    try:
                        tu   = f"{ep.url}?{param}={urllib.parse.quote(payload)}"
                        resp = await self._get(tu)
                        if not resp:
                            continue
                        body = await resp.text(errors="ignore")
                        if "root:x:0:0" in body or "daemon:" in body:
                            self.add_finding(Finding(
                                title=f"Path Traversal/LFI — /etc/passwd Readable via '{param}'",
                                severity="Critical", confidence="High",
                                category="LFI", url=ep.url, parameter=param,
                                payload=payload, evidence=body[:250],
                                description="Path traversal confirmed — arbitrary file read.",
                                why_important="Reads any file the server user can access: SSH keys, "
                                              "DB configs, source code, /etc/shadow.",
                                remediation="Whitelist allowed files. Never use user input in file paths.",
                                steps=["Use realpath() and verify path starts within allowed dir",
                                       "Whitelist allowed file names",
                                       "Chroot the web process"],
                                cvss=9.1, cve="CWE-22", scanner="active"))
                            return
                    except Exception:
                        pass

    async def _test_open_redirect(self):
        for ep in self.endpoints:
            rd_params = [p for p in ep.params
                         if any(k in p.lower() for k in
                                ["redirect","return","next","goto","url","dest","back","ref","target"])]
            for param in rd_params:
                try:
                    tu   = f"{ep.url}?{param}={urllib.parse.quote('https://evil-attacker.com')}"
                    resp = await self._get(tu)
                    if not resp:
                        continue
                    loc = resp.headers.get("Location", "")
                    if "evil-attacker.com" in loc:
                        self.add_finding(Finding(
                            title=f"Open Redirect via '{param}'",
                            severity="Medium", confidence="High",
                            category="Open Redirect", url=ep.url, parameter=param,
                            payload="https://evil-attacker.com",
                            evidence=f"Location: {loc}",
                            description="Application redirects to arbitrary external URL.",
                            why_important="Phishing: victim trusts your domain URL, "
                                          "gets redirected to attacker fake login page.",
                            remediation="Validate redirect URLs against allowlist.",
                            steps=["Build allowlist of valid redirect destinations",
                                   "Use relative URLs for internal redirects only",
                                   "Reject any URL not on approved list"],
                            cvss=6.1, scanner="active"))
                except Exception:
                    pass

    async def _test_auth(self):
        login_eps = [e for e in self.endpoints
                     if any(x in e.path.lower() for x in ["/login", "/signin", "/auth/login"])
                     and e.status == 200]
        for ep in login_eps[:2]:
            try:
                blocked = False
                for i in range(6):
                    resp = await self._post(ep.url,
                                           data={"username":"admin","password":f"wrongpass{i}"})
                    if resp and resp.status in (429, 403):
                        blocked = True; break
                if not blocked:
                    self.add_finding(Finding(
                        title=f"No Rate Limiting on Login: {ep.path}",
                        severity="Medium", confidence="Medium",
                        category="Authentication", url=ep.url,
                        parameter="username/password",
                        payload="6 rapid POST requests — no throttle",
                        evidence="Sent 6 login attempts with no 429/lockout response",
                        description="Login endpoint allows unlimited password attempts.",
                        why_important="Automated tools test millions of passwords/minute. "
                                      "Top 1000 passwords crack most accounts. "
                                      "Credential stuffing attacks test leaked password lists.",
                        remediation="Rate limit: max 5 attempts per IP per 15 minutes.",
                        steps=["Add nginx: limit_req_zone / fail2ban",
                               "Implement account lockout after N failures",
                               "Add CAPTCHA after 3 failed attempts",
                               "Alert on >10 failed attempts per account"],
                        cvss=7.3, scanner="active"))
            except Exception:
                pass

    async def _test_graphql(self):
        gql_eps = [e for e in self.endpoints if "graphql" in e.path.lower() and e.status == 200]
        for ep in gql_eps[:1]:
            try:
                resp = await self._session.post(ep.url, json={"query":"{ __schema { types { name } } }"},
                                                ssl=False, timeout=aiohttp.ClientTimeout(total=self.timeout))
                if resp:
                    self._req_count += 1
                    body = await resp.text(errors="ignore")
                    if "__schema" in body and "types" in body:
                        self.add_finding(Finding(
                            title="GraphQL Introspection Enabled — Schema Exposed",
                            severity="Medium", confidence="High",
                            category="GraphQL", url=ep.url, parameter="query",
                            payload='{ __schema { types { name } } }',
                            evidence=body[:200],
                            description="GraphQL introspection returns complete API schema.",
                            why_important="Full schema exposes all queries, mutations, types. "
                                          "Attackers map entire API for IDOR and auth bypass.",
                            remediation="Disable introspection in production.",
                            steps=["Apollo: introspection: false in server config",
                                   "Use persisted queries for production",
                                   "Implement query allowlisting"],
                            cvss=5.3, scanner="active"))
            except Exception:
                pass

    # ── Phase 5: Info disclosure ──────────────────────────────────────────────

    async def _phase_info(self):
        self.log("[*] Phase 5: Information disclosure checks...", "white")
        exposed = [e for e in self.endpoints
                   if e.status == 200 and any(s in e.path.lower() for s in SENSITIVE_PATHS)]
        for ep in exposed:
            self.log(f"  ⚠ Sensitive exposed: {ep.path}", "crit")
        self.log("[✓] Info disclosure complete", "ok")

    # ── Attack graph ──────────────────────────────────────────────────────────

    def _build_graph(self):
        nodes = [
            {"id":"attacker","label":"Attacker","type":"attacker","x":50,"y":240},
            {"id":"internet","label":"Internet\n(Public)","type":"entry","x":200,"y":240},
            {"id":"target","label":self.domain,"type":"target","x":380,"y":240},
            {"id":"web","label":"Web Server","type":"service","x":560,"y":120},
            {"id":"api","label":"API Layer","type":"service","x":560,"y":240},
            {"id":"db","label":"Database","type":"service","x":560,"y":360},
            {"id":"admin","label":"Admin Panel","type":"danger","x":750,"y":80},
            {"id":"auth","label":"Auth Service","type":"service","x":750,"y":200},
            {"id":"cloud","label":"Cloud Storage","type":"service","x":750,"y":320},
            {"id":"internal","label":"Internal\nNetwork","type":"danger","x":750,"y":440},
        ]
        edges = [
            {"from":"attacker","to":"internet","label":"HTTP/HTTPS","type":"normal"},
            {"from":"internet","to":"target","label":"Reaches Target","type":"normal"},
            {"from":"target","to":"web","label":"Web Traffic","type":"normal"},
            {"from":"target","to":"api","label":"API Calls","type":"normal"},
            {"from":"api","to":"db","label":"DB Queries","type":"normal"},
            {"from":"web","to":"admin","label":"Admin Route","type":"warn"},
            {"from":"api","to":"auth","label":"Auth Checks","type":"normal"},
            {"from":"api","to":"cloud","label":"Storage","type":"normal"},
        ]
        cats = {f.category for f in self.findings}
        if "XSS"            in cats: edges.append({"from":"attacker","to":"web","label":"XSS Payload","type":"attack"})
        if "SQLi"           in cats: edges.append({"from":"api","to":"db","label":"SQLi → Dump DB","type":"attack"})
        if "SSRF"           in cats: edges.append({"from":"api","to":"internal","label":"SSRF → Internal","type":"attack"})
        if "Authentication" in cats: edges.append({"from":"attacker","to":"auth","label":"Brute Force","type":"attack"})
        if any(f.severity == "Critical" for f in self.findings):
            edges.append({"from":"attacker","to":"admin","label":"Privilege Escalation","type":"attack"})

        exposed = [e for e in self.endpoints if e.status == 200 and e.issues][:3]
        for i, ep in enumerate(exposed):
            nid = f"exp_{i}"
            nodes.append({"id":nid,"label":ep.path[:22],"type":"vuln","x":950,"y":80+i*130})
            edges.append({"from":"web","to":nid,"label":ep.issues[0][:18],"type":"attack"})

        return {"nodes":nodes,"edges":edges}
