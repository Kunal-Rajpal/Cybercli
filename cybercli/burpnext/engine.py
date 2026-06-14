"""BurpNext Engine v3 — Main WAPT Orchestrator"""
import asyncio, aiohttp, ssl, time, logging, urllib.parse, re, html as html_lib
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Callable, Set
from datetime import datetime

logger = logging.getLogger("burpnext.engine")

OWASP_MAP = {
    "SQLi":"A03:2021","XSS":"A03:2021","CMDi":"A03:2021",
    "SSRF":"A10:2021","IDOR":"A01:2021","Open Redirect":"A01:2021",
    "LFI":"A01:2021","JWT":"A07:2021","Authentication":"A07:2021",
    "CSRF":"A01:2021","Headers":"A05:2021","Cookies":"A05:2021",
    "SSL/TLS":"A02:2021","Info Disclosure":"A05:2021",
    "CORS":"A05:2021","GraphQL":"A05:2021",
}
OWASP_NAMES = {
    "A01:2021":"Broken Access Control","A02:2021":"Cryptographic Failures",
    "A03:2021":"Injection","A04:2021":"Insecure Design",
    "A05:2021":"Security Misconfiguration","A06:2021":"Vulnerable Components",
    "A07:2021":"Authentication Failures","A08:2021":"Software Integrity Failures",
    "A09:2021":"Logging Failures","A10:2021":"SSRF",
}
COMMON_PATHS = [
    "/","/robots.txt","/sitemap.xml","/.well-known/security.txt",
    "/login","/signin","/logout","/register","/signup","/forgot-password",
    "/admin","/administrator","/admin/login","/admin/dashboard",
    "/api","/api/v1","/api/v2","/api/v3",
    "/graphql","/graphiql","/playground",
    "/users","/user","/profile","/account","/me","/dashboard",
    "/health","/status","/ping","/version","/info",
    "/.env","/.env.local","/.env.production","/.git/config","/.git/HEAD",
    "/config","/settings","/backup","/backup.zip",
    "/phpinfo.php","/info.php","/test.php",
    "/server-status","/server-info","/.htaccess",
    "/actuator","/actuator/health","/actuator/env",
    "/swagger-ui.html","/swagger-ui/","/api-docs","/openapi.json","/v3/api-docs",
    "/debug","/trace","/metrics","/.htpasswd",
    "/phpmyadmin","/adminer.php","/wp-admin","/wp-login.php","/wp-config.php",
    "/about.aspx","/login.aspx","/default.aspx","/comments.aspx","/signup.aspx",
    "/upload","/uploads","/files","/documents","/media","/static","/assets",
    "/console","/panel","/portal","/cp",
]
SENSITIVE_KEYS = ['.env','.git','phpinfo','server-status','actuator/env',
                  'backup','phpmyadmin','adminer','.htaccess','wp-config']
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"

@dataclass
class Finding:
    title: str; severity: str; confidence: str; category: str
    url: str; method: str = "GET"; parameter: str = ""
    payload: str = ""; evidence: str = ""; description: str = ""
    why: str = ""; business_impact: str = ""; remediation: str = ""
    steps: List[str] = field(default_factory=list)
    cvss_score: float = 0.0; cwe: str = ""; owasp: str = ""; owasp_name: str = ""
    scanner: str = "active"; request_raw: str = ""
    ai_validated: bool = False; ai_confidence: float = 0.0
    ai_analysis: str = ""; ai_attack_scenario: str = ""; false_positive: bool = False
    def __post_init__(self):
        if not self.owasp:      self.owasp      = OWASP_MAP.get(self.category,"A05:2021")
        if not self.owasp_name: self.owasp_name = OWASP_NAMES.get(self.owasp,"Security Misconfiguration")
    def to_dict(self): return asdict(self)

@dataclass
class Endpoint:
    url: str; path: str; method: str; status: int
    content_type: str = ""; content_length: int = 0
    params: List[str] = field(default_factory=list)
    headers: Dict[str,str] = field(default_factory=dict)
    body_snippet: str = ""; response_time: float = 0.0
    source: str = "spider"; issues: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    def to_dict(self):
        return {"url":self.url,"path":self.path,"method":self.method,
                "status":self.status,"contentType":self.content_type,
                "contentLength":self.content_length,"params":self.params,
                "responseTime":round(self.response_time,3),"source":self.source,
                "issues":self.issues,"technologies":self.technologies}

@dataclass
class ScanResult:
    target: str; domain: str; start_time: str; end_time: str
    duration: str; total_requests: int
    findings: List[Finding]; endpoints: List[Endpoint]
    technologies: List[str]; js_endpoints: List[str]
    subdomains: List[str]; swagger_found: bool; graphql_found: bool
    websockets: List[str]; secrets_found: List[dict]
    comments_found: List[str]; emails_found: List[str]
    stats: dict; graph: dict
    ai_provider: str = "none"; exec_summary: str = ""; attack_chain: str = ""
    def to_dict(self):
        return {
            "target":self.target,"domain":self.domain,
            "scanDate":self.start_time,"startTime":self.start_time,
            "endTime":self.end_time,"duration":self.duration,
            "totalRequests":self.total_requests,"requests":self.total_requests,
            "findings":[f.to_dict() for f in self.findings],
            "endpoints":[e.to_dict() for e in self.endpoints],
            "technologies":self.technologies,"jsEndpoints":self.js_endpoints,
            "subdomains":self.subdomains,"swaggerFound":self.swagger_found,
            "graphqlFound":self.graphql_found,"websockets":self.websockets,
            "secretsFound":self.secrets_found,
            "commentsFound":self.comments_found,"emailsFound":self.emails_found,
            "stats":self.stats,"graph":self.graph,
            "aiProvider":self.ai_provider,"execSummary":self.exec_summary,
            "attackChain":self.attack_chain,
        }

def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try: ctx.minimum_version = ssl.TLSVersion.TLSv1
    except: pass
    return ctx

class BurpNextEngine:
    def __init__(self, target, on_log=None, on_finding=None, on_progress=None,
                 timeout=15, threads=12, filter_404=True, deep_scan=False):
        if not target.startswith("http"): target = "https://" + target
        self.target     = target.rstrip("/")
        self.domain     = urllib.parse.urlparse(target).hostname or target
        self.on_log     = on_log      or (lambda m,l="info": None)
        self.on_finding = on_finding  or (lambda f: None)
        self.on_progress= on_progress or (lambda p,l: None)
        self.timeout    = timeout; self.threads = threads
        self.filter_404 = filter_404; self.deep_scan = deep_scan
        self.findings:     List[Finding]  = []
        self.endpoints:    List[Endpoint] = []
        self.technologies: List[str]      = []
        self.js_endpoints: List[str]      = []
        self.subdomains:   List[str]      = []
        self.websockets:   List[str]      = []
        self.secrets:      List[dict]     = []
        self.comments:     List[str]      = []
        self.emails:       List[str]      = []
        self.swagger_found = False; self.graphql_found = False
        self._req_count = 0
        self._visited: Set[str] = set()
        self._session: Optional[aiohttp.ClientSession] = None
        self._main_headers: dict = {}
        self._main_body:    str  = ""
        self._fkeys: Set[str]    = set()
        self._active_timeout = min(6, max(4, timeout // 3))

    def log(self, msg, level="info"): self.on_log(msg, level)

    def add_finding(self, f: Finding):
        key = f"{f.title}|{f.url}|{f.parameter}"
        if key in self._fkeys: return
        self._fkeys.add(key)
        self.findings.append(f); self.on_finding(f)

    async def _get(self, url, headers=None, to=None):
        t = to or self.timeout
        for ssl_opt in [{"ssl":_ssl_ctx()},{"ssl":False}]:
            try:
                timeout = aiohttp.ClientTimeout(total=t, connect=min(5,t//2))
                resp = await self._session.get(url, timeout=timeout,
                    allow_redirects=True, headers=headers, **ssl_opt)
                self._req_count += 1; return resp
            except asyncio.TimeoutError: break
            except (aiohttp.ClientConnectorError, aiohttp.ClientSSLError):
                if not ssl_opt.get("ssl",True): break
                continue
            except Exception: break
        return None

    async def _post(self, url, data=None, json_data=None, headers=None, to=None):
        t = to or self.timeout
        try:
            timeout = aiohttp.ClientTimeout(total=t, connect=min(5,t//2))
            resp = await self._session.post(url, data=data, json=json_data,
                timeout=timeout, ssl=False, allow_redirects=False, headers=headers)
            self._req_count += 1; return resp
        except Exception: return None

    async def _read(self, r, limit=16384):
        try: return (await r.content.read(limit)).decode("utf-8","ignore")
        except: return ""

    async def _safe_get(self, url, headers=None):
        try:
            return await asyncio.wait_for(
                self._get(url, headers=headers, to=self._active_timeout),
                timeout=self._active_timeout+1)
        except Exception: return None

    async def run(self) -> ScanResult:
        t0 = time.time(); start = datetime.utcnow().isoformat()
        conn = aiohttp.TCPConnector(ssl=_ssl_ctx(), limit=self.threads,
                                    limit_per_host=5, ttl_dns_cache=300)
        to   = aiohttp.ClientTimeout(total=self.timeout, connect=min(8,self.timeout//2))
        self._session = aiohttp.ClientSession(connector=conn, timeout=to, headers={
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
        })
        try:
            self.on_progress(5,"Phase 1/8")
            self.log(f"[⬡] BurpNext v3 | Target: {self.target}", "info")
            await self._p1_spider()
            self.on_progress(18,"Phase 2/8"); await self._p2_js()
            self.on_progress(28,"Phase 3/8"); await self._p3_api()
            self.on_progress(38,"Phase 4/8"); await self._p4_passive()
            self.on_progress(52,"Phase 5/8")
            try:
                await asyncio.wait_for(self._p5_active(), timeout=120)
            except asyncio.TimeoutError:
                self.log("  [!] Active scan 120s cap reached — continuing","warn")
            self.on_progress(78,"Phase 6/8"); await self._p6_auth()
            self.on_progress(86,"Phase 7/8"); await self._p7_tech()
            self.on_progress(92,"Phase 8/8"); await self._p8_info()
        finally:
            await self._session.close()

        self.on_progress(95,"Report")
        dur  = f"{time.time()-t0:.1f}s"
        eps  = [e for e in self.endpoints if not self.filter_404 or e.status != 404]
        sv   = lambda s: sum(1 for f in self.findings if f.severity==s)
        stats = {
            "critical":sv("Critical"),"high":sv("High"),
            "medium":sv("Medium"),"low":sv("Low"),
            "info":sv("Informational"),"total":len(self.findings),
            "endpoints":len(eps),"requests":self._req_count,
            "duration":dur,"aiValidated":False,
            "jsEndpoints":len(self.js_endpoints),
            "technologies":len(self.technologies),
            "secrets":len(self.secrets),
        }
        return ScanResult(
            target=self.target, domain=self.domain,
            start_time=start, end_time=datetime.utcnow().isoformat(),
            duration=dur, total_requests=self._req_count,
            findings=self.findings, endpoints=eps,
            technologies=self.technologies, js_endpoints=self.js_endpoints,
            subdomains=self.subdomains, swagger_found=self.swagger_found,
            graphql_found=self.graphql_found, websockets=self.websockets,
            secrets_found=self.secrets, comments_found=self.comments,
            emails_found=self.emails, stats=stats, graph=self._build_graph(),
        )

    async def _p1_spider(self):
        self.log("[*] Phase 1: Spider & endpoint discovery...","white")
        sem = asyncio.Semaphore(self.threads)
        async def probe(path):
            url = self.target+path
            if url in self._visited: return
            self._visited.add(url)
            async with sem:
                t0=time.time(); resp=await self._get(url)
                if not resp: return
                elapsed=time.time()-t0
                body=await self._read(resp,8192)
                ct=resp.headers.get("Content-Type",""); status=resp.status
                if path=="/" or (not self._main_headers and status<400):
                    self._main_headers=dict(resp.headers); self._main_body=body
                params=self._get_params(path,body,ct)
                issues=self._get_issues(path,status,body)
                techs=self._detect_tech(dict(resp.headers),body)
                ep=Endpoint(url=url,path=path,method="GET",status=status,
                    content_type=ct.split(";")[0].strip(),
                    content_length=int(resp.headers.get("Content-Length",len(body))),
                    params=params,headers=dict(resp.headers),
                    body_snippet=body[:500],response_time=round(elapsed,3),
                    source="brute",issues=issues,technologies=techs)
                self.endpoints.append(ep)
                if status!=404:
                    icon="✓" if status<300 else "→" if status<400 else "⚠"
                    lv="ok" if status<300 else "warn" if status<500 else "crit"
                    self.log(f"  {icon} [{status}] {path}",lv)
                if status==200:
                    self._flag_sensitive(path,url,body)
                    if "text/html" in ct:
                        await self._spider_html(body,sem)
                        for m in re.finditer(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',body):
                            if m.group() not in self.emails: self.emails.append(m.group())
                        for m in re.finditer(r'<!--(.*?)-->',body,re.DOTALL):
                            c=m.group(1).strip()
                            if len(c)>10 and any(k in c.lower() for k in ["todo","fixme","password","secret","debug","vuln"]):
                                self.comments.append(c[:200])
        await asyncio.gather(*[probe(p) for p in COMMON_PATHS],return_exceptions=True)
        if not self._main_headers:
            resp=await self._get(self.target)
            if resp:
                self._main_headers=dict(resp.headers)
                self._main_body=await self._read(resp,32768)
                self.log(f"  ✓ Main page: {len(self._main_body)} bytes","ok")
        visible=[e for e in self.endpoints if e.status!=404]
        self.log(f"[✓] Discovery: {len(visible)} reachable / {len(self.endpoints)} probed","ok")

    async def _spider_html(self, html_body, sem):
        for pat in [r'href=["\']([^"\'#>?]{1,100})["\']',r'action=["\']([^"\'#>]{1,100})["\']']:
            for m in re.finditer(pat,html_body,re.I):
                href=m.group(1).strip()
                if href.startswith(("javascript:","mailto:","tel:","data:","#","http")): continue
                path=href if href.startswith("/") else "/"+href
                path=path.split("?")[0].split("#")[0][:120]
                if not path or len(path)>100: continue
                url=self.target+path
                if url in self._visited: continue
                self._visited.add(url)
                async with sem:
                    resp=await self._get(url)
                    if not resp: continue
                    body=await self._read(resp,4096)
                    ct=resp.headers.get("Content-Type","")
                    ep=Endpoint(url=url,path=path,method="GET",status=resp.status,
                        content_type=ct.split(";")[0].strip(),content_length=len(body),
                        params=self._get_params(path,body,ct),headers=dict(resp.headers),
                        body_snippet=body[:400],response_time=0.0,source="spider",
                        issues=self._get_issues(path,resp.status,body),
                        technologies=self._detect_tech(dict(resp.headers),body))
                    if url not in [e.url for e in self.endpoints]:
                        self.endpoints.append(ep)
                    if resp.status not in (404,410):
                        icon="✓" if resp.status<300 else "→"
                        self.log(f"  {icon} [{resp.status}] {path} [spider]","ok" if resp.status<300 else "dim")

    def _get_params(self, path, body="", ct=""):
        params=[]
        if "?" in path:
            qs=path.split("?",1)[1]
            params=[p.split("=")[0] for p in qs.split("&") if "=" in p]
        if body and "text/html" in ct:
            params.extend(re.findall(r'<input[^>]+name=["\']([^"\']+)["\']',body,re.I))
            params.extend(re.findall(r'<textarea[^>]+name=["\']([^"\']+)["\']',body,re.I))
            params.extend(re.findall(r'<select[^>]+name=["\']([^"\']+)["\']',body,re.I))
        for h in ["id","q","search","user","file","url","page","name","token","key","cat","type","filter","ref","redirect"]:
            if h in path.lower() and h not in params:
                params.append(h); break
        return list(dict.fromkeys(params))[:8]

    def _get_issues(self, path, status, body):
        issues=[]; pl=path.lower()
        if status==200:
            if any(x in pl for x in ['.env','.git','phpinfo','server-status','actuator/env']): issues.append("⚠ SENSITIVE EXPOSURE")
            if 'admin'   in pl: issues.append("Admin panel")
            if 'graphql' in pl: issues.append("GraphQL endpoint")
            if 'swagger' in pl: issues.append("API docs exposed")
            if body and any(x in body.lower() for x in ["sql syntax","traceback","fatal error"]): issues.append("Error disclosure")
        if status==403:         issues.append("Access denied — endpoint exists")
        if status==429:         issues.append("Rate limited — endpoint exists")
        if status in (301,302): issues.append("Redirect")
        return issues

    def _detect_tech(self, hdrs, body):
        techs=[]
        server=hdrs.get("Server",""); xpb=hdrs.get("X-Powered-By",""); b=body.lower() if body else ""
        for t in ["nginx","apache","iis","litespeed","caddy","gunicorn"]:
            if t in server.lower(): techs.append(t.capitalize())
        for t in ["php","asp.net","express","node","django","flask","rails","laravel"]:
            if t in xpb.lower(): techs.append(t.upper() if len(t)<=3 else t.capitalize())
        for kw,name in {"react":"React","angular":"Angular","vue.js":"Vue.js","jquery":"jQuery",
                        "next.js":"Next.js","bootstrap":"Bootstrap","tailwind":"Tailwind CSS",
                        "graphql":"GraphQL","socket.io":"Socket.IO","wordpress":"WordPress"}.items():
            if kw in b and name not in techs: techs.append(name)
        return list(set(techs))[:6]

    def _flag_sensitive(self, path, url, body):
        SENS={
            ".env":    ("Environment File Exposed (.env)","Critical",9.8,"Contains DB passwords, API keys. Complete app takeover.","Remove from web root."),
            ".git":    ("Git Repository Exposed (.git/)","Critical",9.1,"Full source code + credentials downloadable.","Block: location /.git { deny all; }"),
            "phpinfo": ("phpinfo() Exposed","High",7.5,"PHP version, paths, env vars.","Remove from production."),
            "actuator/env":("Spring Boot /env Exposed","Critical",9.4,"All env vars including DB passwords.","Require auth for actuator endpoints."),
            "phpmyadmin":("phpMyAdmin Exposed","High",8.5,"Direct DB access panel.","Restrict to localhost."),
            "backup":  ("Backup File Accessible","High",7.8,"May contain DB dump or credentials.","Remove from web root."),
        }
        for key,(title,sev,cvss,why,fix) in SENS.items():
            if key in path.lower():
                self.add_finding(Finding(
                    title=title,severity=sev,confidence="High",category="Info Disclosure",
                    url=url,parameter=path,evidence=f"HTTP 200 at {url}\n{body[:200]}",
                    description=f"'{path}' publicly accessible without authentication.",
                    why=why,business_impact="Credential exposure, full compromise.",
                    remediation=fix,steps=["Block immediately","Move outside web root","Rotate credentials"],
                    cvss_score=cvss,cwe="CWE-200",scanner="passive"))
                break

    async def _p2_js(self):
        self.log("[*] Phase 2: JavaScript endpoint extraction...","white")
        js_urls=[e.url for e in self.endpoints if e.status==200
                 and e.path.lower().endswith(".js") and "min" not in e.path.lower()][:15]
        if self._main_body:
            for m in re.finditer(r'src=["\']([^"\']+\.js[^"\']*)["\']',self._main_body,re.I):
                src=m.group(1)
                if src.startswith("http") and self.domain in src: js_urls.append(src)
                elif src.startswith("/"): js_urls.append(self.target+src)
        JS_PATS=[
            r'(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["\']([/][^"\']{2,100})["\']',
            r'(?:url|endpoint|api|path|route)\s*[=:]\s*["\']([/][a-zA-Z0-9/_\-\.]{3,80})["\']',
            r'["\']/(api|v\d+|graphql|rest|service)[/a-zA-Z0-9_\-\.]{1,60}["\']',
        ]
        SEC_PATS=[
            (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']{8,})["\']',"API Key"),
            (r'(?:password|secret)\s*=\s*["\']([^"\']{4,})["\']',"Hardcoded Secret"),
            (r'AKIA[0-9A-Z]{16}',"AWS Access Key"),
        ]
        found: Set[str]=set(); sem=asyncio.Semaphore(5)
        async def parse(js_url):
            async with sem:
                resp=await self._get(js_url,to=10)
                if not resp or resp.status!=200: return
                body=await self._read(resp,65536)
                for pat in JS_PATS:
                    for m in re.finditer(pat,body,re.I):
                        ep=m.group(1).split("?")[0].rstrip("/")
                        if ep.startswith("/") and 2<len(ep)<100 and ep not in found:
                            if not ep.endswith((".css",".png",".jpg",".gif",".svg",".ico")): found.add(ep)
                for pat,label in SEC_PATS:
                    for m in re.finditer(pat,body,re.I):
                        self.secrets.append({"type":label,"value":m.group(0)[:60]+"...","file":js_url})
        await asyncio.gather(*[parse(u) for u in list(set(js_urls))[:12]],return_exceptions=True)
        self.js_endpoints=list(found)
        for s in self.secrets:
            self.add_finding(Finding(
                title=f"Hardcoded {s['type']} in JavaScript",severity="Critical",confidence="High",
                category="Info Disclosure",url=s.get("file",""),evidence=s.get("value",""),
                description=f"Hardcoded {s['type']} in client-side JS — visible to everyone.",
                why="API keys visible in page source. Third-party service compromise.",
                business_impact="Credential exposure, third-party service takeover.",
                remediation="Move to server-side. Rotate exposed key immediately.",
                steps=["Move to backend","Rotate exposed key","Use env variables"],
                cvss_score=9.1,cwe="CWE-312",scanner="passive"))
        if self.js_endpoints: self.log(f"  → {len(self.js_endpoints)} JS endpoints, {len(self.secrets)} secrets","ok")
        self.log("[✓] JS analysis complete","ok")

    async def _p3_api(self):
        self.log("[*] Phase 3: API discovery (Swagger/GraphQL)...","white")
        for ep in self.endpoints:
            if any(p in ep.path.lower() for p in ["/swagger","/api-docs","/openapi.json","/v3/api-docs"]) and ep.status==200:
                self.swagger_found=True
                self.log(f"  ✓ Swagger: {ep.path}","ok")
                self.add_finding(Finding(
                    title="Swagger/OpenAPI Documentation Publicly Exposed",severity="Medium",confidence="High",
                    category="Info Disclosure",url=ep.url,evidence=f"Swagger at {ep.url}",
                    description="Complete API docs accessible without authentication.",
                    why="All endpoints, params, auth methods exposed. API attack surface mapped instantly.",
                    business_impact="Full API enumeration without any documentation.",
                    remediation="Restrict to authenticated users or internal IPs.",
                    steps=["Require auth for /swagger-ui","Restrict by IP","Disable in production"],
                    cvss_score=5.3,cwe="CWE-200",scanner="passive"))
                break
        gql=[e for e in self.endpoints if "graphql" in e.path.lower() and e.status==200]
        if gql:
            self.graphql_found=True
            resp=await self._post(gql[0].url,json_data={"query":"{ __schema { types { name } } }"},
                                  headers={"Content-Type":"application/json"},to=8)
            if resp:
                body=await self._read(resp)
                if "__schema" in body:
                    self.add_finding(Finding(
                        title="GraphQL Introspection Enabled — Full Schema Exposed",severity="Medium",
                        confidence="High",category="GraphQL",url=gql[0].url,method="POST",
                        payload='{"query":"{ __schema { types { name } } }"}',evidence=body[:300],
                        description="GraphQL introspection returns complete API schema.",
                        why="All queries/mutations/types exposed. Enables targeted IDOR and auth bypass.",
                        business_impact="Complete API enumeration without any docs.",
                        remediation="Disable introspection in production.",
                        steps=["Apollo: introspection:false","Implement query allowlisting"],
                        cvss_score=5.3,cwe="CWE-200",scanner="active"))
        self.log(f"[✓] API — Swagger:{self.swagger_found} GraphQL:{self.graphql_found}","ok")

    async def _p4_passive(self):
        self.log("[*] Phase 4: Passive scan — headers, cookies, JWT...","white")
        if not self._main_headers:
            resp=await self._get(self.target)
            if resp:
                self._main_headers=dict(resp.headers)
                self._main_body=await self._read(resp,32768)
                self.log(f"  ✓ Main page fetched ({len(self._main_body)} bytes)","ok")
            else:
                self.log("  [!] Cannot reach target","warn"); return
        h=lambda k: self._main_headers.get(k,self._main_headers.get(k.lower(),""))
        for hdr,sev,cvss,cwe,why,fix,steps in [
            ("Strict-Transport-Security","Medium",5.4,"CWE-319",
             "Without HSTS browsers allow HTTP. MITM attacker captures ALL traffic — passwords, sessions, PII.",
             "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
             ["Add to server config","Set max-age=31536000","Submit to hstspreload.org"]),
            ("Content-Security-Policy","Medium",6.1,"CWE-1021",
             "No CSP = unrestricted JavaScript. Any XSS runs with full page trust — cookie theft, keyloggers.",
             "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
             ["Audit content sources","Use nonces for inline scripts","Start with CSP-Report-Only"]),
            ("X-Frame-Options","Low",4.3,"CWE-1021",
             "Pages embeddable in iframes. Clickjacking: invisible buttons trick users.",
             "X-Frame-Options: DENY",["Add DENY","Or: CSP frame-ancestors 'none'"]),
            ("X-Content-Type-Options","Low",3.1,"CWE-430",
             "MIME sniffing may execute uploaded files as scripts.",
             "X-Content-Type-Options: nosniff",["Add nosniff to all responses"]),
            ("Referrer-Policy","Low",2.4,"CWE-200",
             "URL tokens leak via Referer to analytics/CDN.",
             "Referrer-Policy: strict-origin-when-cross-origin",["Add to all responses"]),
            ("Permissions-Policy","Low",2.1,"CWE-693",
             "XSS/iframes access camera/mic/geolocation without permission.",
             "Permissions-Policy: geolocation=(), microphone=(), camera=()",
             ["Deny all APIs not needed"]),
        ]:
            val=h(hdr)
            if not val:
                self.add_finding(Finding(
                    title=f"Missing Security Header: {hdr}",severity=sev,confidence="High",
                    category="Headers",url=self.target,parameter=hdr,
                    evidence=f"Header '{hdr}' absent from HTTP response",
                    description=f"{hdr} not configured.",
                    why=why,business_impact="Increases attack surface.",
                    remediation=f"Add: {fix}",steps=steps,
                    cvss_score=cvss,cwe=cwe,owasp="A05:2021",scanner="passive"))
                self.log(f"  ✗ [Missing] {hdr}","warn")
            else:
                if hdr=="Content-Security-Policy":
                    if "unsafe-inline" in val:
                        self.add_finding(Finding(
                            title="CSP: 'unsafe-inline' Permits Inline Script Execution",
                            severity="Medium",confidence="High",category="Headers",
                            url=self.target,parameter=hdr,evidence=f"CSP: {val[:150]}",
                            description="unsafe-inline allows inline JS, defeating XSS protection.",
                            why="Injected scripts execute despite CSP.",
                            business_impact="XSS attacks work even with CSP enabled.",
                            remediation="Replace unsafe-inline with nonces.",
                            steps=["Generate nonce per request","Remove unsafe-inline"],
                            cvss_score=5.4,cwe="CWE-1021",owasp="A05:2021",scanner="passive"))
                    if "unsafe-eval" in val:
                        self.add_finding(Finding(
                            title="CSP: 'unsafe-eval' Allows eval() Execution",
                            severity="High",confidence="High",category="Headers",
                            url=self.target,parameter=hdr,evidence=f"CSP: {val[:150]}",
                            description="unsafe-eval permits eval() and Function() execution.",
                            why="eval() executes attacker-controlled strings as code.",
                            business_impact="XSS via eval() bypasses CSP.",
                            remediation="Remove unsafe-eval.",
                            steps=["Remove unsafe-eval","Replace eval() with JSON.parse()"],
                            cvss_score=6.5,cwe="CWE-95",owasp="A05:2021",scanner="passive"))
                self.log(f"  ✓ {hdr}: present","ok")
        server=h("Server")
        if server and re.search(r'\d+\.\d+|apache|nginx|iis|php|litespeed',server,re.I):
            self.add_finding(Finding(
                title=f"Server Version Disclosure: {server}",severity="Low",confidence="High",
                category="Info Disclosure",url=self.target,parameter="Server",
                evidence=f"Server: {server}",description="Server header reveals version.",
                why="Enables targeted CVE exploitation.",business_impact="Targeted CVE attacks.",
                remediation="Suppress: server_tokens off;",
                steps=["Nginx: server_tokens off","Apache: ServerTokens Prod"],
                cvss_score=3.1,cwe="CWE-200",scanner="passive"))
        xpb=h("X-Powered-By")
        if xpb:
            self.add_finding(Finding(
                title=f"Framework Disclosure: X-Powered-By: {xpb}",severity="Low",confidence="High",
                category="Info Disclosure",url=self.target,parameter="X-Powered-By",
                evidence=f"X-Powered-By: {xpb}",description="Framework version disclosed.",
                why="Framework-specific CVEs targeted directly.",business_impact="Framework exploitation.",
                remediation="Remove X-Powered-By.",
                steps=["PHP: expose_php=Off","Express: app.disable('x-powered-by')"],
                cvss_score=2.1,cwe="CWE-200",scanner="passive"))
        sc_raw=self._main_headers.get("Set-Cookie",self._main_headers.get("set-cookie",""))
        if sc_raw:
            cookies=sc_raw if isinstance(sc_raw,list) else [sc_raw]
            for cookie in cookies:
                name=cookie.split("=")[0].strip(); lower=cookie.lower()
                if not any(k in name.lower() for k in ["session","auth","token","sid","csrf","jwt","access","refresh"]): continue
                for flag,title,sev,cvss,cwe,why,fix in [
                    ("secure",f"Cookie Missing Secure Flag: {name}","Medium",5.4,"CWE-614",
                     "Cookie sent in plaintext. Network attacker captures → session hijack.",
                     f"Set-Cookie: {name}=value; Secure; HttpOnly; SameSite=Strict"),
                    ("httponly",f"Cookie Missing HttpOnly Flag: {name}","Medium",4.3,"CWE-1004",
                     "Cookie readable via document.cookie. Any XSS escalates to hijack.",
                     f"Set-Cookie: {name}=value; HttpOnly; Secure; SameSite=Strict"),
                    ("samesite",f"Cookie Missing SameSite: {name}","Low",3.5,"CWE-352",
                     "Cookie sent on cross-site requests — CSRF possible.",
                     "Add SameSite=Strict"),
                ]:
                    if flag not in lower:
                        self.add_finding(Finding(
                            title=title,severity=sev,confidence="High",category="Cookies",
                            url=self.target,parameter=name,evidence=cookie[:150],
                            description=f"Cookie '{name}' missing {flag.capitalize()}.",
                            why=why,business_impact="Session theft or CSRF possible.",
                            remediation=fix,steps=[f"Add {flag.capitalize()} to Set-Cookie"],
                            cvss_score=cvss,cwe=cwe,scanner="passive"))
        if not self.target.startswith("https"):
            self.add_finding(Finding(
                title="Target Not Using HTTPS — All Traffic Plaintext",severity="High",
                confidence="High",category="SSL/TLS",url=self.target,evidence="Protocol: HTTP",
                description="Site served over unencrypted HTTP.",
                why="All data readable by any network observer.",
                business_impact="Complete traffic interception.",
                remediation="Deploy TLS and redirect HTTP→HTTPS.",
                steps=["certbot --nginx -d yourdomain.com","Add 301 redirect","Enable HSTS"],
                cvss_score=7.5,cwe="CWE-319",scanner="ssl"))
        if self._main_body:
            for pat,title,sev,cvss in [
                (r'Traceback \(most recent call last\)',"Python Stack Trace Exposed","Medium",5.3),
                (r'Fatal error:.*on line \d+',"PHP Error Exposed","Medium",5.3),
                (r'You have an error in your SQL syntax',"MySQL Error Exposed","High",7.2),
                (r'ORA-\d{5}:',"Oracle Error Exposed","High",6.8),
                (r'Microsoft OLE DB',"MSSQL Error Exposed","High",7.2),
            ]:
                m=re.search(pat,self._main_body,re.I)
                if m:
                    self.add_finding(Finding(
                        title=title,severity=sev,confidence="High",category="Info Disclosure",
                        url=self.target,evidence=m.group()[:200],
                        description="Error/stack trace visible in HTTP response.",
                        why="Reveals internal paths, class names, DB schema.",
                        business_impact="Aids targeted attack development.",
                        remediation="Show generic error pages. Log server-side only.",
                        steps=["display_errors=Off","Return generic 500","Log server-side"],
                        cvss_score=cvss,cwe="CWE-209",scanner="passive"))
        self.log(f"[✓] Passive: {len([f for f in self.findings if f.scanner=='passive'])} findings","ok")

    async def _p5_active(self):
        self.log("[*] Phase 5: Active OWASP Top 10 scan...","white")
        try:
            resp=await self._safe_get(self.target,headers={"Origin":"https://evil-attacker.com"})
            if resp:
                acao=resp.headers.get("Access-Control-Allow-Origin","")
                acac=resp.headers.get("Access-Control-Allow-Credentials","")
                if acao=="*":
                    self.add_finding(Finding(
                        title="CORS: Wildcard Origin — Any Site Can Read API Responses",
                        severity="Medium",confidence="High",category="CORS",url=self.target,
                        payload="Origin: https://evil-attacker.com",
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        description="Wildcard CORS — any website reads API responses.",
                        why="Malicious site makes authenticated requests and reads all data.",
                        business_impact="All API data readable by attacker-controlled sites.",
                        remediation="Replace * with explicit trusted origins.",
                        steps=["Build ALLOWED_ORIGINS","Validate origin server-side"],
                        cvss_score=5.4,cwe="CWE-942",owasp="A05:2021",scanner="active"))
                if acao and acac.lower()=="true" and "evil-attacker.com" in acao:
                    self.add_finding(Finding(
                        title="CORS: Reflected Origin + Credentials — Authenticated Data Theft",
                        severity="Critical",confidence="High",category="CORS",url=self.target,
                        payload="Origin: https://evil-attacker.com",
                        evidence=f"ACAO: {acao}\nACAC: {acac}",
                        description="Arbitrary origin reflected with credentials — full CORS bypass.",
                        why="Attacker page silently reads all victim's private API data.",
                        business_impact="Complete authenticated API access for any attacker.",
                        remediation="Validate Origin against strict allowlist before reflecting.",
                        steps=["Implement allowlist","Never reflect without validation"],
                        cvss_score=9.1,cwe="CWE-942",owasp="A05:2021",scanner="active"))
        except Exception: pass
        try:
            resp=await self._safe_get(self.target,headers={"Host":"evil-attacker.com"})
            if resp:
                body=await self._read(resp)
                if "evil-attacker.com" in body:
                    self.add_finding(Finding(
                        title="Host Header Injection — Reflected in Response",
                        severity="High",confidence="High",category="Headers",
                        url=self.target,parameter="Host",payload="Host: evil-attacker.com",
                        evidence="Injected Host value reflected in response body",
                        description="Host header reflected — password reset poisoning possible.",
                        why="Attacker sends victim reset link pointing to evil domain.",
                        business_impact="Account hijacking via password reset poisoning.",
                        remediation="Whitelist valid Host values.",
                        steps=["Maintain ALLOWED_HOSTS","Validate Host against allowlist"],
                        cvss_score=7.5,cwe="CWE-20",owasp="A03:2021",scanner="active"))
        except Exception: pass
        testable=[e for e in self.endpoints if e.status==200][:10]
        self.log(f"  → Testing {len(testable)} injectable endpoints...","dim")
        DEFAULT_PARAMS=["id","q","search","user","file","url","page","name","cat","type","filter","ref","redirect","token","key"]
        completed=0
        for ep in testable:
            all_params=list(dict.fromkeys(ep.params+DEFAULT_PARAMS))[:6]
            completed+=1
            self.log(f"  → [{completed}/{len(testable)}] {ep.path} ({len(all_params)} params)","dim")
            for param in all_params[:4]:
                for payload,pats in [
                    ("'",[r"sql syntax",r"mysql",r"ora-\d",r"sqlstate",r"unclosed quotation",r"you have an error",r"pg_query"]),
                    ("' OR '1'='1",[r"sql syntax",r"mysql",r"database error"]),
                ]:
                    try:
                        test_url=f"{ep.url}?{param}={urllib.parse.quote(payload)}"
                        resp=await self._safe_get(test_url)
                        if not resp: continue
                        body=(await self._read(resp)).lower()
                        for pat in pats:
                            if re.search(pat,body,re.I):
                                self.add_finding(Finding(
                                    title=f"SQL Injection (Error-Based) — Parameter '{param}'",
                                    severity="Critical",confidence="High",category="SQLi",
                                    url=ep.url,parameter=param,payload=payload,
                                    evidence=f"DB error '{pat}' in response\nURL: {test_url}",
                                    description=f"'{param}' directly interpolated into SQL query.",
                                    why="Reads entire DB — credentials, PII, financial data. RCE possible.",
                                    business_impact="Complete database compromise. GDPR breach.",
                                    remediation="Parameterized queries for ALL DB operations.",
                                    steps=["PHP PDO: prepare/execute","Python: cursor.execute with params","Use ORM"],
                                    cvss_score=9.8,cwe="CWE-89",owasp="A03:2021",scanner="active",
                                    request_raw=f"GET {test_url} HTTP/1.1\nHost: {self.domain}"))
                                break
                    except Exception: pass
            for param in all_params[:4]:
                for payload,ptype in [
                    ('<script>alert(document.domain)</script>',"Script Tag"),
                    ('"><img src=x onerror=alert(1)>',"Attr Breakout"),
                    ('<svg/onload=alert(1)>',"SVG XSS"),
                ]:
                    try:
                        test_url=f"{ep.url}?{param}={urllib.parse.quote(payload)}"
                        resp=await self._safe_get(test_url)
                        if not resp: continue
                        ct=resp.headers.get("Content-Type",""); body=await self._read(resp)
                        if "text/html" in ct and payload in body and html_lib.escape(payload) not in body:
                            self.add_finding(Finding(
                                title=f"Reflected XSS ({ptype}) — Parameter '{param}'",
                                severity="High",confidence="High",category="XSS",
                                url=ep.url,parameter=param,payload=payload,
                                evidence="Payload reflected unencoded in HTML response",
                                description=f"'{param}' reflects input without HTML encoding.",
                                why="Executes attacker JS in victim's browser. Cookie theft, account takeover.",
                                business_impact="Account hijacking, credential theft.",
                                remediation="HTML-encode all output. Implement nonce-based CSP.",
                                steps=["PHP: htmlspecialchars($v,ENT_QUOTES,'UTF-8')","Add CSP nonce"],
                                cvss_score=7.4,cwe="CWE-79",owasp="A03:2021",scanner="active",
                                request_raw=f"GET {test_url} HTTP/1.1\nHost: {self.domain}"))
                            break
                    except Exception: pass
            URL_PARAMS=["url","uri","src","dest","redirect","callback","fetch","proxy","href","link","target"]
            for param in [p for p in all_params if any(k in p.lower() for k in URL_PARAMS)][:2]:
                try:
                    test_url=f"{ep.url}?{param}={urllib.parse.quote('http://169.254.169.254/latest/meta-data/')}"
                    resp=await self._safe_get(test_url)
                    if resp:
                        body=await self._read(resp)
                        if any(i in body for i in ["ami-id","instance-id","iam","security-credentials"]):
                            self.add_finding(Finding(
                                title=f"SSRF — Cloud Metadata Accessible via '{param}'",
                                severity="Critical",confidence="High",category="SSRF",
                                url=ep.url,parameter=param,
                                payload="http://169.254.169.254/latest/meta-data/",
                                evidence=body[:300],
                                description=f"SSRF confirmed — cloud metadata reachable via '{param}'.",
                                why="Cloud metadata returns IAM credentials → full cloud takeover.",
                                business_impact="Complete cloud infrastructure compromise.",
                                remediation="Block metadata IPs. Validate URLs against allowlist.",
                                steps=["Enable IMDSv2","Block 169.254.169.254 at WAF","URL allowlist"],
                                cvss_score=9.8,cwe="CWE-918",owasp="A10:2021",scanner="active"))
                except Exception: pass
            FILE_PARAMS=["file","path","page","include","template","doc","read","view","load","download"]
            for param in [p for p in all_params if any(k in p.lower() for k in FILE_PARAMS)][:2]:
                for lfi in ["../../../../etc/passwd","..%2F..%2F..%2Fetc%2Fpasswd"]:
                    try:
                        test_url=f"{ep.url}?{param}={urllib.parse.quote(lfi)}"
                        resp=await self._safe_get(test_url)
                        if resp:
                            body=await self._read(resp)
                            if "root:x:0:0" in body or "daemon:" in body:
                                self.add_finding(Finding(
                                    title=f"Path Traversal/LFI — /etc/passwd Read via '{param}'",
                                    severity="Critical",confidence="High",category="LFI",
                                    url=ep.url,parameter=param,payload=lfi,evidence=body[:300],
                                    description=f"Arbitrary file read confirmed via '{param}'.",
                                    why="Reads SSH keys, configs, /etc/shadow. RCE via log poisoning.",
                                    business_impact="Server compromise, credential theft.",
                                    remediation="Whitelist allowed files. Never user input in paths.",
                                    steps=["realpath() + check prefix","Whitelist filenames","Chroot"],
                                    cvss_score=9.1,cwe="CWE-22",owasp="A01:2021",scanner="active"))
                                break
                    except Exception: pass
            RD_PARAMS=["redirect","return","next","goto","url","dest","back","r","to","location","ref"]
            for param in [p for p in all_params if any(k in p.lower() for k in RD_PARAMS)][:2]:
                try:
                    test_url=f"{ep.url}?{param}={urllib.parse.quote('https://evil-attacker.com')}"
                    resp=await self._safe_get(test_url)
                    if resp:
                        loc=resp.headers.get("Location","")
                        if "evil-attacker.com" in loc:
                            self.add_finding(Finding(
                                title=f"Open Redirect via '{param}'",severity="Medium",confidence="High",
                                category="Open Redirect",url=ep.url,parameter=param,
                                payload="https://evil-attacker.com",evidence=f"Location: {loc}",
                                description=f"Unvalidated redirect via '{param}'.",
                                why="Phishing: victim trusts your URL, lands on attacker's fake login.",
                                business_impact="Brand abuse, credential theft.",
                                remediation="Validate redirects against allowlist.",
                                steps=["Build ALLOWED_REDIRECTS","Reject absolute URLs not on list"],
                                cvss_score=6.1,cwe="CWE-601",owasp="A01:2021",scanner="active"))
                            break
                except Exception: pass
        active_n=len([f for f in self.findings if f.scanner=="active"])
        self.log(f"[✓] Active: {active_n} findings confirmed","ok")

    async def _p6_auth(self):
        self.log("[*] Phase 6: Authentication tests...","white")
        login_eps=[e for e in self.endpoints
                   if any(x in e.path.lower() for x in ["/login","/signin","/auth"])
                   and e.status==200][:2]
        for ep in login_eps:
            try:
                blocked=False
                for i in range(6):
                    resp=await self._post(ep.url,
                        data={"username":"admin","password":f"wrongpass{i}"},to=6)
                    if resp and resp.status in (429,423,403): blocked=True; break
                    await asyncio.sleep(0.2)
                if not blocked:
                    self.add_finding(Finding(
                        title=f"No Rate Limiting on Login: {ep.path}",severity="Medium",
                        confidence="Medium",category="Authentication",url=ep.url,method="POST",
                        parameter="username/password",payload="6 rapid POSTs — no throttle",
                        evidence="6 attempts with no 429/423/403 lockout",
                        description="Login endpoint accepts unlimited password attempts.",
                        why="Automated tools test millions of passwords/min. Credential stuffing.",
                        business_impact="Mass account compromise.",
                        remediation="Rate limit: max 5 attempts/IP/15 min.",
                        steps=["nginx: limit_req_zone","Lockout after N failures","CAPTCHA"],
                        cvss_score=7.3,cwe="CWE-307",owasp="A07:2021",scanner="active"))
            except Exception: pass
        self.log("[✓] Auth tests complete","ok")

    async def _p7_tech(self):
        self.log("[*] Phase 7: Technology fingerprinting...","white")
        techs=set()
        for ep in self.endpoints:
            for t in ep.technologies: techs.add(t)
        h=self._main_headers; b=self._main_body.lower() if self._main_body else ""
        server=h.get("Server",""); xpb=h.get("X-Powered-By","")
        for t in ["nginx","apache","iis","litespeed","caddy","gunicorn"]:
            if t in server.lower(): techs.add(t.capitalize())
        for t in ["php","asp.net","express","node","django","flask","rails","laravel"]:
            if t in xpb.lower(): techs.add(t.upper() if len(t)<=3 else t.capitalize())
        for kw,name in {"react":"React","angular":"Angular","vue.js":"Vue.js","jquery":"jQuery",
                        "next.js":"Next.js","bootstrap":"Bootstrap","tailwind":"Tailwind CSS",
                        "graphql":"GraphQL","socket.io":"Socket.IO","wordpress":"WordPress"}.items():
            if kw in b: techs.add(name)
        self.technologies=list(techs)
        if self.technologies: self.log(f"  → Detected: {', '.join(self.technologies[:8])}","ok")
        self.log("[✓] Tech fingerprint complete","ok")

    async def _p8_info(self):
        self.log("[*] Phase 8: Information disclosure checks...","white")
        exposed=[e for e in self.endpoints if e.status==200
                 and any(s in e.path.lower() for s in SENSITIVE_KEYS)]
        for ep in exposed: self.log(f"  ⚠ SENSITIVE: {ep.path}","crit")
        self.log("[✓] Info disclosure complete","ok")

    def _build_graph(self):
        nodes=[
            {"id":"attacker","label":"Attacker",        "type":"attacker","x":40, "y":250},
            {"id":"internet","label":"Internet",         "type":"entry",   "x":190,"y":250},
            {"id":"target",  "label":self.domain,        "type":"target",  "x":370,"y":250},
            {"id":"web",     "label":"Web Server",        "type":"service", "x":550,"y":110},
            {"id":"api",     "label":"API Layer",         "type":"service", "x":550,"y":250},
            {"id":"db",      "label":"Database",          "type":"service", "x":550,"y":390},
            {"id":"admin",   "label":"Admin Panel",       "type":"danger",  "x":740,"y":60},
            {"id":"auth",    "label":"Auth/Session",      "type":"service", "x":740,"y":190},
            {"id":"cloud",   "label":"Cloud/Storage",     "type":"service", "x":740,"y":320},
            {"id":"internal","label":"Internal\nNetwork", "type":"danger",  "x":740,"y":450},
        ]
        edges=[
            {"from":"attacker","to":"internet","label":"HTTP/S",      "type":"normal"},
            {"from":"internet","to":"target",  "label":"Reaches",     "type":"normal"},
            {"from":"target",  "to":"web",     "label":"Web Traffic", "type":"normal"},
            {"from":"target",  "to":"api",     "label":"API Calls",   "type":"normal"},
            {"from":"api",     "to":"db",      "label":"DB Queries",  "type":"normal"},
            {"from":"web",     "to":"admin",   "label":"Admin Route", "type":"warn"},
            {"from":"api",     "to":"auth",    "label":"Auth Checks", "type":"normal"},
            {"from":"api",     "to":"cloud",   "label":"Storage",     "type":"normal"},
        ]
        cats={f.category for f in self.findings}
        if "XSS"   in cats: edges.append({"from":"attacker","to":"web","label":"XSS","type":"attack"})
        if "SQLi"  in cats: edges.append({"from":"api","to":"db","label":"SQLi→DB","type":"attack"})
        if "SSRF"  in cats: edges.append({"from":"api","to":"internal","label":"SSRF","type":"attack"})
        if "IDOR"  in cats: edges.append({"from":"attacker","to":"api","label":"IDOR","type":"attack"})
        if "Authentication" in cats: edges.append({"from":"attacker","to":"auth","label":"BruteForce","type":"attack"})
        if any(f.severity=="Critical" for f in self.findings):
            edges.append({"from":"attacker","to":"admin","label":"Priv Esc","type":"attack"})
        if self.graphql_found:
            nodes.append({"id":"graphql","label":"GraphQL","type":"service","x":550,"y":450})
            edges.append({"from":"target","to":"graphql","label":"GraphQL","type":"normal"})
            edges.append({"from":"attacker","to":"graphql","label":"Introspect","type":"attack"})
        if self.secrets:
            nodes.append({"id":"secrets","label":"Exposed\nSecrets","type":"danger","x":370,"y":450})
            edges.append({"from":"attacker","to":"secrets","label":"View Source","type":"attack"})
        for i,ep in enumerate([e for e in self.endpoints if e.status==200 and e.issues][:3]):
            nid=f"vuln_{i}"
            nodes.append({"id":nid,"label":ep.path[:18],"type":"vuln","x":950,"y":60+i*140})
            edges.append({"from":"web","to":nid,"label":ep.issues[0][:16],"type":"attack"})
        return {"nodes":nodes,"edges":edges}
