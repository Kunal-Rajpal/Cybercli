"""
Passive Scanner — Observe traffic, find security issues without attack traffic.
Checks: CSP, HSTS, CORS, Cookie flags, JWT, exposed headers, stack leakage, IP leaks.
"""

import re
import json
import base64
import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger("cybercli.passive")


class PassiveScanner:
    """
    ZAP-style passive scanner. NO attack traffic generated.
    Checks every request/response pair for misconfigurations.
    Isolated — failure does NOT affect other modules.
    """

    SENSITIVE_HEADER_PATTERNS = [
        r"X-Powered-By",
        r"Server",
        r"X-AspNet-Version",
        r"X-AspNetMvc-Version",
        r"X-Generator",
        r"X-Debug",
        r"X-Runtime",
    ]

    STACK_LEAK_PATTERNS = [
        r"at\s+[\w\.]+\([\w\.]+:\d+:\d+\)",      # JS stack trace
        r"Traceback \(most recent call last\)",     # Python
        r"Exception in thread",                     # Java
        r"Fatal error:",                            # PHP
        r"Microsoft OLE DB Provider",               # ASP
        r"mysql_fetch",                             # PHP MySQL
        r"SQLException",                            # Java SQL
        r"ORA-\d{5}",                              # Oracle
        r"pg_query\(\)",                            # PostgreSQL
    ]

    INTERNAL_IP_PATTERN = re.compile(
        r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
        r'192\.168\.\d{1,3}\.\d{1,3})\b'
    )

    JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

    def __init__(self):
        self._findings: List[dict] = []

    def scan_request(self, req) -> List[dict]:
        findings = []
        try:
            findings += self._check_jwt_in_request(req)
            findings += self._check_sensitive_params(req)
        except Exception as e:
            logger.debug(f"[PASSIVE] Request scan error: {e}")
        return findings

    def scan_response(self, res, req=None) -> List[dict]:
        findings = []
        try:
            findings += self._check_security_headers(res, req)
            findings += self._check_cors(res, req)
            findings += self._check_cookies(res, req)
            findings += self._check_stack_leakage(res, req)
            findings += self._check_internal_ip(res, req)
            findings += self._check_jwt_in_response(res, req)
            findings += self._check_csp(res, req)
        except Exception as e:
            logger.debug(f"[PASSIVE] Response scan error: {e}")
        return findings

    def _finding(self, title, severity, confidence, url, description, evidence=""):
        f = {
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "url": url or "",
            "description": description,
            "evidence": evidence[:200] if evidence else "",
            "timestamp": datetime.utcnow().isoformat(),
            "scanner": "passive",
        }
        self._findings.append(f)
        return f

    def _check_security_headers(self, res, req) -> List[dict]:
        findings = []
        url = getattr(req, "url", "")
        headers = {k.lower(): v for k, v in (getattr(res, "headers", {}) or {}).items()}

        if "strict-transport-security" not in headers:
            findings.append(self._finding(
                "Missing HSTS Header", "Medium", "High", url,
                "The Strict-Transport-Security header is not set. "
                "This allows downgrade attacks to HTTP.",
            ))

        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            findings.append(self._finding(
                "Missing Clickjacking Protection", "Medium", "High", url,
                "Neither X-Frame-Options nor CSP frame-ancestors is set.",
            ))

        if "x-content-type-options" not in headers:
            findings.append(self._finding(
                "Missing X-Content-Type-Options", "Low", "High", url,
                "X-Content-Type-Options: nosniff not set. "
                "Browser may MIME-sniff responses.",
            ))

        if "referrer-policy" not in headers:
            findings.append(self._finding(
                "Missing Referrer-Policy", "Informational", "High", url,
                "Referrer-Policy header not set. Sensitive URLs may leak.",
            ))

        for pat in self.SENSITIVE_HEADER_PATTERNS:
            for h, v in headers.items():
                if re.search(pat, h, re.IGNORECASE):
                    findings.append(self._finding(
                        f"Server Technology Disclosure ({h})", "Low", "High", url,
                        f"Header '{h}: {v}' reveals server technology.",
                        evidence=f"{h}: {v}"
                    ))
                    break

        return findings

    def _check_cors(self, res, req) -> List[dict]:
        findings = []
        url = getattr(req, "url", "")
        headers = {k.lower(): v for k, v in (getattr(res, "headers", {}) or {}).items()}
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")

        if acao == "*":
            findings.append(self._finding(
                "Wildcard CORS Policy", "Medium", "High", url,
                "Access-Control-Allow-Origin: * allows any origin to read responses.",
                evidence=f"ACAO: {acao}"
            ))

        if acao not in ("", "*") and acac.lower() == "true":
            req_origin = ""
            if req:
                req_headers = {k.lower(): v for k, v in (getattr(req, "headers", {}) or {}).items()}
                req_origin = req_headers.get("origin", "")
            if req_origin and acao == req_origin:
                findings.append(self._finding(
                    "Reflected Origin in CORS (Potential Misconfiguration)", "High", "Medium", url,
                    "Server reflects the request Origin back with credentials allowed. "
                    "If not validated server-side, this enables CORS exploitation.",
                    evidence=f"ACAO: {acao}, ACAC: {acac}"
                ))

        return findings

    def _check_cookies(self, res, req) -> List[dict]:
        findings = []
        url = getattr(req, "url", "")
        headers = getattr(res, "headers", {}) or {}

        set_cookies = []
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                set_cookies.append(v)

        for cookie in set_cookies:
            cookie_lower = cookie.lower()
            name = cookie.split("=")[0].strip()

            if "secure" not in cookie_lower:
                findings.append(self._finding(
                    f"Cookie Missing Secure Flag: {name}", "Medium", "High", url,
                    f"Cookie '{name}' does not have the Secure flag. "
                    "Transmittable over HTTP.",
                    evidence=cookie[:100]
                ))

            if "httponly" not in cookie_lower:
                findings.append(self._finding(
                    f"Cookie Missing HttpOnly Flag: {name}", "Medium", "High", url,
                    f"Cookie '{name}' does not have HttpOnly flag. "
                    "Accessible via JavaScript — XSS can steal it.",
                    evidence=cookie[:100]
                ))

            if "samesite" not in cookie_lower:
                findings.append(self._finding(
                    f"Cookie Missing SameSite: {name}", "Low", "High", url,
                    f"Cookie '{name}' missing SameSite attribute. CSRF risk.",
                    evidence=cookie[:100]
                ))

        return findings

    def _check_stack_leakage(self, res, req) -> List[dict]:
        findings = []
        url = getattr(req, "url", "")
        body = getattr(res, "body", b"") or b""
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="ignore")

        for pat in self.STACK_LEAK_PATTERNS:
            m = re.search(pat, body)
            if m:
                findings.append(self._finding(
                    "Stack Trace / Error Disclosure", "Medium", "High", url,
                    "Application error/stack trace exposed in response. "
                    "Reveals internal structure.",
                    evidence=m.group()[:150]
                ))
                break

        return findings

    def _check_internal_ip(self, res, req) -> List[dict]:
        findings = []
        url = getattr(req, "url", "")
        body = getattr(res, "body", b"") or b""
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="ignore")

        m = self.INTERNAL_IP_PATTERN.search(body)
        if m:
            findings.append(self._finding(
                "Internal IP Address Disclosure", "Low", "Medium", url,
                "Internal/private IP address found in response body. "
                "Can aid reconnaissance.",
                evidence=m.group()
            ))

        return findings

    def _check_jwt_in_response(self, res, req) -> List[dict]:
        findings = []
        url = getattr(req, "url", "")
        body = getattr(res, "body", b"") or b""
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="ignore")

        tokens = self.JWT_PATTERN.findall(body)
        for token in tokens[:3]:
            try:
                parts = token.split(".")
                header = json.loads(base64.b64decode(parts[0] + "=="))
                alg = header.get("alg", "unknown")

                if alg.upper() in ("NONE", "HS256"):
                    severity = "High" if alg.upper() == "NONE" else "Medium"
                    findings.append(self._finding(
                        f"JWT with Weak Algorithm: {alg}", severity, "High", url,
                        f"JWT token found in response using algorithm '{alg}'. "
                        f"{'None algorithm allows bypass.' if alg.upper() == 'NONE' else 'HS256 may be brutable.'}",
                        evidence=token[:80] + "..."
                    ))
            except Exception:
                pass

        return findings

    def _check_jwt_in_request(self, req) -> List[dict]:
        findings = []
        url = getattr(req, "url", "")
        auth = ""
        if req and hasattr(req, "headers"):
            headers = {k.lower(): v for k, v in (req.headers or {}).items()}
            auth = headers.get("authorization", "")

        if auth.lower().startswith("bearer "):
            token = auth[7:]
            try:
                parts = token.split(".")
                header = json.loads(base64.b64decode(parts[0] + "=="))
                alg = header.get("alg", "unknown")
                if alg.upper() == "NONE":
                    findings.append(self._finding(
                        "JWT None Algorithm in Request", "Critical", "High", url,
                        "Request uses JWT with alg:none — authentication bypass possible.",
                        evidence=token[:80]
                    ))
            except Exception:
                pass

        return findings

    def _check_sensitive_params(self, req) -> List[dict]:
        findings = []
        url = getattr(req, "url", "")
        sensitive = ["password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "auth"]
        if "?" in url:
            qs = url.split("?", 1)[1]
            for param in sensitive:
                if param in qs.lower():
                    findings.append(self._finding(
                        f"Sensitive Parameter in URL: {param}", "Medium", "High", url,
                        f"Sensitive parameter '{param}' passed in URL. "
                        "Will be logged in server logs and referrer headers.",
                        evidence=qs[:100]
                    ))
        return findings

    def _check_csp(self, res, req) -> List[dict]:
        findings = []
        url = getattr(req, "url", "")
        headers = {k.lower(): v for k, v in (getattr(res, "headers", {}) or {}).items()}
        csp = headers.get("content-security-policy", "")

        if not csp:
            findings.append(self._finding(
                "Missing Content-Security-Policy", "Medium", "High", url,
                "No CSP header found. XSS attacks are unrestricted.",
            ))
            return findings

        if "unsafe-inline" in csp:
            findings.append(self._finding(
                "CSP: unsafe-inline Allowed", "Medium", "High", url,
                "CSP allows 'unsafe-inline'. Inline XSS possible.",
                evidence=csp[:100]
            ))

        if "unsafe-eval" in csp:
            findings.append(self._finding(
                "CSP: unsafe-eval Allowed", "Medium", "Medium", url,
                "CSP allows 'unsafe-eval'. eval()-based XSS possible.",
                evidence=csp[:100]
            ))

        if "*" in csp.split("script-src")[-1].split(";")[0] if "script-src" in csp else True:
            if "default-src *" in csp or "script-src *" in csp:
                findings.append(self._finding(
                    "CSP Wildcard Source", "High", "High", url,
                    "CSP uses wildcard (*) source. Effectively no restriction.",
                    evidence=csp[:100]
                ))

        return findings

    def get_all_findings(self) -> List[dict]:
        return list(self._findings)
