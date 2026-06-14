"""BurpNext Active Scanner — Cross-Site Scripting"""
import aiohttp, urllib.parse, html as html_lib, logging, re
from typing import List
logger = logging.getLogger("burpnext.xss")

PAYLOADS = [
    ('<script>alert(document.domain)</script>',     "Script Tag"),
    ('"><script>alert(1)</script>',                 "Attr Breakout Script"),
    ('"><img src=x onerror=alert(1)>',              "Attr Breakout Img"),
    ('<svg/onload=alert(1)>',                       "SVG onload"),
    ("';alert(String.fromCharCode(88,83,83))//",    "JS String Break"),
    ('<body onload=alert(1)>',                      "Body onload"),
    ('javascript:alert(1)',                         "JS Protocol"),
    ('"><details open ontoggle=alert(1)>',          "HTML5 Details"),
]
DOM_SINKS = ["document.write","document.writeln","innerHTML","outerHTML",
             "eval(","setTimeout(","setInterval(","location.href",".src ="]

async def test(session, url: str, param: str, method: str="GET") -> List[dict]:
    findings = []
    for payload, ptype in PAYLOADS:
        try:
            to = aiohttp.ClientTimeout(total=8)
            encoded = urllib.parse.quote(payload)
            if method.upper() == "GET":
                test_url = f"{url}?{param}={encoded}"
                async with session.get(test_url, ssl=False, allow_redirects=False, timeout=to) as r:
                    ct = r.headers.get("Content-Type","")
                    if "text/html" not in ct: continue
                    body = (await r.content.read(65536)).decode("utf-8","ignore")
                    escaped = html_lib.escape(payload)
                    if payload in body and escaped not in body:
                        findings.append({
                            "title": f"Reflected XSS ({ptype}) — Parameter '{param}'",
                            "severity": "High", "cvss": 7.4, "confidence": "High",
                            "cwe": "CWE-79", "owasp": "A03:2021",
                            "url": url, "method": method, "parameter": param,
                            "payload": payload,
                            "evidence": f"Payload reflected unencoded in text/html response\nType: {ptype}\nURL: {test_url}",
                            "description": f"Parameter '{param}' reflects user input in HTML without encoding. XSS confirmed.",
                            "why": "Executes attacker's JavaScript in victim's browser. Cookie theft leads to instant account takeover. Keyloggers capture passwords typed on the page.",
                            "business_impact": "Account hijacking, credential theft, malware distribution via trusted domain.",
                            "remediation": "HTML-encode all user-controlled output. Implement nonce-based CSP.",
                            "steps": [
                                "PHP: echo htmlspecialchars($val, ENT_QUOTES, 'UTF-8');",
                                "Python/Jinja2: {{ value | e }} (auto-escaped by default)",
                                "Node.js: use he.encode(val) or DOMPurify for rich HTML",
                                "Add CSP: script-src 'nonce-{random}' — blocks injected scripts",
                                "Set X-XSS-Protection: 1; mode=block as defense in depth",
                            ],
                            "request_raw": f"GET {test_url} HTTP/1.1\nHost: {urllib.parse.urlparse(url).hostname}",
                        })
                        return findings
        except Exception as e:
            logger.debug(f"[XSS] {param}/{ptype}: {e}")
    return findings

async def test_dom_indicators(session, url: str) -> List[dict]:
    findings = []
    try:
        to = aiohttp.ClientTimeout(total=8)
        async with session.get(url, ssl=False, allow_redirects=False, timeout=to) as r:
            ct = r.headers.get("Content-Type","")
            if "text/html" not in ct: return findings
            body = (await r.content.read(65536)).decode("utf-8","ignore")
            found_sinks = [s for s in DOM_SINKS if s in body]
            if found_sinks and re.search(r'location\.(?:search|hash|href)', body):
                findings.append({
                    "title": "DOM XSS Indicators — Unvalidated URL Data Flows into Dangerous Sink",
                    "severity": "Medium", "cvss": 6.1, "confidence": "Medium",
                    "cwe": "CWE-79", "owasp": "A03:2021",
                    "url": url, "method": "GET", "parameter": "URL hash/search",
                    "payload": "N/A — DOM-based, no server round-trip",
                    "evidence": f"DOM sinks found: {found_sinks[:3]}\nURL sources: location.search/hash used",
                    "description": "Page reads from URL (location.search/hash) and writes to dangerous DOM sinks without sanitization.",
                    "why": "Attacker crafts link with malicious fragment/query → victim clicks → JS executes in their browser. Never touches server.",
                    "business_impact": "Account takeover, credential theft. Harder to detect — no server logs.",
                    "remediation": "Use textContent instead of innerHTML. Sanitize with DOMPurify before DOM writes.",
                    "steps": [
                        "Replace innerHTML with textContent for plain text",
                        "Use DOMPurify.sanitize(input) before innerHTML",
                        "Validate/allowlist URL params before use in DOM",
                        "Add CSP: script-src 'nonce-{value}' to block injected scripts",
                    ],
                    "request_raw": f"GET {url} HTTP/1.1",
                })
    except Exception as e:
        logger.debug(f"[DOM-XSS] {url}: {e}")
    return findings
