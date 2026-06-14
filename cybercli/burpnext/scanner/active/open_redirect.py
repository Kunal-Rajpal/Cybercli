"""BurpNext Active Scanner — Open Redirect Detection"""
import aiohttp, urllib.parse, logging
from typing import List
logger = logging.getLogger("burpnext.redirect")

REDIRECT_PARAMS = ["redirect","return","next","goto","url","dest","back","forward",
                   "ref","target","continue","to","location","r","redir","returnUrl","redirectUrl"]
PAYLOADS = [
    "https://evil-attacker.com",
    "//evil-attacker.com",
    "/\\evil-attacker.com",
    "https:////evil-attacker.com",
    "/%09/evil-attacker.com",
]

async def test(session, url: str, params: List[str]) -> List[dict]:
    findings = []
    rd_params = [p for p in params if any(k in p.lower() for k in [r.lower() for r in REDIRECT_PARAMS])]
    for param in rd_params[:3]:
        for payload in PAYLOADS:
            try:
                test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                async with session.get(test_url, ssl=False, allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=10)) as r:
                    loc = r.headers.get("Location","")
                    if "evil-attacker.com" in loc:
                        findings.append({
                            "title": f"Open Redirect — Unvalidated Redirect via '{param}'",
                            "severity": "Medium", "cvss": 6.1, "confidence": "High",
                            "cwe": "CWE-601", "owasp": "A01:2021",
                            "url": url, "method": "GET", "parameter": param,
                            "payload": payload, "evidence": f"Location: {loc}",
                            "description": f"Application redirects to attacker URL via '{param}' without validation.",
                            "why": "Phishing: victim receives legitimate-looking link (yourdomain.com/login?redirect=evil.com), clicks it, lands on attacker's fake login page. OAuth token theft via redirect_uri manipulation.",
                            "business_impact": "Brand abuse, credential theft, OAuth token theft.",
                            "remediation": "Validate redirect URLs against strict allowlist.",
                            "steps": [
                                "Maintain ALLOWED_REDIRECTS = {'/dashboard', '/profile', '/home'}",
                                "Use relative URLs for internal redirects — never absolute",
                                "If external needed: whitelist exact domains",
                                "Log suspicious redirect attempts with non-whitelisted targets",
                            ],
                            "request_raw": f"GET {test_url} HTTP/1.1",
                        })
                        return findings
            except Exception as e:
                logger.debug(f"[Redirect] {param}/{payload}: {e}")
    return findings
