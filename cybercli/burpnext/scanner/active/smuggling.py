"""BurpNext Active Scanner — HTTP Request Smuggling Detection"""
import aiohttp, asyncio, logging, time
from typing import List
logger = logging.getLogger("burpnext.smuggling")

async def test(session, url: str) -> List[dict]:
    findings = []
    try:
        t0 = time.time()
        payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {url.split('/')[2] if '//' in url else url}\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "0\r\n\r\n"
            "X"
        )
        try:
            async with session.post(url, data=payload.encode(),
                headers={"Content-Type":"application/x-www-form-urlencoded",
                         "Transfer-Encoding":"chunked"},
                ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as r:
                elapsed = time.time()-t0
                if r.status in (400,200) and elapsed < 8:
                    pass
        except Exception: pass

        t1 = time.time()
        try:
            async with session.post(url,
                headers={"Content-Length":"4","Transfer-Encoding":"chunked",
                         "Content-Type":"application/x-www-form-urlencoded"},
                data=b"1\r\nZ\r\n0\r\n\r\n",
                ssl=False, timeout=aiohttp.ClientTimeout(total=12)) as r:
                elapsed = time.time()-t1
                if r.status >= 400 or elapsed > 4:
                    findings.append({
                        "title": "Potential HTTP Request Smuggling (CL.TE) — Investigate Manually",
                        "severity": "High", "cvss": 8.1, "confidence": "Low",
                        "cwe": "CWE-444", "owasp": "A04:2021",
                        "url": url, "method": "POST", "parameter": "Content-Length + Transfer-Encoding",
                        "payload": "Conflicting CL and TE headers",
                        "evidence": f"Unexpected response to CL.TE probe: HTTP {r.status}, elapsed: {elapsed:.2f}s",
                        "description": "Server may be vulnerable to HTTP request smuggling via conflicting Content-Length and Transfer-Encoding headers.",
                        "why": "Request smuggling bypasses WAF/proxy security, hijacks other users' requests, poisons caches, enables auth bypass, and escalates XSS to full session hijacking.",
                        "business_impact": "WAF bypass, session hijacking, cache poisoning, authentication bypass.",
                        "remediation": "Ensure front-end and back-end servers agree on request boundaries.",
                        "steps": [
                            "Normalize Transfer-Encoding headers at reverse proxy layer",
                            "Reject requests with both Content-Length and Transfer-Encoding",
                            "Use HTTP/2 end-to-end — eliminates TE-based smuggling",
                            "Verify with Burp Suite HTTP Request Smuggler extension",
                        ],
                        "request_raw": "POST / HTTP/1.1\nContent-Length: 4\nTransfer-Encoding: chunked\n\n1\r\nZ\r\n0\r\n",
                    })
        except Exception: pass
    except Exception as e:
        logger.debug(f"[Smuggling] {e}")
    return findings
