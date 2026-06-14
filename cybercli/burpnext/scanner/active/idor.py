"""BurpNext Active Scanner — IDOR Detection"""
import aiohttp, logging
from typing import List
logger = logging.getLogger("burpnext.idor")

ID_PARAMS = ["id","user_id","userid","uid","account_id","order_id","doc_id",
             "file_id","record_id","customer_id","profile_id","invoice_id"]

async def test(session, url: str, params: List[str], method: str="GET") -> List[dict]:
    findings = []
    id_params = [p for p in params if p.lower() in ID_PARAMS or p.lower().endswith("_id")]
    for param in id_params[:3]:
        try:
            r1 = await session.get(f"{url}?{param}=1", ssl=False, allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=10))
            r2 = await session.get(f"{url}?{param}=2", ssl=False, allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=10))
            b1 = (await r1.content.read(8192)).decode("utf-8","ignore")
            b2 = (await r2.content.read(8192)).decode("utf-8","ignore")
            if r1.status==200 and r2.status==200 and len(b1)>100 and b1!=b2:
                sensitive = any(kw in b1.lower() for kw in ["email","phone","address","name","username","password","token","credit","ssn","dob"])
                findings.append({
                    "title": f"Potential IDOR — Parameter '{param}' Returns Different Users' Data",
                    "severity": "High" if sensitive else "Medium",
                    "cvss": 8.1 if sensitive else 6.5, "confidence": "Medium",
                    "cwe": "CWE-639", "owasp": "A01:2021",
                    "url": url, "method": method, "parameter": param,
                    "payload": f"?{param}=1 and ?{param}=2",
                    "evidence": f"ID=1: {len(b1)} bytes, ID=2: {len(b2)} bytes — different content returned\n{'Sensitive data indicators found' if sensitive else ''}",
                    "description": f"Changing '{param}' returns different user objects without visible authorization check. Sequential enumeration exposes all records.",
                    "why": "Horizontal privilege escalation: attacker accesses any user's profile, orders, messages, financial data by incrementing IDs. Mass data breach via automation.",
                    "business_impact": "All user data accessible. Mass PII/financial data breach. GDPR violation.",
                    "remediation": "Server-side authorization check on every object access. Use UUIDs instead of sequential integers.",
                    "steps": [
                        "Verify authenticated user owns requested object server-side: if (record.user_id != session.user_id) return 403",
                        "Replace sequential integer IDs with UUIDs (v4): uuid.uuid4()",
                        "Implement Object-Level Authorization (OLA) middleware",
                        "Log and alert on rapid sequential access patterns",
                    ],
                    "request_raw": f"GET {url}?{param}=1 HTTP/1.1\nGET {url}?{param}=2 HTTP/1.1",
                })
        except Exception as e:
            logger.debug(f"[IDOR] {param}: {e}")
    return findings
