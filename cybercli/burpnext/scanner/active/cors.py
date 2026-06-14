"""BurpNext Active Scanner — CORS Misconfiguration"""
import aiohttp, logging
from typing import List
logger = logging.getLogger("burpnext.cors")

async def test(session, url: str) -> List[dict]:
    findings = []
    tests = [
        ("https://evil-attacker.com",   "Arbitrary External Origin"),
        ("null",                         "Null Origin"),
        (f"https://evil{url.split('/')[2] if '//' in url else ''}.com", "Prefix Match Bypass"),
    ]
    for origin, label in tests:
        try:
            async with session.get(url, headers={"Origin":origin}, ssl=False,
                allow_redirects=False, timeout=aiohttp.ClientTimeout(total=10)) as r:
                acao = r.headers.get("Access-Control-Allow-Origin","")
                acac = r.headers.get("Access-Control-Allow-Credentials","")
                if acao == "*":
                    findings.append({
                        "title": "CORS: Wildcard Origin — Any Site Can Read API Responses",
                        "severity": "Medium", "cvss": 5.4, "confidence": "High",
                        "cwe": "CWE-942", "owasp": "A05:2021",
                        "url": url, "method": "GET", "parameter": "Origin Header",
                        "payload": f"Origin: {origin}",
                        "evidence": f"Access-Control-Allow-Origin: {acao}",
                        "description": "Wildcard CORS header — any website can read all API responses.",
                        "why": "Malicious website makes authenticated fetch() requests using victim's cookies and reads all API data silently.",
                        "business_impact": "All API data readable by any attacker-controlled website.",
                        "remediation": "Replace * with explicit trusted origin allowlist.",
                        "steps": ["Build ALLOWED_ORIGINS = {'https://yourdomain.com'}",
                                  "if (ALLOWED_ORIGINS.has(origin)) res.setHeader('ACAO', origin)",
                                  "Never use * with authenticated endpoints"],
                        "request_raw": f"GET {url} HTTP/1.1\nOrigin: {origin}",
                    })
                elif acao and "evil-attacker.com" in acao and acac.lower() == "true":
                    findings.append({
                        "title": f"CORS: Arbitrary Origin Reflected + Credentials — {label}",
                        "severity": "Critical", "cvss": 9.1, "confidence": "High",
                        "cwe": "CWE-942", "owasp": "A05:2021",
                        "url": url, "method": "GET", "parameter": "Origin + ACAC Headers",
                        "payload": f"Origin: {origin}",
                        "evidence": f"ACAO: {acao}\nACAC: {acac}",
                        "description": f"Server reflects arbitrary origin with credentials. {label} confirmed.",
                        "why": "Attacker hosts evil page, victim visits, page silently reads all authenticated API data including session tokens, PII, financial data.",
                        "business_impact": "Complete authenticated API access for any attacker.",
                        "remediation": "Strict allowlist validation before reflecting Origin.",
                        "steps": ["Maintain server-side ALLOWED_ORIGINS set",
                                  "Validate exact match — never reflect without validation",
                                  "Set ACAC:true only for explicitly trusted origins"],
                        "request_raw": f"GET {url} HTTP/1.1\nOrigin: {origin}",
                    })
                    return findings
        except Exception as e:
            logger.debug(f"[CORS] {origin}: {e}")
    return findings
