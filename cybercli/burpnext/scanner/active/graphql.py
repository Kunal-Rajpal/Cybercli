"""BurpNext Active Scanner — GraphQL Security Tests"""
import aiohttp, logging
from typing import List
logger = logging.getLogger("burpnext.graphql")

async def test(session, url: str) -> List[dict]:
    findings = []
    try:
        resp = await session.post(url,
            json={"query":"{ __schema { types { name fields { name } } } }"},
            headers={"Content-Type":"application/json"},
            ssl=False, timeout=aiohttp.ClientTimeout(total=12))
        body = await resp.text(errors="ignore")
        if "__schema" in body and "types" in body:
            findings.append({
                "title": "GraphQL Introspection Enabled — Full Schema Exposed",
                "severity": "Medium", "cvss": 5.3, "confidence": "High",
                "cwe": "CWE-200", "owasp": "A05:2021",
                "url": url, "method": "POST", "parameter": "query",
                "payload": '{"query":"{ __schema { types { name } } }"}',
                "evidence": body[:400],
                "description": "GraphQL introspection returns complete API schema including all types, queries, mutations.",
                "why": "Complete API attack surface revealed — all mutations, admin operations, hidden fields. Enables targeted IDOR, auth bypass, and business logic attack discovery without any documentation.",
                "business_impact": "Full API enumeration by any attacker.",
                "remediation": "Disable introspection in production environments.",
                "steps": [
                    "Apollo Server: introspection: false in production",
                    "graphql-js: NoSchemaIntrospectionCustomRule validation rule",
                    "Implement persisted queries to allowlist approved operations",
                ],
                "request_raw": f"POST {url} HTTP/1.1\nContent-Type: application/json\n\n" + '{"query":"{ __schema { types { name } } }"}',
            })
    except Exception as e:
        logger.debug(f"[GraphQL] Introspection: {e}")
    try:
        batch = [{"query":"{ __typename }"}] * 50
        resp = await session.post(url, json=batch,
            headers={"Content-Type":"application/json"},
            ssl=False, timeout=aiohttp.ClientTimeout(total=15))
        if resp.status == 200:
            findings.append({
                "title": "GraphQL Batching — DoS / Brute Force Amplification",
                "severity": "Medium", "cvss": 5.9, "confidence": "Medium",
                "cwe": "CWE-770", "owasp": "A04:2021",
                "url": url, "method": "POST", "parameter": "batch query",
                "payload": "Array of 50 queries in single request",
                "evidence": f"Server accepted batch of 50 queries — HTTP {resp.status}",
                "description": "GraphQL accepts batched queries enabling brute force in single request.",
                "why": "Attacker sends 1000 login mutations in a single HTTP request, bypassing per-request rate limiting completely.",
                "business_impact": "Rate limiting bypass, brute force amplification, DoS potential.",
                "remediation": "Limit batch size. Implement query complexity limits.",
                "steps": [
                    "Limit batch array size to 5-10 operations",
                    "Implement query complexity scoring and limits",
                    "Rate limit per query operation, not just per HTTP request",
                ],
                "request_raw": f"POST {url} HTTP/1.1\nContent-Type: application/json\n\n[query1, query2, ...x50]",
            })
    except Exception as e:
        logger.debug(f"[GraphQL] Batching: {e}")
    return findings
