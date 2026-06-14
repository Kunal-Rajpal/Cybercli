"""BurpNext Active Scanner — SQL Injection"""
import aiohttp, urllib.parse, logging, re
from typing import List
logger = logging.getLogger("burpnext.sqli")

ERROR_PATTERNS = [
    "sql syntax", "you have an error in your sql", "mysql_fetch", "pg_query",
    "microsoft ole db", "odbc sql server", "sqlite3.operationalerror",
    "unclosed quotation mark", "quoted string not properly terminated",
    "division by zero", "invalid column name", "unknown column",
    "warning.*mysql", "supplied argument is not a valid mysql",
    "sqlstate", "ora-", "syntax error",
]
PAYLOADS = [
    ("'",                           "Single Quote"),
    ("''",                          "Double Single Quote"),
    ("' OR '1'='1",                 "OR True"),
    ("' OR '1'='1'--",              "OR True Comment"),
    ("' UNION SELECT NULL--",       "UNION NULL"),
    ("1 AND 1=1",                   "Numeric AND True"),
    ("1 AND 1=2",                   "Numeric AND False"),
    ("' AND SLEEP(0)--",            "Time-Based Probe"),
    ("admin'--",                    "Admin Comment"),
]

async def test(session, url: str, param: str, method: str="GET") -> List[dict]:
    findings = []
    for payload, ptype in PAYLOADS[:5]:
        try:
            to = aiohttp.ClientTimeout(total=8)
            if method.upper() == "GET":
                test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                async with session.get(test_url, ssl=False, allow_redirects=False, timeout=to) as r:
                    body = (await r.content.read(16384)).decode("utf-8","ignore").lower()
                    for pat in ERROR_PATTERNS:
                        if re.search(pat, body, re.I):
                            findings.append({
                                "title": f"SQL Injection (Error-Based) — Parameter '{param}'",
                                "severity": "Critical", "cvss": 9.8, "confidence": "High",
                                "cwe": "CWE-89", "owasp": "A03:2021",
                                "url": url, "method": method, "parameter": param,
                                "payload": payload,
                                "evidence": f"DB error pattern '{pat}' in response\nPayload type: {ptype}\nTest URL: {test_url}",
                                "description": f"Parameter '{param}' directly interpolated into SQL query without sanitization.",
                                "why": "Reads entire database — user credentials, PII, financial data. Can modify/delete data. MySQL: OS command execution via INTO OUTFILE or xp_cmdshell.",
                                "business_impact": "Complete database compromise. GDPR/PCI breach. All customer data at risk.",
                                "remediation": "Parameterized queries (prepared statements) for ALL database operations.",
                                "steps": [
                                    "PHP PDO: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $stmt->execute([$id]);",
                                    "Python: cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))",
                                    "Node.js: db.query('SELECT * FROM users WHERE id = ?', [userId])",
                                    "Use ORM (Hibernate/SQLAlchemy/Prisma) — parameterization built-in",
                                    "Apply least-privilege DB account — no DROP/CREATE permissions",
                                ],
                                "request_raw": f"GET {test_url} HTTP/1.1\nHost: {urllib.parse.urlparse(url).hostname}",
                            })
                            return findings
        except Exception as e:
            logger.debug(f"[SQLi] {param}/{payload}: {e}")
    return findings
