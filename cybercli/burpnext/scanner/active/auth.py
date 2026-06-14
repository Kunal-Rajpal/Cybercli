"""BurpNext Active Scanner — Authentication Weaknesses"""
import asyncio, aiohttp, logging
from typing import List
logger = logging.getLogger("burpnext.auth")

DEFAULTS = [
    ("admin","admin"),("admin","password"),("admin","123456"),("admin",""),
    ("root","root"),("test","test"),("guest","guest"),("administrator","administrator"),
]

async def test_rate_limit(session, url: str, method: str="POST") -> List[dict]:
    findings = []
    blocked = False
    for i in range(8):
        try:
            resp = await session.request(method, url,
                data={"username":"admin","password":f"wrongpass{i}","email":"admin@test.com"},
                ssl=False, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=6))
            if resp.status in (429,423,403): blocked=True; break
            await asyncio.sleep(0.15)
        except Exception: pass
    if not blocked:
        findings.append({
            "title": f"No Rate Limiting / Account Lockout on Login: {url.split('/')[-1] or 'Login'}",
            "severity": "Medium", "cvss": 7.3, "confidence": "Medium",
            "cwe": "CWE-307", "owasp": "A07:2021",
            "url": url, "method": method, "parameter": "username/password",
            "payload": "8 rapid POST requests — no throttle response",
            "evidence": "Sent 8 login attempts with no 429/423/403 lockout response received",
            "description": "Login endpoint accepts unlimited authentication attempts without rate limiting.",
            "why": "Hydra/Medusa test millions of passwords per minute. Top 1000 passwords crack most accounts in under a minute. Credential stuffing uses breach databases of billions of username:password pairs.",
            "business_impact": "Mass account compromise, credential stuffing attacks.",
            "remediation": "Rate limit: max 5 attempts per IP per 15 minutes. Account lockout after 10 failures.",
            "steps": [
                "Nginx: limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m",
                "Account lockout after 5-10 failures with 15-minute cooldown",
                "Progressive delays: 1s, 2s, 4s, 8s... after each failure",
                "CAPTCHA challenge after 3 failed attempts",
                "Alert on >10 failed attempts per account per hour",
            ],
            "request_raw": f"POST {url} HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin&password=wrongpass",
        })
    return findings

async def test_default_creds(session, url: str) -> List[dict]:
    findings = []
    for user, pwd in DEFAULTS:
        try:
            resp = await session.post(url,
                data={"username":user,"password":pwd},
                ssl=False, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=8))
            body = (await resp.content.read(8192)).decode("utf-8","ignore")
            if resp.status in (200,302) and any(kw in body.lower() for kw in
               ["dashboard","logout","welcome","profile","account","settings"]):
                findings.append({
                    "title": f"Default Credentials Valid: {user}/{pwd}",
                    "severity": "Critical", "cvss": 9.8, "confidence": "High",
                    "cwe": "CWE-1392", "owasp": "A07:2021",
                    "url": url, "method": "POST", "parameter": "username/password",
                    "payload": f"username={user}&password={pwd}",
                    "evidence": f"Login succeeded with default credentials {user}/{pwd}",
                    "description": f"Application accepts default credentials {user}/{pwd}.",
                    "why": "Complete authentication bypass. Attacker immediately has full application access with no exploitation needed.",
                    "business_impact": "Immediate unauthorized access to all application functionality.",
                    "remediation": "Change all default credentials immediately. Force change on first login.",
                    "steps": [
                        f"Change password for {user} immediately",
                        "Force password change on initial login",
                        "Remove all test/guest/demo accounts from production",
                        "Audit all accounts for default or weak passwords",
                    ],
                    "request_raw": f"POST {url} HTTP/1.1\n\nusername={user}&password={pwd}",
                })
                return findings
        except Exception as e:
            logger.debug(f"[Auth] Default {user}: {e}")
    return findings
