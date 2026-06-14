"""BurpNext Active Scanner — Command Injection"""
import aiohttp, urllib.parse, logging, re, time
from typing import List
logger = logging.getLogger("burpnext.cmdi")

PAYLOADS = [
    ("; echo BURPNXT_CMD_$(id)",     ["BURPNXT_CMD_","uid=","root"],   "Semicolon"),
    ("| echo BURPNXT_CMD_$(id)",     ["BURPNXT_CMD_","uid=","root"],   "Pipe"),
    ("&& echo BURPNXT_CMD_$(id)",    ["BURPNXT_CMD_","uid=","root"],   "AND"),
    ("$(echo BURPNXT_CMD_$(id))",    ["BURPNXT_CMD_","uid=","root"],   "Subshell"),
    ("`echo BURPNXT_CMD_$(id)`",     ["BURPNXT_CMD_","uid=","root"],   "Backtick"),
    ("; cat /etc/passwd",            ["root:x:0:0","daemon:","bin:"],  "Cat Passwd"),
]

async def test(session, url: str, param: str, method: str="GET") -> List[dict]:
    findings = []
    for payload, indicators, ptype in PAYLOADS[:4]:
        try:
            to = aiohttp.ClientTimeout(total=8)
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            async with session.get(test_url, ssl=False, allow_redirects=False, timeout=to) as r:
                body = (await r.content.read(16384)).decode("utf-8","ignore")
                if any(ind in body for ind in indicators):
                    findings.append({
                        "title": f"Command Injection (OS CMDi) — Parameter '{param}'",
                        "severity": "Critical", "cvss": 9.8, "confidence": "High",
                        "cwe": "CWE-78", "owasp": "A03:2021",
                        "url": url, "method": method, "parameter": param,
                        "payload": payload,
                        "evidence": f"OS command output detected in response\nType: {ptype}\nURL: {test_url}",
                        "description": f"Parameter '{param}' passed directly to OS shell — command injection confirmed.",
                        "why": "Attacker executes arbitrary OS commands as the web server user. Reads /etc/passwd, SSH keys. Installs reverse shells for persistent access.",
                        "business_impact": "Complete server compromise. Lateral movement to internal network. Data exfiltration.",
                        "remediation": "Never pass user input to shell commands. Use language-native libraries instead.",
                        "steps": [
                            "Python: use subprocess with list args — subprocess.run(['cmd', arg]) never shell=True",
                            "PHP: avoid exec()/system()/passthru() with user input entirely",
                            "If shell required: whitelist allowed values — if input not in ALLOWED: reject",
                            "Run web process as minimal-privilege user (not root/www-data)",
                            "WAF: block common injection metacharacters (;|&$`)",
                        ],
                        "request_raw": f"GET {test_url} HTTP/1.1",
                    })
                    return findings
        except Exception as e:
            logger.debug(f"[CMDi] {param}/{ptype}: {e}")
    return findings
