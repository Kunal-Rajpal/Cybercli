"""BurpNext Passive Scanner — Cookie Security"""
from typing import List

SENSITIVE_NAMES = ["session","auth","token","sid","csrf","jwt","access","refresh","user","account"]

def check_cookies(headers: dict, url: str) -> List[dict]:
    findings = []
    sc_raw = headers.get("Set-Cookie", headers.get("set-cookie", ""))
    if not sc_raw: return findings
    cookies = sc_raw if isinstance(sc_raw, list) else [sc_raw]
    
    for cookie in cookies:
        name  = cookie.split("=")[0].strip()
        lower = cookie.lower()
        if not any(k in name.lower() for k in SENSITIVE_NAMES): continue
        
        checks = [
            ("secure",   f"Cookie Missing Secure Flag: {name}",   "Medium", 5.4, "CWE-614",
             "Cookie transmitted in plaintext over HTTP. Network attacker captures it → instant session hijack.",
             f"Set-Cookie: {name}=value; Secure; HttpOnly; SameSite=Strict"),
            ("httponly",  f"Cookie Missing HttpOnly Flag: {name}",  "Medium", 4.3, "CWE-1004",
             "Cookie readable via document.cookie. Any XSS immediately escalates to full session hijack.",
             f"Set-Cookie: {name}=value; HttpOnly; Secure; SameSite=Strict"),
            ("samesite",  f"Cookie Missing SameSite Attribute: {name}", "Low", 3.5, "CWE-352",
             "Cookie sent with cross-site requests — CSRF attacks possible without extra token.",
             "Add SameSite=Strict (or Lax for OAuth flows)"),
        ]
        for flag, title, sev, cvss, cwe, why, fix in checks:
            if flag not in lower:
                findings.append({
                    "title": title, "severity": sev, "cvss": cvss, "url": url,
                    "parameter": name, "evidence": cookie[:150], "cwe": cwe,
                    "description": f"Cookie '{name}' missing {flag.capitalize()} attribute.",
                    "why": why, "fix": fix,
                    "steps": [f"Add {flag.capitalize()} to Set-Cookie header",
                              "Verify in DevTools: Application → Cookies"],
                })
    return findings
