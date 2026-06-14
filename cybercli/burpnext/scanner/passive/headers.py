"""BurpNext Passive Scanner — HTTP Security Headers"""
from typing import List, Dict

def check_headers(headers: dict, url: str) -> List[dict]:
    findings = []
    h = lambda k: headers.get(k, headers.get(k.lower(), ""))
    
    CHECKS = [
        ("Strict-Transport-Security", "Medium", 5.4, "CWE-319",
         "Without HSTS, browsers allow HTTP. MITM attacker intercepts ALL traffic — passwords, sessions, PII in plaintext.",
         "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
         ["Add to all HTTPS responses", "Set max-age=31536000", "Submit to hstspreload.org"]),
        ("Content-Security-Policy", "Medium", 6.1, "CWE-1021",
         "No CSP means no JavaScript restriction. Any XSS payload runs with full trust — cookie theft, keyloggers.",
         "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
         ["Audit all content sources", "Use nonces for inline scripts", "Start with CSP-Report-Only"]),
        ("X-Frame-Options", "Low", 4.3, "CWE-1021",
         "Pages can be embedded in iframes. Clickjacking: invisible overlays trick users into unintended actions.",
         "X-Frame-Options: DENY",
         ["Add DENY header", "Or use CSP: frame-ancestors 'none'"]),
        ("X-Content-Type-Options", "Low", 3.1, "CWE-430",
         "MIME sniffing may cause uploaded files to be executed as scripts — file upload to XSS.",
         "X-Content-Type-Options: nosniff",
         ["Add nosniff to all responses"]),
        ("Referrer-Policy", "Low", 2.4, "CWE-200",
         "URL tokens (reset links, session IDs) leak via Referer header to third-party analytics.",
         "Referrer-Policy: strict-origin-when-cross-origin",
         ["Add to all responses"]),
        ("Permissions-Policy", "Low", 2.1, "CWE-693",
         "XSS or malicious iframes can access camera/microphone/geolocation without extra permission.",
         "Permissions-Policy: geolocation=(), microphone=(), camera=()",
         ["Deny all APIs not needed"]),
    ]
    
    for hdr, sev, cvss, cwe, why, fix, steps in CHECKS:
        val = h(hdr)
        if not val:
            findings.append({
                "title": f"Missing Security Header: {hdr}",
                "severity": sev, "cvss": cvss, "url": url,
                "header": hdr, "evidence": f"Header '{hdr}' absent from HTTP response",
                "description": f"{hdr} not configured. Zero-downtime server config fix.",
                "why": why, "fix": fix, "steps": steps, "cwe": cwe,
            })
        else:
            # CSP weakness checks
            if hdr == "Content-Security-Policy":
                if "unsafe-inline" in val:
                    findings.append({
                        "title": "CSP: 'unsafe-inline' Permits Inline Script Execution",
                        "severity": "Medium", "cvss": 5.4, "url": url,
                        "header": hdr, "evidence": f"CSP: {val[:150]}",
                        "description": "unsafe-inline allows all inline JS, defeating XSS protection.",
                        "why": "Injected script tags execute freely despite CSP.",
                        "fix": "Replace unsafe-inline with nonces.", "cwe": "CWE-1021",
                        "steps": ["Generate nonce per request", "Apply to inline scripts", "Remove unsafe-inline"],
                    })
                if "unsafe-eval" in val:
                    findings.append({
                        "title": "CSP: 'unsafe-eval' Allows eval() Execution",
                        "severity": "High", "cvss": 6.5, "url": url,
                        "header": hdr, "evidence": f"CSP: {val[:150]}",
                        "description": "unsafe-eval permits eval() and Function() — arbitrary string execution.",
                        "why": "eval() can execute attacker-controlled strings as code.",
                        "fix": "Remove unsafe-eval. Refactor code using eval().", "cwe": "CWE-95",
                        "steps": ["Remove unsafe-eval", "Replace eval() with JSON.parse()"],
                    })
    return findings
