"""BurpNext Passive Scanner — Content Security Policy Analysis"""
from typing import List

def analyze_csp(csp_value: str, url: str) -> List[dict]:
    """Analyze CSP header for weaknesses — only call from outside passive scan to avoid duplication."""
    findings = []
    if not csp_value: return findings
    val = csp_value.lower()
    
    checks = [
        ("unsafe-inline", "CSP: unsafe-inline Permits Inline Scripts", "Medium", 5.4,
         "Allows all inline script execution. Completely defeats XSS protection.",
         "Replace with nonces: script-src 'nonce-{random}'"),
        ("unsafe-eval",   "CSP: unsafe-eval Allows Dynamic Code Execution", "High", 6.5,
         "Permits eval(), Function(), setTimeout(string). Attackers use these to execute code.",
         "Remove unsafe-eval. Refactor eval() usage."),
        ("data:",          "CSP: data: URI Scheme Allowed", "Low", 3.1,
         "data: URIs can be used to load scripts in some browsers.",
         "Remove data: from script-src if present."),
    ]
    for pattern, title, sev, cvss, why, fix in checks:
        if pattern in val:
            findings.append({
                "title": title, "severity": sev, "cvss": cvss, "url": url,
                "parameter": "Content-Security-Policy",
                "evidence": f"CSP: {csp_value[:200]}",
                "description": f"CSP contains '{pattern}' directive.",
                "why": why, "fix": fix, "cwe": "CWE-1021",
                "steps": [f"Remove '{pattern}' from CSP", "Test application after removal"],
            })
    return findings
