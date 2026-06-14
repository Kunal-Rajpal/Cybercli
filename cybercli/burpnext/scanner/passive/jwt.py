"""BurpNext Passive Scanner — JWT Vulnerabilities"""
import base64, json, re
from typing import List

def check_jwt(headers: dict, body: str, url: str) -> List[dict]:
    findings = []
    
    def decode_part(part):
        try: return json.loads(base64.b64decode(part + "=="))
        except: return {}
    
    # Find JWTs in headers and body
    tokens = []
    auth = headers.get("Authorization", headers.get("authorization",""))
    if auth.startswith("Bearer "):
        tokens.append(auth[7:])
    for m in re.finditer(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', body or ""):
        tokens.append(m.group())
    
    seen = set()
    for token in tokens:
        if token in seen: continue
        seen.add(token)
        parts = token.split(".")
        if len(parts) != 3: continue
        
        header  = decode_part(parts[0])
        payload = decode_part(parts[1])
        alg     = header.get("alg","")
        
        # alg:none attack
        if alg.lower() in ("none",""):
            findings.append({
                "title": "JWT Algorithm 'none' — Signature Bypass",
                "severity": "Critical", "cvss": 9.8, "url": url,
                "parameter": "Authorization / JWT token",
                "evidence": f"JWT header: {json.dumps(header)[:150]}",
                "cwe": "CWE-345",
                "description": "JWT uses 'none' algorithm — no cryptographic signature. Anyone can forge tokens.",
                "why": "Attacker creates JWT with any claims (admin:true) and no valid signature. Full auth bypass.",
                "fix": "Explicitly reject 'none' algorithm. Use RS256 for multi-service or HS256 with strong secret.",
                "steps": ["Allowlist only trusted algorithms","Never accept 'none'","Use RS256 for distributed systems"],
            })
        
        # HS256 weak secret
        if alg == "HS256":
            findings.append({
                "title": "JWT Using HS256 — Verify Secret Strength",
                "severity": "Low", "cvss": 3.1, "url": url,
                "parameter": "Authorization / JWT token",
                "evidence": f"alg: HS256 | payload keys: {list(payload.keys())[:5]}",
                "cwe": "CWE-326",
                "description": "HS256 requires a strong random secret. Weak secrets crackable with hashcat/jwt_tool.",
                "why": "Weak HMAC secret means attacker brute-forces secret and forges any JWT claim.",
                "fix": "Use cryptographically random secret ≥32 bytes. Consider RS256 asymmetric.",
                "steps": ["Use secrets.token_bytes(32) to generate","Store in env variable","Rotate periodically"],
            })
        
        # Expired check
        exp = payload.get("exp")
        if exp is None:
            findings.append({
                "title": "JWT Without Expiration (exp) Claim",
                "severity": "Medium", "cvss": 5.3, "url": url,
                "parameter": "JWT token",
                "evidence": f"Payload claims: {list(payload.keys())}",
                "cwe": "CWE-613",
                "description": "JWT has no expiration. Stolen tokens are valid forever.",
                "why": "Leaked or intercepted JWT remains valid indefinitely. No way to invalidate stolen tokens.",
                "fix": "Add exp claim: max 1 hour for access tokens, 7 days for refresh.",
                "steps": ["Add exp: current_time + 3600","Add refresh token rotation","Implement token revocation list"],
            })
    
    return findings
