# cybercli/core/threat_intel_core.py
"""
Threat intelligence enrichment helpers (safe).
- Local heuristics + optional external lookups (only with API keys set in environment)
- Does NOT perform or automate offensive actions.
- Example functions: hash_lookup, domain_reputation, ip_lookup
"""
from __future__ import annotations
from typing import Optional, Dict, Any
import os
import hashlib
import json
import time
import requests

VT_BASE = "https://www.virustotal.com/api/v3"
VT_API_KEY = os.environ.get("VT_API_KEY", None)  # optional

class ThreatIntelCore:
    def __init__(self, cache_path: Optional[str] = None):
        self.cache_path = cache_path or "/tmp/cybercli_threat_cache.json"
        # load cache if exists
        try:
            with open(self.cache_path, "r") as f:
                self.cache = json.load(f)
        except Exception:
            self.cache = {}

    def _cache_set(self, k: str, v: Any):
        self.cache[k] = {"ts": int(time.time()), "value": v}
        try:
            with open(self.cache_path, "w") as f:
                json.dump(self.cache, f, indent=2)
        except Exception:
            pass

    def _cache_get(self, k: str, max_age: int = 86400) -> Optional[Any]:
        v = self.cache.get(k)
        if not v:
            return None
        if int(time.time()) - v.get("ts", 0) > max_age:
            return None
        return v.get("value")

    # -------------------------
    # Hash lookup (safe)
    # -------------------------
    def hash_lookup(self, sha256: str) -> Dict[str, Any]:
        sha = sha256.lower()
        if len(sha) not in (32, 40, 64):
            return {"error": "invalid hash length"}
        cached = self._cache_get(f"hash:{sha}")
        if cached:
            return {"source": "cache", "result": cached}

        # If VT key present, attempt to query (optional)
        if VT_API_KEY:
            try:
                headers = {"x-apikey": VT_API_KEY}
                r = requests.get(f"{VT_BASE}/files/{sha}", headers=headers, timeout=6)
                if r.status_code == 200:
                    data = r.json()
                    self._cache_set(f"hash:{sha}", data)
                    return {"source": "virustotal", "result": data}
                # not found or other
            except Exception:
                pass

        # Fallback heuristic: local rule-based classification by suspicious strings
        result = {"found": False, "notes": []}
        # very lightweight heuristic checks
        if sha.startswith("0") or sha.startswith("00"):
            result["notes"].append("hash begins with 0 — low entropy (heuristic)")
        # default unknown
        self._cache_set(f"hash:{sha}", result)
        return {"source": "heuristic", "result": result}

    # -------------------------
    # Domain/IP reputation (safe)
    # -------------------------
    def domain_reputation(self, domain: str) -> Dict[str, Any]:
        cached = self._cache_get(f"domain:{domain}")
        if cached:
            return {"source": "cache", "result": cached}

        # Simple passive lookup using ip-api (geo) for domain -> ip then quick mark
        try:
            # resolve via DNS using requests to an external service is not required; instead use socket
            import socket
            ip = socket.gethostbyname(domain)
        except Exception:
            ip = None

        info = {"domain": domain, "ip": ip, "reputation": "unknown", "notes": []}
        if ip:
            try:
                r = requests.get(f"http://ip-api.com/json/{ip}", timeout=4)
                if r.status_code == 200:
                    info["geo"] = r.json()
            except Exception:
                pass

        # basic heuristics
        if domain.endswith(".zip") or domain.count("-") > 5:
            info["notes"].append("domain looks auto-generated / suspicious (heuristic)")

        self._cache_set(f"domain:{domain}", info)
        return {"source": "heuristic", "result": info}

    def ip_lookup(self, ip: str) -> Dict[str, Any]:
        cached = self._cache_get(f"ip:{ip}")
        if cached:
            return {"source": "cache", "result": cached}
        res = {}
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=4)
            if r.status_code == 200:
                res = r.json()
        except Exception:
            res = {"error": "lookup-failed"}
        self._cache_set(f"ip:{ip}", res)
        return {"source": "ip-api", "result": res}

