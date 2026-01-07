# cybercli/core/brute_utils.py
from pathlib import Path
import requests, re
from typing import List, Dict, Any

COMMON_DIRS = [
    "robots.txt","sitemap.xml","security.txt",".well-known/security.txt",
    "admin","login","dashboard","cp","console","portal","api","api/v1","graphql",
    ".git/HEAD",".env","server-status","phpinfo.php","wp-admin","wp-login.php","backup",
    "old","test","staging","uploads","private","config",".DS_Store"
]

def dir_bruteforce(base_url: str, outdir: Path) -> List[Dict[str,Any]]:
    found = []
    outdir.mkdir(parents=True, exist_ok=True)
    for p in COMMON_DIRS:
        u = base_url.rstrip("/") + "/" + p
        try:
            r = requests.head(u, timeout=6, allow_redirects=True, verify=False)
            if r.status_code < 400:
                found.append({"path": "/" + p, "status": r.status_code, "len": int(r.headers.get("Content-Length", "0") or "0"), "url": r.url})
        except Exception:
            pass
    if found:
        with open(outdir / "dirbrute.json", "w", encoding="utf-8") as f:
            import json; json.dump(found, f, indent=2)
    return found

# alias name some other modules expect
def scan_secrets_from_text(text: str):
    # simple wrapper
    from cybercli.core.recon_core import harvest_secrets_from_text
    return harvest_secrets_from_text(text)

