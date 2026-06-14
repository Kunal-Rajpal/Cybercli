# cybercli/core/osint_utils.py
import requests, re
from typing import List

def query_crtsh(domain: str) -> List[str]:
    out = []
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=12, headers={"User-Agent": "cybercli/1.0"})
        if r.status_code == 200:
            seen = set()
            for item in r.json():
                for n in str(item.get("name_value", "")).split("\n"):
                    if n and n not in seen:
                        seen.add(n); out.append(n)
    except Exception:
        pass
    return out

def wayback_urls(domain: str):
    try:
        r = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey",timeout=15)
        return sorted(set(r.text.splitlines()))
    except Exception:
        return []

def extract_js_endpoints(js_urls):
    endpoints = []
    for js in js_urls[:30]:
        try:
            r = requests.get(js,timeout=10)
            endpoints += re.findall(r"[\"'](https?://[^\s\"']+)[\"']", r.text)
        except Exception:
            pass
    return sorted(set(endpoints))

