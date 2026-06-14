#!/usr/bin/env python3
# cybercli/core/websec_core.py
# -*- coding: utf-8 -*-
"""
Web application security core helpers (safe defaults).

Features:
 - simple HTTP header analysis
 - robots.txt fetch & parse
 - technology fingerprinting (via headers, meta tags, common endpoints)
 - limited crawler (depth-limited, same-host only)
 - basic WAF detection heuristics
 - parameter discovery from URLs and HTML forms
 - safe directory discovery (HEAD requests; optional GET)
 - payload suggestion generator for manual testing (SQLi/XSS) — suggestions only, no auto-exec
 - simple HTML + TXT report writer (writes under reports/<target>/<stamp>/websec_*)
"""

from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import datetime, time, json, re, socket, ssl, random, html as htmlmod

# optional deps
try:
    import requests
except Exception:
    requests = None

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

# small helpers copied/kept minimal to avoid heavy coupling
def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p

def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def _escape_html(s: str) -> str:
    return htmlmod.escape(s or "")

# small HTML writer used by this module (keeps reports local & simple)
CSS = """
body{background:#0b0f12;color:#d7fbd7;font-family:ui-monospace,Consolas,Monaco,monospace;padding:12px}
.card{background:#0f1620;padding:12px;border-radius:8px;margin-bottom:12px}
pre{white-space:pre-wrap;word-break:break-word}
"""

def write_simple_report(outdir: Path, base: str, summary: str, body: str) -> Dict[str,str]:
    outdir = ensure_dir(outdir)
    txt = outdir / f"{base}.txt"
    html = outdir / f"{base}.html"
    started = now_stamp()
    txt.write_text(f"# {base}\n# {started}\n\nSUMMARY:\n{summary}\n\nBODY:\n{body}\n", encoding="utf-8", errors="ignore")
    html_body = f"""<!doctype html><html><head><meta charset='utf-8'><title>{base}</title><style>{CSS}</style></head>
<body>
<div class="card"><h2>{_escape_html(base)}</h2><small>{_escape_html(started)}</small></div>
<div class="card"><b>Summary</b><pre>{_escape_html(summary)}</pre></div>
<div class="card"><b>Details</b><pre>{_escape_html(body)}</pre></div>
</body></html>"""
    html.write_text(html_body, encoding="utf-8", errors="ignore")
    return {"txt": str(txt.resolve()), "html": str(html.resolve())}

# ---------------- core helpers ----------------
def _check_requests_available() -> Tuple[bool,str]:
    if requests is None:
        return False, "requests library not installed (pip install requests)"
    return True, ""

def _check_bs4_available() -> Tuple[bool,str]:
    if BeautifulSoup is None:
        return False, "bs4 (BeautifulSoup) not installed (pip install beautifulsoup4)"
    return True, ""

# ---------------- HTTP helpers ----------------
DEFAULT_TIMEOUT = 10

def fetch_url_head(url: str, timeout: int = DEFAULT_TIMEOUT, verify: bool = True) -> Tuple[int, Dict[str,str], str]:
    """
    Performs a HEAD then if HEAD not supported falls back to GET with stream.
    Returns (status_code, headers (dict), error_str).
    """
    ok, msg = _check_requests_available()
    if not ok:
        return 0, {}, msg
    headers = {}
    try:
        r = requests.head(url, timeout=timeout, verify=verify, allow_redirects=True)
        headers = dict(r.headers)
        return r.status_code, headers, ""
    except Exception as e:
        try:
            r = requests.get(url, timeout=timeout, verify=verify, stream=True)
            headers = dict(r.headers)
            return r.status_code, headers, ""
        except Exception as e2:
            return 0, {}, f"error: {e2}"

def fetch_url_get(url: str, timeout: int = DEFAULT_TIMEOUT, verify: bool = True) -> Tuple[int, str, str]:
    ok, msg = _check_requests_available()
    if not ok:
        return 0, "", msg
    try:
        r = requests.get(url, timeout=timeout, verify=verify)
        return r.status_code, r.text or "", ""
    except Exception as e:
        return 0, "", f"error: {e}"

# ---------------- robots.txt ----------------
def fetch_robots_txt(base_url: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[int, str]:
    """
    Fetch robots.txt for a base URL (e.g. https://example.com/).
    """
    if not base_url.endswith("/"):
        base_url = base_url + "/"
    url = base_url + "robots.txt"
    code, text, err = fetch_url_get(url, timeout=timeout)
    if err:
        return code, err
    return code, text

# ---------------- fingerprinting ----------------
COMMON_TECH_SIGS = {
    "cloudflare": ["cloudflare"],
    "nginx": ["nginx"],
    "apache": ["apache"],
    "haproxy": ["haproxy"],
    "aws": ["amazonaws", "x-amz-"],
    "nginx-ingress": ["nginx/"],
    "traefik": ["traefik"],
    "akka-http": ["akka-http"],
}

def fingerprint_tech(url: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, List[str]]:
    """
    Returns a mapping of detected components -> evidence.
    Uses headers and a shallow GET for meta tags.
    """
    detected = {}
    code, headers, err = fetch_url_head(url, timeout=timeout)
    if err:
        return {"error": [err]}
    hjoin = " ".join([f"{k}:{v}" for k,v in headers.items()])
    for k, sigs in COMMON_TECH_SIGS.items():
        for s in sigs:
            if s.lower() in hjoin.lower():
                detected.setdefault(k, []).append(f"header:{s}")
    # attempt shallow fetch of HTML meta tags if bs4 available
    ok, errmsg = _check_bs4_available()
    if ok:
        sc, body, berr = fetch_url_get(url, timeout=timeout)
        if sc and body:
            try:
                soup = BeautifulSoup(body, "html.parser")
                meta = " ".join([str(x) for x in soup.find_all("meta")])
                for k, sigs in COMMON_TECH_SIGS.items():
                    for s in sigs:
                        if s.lower() in meta.lower():
                            detected.setdefault(k, []).append(f"meta:{s}")
            except Exception:
                pass
    return detected

# ---------------- WAF detection ----------------
WAF_SIGNATURES = {
    "cloudflare": ["cloudflare"],
    "f5-bigip": ["bigip", "f5"],
    "aws-waf": ["aws-waf", "x-amzn-requestid"],
    "mod_security": ["mod_security", "mod_security_action"],
}

def detect_waf(url: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str,str]:
    """
    Heuristic WAF detection using response headers and a benign probe.
    """
    res = {}
    code, headers, err = fetch_url_head(url, timeout=timeout)
    if err:
        return {"error": err}
    hstr = " ".join([f"{k}:{v}" for k,v in headers.items()]).lower()
    for k, sigs in WAF_SIGNATURES.items():
        for s in sigs:
            if s in hstr:
                res[k] = "header-match"
    # benign probe (use a non-malicious path) to see response differences
    probe = url.rstrip("/") + "/.well-known/security.txt"
    sc, _, perr = fetch_url_head(probe, timeout=timeout)
    # note: we do not send malicious payloads here
    res["probe_status"] = str(sc)
    return res

# ---------------- param discovery ----------------
FORM_PARAM_RE = re.compile(r'<form[^>]*>(.*?)</form>', re.S | re.I)
INPUT_RE = re.compile(r'<input[^>]+name=["\']?([^"\'>\s]+)', re.I)

def discover_parameters(url: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, List[str]]:
    """
    Discover URL parameters and form inputs on the page (non-destructive).
    """
    sc, body, err = fetch_url_get(url, timeout=timeout)
    if err:
        return {"error": [err]}
    params = {}
    # URL query params (if provided)
    try:
        parsed = requests.utils.urlparse(url)
        q = requests.utils.parse_qs(parsed.query)
        if q:
            params["url_query"] = list(q.keys())
    except Exception:
        pass
    # simple form parsing (if bs4 exists, use that)
    ok, msg = _check_bs4_available()
    if ok:
        try:
            soup = BeautifulSoup(body, "html.parser")
            forms = []
            for f in soup.find_all("form"):
                fid = f.get("id") or f.get("name") or f.get("action") or "form"
                inputs = [i.get("name") for i in f.find_all("input") if i.get("name")]
                forms.append({"id": fid, "action": f.get("action"), "inputs": inputs})
            params["forms"] = forms
        except Exception:
            pass
    else:
        # fallback naive regex parse
        for m in FORM_PARAM_RE.finditer(body):
            form_block = m.group(1)
            names = INPUT_RE.findall(form_block)
            if names:
                params.setdefault("forms_regex", []).append(names)
    return params

# ---------------- crawler (safe, depth-limited, same-host) ----------------
def _same_host(base: str, other: str) -> bool:
    try:
        basep = requests.utils.urlparse(base)
        outp = requests.utils.urlparse(other)
        return basep.netloc == outp.netloc
    except Exception:
        return False

def crawl_site(start_url: str, depth: int = 2, max_pages: int = 200, timeout: int = DEFAULT_TIMEOUT) -> Dict[str,Any]:
    """
    Very small BFS crawler that stays on same host, respects robots.txt only by default (no auto-scan).
    Returns discovered URLs and forms/params summary.
    """
    ok, msg = _check_requests_available()
    if not ok:
        return {"error": msg}
    ok2, msg2 = _check_bs4_available()
    seen = set()
    queue = [(start_url, 0)]
    results = {"pages": [], "forms_found": 0, "errors": []}
    while queue and len(seen) < max_pages:
        url, d = queue.pop(0)
        if url in seen:
            continue
        if d > depth:
            continue
        try:
            sc, body, err = fetch_url_get(url, timeout=timeout)
            if err:
                results["errors"].append({"url": url, "err": err})
                seen.add(url)
                continue
            seen.add(url)
            page_record = {"url": url, "status": sc}
            # parse links if bs4 available
            if ok2 and body:
                try:
                    soup = BeautifulSoup(body, "html.parser")
                    links = []
                    for a in soup.find_all("a", href=True):
                        href = a.get("href")
                        if not href:
                            continue
                        joined = requests.compat.urljoin(url, href)
                        if _same_host(start_url, joined) and joined not in seen:
                            links.append(joined)
                            if d+1 <= depth:
                                queue.append((joined, d+1))
                    page_record["links_count"] = len(links)
                    # forms count
                    forms = soup.find_all("form")
                    page_record["forms"] = len(forms)
                    results["forms_found"] += len(forms)
                except Exception:
                    pass
            results["pages"].append(page_record)
        except Exception as e:
            results["errors"].append({"url": url, "err": str(e)})
    return results

# ---------------- dir discovery (HEAD-based safe) ----------------
def dir_discovery(base_url: str, wordlist: Optional[List[str]] = None, timeout: int = DEFAULT_TIMEOUT, do_get: bool = False, max_checks: int = 500) -> Dict[str,List[str]]:
    """
    Do HEAD requests against candidate paths. Returns lists of found and not found.
    Set do_get=True to fetch body (use carefuly). This function is conservative by default.
    """
    ok, msg = _check_requests_available()
    if not ok:
        return {"error": msg}
    if not base_url.endswith("/"):
        base_url = base_url + "/"
    found = []
    not_found = []
    wordlist = wordlist or ["admin","login","robots.txt",".git","backup","wp-admin","phpinfo.php","config.php"]
    checks = 0
    for p in wordlist:
        if checks >= max_checks:
            break
        checks += 1
        url = base_url + p.lstrip("/")
        try:
            r = requests.head(url, timeout=timeout, allow_redirects=True)
            if r.status_code < 400:
                found.append({"path": p, "status": r.status_code})
                if do_get:
                    try:
                        g = requests.get(url, timeout=timeout)
                        found[-1]["body_preview"] = (g.text or "")[:2000]
                    except Exception:
                        pass
            else:
                not_found.append({"path": p, "status": r.status_code})
        except Exception as e:
            not_found.append({"path": p, "err": str(e)})
    return {"found": found, "not_found": not_found}

# ---------------- payload suggestions (NO EXECUTION) ----------------
def sqli_payloads() -> List[str]:
    return [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1-- ",
        "' OR '1'='1' /*",
    ]

def xss_payloads() -> List[str]:
    return [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>",
    ]

def payload_suggestions() -> Dict[str,List[str]]:
    """
    Return payload suggestions for manual testing. This module will NOT send them automatically.
    """
    return {"sqli": sqli_payloads(), "xss": xss_payloads()}

# ---------------- consolidated scan (safe, non-destructive) ----------------
def webapp_quick_scan(target_url: str, reports_root: Path, target_name: str, crawl: bool = True, crawl_depth: int = 1, dir_brute: bool = False, dir_words: Optional[List[str]] = None) -> Dict[str,str]:
    """
    Run a non-destructive quick scan:
    - fetch headers
    - fingerprint tech
    - detect waf
    - discover simple params
    - optional crawl (depth-limited)
    - optional dir discovery (HEAD only)
    Writes an HTML + TXT report into reports_root/target_name/<stamp>/websec_quick_scan_*
    """
    run_root = ensure_dir(reports_root / target_name / now_stamp())
    outdir = ensure_dir(run_root / "websec")
    started = now_stamp()
    parts = []
    parts.append(f"Target: {target_url}")
    sc, headers, herr = fetch_url_head(target_url)
    parts.append(f"HEAD status: {sc}")
    parts.append(f"Headers: {json.dumps(headers, indent=2)}")
    tech = fingerprint_tech(target_url)
    parts.append(f"Fingerprint: {json.dumps(tech, indent=2)}")
    waf = detect_waf(target_url)
    parts.append(f"WAF detection: {json.dumps(waf, indent=2)}")
    params = discover_parameters(target_url)
    parts.append(f"Parameters/forms: {json.dumps(params, indent=2)}")
    if crawl:
        parts.append("Starting crawl (safe, depth-limited)...")
        cr = crawl_site(target_url, depth=crawl_depth)
        parts.append(f"Crawl: {json.dumps(cr, indent=2)}")
    if dir_brute:
        parts.append("Starting directory discovery (HEAD-based)...")
        dr = dir_discovery(target_url, wordlist=dir_words)
        parts.append(f"Dir discovery: {json.dumps(dr, indent=2)}")
    parts.append("Payload suggestions (for manual testing):")
    parts.append(json.dumps(payload_suggestions(), indent=2))
    body = "\n\n".join(parts)
    summary = f"Quick webapp scan for {target_url}"
    rep = write_simple_report(outdir, "websec_quick_scan", summary, body)
    return rep

