# cybercli/core/scan_core.py
# -*- coding: utf-8 -*-
import json, re, socket, subprocess, time, random, shutil
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from rich.console import Console

console = Console()
requests.packages.urllib3.disable_warnings()

# -------------------------
# Helpers
# -------------------------
def _to_jsonable(obj: Any) -> Any:
    try:
        if obj is None or isinstance(obj, (str, int, float, bool)):
            return obj
        if isinstance(obj, dict):
            return {str(k): _to_jsonable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            return [_to_jsonable(v) for v in obj]
        return str(obj)
    except Exception:
        return str(obj)

def save_result(outdir: Path, filename: str, data: Any) -> str:
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / filename
    with open(path, "w", encoding="utf-8") as f:
        if isinstance(data, (dict, list)):
            json.dump(_to_jsonable(data), f, indent=2, ensure_ascii=False)
        else:
            f.write(str(data))
    return str(path)

# -------------------------
# Vibes / cinematic helpers
# -------------------------
def _rand_line(chars="01▮▯░▒▓", n=64):
    return "".join(random.choice(chars) for _ in range(n))

def boss_scan_vibes(target: str, style: str = "normal"):
    if style == "ultra":
        console.print(f"[bold red]⚡ ULTRA-SCAN • TARGET: {target} ⚡[/bold red]")
    else:
        console.print(f"[bold magenta]:: Scan starting on {target} ::[/bold magenta]")
    for _ in range(6 if style=="normal" else 12):
        console.print(f"[green]{_rand_line()}[/green]")
        time.sleep(0.05)
    console.print("[cyan]// scan engines warm • telemetry live[/cyan]\n")

def cinematic_inject_animation(lines, delay: float = 0.06):
    for ln in lines:
        console.print(ln)
        time.sleep(delay)

# -------------------------
# Network / probe primitives
# -------------------------
COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,587,8080,8443,9200,3306,5432]

def quick_tcp_connect(ip: str, ports: list[int], timeout: float = 0.5) -> list[int]:
    open_ports = []
    for p in ports:
        try:
            s = socket.socket()
            s.settimeout(timeout)
            if s.connect_ex((ip, p)) == 0:
                open_ports.append(p)
            s.close()
        except Exception:
            pass
    return open_ports

def run_nmap_on_ip(ip: str, args: Optional[list[str]] = None, timeout: int = 300) -> Dict[str, Any]:
    out = {"ip": ip, "nmap_raw": None, "open_ports": []}
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        out["error"] = "nmap_binary_missing"
        return out
    cmd = [nmap_bin, "-sV", "-Pn", "--host-timeout", "30s", ip]
    if args:
        cmd = [nmap_bin] + args + [ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out["nmap_raw"] = proc.stdout
        for line in proc.stdout.splitlines():
            if "open" in line and ("/tcp" in line or "/udp" in line):
                try:
                    port = int(line.split("/")[0]) if "/" in line else None
                except Exception:
                    port = None
                service = " ".join(line.split()[2:]) if len(line.split()) >= 3 else ""
                out["open_ports"].append({"port": port, "service": service, "raw": line})
    except Exception as e:
        out["error"] = str(e)
    return out

# -------------------------
# HTTP + content probe
# -------------------------
def normalize_base_url(target: str) -> str:
    parsed = urlparse(target.strip())
    return f"{parsed.scheme}://{parsed.hostname}" if parsed.scheme else f"https://{target}"

def http_probe(base_url: str, timeout: int = 8) -> Dict[str, Any]:
    info = {}
    headers = {"User-Agent":"cybercli/1.0"}
    try:
        r = requests.get(base_url, timeout=timeout, allow_redirects=True, verify=False, headers=headers)
        info["status_code"] = r.status_code
        info["final_url"] = r.url
        info["headers"] = dict(r.headers)
        info["cookies"] = {c.name: c.value for c in r.cookies}
        if "html" in r.headers.get("Content-Type",""):
            soup = BeautifulSoup(r.text, "html.parser")
            info["title"] = soup.title.string.strip() if soup.title else None
            info["links"] = [a.get("href") for a in soup.find_all("a", href=True)]
            info["scripts"] = [s.get("src") for s in soup.find_all("script", src=True)]
            info["body_snippet"] = r.text[:4000]
    except Exception as e:
        info["error"] = str(e)
    return info

def fetch_robots(base_url: str) -> Dict[str, Any]:
    try:
        r = requests.get(base_url.rstrip("/") + "/robots.txt", timeout=6, verify=False)
        return {"status_code": r.status_code, "text": r.text if r.status_code < 400 else ""}
    except Exception as e:
        return {"error": str(e)}

def try_sitemap(base_url: str) -> Dict[str, Any]:
    out = {"found": False, "urls": []}
    for p in ["/sitemap.xml", "/sitemap_index.xml"]:
        try:
            r = requests.get(base_url.rstrip("/") + p, timeout=6, verify=False)
            if r.status_code < 400 and "<url" in r.text:
                out["found"] = True
                out["urls"] = re.findall(r"<loc>([^<]+)</loc>", r.text)
                break
        except Exception: continue
    return out

def extract_js_endpoints_from_list(js_urls: list[str], limit: int = 30) -> list[str]:
    endpoints = set()
    for js in js_urls[:limit]:
        try:
            if js.startswith("http"):
                r = requests.get(js, timeout=6, verify=False)
                for m in re.findall(r"(https?://[^\s'\"\\)]+)", r.text):
                    endpoints.add(m.strip())
        except Exception: continue
    return sorted(endpoints)

def detect_tokens_in_text(text: str) -> Dict[str, list[str]]:
    patterns = {
        "aws_key": r"AKIA[0-9A-Z]{16}",
        "google_api": r"AIza[0-9A-Za-z_\-]{35}",
        "jwt_like": r"eyJ[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+",
    }
    out = {}
    for name, rgx in patterns.items():
        m = re.findall(rgx, text or "", flags=re.IGNORECASE)
        if m: out[name] = list(set(m))
    return out

# -------------------------
# NEW: CVE map + Cloud enum + Fuzz
# -------------------------
CVE_BANNER_MAP = {
    "Apache/2.4.49": ["CVE-2021-41773","CVE-2021-42013"],
    "OpenSSH_7.2":   ["CVE-2016-0777"],
    "Log4j":         ["CVE-2021-44228"],
}

def map_cves_from_nmap(nmap_results: list[Dict[str, Any]]) -> list[str]:
    hits = []
    for host in nmap_results or []:
        for p in host.get("open_ports", []):
            banner = p.get("service") or p.get("raw","")
            for key,cves in CVE_BANNER_MAP.items():
                if key.lower() in banner.lower():
                    hits.extend(cves)
    return sorted(set(hits))

def cloud_enum_basic(domain: str) -> Dict[str, bool]:
    checks = {
        "aws_s3": f"https://{domain}.s3.amazonaws.com",
        "azure_blob": f"https://{domain}.blob.core.windows.net",
        "gcp_gcs": f"https://storage.googleapis.com/{domain}",
    }
    out={}
    for name,url in checks.items():
        try:
            r=requests.head(url,timeout=4,verify=False)
            out[name]= r.status_code in (200,403)
        except Exception: out[name]=False
    return out

def fuzz_reflection(base_url: str) -> Dict[str,list[str]]:
    payloads = {
        "sqli":["' OR '1'='1","\" OR \"1\"=\"1"],
        "xss":["<script>alert(1)</script>","\"><img src=x onerror=alert(1)>"],
    }
    reflections={}
    try:
        for cat,pl_list in payloads.items():
            found=[]
            for pl in pl_list:
                r=requests.get(base_url+"?q="+pl,timeout=5,verify=False)
                if pl in r.text:
                    found.append(pl)
            if found: reflections[cat]=found
    except Exception: pass
    return reflections

# -------------------------
# Orchestration
# -------------------------
def run_scan(
    target:str, base_url:Optional[str], outdir:str,
    do_quick=True, do_nmap=False, do_http=True, do_robots=True, do_sitemap=True,
    do_js=True, do_tokens=True, do_links=True, do_report=True,
    verbose=True, operator:Optional[str]=None,
    simulate_exploit=False, cinematic_mode=False,
    fuzz=False,
):
    domain=target.strip()
    target_dir=Path(outdir)/domain
    target_dir.mkdir(parents=True, exist_ok=True)
    if not base_url: base_url=normalize_base_url(domain)

    result={"target":domain,"base_url":base_url,"timestamp":time.time(),
        "quick_tcp":[],"nmap":[],"http_probe":{},"robots":{},"sitemap":{},
        "js_endpoints":[],"tokens":{},"links":[],"cve_hints":[],"cloud":{},"fuzz":{}}

    if verbose: console.print(f"[bold cyan]▶ Scan:[/bold cyan] {domain}  [dim]{base_url}[/dim]")

    try: ips=[i[4][0] for i in socket.getaddrinfo(domain,None)]
    except: ips=[]
    ips=sorted(set(ips))

    if do_quick and ips:
        result["quick_tcp"]=[{"ip":ip,"open_ports":quick_tcp_connect(ip,COMMON_PORTS)} for ip in ips]
        save_result(target_dir,"quick_tcp.json",result["quick_tcp"])

    if do_nmap and ips:
        nm=[run_nmap_on_ip(ip) for ip in ips]
        result["nmap"]=nm
        save_result(target_dir,"nmap.json",nm)
        result["cve_hints"]=map_cves_from_nmap(nm)

    if do_http:
        info=http_probe(base_url)
        result["http_probe"]=info
        save_result(target_dir,"http_probe.json",info)

    if do_robots:
        rinfo=fetch_robots(base_url); result["robots"]=rinfo
        save_result(target_dir,"robots.json",rinfo)

    if do_sitemap:
        s=try_sitemap(base_url); result["sitemap"]=s
        save_result(target_dir,"sitemap.json",s)

    if do_links: 
        result["links"]=result["http_probe"].get("links",[]); 
        save_result(target_dir,"links.json",result["links"])

    if do_js:
        scripts=result["http_probe"].get("scripts",[])
        js_urls=[s if s.startswith("http") else base_url.rstrip("/")+s for s in scripts if s]
        js_endpoints=extract_js_endpoints_from_list(js_urls)
        result["js_endpoints"]=js_endpoints
        save_result(target_dir,"js_endpoints.json",js_endpoints)

    if do_tokens:
        body=result["http_probe"].get("body_snippet","")
        tokens=detect_tokens_in_text(body)
        result["tokens"]=tokens
        save_result(target_dir,"tokens.json",tokens)

    result["cloud"]=cloud_enum_basic(domain)
    save_result(target_dir,"cloud.json",result["cloud"])

    if fuzz:
        result["fuzz"]=fuzz_reflection(base_url)
        save_result(target_dir,"fuzz.json",result["fuzz"])

    result["summary"]={"ips":ips,"http_status":result["http_probe"].get("status_code"),
        "js_endpoints":len(result["js_endpoints"]),
        "tokens":sum(len(v) for v in result["tokens"].values()),
        "cves":result["cve_hints"],"cloud":result["cloud"],
        "fuzz":result["fuzz"]}
    save_result(target_dir,"scan_summary.json",result["summary"])

    console.print(f"[green]✔ Scan done. Artifacts:[/green] {target_dir}")
    return result

