# cybercli/core/recon_core.py
# -*- coding: utf-8 -*-
import base64, io, json, re, socket, ssl, subprocess, time, random, webbrowser, shutil
from datetime import datetime, date
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# third-party
import dns.resolver, requests, tldextract, whois
from bs4 import BeautifulSoup
from rich import print as rprint
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn

console = Console()

# Optional deps (graceful)
try:
    import mmh3
except Exception:
    mmh3 = None

# local module imports (Option B modular)
from .net_utils import quick_connect_scan, run_nmap
from .osint_utils import query_crtsh, wayback_urls, extract_js_endpoints
from .brute_utils import dir_bruteforce, scan_secrets_from_text
from .screen_utils import take_screenshot_playwright, take_screenshot_selenium, take_screenshot_wkhtml
from .graph_utils import render_asset_graph
# Note: import both render_html_report and build_html_and_pdf_report (wrapper)
from .report_utils import render_html_report, build_html_and_pdf_report
from .cloud_enum import cloud_enum
from .darknet_utils import search_darknet_indicators
from .supply_chain import enumerate_supply_chain

# -------------------------
# Config & allowlist helpers
# -------------------------
def load_config() -> dict:
    try:
        import yaml
        cfg_path = Path.cwd() / "config.yml"
        if cfg_path.exists():
            with open(cfg_path, "r") as f:
                return yaml.safe_load(f) or {}
    except Exception:
        pass
    return {}

def allowed_target(target: str) -> bool:
    cfg = load_config()
    allow = cfg.get("ALLOWLIST", [])
    if not allow:
        return True
    return any(a for a in allow if a in target)

# -------------------------
# Vibes
# -------------------------
def _rand_line(chars="01▮▯░▒▓", n=64):
    return "".join(random.choice(chars) for _ in range(n))

def hacking_vibes(target: str):
    console.print(f"[bold magenta]:: Initiating Recon on {target} ::[/bold magenta]")
    for _ in range(8):
        console.print(f"[green]{_rand_line()}[/green]")
        time.sleep(0.07)
    console.print("[cyan]// link: entropy stabilized • payload engines armed[/cyan]\n")

def ultra_vibes(target: str):
    phases = ["[Reconnaissance]", "[Enumeration]", "[Fingerprinting]", "[OSINT]", "[Reporting]"]
    console.print(f"[bold red]⚡ ULTRAVIBES • TARGET: {target} ⚡[/bold red]")
    with Progress(SpinnerColumn(), *Progress.get_default_columns(), TimeElapsedColumn()) as prog:
        t = prog.add_task("Matrix compiling…", total=len(phases) * 30)
        for ph in phases:
            for i in range(30):
                if i % 6 == 0:
                    console.print(f"[green]{_rand_line()}[/green]")
                time.sleep(0.03)
                prog.update(t, advance=1, description=f"{ph}")
    console.print("[bold green]>> sequence complete • entering report phase[/bold green]\n")

# -------------------------
# Helpers (normalize / json-safe)
# -------------------------
def normalize_target(target_input: str) -> Tuple[str, str]:
    t = target_input.strip()
    parsed = urlparse(t)
    if parsed.scheme:
        domain = parsed.hostname or t
        base_url = f"{parsed.scheme}://{parsed.hostname}"
    else:
        domain = tldextract.extract(t).registered_domain or t
        base_url = f"https://{domain}"
    return domain, base_url

def _to_jsonable(obj: Any) -> Any:
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_jsonable(v) for v in obj]
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

def append_line(outdir: Path, filename: str, line: str) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / filename
    with open(path, "a", encoding="utf-8") as f:
        f.write(line.rstrip() + "\n")

# -------------------------
# Recon primitives (some duplicated for clarity)
# -------------------------
def dns_query_all(name: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = resolver.timeout = 5
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
        try:
            out[rtype] = [r.to_text() for r in resolver.resolve(name, rtype)]
        except Exception:
            out[rtype] = []
    return out

def get_certificate_info(host: str, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
    res: Dict[str, Any] = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                res["subject"] = {k: v for part in cert.get("subject", ()) for k, v in [part[0]]}
                res["issuer"] = {k: v for part in cert.get("issuer", ()) for k, v in [part[0]]}
                res["notBefore"], res["notAfter"] = cert.get("notBefore"), cert.get("notAfter")
                san = cert.get("subjectAltName", ())
                res["san"] = [x[1] for x in san] if san else []
                try:
                    res["tls_version"] = ssock.version()
                    res["cipher"] = ssock.cipher()
                except Exception:
                    pass
    except Exception as e:
        res["error"] = str(e)
    return res

def fetch_url_info(url: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        r = requests.get(url, timeout=8, allow_redirects=True, verify=False,
                         headers={"User-Agent": "cybercli/1.0"})
        info["status_code"], info["final_url"] = r.status_code, r.url
        info["headers"], info["cookies"] = dict(r.headers), {c.name: c.value for c in r.cookies}
        if "html" in r.headers.get("Content-Type", ""):
            soup = BeautifulSoup(r.text, "html.parser")
            info["title"] = soup.title.string.strip() if soup.title else None
            info["links"] = [a.get("href") for a in soup.find_all("a", href=True)]
            info["scripts"] = [s.get("src") for s in soup.find_all("script", src=True)]
            info["emails"] = list(set(re.findall(r"[a-zA-Z0-9.\-_+]+@[a-zA-Z0-9.\-_+]+\.[a-zA-Z]+", r.text)))
    except Exception as e:
        info["error"] = str(e)
    return info

def favicon_hash(base_url: str) -> Optional[int]:
    if not mmh3:
        return None
    try:
        r = requests.get(f"{base_url}/favicon.ico",timeout=10)
        if r.status_code == 200:
            return mmh3.hash(base64.encodebytes(r.content))
    except Exception:
        pass
    return None

# -------------------------
# deep helpers (dir brute, secrets)
# -------------------------
def harvest_secrets_from_text(text: str) -> Dict[str, List[str]]:
    SECRET_REGEXPS = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z_\-]{35}",
        "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
        "GitHub Token": r"ghp_[0-9A-Za-z]{36}",
        "Private Key Begin": r"-----BEGIN (RSA|EC|DSA)? ?PRIVATE KEY-----",
        "JWT": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    }
    hits: Dict[str, List[str]] = {}
    for name, rgx in SECRET_REGEXPS.items():
        m = re.findall(rgx, text or "", flags=re.IGNORECASE)
        if m:
            hits[name] = sorted(list(set(m)))
    return hits

def scan_secrets(base_url: str, http_page: Dict[str, Any], outdir: Path) -> Dict[str, List[str]]:
    acc: Dict[str, List[str]] = {}
    try:
        r = requests.get(base_url, timeout=10, allow_redirects=True, verify=False, headers={"User-Agent":"cybercli/1.0"})
        hits = harvest_secrets_from_text(r.text)
        for k,v in hits.items():
            acc.setdefault(k, []).extend(v)
    except Exception:
        pass
    # scan linked JS (limited)
    js_urls = []
    for s in (http_page.get("scripts") or []):
        if not s:
            continue
        if s.startswith("http"):
            js_urls.append(s)
        elif s.startswith("/"):
            js_urls.append(base_url.rstrip("/") + s)
    for js in js_urls[:40]:
        try:
            r = requests.get(js, timeout=10)
            hits = harvest_secrets_from_text(r.text)
            for k,v in hits.items():
                acc.setdefault(k, []).extend(v)
        except Exception:
            continue
    for k in list(acc.keys()):
        acc[k] = sorted(list(set(acc[k])))
    if acc:
        save_result(outdir, "secrets.json", acc)
    return acc

# -------------------------
# screenshots orchestration
# -------------------------
def take_screenshot(url: str, out_png: Path, timeout: int = 20) -> bool:
    # Normalize URL
    if not url.startswith("http"):
        url = "https://" + url.lstrip("/")

    if take_screenshot_playwright(url, out_png, timeout=timeout):
        return True
    if take_screenshot_selenium(url, out_png, timeout=timeout):
        return True
    if take_screenshot_wkhtml(url, out_png):
        return True
    return False

def capture_screens(base_url: str, dirs: List[Dict[str, Any]], subs: List[str], target_dir: Path) -> List[str]:
    saved = []
    screens_dir = target_dir / "screens"
    screens_dir.mkdir(parents=True, exist_ok=True)
    if take_screenshot(base_url, screens_dir / "base.png"):
        saved.append("screens/base.png")
    for d in (dirs or [])[:6]:
        try:
            u = d.get("url") or (base_url.rstrip("/") + d.get("path", ""))
            name = re.sub(r"[^a-zA-Z0-9_.-]+","_", (d.get("path") or "path")).strip("_")
            if take_screenshot(u, screens_dir / f"dir_{name}.png"):
                saved.append(f"screens/dir_{name}.png")
        except Exception:
            continue
    for sd in (subs or [])[:3]:
        if sd.startswith("*."): continue
        scheme = "https"
        url = f"{scheme}://{sd}"
        safe = re.sub(r"[^a-zA-Z0-9_.-]+","_", sd)
        if take_screenshot(url, screens_dir / f"sub_{safe}.png"):
            saved.append(f"screens/sub_{safe}.png")
    if saved:
        save_result(target_dir, "screens.json", saved)
    return saved

# -------------------------
# small TRA
# -------------------------
def tra_basic(result: Dict[str, Any]) -> Dict[str, Any]:
    criticality = 3
    if (result.get("http", {}).get(result.get("base_url",""), {}).get("emails")):
        criticality += 1
    if any("/admin" in (d.get("path") or "") or "login" in (d.get("path") or "") for d in result.get("dirbrute", []) or []):
        criticality += 1
    criticality = min(5, criticality)

    likelihood = 1
    open_count = sum(len(x.get("open_ports", [])) for x in result.get("quick_open_ports", []))
    if open_count >= 2: likelihood += 1
    if result.get("secrets"): likelihood += 2
    if result.get("cve_hints"): likelihood += 1
    likelihood = min(5, likelihood)

    risk = min(5, round((criticality * likelihood) / 5 + 0.5))
    return {
        "criticality": criticality,
        "likelihood": likelihood,
        "risk_score_5": risk,
        "notes": {
            "open_ports": open_count,
            "secrets": list(result.get("secrets", {}).keys()),
            "cve_hints": result.get("cve_hints", []),
        }
    }

# -------------------------
# Main orchestrator
# -------------------------
def run_recon(
    target: str,
    base_url: Optional[str],
    outdir: str,
    do_whois: bool,
    do_dns: bool,
    do_subdomains: bool,
    do_ports: bool,
    do_http: bool,
    do_nmap: bool,
    do_osint: bool,
    do_deep: bool,
    do_screens: bool,
    do_tra: bool,
    do_graph: bool,
    do_report: bool,
    verbose: bool,
    do_supply: bool = False # New default False
) -> None:
    if not allowed_target(target):
        rprint(f"[red]Target '{target}' is not in ALLOWLIST (config.yml). Aborting.[/red]")
        return

    domain = tldextract.extract(target).registered_domain or target
    target_dir = Path(outdir) / domain
    target_dir.mkdir(parents=True, exist_ok=True)
    if not base_url:
        _, base_url = normalize_target(domain)

    if verbose:
        rprint(f"[bold cyan]▶ Starting Recon:[/bold cyan] [white]{domain}[/white]  [dim]{base_url}[/dim]")

    result: Dict[str, Any] = {
        "target": domain, "base_url": base_url, "timestamp": time.time(),
        "dns": {}, "whois": {}, "cert": {}, "crtsh_subdomains": [],
        "http": {}, "ips": [], "quick_open_ports": [], "nmap": [],
        "tech_hints": {}, "vibe_warnings": []
    }

    progress = None
    if verbose:
        progress = Progress(SpinnerColumn(), *Progress.get_default_columns(), TimeElapsedColumn())
        progress.start()
        task = progress.add_task("[bold cyan]Recon running...", total=None)

    try:
        # WHOIS
        if do_whois:
            try:
                w = whois.whois(domain)
                result["whois"] = _to_jsonable(dict(w))
                save_result(target_dir, "whois.json", result["whois"])
                if verbose: rprint("[cyan]• WHOIS saved[/cyan]")
            except Exception as e:
                result["whois_error"] = str(e); append_line(target_dir, "warnings.txt", f"whois_error: {e}")

        # DNS
        if do_dns:
            try:
                result["dns"] = dns_query_all(domain)
                save_result(target_dir, "dns.json", result["dns"])
                if verbose: rprint("[cyan]• DNS records saved[/cyan]")
            except Exception as e:
                result["dns_error"] = str(e); append_line(target_dir, "warnings.txt", f"dns_error: {e}")

        # Cert
        try:
            cert_info = get_certificate_info(domain)
            result["cert"] = cert_info
            save_result(target_dir, "cert.json", cert_info)
            for san in cert_info.get("san", []) or []:
                if san and san not in result["crtsh_subdomains"]:
                    result["crtsh_subdomains"].append(san)
            if verbose: rprint("[cyan]• Certificate info saved[/cyan]")
        except Exception as e:
            result["cert_error"] = str(e); append_line(target_dir, "warnings.txt", f"cert_error: {e}")

        # Subdomains (crt.sh)
        if do_subdomains:
            try:
                crt = query_crtsh(domain)
                for x in crt:
                    if x not in result["crtsh_subdomains"]:
                        result["crtsh_subdomains"].append(x)
                save_result(target_dir, "subdomains.json", result["crtsh_subdomains"])
                if verbose: rprint(f"[cyan]• Subdomains: {len(result['crtsh_subdomains'])}[/cyan]")
            except Exception as e:
                result["subdomains_error"] = str(e); append_line(target_dir, "warnings.txt", f"crtsh_error: {e}")

        # IP resolution
        ips = set()
        try:
            for a in result.get("dns", {}).get("A", []):
                if a: ips.add(a.split()[0])
        except Exception:
            pass
        try:
            for entry in socket.getaddrinfo(domain, None):
                ips.add(entry[4][0])
        except Exception:
            pass
        result["ips"] = sorted(list(ips))
        save_result(target_dir, "ips.json", result["ips"])
        if verbose: rprint(f"[cyan]• IPs: {', '.join(result['ips']) if result['ips'] else 'none'}[/cyan]")

        # Quick ports
        if do_ports and result["ips"]:
            common_ports = [21,22,25,53,80,110,143,443,445,587,993,995,8080,8443]
            quick = []
            for ip in result["ips"]:
                openp = quick_connect_scan(ip, common_ports)
                quick.append({"ip": ip, "open_ports": openp})
            result["quick_open_ports"] = quick
            save_result(target_dir, "quick_ports.json", quick)
            if verbose: rprint("[cyan]• Quick port scan saved[/cyan]")

        # HTTP
        if do_http:
            http_info = fetch_url_info(base_url)
            result["http"][base_url] = http_info
            save_result(target_dir, "http.json", result["http"])
            if verbose: rprint("[cyan]• HTTP probe saved[/cyan]")

        # Tech hints
        headers = {}
        if result["http"].get(base_url):
            headers = result["http"][base_url].get("headers", {}) or {}
        if headers:
            result["tech_hints"] = {
                "server_header": headers.get("Server"),
                "x_powered_by": headers.get("X-Powered-By") or headers.get("x-powered-by"),
                "csp": headers.get("Content-Security-Policy"),
            }

        # OSINT
        if do_osint:
            rev_all = []
            for ip in result.get("ips", []):
                try:
                    r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}",timeout=12)
                    rev = [x.strip() for x in r.text.splitlines() if x.strip() and "No records" not in r.text]
                except Exception:
                    rev = []
                if rev: rev_all.extend(rev)
            if rev_all:
                result["reverse_ip_domains"] = sorted(list(set(rev_all)))
                save_result(target_dir, "reverse_ip_domains.txt", "\n".join(result["reverse_ip_domains"]))
                if verbose: rprint(f"[cyan]• Reverse IP domains: {len(result['reverse_ip_domains'])}[/cyan]")

            wb = wayback_urls(domain)
            if wb:
                result["wayback_urls"] = wb
                save_result(target_dir, "wayback_urls.txt", "\n".join(wb))
                if verbose: rprint(f"[cyan]• Wayback URLs: {len(wb)}[/cyan]")

            js_urls = []
            page = result["http"].get(base_url, {})
            for s in (page.get("scripts") or []):
                if s and s.startswith("http"):
                    js_urls.append(s)
                elif s and s.startswith("/"):
                    js_urls.append(base_url.rstrip("/") + s)
            if "wayback_urls" in result:
                for u in result["wayback_urls"]:
                    if u.endswith(".js"):
                        js_urls.append(u)
            if js_urls:
                endpoints = extract_js_endpoints(sorted(set(js_urls))[:60])
                if endpoints:
                    result["js_endpoints"] = endpoints
                    save_result(target_dir, "js_endpoints.txt", "\n".join(endpoints))
                    if verbose: 
                        rprint(f"[cyan]• JS endpoints: {len(endpoints)})[/cyan]")

            fav_hash = favicon_hash(base_url)
            if fav_hash is not None:
                result["favicon_hash"] = fav_hash
                save_result(target_dir, "favicon_hash.txt", str(fav_hash))
                if verbose: rprint(f"[cyan]• Favicon hash: {fav_hash}[/cyan]")

        # DEEP
        if do_deep:
            dirs = dir_bruteforce(base_url, target_dir)
            if dirs:
                result["dirbrute"] = dirs
                if verbose: 
                    rprint(f"[cyan]• Dir brute hits: {len(dirs)})[/cyan]")

            secrets = scan_secrets(base_url, result["http"].get(base_url, {}), target_dir)
            if secrets:
                result["secrets"] = secrets
                if verbose: rprint(f"[cyan]• Secrets found: {sum(len(v) for v in secrets.values())}[/cyan]")

            ch = []
            for key, pat, msg in [
                ("Server", r"Apache/2\.4\.49\b", "CVE-2021-41773"),
                ("Server", r"Apache/2\.4\.50\b", "CVE-2021-42013"),
                ("X-Powered-By", r"PHP/5\.", "PHP5 EOL"),
            ]:
                val = headers.get(key) or headers.get(key.lower())
                if val and re.search(pat, str(val)):
                    ch.append(f"{key}={val} -> {msg}")
            if ch:
                result["cve_hints"] = ch
                save_result(target_dir, "cve_hints.txt", "\n".join(ch))
                if verbose: rprint(f"[cyan]• CVE hints: {len(ch)}[/cyan]")

            sec = {}
            for path in ["/.well-known/security.txt", "/security.txt"]:
                try:
                    r = requests.get(base_url.rstrip("/") + path, timeout=8, verify=False)
                    if r.status_code < 400:
                        sec["url"] = r.url
                        sec["status"] = r.status_code
                        sec["content"] = r.text[:5000]
                        break
                except Exception:
                    pass
            if sec:
                result["security_txt"] = sec
                if verbose: rprint("[cyan]• security.txt present[/cyan]")

        # Supply Chain (advanced)
        if do_supply:
            try:
                sc = enumerate_supply_chain(
                    domain=domain,
                    base_url=base_url,
                    http_info=result.get("http", {}).get(base_url, {}),
                    dns_records=result.get("dns", {}),
                    wayback_urls=result.get("wayback_urls", []),
                    whois_obj=result.get("whois", {}),
                    out_dir=target_dir
                )
                # save a summary placeholder (actual enumerate_supply_chain should save its own files)
                result["supply_chain"] = {"summary": sc.get("summary", {}), "files": sc.get("files", []) if isinstance(sc, dict) else []}
                if verbose: rprint("[magenta]• Supply chain mapping saved[/magenta]")
            except Exception as e:
                append_line(target_dir, "warnings.txt", f"supply_chain_err: {e}")

        # Nmap
        if do_nmap and result["ips"]:
            nm_all = []
            for ip in result["ips"]:
                if verbose: rprint(f"[yellow][~] Running nmap on {ip}[/yellow]")
                nm_all.append(run_nmap(ip))
            result["nmap"] = nm_all
            save_result(target_dir, "nmap.json", nm_all)
            if verbose: rprint("[cyan]• Nmap summary saved[/cyan]")

        # Screens
        if do_screens:
            scr = capture_screens(base_url, result.get("dirbrute", []), result.get("crtsh_subdomains", []), target_dir)
            if scr:
                result["screens"] = scr
                if verbose: rprint(f"[cyan]• Screens captured: {len(scr)}[/cyan]")
            else:
                append_line(target_dir, "warnings.txt", "screenshot_backend: none available or failed")

        # Cloud & Darknet (new modules)
        try:
            c = cloud_enum(domain, target_dir)
            result["cloud_enum"] = c
            if verbose: rprint(f"[magenta]• Cloud enum saved[/magenta]")
        except Exception as e:
            append_line(target_dir, "warnings.txt", f"cloud_enum_err: {e}")

        try:
            d = search_darknet_indicators(domain, target_dir)
            result["darknet"] = d
            if verbose: rprint(f"[magenta]• Darknet intel saved[/magenta]")
        except Exception as e:
            append_line(target_dir, "warnings.txt", f"darknet_err: {e}")

        # TRA
        if do_tra:
            result["tra"] = tra_basic(result)
            save_result(target_dir, "tra.json", result["tra"])
            if verbose: rprint(f"[magenta]• TRA risk (5): {result['tra']['risk_score_5']}[/magenta]")

        # finish timing
        result["finished"] = time.time()
        result["duration_sec"] = round(result["finished"] - result["timestamp"], 2)

        # Graph
        if do_graph:
            try:
                graph_out = render_asset_graph(domain, {"subdomains": result.get("crtsh_subdomains", []), "ips": result.get("ips", [])}, target_dir, fmt="png")
                result["asset_graph"] = graph_out
                if verbose: rprint(f"[magenta]• Asset graph → {graph_out}[/magenta]")
            except Exception as e:
                append_line(target_dir, "warnings.txt", f"graph_error: {e}")

        # Report (legacy simple HTML)
        if do_report:
            try:
                out_html = render_html_report(result, target_dir)
                result["html_report"] = out_html
                if verbose: rprint(f"[magenta]• HTML report → {out_html}[/magenta]")
            except Exception as e:
                append_line(target_dir, "warnings.txt", f"report_error: {e}")

    finally:
        if progress:
            progress.stop()

    # Save summary
    save_result(target_dir, "summary.json", result)
    rprint(f"[green]✔ Recon complete.[/green] Artifacts: [bold]{target_dir}[/bold]")

    # Interactive prompt: generate final HTML+PDF (cinematic)
    try:
        # If non-interactive environment (no tty) input() may block — keep prompt but safe
        choice = ""
        try:
            choice = input("Generate final HTML+PDF report now? (y/N): ").strip().lower()
        except Exception:
            # if input not possible, skip
            choice = "n"
        if choice == "y":
            rprint("⚠ Simulation mode: showing cinematic exploit theatre (NO ATTACKS)")
            # show short cinematic lines (non-destructive)
            vib_lines = [
                "[80/tcp] -> injecting payload: ' OR '1'='1 --",
                "[80/tcp] -> server reflected -> POSSIBLE SQLi (simulated hint)",
                "[443/tcp] -> TLS handshake... weak cipher: TLS_RSA_WITH_3DES (simulated check)",
                ">>> fuzzing param 'q' with payload: <script>alert(1337)</script>",
                ">>> server reflected input -> [XSS HINT] (simulated)"
            ]
            for ln in vib_lines:
                rprint(ln)
                time.sleep(0.18)
            rprint("Generating report (HTML + PDF)...")
            try:
                built = build_html_and_pdf_report(result, target_dir, operator=None, simulate=True)
                rprint(f"[green]Report generated:[/green] {built.get('html')} {built.get('pdf')}")
            except Exception as e:
                rprint(f"[red]Report generation failed:[/red] {e}")
                rprint(traceback.format_exc())
        else:
            if verbose:
                rprint("[cyan]Report generation skipped (you can run with --report to auto-generate HTML).[/cyan]")
    except Exception:
        # ignore interactive errors
        pass

# QoL
def auto_open_report(outdir: str, target: str, graph: bool = True, report: bool = True):
    domain = tldextract.extract(target).registered_domain or target
    target_dir = Path(outdir) / domain
    if report:
        html = target_dir / "report.html"
        if html.exists():
            rprint(f"[cyan]Report: {html}[/cyan]")
            try: webbrowser.open(html.as_uri())
            except Exception: pass
    if graph:
        for nm in ["asset_graph.png","asset_graph.svg","asset_graph.dot"]:
            p = target_dir / nm
            if p.exists():
                rprint(f"[cyan]Graph:  {p}[/cyan]")
                try: webbrowser.open(p.as_uri())
                except Exception: pass

