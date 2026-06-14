#!/usr/bin/env python3
# cybercli/core/forensics_core.py
# -*- coding: utf-8 -*-
"""
Forensics core helpers (safe, non-destructive).

Features:
 - collect_system_info() : uname, os-release, network interfaces, users
 - list_installed_packages() : apt/rpm/pip/npm best-effort
 - list_startup_items() : systemd units, cron entries, rc.local
 - collect_logs() : copy selected logs (syslog, auth.log, messages, journalctl helper)
 - compute_hashes() : sha256 hashes for files (path list)
 - build_timeline() : produce simple timeline from filesystem metadata (mtime, ctime)
 - ioc_scan() : scan files for IOCs (file-hashes or substrings)
 - reporting: tries to use cybercli.core.privesc_core.write_html_report if available,
   otherwise uses a minimal local report writer.
All functions are designed non-destructive and require explicit authorization at the CLI layer.
"""

from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import platform, os, shutil, json, datetime, hashlib, pwd, grp, subprocess, sys, re

# Try to reuse existing reporting helpers if present
try:
    from cybercli.core.privesc_core import ensure_dir as _ensure_dir, write_html_report as _write_html_report, now_stamp as _now_stamp
    _HAS_PRIVESC_REPORT = True
except Exception:
    _HAS_PRIVESC_REPORT = False

# fallback simple writer if privesc_core not available
def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p

def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

SIMPLE_CSS = """
body{background:#0b0f12;color:#d7fbd7;font-family:ui-monospace,Consolas,Monaco,monospace;padding:12px}
.card{background:#0f1620;padding:12px;border-radius:8px;margin-bottom:12px}
pre{white-space:pre-wrap;word-break:break-word}
"""

def simple_write_report(outdir: Path, base: str, body: str, meta: Optional[dict]=None) -> Dict[str,str]:
    outdir = ensure_dir(outdir)
    txt = outdir / f"{base}.txt"
    html = outdir / f"{base}.html"
    started = datetime.datetime.utcnow().isoformat() + "Z"
    txt.write_text(f"# {base}\n# {started}\n\n{body}\n", encoding="utf-8", errors="ignore")
    html_body = f"""<!doctype html><html><head><meta charset='utf-8'><title>{base}</title><style>{SIMPLE_CSS}</style></head>
<body>
<div class="card"><h2>{base}</h2><small>{started}</small></div>
<div class="card"><pre>{body}</pre></div>
</body></html>"""
    html.write_text(html_body, encoding="utf-8", errors="ignore")
    return {"txt": str(txt.resolve()), "html": str(html.resolve())}

def write_report_auto(outdir: Path, base: str, cmd: List[str], rc: int, out: str, err: str, started_ts: str, ended_ts: str, meta: Optional[dict]=None) -> Dict[str,str]:
    """
    Use privesc_core.write_html_report if available (keeps consistent dashboard).
    Otherwise write a minimal report.
    """
    if _HAS_PRIVESC_REPORT:
        try:
            return _write_html_report(outdir, base, cmd, rc, out, err, started_ts, ended_ts, meta=meta)
        except Exception:
            pass
    # fallback
    body = f"CMD: {' '.join(cmd)}\n\nSTDOUT:\n{out}\n\nSTDERR:\n{err}\n"
    return simple_write_report(outdir, base, body, meta=meta)

# ---------------------- helpers ----------------------
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def safe_read_text(p: Path, max_chars: int = 20000) -> str:
    try:
        return p.read_text(errors="ignore")[:max_chars]
    except Exception as e:
        return f"<read-error: {e}>"

# ---------------------- system info ----------------------
def collect_system_info() -> Dict[str,Any]:
    info = {}
    info["platform"] = platform.platform()
    info["system"] = platform.system()
    info["machine"] = platform.machine()
    try:
        if Path("/etc/os-release").exists():
            info["os_release"] = Path("/etc/os-release").read_text(errors="ignore")
    except Exception:
        pass
    # uname
    try:
        info["uname"] = " ".join(platform.uname())
    except Exception:
        pass
    # current users / logged in
    try:
        who = subprocess.check_output(["who"], text=True, stderr=subprocess.DEVNULL)
        info["who"] = who.strip()
    except Exception:
        info["who"] = "<who unavailable>"
    # users list from /etc/passwd (non-sensitive: only usernames)
    try:
        users = [u.pw_name for u in pwd.getpwall()]
        info["local_users_count"] = len(users)
    except Exception:
        info["local_users_count"] = "unknown"
    return info

# ---------------------- installed packages ----------------------
def list_installed_packages(limit: int = 500) -> Dict[str,Any]:
    results = {}
    # apt
    if shutil.which("dpkg"):
        try:
            out = subprocess.check_output(["dpkg","-l"], text=True, stderr=subprocess.DEVNULL)
            lines = out.splitlines()[:limit]
            results["dpkg"] = "\n".join(lines)
        except Exception:
            results["dpkg"] = "<dpkg-error>"
    # rpm
    if shutil.which("rpm"):
        try:
            out = subprocess.check_output(["rpm","-qa"], text=True, stderr=subprocess.DEVNULL)
            results["rpm_count"] = len(out.splitlines())
        except Exception:
            results["rpm_count"] = "<rpm-error>"
    # pip
    try:
        out = subprocess.check_output([sys.executable, "-m", "pip", "list", "--format=json"], text=True, stderr=subprocess.DEVNULL, timeout=30)
        results["pip"] = json.loads(out)
    except Exception:
        results["pip"] = "<pip-unavailable-or-error>"
    # npm
    if shutil.which("npm"):
        try:
            out = subprocess.check_output(["npm","-v"], text=True, stderr=subprocess.DEVNULL, timeout=10)
            results["npm_version"] = out.strip()
        except Exception:
            results["npm_version"] = "<npm-error>"
    return results

# ---------------------- startup / autoruns ----------------------
def list_startup_items() -> Dict[str,Any]:
    res = {}
    # systemd units (list enabled)
    if shutil.which("systemctl"):
        try:
            out = subprocess.check_output(["systemctl","list-unit-files","--type=service","--no-pager","--no-legend"], text=True, stderr=subprocess.DEVNULL, timeout=30)
            res["systemd_units_sample"] = "\n".join(out.splitlines()[:200])
        except Exception:
            res["systemd_units_sample"] = "<systemctl-error>"
    # cron (root and user crontabs)
    try:
        cron_files = []
        cron_dirs = ["/etc/cron.d","/etc/cron.daily","/etc/cron.hourly","/var/spool/cron"]
        for d in cron_dirs:
            p = Path(d)
            if p.exists():
                for f in p.glob("*"):
                    if f.is_file():
                        cron_files.append(str(f))
        res["cron_files"] = cron_files[:200]
    except Exception:
        res["cron_files"] = "<cron-error>"
    # rc.local
    try:
        rcl = Path("/etc/rc.local")
        if rcl.exists():
            res["rc_local"] = safe_read_text(rcl, max_chars=5000)
    except Exception:
        pass
    return res

# ---------------------- logs collection ----------------------
def collect_logs(report_root: Path, targets: Optional[List[str]] = None, max_bytes_per_file: int = 200000) -> Dict[str,str]:
    """
    Copy selected logs into report folder (best-effort). Non-destructive.
    targets: list of absolute log paths to collect (if not provided, uses a default list)
    Returns mapping of file -> saved_path
    """
    defaults = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/kern.log",
        "/var/log/faillog",
        "/var/log/dmesg",
    ]
    to_get = targets or defaults
    outdir = ensure_dir(report_root / "logs")
    saved = {}
    for p in to_get:
        try:
            src = Path(p)
            if not src.exists():
                continue
            content = src.read_bytes()[:max_bytes_per_file]
            dest = outdir / f"{src.name}"
            dest.write_bytes(content)
            saved[p] = str(dest.resolve())
        except Exception as e:
            saved[p] = f"<error: {e}>"
    # also collect journalctl -n if systemd journal present
    if shutil.which("journalctl"):
        try:
            out = subprocess.check_output(["journalctl","-n","1000","--no-pager"], text=True, stderr=subprocess.DEVNULL, timeout=30)
            dest = outdir / "journal_last1000.txt"
            dest.write_text(out, encoding="utf-8", errors="ignore")
            saved["journal_last1000"] = str(dest.resolve())
        except Exception:
            saved["journal_last1000"] = "<journalctl-error>"
    return saved

# ---------------------- hash files ----------------------
def compute_hashes(paths: List[str], max_files: int = 1000) -> Dict[str,str]:
    """
    Compute sha256 for provided file paths (best-effort). Returns mapping path -> sha256 or error.
    """
    out = {}
    count = 0
    for p in paths:
        if count >= max_files:
            break
        try:
            fp = Path(p)
            if fp.is_file():
                out[str(fp)] = sha256_file(fp)
                count += 1
            else:
                out[str(fp)] = "<not-a-file>"
        except Exception as e:
            out[str(p)] = f"<error: {e}>"
    return out

# ---------------------- timeline builder ----------------------
def build_timeline(paths: List[str], max_entries: int = 5000) -> List[Dict[str,Any]]:
    """
    Walk provided paths and produce a timeline list of file events (path, mtime, ctime, size, owner).
    Non-destructive. Sorting by mtime descending.
    """
    entries = []
    seen = 0
    for root in paths:
        rp = Path(root)
        if not rp.exists():
            continue
        for p in rp.rglob("*"):
            if seen >= max_entries:
                break
            try:
                st = p.stat()
                owner = None
                try:
                    owner = pwd.getpwuid(st.st_uid).pw_name
                except Exception:
                    owner = str(st.st_uid)
                entries.append({
                    "path": str(p),
                    "mtime": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(),
                    "ctime": datetime.datetime.fromtimestamp(st.st_ctime).isoformat(),
                    "size": st.st_size,
                    "owner": owner
                })
                seen += 1
            except Exception:
                continue
    # sort by mtime desc
    entries_sorted = sorted(entries, key=lambda x: x.get("mtime",""), reverse=True)
    return entries_sorted

# ---------------------- IOC scanner ----------------------
def ioc_scan_files(iocs: Dict[str, List[str]], scan_paths: List[str], max_files: int = 2000) -> Dict[str,Any]:
    """
    iocs: {"hashes": [...], "strings": [...]}
    scan_paths: list of files or directories to scan. Returns matches.
    This function is conservative: it scans only readable files and avoids large binaries by size limit.
    """
    matches = {"hash_matches": [], "string_matches": []}
    hashes = set([h.lower() for h in iocs.get("hashes", [])])
    strings = iocs.get("strings", [])
    scanned = 0
    for root in scan_paths:
        rp = Path(root)
        if rp.is_file():
            files = [rp]
        else:
            files = [p for p in rp.rglob("*") if p.is_file()]
        for f in files:
            if scanned >= max_files:
                break
            try:
                size = f.stat().st_size
                # skip very large files
                if size > 50*1024*1024:
                    continue
                # hash check
                try:
                    h = sha256_file(f)
                    if h.lower() in hashes:
                        matches["hash_matches"].append({"file": str(f), "sha256": h})
                except Exception:
                    pass
                # string scanning (read first N bytes)
                try:
                    txt = f.read_bytes()[:200000].decode(errors="ignore").lower()
                    for s in strings:
                        if s.lower() in txt:
                            matches["string_matches"].append({"file": str(f), "match": s})
                except Exception:
                    pass
                scanned += 1
            except Exception:
                continue
    return matches

# ---------------------- high-level bundled functions ----------------------
def collect_forensic_bundle(report_root: Path, target_name: str, collect_logs_paths: Optional[List[str]] = None) -> Dict[str,str]:
    """
    Run a conservative collection: system info, installed packages, autoruns, small logs snapshot.
    Writes a multi-file report under report_root/target_name/<stamp>/forensics
    Returns mapping of generated files.
    """
    run_root = ensure_dir(report_root / target_name / now_stamp())
    outdir = ensure_dir(run_root / "forensics")
    started = datetime.datetime.utcnow().isoformat() + "Z"
    parts = {}
    # system info
    sysinfo = collect_system_info()
    parts["system_info.json"] = (outdir / "system_info.json")
    parts["system_info.json"].write_text(json.dumps(sysinfo, indent=2), encoding="utf-8")
    # installed packages
    pkgs = list_installed_packages()
    parts["installed_packages.json"] = (outdir / "installed_packages.json")
    parts["installed_packages.json"].write_text(json.dumps(pkgs, default=str, indent=2), encoding="utf-8")
    # startup
    su = list_startup_items()
    parts["startup.json"] = (outdir / "startup.json")
    parts["startup.json"].write_text(json.dumps(su, indent=2), encoding="utf-8")
    # logs
    saved_logs = collect_logs(outdir, targets=collect_logs_paths)
    parts["logs_summary.json"] = (outdir / "logs_summary.json")
    parts["logs_summary.json"].write_text(json.dumps(saved_logs, indent=2), encoding="utf-8")
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    # write summary report via write_report_auto
    summary_body = f"Collected system info, installed packages, startup items and log snapshots. Files: {list(parts.keys())}"
    # use report writer that mimics existing pattern (cmd is descriptive)
    rep = write_report_auto(outdir, "forensics_collection", ["forensics_bundle"], 0, summary_body, "", started, ended, meta={"tool":"forensics_collection"})
    return {"report": rep, "files": {k:str(v.resolve()) for k,v in parts.items()}, "logs": saved_logs}

def timeline_bundle(report_root: Path, target_name: str, paths: List[str], max_entries: int = 5000) -> Dict[str,str]:
    run_root = ensure_dir(report_root / target_name / now_stamp())
    outdir = ensure_dir(run_root / "forensics")
    started = datetime.datetime.utcnow().isoformat() + "Z"
    entries = build_timeline(paths, max_entries=max_entries)
    tpath = outdir / "timeline.json"
    tpath.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    rep = write_report_auto(outdir, "timeline", ["timeline_build"], 0, f"Timeline entries: {len(entries)}", "", started, ended, meta={"tool":"timeline","count":len(entries)})
    return {"report": rep, "timeline_file": str(tpath.resolve()), "entries": len(entries)}

def ioc_scan_bundle(report_root: Path, target_name: str, iocs: Dict[str,List[str]], paths: List[str]) -> Dict[str,Any]:
    run_root = ensure_dir(report_root / target_name / now_stamp())
    outdir = ensure_dir(run_root / "forensics")
    started = datetime.datetime.utcnow().isoformat() + "Z"
    matches = ioc_scan_files(iocs, paths)
    mpath = outdir / "ioc_matches.json"
    mpath.write_text(json.dumps(matches, indent=2), encoding="utf-8")
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    rep = write_report_auto(outdir, "ioc_scan", ["ioc_scan"], 0, json.dumps(matches, indent=2), "", started, ended, meta={"tool":"ioc_scan"})
    return {"report": rep, "matches_file": str(mpath.resolve()), "matches_count": len(matches.get("hash_matches",[])) + len(matches.get("string_matches",[]))}

# -------------- end of forensics_core.py --------------

