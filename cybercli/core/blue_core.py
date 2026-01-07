#!/usr/bin/env python3
# cybercli/core/blue_core.py
# -*- coding: utf-8 -*-
"""
Blue Team monitoring helpers (non-destructive).

Features:
 - process anomaly detection (compare running processes to baseline list)
 - file integrity monitor baseline & scan (sha256)
 - log monitoring helper (tail last N lines, search for patterns)
 - suspicious network connections (netstat/ss)
 - YARA scan hook (requires yara-python)
 - Reporting via privesc_core writer if available
"""

from __future__ import annotations
from pathlib import Path
from typing import List,Dict,Any,Optional
import subprocess, shutil, hashlib, json, datetime

# optional yara
try:
    import yara
    _HAS_YARA = True
except Exception:
    _HAS_YARA = False

# reuse writer if available
try:
    from cybercli.core.privesc_core import ensure_dir as _ensure_dir, write_html_report as _write_html_report, now_stamp as _now_stamp
    _HAS_PRIVESC_REPORT = True
except Exception:
    _HAS_PRIVESC_REPORT = False

def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p

def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def simple_write_report(outdir: Path, base: str, body: str) -> Dict[str,str]:
    outdir = ensure_dir(outdir)
    txt = outdir / f"{base}.txt"
    html = outdir / f"{base}.html"
    txt.write_text(body, encoding="utf-8")
    html.write_text(f"<html><body><pre>{body}</pre></body></html>", encoding="utf-8")
    return {"txt": str(txt.resolve()), "html": str(html.resolve())}

def write_report_auto(outdir: Path, base: str, cmd: List[str], rc: int, out: str, err: str, started_ts: str, ended_ts: str, meta: Optional[dict]=None) -> Dict[str,str]:
    if _HAS_PRIVESC_REPORT:
        try:
            return _write_html_report(outdir, base, cmd, rc, out, err, started_ts, ended_ts, meta=meta)
        except Exception:
            pass
    return simple_write_report(outdir, base, out)

# ---------------- helpers ----------------
def _run_cmd(cmd: List[str], timeout: int = 10) -> Dict[str,Any]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": p.stdout.strip(), "err": p.stderr.strip()}
    except Exception as e:
        return {"rc": -1, "out":"", "err": str(e)}

# ---------------- process anomaly ----------------
def list_processes() -> List[Dict[str,Any]]:
    """
    Return list of processes with PID, cmdline, user.
    """
    procs = []
    try:
        if shutil.which("ps"):
            r = _run_cmd(["ps","axo","pid,user,comm,args"])
            for ln in r["out"].splitlines()[1:]:
                parts = ln.strip().split(None,3)
                if len(parts) >= 4:
                    pid, user, comm, args = parts
                elif len(parts) == 3:
                    pid, user, comm = parts
                    args = comm
                else:
                    continue
                procs.append({"pid": pid, "user": user, "comm": comm, "args": args})
    except Exception:
        pass
    return procs

def detect_proc_anomalies(baseline_cmds: List[str]) -> Dict[str,Any]:
    """
    Baseline_cmds is list of allowed commands (comm or args substrings).
    Returns processes not matching baseline (possible anomalies).
    """
    procs = list_processes()
    anomalies = []
    for p in procs:
        ok = False
        for b in baseline_cmds:
            if b in p.get("args","") or b in p.get("comm",""):
                ok = True; break
        if not ok:
            anomalies.append(p)
    return {"anomalies": anomalies, "total_procs": len(procs)}

# ---------------- file integrity ----------------
def build_file_integrity_baseline(paths: List[str], outpath: Path) -> Dict[str,Any]:
    """
    Walk provided paths, compute sha256 for files, and save baseline JSON.
    """
    baseline = {}
    count = 0
    for root in paths:
        rp = Path(root)
        if not rp.exists():
            continue
        for f in rp.rglob("*"):
            if f.is_file():
                try:
                    h = hashlib.sha256(f.read_bytes()).hexdigest()
                    baseline[str(f)] = {"sha256": h}
                    count += 1
                except Exception:
                    continue
    ensure_dir(outpath.parent)
    outpath.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
    return {"baseline_file": str(outpath.resolve()), "files": count}

def scan_file_integrity_against_baseline(baseline_file: Path, max_files: int = 5000) -> Dict[str,Any]:
    if not baseline_file.exists():
        return {"error": "baseline file not found"}
    try:
        baseline = json.loads(baseline_file.read_text(encoding="utf-8"))
    except Exception:
        return {"error": "baseline load error"}
    modified = []
    checked = 0
    for p, meta in baseline.items():
        if checked >= max_files:
            break
        try:
            f = Path(p)
            if not f.exists():
                modified.append({"file": p, "status": "missing"})
            else:
                cur = hashlib.sha256(f.read_bytes()).hexdigest()
                if cur != meta.get("sha256"):
                    modified.append({"file": p, "status": "modified"})
            checked += 1
        except Exception:
            continue
    return {"modified": modified, "checked": checked}

# ---------------- log monitoring ----------------
def tail_logs(paths: List[str], lines: int = 200) -> Dict[str,str]:
    out = {}
    for p in paths:
        try:
            f = Path(p)
            if not f.exists():
                out[p] = "<not-found>"
                continue
            content = f.read_text(errors="ignore").splitlines()[-lines:]
            out[p] = "\n".join(content)
        except Exception as e:
            out[p] = f"<error: {e}>"
    return out

# ---------------- network connections ----------------
def net_connections() -> Dict[str,Any]:
    if shutil.which("ss"):
        r = _run_cmd(["ss","-tunap"])
        return {"method":"ss","out": r["out"][:20000]}
    if shutil.which("netstat"):
        r = _run_cmd(["netstat","-tunap"])
        return {"method":"netstat","out": r["out"][:20000]}
    return {"error":"ss/netstat not available"}

# ---------------- yara scan hook ----------------
def yara_scan_paths(rules_path: str, scan_paths: List[str], max_files:int = 2000) -> Dict[str,Any]:
    if not _HAS_YARA:
        return {"error":"yara-python not installed"}
    matches = []
    rules = yara.compile(filepath=rules_path)
    scanned = 0
    for root in scan_paths:
        rp = Path(root)
        files = [rp] if rp.is_file() else list(rp.rglob("*"))
        for f in files:
            if scanned >= max_files:
                break
            if not f.is_file():
                continue
            try:
                m = rules.match(str(f))
                if m:
                    matches.append({"file": str(f), "matches": [str(x) for x in m]})
            except Exception:
                pass
            scanned += 1
    return {"matches": matches}

# ---------------- high-level bundles ----------------
def blue_quick_checks(report_root: Path, target_name: str, baseline_paths: Optional[List[str]] = None) -> Dict[str,Any]:
    run_root = ensure_dir(report_root / target_name / now_stamp())
    outdir = ensure_dir(run_root / "blue")
    started = datetime.datetime.utcnow().isoformat() + "Z"
    parts = {}
    parts["processes"] = list_processes()[:500]
    parts["net"] = net_connections()
    parts["recent_logs"] = tail_logs(["/var/log/auth.log","/var/log/syslog"], lines=200)
    if baseline_paths:
        baseline_file = outdir / "fint_baseline.json"
        bres = build_file_integrity_baseline(baseline_paths, baseline_file)
        parts["baseline"] = bres
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    rep = write_report_auto(outdir, "blue_quick_checks", ["blue_quick_checks"], 0, json.dumps(parts, indent=2), "", started, ended, meta={"tool":"blue_quick_checks"})
    return {"report": rep, "body": parts}

