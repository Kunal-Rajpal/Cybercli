#!/usr/bin/env python3
# cybercli/core/container_core.py
# -*- coding: utf-8 -*-
"""
Container security core helpers (Docker + Kubernetes checks). Non-destructive.

Features:
 - Docker local checks: list containers, inspect images, check for running privileged containers, capabilities, mounts, sensitive volume mounts
 - Trivy/Scan hook if available (calls trivy CLI) — requires trivy installed
 - Simple CIS-like checks (privileged, host network, mounts to /etc, docker.sock)
 - Kubernetes checks via kubectl (RBAC list, serviceaccounts, pod security contexts) using provided kubeconfig or local kubectl
 - Reporting via privesc_core writer if available
"""

from __future__ import annotations
from pathlib import Path
from typing import List, Dict,Any, Optional
import subprocess, shutil, json, datetime

# optional docker sdk
try:
    import docker
except Exception:
    docker = None

# re-use writer if present
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

# ---------------- helpers ----------------
def _run_cmd(cmd: List[str], timeout: int = 30) -> Dict[str,Any]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": p.stdout.strip(), "err": p.stderr.strip()}
    except Exception as e:
        return {"rc": -1, "out": "", "err": str(e)}

# ---------------- Docker checks ----------------
def docker_list_containers() -> Dict[str,Any]:
    if docker:
        try:
            client = docker.from_env()
            containers = []
            for c in client.containers.list(all=True):
                cfg = c.attrs
                containers.append({"id": c.id[:12], "name": c.name, "image": cfg.get("Config",{}).get("Image"), "state": cfg.get("State",{}).get("Status")})
            return {"method":"docker-sdk","containers":containers}
        except Exception as e:
            return {"error": str(e)}
    # fallback to docker CLI
    if shutil.which("docker"):
        r = _run_cmd(["docker","ps","-a","--format","{{.ID}}::{{.Names}}::{{.Image}}::{{.Status}}"])
        if r["rc"] == 0:
            items = []
            for ln in r["out"].splitlines():
                try:
                    cid,name,image,status = ln.split("::")
                    items.append({"id": cid, "name": name, "image": image, "status": status})
                except Exception:
                    continue
            return {"method":"docker-cli","containers":items}
        return {"error": r["err"]}
    return {"error":"docker not available"}

def docker_inspect_image(image: str) -> Dict[str,Any]:
    if shutil.which("docker"):
        r = _run_cmd(["docker","image","inspect",image])
        if r["rc"] == 0:
            try:
                data = json.loads(r["out"])
                return {"inspect": data}
            except Exception:
                return {"raw": r["out"]}
    return {"error": "docker not available or inspect failed"}

def docker_cis_checks() -> Dict[str,Any]:
    """
    Basic CIS-like checks for running containers: privileged, host network, mounts to sensitive paths, docker.sock.
    """
    res = {"issues": []}
    info = docker_list_containers()
    if "containers" not in info:
        return {"error": "no containers info", "raw": info}
    for c in info["containers"]:
        # try inspect for details
        try:
            insp = docker_inspect_image(c["id"])
            cfg = insp.get("inspect", [{}])[0] if isinstance(insp.get("inspect"), list) else {}
            host_config = cfg.get("HostConfig", {})
            if host_config.get("Privileged"):
                res["issues"].append({"container": c["name"], "issue": "privileged"})
            if host_config.get("NetworkMode","") == "host":
                res["issues"].append({"container": c["name"], "issue": "host-network"})
            binds = host_config.get("Binds") or []
            for b in binds:
                if "/var/run/docker.sock" in b or "/etc" in b or "/root" in b:
                    res["issues"].append({"container": c["name"], "issue": f"sensitive-bind {b}"})
        except Exception:
            continue
    return res

def trivy_scan_image(image: str) -> Dict[str,Any]:
    """
    Invoke trivy CLI if available. Requires trivy installed.
    """
    if not shutil.which("trivy"):
        return {"error":"trivy not installed"}
    r = _run_cmd(["trivy","image","--quiet", "--format", "json", image], timeout=300)
    if r["rc"] == 0 and r["out"]:
        try:
            return json.loads(r["out"])
        except Exception:
            return {"raw": r["out"]}
    return {"error": r["err"]}

# ---------------- Kubernetes checks ----------------
def kubectl_get_rbac() -> Dict[str,Any]:
    if not shutil.which("kubectl"):
        return {"error":"kubectl not found"}
    r = _run_cmd(["kubectl","get","clusterrolebindings,clusterroles,roles,rolebindings,sa,namespace","--all-namespaces","-o","json"], timeout=60)
    if r["rc"] == 0 and r["out"]:
        try:
            return json.loads(r["out"])
        except Exception:
            return {"raw": r["out"]}
    return {"error": r["err"]}

def kubectl_pod_security_summary() -> Dict[str,Any]:
    if not shutil.which("kubectl"):
        return {"error":"kubectl not found"}
    r = _run_cmd(["kubectl","get","pods","--all-namespaces","-o","json"], timeout=60)
    if r["rc"] == 0 and r["out"]:
        try:
            pods = json.loads(r["out"]).get("items",[])
            summary = []
            for p in pods:
                spec = p.get("spec",{})
                containers = spec.get("containers",[])
                for c in containers:
                    sc = c.get("securityContext") or {}
                    summary.append({"ns": p.get("metadata",{}).get("namespace"), "pod": p.get("metadata",{}).get("name"), "container": c.get("name"), "securityContext": sc})
            return {"summary": summary}
        except Exception:
            return {"raw": r["out"]}
    return {"error": r["err"]}

# ---------------- high-level wrappers ----------------
def container_quick_audit(report_root: Path, target_name: str) -> Dict[str,Any]:
    run_root = ensure_dir(report_root / target_name / now_stamp())
    outdir = ensure_dir(run_root / "container")
    started = datetime.datetime.utcnow().isoformat() + "Z"
    parts = {}
    parts["docker_containers"] = docker_list_containers()
    parts["docker_cis"] = docker_cis_checks()
    parts["kubectl_rbac"] = kubectl_get_rbac()
    parts["kubectl_pss"] = kubectl_pod_security_summary()
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    rep = write_report_auto(outdir, "container_quick_audit", ["container_quick_audit"], 0, json.dumps(parts, indent=2), "", started, ended, meta={"tool":"container_quick_audit"})
    return {"report": rep, "body": parts}

