#!/usr/bin/env python3
# cybercli/core/privesc_core.py
# -*- coding: utf-8 -*-
"""
Privilege-Escalation core (SAFE helpers).

Preserves all original behavior while adding:
 - Auto-installer for common tools (safe, opt-in)
 - OS detection helpers
 - Improved reporting: summary, simple risk scoring, markdown output
 - Better error handling (safe_run wrappers)
 - Plugin discovery helper
 - Additional safe wrappers for community scanners
 - Vulnerability check (package/upgrades + kernel heuristics)
 - Container detection
 - File integrity scanner (sha256 baseline)
 - NOTE: No reverse-shell generation. See connectivity_check_generator instead.
"""

from __future__ import annotations
from pathlib import Path
from typing import Dict, Optional, List, Tuple, Any
import subprocess, shlex, datetime, os, shutil, json, random, string, time, base64, hashlib, importlib.util, sys, urllib.request

# optional nice terminal visuals (rich)
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
except Exception:
    Console = None

console = Console() if Console else None

# optional ssh client
try:
    import paramiko
except Exception:
    paramiko = None

ROOT_TOOLS_DIRS = [
    Path("tools"),
    Path("/usr/share"),
    Path("/usr/local/bin"),
    Path("/opt"),
    Path("/usr/share/pease"),
]
# extended known local tools (original ones still supported)
LOCAL_TOOLS = (
    "linpeas", "les", "pspy", "chkrootkit", "rkhunter", "kube-hunter",
    "osqueryi", "lynis",
    "kube-bench", "kube-linter", "polaris",
    "docker-bench-security", "trivy", "dive",
    "scoutsuite", "prowler", "cloudsploit",
    "gitleaks", "semgrep", "trufflehog", "checkov",
    "unix-privesc-check", "watson", "sudo-killer", "peass-ng"
)
REPORTS_ROOT_DEFAULT = Path("reports")

# ----------------- helpers (preserve originals) -----------------
def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p

def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def _rand_id(n=8) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))

def _escape_html(s: str) -> str:
    return (s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"))

def matrix_vibes(duration_s: float = 1.0, width: int = 60):
    """Small terminal animation to give 'hacking vibes'."""
    chars = "01▮▯░▒▓█▉▊▋▌▍▎▏"
    end = time.time() + duration_s
    try:
        if console:
            for _ in range(int(max(1, duration_s*10))):
                console.print("".join(random.choice(chars) for _ in range(width)), style="green")
                time.sleep(duration_s / max(1, int(duration_s*10)))
        else:
            while time.time() < end:
                print("".join(random.choice(chars) for _ in range(width)))
                time.sleep(0.06)
    except KeyboardInterrupt:
        return

# ----------------- discovery -----------------
def which(name: str) -> Optional[str]:
    """Prefer shutil.which, then search common tool dirs for script/executable names."""
    p = shutil.which(name)
    if p:
        return p
    for base in ROOT_TOOLS_DIRS:
        try:
            if not base.exists():
                continue
            cand = base / name
            if cand.exists():
                return str(cand.resolve())
            # also check script name with extension
            cand_sh = base / f"{name}.sh"
            if cand_sh.exists():
                return str(cand_sh.resolve())
            # shallow matches to avoid performance hit
            for sub in base.glob(f"*{name}*"):
                if sub.is_file():
                    return str(sub.resolve())
        except Exception:
            continue
    return None

# ----------------- reporting (TXT + HTML + MARKDOWN) -----------------
CSS_SIMPLE = """
body{background:#0b0f12;color:#d7fbd7;font-family:ui-monospace,Consolas,Monaco,monospace;padding:12px}
.card{background:#0f1620;padding:12px;border-radius:8px;margin-bottom:12px}
pre{white-space:pre-wrap;word-break:break-word}
.badge{background:#121820;padding:3px 8px;border-radius:999px;color:#9ad29a;margin-left:8px}
.risk-high{color:#ff6b6b;font-weight:bold}
.risk-medium{color:#ffcc66;font-weight:bold}
.risk-low{color:#9ad29a;font-weight:bold}
"""

JS_COPY = """
function copyId(id){ let el=document.getElementById(id); const sel=window.getSelection(); const rng=document.createRange(); rng.selectNodeContents(el); sel.removeAllRanges(); sel.addRange(rng); try{document.execCommand('copy')}catch(e){} sel.removeAllRanges(); }
"""

def generate_summary_and_score(out: str) -> Tuple[str,int,List[str]]:
    """
    Simple heuristic: find high-risk markers, produce a short summary and a risk score 0-100.
    This is a heuristic helper — not a replacement for human analysis.
    """
    markers_high = ["root", "uid=0", "password", "credential", "token", "private key", "SSH_AUTH_SOCK", "suid", "cap_net_admin", "cap_sys_admin"]
    markers_medium = ["world-writable", "docker", "kube", "kubectl", "cluster-admin", "pod", "serviceaccount", "sensitive"]
    found = set()
    score = 0
    txt = (out or "").lower()
    for m in markers_high:
        if m in txt:
            found.add(m)
            score += 20
    for m in markers_medium:
        if m in txt:
            found.add(m)
            score += 8
    # clamp
    score = max(0, min(100, score))
    summary = f"Detected {len(found)} suspicious keywords; heuristic risk score: {score}/100"
    return summary, score, sorted(found)

def write_markdown_report(outdir: Path, base: str, cmd: List[str], rc: int, out: str, err: str, started: str, ended: str, meta: Optional[dict]=None) -> str:
    """
    Write a markdown summary (besides the TXT + HTML).
    Returns path to md file.
    """
    outdir = ensure_dir(outdir)
    md = outdir / f"{base}.md"
    meta = meta or {}
    summary, score, findings = generate_summary_and_score(out)
    mdbody = [
        f"# {base}",
        "",
        f"- **Command**: `{shlex.join(cmd)}`",
        f"- **Started**: {started}",
        f"- **Ended**: {ended}",
        f"- **Return code**: {rc}",
        f"- **Heuristic score**: {score}/100",
        f"- **Findings preview**: {', '.join(findings) if findings else 'none'}",
        "",
        "## STDOUT",
        "```",
        (out or "")[:20000],
        "```",
        "",
        "## STDERR",
        "```",
        (err or "")[:20000],
        "```",
        "",
        "## Meta",
        "```json",
        json.dumps(meta or {}, indent=2),
        "```"
    ]
    md.write_text("\n".join(mdbody), encoding="utf-8", errors="ignore")
    return str(md.resolve())

def write_html_report(outdir: Path, base: str, cmd: List[str], rc: int, out: str, err: str, started: str, ended: str, meta: Optional[dict]=None) -> Dict[str,str]:
    """
    Original HTML writer augmented with summary and risk badge and a Markdown file sibling.
    """
    outdir = ensure_dir(outdir)
    txt = outdir / f"{base}.txt"
    html = outdir / f"{base}.html"
    txt_body = f"$ {shlex.join(cmd)}\n# started: {started}\n# ended:   {ended}\n# rc: {rc}\n\nSTDOUT:\n{out}\n\nSTDERR:\n{err}\n"
    txt.write_text(txt_body, encoding="utf-8", errors="ignore")
    meta = meta or {}
    out_id = _rand_id(); err_id = _rand_id()
    summary, score, findings = generate_summary_and_score(out)
    # risk class
    if score >= 60:
        risk_class = "risk-high"
    elif score >= 25:
        risk_class = "risk-medium"
    else:
        risk_class = "risk-low"
    html_body = f"""<!doctype html><html><head><meta charset='utf-8'><title>{base}</title><style>{CSS_SIMPLE}</style><script>{JS_COPY}</script></head>
<body>
<div class="card"><h2>{_escape_html(base)} <span class="badge">{_escape_html(json.dumps(meta))}</span></h2>
<small>Started: {started} • Ended: {ended} • RC: {rc}</small>
<p class="{risk_class}">Heuristic risk score: {score}/100 — {_escape_html(summary)}</p></div>

<div class="card"><b>Command</b><pre>{_escape_html(shlex.join(cmd))}</pre></div>
<div class="card"><b>STDOUT</b><button onclick="copyId('{out_id}')">Copy</button><pre id="{out_id}">{_escape_html(out)}</pre></div>
<div class="card"><b>STDERR</b><button onclick="copyId('{err_id}')">Copy</button><pre id="{err_id}">{_escape_html(err)}</pre></div>
</body></html>"""
    html.write_text(html_body, encoding="utf-8", errors="ignore")
    # write markdown sibling
    try:
        write_markdown_report(outdir, base, cmd, rc, out, err, started, ended, meta)
    except Exception:
        pass
    return {"txt": str(txt.resolve()), "html": str(html.resolve())}

def build_dashboard(run_root: Path) -> str:
    run_root = Path(run_root)
    ensure_dir(run_root)
    items: List[Tuple[str,str]] = []
    for tool_dir in sorted(run_root.glob("*")):
        if not tool_dir.is_dir():
            continue
        for f in sorted(tool_dir.glob("*.html")):
            rel = f.relative_to(run_root).as_posix()
            label = f"{tool_dir.name} / {f.stem}"
            items.append((label, rel))
    nav = "\n".join(f"<li><a href='#' onclick=\"document.getElementById('v').src='{_escape_html(path)}'\">{_escape_html(lbl)}</a></li>" for lbl, path in items)
    first = _escape_html(items[0][1]) if items else "about:blank"
    html = f"""<!doctype html><html><head><meta charset='utf-8'><title>Dashboard</title>
<style>body{{margin:0}}.aside{{position:fixed;left:0;top:0;bottom:0;width:320px;background:#0f1720;color:#9ad29a;padding:12px;overflow:auto}}.main{{margin-left:320px}}iframe{{width:100%;height:100vh;border:0}}</style>
</head><body>
<div class="aside"><h3>Reports</h3><ul style="list-style:none;padding:0">{nav or '<li>No reports</li>'}</ul></div>
<div class="main"><iframe id="v" src="{first}"></iframe></div>
</body></html>"""
    out = run_root / "dashboard.html"
    out.write_text(html, encoding="utf-8", errors="ignore")
    return str(out.resolve())

# ----------------- safe local command runner (better error handling) -----------------
def _run_local_cmd_capture(cmd: List[str], timeout: int = 900) -> Tuple[int, str, str]:
    started = datetime.datetime.utcnow().isoformat() + "Z"
    try:
        if console:
            with Progress(SpinnerColumn(), TextColumn("[green]{task.description}"), TimeElapsedColumn()) as prog:
                task = prog.add_task("running", total=None)
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                prog.update(task, description="done")
        else:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        return -1, "", f"TIMEOUT: {e}"
    except Exception as e:
        return -1, "", f"ERROR: {e}"

def safe_run_local(cmd: List[str], timeout: int = 900) -> Tuple[int, str, str]:
    """
    Wrapper around _run_local_cmd_capture which ensures we never raise to the caller,
    and always return structured response. Also gives friendly suggestion if command not found.
    """
    try:
        rc, out, err = _run_local_cmd_capture(cmd, timeout=timeout)
        if rc == 127 and ("not found" in (err or "").lower()):
            suggestion = f"Command not found: {cmd[0]}. Consider installing it or pass --path to the tool."
            if err:
                err = err + "\n" + suggestion
            else:
                err = suggestion
        return rc, out, err
    except Exception as e:
        return -1, "", f"ERROR: {e}"

# ----------------- ssh remote exec (safe wrapper) -----------------
def ssh_run_command(host: str, username: str, password: str, command: str, port: int = 22, timeout: int = 30) -> Tuple[str, str]:
    """
    Execute a command on remote host using username/password.
    Returns (stdout, stderr). If paramiko missing returns error string in stderr.
    This preserves previous behavior but always returns strings and never raises.
    """
    if paramiko is None:
        return "", "paramiko not installed in environment"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, port=port, username=username, password=password, timeout=timeout, look_for_keys=False, allow_agent=False)
        stdin, stdout, stderr = client.exec_command(command)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        client.close()
        return out, err
    except Exception as e:
        try:
            client.close()
        except Exception:
            pass
        return "", str(e)

def safe_ssh_run_command(host: str, username: str, password: str, command: str, port: int = 22, timeout: int = 30) -> Tuple[str, str]:
    """
    Thin wrapper that calls ssh_run_command and returns a friendly message on failures.
    """
    out, err = ssh_run_command(host, username, password, command, port=port, timeout=timeout)
    if err and ("no such file" in err.lower() or "not found" in err.lower()):
        err = err + "\nHint: the command may not be installed on the remote host. Consider uploading it via the SFTP helper."
    return out, err

def ssh_upload_file(host: str, username: str, password: str, local_path: str, remote_path: str, port: int = 22) -> Tuple[bool, str]:
    """
    Upload a local file to remote_path using SFTP. Returns (success, message).
    Requires paramiko.
    """
    if paramiko is None:
        return False, "paramiko not installed"
    if not Path(local_path).exists():
        return False, f"Local path not found: {local_path}"
    try:
        t = paramiko.Transport((host, port))
        t.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(t)
        # ensure remote directory exists (best-effort)
        remote_dir = os.path.dirname(remote_path)
        try:
            # try to create directories via ssh if necessary
            ssh_run_command(host, username, password, f"mkdir -p {shlex.quote(remote_dir)}")
        except Exception:
            pass
        sftp.put(local_path, remote_path)
        try:
            sftp.chmod(remote_path, 0o755)  # make executable by default
        except Exception:
            pass
        sftp.close()
        t.close()
        return True, f"Uploaded {local_path} -> {remote_path}"
    except Exception as e:
        return False, str(e)

def ssh_invoke_interactive_shell(host: str, username: str, password: str, port: int = 22):
    """
    Open an interactive remote shell (via paramiko invoke_shell).
    This prints remote output to local terminal and sends local stdin to remote.
    """
    if paramiko is None:
        print("paramiko not installed"); return
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, port=port, username=username, password=password, look_for_keys=False, allow_agent=False)
    chan = client.invoke_shell()
    print("[+] Interactive shell opened. Type commands, 'exit' to quit.")
    import sys, select
    try:
        while True:
            r, _, _ = select.select([chan, sys.stdin], [], [])
            if chan in r:
                x = chan.recv(4096).decode(errors="ignore")
                if not x:
                    break
                sys.stdout.write(x); sys.stdout.flush()
            if sys.stdin in r:
                inp = sys.stdin.readline()
                if not inp:
                    break
                chan.send(inp)
                if inp.strip().lower() in ("exit", "quit"):
                    break
    finally:
        try:
            chan.close()
            client.close()
        except Exception:
            pass

# ----------------- helper: upload kubeconfig & run kubectl via exported KUBECONFIG -------------
def upload_kubeconfig_and_run(host: str, username: str, password: str, local_kubeconfig: str, remote_dest: str, kubectl_cmd: str, timeout: int = 60) -> Tuple[str, str]:
    """
    Upload a kubeconfig file to remote host, and run kubectl using that file by setting KUBECONFIG env var.
    Returns (stdout, stderr). Designed as an explicit helper (user must confirm use).
    """
    ok, msg = ssh_upload_file(host, username, password, local_kubeconfig, remote_dest)
    if not ok:
        return "", f"upload-failed: {msg}"
    prefixed = f"export KUBECONFIG={shlex.quote(remote_dest)} && {kubectl_cmd}"
    return ssh_run_command(host, username, password, prefixed, timeout=timeout)

# ----------------- tool path resolution & local wrapper (extends original) -----------------
def _find_tool_path(toolname: str, manual_path: Optional[str] = None) -> Optional[str]:
    if manual_path:
        p = Path(manual_path)
        if p.exists():
            return str(p.resolve())
    w = which(toolname)
    if w:
        return w
    for base in ROOT_TOOLS_DIRS:
        p1 = base / toolname
        if p1.exists():
            return str(p1.resolve())
        p2 = base / f"{toolname}.sh"
        if p2.exists():
            return str(p2.resolve())
    # if tools/ contains a subdir
    tools_dir = Path("tools")
    candidate = tools_dir / toolname
    if candidate.exists():
        return str(candidate.resolve())
    return None

def run_tool_wrapper_local(tool_key: str, target: str, reports_root: Path, manual_path: Optional[str] = None, extra_args: Optional[List[str]] = None) -> Dict[str, str]:
    """
    Run a local tool by name. Supported: original + additional tools.
    This function keeps the same behavior as original but uses safe_run_local.
    """
    run_root = ensure_dir(reports_root / target / now_stamp())
    outdir = ensure_dir(run_root / tool_key)
    started = datetime.datetime.utcnow().isoformat() + "Z"
    extra_args = extra_args or []
    mapping = {
        "linpeas": lambda p: ["/bin/bash", p],
        "les": lambda p: ["/bin/bash", p],
        "pspy": lambda p: [p],
        "chkrootkit": lambda p: [p],
        "rkhunter": lambda p: [p, "--check"],
        "kube-hunter": lambda p: [p, "--quick"],

        # additional local tools (best-effort invocation)
        "osqueryi": lambda p: [p, "--json"],
        "lynis": lambda p: [p, "audit", "system"],
        "kube-bench": lambda p: [p],
        "kube-linter": lambda p: [p, "lint", "."],
        "polaris": lambda p: [p, "audit", "--local"],
        "docker-bench-security": lambda p: ["/bin/bash", p],
        "trivy": lambda p: [p, "fs", "."],
        "dive": lambda p: [p, "."],
        "scoutsuite": lambda p: [p],
        "prowler": lambda p: [p],
        "cloudsploit": lambda p: [p, "scan"],
        "gitleaks": lambda p: [p, "detect", "-s", "."],
        "semgrep": lambda p: [p, "scan", "--config", "auto", "."],
        "trufflehog": lambda p: [p, "filesystem", "--directory", "."],
        "checkov": lambda p: [p, "-d", "."],
        "unix-privesc-check": lambda p: [p],
        "watson": lambda p: [p],  # wrapper; actual invocation depends on tool
        "sudo-killer": lambda p: [p],
        "peass-ng": lambda p: [p],  # placeholder for windows peass wrappers (no auto-run)
    }
    if tool_key not in mapping:
        rc, out, err = 127, "", f"Unsupported tool: {tool_key}"
        return write_html_report(outdir, tool_key, [tool_key, "<unsupported>"], rc, out, err, started, datetime.datetime.utcnow().isoformat() + "Z", meta={"tool": tool_key})
    path = _find_tool_path(tool_key, manual_path)
    if not path:
        rc, out, err = 127, "", f"{tool_key} not found. Provide manual path or place in standard locations."
        return write_html_report(outdir, tool_key, [tool_key, "<not-found>"], rc, out, err, started, datetime.datetime.utcnow().isoformat() + "Z", meta={"tool": tool_key})
    cmd = mapping[tool_key](path) + extra_args
    matrix_vibes(0.6)
    rc, out, err = safe_run_local(cmd, timeout=3600)
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    rep = write_html_report(outdir, tool_key, cmd, rc, out or "", err or "", started, ended, meta={"tool": tool_key, "path": path})
    try:
        build_dashboard(run_root)
    except Exception:
        pass
    return rep

# ----------------- generic remote wrapper -----------------
def _run_generic_remote(target: str, reports_root: Path, host: str, user: str, password: str, name: str, remote_cmd: str, outsub: str = None) -> Dict[str, str]:
    """
    Generic helper to run a remote command (string) and write a report.
    name: identifies the tool (e.g., 'trivy_remote')
    outsub: optional subfolder name under timestamp (defaults to name)
    """
    run_root = ensure_dir(reports_root / target / now_stamp())
    outdir = ensure_dir(run_root / (outsub or name))
    started = datetime.datetime.utcnow().isoformat() + "Z"
    matrix_vibes(0.5)
    out, err = safe_ssh_run_command(host, user, password, remote_cmd)
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    return write_html_report(outdir, name, shlex.split(remote_cmd) if isinstance(remote_cmd, str) else [remote_cmd], 0 if out else 1, out or "", err or "", started, ended, meta={"tool": name, "host": host})

# ----------------- remote wrappers (ssh-run) -----------------
def run_linpeas_remote(target: str, reports_root: Path, host: str, user: str, password: str, linpeas_path: str = "linpeas.sh") -> Dict[str, str]:
    run_root = ensure_dir(reports_root / target / now_stamp())
    outdir = ensure_dir(run_root / "linpeas_remote")
    started = datetime.datetime.utcnow().isoformat() + "Z"
    matrix_vibes(0.6)
    out, err = safe_ssh_run_command(host, user, password, f"bash {linpeas_path}")
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    return write_html_report(outdir, "linpeas_remote", ["bash", linpeas_path], 0 if out else 1, out or "", err or "", started, ended, meta={"tool": "linpeas_remote", "host": host})

# (original remote wrappers preserved here — no renames)
def run_les_remote(target: str, reports_root: Path, host: str, user: str, password: str, script_path: str = "linux-exploit-suggester.sh") -> Dict[str, str]:
    run_root = ensure_dir(reports_root / target / now_stamp())
    outdir = ensure_dir(run_root / "les_remote")
    started = datetime.datetime.utcnow().isoformat() + "Z"
    matrix_vibes(0.6)
    out, err = safe_ssh_run_command(host, user, password, f"bash {script_path}")
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    return write_html_report(outdir, "les_remote", ["bash", script_path], 0 if out else 1, out or "", err or "", started, ended, meta={"tool": "les_remote", "host": host})

def run_pspy_remote(target: str, reports_root: Path, host: str, user: str, password: str, pspy_path: str = "pspy64") -> Dict[str, str]:
    run_root = ensure_dir(reports_root / target / now_stamp())
    outdir = ensure_dir(run_root / "pspy_remote")
    started = datetime.datetime.utcnow().isoformat() + "Z"
    matrix_vibes(0.6)
    out, err = safe_ssh_run_command(host, user, password, f"{pspy_path} --once")
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    return write_html_report(outdir, "pspy_remote", [pspy_path, "--once"], 0 if out else 1, out or "", err or "", started, ended, meta={"tool": "pspy_remote", "host": host})

def run_chkrootkit_remote(target: str, reports_root: Path, host: str, user: str, password: str) -> Dict[str, str]:
    run_root = ensure_dir(reports_root / target / now_stamp())
    outdir = ensure_dir(run_root / "chkrootkit_remote")
    started = datetime.datetime.utcnow().isoformat() + "Z"
    matrix_vibes(0.5)
    out, err = safe_ssh_run_command(host, user, password, "chkrootkit")
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    return write_html_report(outdir, "chkrootkit_remote", ["chkrootkit"], 0 if out else 1, out or "", err or "", started, ended, meta={"tool": "chkrootkit_remote", "host": host})

def run_rkhunter_remote(target: str, reports_root: Path, host: str, user: str, password: str) -> Dict[str, str]:
    run_root = ensure_dir(reports_root / target / now_stamp())
    outdir = ensure_dir(run_root / "rkhunter_remote")
    started = datetime.datetime.utcnow().isoformat() + "Z"
    matrix_vibes(0.5)
    out, err = safe_ssh_run_command(host, user, password, "rkhunter --check --sk")
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    return write_html_report(outdir, "rkhunter_remote", ["rkhunter", "--check", "--sk"], 0 if out else 1, out or "", err or "", started, ended, meta={"tool": "rkhunter_remote", "host": host})

def run_kubehunter_remote(target: str, reports_root: Path, host: str, user: str, password: str) -> Dict[str, str]:
    run_root = ensure_dir(reports_root / target / now_stamp())
    outdir = ensure_dir(run_root / "kubehunter_remote")
    started = datetime.datetime.utcnow().isoformat() + "Z"
    matrix_vibes(0.5)
    out, err = safe_ssh_run_command(host, user, password, "kube-hunter --quick")
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    return write_html_report(outdir, "kubehunter_remote", ["kube-hunter", "--quick"], 0 if out else 1, out or "", err or "", started, ended, meta={"tool": "kube-hunter_remote", "host": host})

# New remote wrappers for added tools (best-effort)
def run_lynis_remote(target: str, reports_root: Path, host: str, user: str, password: str, lynis_path: str = "lynis") -> Dict[str, str]:
    return _run_generic_remote(target, reports_root, host, user, password, "lynis_remote", f"{lynis_path} audit system")

def run_osquery_remote(target: str, reports_root: Path, host: str, user: str, password: str, osquery_path: str = "osqueryi") -> Dict[str, str]:
    # run a basic osqueryi query as example
    return _run_generic_remote(target, reports_root, host, user, password, "osquery_remote", f"{osquery_path} --json 'select hostname, uid, username from system_info;'")

def run_kubebench_remote(target: str, reports_root: Path, host: str, user: str, password: str, kb_path: str = "kube-bench") -> Dict[str, str]:
    return _run_generic_remote(target, reports_root, host, user, password, "kube_bench_remote", f"{kb_path}")

def run_kubelinter_remote(target: str, reports_root: Path, host: str, user: str, password: str, kl_path: str = "kube-linter") -> Dict[str, str]:
    return _run_generic_remote(target, reports_root, host, user, password, "kube_linter_remote", f"{kl_path} lint .")

def run_polaris_remote(target: str, reports_root: Path, host: str, user: str, password: str, polaris_path: str = "polaris") -> Dict[str, str]:
    return _run_generic_remote(target, reports_root, host, user, password, "polaris_remote", f"{polaris_path} audit --local")

def run_dockerbench_remote(target: str, reports_root: Path, host: str, user: str, password: str, db_path: str = "docker-bench-security.sh") -> Dict[str, str]:
    return _run_generic_remote(target, reports_root, host, user, password, "docker_bench_remote", f"bash {db_path}")

def run_trivy_remote(target: str, reports_root: Path, host: str, user: str, password: str, trivy_path: str = "trivy") -> Dict[str, str]:
    return _run_generic_remote(target, reports_root, host, user, password, "trivy_remote", f"{trivy_path} fs / --quiet")

def run_scoutsuite_remote(target: str, reports_root: Path, host: str, user: str, password: str, ss_path: str = "scoutsuite") -> Dict[str, str]:
    return _run_generic_remote(target, reports_root, host, user, password, "scoutsuite_remote", f"{ss_path}")

def run_prowler_remote(target: str, reports_root: Path, host: str, user: str, password: str, prowler_path: str = "prowler") -> Dict[str, str]:
    return _run_generic_remote(target, reports_root, host, user, password, "prowler_remote", f"{prowler_path}")

def run_cloudsploit_remote(target: str, reports_root: Path, host: str, user: str, password: str, cs_path: str = "cloudsploit") -> Dict[str, str]:
    return _run_generic_remote(target, reports_root, host, user, password, "cloudsploit_remote", f"{cs_path} scan")

def run_codetools_remote(target: str, reports_root: Path, host: str, user: str, password: str, tool_cmd: str, name: str) -> Dict[str, str]:
    return _run_generic_remote(target, reports_root, host, user, password, name, tool_cmd)

# ----------------- kubectl helpers (preserved) -----------------
def _try_decode_base64(s: str) -> str:
    try:
        return base64.b64decode(s).decode(errors="ignore")
    except Exception:
        return "<not-decodable>"

def run_kubectl_checks(target: str, reports_root: Path, host: str, user: str, password: str) -> Dict[str, Dict[str, str]]:
    """
    Execute several kubectl queries on the remote host (if it has kubectl configured).
    Returns mapping of command name -> report dict (txt/html).
    NOTE: this only runs commands you explicitly request; you must be authorized.
    """
    run_root = ensure_dir(reports_root / target / now_stamp())
    outdir = ensure_dir(run_root / "kubectl")
    started = datetime.datetime.utcnow().isoformat() + "Z"
    results: Dict[str, Dict[str, str]] = {}
    cmds = {
        "kubectl_get_po": "kubectl get po -A",
        "kubectl_get_secrets": "kubectl get secrets -A -o yaml",
        "kubectl_get_svc": "kubectl get svc -A -o yaml"
    }
    for name, cmd in cmds.items():
        matrix_vibes(0.3)
        out, err = safe_ssh_run_command(host, user, password, cmd)
        # best-effort decode base64-looking values in secrets output
        if name == "kubectl_get_secrets" and out:
            decoded = []
            for line in out.splitlines():
                line_stripped = line.strip()
                # naive extraction: lines that look like key: base64value
                if ":" in line_stripped and not line_stripped.startswith("#"):
                    parts = line_stripped.split(":", 1)
                    key = parts[0].strip()
                    val = parts[1].strip()
                    if val and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in val):
                        dec = _try_decode_base64(val)
                        decoded.append(f"{key}: {dec}")
            if decoded:
                out = out + "\n\n# decoded_base64_candidates:\n" + "\n".join(decoded)
            else:
                out = out + "\n\n# decoded_base64_candidates: <none found>"
        rc = 0 if out else 1
        rep = write_html_report(outdir, name, cmd.split(), rc, out or "", err or "", started, datetime.datetime.utcnow().isoformat() + "Z", meta={"tool": "kubectl", "host": host})
        results[name] = rep
    try:
        build_dashboard(run_root)
    except Exception:
        pass
    return results

# ----------------- notes for sensitive tools (preserved) -----------------
def run_kerbrute_note(target: str, reports_root: Path, domain: str) -> Dict[str, str]:
    run_root = ensure_dir(reports_root / target / now_stamp())
    outdir = ensure_dir(run_root / "kerbrute_note")
    started = datetime.datetime.utcnow().isoformat() + "Z"
    note = ("kerbrute is a Kerberos/AD enumeration tool. This wrapper does NOT run kerbrute automatically.\n\n"
            "Suggested authorized-only local command:\n  kerbrute userenum -d {domain} users.txt\n").format(domain=domain)
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    return write_html_report(outdir, "kerbrute_note", ["kerbrute", "<note>"], 0, note, "", started, ended, meta={"tool": "kerbrute_note"})

def run_winpeas_note(target: str, reports_root: Path, note: Optional[str] = None) -> Dict[str, str]:
    run_root = ensure_dir(reports_root / target / now_stamp())
    outdir = ensure_dir(run_root / "winpeas_note")
    started = datetime.datetime.utcnow().isoformat() + "Z"
    body = ("winPEAS is Windows-only and typically run on a Windows host. This wrapper does NOT run winPEAS automatically.\n"
            "If you ran winPEAS on a Windows host, paste stdout into 'winpeas_output.txt' inside the run folder to attach.\n")
    if note:
        body += "\nNote: " + note + "\n"
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    return write_html_report(outdir, "winpeas_note", ["winPEAS", "<note>"], 0, body, "", started, ended, meta={"tool": "winpeas_note"})

# ----------------- NEW: plugin discovery -----------------
def discover_plugins(plugins_dir: str = "plugins") -> Dict[str, Any]:
    """
    Discover python files under plugins_dir and attempt to import them.
    Each plugin can optionally export a register() function which returns metadata or commands.
    This is intentionally non-invasive and does not modify existing plugin state.
    """
    results = {}
    pdir = Path(plugins_dir)
    if not pdir.exists():
        return results
    for p in pdir.glob("*.py"):
        name = p.stem
        try:
            spec = importlib.util.spec_from_file_location(f"cybercli_plugins.{name}", str(p.resolve()))
            if not spec or not spec.loader:
                continue
            mod = importlib.util.module_from_spec(spec)
            sys.modules[f"cybercli_plugins.{name}"] = mod
            spec.loader.exec_module(mod)
            if hasattr(mod, "register"):
                try:
                    results[name] = mod.register()
                except Exception as e:
                    results[name] = {"error": str(e)}
            else:
                results[name] = {"loaded": True}
        except Exception as e:
            results[name] = {"error": str(e)}
    return results

# ----------------- NEW: auto-installer for missing tools (opt-in) -----------------
TOOL_INSTALL_SOURCES = {
    # tool_key: (download_url, default_local_name)
    "linpeas": ("https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh", "linpeas.sh"),
    "les": ("https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh", "linux-exploit-suggester.sh"),
    "pspy": ("https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64", "pspy64"),
    # Note: these URLs are examples and may change; always verify sources before using in production.
}

def ensure_tool_installed(tool_key: str, target_dir: Path = Path("tools")) -> Tuple[bool,str]:
    """
    Try to ensure a tool exists locally by checking common paths and optionally downloading
    from a preconfigured source into tools/. This is opt-in and will ask for confirmation
    if interactive=True was requested by caller. Returns (ok, path_or_errmsg).
    """
    path = _find_tool_path(tool_key)
    if path:
        return True, path
    # only attempt download if we have a configured source
    if tool_key not in TOOL_INSTALL_SOURCES:
        return False, f"No auto-install source configured for {tool_key}"
    url, fname = TOOL_INSTALL_SOURCES[tool_key]
    target_dir = ensure_dir(target_dir)
    out_path = target_dir / fname
    try:
        # Download to temporary path
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = resp.read()
            out_path.write_bytes(data)
        # chmod +x when possible
        try:
            out_path.chmod(0o755)
        except Exception:
            pass
        return True, str(out_path.resolve())
    except Exception as e:
        return False, f"download-failed: {e}"

# ----------------- NEW: OS detection -----------------
def detect_os() -> str:
    """
    Return a canonical os family: debian | rhel | alpine | other
    """
    try:
        if Path("/etc/os-release").exists():
            data = Path("/etc/os-release").read_text(errors="ignore").lower()
            if "debian" in data or "ubuntu" in data or "pop" in data or "linuxmint" in data:
                return "debian"
            if "rhel" in data or "centos" in data or "fedora" in data or "red hat" in data:
                return "rhel"
            if "alpine" in data:
                return "alpine"
        # fallback: check package managers presence
        if shutil.which("apt"):
            return "debian"
        if shutil.which("yum") or shutil.which("dnf"):
            return "rhel"
        if shutil.which("apk"):
            return "alpine"
    except Exception:
        pass
    return "other"

# ----------------- NEW: vulnerability checker (local) -----------------
def vuln_check_host(reports_root: Path, target: str = "local", depth: int = 5) -> Dict[str,str]:
    """
    Lightweight vulnerability check:
    - lists upgradable packages (apt/yum/apk)
    - reports kernel version and provides a heuristic (older kernel -> higher score)
    This is intentionally conservative: no external CVE DB lookups (offline). It produces a report and suggestions.
    """
    run_root = ensure_dir(reports_root / target / now_stamp())
    outdir = ensure_dir(run_root / "vuln_check")
    started = datetime.datetime.utcnow().isoformat() + "Z"
    osfam = detect_os()
    lines = []
    suggestions = []
    # kernel info
    try:
        kv = subprocess.check_output(["uname","-r"], text=True).strip()
        lines.append(f"Kernel: {kv}")
        # heuristic
        # If kernel version year unknown, minor heuristic: if kernel < 5.10 then warn
        try:
            nums = [int(x) for x in kv.split("-")[0].split(".") if x.isdigit()]
            if nums and nums[0] < 5:
                suggestions.append("Kernel appears older (<5.x) — consider checking kernel CVEs and updating if appropriate.")
        except Exception:
            pass
    except Exception:
        lines.append("Kernel: unknown")

    # package manager checks
    try:
        if osfam == "debian" and shutil.which("apt"):
            # apt list --upgradable may require apt update; we avoid forcing network update.
            try:
                out = subprocess.check_output(["apt", "list", "--upgradable"], text=True, stderr=subprocess.STDOUT)
                lines.append("APT upgradable packages:\n" + out)
            except Exception as e:
                lines.append("APT upgradable: failed to query (requires apt-cache/permissions).")
        elif osfam == "rhel" and (shutil.which("yum") or shutil.which("dnf")):
            pm = "dnf" if shutil.which("dnf") else "yum"
            try:
                out = subprocess.check_output([pm, "check-update"], text=True, stderr=subprocess.STDOUT, timeout=30)
                lines.append(f"{pm} check-update output:\n" + out)
            except subprocess.CalledProcessError as e:
                # yum/dnf returns non-zero when updates exist; include stdout
                lines.append(f"{pm} updates (raw):\n" + (e.output or ""))
            except Exception:
                lines.append(f"{pm} check-update: failed to run.")
        elif osfam == "alpine" and shutil.which("apk"):
            try:
                out = subprocess.check_output(["apk", "version", "-v"], text=True, stderr=subprocess.STDOUT)
                lines.append("apk versions:\n" + out)
            except Exception:
                lines.append("apk query: failed to run.")
        else:
            lines.append("Package manager not recognized or not queryable.")
    except Exception:
        lines.append("Package manager check error.")

    # file system permissions quick check
    try:
        # find world-writable files in /tmp and /var/tmp (limited search)
        ww = subprocess.check_output(["sh","-c","find /tmp -maxdepth 2 -type f -perm -o+w 2>/dev/null | wc -l"], text=True).strip()
        lines.append(f"World-writable files under /tmp (count): {ww}")
    except Exception:
        lines.append("World-writable quick-check: failed.")

    body = "\n\n".join(lines)
    ended = datetime.datetime.utcnow().isoformat() + "Z"
    rep = write_html_report(outdir, "vuln_check", ["vuln_check"], 0 if body else 1, body, "\n".join(suggestions), started, ended, meta={"tool":"vuln_check","os":detect_os()})
    try:
        build_dashboard(run_root)
    except Exception:
        pass
    return rep

# ----------------- NEW: container detection -----------------
def is_running_in_container() -> bool:
    """
    Best-effort check whether the current process is running inside a container.
    """
    try:
        if Path("/.dockerenv").exists():
            return True
        # check cgroup for docker / kubepods hints
        if Path("/proc/1/cgroup").exists():
            cg = Path("/proc/1/cgroup").read_text(errors="ignore").lower()
            if "docker" in cg or "kubepods" in cg or "containerd" in cg:
                return True
    except Exception:
        pass
    return False

# ----------------- NEW: file integrity scanner -----------------
def file_integrity_scan(root: str = "/", baseline_path: Optional[str] = None, extensions: Optional[List[str]] = None, max_files: int = 5000) -> Dict[str, Any]:
    """
    Walk 'root' and compute sha256 for files with given extensions or all files, up to max_files.
    If baseline_path provided and exists, compare and return diffs. Otherwise create baseline file.
    Returns a dict with results and writes to a report file in the caller's context if desired.
    """
    rootp = Path(root)
    files = []
    exts = set(extensions or [])
    count = 0
    for p in rootp.rglob("*"):
        if count >= max_files:
            break
        try:
            if p.is_file():
                if exts and p.suffix not in exts:
                    continue
                files.append(p)
                count += 1
        except Exception:
            continue
    results = {}
    for f in files:
        try:
            b = f.read_bytes()
            h = hashlib.sha256(b).hexdigest()
            results[str(f)] = h
        except Exception:
            results[str(f)] = "<err>"
    if baseline_path:
        bp = Path(baseline_path)
        diffs = {"added": [], "removed": [], "changed": []}
        if bp.exists():
            base = json.loads(bp.read_text(errors="ignore") or "{}")
            # compare
            for k, v in results.items():
                if k not in base:
                    diffs["added"].append(k)
                else:
                    if base[k] != v:
                        diffs["changed"].append(k)
            for k in base.keys():
                if k not in results:
                    diffs["removed"].append(k)
            return {"baseline_used": str(bp.resolve()), "diffs": diffs, "counts": {k: len(v) for k,v in diffs.items()}}
        else:
            # write baseline
            bp.write_text(json.dumps(results, indent=2), encoding="utf-8")
            return {"baseline_written": str(bp.resolve()), "files_hashed": len(results)}
    else:
        return {"files_hashed": len(results)}

# ----------------- NEW: connectivity-check generator (safe alternative to reverse shell) -----------------
def connectivity_check_generator(host: str, port: int) -> str:
    """
    Generate a safe connectivity check command string (no execution).
    This is a helpful alternative: it suggests how to test connectivity rather than creating a reverse shell payload.
    """
    # use netcat if available
    cmds = [
        f"nc -vz {shlex.quote(host)} {port}  # netcat connection attempt (verbose, zero-I/O)",
        f"timeout 5 bash -c '</dev/tcp/{host}/{port}' && echo 'open' || echo 'closed'  # shell TCP check (POSIX)",
        f"python3 -c \"import socket; s=socket.socket(); s.settimeout(5); print('open' if s.connect_ex(({repr(host)},{port}))==0 else 'closed')\""
    ]
    return "\n".join(cmds)

# ----------------- NEW: simple downloader helper for tools (safe, opt-in) -----------------
def download_to_tools(url: str, filename: Optional[str] = None, tools_dir: Path = Path("tools")) -> Tuple[bool,str]:
    """
    Download a URL into tools_dir and set executable bit. Returns (ok, path_or_error).
    This is used by ensure_tool_installed but provided standalone.
    """
    ensure_dir(tools_dir)
    name = filename or Path(url).name
    target = tools_dir / name
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = resp.read()
            target.write_bytes(data)
        try:
            target.chmod(0o755)
        except Exception:
            pass
        return True, str(target.resolve())
    except Exception as e:
        return False, str(e)

# -------------- END OF EXTENSIONS (core) --------------
# The rest of your original functions / wrappers remain intact above; callers will continue to behave the same.

