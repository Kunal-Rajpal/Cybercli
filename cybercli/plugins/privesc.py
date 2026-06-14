#!/usr/bin/env python3
# cybercli/plugins/privesc.py
# -*- coding: utf-8 -*-
"""
Typer plugin for PrivEsc helpers (interactive).

Preserves original behaviour while adding:
 - auto-installer prompts for common missing tools
 - menu entries to run additional scanners (K8s/Docker/Cloud/Code)
 - vulnerability check command
 - file-integrity scan command
 - plugin discovery command
 - connectivity-check generator (safe)
 - OS detection wrapper command
"""
from pathlib import Path
from typing import Optional
import typer
from rich import print as rprint
import datetime, json, base64, shlex

from cybercli.core import privesc_core as pcore
from cybercli.core.privesc_core import ensure_dir, now_stamp

app = typer.Typer(help="PrivEsc helpers (safe wrappers)")
REPORTS_ROOT = Path("reports")

def _ensure_authorization():
    rprint("[yellow]You must have explicit written authorization to test this target.[/yellow]")
    if not typer.confirm("Do you have written authorization to test this target?", default=False):
        rprint("[red]Authorization required. Aborting.[/red]")
        raise typer.Exit(code=1)

@app.command("start")
def start(
    target: str = typer.Argument(..., help="Logical target folder/name"),
    vibes: bool = typer.Option(True, "--vibes/--no-vibes", help="Show matrix vibes"),
):
    """Interactive PrivEsc menu (local & remote helpers)."""
    if vibes:
        try:
            pcore.matrix_vibes(0.9)
        except Exception:
            pass

    _ensure_authorization()

    while True:
        rprint("\n[bold cyan]PrivEsc Helpers — Menu[/bold cyan]")
        rprint("1) Run LOCAL tool (linpeas|les|pspy|chkrootkit|rkhunter|kube-hunter|... )")
        rprint("2) Remote SSH actions (provide credentials)")
        rprint("3) Upload local tool to remote (SFTP + optional exec)")
        rprint("4) Upload & use kubeconfig (use local kubeconfig on remote)")
        rprint("5) Kerbrute note (do not run)")
        rprint("6) winPEAS wrapper note (Windows-only)")
        rprint("7) Auto-install missing tool into tools/ (safe, opt-in)")
        rprint("8) Vulnerability quick-check (local host)")
        rprint("9) File integrity scan (baseline or compare)")
        rprint("10) Plugin discovery")
        rprint("11) Connectivity check generator (safe)")
        rprint("0) Exit")
        choice = typer.prompt("Select", default="0").strip()

        if choice == "0":
            rprint("Bye."); break

        if choice == "1":
            tool = typer.prompt("Tool to run (e.g. linpeas, les, pspy, trivy, gitleaks)", default="linpeas")
            manual_path = typer.prompt("Manual path to tool (leave blank to auto-detect)", default="")
            extra = typer.prompt("Extra args (space-separated, leave blank if none)", default="")
            extra_args = extra.strip().split() if extra.strip() else None

            # optional: if not found, offer to auto-install for known tools
            ok_path = pcore._find_tool_path(tool, manual_path or None)
            if not ok_path and tool in pcore.TOOL_INSTALL_SOURCES:
                rprint(f"[yellow]{tool} not found locally. An auto-download source is configured. You can install to tools/ directory (opt-in).[/yellow]")
                if typer.confirm(f"Download {tool} now from configured source?", default=False):
                    ok, msg = pcore.ensure_tool_installed(tool)
                    if ok:
                        rprint(f"[green]Downloaded: {msg}[/green]")
                    else:
                        rprint(f"[red]Install failed: {msg}[/red]")

            rep = pcore.run_tool_wrapper_local(tool, target, REPORTS_ROOT, manual_path or None, extra_args)
            rprint(f"[green]Saved:[/green] TXT: {rep['txt']}  HTML: {rep['html']}")

        elif choice == "2":
            host = typer.prompt("SSH host or IP")
            user = typer.prompt("SSH username")

            rprint("\n[cyan]Authentication options:[/cyan]")
            rprint("[1] Enter password manually")
            rprint("[2] Automated credential attacks (DISABLED)")
            rprint("[3] Abort")

            auth_choice = typer.prompt("Select", default="1").strip()
            if auth_choice == "1":
                password = typer.prompt("Enter SSH password", hide_input=True)
            elif auth_choice == "2":
                rprint("[red]Automated credential attacks are disabled in this tool for safety.[/red]")
                if not typer.confirm("Switch to manual password entry now?", default=True):
                    continue
                password = typer.prompt("Enter SSH password", hide_input=True)
            else:
                rprint("[red]Aborting remote flow.[/red]"); continue

            # quick verification (whoami + hostname + uname)
            rprint("[cyan]Testing SSH connection (whoami, hostname, uname -a, pwd)...[/cyan]")
            out, err = pcore.ssh_run_command(host, user, password, "whoami && hostname && uname -a && pwd && head -n 3 /etc/os-release || true")
            if out and out.strip():
                rprint(f"[green]Connected to {user}@{host}[/green]")
                rprint(f"[dim]Remote verification output:[/dim]\n{out.strip()}")
            else:
                rprint(f"[red]SSH connection failed: {err or 'unknown error'}[/red]")
                continue

            # Remote actions menu (preserved original behavior)
            while True:
                rprint("\n[bold cyan]Remote Actions[/bold cyan]")
                rprint("1) Run linpeas remotely (requires linpeas present on remote)")
                rprint("2) Run linux-exploit-suggester remotely")
                rprint("3) Run pspy remotely")
                rprint("4) Run chkrootkit remotely")
                rprint("5) Run rkhunter remotely")
                rprint("6) Run kube-hunter remotely")
                rprint("7) Kubernetes checks (kubectl get po/secrets/svc + decode candidates)")
                rprint("8) Execute arbitrary remote command (BE CAREFUL)")
                rprint("9) Open interactive remote shell")
                rprint("10) Run additional remote scanners (lynis, trivy, prowler, etc.)")
                rprint("0) Back")
                act = typer.prompt("Select", default="0").strip()
                if act == "0": break
                if act == "1":
                    remote_path = typer.prompt("Remote path to linpeas (default: linpeas.sh)", default="linpeas.sh")
                    rep = pcore.run_linpeas_remote(target, REPORTS_ROOT, host, user, password, linpeas_path=remote_path)
                    rprint(f"[green]Report saved:[/green] {rep['html']}")
                elif act == "2":
                    remote_path = typer.prompt("Remote path to linux-exploit-suggester (default: linux-exploit-suggester.sh)", default="linux-exploit-suggester.sh")
                    rep = pcore.run_les_remote(target, REPORTS_ROOT, host, user, password, script_path=remote_path)
                    rprint(f"[green]Report saved:[/green] {rep['html']}")
                elif act == "3":
                    pspy_path = typer.prompt("Remote path to pspy binary (default: pspy64)", default="pspy64")
                    rep = pcore.run_pspy_remote(target, REPORTS_ROOT, host, user, password, pspy_path)
                    rprint(f"[green]Report saved:[/green] {rep['html']}")
                elif act == "4":
                    rep = pcore.run_chkrootkit_remote(target, REPORTS_ROOT, host, user, password)
                    rprint(f"[green]Report saved:[/green] {rep['html']}")
                elif act == "5":
                    rep = pcore.run_rkhunter_remote(target, REPORTS_ROOT, host, user, password)
                    rprint(f"[green]Report saved:[/green] {rep['html']}")
                elif act == "6":
                    rep = pcore.run_kubehunter_remote(target, REPORTS_ROOT, host, user, password)
                    rprint(f"[green]Report saved:[/green] {rep['html']}")
                elif act == "7":
                    rprint("[cyan]About to run kubectl summary checks on remote host (kubectl must be available on remote).[/cyan]")
                    if not typer.confirm("Proceed to run kubectl get po -A and other kubectl checks on remote?", default=True):
                        rprint("[yellow]Skipped kubectl checks.[/yellow]")
                        continue
                    reps = pcore.run_kubectl_checks(target, REPORTS_ROOT, host, user, password)
                    rprint(f"[green]Saved kubectl reports:[/green] {', '.join(reps.keys())}")
                    po_rep = reps.get("kubectl_get_po")
                    if po_rep:
                        try:
                            txt_path = po_rep.get("txt")
                            if txt_path and Path(txt_path).exists():
                                content = Path(txt_path).read_text(errors="ignore")
                                lines = content.splitlines()
                                idx = next((i for i,l in enumerate(lines) if l.strip().startswith("STDOUT:")), None)
                                display = "\n".join(lines[idx+1:idx+60]) if idx is not None else "\n".join(lines[:60])
                                rprint("[bold]kubectl get po -A output (preview):[/bold]")
                                rprint(display[:4000])
                            else:
                                rprint("[yellow]kubectl_get_po report TXT not found for preview.[/yellow]")
                        except Exception:
                            pass
                    if typer.confirm("Interactively describe a pod or decode a secret from the remote cluster?", default=False):
                        if typer.confirm("Describe a pod? (otherwise we'll attempt to decode secrets)", default=True):
                            ns = typer.prompt("Namespace (or 'default')", default="default")
                            pod = typer.prompt("Pod name (exact; copy from kubectl_get_po output)", default="")
                            if pod:
                                cmd = f"kubectl describe pod {shlex.quote(pod)} -n {shlex.quote(ns)}"
                                rprint(f"[cyan]Running: {cmd}[/cyan]")
                                outd, errd = pcore.ssh_run_command(host, user, password, cmd)
                                repd = pcore.write_html_report(ensure_dir(REPORTS_ROOT.joinpath(target).joinpath(now_stamp()).joinpath("kubectl")), f"describe_pod_{pod}", cmd.split(), 0 if outd else 1, outd or "", errd or "", datetime.datetime.utcnow().isoformat()+"Z", datetime.datetime.utcnow().isoformat()+"Z", meta={"tool":"kubectl_describe","pod":pod,"namespace":ns})
                                rprint(f"[green]Describe saved:[/green] {repd['html']}")
                                rprint(f"[dim]{outd}[/dim]")
                                if typer.confirm("Do you want a suggested kubectl exec command to check inside the pod?", default=False):
                                    rprint(f"[yellow]Suggested: kubectl exec -it {pod} -n {ns} -- /bin/bash (or /bin/sh)[/yellow]")
                                    rprint("[yellow]Note: executing inside a pod requires authorization and may change system state. This tool will not exec into pods automatically unless you run an explicit command.[/yellow]")
                        else:
                            name = typer.prompt("Secret name to fetch (exact) or leave blank to fetch all", default="")
                            if name:
                                cmd = f"kubectl get secret {shlex.quote(name)} -n default -o jsonpath='{{.data}}' || true"
                                rprint(f"[cyan]Running: {cmd}[/cyan]")
                                outd, errd = pcore.ssh_run_command(host, user, password, cmd)
                                decoded = {}
                                for line in (outd or "").splitlines():
                                    line = line.strip().strip("{} ,")
                                    if not line:
                                        continue
                                    if ":" in line:
                                        k, v = line.split(":", 1)
                                        k = k.strip().strip('"')
                                        v = v.strip().strip('"')
                                        dec = "<not-decodable>"
                                        try:
                                            dec = base64.b64decode(v).decode(errors="ignore")
                                        except Exception:
                                            pass
                                        decoded[k] = dec
                                repd = pcore.write_html_report(ensure_dir(REPORTS_ROOT.joinpath(target).joinpath(now_stamp()).joinpath("kubectl")), f"secret_{name or 'all'}", ["kubectl","get","secret",name], 0 if outd else 1, outd or (json.dumps(decoded, indent=2) if decoded else ""), errd or "", datetime.datetime.utcnow().isoformat()+"Z", datetime.datetime.utcnow().isoformat()+"Z", meta={"tool":"kubectl_secret","name":name})
                                rprint(f"[green]Secret report saved:[/green] {repd['html']}")
                elif act == "8":
                    rprint("[red]WARNING: You're about to run an arbitrary command on the remote host. Only proceed if authorized and you understand the impact.[/red]")
                    if not typer.confirm("Proceed to run arbitrary remote command?", default=False):
                        continue
                    rc_cmd = typer.prompt("Enter the command to run (exact)")
                    rprint(f"[cyan]Running: {rc_cmd}[/cyan]")
                    outc, errc = pcore.ssh_run_command(host, user, password, rc_cmd)
                    repc = pcore.write_html_report(ensure_dir(REPORTS_ROOT.joinpath(target).joinpath(now_stamp()).joinpath("remote_cmds")), f"remote_cmd_{now_stamp()}", rc_cmd.split(), 0 if outc else 1, outc or "", errc or "", datetime.datetime.utcnow().isoformat()+"Z", datetime.datetime.utcnow().isoformat()+"Z", meta={"tool":"remote_cmd","host":host})
                    rprint(f"[green]Saved command report:[/green] {repc['html']}")
                    rprint(f"[dim]{outc or errc}[/dim]")
                elif act == "9":
                    rprint("[yellow]Opening interactive remote shell (invoke_shell). Type 'exit' to quit.[/yellow]")
                    pcore.ssh_invoke_interactive_shell(host, user, password)
                elif act == "10":
                    rprint("[cyan]Choose remote scanner to run (must be present on remote host):[/cyan]")
                    rprint("1) lynis")
                    rprint("2) osqueryi")
                    rprint("3) kube-bench")
                    rprint("4) kube-linter")
                    rprint("5) polaris")
                    rprint("6) docker-bench-security")
                    rprint("7) trivy")
                    rprint("8) scoutsuite")
                    rprint("9) prowler")
                    rprint("10) cloudsploit")
                    rprint("11) gitleaks")
                    rprint("12) semgrep")
                    rprint("13) trufflehog")
                    rprint("14) checkov")
                    sel = typer.prompt("Select", default="0").strip()
                    if sel == "1":
                        rp = typer.prompt("Remote path to lynis (default: lynis)", default="lynis")
                        rep = pcore.run_lynis_remote(target, REPORTS_ROOT, host, user, password, rp)
                        rprint(f"[green]Saved:[/green] {rep['html']}")
                    elif sel == "2":
                        rp = typer.prompt("Remote path to osqueryi (default: osqueryi)", default="osqueryi")
                        rep = pcore.run_osquery_remote(target, REPORTS_ROOT, host, user, password, rp)
                        rprint(f"[green]Saved:[/green] {rep['html']}")
                    elif sel == "3":
                        rp = typer.prompt("Remote path to kube-bench (default: kube-bench)", default="kube-bench")
                        rep = pcore.run_kubebench_remote(target, REPORTS_ROOT, host, user, password, rp)
                        rprint(f"[green]Saved:[/green] {rep['html']}")
                    elif sel == "4":
                        rp = typer.prompt("Remote path to kube-linter (default: kube-linter)", default="kube-linter")
                        rep = pcore.run_kubelinter_remote(target, REPORTS_ROOT, host, user, password, rp)
                        rprint(f"[green]Saved:[/green] {rep['html']}")
                    elif sel == "5":
                        rp = typer.prompt("Remote path to polaris (default: polaris)", default="polaris")
                        rep = pcore.run_polaris_remote(target, REPORTS_ROOT, host, user, password, rp)
                        rprint(f"[green]Saved:[/green] {rep['html']}")
                    elif sel == "6":
                        rp = typer.prompt("Remote path to docker-bench-security (default: docker-bench-security.sh)", default="docker-bench-security.sh")
                        rep = pcore.run_dockerbench_remote(target, REPORTS_ROOT, host, user, password, rp)
                        rprint(f"[green]Saved:[/green] {rep['html']}")
                    elif sel == "7":
                        rp = typer.prompt("Remote path to trivy (default: trivy)", default="trivy")
                        rep = pcore.run_trivy_remote(target, REPORTS_ROOT, host, user, password, rp)
                        rprint(f"[green]Saved:[/green] {rep['html']}")
                    elif sel == "8":
                        rp = typer.prompt("Remote path to scoutsuite (default: scoutsuite)", default="scoutsuite")
                        rep = pcore.run_scoutsuite_remote(target, REPORTS_ROOT, host, user, password, rp)
                        rprint(f"[green]Saved:[/green] {rep['html']}")
                    elif sel == "9":
                        rp = typer.prompt("Remote path to prowler (default: prowler)", default="prowler")
                        rep = pcore.run_prowler_remote(target, REPORTS_ROOT, host, user, password, rp)
                        rprint(f"[green]Saved:[/green] {rep['html']}")
                    elif sel == "10":
                        rp = typer.prompt("Remote path to cloudsploit (default: cloudsploit)", default="cloudsploit")
                        rep = pcore.run_cloudsploit_remote(target, REPORTS_ROOT, host, user, password, rp)
                        rprint(f"[green]Saved:[/green] {rep['html']}")
                    elif sel in ("11","12","13","14"):
                        mapping_sel = {"11":"gitleaks","12":"semgrep","13":"trufflehog","14":"checkov"}
                        sel_key = mapping_sel.get(sel)
                        rp = typer.prompt(f"Remote path to {sel_key} (default: {sel_key})", default=sel_key)
                        cmd_map = {
                            "gitleaks": f"{rp} detect -s .",
                            "semgrep": f"{rp} scan --config auto .",
                            "trufflehog": f"{rp} filesystem --directory .",
                            "checkov": f"{rp} -d ."
                        }
                        cmd = cmd_map.get(sel_key, rp)
                        rep = pcore.run_codetools_remote(target, REPORTS_ROOT, host, user, password, cmd, f"{sel_key}_remote")
                        rprint(f"[green]Saved:[/green] {rep['html']}")
                    else:
                        rprint("[red]Invalid selection or not implemented.[/red]")

        elif choice == "3":
            host = typer.prompt("SSH host or IP")
            user = typer.prompt("SSH username")
            password = typer.prompt("SSH password (used only for SFTP)", hide_input=True)
            local_path = typer.prompt("Local file path to upload (e.g. /home/kali/tools/linpeas.sh)")
            remote_path = typer.prompt("Remote destination path (e.g. /tmp/linpeas.sh)", default=f"/tmp/{Path(local_path).name}")
            rprint(f"[cyan]Uploading {local_path} -> {user}@{host}:{remote_path}[/cyan]")
            ok, msg = pcore.ssh_upload_file(host, user, password, local_path, remote_path)
            if ok:
                rprint(f"[green]{msg}[/green]")
                if typer.confirm("Run uploaded file on remote host now? (Only if it's safe and you are authorized)", default=False):
                    cmd = typer.prompt("Enter the command to execute the uploaded file (e.g. bash /tmp/linpeas.sh)", default=f"bash {remote_path}")
                    rprint(f"[cyan]Running: {cmd}[/cyan]")
                    out, err = pcore.ssh_run_command(host, user, password, cmd)
                    rep = pcore.write_html_report(ensure_dir(REPORTS_ROOT.joinpath(target).joinpath(now_stamp()).joinpath("uploaded")), f"uploaded_exec_{Path(local_path).name}", shlex.split(cmd), 0 if out else 1, out or "", err or "", datetime.datetime.utcnow().isoformat()+"Z", datetime.datetime.utcnow().isoformat()+"Z", meta={"tool":"uploaded_exec","remote":remote_path})
                    rprint(f"[green]Uploaded-run report saved:[/green] {rep['html']}")
                    rprint(f"[dim]{out or err}[/dim]")
            else:
                rprint(f"[red]Upload failed: {msg}[/red]")

        elif choice == "4":
            host = typer.prompt("SSH host or IP")
            user = typer.prompt("SSH username")
            password = typer.prompt("SSH password (used only for SFTP)", hide_input=True)
            local_kc = typer.prompt("Local kubeconfig path to upload (e.g. ~/.kube/config)")
            remote_kc = typer.prompt("Remote destination path (e.g. /tmp/kubeconfig)", default=f"/tmp/{Path(local_kc).name}")
            rprint(f"[cyan]This will upload your local kubeconfig ({local_kc}) to the remote host and run kubectl commands using it (KUBECONFIG set to {remote_kc}).[/cyan]")
            if not typer.confirm("Proceed with upload and remote kubectl test?", default=False):
                rprint("[yellow]Cancelled kubeconfig upload/use.[/yellow]"); continue
            rprint(f"[cyan]Uploading {local_kc} -> {user}@{host}:{remote_kc}[/cyan]")
            ok, msg = pcore.ssh_upload_file(host, user, password, local_kc, remote_kc)
            if not ok:
                rprint(f"[red]Upload failed: {msg}[/red]"); continue
            rprint(f"[green]{msg}[/green]")
            rprint("[cyan]Running remote: export KUBECONFIG=<remote> && kubectl get po -A[/cyan]")
            out, err = pcore.upload_kubeconfig_and_run(host, user, password, local_kc, remote_kc, "kubectl get po -A", timeout=60)
            rep = pcore.write_html_report(ensure_dir(REPORTS_ROOT.joinpath(target).joinpath(now_stamp()).joinpath("kubeconfig_upload")), "kubeconfig_get_po", ["kubectl", "get", "po", "-A"], 0 if out else 1, out or "", err or "", datetime.datetime.utcnow().isoformat()+"Z", datetime.datetime.utcnow().isoformat()+"Z", meta={"tool":"kubeconfig_get_po","remote":remote_kc})
            rprint(f"[green]Saved kubeconfig-run report:[/green] {rep['html']}")
            rprint(f"[dim]{out or err}[/dim]")

        elif choice == "5":
            domain = typer.prompt("Kerberos domain (for recommended command, e.g. EXAMPLE.LOCAL)")
            rep = pcore.run_kerbrute_note(target, REPORTS_ROOT, domain)
            rprint(f"[yellow]Note saved:[/yellow] {rep['html']}")

        elif choice == "6":
            note = typer.prompt("Optional note about how/where you ran winPEAS", default="")
            rep = pcore.run_winpeas_note(target, REPORTS_ROOT, note or None)
            rprint(f"[yellow]Note saved:[/yellow] {rep['html']}")

        elif choice == "7":
            tool = typer.prompt("Tool key to auto-install (e.g. linpeas, pspy). See docs for configured sources.", default="linpeas")
            rprint("[yellow]Auto-install is opt-in and will download from configured public sources into tools/. Verify sources before using in production.[/yellow]")
            if not typer.confirm("Proceed with auto-download?", default=False):
                rprint("[yellow]Cancelled auto-install.[/yellow]"); continue
            ok, msg = pcore.ensure_tool_installed(tool)
            if ok:
                rprint(f"[green]Installed: {msg}[/green]")
            else:
                rprint(f"[red]Install failed: {msg}[/red]")

        elif choice == "8":
            rprint("[cyan]Running local vulnerability quick-check (package upgrades, kernel hints)...[/cyan]")
            rep = pcore.vuln_check_host(REPORTS_ROOT, target)
            rprint(f"[green]Vuln-check saved:[/green] {rep['html']}")

        elif choice == "9":
            root = typer.prompt("Root path to scan (e.g. /etc or /home) or leave blank for /", default="/")
            baseline = typer.prompt("Baseline file path to compare or leave blank to create baseline in ./integrity_baseline.json", default="")
            if not baseline:
                baseline = f"./integrity_baseline_{now_stamp()}.json"
            rprint("[cyan]Starting file integrity scan (sha256) — this may be slow depending on path and files.[/cyan]")
            res = pcore.file_integrity_scan(root=root, baseline_path=baseline)
            rprint(f"[green]File integrity result:[/green] {res}")

        elif choice == "10":
            rprint("[cyan]Discovering plugins under ./plugins/* (attempting to import safe modules)...[/cyan]")
            res = pcore.discover_plugins("plugins")
            rprint(f"[green]Plugins discovered:[/green] {json.dumps(res, indent=2)[:4000]}")

        elif choice == "11":
            host = typer.prompt("Host to test connectivity to", default="127.0.0.1")
            port = int(typer.prompt("Port to test", default="80"))
            rprint("[yellow]This will produce suggested commands to test connectivity (no execution).[/yellow]")
            cmds = pcore.connectivity_check_generator(host, port)
            rprint(f"[green]Suggested connectivity checks:[/green]\n{cmds}")

        else:
            rprint("[red]Invalid selection[/red]")

# convenience typed commands (preserve originals)
@app.command("linpeas")
def linpeas_cmd(target: str = typer.Option(..., "--target", "-t"), path: Optional[str] = typer.Option(None, "--path")):
    _ensure_authorization()
    rep = pcore.run_tool_wrapper_local("linpeas", target, REPORTS_ROOT, manual_path=path)
    rprint(f"[green]Saved:[/green] TXT: {rep['txt']}  HTML: {rep['html']}")

@app.command("les")
def les_cmd(target: str = typer.Option(..., "--target", "-t"), path: Optional[str] = typer.Option(None, "--path")):
    _ensure_authorization()
    rep = pcore.run_tool_wrapper_local("les", target, REPORTS_ROOT, manual_path=path)
    rprint(f"[green]Saved:[/green] TXT: {rep['txt']}  HTML: {rep['html']}")

# new convenience command examples
@app.command("vulncheck")
def vulncheck_cmd(target: str = typer.Option(..., "--target", "-t")):
    _ensure_authorization()
    rep = pcore.vuln_check_host(REPORTS_ROOT, target)
    rprint(f"[green]Saved:[/green] {rep['html']}")

@app.command("discover-plugins")
def discover_plugins_cmd():
    res = pcore.discover_plugins("plugins")
    rprint(f"[green]Plugins discovered:[/green] {json.dumps(res, indent=2)[:4000]}")

@app.command("is-container")
def is_container_cmd():
    r = pcore.is_running_in_container()
    rprint(f"[green]Running in container? {r}[/green]")

@app.command("integrity-scan")
def integrity_scan_cmd(root: str = typer.Option("/", "--root"), baseline: Optional[str] = typer.Option(None, "--baseline")):
    _ensure_authorization()
    baseline_path = baseline or f"./integrity_baseline_{now_stamp()}.json"
    res = pcore.file_integrity_scan(root=root, baseline_path=baseline_path)
    rprint(f"[green]Integrity scan result:[/green] {res}")

# do NOT implement reverse shell generator — provide safe alternative
@app.command("connectivity-check")
def connectivity_check_cmd(host: str = typer.Option("127.0.0.1"), port: int = typer.Option(80)):
    rprint("[yellow]This feature generates suggested connectivity test commands (no execution). Reverse-shell generation is not provided for safety reasons.[/yellow]")
    cmds = pcore.connectivity_check_generator(host, port)
    rprint(cmds)

