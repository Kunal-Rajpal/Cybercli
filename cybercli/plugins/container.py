#!/usr/bin/env python3
# cybercli/plugins/container.py
# -*- coding: utf-8 -*-
"""
Typer plugin for container security checks (Docker + Kubernetes), non-destructive.
"""

from pathlib import Path
from typing import Optional
import typer, json
from rich import print as rprint

from cybercli.core import container_core as ccore

app = typer.Typer(help="Container & Kubernetes security helpers (safe)")

REPORTS_ROOT = Path("reports")

def _ensure_authorization():
    rprint("[yellow]You must have explicit written authorization to run container/k8s audits on this host/cluster.[/yellow]")
    if not typer.confirm("Do you have authorization to audit containers/k8s here?", default=False):
        rprint("[red]Authorization required. Aborting.[/red]")
        raise typer.Exit(code=1)

@app.command("quick-audit")
def quick_audit(target_name: str = typer.Argument("container_target", help="Logical target/folder name")):
    _ensure_authorization()
    rprint("[cyan]Running container quick audit (Docker + Kubernetes) ...[/cyan]")
    res = ccore.container_quick_audit(REPORTS_ROOT, target_name)
    rep = res.get("report", {})
    rprint(f"[green]Report saved:[/green] TXT: {rep.get('txt')}  HTML: {rep.get('html')}")
    # print short summary
    body = res.get("body", {})
    if "docker_cis" in body:
        issues = body["docker_cis"].get("issues") if isinstance(body["docker_cis"], dict) else None
        rprint(f"[yellow]Docker issues found (sample):[/yellow] {json.dumps(issues or [], indent=2)[:2000]}")

@app.command("trivy-image")
def trivy_image(image: str = typer.Argument(..., help="Image name to scan (requires trivy installed)")):
    _ensure_authorization()
    rprint(f"[cyan]Scanning image with trivy: {image}[/cyan]")
    res = ccore.trivy_scan_image(image)
    rprint(json.dumps(res, indent=2)[:4000])

@app.command("docker-list")
def docker_list():
    _ensure_authorization()
    rprint("[cyan]Listing docker containers (local)...[/cyan]")
    res = ccore.docker_list_containers()
    rprint(json.dumps(res, indent=2))

@app.command("kubectl-rbac")
def kubectl_rbac():
    _ensure_authorization()
    rprint("[cyan]Collecting Kubernetes RBAC & SA info (kubectl must be configured)...[/cyan]")
    res = ccore.kubectl_get_rbac()
    if isinstance(res, dict) and "error" in res:
        rprint(f"[red]Error: {res['error']}[/red]")
    else:
        rprint("[green]RBAC collected (saved to report when using quick-audit).[/green]")

