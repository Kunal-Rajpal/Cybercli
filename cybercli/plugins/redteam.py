#!/usr/bin/env python3
# cybercli/plugins/redteam.py
# -*- coding: utf-8 -*-
"""
Typer plugin for Red Team toolkit helpers (generators and planners only).
"""

from pathlib import Path
from typing import Optional
import typer, json
from rich import print as rprint

from cybercli.core import redteam_core as rc

app = typer.Typer(help="Red Team toolkit (safe generators & planners)")

REPORTS_ROOT = Path("reports")

def _ensure_authorization():
    rprint("[yellow]You must have explicit written authorization to use red-team planning helpers.[/yellow]")
    if not typer.confirm("Do you have authorization to plan simulated attacks in this environment?", default=False):
        rprint("[red]Authorization required. Aborting.[/red]")
        raise typer.Exit(code=1)

@app.command("payloads")
def payloads(host: str = typer.Argument(..., help="Callback host"), port: int = typer.Argument(..., help="Callback port")):
    _ensure_authorization()
    rprint("[cyan]Generating reverse shell payload templates (display only)...[/cyan]")
    res = rc.generate_reverse_shells(host, port)
    rprint(json.dumps(res, indent=2))

@app.command("plan")
def plan_cmd(
    target_name: str = typer.Argument("red_target", help="Logical target/folder"),
    host: str = typer.Argument(..., help="Callback host for payload examples"),
    port: int = typer.Argument(..., help="Callback port"),
    assets_json: Optional[str] = typer.Option(None, "--assets", help="Path to JSON file listing assets"),
    creds_json: Optional[str] = typer.Option(None, "--creds", help="Path to JSON file with credentials mapping"),
    export_attack_path: Optional[str] = typer.Option(None, "--export", help="Filename to export plan json in report folder")
):
    _ensure_authorization()
    # load assets/creds if provided
    assets = []
    creds = {}
    if assets_json:
        p = Path(assets_json)
        if p.exists():
            assets = json.loads(p.read_text(encoding="utf-8"))
    if creds_json:
        p = Path(creds_json)
        if p.exists():
            creds = json.loads(p.read_text(encoding="utf-8"))
    rprint("[cyan]Building red-team bundle (payloads + plan) ...[/cyan]")
    res = rc.redteam_bundle_payloads_and_plan(REPORTS_ROOT, target_name, host, port, assets, creds, out_json=export_attack_path)
    rep = res.get("report",{})
    rprint(f"[green]Report saved:[/green] TXT: {rep.get('txt')}  HTML: {rep.get('html')}")
    rprint("[dim]Plan preview:[/dim]")
    rprint(json.dumps(res.get("body",{}), indent=2)[:4000])

