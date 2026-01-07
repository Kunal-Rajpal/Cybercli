#!/usr/bin/env python3
# cybercli/plugins/forensics.py
# -*- coding: utf-8 -*-
"""
Typer plugin for forensic helpers (safe, non-destructive).
Commands:
 - collect      : conservative forensic snapshot (system info, packages, startup, logs)
 - timeline     : build timeline from filesystem paths
 - ioc-scan     : scan given paths for hashes/strings
 - hash-files   : compute sha256 for a list of files
 - report-open  : helper to list latest forensic reports
All commands require explicit authorization.
"""

from pathlib import Path
from typing import List, Optional
import typer, json
from rich import print as rprint

from cybercli.core import forensics_core as fcore

app = typer.Typer(help="Forensics helpers (safe)")

REPORTS_ROOT = Path("reports")

def _ensure_authorization():
    rprint("[yellow]You must have explicit written authorization to collect forensic artifacts.[/yellow]")
    if not typer.confirm("Do you have written authorization to collect and analyze forensic data on this host/target?", default=False):
        rprint("[red]Authorization required. Aborting.[/red]")
        raise typer.Exit(code=1)

@app.command("collect")
def collect_cmd(
    target_name: str = typer.Argument("forensic_target", help="Logical target/folder name"),
    logs: Optional[str] = typer.Option(None, "--logs", help="Comma-separated list of log absolute paths to collect (optional)"),
):
    _ensure_authorization()
    rprint(f"[cyan]Starting conservative forensic collection for target: {target_name}[/cyan]")
    logs_list = [x.strip() for x in logs.split(",")] if logs else None
    res = fcore.collect_forensic_bundle(REPORTS_ROOT, target_name, collect_logs_paths=logs_list)
    rprint(f"[green]Collection complete.[/green] Report: {res['report']['html']}")

@app.command("timeline")
def timeline_cmd(
    target_name: str = typer.Argument("forensic_target", help="Logical target/folder name"),
    paths: Optional[str] = typer.Option("/", "--paths", help="Comma-separated list of paths to include in timeline"),
    max_entries: int = typer.Option(2000, "--max", "-m", help="Maximum timeline entries"),
):
    _ensure_authorization()
    paths_list = [p.strip() for p in paths.split(",")] if paths else ["/"]
    rprint(f"[cyan]Building timeline for: {paths_list} (max {max_entries})[/cyan]")
    res = fcore.timeline_bundle(REPORTS_ROOT, target_name, paths_list, max_entries=max_entries)
    rprint(f"[green]Timeline saved:[/green] {res['report']['html']}")
    rprint(f"[dim]Entries: {res['entries']} File: {res['timeline_file']}[/dim]")

@app.command("ioc-scan")
def ioc_scan_cmd(
    target_name: str = typer.Argument("forensic_target", help="Logical target/folder name"),
    hashes: Optional[str] = typer.Option(None, "--hashes", help="Comma-separated list of SHA256 hashes to search"),
    strings: Optional[str] = typer.Option(None, "--strings", help="Comma-separated list of strings to search"),
    paths: Optional[str] = typer.Option("/", "--paths", help="Comma-separated list of files/directories to scan"),
):
    _ensure_authorization()
    iocs = {"hashes": [], "strings": []}
    if hashes:
        iocs["hashes"] = [h.strip().lower() for h in hashes.split(",") if h.strip()]
    if strings:
        iocs["strings"] = [s.strip() for s in strings.split(",") if s.strip()]
    paths_list = [p.strip() for p in paths.split(",")] if paths else ["/"]
    rprint(f"[cyan]Running IOC scan for paths: {paths_list}[/cyan]")
    res = fcore.ioc_scan_bundle(REPORTS_ROOT, target_name, iocs, paths_list)
    rprint(f"[green]IOC scan saved:[/green] {res['report']['html']}")
    rprint(f"[dim]Matches: {res['matches_count']} File: {res['matches_file']}[/dim]")

@app.command("hash-files")
def hash_files_cmd(
    files: str = typer.Argument(..., help="Comma-separated list of file paths to hash"),
):
    _ensure_authorization()
    files_list = [f.strip() for f in files.split(",")]
    rprint(f"[cyan]Computing sha256 for {len(files_list)} files[/cyan]")
    res = fcore.compute_hashes(files_list, max_files=len(files_list))
    rprint(json.dumps(res, indent=2)[:4000])

@app.command("logs-collect")
def logs_collect_cmd(
    target_name: str = typer.Argument("forensic_target", help="Logical target folder name"),
    logs: Optional[str] = typer.Option(None, "--logs", help="Comma-separated list of absolute log paths to collect"),
):
    _ensure_authorization()
    logs_list = [x.strip() for x in logs.split(",")] if logs else None
    rprint("[cyan]Collecting logs (conservative snapshot)[/cyan]")
    out = fcore.collect_logs(Path("reports") / target_name, targets=logs_list)
    rprint(f"[green]Saved logs: {json.dumps(out, indent=2)}[/green]")

@app.command("report-open")
def report_open_cmd(reports_dir: Optional[str] = typer.Option(None, "--reports", "-r")):
    base = Path(reports_dir) if reports_dir else Path("reports")
    if not base.exists():
        rprint("[red]No reports directory found yet.[/red]"); raise typer.Exit(code=1)
    folders = sorted([p for p in base.rglob("*") if p.is_dir()], key=lambda x: x.stat().st_mtime, reverse=True)
    forensics = [f for f in folders if "forensics" in str(f).lower() or "forensic" in str(f).lower()]
    if not forensics:
        rprint("[yellow]No forensic reports found.[/yellow]"); raise typer.Exit(code=0)
    rprint("[green]Latest forensic report folders (top 10):[/green]")
    for f in forensics[:10]:
        rprint(f"{f}")

