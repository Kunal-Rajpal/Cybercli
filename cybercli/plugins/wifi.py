#!/usr/bin/env python3
# cybercli/plugins/wifi.py
# -*- coding: utf-8 -*-
"""
Typer plugin for wireless helpers (safe mode).

Commands:
 - list-ifs        : list wireless interfaces
 - scan            : passive AP scan (nmcli/iwlist)
 - monitor-check   : check monitor mode availability (no changes made)
 - analyze-pcap    : analyze provided pcap for handshakes/PMKID (requires scapy)
 - detect-rogue    : run rogue heuristics against a saved scan JSON
 - quick-scan      : run wireless_quick_scan and save report
 - report-open     : helper to list latest wireless reports
All commands require explicit authorization.
"""

from pathlib import Path
from typing import Optional, List
import typer, json
from rich import print as rprint

from cybercli.core import wifi_core as wcore

app = typer.Typer(help="Wireless helpers (safe, passive)")

REPORTS_ROOT = Path("reports")

def _ensure_authorization():
    rprint("[yellow]You must have explicit written authorization to run wireless scans on this host/environment.[/yellow]")
    if not typer.confirm("Do you have written authorization to run these passive wireless checks?", default=False):
        rprint("[red]Authorization required. Aborting.[/red]")
        raise typer.Exit(code=1)

@app.command("list-ifs")
def list_ifs():
    _ensure_authorization()
    rprint("[cyan]Listing wireless interfaces...[/cyan]")
    res = wcore.list_wireless_interfaces()
    rprint(json.dumps(res, indent=2))

@app.command("scan")
def scan_cmd(interface: Optional[str] = typer.Option(None, "--iface", "-i", help="Interface to prefer for scan (optional)"),
             timeout: int = typer.Option(10, "--timeout", "-t")):
    _ensure_authorization()
    rprint(f"[cyan]Running passive scan (timeout {timeout}s)...[/cyan]")
    res = wcore.scan_access_points(interface=interface, timeout=timeout)
    # save scan to reports for later analysis
    run_root = REPORTS_ROOT / "wireless_scans" / wcore.now_stamp()
    run_root.mkdir(parents=True, exist_ok=True)
    scan_file = run_root / "scan.json"
    scan_file.write_text(json.dumps(res, indent=2), encoding="utf-8")
    rprint(f"[green]Scan saved:[/green] {scan_file}")
    rprint(json.dumps(res, indent=2)[:4000])

@app.command("monitor-check")
def monitor_check(interface: str = typer.Argument(..., help="Interface to check (e.g. wlan0)")):
    _ensure_authorization()
    rprint(f"[cyan]Checking monitor support for {interface} (no changes will be made)...[/cyan]")
    res = wcore.monitor_mode_check(interface)
    rprint(json.dumps(res, indent=2))

@app.command("analyze-pcap")
def analyze_pcap_cmd(pcap: str = typer.Argument(..., help="Path to pcap file to analyze (pcap/pcapng)")):
    _ensure_authorization()
    rprint(f"[cyan]Analyzing pcap: {pcap} (best-effort, requires scapy)...[/cyan]")
    res = wcore.analyze_pcap(pcap)
    rprint(json.dumps(res, indent=2))

@app.command("detect-rogue")
def detect_rogue_cmd(scan_json: str = typer.Argument(..., help="Path to saved scan JSON (from wifi scan command)"), known_ssids: Optional[str] = typer.Option(None, "--known", help="Comma-separated known SSIDs")):
    _ensure_authorization()
    p = Path(scan_json)
    if not p.exists():
        rprint(f"[red]Scan file not found: {scan_json}[/red]"); raise typer.Exit(code=1)
    data = json.loads(p.read_text(encoding="utf-8"))
    aps = data.get("aps") if isinstance(data.get("aps"), dict) else {}
    known = [s.strip() for s in known_ssids.split(",")] if known_ssids else None
    res = wcore.detect_rogue_aps(aps, known_ssids=known)
    rprint(json.dumps(res, indent=2))

@app.command("quick-scan")
def quick_scan_cmd(target: str = typer.Argument("wireless_target", help="Logical target name for report"),
                   iface: Optional[str] = typer.Option(None, "--iface", "-i"),
                   known_ssids: Optional[str] = typer.Option(None, "--known", help="Comma-separated known SSIDs"),
                   timeout: int = typer.Option(10, "--timeout", "-t")):
    _ensure_authorization()
    known = [s.strip() for s in known_ssids.split(",")] if known_ssids else None
    rprint(f"[cyan]Running wireless quick scan on target {target} (iface={iface})[/cyan]")
    res = wcore.wireless_quick_scan(REPORTS_ROOT, target, interface=iface, known_ssids=known, timeout=timeout)
    rep = res.get("report", {})
    rprint(f"[green]Report saved:[/green] TXT: {rep.get('txt')}  HTML: {rep.get('html')}")
    rprint("[dim]Scan body preview:[/dim]")
    rprint(json.dumps(res.get("body", {}), indent=2)[:4000])

@app.command("report-open")
def report_open_cmd(reports_dir: Optional[str] = typer.Option(None, "--reports", "-r")):
    base = Path(reports_dir) if reports_dir else Path("reports")
    if not base.exists():
        rprint("[red]No reports directory found yet.[/red]"); raise typer.Exit(code=1)
    folders = sorted([p for p in base.rglob("*") if p.is_dir()], key=lambda x: x.stat().st_mtime, reverse=True)
    wifi = [f for f in folders if "wireless" in str(f).lower() or "wireless" in "".join([c.name for c in f.parents])]
    if not wifi:
        rprint("[yellow]No wireless reports found.[/yellow]"); raise typer.Exit(code=0)
    rprint("[green]Latest wireless report folders (top 10):[/green]")
    for f in wifi[:10]:
        rprint(f"{f}")

