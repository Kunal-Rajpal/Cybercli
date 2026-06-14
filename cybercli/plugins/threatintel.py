#!/usr/bin/env python3
# cybercli/plugins/threatintel.py
# -*- coding: utf-8 -*-
"""
Typer plugin for Threat Intelligence features.

Commands:
 - ioc-scan      : scan files/directories for provided hash/string IOCs
 - domain-triage : run resolve/whois triage for a domain
 - phish-check   : score a URL for phishing likelihood (heuristic)
 - dnsbl-check   : check IP against common DNSBLs
 - vt-lookup     : stub for VirusTotal-style lookup (requires API key; safe stub)
"""

from pathlib import Path
from typing import List, Optional
import typer, json
from rich import print as rprint

from cybercli.core import threat_intel_core as ticore

app = typer.Typer(help="Threat Intelligence helpers (safe, read-only)")
REPORTS_ROOT = Path("reports")

def _ensure_authorization():
    rprint("[yellow]You must have explicit written authorization to run threat-intel checks on data you own or are authorized to scan.[/yellow]")
    if not typer.confirm("Do you have authorization to scan these files/domains?", default=False):
        rprint("[red]Authorization required. Aborting.[/red]")
        raise typer.Exit(code=1)

@app.command("ioc-scan")
def ioc_scan(
    target_name: str = typer.Argument("ti_target", help="Logical target/folder name"),
    paths: str = typer.Argument(..., help="Comma-separated list of files or directories to scan"),
    hashes: Optional[str] = typer.Option(None, "--hashes", help="Comma-separated list of hashes to check"),
    strings: Optional[str] = typer.Option(None, "--strings", help="Comma-separated list of strings/domains to search"),
):
    _ensure_authorization()
    paths_list = [p.strip() for p in paths.split(",")]
    hash_list = [h.strip().lower() for h in hashes.split(",")] if hashes else []
    str_list = [s.strip() for s in strings.split(",")] if strings else []
    rprint(f"[cyan]Scanning {paths_list} for IOCs...[/cyan]")
    res = ticore.ti_scan_iocs_and_report(REPORTS_ROOT, target_name, paths_list, ioc_hashes=hash_list, ioc_strings=str_list)
    rprint(f"[green]IOC scan report:[/green] {res['report']['html']}")

@app.command("domain-triage")
def domain_triage(
    target_name: str = typer.Argument("ti_domain", help="Logical target/folder name"),
    domain: str = typer.Argument(..., help="Domain to triage (example.com)")
):
    _ensure_authorization()
    rprint(f"[cyan]Running domain triage for {domain}...[/cyan]")
    res = ticore.ti_domain_triage_and_report(REPORTS_ROOT, target_name, domain)
    rprint(f"[green]Domain triage report:[/green] {res['report']['html']}")

@app.command("phish-check")
def phish_check(
    target_name: str = typer.Argument("ti_phish", help="Logical target/folder name"),
    url: str = typer.Argument(..., help="URL to evaluate")
):
    _ensure_authorization()
    rprint(f"[cyan]Scoring URL: {url}[/cyan]")
    res = ticore.ti_phish_check_and_report(REPORTS_ROOT, target_name, url)
    rprint(f"[green]Phishing score report:[/green] {res['report']['html']}")
    rprint(res["score"])

@app.command("dnsbl-check")
def dnsbl_check(ip: str = typer.Argument(..., help="IPv4 address to check")):
    _ensure_authorization()
    rprint(f"[cyan]Checking DNSBLs for {ip}...[/cyan]")
    res = ticore.dnsbl_lookup(ip)
    rprint(json.dumps(res, indent=2))

@app.command("vt-lookup")
def vt_lookup(resource: str = typer.Argument(..., help="Hash, IP, or domain to look up"), api_key: Optional[str] = typer.Option(None, "--key", help="VirusTotal API key (required to run)")):
    _ensure_authorization()
    if not api_key:
        rprint("[yellow]No API key provided; running safe stub. Supply --key to enable real queries (if implemented).[/yellow]")
    res = ticore.vt_lookup_stub(resource, api_key)
    rprint(json.dumps(res, indent=2))

