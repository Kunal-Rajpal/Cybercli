#!/usr/bin/env python3
# cybercli/plugins/ad.py
# -*- coding: utf-8 -*-
"""
Active Directory module (safe enumeration only).
"""

from pathlib import Path
import typer
from rich import print as rprint

from cybercli.core import ad_core

app = typer.Typer(help="Active Directory enumeration (safe mode).")
REPORTS_ROOT = Path("reports")

def _ensure_auth():
    rprint("[yellow]AD enumeration requires explicit authorization.[/yellow]")
    if not typer.confirm("Do you have written permission to test this domain?", default=False):
        raise typer.Exit()

@app.command("enum")
def ad_enum(
    domain: str = typer.Argument(..., help="Target AD domain, e.g. contoso.com"),
    dc_host: str = typer.Argument(..., help="Domain Controller hostname/IP")
):
    _ensure_auth()

    rprint(f"[cyan]Starting AD enumeration on domain: {domain}[/cyan]")
    rep = ad_core.domain_info_bundle(domain, dc_host, REPORTS_ROOT)

    rprint("[green]AD enumeration complete.[/green]")
    rprint(f"[bold]TXT:[/bold] {rep['txt']}")
    rprint(f"[bold]HTML:[/bold] {rep['html']}")

@app.command("discover-dc")
def discover_dc(domain: str):
    _ensure_auth()
    rprint(f"[cyan]Discovering Domain Controllers for {domain}...[/cyan]")
    res = ad_core.discover_dc(domain)
    rprint(res)

@app.command("ldap")
def ldap_enum(dc_host: str):
    _ensure_auth()
    rprint(f"[cyan]Running LDAP discovery on {dc_host}...[/cyan]")
    rprint(ad_core.ldap_domain_enum(dc_host))

@app.command("rpc")
def rpc_enum(dc_host: str):
    _ensure_auth()
    rprint(f"[cyan]Enumerating users/groups via RPC on {dc_host}...[/cyan]")
    rprint(ad_core.rpc_user_enum(dc_host))






# For short code to 
# # cybercli/plugins/ad.py

# import typer
# import json
# from cybercli.core.ad_core import ActiveDirectoryAuditor

# app = typer.Typer(help="Active Directory Security Audit Module")


# @app.command("audit")
# def ad_audit(
#     dc_ip: str = typer.Argument(..., help="Domain Controller IP"),
#     domain: str = typer.Option(..., "-d", "--domain", help="Domain name"),
#     username: str = typer.Option(..., "-u", "--username", help="Domain user"),
#     password: str = typer.Option(..., "-p", "--password", help="Password"),
#     output: str = typer.Option("ad_audit_report.json", "-o", "--output", help="Save report JSON")
# ):
#     """
#     Runs the entire AD security audit suite (SAFE, NO EXPLOITATION)
#     """

#     typer.echo("[*] Connecting to Domain Controller...")
#     audit = ActiveDirectoryAuditor(dc_ip, domain, username, password)
#     typer.echo("[+] Connected!")

#     typer.echo("[*] Running full Active Directory audit...")
#     results = audit.full_audit()

#     with open(output, "w") as f:
#         json.dump(results, f, indent=4)

#     typer.echo(f"[+] Audit completed! Report saved to: {output}")

