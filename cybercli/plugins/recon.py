# cybercli/plugins/recon.py
import typer
from rich import print as rprint
from rich.console import Console

from cybercli.core.recon_core import (
    run_recon,
    auto_open_report,
    hacking_vibes,
    ultra_vibes,
)

console = Console()
app = typer.Typer(help="Reconnaissance module")

@app.command("start")
def start(
    target: str = typer.Argument(..., help="Target domain or URL (e.g., example.com or https://example.com)"),
    outdir: str = typer.Option("artifacts", "--outdir", "-o", help="Output directory base"),
    base_url: str = typer.Option("", "--base-url", help="Override base URL (default derived from target)"),

    # 🔹 By default sirf basics True rahenge
    whois: bool = typer.Option(True, help="WHOIS lookup"),
    dns: bool = typer.Option(True, help="DNS records (A, AAAA, MX, NS, TXT, SOA)"),
    cert: bool = typer.Option(True, help="SSL/TLS certificate info"),
    ips: bool = typer.Option(True, help="Resolve IP addresses"),

    # 🔹 Advance modules default False
    subdomains: bool = typer.Option(False, help="Subdomain enum (crt.sh + SAN)"),
    ports: bool = typer.Option(False, help="Quick common-port TCP connect scan"),
    http: bool = typer.Option(False, help="HTTP banner/page parse"),
    nmap: bool = typer.Option(False, help="Run nmap -sV -Pn (30s host-timeout)"),
    osint: bool = typer.Option(False, help="Reverse IP, Wayback, JS endpoints, favicon hash"),
    deep: bool = typer.Option(False, help="Dir brute, secrets scan, heuristic CVE hints, security.txt"),
    screens: bool = typer.Option(False, help="Best-effort screenshots (Selenium/Playwright/wkhtmltoimage)"),
    tra: bool = typer.Option(False, help="Basic risk scoring (TRA)"),
    graph: bool = typer.Option(False, help="Asset graph (Graphviz)"),
    report: bool = typer.Option(False, help="HTML single-file report"),
    verbose: bool = typer.Option(True, "--verbose", "-v", help="Verbose/progress logs"),

    supply: bool = typer.Option(False, "--supply", help="Advanced Supply Chain mapping (3rd party , CDN , vendors , lib)"),

    # 🔹 Hacker vibes
    vibes: bool = typer.Option(False, "--vibes", help="Hacker vibes animation"),
    ultravibes: bool = typer.Option(False, "--ultravibes", help="ULTRA hacker animation"),
):
    """
    Fire recon with basics by default (WHOIS, DNS, CERT, IPs).
    Use flags to unlock advanced modules.
    """

    # Animation
    if ultravibes:
        ultra_vibes(target)
    elif vibes:
        hacking_vibes(target)

    # Agar sirf basics run ho rahe hain aur koi flag nahi diya
    if not any([subdomains, ports, http, nmap, osint, deep, screens, tra, graph, report]):
        console.print("[yellow bold]⚠ More details available![/yellow bold]")
        console.print("[cyan]👉 Use extra flags for advanced recon (e.g., --osint, --deep, --graph, --report)[/cyan]\n")

    # Run recon
    run_recon(
        target=target,
        base_url=base_url or None,
        outdir=outdir,
        do_whois=whois,
        do_dns=dns,
        do_subdomains=subdomains,
        do_ports=ports,
        do_http=http,
        do_nmap=nmap,
        do_osint=osint,
        do_deep=deep,
        do_screens=screens,
        do_tra=tra,
        do_graph=graph,
        do_report=report,
        verbose=verbose,
        do_supply=supply
    )

    auto_open_report(outdir, target, graph=graph, report=report)


@app.command("usage")
def usage():
    rprint("[bold cyan]Examples[/bold cyan]")
    rprint("  python3 -m cybercli.main recon start example.com -v --ultravibes")
    rprint("  python3 -m cybercli.main recon start target.com --osint --deep --graph --report")
    rprint("  python3 -m cybercli.main recon start target.com --outdir artifacts --no-screens")
    rprint("  python3 -m cybercli.main recon start target.com --supply # advanced supply chain mapping")

