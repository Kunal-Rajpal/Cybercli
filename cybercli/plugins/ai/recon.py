# cybercli/plugins/ai/recon.py
import typer
import socket
import time
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from cybercli.core.ai_core import CyberAICore
from cybercli.core.threat_intel_core import ThreatIntelCore

ai_recon_app = typer.Typer(help="AI-assisted Recon helpers (passive)")

console = Console()
_ai = CyberAICore()
_ti = ThreatIntelCore()

def _hacker_banner(title: str):
    txt = Text.assemble(
        ("╭─ ", "bright_magenta"),
        (title, "bold cyan"),
        (" ─╮", "bright_magenta")
    )
    console.print(Panel(txt, border_style="magenta"))

@ai_recon_app.command("dns")
def dns_lookup(domain: str):
    """Resolve DNS and enrich with passive intel."""
    _hacker_banner("AI RECON • DNS")
    console.print(f"[green]Target:[/green] {domain}")
    console.print("[yellow]Resolving DNS…[/yellow]", end="\n")
    try:
        ip = socket.gethostbyname(domain)
        console.print(f"[bold green]→ {domain} resolves to {ip}[/bold green]")
    except Exception as e:
        console.print(f"[red]DNS resolution failed: {e}[/red]")
        raise typer.Exit()

    console.print("[cyan]Fetching passive intel (geo, basic reputation)…[/cyan]")
    intel = _ti.domain_reputation(domain)
    console.print(Panel.fit(Text(str(intel)), title="Passive Intel", border_style="cyan"))

@ai_recon_app.command("banner")
def banner_guess(host: str, port: int = typer.Option(80)):
    """
    Passive banner guess: this function does not connect to remote services.
    Instead it uses heuristics on port to suggest likely services.
    """
    _hacker_banner("AI RECON • BANNER GUESS")
    console.print(f"[green]Host:[/green] {host}  [green]Port:[/green] {port}")
    # heuristic mapping
    mapping = {80: "http", 443: "https", 22: "ssh", 3306: "mysql", 6379: "redis"}
    svc = mapping.get(port, "unknown-service")
    console.print(f"[yellow]Heuristic service guess:[/yellow] {svc}")
    console.print("[dim]Note: this is passive heuristics only.[/dim]")

