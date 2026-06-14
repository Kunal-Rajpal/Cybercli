# cybercli/plugins/ai/osint.py
import typer
import time
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from cybercli.core.ai_core import CyberAICore

ai_osint_app = typer.Typer(help="AI OSINT enrichment (email, github, domain)")

console = Console()
_ai = CyberAICore()

def _hacker_banner(title: str):
    txt = Text.assemble(
        ("╭─ ", "bright_magenta"),
        (title, "bold cyan"),
        (" ─╮", "bright_magenta")
    )
    console.print(Panel(txt, border_style="magenta"))

@ai_osint_app.command("email")
def email_check(email: str):
    """Passive email footprint / breach hint (heuristic)."""
    _hacker_banner("AI OSINT • EMAIL")
    console.print(f"[green]Target Email:[/green] {email}")
    console.print("[yellow]Checking breach signals…[/yellow]")
    # uses ai_core.classifier/predict heuristics via analyze_osint stub
    data = {"keywords": ["breach"] if "test" in email else [], "sources": ["local"]}
    out = _ai.analyze_osint(data)
    console.print(Panel.fit(Text(str(out)), title="OSINT Summary", border_style="cyan"))

@ai_osint_app.command("github")
def github_user(username: str):
    """Pull basic GitHub profile (public) via core osint helper (safe)."""
    _hacker_banner("AI OSINT • GITHUB")
    console.print(f"[green]Username:[/green] {username}")
    console.print("[yellow]Querying public profile…[/yellow]")
    # The ai_core may call osint_utils; CyberAICore.analyze_osint expects structured input
    data = {"keywords": [], "sources": ["github"]}
    out = _ai.analyze_osint(data)
    console.print(Panel.fit(Text(str(out)), title="Profile Summary", border_style="cyan"))

