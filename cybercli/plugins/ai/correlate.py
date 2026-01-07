# cybercli/plugins/ai/correlate.py
import typer
import json
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from cybercli.core.correlation_core import CorrelationCore

ai_correlate_app = typer.Typer(help="AI correlation utilities (clusters & insights)")

console = Console()
_corr = CorrelationCore()

def _hacker_banner(title: str):
    txt = Text.assemble(
        ("╭─ ", "bright_magenta"),
        (title, "bold cyan"),
        (" ─╮", "bright_magenta")
    )
    console.print(Panel(txt, border_style="magenta"))

@ai_correlate_app.command("file")
def correlate_file(events_json: str = typer.Option(..., help="Path to JSON array of events")):
    """
    Reads a JSON array of events and returns correlated clusters.
    Each event is a dict; recommended keys: timestamp, source, message.
    """
    _hacker_banner("AI CORRELATE • FILE")
    try:
        with open(events_json, "r") as f:
            events = json.load(f)
    except Exception as e:
        console.print(f"[red]Error reading events file: {e}[/red]")
        raise typer.Exit()

    console.print("[yellow]Running correlation engine…[/yellow]")
    out = _corr.correlate(events)
    console.print(Panel.fit(Text(str(out)), title="Correlation", border_style="magenta"))

