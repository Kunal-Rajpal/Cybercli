# cybercli/plugins/ai/classifier.py
import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from cybercli.core.classifier_core import ClassifierCore

ai_classifier_app = typer.Typer(help="AI lightweight classifier (keyword heuristics)")

console = Console()
_clf = ClassifierCore()

def _hacker_banner(title: str):
    txt = Text.assemble(
        ("╭─ ", "bright_magenta"),
        (title, "bold cyan"),
        (" ─╮", "bright_magenta")
    )
    console.print(Panel(txt, border_style="magenta"))

@ai_classifier_app.command("text")
def classify_text(text: str):
    """Classify a piece of text (nmap output, log lines, notes)."""
    _hacker_banner("AI CLASSIFIER • TEXT")
    console.print("[yellow]Analyzing text…[/yellow]")
    out = _clf.classify(text)
    console.print(Panel.fit(Text(str(out)), title="Classification", border_style="cyan"))

