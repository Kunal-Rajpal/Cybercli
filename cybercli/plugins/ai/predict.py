# cybercli/plugins/ai/predict.py
import typer
import json
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from cybercli.core.predict_core import PredictCore

ai_predict_app = typer.Typer(help="AI Predictive engine (trend & score)")

console = Console()
_predict = PredictCore()

def _hacker_banner(title: str):
    txt = Text.assemble(
        ("╭─ ", "bright_magenta"),
        (title, "bold cyan"),
        (" ─╮", "bright_magenta")
    )
    console.print(Panel(txt, border_style="magenta"))

@ai_predict_app.command("score")
def predict_from_json(indicators_json: str = typer.Option(..., help="Path to JSON indicators for prediction")):
    """
    Accepts JSON with keys like 'open_ports','outdated_packages','weak_passwords'.
    Returns a predicted future score and trend.
    """
    _hacker_banner("AI PREDICT • SCORE")
    try:
        with open(indicators_json, "r") as f:
            indicators = json.load(f)
    except Exception as e:
        console.print(f"[red]Cannot open JSON: {e}[/red]")
        raise typer.Exit()
    console.print("[yellow]Running prediction model…[/yellow]")
    out = _predict.predict(indicators)
    console.print(Panel.fit(Text(str(out)), title="Prediction", border_style="cyan"))

