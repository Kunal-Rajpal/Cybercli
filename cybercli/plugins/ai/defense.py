# cybercli/plugins/ai/defense.py
import typer
import json
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from cybercli.core.predict_core import PredictCore
from cybercli.core.threat_intel_core import ThreatIntelCore

ai_defense_app = typer.Typer(help="AI Defensive assistant: recommendations and hardening")

console = Console()
_predictor = PredictCore()
_ti = ThreatIntelCore()

def _hacker_banner(title: str):
    txt = Text.assemble(
        ("╭─ ", "bright_magenta"),
        (title, "bold cyan"),
        (" ─╮", "bright_magenta")
    )
    console.print(Panel(txt, border_style="magenta"))

@ai_defense_app.command("harden")
def harden_from_json(env_json: str = typer.Option(..., help="Path to exported environment JSON (open_ports, outdated_packages, weak_passwords)")):
    """
    Read a JSON file describing environment indicators and output prioritized hardening advice.
    Example JSON:
      {"open_ports": 12, "outdated_packages": 3, "weak_passwords": true}
    """
    _hacker_banner("AI DEFENSE • HARDEN")
    try:
        with open(env_json, "r") as f:
            env = json.load(f)
    except Exception as e:
        console.print(f"[red]Failed to read JSON: {e}[/red]")
        raise typer.Exit()

    console.print("[yellow]Computing prediction & recommended actions…[/yellow]")
    res = _predictor.predict(env)
    console.print(Panel.fit(Text(str(res)), title="Defense Plan", border_style="green"))

