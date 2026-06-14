# cybercli/plugins/ai/report.py
import typer
import json
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from datetime import datetime

ai_report_app = typer.Typer(help="AI report generator (assemble results into a readable report)")

console = Console()

def _hacker_banner(title: str):
    txt = Text.assemble(
        ("╭─ ", "bright_magenta"),
        (title, "bold cyan"),
        (" ─╮", "bright_magenta")
    )
    console.print(Panel(txt, border_style="magenta"))

@ai_report_app.command("assemble")
def assemble_report(parts_json: str = typer.Option(..., help="Path to JSON object containing parts: osint, scan_risk, correlation, prediction, intel")):
    """
    Accepts a JSON file produced by CyberAICore.full_ai_pipeline or similar dict:
    { "osint": {...}, "scan_risk": {...}, "correlation": {...}, "prediction": {...}, "intel": {...} }
    Produces a simple textual report in <timestamp>_report.txt
    """
    _hacker_banner("AI REPORT • ASSEMBLE")
    try:
        with open(parts_json, "r") as f:
            parts = json.load(f)
    except Exception as e:
        console.print(f"[red]Cannot read parts JSON: {e}[/red]")
        raise typer.Exit()

    # build a short report
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    fname = f"reports/ai_report_{ts}.txt"
    lines = []
    lines.append("CYBERCLI AI REPORT")
    lines.append("=" * 40)
    lines.append(f"Generated: {ts}")
    for k in ("osint", "scan_risk", "correlation", "prediction", "intel"):
        if k in parts:
            lines.append("")
            lines.append(f"--- {k.upper()} ---")
            lines.append(json.dumps(parts[k], indent=2))
    try:
        with open(fname, "w") as f:
            f.write("\n".join(lines))
    except Exception as e:
        console.print(f"[red]Failed to write report: {e}[/red]")
        raise typer.Exit()

    console.print(Panel.fit(Text(f"Saved AI report: {fname}"), title="REPORT", border_style="green"))

