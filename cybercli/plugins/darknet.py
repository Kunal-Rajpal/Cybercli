# cybercli/plugins/darknet.py
import json
import typer
from pathlib import Path
from rich.console import Console

console = Console()
app = typer.Typer(help="Darknet intelligence (safe simulations over local corpora)")

@app.command("breach-leaks")
def breach_leaks(corpus: str = typer.Option(..., help="Local JSON leak corpus"), keyword: str = typer.Option(...)):
    data = json.loads(Path(corpus).read_text(encoding="utf-8"))
    hits = [item for item in data if keyword.lower() in json.dumps(item).lower()]
    console.print({"hits": len(hits), "sample": hits[:5]})

