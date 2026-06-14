# cybercli/plugins/supplychain.py
import json
import typer
from pathlib import Path
from rich.console import Console

console = Console()
app = typer.Typer(help="Supply chain security helpers (SBOM, audits)")

@app.command("sbom-generate")
def sbom_generate(req_path: str = typer.Option(..., help="requirements.txt or package.json")):
    p = Path(req_path)
    if not p.exists():
        console.print("[red]Not found[/red]"); raise typer.Exit()
    if p.suffix == ".json":
        data = json.loads(p.read_text(encoding="utf-8"))
        deps = data.get("dependencies", {})
    else:
        deps = [line.strip() for line in p.read_text().splitlines() if line.strip() and not line.startswith("#")]
    console.print({"sbom_count": len(deps), "sample": list(deps)[:10]})

