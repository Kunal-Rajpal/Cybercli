# cybercli/plugins/apisec.py
import json
import typer
from rich.console import Console
from pathlib import Path

console = Console()
app = typer.Typer(help="API Security passive tools (analysis, schema checks)")

def load_json(path): return json.loads(Path(path).read_text(encoding="utf-8"))

@app.command("api-endpoints")
def api_endpoints(spec: str = typer.Option(..., help="OpenAPI/Swagger JSON file")):
    doc = load_json(spec)
    paths = list(doc.get("paths", {}).keys())
    console.print({"endpoints_count": len(paths), "endpoints_sample": paths[:10]})

@app.command("api-schema-extract")
def api_schema_extract(spec: str = typer.Option(..., help="OpenAPI JSON")):
    doc = load_json(spec)
    schemas = list(doc.get("components", {}).get("schemas", {}).keys())
    console.print({"schema_count": len(schemas), "schemas_sample": schemas[:10]})

