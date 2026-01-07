# cybercli/plugins/mobilesec.py
import json
import typer
from rich.console import Console
from pathlib import Path

console = Console()
app = typer.Typer(help="Mobile app static analysis helpers (APK/IPA)")

def load_json(path): return json.loads(Path(path).read_text(encoding="utf-8"))

@app.command("apk-analyze")
def apk_analyze(manifest_json: str = typer.Option(..., help="APK manifest exported as JSON")):
    doc = load_json(manifest_json)
    perms = doc.get("uses-permission", [])
    high_risk = [p for p in perms if any(x in p.lower() for x in ("sms","call","record","contacts"))]
    console.print({"app": doc.get("package"), "permissions_count": len(perms), "high_risk": high_risk})

@app.command("cert-pin-check")
def cert_pin_check(info_json: str = typer.Option(..., help="Exported networking config JSON")):
    doc = load_json(info_json)
    pinned = doc.get("certificate_pinning", False)
    console.print({"certificate_pinning": pinned})

