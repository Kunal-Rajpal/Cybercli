# cybercli/plugins/iotsec.py
import json
import typer
from pathlib import Path
from rich.console import Console

console = Console()
app = typer.Typer(help="IoT security helpers (passive analysis)")

@app.command("iot-discover")
def iot_discover(metadata_json: str = typer.Option(..., help="Network device metadata json")):
    data = json.loads(Path(metadata_json).read_text(encoding="utf-8"))
    devices = data.get("devices", [])
    console.print({"devices_found": len(devices), "sample": devices[:8]})

@app.command("mqtt-enum")
def mqtt_enum(metadata_json: str = typer.Option(..., help="Network metadata json")):
    data = json.loads(Path(metadata_json).read_text(encoding="utf-8"))
    topics = set()
    for d in data.get("devices", []):
        topics.update(d.get("mqtt_topics", []))
    console.print({"unique_topics": len(topics), "topics_sample": list(topics)[:10]})

