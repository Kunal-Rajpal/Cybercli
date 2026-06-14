import typer
import subprocess
import json
import os
from datetime import datetime
from rich import print
from rich.table import Table
from rich.progress import Progress
from rich.console import Console

app = typer.Typer(help="SSL/TLS Scanner using testssl.sh")
console = Console()


REPORT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "reports",
    "ssl"
)
os.makedirs(REPORT_DIR, exist_ok=True)


def run_testssl(target: str, json_path: str, html_path: str):
    cmd = [
        "testssl",
        "--quiet",
        "--warnings", "off",
        f"--jsonfile={json_path}",
        f"--htmlfile={html_path}",
        target
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


def load_json(path: str):
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except:
        return None


def detect_issues(findings):
    weak = []
    expired = []
    hostname_bad = []
    tls_weak = []
    for f in findings:
        msg = f.get("finding", "")
        sid = f.get("id", "")
        if "expired" in msg.lower():
            expired.append(f)
        if "mismatch" in msg.lower():
            hostname_bad.append(f)
        if "TLS1" in sid and "offered" in msg.lower():
            if "TLS1_3" not in sid:
                tls_weak.append(f)
        if "weak" in msg.lower() or "anon" in msg.lower():
            weak.append(f)
    return weak, expired, hostname_bad, tls_weak


def colorize(sev):
    if sev == "CRITICAL":
        return "[bold red]"
    if sev == "HIGH":
        return "[red]"
    if sev == "WARN":
        return "[yellow]"
    if sev == "OK":
        return "[green]"
    return "[cyan]"


def export_md(target, findings, md_path):
    with open(md_path, "w") as f:
        f.write(f"# SSL Report for {target}\n\n")
        for item in findings:
            sev = item.get("severity", "INFO")
            msg = item.get("finding", "")
            f.write(f"- **{sev}** – {msg}\n")
    return md_path


@app.command()
def check(target: str):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = os.path.join(REPORT_DIR, f"{target}-{timestamp}.json")
    html_path = os.path.join(REPORT_DIR, f"{target}-{timestamp}.html")
    md_path = os.path.join(REPORT_DIR, f"{target}-{timestamp}.md")

    with Progress() as progress:
        task = progress.add_task("[cyan]Running testssl...", total=100)
        for _ in range(3):
            progress.update(task, advance=33)
        result = run_testssl(target, json_path, html_path)
        progress.update(task, total=100)

    print(f"[bold green]✔ Scan Completed[/bold green]")
    data = load_json(json_path)

    print(f"[white]JSON saved:[/white] {json_path}")
    print(f"[white]HTML saved:[/white] {html_path}")

    if not data:
        print("[yellow]No JSON structure detected — check HTML[/yellow]")
        return

    # CASE 1: testssl sometimes returns a pure list
    if isinstance(data, list):
        findings = data
    else:
        findings = data.get("scanResult", {}).get("findings", [])

    print("\n[bold cyan]== Findings Summary ==[/bold cyan]")

    if not findings:
        print("[green]No major issues detected 🤝[/green]")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Severity")
    table.add_column("Finding")

    for f in findings:
        sev = f.get("severity", "INFO")
        msg = f.get("finding", "")
        table.add_row(f"{colorize(sev)}{sev}", msg)

    console.print(table)

    weak, expired, mismatch, tls_weak = detect_issues(findings)

    print("\n[bold red]⚠ Deep Risk Checks[/bold red]")
    if weak:
        print(f"[yellow]Weak Ciphers Found: {len(weak)}[/yellow]")
    if expired:
        print(f"[red]Expired Cert Issues: {len(expired)}[/red]")
    if mismatch:
        print(f"[red]Hostname Mismatch Detected[/red]")
    if tls_weak:
        print(f"[yellow]Weak TLS Versions Enabled[/yellow]")

    export_md(target, findings, md_path)
    print(f"\n[bold green]Markdown exported:[/bold green] {md_path}")

    print("\n[cyan]Want Elastic/Graylog push next?[/cyan]  🚀🔥")

