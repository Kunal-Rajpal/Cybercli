import typer
from rich import print
from rich.table import Table

from cybercli.core.vuln_lifecycle_core import VulnerabilityCore

app = typer.Typer(help="Vulnerability Lifecycle Engine")
core = VulnerabilityCore()


@app.command("add")
def add(
    engagement: str = typer.Option(...),
    asset_id: str = typer.Option(...),
    title: str = typer.Option(...),
    category: str = typer.Option(...),
    attack_vector: str = typer.Option(...),
    severity: str = typer.Option(...),
    confidence: str = typer.Option("medium"),
    tool: str = typer.Option("manual"),
    desc: str = typer.Option(""),
):
    vuln = core.add_vulnerability(
        engagement_id=engagement,
        asset_id=asset_id,
        title=title,
        category=category,
        attack_vector=attack_vector,
        description=desc,
        severity=severity,
        confidence=confidence,
        discovered_by=tool,
    )
    print("[green]✔ Vulnerability added[/green]")
    print(vuln)


@app.command("triage")
def triage(
    vuln_id: str,
    business_impact: str,
    exploitability: str,
):
    v = core.triage(vuln_id, business_impact, exploitability)
    print("[yellow]✔ Vulnerability triaged[/yellow]")
    print(v)


@app.command("list")
def list_vulns(
    engagement: str = typer.Option(None),
    status: str = typer.Option(None),
):
    vulns = core.list(engagement, status)

    table = Table(title="Vulnerabilities")
    table.add_column("ID")
    table.add_column("Asset")
    table.add_column("Title")
    table.add_column("Severity")
    table.add_column("Risk")
    table.add_column("Status")

    for v in vulns:
        table.add_row(
            v["vuln_id"],
            v["asset_id"],
            v["title"],
            v["severity"],
            v["risk_rating"],
            v["status"],
        )

    print(table)

