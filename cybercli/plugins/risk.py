import typer
from rich import print
from rich.table import Table

from cybercli.core.risk_core import RiskEngine

app = typer.Typer(help="Risk & Business Impact Engine")
engine = RiskEngine()


@app.command("add")
def add_risk(
    vuln_id: str,
    service: str,
    owner: str,
    likelihood: int = typer.Option(..., help="1–5"),
    financial: int = typer.Option(..., help="1–5"),
    operational: int = typer.Option(..., help="1–5"),
    compliance: int = typer.Option(..., help="1–5"),
    reputation: int = typer.Option(..., help="1–5"),
    strategic: int = typer.Option(..., help="1–5"),
):
    risk = engine.register_risk(
        vuln_id=vuln_id,
        likelihood=likelihood,
        affected_service=service,
        owner=owner,
        impact_breakdown={
            "financial": financial,
            "operational": operational,
            "compliance": compliance,
            "reputation": reputation,
            "strategic": strategic,
        }
    )

    print("[green]✔ Risk registered[/green]")
    print(risk)


@app.command("list")
def list_risks(level: str = typer.Option(None)):
    risks = engine.list(level)

    table = Table(title="Risk Register")
    table.add_column("Risk ID")
    table.add_column("Vuln")
    table.add_column("Service")
    table.add_column("Level")
    table.add_column("Score")
    table.add_column("Owner")

    for r in risks:
        table.add_row(
            r["risk_id"],
            r["vuln_id"],
            r["affected_service"],
            r["risk_level"],
            str(r["overall_risk_score"]),
            r["owner"],
        )

    print(table)

