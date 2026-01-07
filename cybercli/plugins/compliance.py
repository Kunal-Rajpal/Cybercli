import typer
from rich import print
from rich.panel import Panel
from rich.table import Table

from cybercli.core.complaince_core import ComplianceEngine
from cybercli.core.vuln_lifecycle_core import VulnerabilityCore

app = typer.Typer(help="Compliance & Regulatory Mapping Engine")

compliance = ComplianceEngine()
vuln_engine = VulnerabilityCore()


@app.command("check")
def check():
    """
    Map vulnerabilities to compliance frameworks
    """

    vulns = vuln_engine.list_vulnerabilities()
    if not vulns:
        print("[red]No vulnerabilities found[/red]")
        return

    table = Table(title="Compliance Violations")
    table.add_column("Vulnerability")
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Title")

    violated = 0

    for v in vulns:
        mappings = compliance.map_finding(v)
        if mappings:
            violated += len(mappings)
            for m in mappings:
                table.add_row(
                    v["title"],
                    m["framework"],
                    m["control_id"],
                    m["title"]
                )

    score = compliance.compliance_score(
        total_controls=20,  # baseline configurable later
        violated=violated
    )

    print(Panel.fit(
        f"[bold cyan]COMPLIANCE SUMMARY[/bold cyan]\n"
        f"Violations: {violated}\n"
        f"Compliance Score: {score}%"
    ))

    print(table)

