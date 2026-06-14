import typer
from rich import print
from rich.panel import Panel
from rich.table import Table

from cybercli.core.attack_path_core import AttackPathEngine

app = typer.Typer(help="Attack Path & Kill Chain Engine")
engine = AttackPathEngine()


@app.command("simulate")
def simulate():
    """
    Demo realistic attack path
    """

    path = engine.create_path(
        entry_asset="Public Web App",
        target_asset="Production Database",
        likelihood=5,
        impact="Data Exfiltration + Business Outage",
        techniques=[
            {
                "phase": "Initial Access",
                "technique_id": "T1190",
                "name": "Exploit Public-Facing App",
                "description": "Unauth RCE via API flaw",
            },
            {
                "phase": "Execution",
                "technique_id": "T1059",
                "name": "Command Execution",
                "description": "Reverse shell spawned",
            },
            {
                "phase": "Privilege Escalation",
                "technique_id": "T1068",
                "name": "Kernel Exploit",
                "description": "Root access gained",
            },
            {
                "phase": "Credential Access",
                "technique_id": "T1003",
                "name": "Credential Dumping",
                "description": "DB creds extracted",
            },
            {
                "phase": "Impact",
                "technique_id": "T1486",
                "name": "Data Encryption / Exfiltration",
                "description": "Sensitive data stolen",
            },
        ],
    )

    print(Panel.fit(
        f"[bold red]ATTACK PATH SIMULATED[/bold red]\n\n"
        f"Entry: {path['entry_asset']}\n"
        f"Target: {path['target_asset']}\n"
        f"Risk: {path['risk_level']}\n"
        f"Impact: {path['impact']}"
    ))


@app.command("list")
def list_paths():
    paths = engine.list_paths()

    table = Table(title="Attack Paths")
    table.add_column("Path ID")
    table.add_column("Entry")
    table.add_column("Target")
    table.add_column("Steps")
    table.add_column("Risk")

    for p in paths:
        table.add_row(
            p["path_id"],
            p["entry_asset"],
            p["target_asset"],
            str(p["steps"]),
            p["risk_level"],
        )

    print(table)

