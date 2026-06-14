import typer
from rich import print
from rich.panel import Panel
from cybercli.core.automation_guard_core import AutomationEngine

app = typer.Typer(help="Safe Automation Control Engine")

engine = AutomationEngine()


@app.command("add-rule")
def add_rule(
    name: str,
    actions: str,
    max_severity: str = "medium",
    consent_required: bool = True
):
    rule_id = engine.add_rule(
        name=name,
        allowed_actions=actions.split(","),
        max_severity=max_severity,
        requires_consent=consent_required
    )
    print(Panel.fit(
        f"[green]Rule Created[/green]\n{name}\nID: {rule_id}"
    ))


@app.command("check")
def check(
    action: str,
    severity: str,
    consent: bool = True
):
    allowed = engine.is_action_allowed(action, severity, consent)
    if allowed:
        print(Panel.fit("[green]ACTION ALLOWED[/green]"))
    else:
        print(Panel.fit("[red]ACTION BLOCKED[/red]"))


@app.command("kill-switch")
def kill_switch(state: bool):
    engine.kill_switch(state)
    print(Panel.fit(f"[yellow]Kill switch set to {state}[/yellow]"))

