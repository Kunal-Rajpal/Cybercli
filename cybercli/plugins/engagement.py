import typer
from rich import print
from cybercli.core.engagement_core import EngagementCore, EngagementError

app = typer.Typer(help="Engagement & Scope Management")

core = EngagementCore()


@app.command("create")
def create(
    client: str = typer.Option(...),
    scope: str = typer.Option(..., help="Comma separated domains/IPs"),
    start: str = typer.Option(..., help="YYYY-MM-DD"),
    end: str = typer.Option(..., help="YYYY-MM-DD"),
    owner: str = typer.Option("redteam"),
):
    engagement = core.create_engagement(
        client=client,
        scope=[s.strip() for s in scope.split(",")],
        start_date=start,
        end_date=end,
        owner=owner,
    )
    print("[green]✔ Engagement created[/green]")
    print(engagement)


@app.command("check")
def check(target: str):
    try:
        eng = core.validate_target(target)
        print("[green]✔ Target allowed under engagement[/green]")
        print(eng)
    except EngagementError as e:
        print(f"[red]{e}[/red]")

