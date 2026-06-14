import typer
from rich import print
from cybercli.core.consent_core import ConsentCore, ConsentError

app = typer.Typer(help="Consent & Legal Proof")

core = ConsentCore()


@app.command("add")
def add(
    engagement_id: str = typer.Option(...),
    signed_by: str = typer.Option(...),
    proof_file: str = typer.Option(...),
):
    entry = core.add_consent(
        engagement_id, signed_by, proof_file
    )
    print("[green]✔ Consent recorded[/green]")
    print(entry)


@app.command("check")
def check(engagement_id: str):
    try:
        core.validate(engagement_id)
        print("[green]✔ Consent valid[/green]")
    except ConsentError as e:
        print(f"[red]{e}[/red]")

