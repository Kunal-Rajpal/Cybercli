import typer
from rich import print
from rich.table import Table

from cybercli.core.asset_inventory_core import AssetInventoryCore

app = typer.Typer(help="Asset Inventory — Brain Memory")

core = AssetInventoryCore()


@app.command("add")
def add(
    engagement: str = typer.Option(...),
    asset_type: str = typer.Option(..., help="domain | ip | api | cloud | app"),
    identifier: str = typer.Option(...),
    owner: str = typer.Option("unknown"),
    criticality: str = typer.Option("medium"),
    tags: str = typer.Option("", help="comma separated"),
    source: str = typer.Option("manual"),
):
    asset = core.add_asset(
        engagement_id=engagement,
        asset_type=asset_type,
        identifier=identifier,
        owner=owner,
        criticality=criticality,
        tags=[t.strip() for t in tags.split(",") if t],
        source=source,
    )
    print("[green]✔ Asset added[/green]")
    print(asset)


@app.command("list")
def list_assets(engagement: str = typer.Option(None)):
    assets = core.list_assets(engagement)
    table = Table(title="Asset Inventory")
    table.add_column("ID")
    table.add_column("Type")
    table.add_column("Identifier")
    table.add_column("Criticality")
    table.add_column("Owner")

    for a in assets:
        table.add_row(
            a["asset_id"],
            a["type"],
            a["identifier"],
            a["criticality"],
            a["owner"],
        )

    print(table)

