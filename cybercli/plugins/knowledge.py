import typer
from rich import print
from rich.panel import Panel
from rich.table import Table

from cybercli.core.knowledge_graph_core import KnowledgeGraph

app = typer.Typer(help="Knowledge Graph — Security Brain")

kg = KnowledgeGraph()


@app.command("add-asset")
def add_asset(name: str, asset_type: str = "server"):
    node_id = kg.add_node("asset", name, {"asset_type": asset_type})
    print(Panel.fit(f"[green]Asset added:[/green] {name}\nID: {node_id}"))


@app.command("add-vuln")
def add_vuln(title: str, severity: str = "medium"):
    node_id = kg.add_node("vulnerability", title, {"severity": severity})
    print(Panel.fit(f"[red]Vulnerability added:[/red] {title}\nID: {node_id}"))


@app.command("link")
def link(src: str, relation: str, dst: str):
    kg.link(src, relation, dst)
    print(Panel.fit(f"[cyan]Linked:[/cyan] {src} --{relation}--> {dst}"))


@app.command("show")
def show(node_type: str):
    nodes = kg.find_by_type(node_type)

    table = Table(title=f"{node_type.upper()} NODES")
    table.add_column("ID")
    table.add_column("Label")
    table.add_column("Metadata")

    for n in nodes:
        table.add_row(n["id"], n["label"], str(n["metadata"]))

    print(table)

