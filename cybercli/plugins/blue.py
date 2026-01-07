# #!/usr/bin/env python3
# # cybercli/plugins/blue.py
# # -*- coding: utf-8 -*-
# """
# Typer plugin for Blue Team monitoring helpers (non-destructive).
# """

# from pathlib import Path
# from typing import Optional, List
# import typer, json
# from rich import print as rprint

# from cybercli.core import blue_core as bcore

# app = typer.Typer(help="Blue Team helpers (monitoring & detection)")

# REPORTS_ROOT = Path("reports")

# def _ensure_authorization():
#     rprint("[yellow]You must have written authorization to run monitoring and file scans on systems where you have permission.[/yellow]")
#     if not typer.confirm("Do you have authorization to run these detection checks?", default=False):
#         rprint("[red]Authorization required. Aborting.[/red]")
#         raise typer.Exit(code=1)

# @app.command("quick-checks")
# def quick_checks(target_name: str = typer.Argument("blue_target", help="Logical target/folder name"), baseline_paths: Optional[str] = typer.Option(None, "--paths", help="Comma-separated list of paths to baseline for file-integrity")):
#     _ensure_authorization()
#     bp = [p.strip() for p in baseline_paths.split(",")] if baseline_paths else None
#     rprint("[cyan]Running blue quick checks (processes, net, logs, optional baseline)...[/cyan]")
#     res = bcore.blue_quick_checks(REPORTS_ROOT, target_name, baseline_paths=bp)
#     rep = res.get("report",{})
#     rprint(f"[green]Report saved:[/green] TXT: {rep.get('txt')}  HTML: {rep.get('html')}")
#     rprint("[dim]Summary preview:[/dim]")
#     rprint(json.dumps(res.get("body",{}), indent=2)[:4000])

# @app.command("baseline-build")
# def baseline_build(paths: str = typer.Argument(..., help="Comma-separated list of paths to include in baseline"), out: Optional[str] = typer.Option(None, "--out", "-o", help="Output baseline filename (saved under reports/<target>/<stamp>/blue)")):
#     _ensure_authorization()
#     p_list = [p.strip() for p in paths.split(",")]
#     # use a generic target folder
#     target_name = "baseline_build"
#     rprint("[cyan]Building file integrity baseline...[/cyan]")
#     run_root = Path("reports") / target_name / bcore.now_stamp() / "blue"
#     run_root.mkdir(parents=True, exist_ok=True)
#     outname = out or "fint_baseline.json"
#     res = bcore.build_file_integrity_baseline(p_list, run_root / outname)
#     rprint(f"[green]Baseline saved:[/green] {res.get('baseline_file')} Files: {res.get('files')}")

# @app.command("yara-scan")
# def yara_scan(rules: str = typer.Argument(..., help="Path to YARA rules file"), paths: str = typer.Argument(..., help="Comma-separated list of paths to scan")):
#     _ensure_authorization()
#     p_list = [p.strip() for p in paths.split(",")]
#     rprint("[cyan]Running YARA scan (requires yara-python)...[/cyan]")
#     res = bcore.yara_scan_paths(rules, p_list)
#     rprint(json.dumps(res, indent=2)[:4000])










## next phase blue team need to be use 
import typer
from rich import print
from rich.panel import Panel
from rich.table import Table

from cybercli.core.defense_map_core import DefenseMappingEngine
from cybercli.core.attack_path_core import AttackPathEngine

app = typer.Typer(help="Blue Team Detection & Defense Engine")

defense = DefenseMappingEngine()
attack = AttackPathEngine()


@app.command("map")
def map_latest():
    """
    Map latest attack path to detection & defense
    """

    paths = attack.list_paths()
    if not paths:
        print("[red]No attack paths found[/red]")
        return

    latest = paths[-1]
    enriched = defense.enrich_attack_path(latest["kill_chain"])
    coverage = defense.coverage_score(latest["kill_chain"])

    print(Panel.fit(
        f"[bold cyan]BLUE TEAM MAPPING[/bold cyan]\n\n"
        f"Path: {latest['path_id']}\n"
        f"Coverage: {coverage}%\n"
        f"Risk: {latest['risk_level']}"
    ))

    table = Table(title="Detection & Defense")
    table.add_column("Phase")
    table.add_column("Technique")
    table.add_column("Detection")
    table.add_column("Prevention")

    for step in enriched:
        d = step["defense"]
        if isinstance(d, dict):
            table.add_row(
                step["phase"],
                step["technique_id"],
                "\n".join(d["detect"]),
                "\n".join(d["prevent"]),
            )
        else:
            table.add_row(
                step["phase"],
                step["technique_id"],
                "❌ None",
                "❌ None",
            )

    print(table)
















