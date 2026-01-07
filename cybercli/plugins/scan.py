# cybercli/plugins/scan.py
import typer
from rich import print as rprint
from cybercli.core.scan_core import run_scan, boss_scan_vibes

app = typer.Typer(help="Scanning module")

@app.command("start")
def start(
    target: str = typer.Argument(..., help="Target domain/IP"),
    outdir: str = typer.Option("artifacts", "--outdir", "-o"),
    base_url: str = typer.Option("", "--base-url"),
    quick: bool = typer.Option(True, help="Quick TCP connect scan"),
    nmap: bool = typer.Option(False, help="Run nmap -sV -Pn"),
    http: bool = typer.Option(True, help="HTTP probe"),
    robots: bool = typer.Option(True, help="Fetch robots.txt"),
    sitemap: bool = typer.Option(True, help="Try sitemap.xml"),
    js: bool = typer.Option(True, help="Extract JS endpoints"),
    tokens: bool = typer.Option(True, help="Detect tokens in HTML/JS"),
    links: bool = typer.Option(True, help="Collect links"),
    report: bool = typer.Option(True, help="Generate HTML/PDF (future)"),
    verbose: bool = typer.Option(True, "--verbose","-v"),
    vibes: bool = typer.Option(False, "--vibes"),
    ultravibes: bool = typer.Option(False, "--ultravibes"),
    ultraboss: bool = typer.Option(False, "--ultraboss"),
    simulate_exploit: bool = typer.Option(False, "--simulate-exploit"),
    fuzz: bool = typer.Option(False, "--fuzz", help="Run safe fuzz reflections"),
    operator: str = typer.Option("", "--operator"),
):
    if ultravibes or vibes:
        boss_scan_vibes(target, style="ultra" if ultravibes else "normal")

    res = run_scan(
        target=target, base_url=(base_url or None), outdir=outdir,
        do_quick=quick, do_nmap=nmap, do_http=http, do_robots=robots,
        do_sitemap=sitemap, do_js=js, do_tokens=tokens, do_links=links,
        do_report=report, verbose=verbose, operator=operator or None,
        simulate_exploit=simulate_exploit or ultraboss,
        cinematic_mode=ultraboss, fuzz=fuzz,
    )

    rprint(f"[bold cyan]Summary:[/bold cyan] {res['summary']}")

@app.command("usage")
def usage():
    rprint("Examples:")
    rprint("  python3 -m cybercli.main scan start example.com --nmap --fuzz")
    rprint("  python3 -m cybercli.main scan start 1.2.3.4 --no-js --no-sitemap")

