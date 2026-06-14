
#!/usr/bin/env python3
# cybercli/plugins/websec.py
# -*- coding: utf-8 -*-
"""
Typer plugin for web application security.

Commands:
 - quick-scan    : safe non-destructive quick scan (headers, fingerprint, waf, params, optional crawl)
 - crawl         : limited crawler (depth, pages)
 - fingerprint   : tech fingerprinting
 - waf-detect    : WAF heuristics
 - params        : discover parameters and forms
 - dir-discover  : safe HEAD-based directory discovery (wordlist optional)
 - payloads      : print payload suggestions (no execution)
 - report-open   : prints paths to saved report files (if any)
All commands require explicit authorization (consent).
"""
from pathlib import Path
from typing import Optional, List
import typer
from rich import print as rprint

from cybercli.core import websec_core as wcore

app = typer.Typer(help="Webapp security helpers (safe mode)")

REPORTS_ROOT = Path("reports")

def _ensure_authorization():
    rprint("[yellow]You must have explicit written authorization to test this target.[/yellow]")
    if not typer.confirm("Do you have written authorization to test this target?", default=False):
        rprint("[red]Authorization required. Aborting.[/red]")
        raise typer.Exit(code=1)

@app.command("quick-scan")
def quick_scan(
    target_url: str = typer.Argument(..., help="Target base URL, e.g. https://example.com"),
    target_name: str = typer.Option("webtarget", "--target-name", "-t"),
    crawl: bool = typer.Option(True, "--crawl/--no-crawl"),
    depth: int = typer.Option(1, "--depth", "-d"),
    dir_discovery: bool = typer.Option(False, "--dir", help="Run safe HEAD-based dir discovery"),
):
    _ensure_authorization()
    rprint(f"[cyan]Running quick webapp scan on {target_url} (safe mode)[/cyan]")
    rep = wcore.webapp_quick_scan(target_url, REPORTS_ROOT, target_name, crawl=crawl, crawl_depth=depth, dir_brute=dir_discovery)
    rprint(f"[green]Report saved:[/green] TXT: {rep['txt']}  HTML: {rep['html']}")

@app.command("crawl")
def crawl_cmd(
    url: str = typer.Argument(..., help="Start URL (same-host only)"),
    depth: int = typer.Option(1, "--depth", "-d"),
    max_pages: int = typer.Option(200, "--max", "-m"),
):
    _ensure_authorization()
    rprint(f"[cyan]Crawling {url} depth={depth} max_pages={max_pages}[/cyan]")
    res = wcore.crawl_site(url, depth=depth, max_pages=max_pages)
    rprint(f"[green]Crawl finished. Pages discovered: {len(res.get('pages',[]))} Forms found: {res.get('forms_found',0)}[/green]")
    # write a small report to reports/
    run_root = REPORTS_ROOT / "crawl_reports" / wcore.now_stamp()
    rep = wcore.write_simple_report(run_root, "crawl", f"Crawl of {url}", json.dumps(res, indent=2))
    rprint(f"[green]Crawl report:[/green] {rep['html']}")

@app.command("fingerprint")
def fingerprint_cmd(url: str = typer.Argument(..., help="URL to fingerprint")):
    _ensure_authorization()
    rprint(f"[cyan]Fingerprinting {url}[/cyan]")
    res = wcore.fingerprint_tech(url)
    rprint(res)

@app.command("waf-detect")
def waf_cmd(url: str = typer.Argument(..., help="URL to probe for WAF heuristics")):
    _ensure_authorization()
    rprint(f"[cyan]Detecting WAF for {url}[/cyan]")
    res = wcore.detect_waf(url)
    rprint(res)

@app.command("params")
def params_cmd(url: str = typer.Argument(..., help="URL to inspect for parameters and forms")):
    _ensure_authorization()
    rprint(f"[cyan]Discovering params on {url}[/cyan]")
    res = wcore.discover_parameters(url)
    rprint(res)

@app.command("dir-discover")
def dir_discover_cmd(
    url: str = typer.Argument(..., help="Base URL, e.g. https://example.com/"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w", help="Path to newline wordlist"),
    do_get: bool = typer.Option(False, "--get", help="Fetch bodies (use with care)"),
):
    _ensure_authorization()
    wl = None
    if wordlist:
        p = Path(wordlist)
        if not p.exists():
            rprint(f"[red]Wordlist not found: {wordlist}[/red]")
            raise typer.Exit(code=1)
        wl = [x.strip() for x in p.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]
    rprint(f"[cyan]Running safe HEAD-based dir discovery on {url} (do_get={do_get})[/cyan]")
    res = wcore.dir_discovery(url, wordlist=wl, do_get=do_get)
    rprint(f"[green]Dir discovery found {len(res.get('found',[]))} items[/green]")
    run_root = REPORTS_ROOT / "dir_discovery" / wcore.now_stamp()
    rep = wcore.write_simple_report(run_root, "dir_discovery", f"Dir discovery for {url}", json.dumps(res, indent=2))
    rprint(f"[green]Saved report:[/green] {rep['html']}")

@app.command("payloads")
def payloads_cmd():
    rprint("[yellow]Payload suggestions provided for manual testing only (no automatic execution). Use responsibly and with authorization.[/yellow]")
    rprint(wcore.payload_suggestions())

@app.command("report-open")
def report_open_cmd(reports_dir: Optional[str] = typer.Option(None, "--reports", "-r")):
    """
    Print latest websec reports folder (helpful to find dashboard).
    """
    base = Path(reports_dir) if reports_dir else Path("reports")
    if not base.exists():
        rprint("[red]No reports directory found yet.[/red]"); raise typer.Exit(code=1)
    # list recent websec folders
    folders = sorted([p for p in base.rglob("*") if p.is_dir()], key=lambda x: x.stat().st_mtime, reverse=True)
    websec = [f for f in folders if "websec" in str(f).lower() or "websec" in "".join([c.name for c in f.parents])]
    if not websec:
        rprint("[yellow]No websec reports found.[/yellow]"); raise typer.Exit(code=0)
    rprint("[green]Latest websec report folders (top 10):[/green]")
    for f in websec[:10]:
        rprint(f"{f}")

