"""
CyberCLI ZAP ENGINE — Full VAPT Orchestrator
Real HTTP scan → Hacker terminal UI → Professional HTML report

Fixes applied:
- Phases now print IN REAL TIME as each phase runs (not all at once before)
- Timeout increased + multiple retry strategies for connection issues
- 404 endpoints filtered from final report
- False positive confidence scoring shown clearly
- Better SSL handling for all target types
"""
import asyncio, time, os, sys, logging
from typing import Optional
from datetime import datetime
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich import box

app = typer.Typer(help="🔥 Full VAPT — Real scan · AI validation · Professional HTML report")
console = Console()
logger  = logging.getLogger("cybercli.zap")

BANNER = """[bold cyan]
  ██████╗██╗   ██╗██████╗ ███████╗██████╗  ██████╗██╗     ██╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██║     ██║
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║     ██║     ██║
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║     ██║     ██║
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║╚██████╗███████╗██║
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝[/bold cyan]
[dim cyan]        AI-Powered VAPT · Better than OWASP ZAP · Real Scans[/dim cyan]"""

SV_STYLE = {"Critical":"bold red","High":"bold yellow","Medium":"yellow","Low":"cyan","Informational":"dim"}
SV_ICON  = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🔵","Informational":"⚪"}


class HackerUI:
    def __init__(self):
        self.t0     = time.time()
        self.counts = {"Critical":0,"High":0,"Medium":0,"Low":0,"Informational":0}

    def banner(self):
        console.print(BANNER)
        console.print(Panel(
            "[dim]Authorized use ONLY. Use on systems you have explicit written permission to test.\n"
            "Unauthorized scanning violates computer fraud laws. CyberCLI accepts no liability.[/dim]",
            title="[red]⚠ LEGAL NOTICE[/red]", border_style="red dim", padding=(0,2)))
        console.print()

    def config(self, target, ai, modules):
        t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
        t.add_column(style="cyan dim", width=22)
        t.add_column(style="white")
        t.add_row("Target",  f"[bold white]{target}[/bold white]")
        t.add_row("AI",      ai.upper() if ai != "none" else "[dim]None — add --ai-provider + --ai-key for AI validation[/dim]")
        t.add_row("Modules", modules)
        t.add_row("Started", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        console.print(Panel(t, title="[cyan]// SCAN CONFIGURATION[/cyan]", border_style="cyan dim"))
        console.print()

    def phase_start(self, label, desc, icon="⬡"):
        """Print phase header — called RIGHT BEFORE that phase runs"""
        elapsed = time.time() - self.t0
        console.print(f"\n[cyan]{icon}[/cyan] [bold white]{label}[/bold white] [dim]({elapsed:.1f}s elapsed)[/dim]")
        console.print(f"   [dim]{desc}[/dim]")

    def phase_done(self, label, count=None, extra=""):
        elapsed = time.time() - self.t0
        msg = f"   [green]✓[/green] [dim]{label} complete"
        if count is not None:
            msg += f" — {count} result(s)"
        if extra:
            msg += f" · {extra}"
        msg += f"  ({elapsed:.1f}s)[/dim]"
        console.print(msg)

    def log(self, msg, level="info"):
        styles = {"info":"[cyan]","ok":"[green]","warn":"[yellow]","crit":"[red]","high":"[bright_red]","dim":"[dim]","white":"[white]"}
        p = styles.get(level,"")
        if p:
            s = p[1:-1]
            console.print(f"  {p}{msg}[/{s}]", highlight=False)
        else:
            console.print(f"  {msg}", highlight=False)

    def finding(self, f):
        sev   = f.severity  if hasattr(f,"severity")  else f.get("severity","Low")
        title = f.title     if hasattr(f,"title")     else f.get("title","")
        url   = (f.url      if hasattr(f,"url")       else f.get("url",""))[:72]
        param = (f.parameter if hasattr(f,"parameter") else f.get("parameter","")) or ""
        cvss  = (f.cvss     if hasattr(f,"cvss")      else f.get("cvss",0)) or 0
        conf  = (f.confidence if hasattr(f,"confidence") else f.get("confidence","Medium")) or "Medium"
        style = SV_STYLE.get(sev,"white")
        icon  = SV_ICON.get(sev,"•")
        self.counts[sev] = self.counts.get(sev,0)+1

        console.print(f"\n  {icon} [{style}][{sev.upper()}][/{style}] [bold white]{title}[/bold white]")
        if url:   console.print(f"     [dim]URL:[/dim]         [cyan]{url}[/cyan]")
        if param: console.print(f"     [dim]Parameter:[/dim]   [yellow]{param}[/yellow]")
        if cvss:  console.print(f"     [dim]CVSS:[/dim]        [{style}]{cvss}[/{style}]")
        console.print(f"     [dim]Confidence:[/dim]  [dim]{conf} — {'✓ Verified by active test' if conf=='High' else '~ Detected passively, verify manually'}[/dim]")

    def summary_table(self, stats, report_path):
        console.print()
        console.rule("[cyan]─── SCAN COMPLETE ───[/cyan]")
        console.print()
        t = Table(box=box.SIMPLE_HEAD, show_edge=False)
        t.add_column("Severity", style="bold")
        t.add_column("Count", justify="right")
        t.add_column("Risk Weight", justify="right", style="dim")
        t.add_column("False Positive Risk", style="dim")
        W  = {"Critical":25,"High":15,"Medium":5,"Low":1,"Informational":0}
        FP = {"Critical":"Very Low — Active test confirmed","High":"Low — Passive evidence present",
              "Medium":"Low-Medium — Config-based, verifiable","Low":"Low — Observable in response","Informational":"Info only"}
        for sev,st in [("Critical","bold red"),("High","bold yellow"),("Medium","yellow"),("Low","cyan"),("Informational","dim")]:
            n = self.counts.get(sev,0)
            if n:
                t.add_row(f"[{st}]{sev}[/{st}]", str(n), str(n*W[sev]), FP[sev])
        console.print(Panel(t, title="[cyan]// VULNERABILITY SUMMARY[/cyan]", border_style="cyan dim"))

        meta = Table(box=box.SIMPLE, show_header=False, padding=(0,3))
        meta.add_column(style="dim", width=22)
        meta.add_column(style="white")
        meta.add_row("Duration",       stats.get("duration","—"))
        meta.add_row("Requests Made",  str(stats.get("requests","—")))
        meta.add_row("Endpoints Found",str(stats.get("endpoints","—")))
        meta.add_row("Total Findings", str(sum(self.counts.values())))
        meta.add_row("AI Validated",   "Yes" if stats.get("aiValidated") else "No")
        console.print(meta)

        if report_path:
            console.print()
            console.print(Panel(
                f"[bold white]Report:[/bold white] [cyan]{report_path}[/cyan]\n"
                "[dim]Open in any browser — fully offline, no server required[/dim]",
                title="[green]✓ REPORT READY[/green]", border_style="green", padding=(1,2)))

    def connection_warning(self, target, error):
        console.print(Panel(
            f"[yellow]Could not connect to:[/yellow] [white]{target}[/white]\n"
            f"[dim]Error: {error}[/dim]\n\n"
            "[white]Possible reasons:[/white]\n"
            "[dim]  • Target is offline or blocking automated scanners\n"
            "  • Network/firewall blocking outbound connections from this host\n"
            "  • Target uses Cloudflare/WAF with bot protection\n"
            "  • DNS resolution failure\n\n"
            "[white]Try:[/white]\n"
            "[dim]  • Check target is reachable: curl -I " + target + "\n"
            "  • Try with HTTP instead of HTTPS\n"
            "  • Add --timeout 30 for slow targets\n"
            "  • Check your network/proxy settings[/dim]",
            title="[yellow]⚠ CONNECTION ISSUE[/yellow]",
            border_style="yellow", padding=(1,2)))


@app.command()
def scan(
    target:      str  = typer.Option(..., "--target","-t",       help="Target URL or domain"),
    ai_provider: str  = typer.Option("none","--ai-provider",     help="AI: claude / openai / gemini / groq"),
    ai_key:      str  = typer.Option("","--ai-key","-k",         help="API key for AI provider"),
    output:      str  = typer.Option("artifacts/reports","--output","-o"),
    threads:     int  = typer.Option(10,"--threads",             help="Concurrent threads"),
    timeout:     int  = typer.Option(15,"--timeout",             help="Request timeout seconds (increase for slow targets)"),
    open_report: bool = typer.Option(False,"--open",             help="Open report in browser after scan"),
    no_filter:   bool = typer.Option(False,"--no-filter",        help="Include 404 endpoints in report"),
):
    """
    Full VAPT scan → professional HTML report

    Examples:
      cybercli zap scan --target https://testphp.vulnweb.com
      cybercli zap scan --target https://example.com --timeout 30
      cybercli zap scan --target https://example.com --ai-provider claude --ai-key sk-ant-...
      cybercli zap scan --target https://example.com --ai-provider groq --ai-key gsk_...
    """
    asyncio.run(_run(target, ai_provider.lower(), ai_key, output, threads, timeout, open_report, no_filter))


async def _run(target, ai_provider, ai_key, output, threads, timeout, open_report, no_filter):
    ui = HackerUI()
    ui.banner()
    ui.config(target, ai_provider,
              "headers · cors · ssl · xss · sqli · ssrf · lfi · cookies · info · auth · graphql")

    from cybercli.core.reporting.scanner import VAPTScanner

    # ── Phase callbacks — fire IN REAL TIME as scanner progresses ──────────────
    phase_printed = set()

    def on_progress(pct, label):
        # Map progress % to phase and print header exactly once per phase
        phase_map = {
            (0,27):  ("Phase 1/6", "Spider & Endpoint Discovery — probing common paths, extracting links from HTML"),
            (27,43): ("Phase 2/6", "Passive Scan — headers, cookies, SSL, info disclosure (no attack traffic)"),
            (43,53): ("Phase 3/6", "SSL/TLS Analysis — certificate validity and HTTP→HTTPS redirect check"),
            (53,81): ("Phase 4/6", "Active Scan — CORS, XSS, SQLi, SSRF, LFI, Open Redirect, Auth, GraphQL"),
            (81,91): ("Phase 5/6", "Information Disclosure — sensitive file exposure and error message checks"),
            (91,100):("Phase 6/6", "Generating Professional VAPT Report"),
        }
        for (lo, hi), (ph, desc) in phase_map.items():
            if lo <= pct < hi and ph not in phase_printed:
                phase_printed.add(ph)
                icon = "📄" if "Report" in ph else "⬡"
                ui.phase_start(ph, desc, icon)
                break

    scanner = VAPTScanner(
        target=target,
        on_log=ui.log,
        on_finding=ui.finding,
        on_progress=on_progress,
        timeout=timeout,
        threads=threads,
        filter_404=(not no_filter),
    )

    result = None
    try:
        result = await scanner.run()
    except Exception as e:
        ui.connection_warning(target, str(e))
        import traceback; traceback.print_exc()
        raise typer.Exit(1)

    # Check if scan actually got any data
    if result.total_requests == 0:
        ui.connection_warning(target,
            "No requests completed — target unreachable or all connections timed out")
        console.print("\n[dim]Generating empty report anyway...[/dim]")

    # ── AI Validation ───────────────────────────────────────────────────────────
    exec_summary = ""
    if ai_provider not in ("none","") and ai_key:
        ui.phase_start("AI Validation",
                       f"False positive reduction + executive summary via {ai_provider.upper()}", "🤖")
        try:
            from cybercli.core.ai_engine.providers import AIProvider
            ai = AIProvider(provider=ai_provider, api_key=ai_key)
            result.findings = await ai.validate_findings(result.findings, target)
            exec_summary    = await ai.generate_executive_summary(result.findings, target, result.stats)
            result.ai_provider          = ai_provider
            result.stats["aiValidated"] = True
            fp = sum(1 for f in result.findings if f.false_positive)
            ui.log(f"[✓] AI complete: {fp} false positives suppressed", "ok")
            ui.phase_done("AI validation", extra=f"{fp} FP suppressed")
        except Exception as e:
            ui.log(f"[!] AI validation error: {e}", "warn")

    # ── Generate Report ─────────────────────────────────────────────────────────
    ui.phase_start("Phase 6/6", "Generating Professional VAPT HTML Report", "📄")
    report_path = None
    try:
        from cybercli.core.reporting.report_template import ReportGenerator
        gen = ReportGenerator(output_dir=output)
        report_path = gen.generate(result, exec_summary=exec_summary)
        ui.log(f"[✓] HTML report: {report_path}", "ok")
    except Exception as e:
        ui.log(f"[!] Report error: {e}", "warn")
        import traceback; traceback.print_exc()
        import json
        os.makedirs(output, exist_ok=True)
        p = os.path.join(output, f"vapt_{int(time.time())}.json")
        with open(p,"w") as fh:
            json.dump(result.to_dict(), fh, indent=2)
        ui.log(f"[✓] JSON fallback saved: {p}", "ok")
        report_path = p

    ui.summary_table(result.stats, report_path)

    if open_report and report_path and report_path.endswith(".html"):
        import subprocess
        subprocess.Popen(["xdg-open", report_path])


@app.command(name="passive-only")
def passive_only(
    target:  str = typer.Option(..., "--target","-t"),
    output:  str = typer.Option("artifacts/reports","--output","-o"),
    timeout: int = typer.Option(15,"--timeout"),
):
    """Passive scan only — headers, cookies, SSL. No attack traffic."""
    asyncio.run(_passive(target, output, timeout))


async def _passive(target, output, timeout):
    ui = HackerUI(); ui.banner()
    ui.phase_start("Passive Scan",
                   "Headers · Cookies · SSL/TLS · Info Disclosure — zero attack traffic")
    from cybercli.core.reporting.scanner import VAPTScanner
    import aiohttp, ssl as _ssl
    s = VAPTScanner(target=target, on_log=ui.log, on_finding=ui.finding, timeout=timeout)
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    conn = aiohttp.TCPConnector(ssl=ctx, limit=5)
    to   = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(connector=conn, timeout=to) as session:
        s._session = session
        try:
            await s._phase_passive()
            await s._phase_ssl()
        except Exception as e:
            ui.log(f"[!] Error: {e}", "warn")
    ui.phase_done("Passive scan", len(s.findings))
    for f in s.findings:
        icon = SV_ICON.get(f.severity,"•")
        st   = SV_STYLE.get(f.severity,"white")
        console.print(f"  {icon} [{st}]{f.severity}[/{st}] — {f.title}")
