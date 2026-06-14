"""BurpNext CLI Plugin — cybercli burp scan/discover/passive/decode/intruder"""
import asyncio, time, os, logging
from typing import Optional
from datetime import datetime
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

app = typer.Typer(help="🔥 BurpNext — Full WAPT · OWASP Top 10 · Better than Burp Suite Pro")
console = Console()

BANNER = r"""[bold cyan]
  ██████╗ ██╗   ██╗██████╗ ██████╗ ███╗   ██╗███████╗██╗  ██╗████████╗
  ██╔══██╗██║   ██║██╔══██╗██╔══██╗████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝
  ██████╔╝██║   ██║██████╔╝██████╔╝██╔██╗ ██║█████╗   ╚███╔╝    ██║
  ██╔══██╗██║   ██║██╔══██╗██╔═══╝ ██║╚██╗██║██╔══╝   ██╔██╗    ██║
  ██████╔╝╚██████╔╝██║  ██║██║     ██║ ╚████║███████╗██╔╝ ██╗   ██║
  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝[/bold cyan]
[dim cyan]           Better than Burp Suite Pro · OWASP Top 10 · AI-Powered WAPT[/dim cyan]"""

SV_STYLE = {"Critical":"bold red","High":"bold yellow","Medium":"yellow","Low":"cyan","Informational":"dim"}
SV_ICON  = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🔵","Informational":"⚪"}
OWASP_S  = {
    "A01:2021":"Broken Access Control","A02:2021":"Crypto Failures","A03:2021":"Injection",
    "A04:2021":"Insecure Design","A05:2021":"Misconfiguration","A06:2021":"Vulnerable Components",
    "A07:2021":"Auth Failures","A08:2021":"Integrity Failures","A09:2021":"Logging Failures","A10:2021":"SSRF",
}
PHASE_MAP = [
    (5,17,  "Phase 1/8","Spider & Endpoint Discovery — HTML crawl + common path brute force"),
    (18,27, "Phase 2/8","JavaScript Extraction — hidden API endpoints + hardcoded secrets"),
    (28,37, "Phase 3/8","API Schema Discovery — Swagger/OpenAPI/GraphQL detection"),
    (38,51, "Phase 4/8","Passive Scan — headers, cookies, JWT, SSL, content analysis"),
    (52,77, "Phase 5/8","Active OWASP Top 10 — SQLi · XSS · SSRF · CMDi · LFI · IDOR · CORS"),
    (78,85, "Phase 6/8","Authentication Tests — rate limit, default credentials"),
    (86,91, "Phase 7/8","Technology Fingerprinting — framework and stack detection"),
    (92,94, "Phase 8/8","Information Disclosure — sensitive files and error messages"),
]

class BurpUI:
    def __init__(self):
        self.t0     = time.time()
        self.counts = {"Critical":0,"High":0,"Medium":0,"Low":0,"Informational":0}
        self._phases_done = set()

    def banner(self):
        console.print(BANNER)
        console.print(Panel(
            "[dim]Authorized use ONLY. Use on systems you have explicit written authorization to test.\n"
            "Unauthorized scanning violates computer fraud laws. BurpNext accepts no liability.[/dim]",
            title="[red]⚠ LEGAL NOTICE[/red]", border_style="red dim", padding=(0,2)))
        console.print()

    def config(self, target, ai, timeout, deep, threads):
        t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
        t.add_column(style="cyan dim", width=22); t.add_column(style="white")
        t.add_row("Target",  f"[bold white]{target}[/bold white]")
        t.add_row("AI",      ai.upper() if ai!="none" else "[dim]None — use --ai-provider to enable[/dim]")
        t.add_row("Timeout", f"{timeout}s / {min(6,timeout//3)}s active")
        t.add_row("Deep",    "Yes — extended brute force" if deep else "Standard")
        t.add_row("Threads", str(threads))
        t.add_row("Started", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        console.print(Panel(t, title="[cyan]// BURPNEXT WAPT SCAN[/cyan]", border_style="cyan dim"))
        console.print()

    def phase(self, pct, label, desc):
        if label in self._phases_done: return
        self._phases_done.add(label)
        elapsed = time.time()-self.t0
        icon = "📄" if "Report" in label else "🤖" if "AI" in label else "⬡"
        console.print(f"\n[cyan]{icon}[/cyan] [bold white]{label}[/bold white] [dim]({elapsed:.1f}s)[/dim]")
        console.print(f"   [dim]{desc}[/dim]")

    def log(self, msg, level="info"):
        styles = {"info":"[cyan]","ok":"[green]","warn":"[yellow]",
                  "crit":"[red]","high":"[bright_red]","dim":"[dim]","white":"[white]"}
        p = styles.get(level,"")
        s = p[1:-1] if p else ""
        if p: console.print(f"  {p}{msg}[/{s}]", highlight=False)
        else: console.print(f"  {msg}", highlight=False)

    def finding(self, f):
        sev   = f.severity  if hasattr(f,"severity")   else f.get("severity","Low")
        title = f.title     if hasattr(f,"title")       else f.get("title","")
        url   = (f.url      if hasattr(f,"url")         else f.get("url",""))[:70]
        param = (f.parameter if hasattr(f,"parameter")  else f.get("parameter","")) or ""
        cvss  = (f.cvss_score if hasattr(f,"cvss_score") else f.get("cvss_score",0)) or 0
        owasp = (f.owasp    if hasattr(f,"owasp")       else f.get("owasp","")) or ""
        style = SV_STYLE.get(sev,"white")
        icon  = SV_ICON.get(sev,"•")
        self.counts[sev] = self.counts.get(sev,0)+1
        console.print(f"\n  {icon} [{style}][{sev.upper()}][/{style}] [bold white]{title}[/bold white]")
        if url:   console.print(f"     [dim]URL:[/dim]        [cyan]{url}[/cyan]")
        if param: console.print(f"     [dim]Parameter:[/dim]  [yellow]{param}[/yellow]")
        if owasp: console.print(f"     [dim]OWASP:[/dim]      [dim]{owasp} — {OWASP_S.get(owasp,'')}[/dim]")
        if cvss>0:console.print(f"     [dim]CVSS:[/dim]       [{style}]{cvss:.1f}[/{style}]")

    def discovery_box(self, eps, js_eps, swagger, graphql, secrets, emails, comments):
        t = Table(box=box.SIMPLE, show_header=False, padding=(0,3))
        t.add_column(style="dim", width=24); t.add_column(style="white")
        t.add_row("Endpoints found",   str(eps))
        t.add_row("JS endpoints",      str(js_eps))
        t.add_row("Swagger/OpenAPI",   "[green]Found[/green]" if swagger else "[dim]Not found[/dim]")
        t.add_row("GraphQL",           "[green]Found[/green]" if graphql else "[dim]Not found[/dim]")
        t.add_row("Secrets in JS",     f"[red]{secrets}[/red]" if secrets else "0")
        t.add_row("Emails found",      str(emails))
        t.add_row("Dev comments",      str(comments))
        console.print(Panel(t, title="[cyan]// DISCOVERY RESULTS[/cyan]", border_style="cyan dim"))

    def final_summary(self, result, report_path):
        console.print(); console.rule("[cyan]─── BURPNEXT SCAN COMPLETE ───[/cyan]"); console.print()
        sv_t = Table(box=box.SIMPLE_HEAD, show_edge=False)
        sv_t.add_column("Severity",style="bold"); sv_t.add_column("Count",justify="right")
        sv_t.add_column("Weight",justify="right",style="dim"); sv_t.add_column("Risk",style="dim")
        W={"Critical":25,"High":15,"Medium":5,"Low":1,"Informational":0}
        RP={"Critical":"Active exploit confirmed","High":"Evidence in response",
            "Medium":"Config/Observable","Low":"Observable","Informational":"Info only"}
        for sev,st in [("Critical","bold red"),("High","bold yellow"),("Medium","yellow"),("Low","cyan"),("Informational","dim")]:
            n=self.counts.get(sev,0)
            if n: sv_t.add_row(f"[{st}]{sev}[/{st}]",str(n),str(n*W[sev]),RP[sev])
        console.print(Panel(sv_t,title="[cyan]// VULNERABILITY SUMMARY[/cyan]",border_style="cyan dim"))

        if result and result.findings:
            owasp_c={}
            for f in result.findings:
                oid=f.owasp or "?"
                owasp_c[oid]=owasp_c.get(oid,0)+1
            if owasp_c:
                ow_t=Table(box=box.SIMPLE_HEAD,show_edge=False)
                ow_t.add_column("OWASP ID",style="cyan dim"); ow_t.add_column("Category"); ow_t.add_column("Count",justify="right")
                for oid,cnt in sorted(owasp_c.items()):
                    ow_t.add_row(oid,OWASP_S.get(oid,oid),f"[yellow]{cnt}[/yellow]")
                console.print(Panel(ow_t,title="[cyan]// OWASP TOP 10 BREAKDOWN[/cyan]",border_style="cyan dim"))

        elapsed=time.time()-self.t0
        meta=Table(box=box.SIMPLE,show_header=False,padding=(0,3))
        meta.add_column(style="dim",width=24); meta.add_column(style="white")
        if result:
            st=result.stats
            meta.add_row("Duration",         st.get("duration",f"{elapsed:.1f}s"))
            meta.add_row("HTTP Requests",    str(st.get("requests","—")))
            meta.add_row("Endpoints Found",  str(st.get("endpoints","—")))
            meta.add_row("JS Endpoints",     str(st.get("jsEndpoints","—")))
            meta.add_row("Technologies",     str(st.get("technologies","—")))
            meta.add_row("Secrets Found",    str(st.get("secrets","—")))
            meta.add_row("Total Findings",   str(sum(self.counts.values())))
            meta.add_row("AI Validated",     "Yes" if st.get("aiValidated") else "No")
        console.print(meta)

        if report_path:
            console.print()
            console.print(Panel(
                f"[bold white]WAPT Report:[/bold white] [cyan]{report_path}[/cyan]\n"
                "[dim]Open in browser — 9 tabs: Dashboard · Findings · Endpoints · "
                "Attack Graph · Headers · Attack Chain · Secrets · Remediation · Executive[/dim]",
                title="[green]✓ BURPNEXT WAPT REPORT READY[/green]",
                border_style="green", padding=(1,2)))


@app.command()
def scan(
    target:      str  = typer.Option(...,"--target","-t",     help="Target URL or domain"),
    ai_provider: str  = typer.Option("none","--ai-provider",  help="AI provider: claude/openai/gemini/groq/ollama"),
    ai_key:      str  = typer.Option("","--ai-key","-k",      help="API key for AI provider"),
    output:      str  = typer.Option("reports","--output","-o",help="Report output directory"),
    threads:     int  = typer.Option(12,"--threads",           help="Concurrent threads"),
    timeout:     int  = typer.Option(15,"--timeout",           help="Request timeout in seconds"),
    deep:        bool = typer.Option(False,"--deep",           help="Deep scan — extended brute force"),
    no_filter:   bool = typer.Option(False,"--no-filter",      help="Include 404s in report"),
    open_report: bool = typer.Option(False,"--open",           help="Auto-open report in browser"),
):
    """Full WAPT scan — 8 phases → professional Burp-style HTML report

    \b
    Examples:
      cybercli burp scan --target https://testphp.vulnweb.com
      cybercli burp scan --target https://example.com --timeout 30
      cybercli burp scan --target https://example.com --ai-provider groq   --ai-key gsk_...
      cybercli burp scan --target https://example.com --ai-provider claude --ai-key sk-ant-...
      cybercli burp scan --target https://example.com --ai-provider ollama
      cybercli burp scan --target https://example.com --deep --open
    """
    asyncio.run(_run_scan(target,ai_provider.lower(),ai_key,output,threads,timeout,deep,not no_filter,open_report))


async def _run_scan(target,ai_provider,ai_key,output,threads,timeout,deep,filter_404,open_report):
    ui = BurpUI()
    ui.banner()
    ui.config(target,ai_provider,timeout,deep,threads)

    try:
        from cybercli.burpnext.engine import BurpNextEngine
    except ImportError as e:
        console.print(f"[red]Engine import error: {e}[/red]")
        raise typer.Exit(1)

    def on_progress(pct, label):
        for lo,hi,ph,desc in PHASE_MAP:
            if lo<=pct<hi: ui.phase(pct,ph,desc); break

    engine = BurpNextEngine(
        target=target, on_log=ui.log, on_finding=ui.finding,
        on_progress=on_progress, timeout=timeout, threads=threads,
        filter_404=filter_404, deep_scan=deep)

    result = None
    try:
        result = await engine.run()
    except Exception as e:
        console.print(Panel(
            f"[yellow]Cannot complete scan:[/yellow] [white]{target}[/white]\n"
            f"[dim]Error: {e}[/dim]\n\n"
            f"[white]Try:[/white]\n"
            f"[dim]  • --timeout 30 for slow targets\n"
            f"  • Try http:// instead of https://\n"
            f"  • Check target is reachable: curl -I {target}[/dim]",
            title="[yellow]⚠ SCAN ERROR[/yellow]",border_style="yellow",padding=(1,2)))
        import traceback; traceback.print_exc()
        raise typer.Exit(1)

    ui.discovery_box(
        eps=result.stats.get("endpoints",0),
        js_eps=len(result.js_endpoints),
        swagger=result.swagger_found,
        graphql=result.graphql_found,
        secrets=len(result.secrets_found),
        emails=len(result.emails_found),
        comments=len(result.comments_found),
    )

    exec_summary = ""; attack_chain = ""
    if ai_provider not in ("none","") and (ai_key or ai_provider=="ollama"):
        ui.phase(95,"AI Validation",f"False positive reduction + exec summary via {ai_provider.upper()}")
        try:
            from cybercli.burpnext.ai.llm_engine import BurpAI
            ai = BurpAI(provider=ai_provider, api_key=ai_key)
            ui.log(f"[*] Validating {min(len(result.findings),12)} findings...","info")
            result.findings = await ai.validate_findings(result.findings, target)
            ui.log("[*] Generating executive summary...","info")
            exec_summary = await ai.generate_executive_summary(result.findings, target, result.stats)
            ui.log("[*] Building attack chain...","info")
            attack_chain = await ai.generate_attack_chain(result.findings, target)
            result.ai_provider          = ai_provider
            result.exec_summary         = exec_summary
            result.attack_chain         = attack_chain
            result.stats["aiValidated"] = True
            fp = sum(1 for f in result.findings if f.false_positive)
            ui.log(f"[✓] AI complete — {fp} false positives suppressed","ok")
        except Exception as e:
            ui.log(f"[!] AI error: {e}","warn")

    ui.phase(96,"Report","Generating Burp-Style WAPT HTML Report")
    report_path = None
    try:
        from cybercli.burpnext.reporting.wapt_report import WAPTReportGenerator
        gen = WAPTReportGenerator(output_dir=output)
        report_path = gen.generate(result, exec_summary=exec_summary, attack_chain=attack_chain)
        ui.log(f"[✓] Report: {report_path}","ok")
    except Exception as e:
        ui.log(f"[!] Report error: {e}","warn")
        import traceback; traceback.print_exc()
        import json, os as _os
        _os.makedirs(output, exist_ok=True)
        p = _os.path.join(output, f"wapt_{int(time.time())}.json")
        with open(p,"w") as fh: json.dump(result.to_dict(), fh, indent=2)
        ui.log(f"[✓] JSON fallback: {p}","ok")
        report_path = p

    ui.final_summary(result, report_path)

    if open_report and report_path and report_path.endswith(".html"):
        import subprocess; subprocess.Popen(["xdg-open", report_path])


@app.command()
def discover(
    target:  str = typer.Option(...,"--target","-t"),
    timeout: int = typer.Option(15,"--timeout"),
):
    """Quick discovery — spider + JS endpoints + Swagger + GraphQL"""
    asyncio.run(_discover(target, timeout))

async def _discover(target, timeout):
    ui = BurpUI(); ui.banner()
    ui.phase(5,"Discovery","Spider · JS endpoints · Swagger · GraphQL")
    try:
        from cybercli.burpnext.engine import BurpNextEngine, _ssl_ctx
        engine = BurpNextEngine(target=target, on_log=ui.log,
                                on_finding=lambda f:None, on_progress=lambda p,l:None,
                                timeout=timeout)
        import aiohttp
        conn = aiohttp.TCPConnector(ssl=_ssl_ctx(), limit=12)
        to   = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(connector=conn, timeout=to) as session:
            engine._session = session
            await engine._p1_spider()
            await engine._p2_js()
            await engine._p3_api()
        visible = [e for e in engine.endpoints if e.status!=404]
        console.print(); console.rule("[cyan]DISCOVERY[/cyan]")
        for ep in visible:
            icon = "✓" if ep.status<300 else "→" if ep.status<400 else "⚠"
            src  = f" [dim][{ep.source}][/dim]" if ep.source!="spider" else ""
            console.print(f"  {icon} [{ep.status}] [cyan]{ep.path}[/cyan] [dim]{ep.content_type}[/dim]{src}")
        ui.discovery_box(len(visible), len(engine.js_endpoints),
            engine.swagger_found, engine.graphql_found,
            len(engine.secrets), len(engine.emails), len(engine.comments))
    except Exception as e:
        console.print(f"[red]Discovery error: {e}[/red]")
        import traceback; traceback.print_exc()


@app.command()
def passive(
    target:  str = typer.Option(...,"--target","-t"),
    output:  str = typer.Option("reports","--output","-o"),
    timeout: int = typer.Option(15,"--timeout"),
):
    """Passive-only scan — headers, cookies, JWT, SSL. Zero attack traffic."""
    asyncio.run(_passive(target, output, timeout))

async def _passive(target, output, timeout):
    ui = BurpUI(); ui.banner()
    ui.phase(40,"Passive Scan","Headers · Cookies · JWT · SSL — zero attack traffic")
    try:
        from cybercli.burpnext.engine import BurpNextEngine, _ssl_ctx, ScanResult
        import aiohttp
        engine = BurpNextEngine(target=target, on_log=ui.log,
                                on_finding=ui.finding, on_progress=lambda p,l:None,
                                timeout=timeout)
        conn = aiohttp.TCPConnector(ssl=_ssl_ctx(), limit=8)
        async with aiohttp.ClientSession(connector=conn,timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            engine._session = session
            r = await engine._get(target)
            if r:
                engine._main_headers = dict(r.headers)
                engine._main_body    = await engine._read(r, 32768)
            await engine._p4_passive()
        console.print(f"\n[green]✓[/green] {len(engine.findings)} passive findings")
        if engine.findings:
            try:
                from cybercli.burpnext.reporting.wapt_report import WAPTReportGenerator
                from datetime import datetime
                result = ScanResult(
                    target=target, domain=engine.domain,
                    start_time=datetime.utcnow().isoformat(),
                    end_time=datetime.utcnow().isoformat(),
                    duration="passive", total_requests=engine._req_count,
                    findings=engine.findings, endpoints=[],
                    technologies=[], js_endpoints=[], subdomains=[],
                    swagger_found=False, graphql_found=False, websockets=[],
                    secrets_found=[], comments_found=[], emails_found=[],
                    stats={"total":len(engine.findings),"requests":engine._req_count,
                           "endpoints":0,"duration":"passive"},
                    graph=engine._build_graph())
                gen = WAPTReportGenerator(output_dir=output)
                rp  = gen.generate(result)
                console.print(Panel(
                    f"[bold white]Report:[/bold white] [cyan]{rp}[/cyan]",
                    title="[green]✓ Report Ready[/green]", border_style="green"))
            except Exception as e:
                ui.log(f"[!] Report: {e}","warn")
    except Exception as e:
        console.print(f"[red]Passive scan error: {e}[/red]")


@app.command()
def decode(
    value: str = typer.Option(...,"--value","-v", help="Value to decode/encode"),
    mode:  str = typer.Option("all","--mode","-m", help="Mode: all/url/base64/html/hex/jwt/md5/sha256"),
):
    """Decoder — URL, Base64, HTML, Hex, JWT, MD5, SHA256"""
    try:
        from cybercli.burpnext.decoder.decoder import Decoder
        if   mode=="all":     result=Decoder.all_encodings(value)
        elif mode=="url":     result={"encode":Decoder.url_encode(value),"decode":Decoder.url_decode(value)}
        elif mode=="base64":  result={"encode":Decoder.base64_encode(value),"decode":Decoder.base64_decode(value)}
        elif mode=="html":    result={"encode":Decoder.html_encode(value),"decode":Decoder.html_decode(value)}
        elif mode=="hex":     result={"encode":Decoder.hex_encode(value),"decode":Decoder.hex_decode(value)}
        elif mode=="jwt":     result=Decoder.decode_jwt(value)
        elif mode=="md5":     result={"md5":Decoder.md5(value)}
        elif mode=="sha256":  result={"sha256":Decoder.sha256(value)}
        else:                 result=Decoder.smart_decode(value)
        t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
        t.add_column(style="cyan dim", width=22); t.add_column(style="white")
        for k,v in result.items():
            if isinstance(v,dict):
                for sk,sv in v.items(): t.add_row(f"  {k}.{sk}", str(sv)[:120])
            else: t.add_row(k, str(v)[:120])
        console.print(Panel(t, title="[cyan]// DECODER[/cyan]", border_style="cyan dim"))
    except Exception as e:
        console.print(f"[red]Decoder error: {e}[/red]")


@app.command()
def intruder(
    url:     str = typer.Option(...,"--url","-u",     help="Target URL"),
    param:   str = typer.Option(...,"--param","-p",   help="Parameter to fuzz"),
    wordlist:str = typer.Option("fuzzing","--wordlist","-w",
                                help="Payload list: sql_injection/xss_basic/common_passwords/fuzzing/command_injection/ssrf_payloads/path_traversal"),
    method:  str = typer.Option("GET","--method","-m",help="HTTP method"),
    threads: int = typer.Option(10,"--threads"),
):
    """Intruder — fuzz parameters with built-in or custom payload lists"""
    asyncio.run(_intruder(url, param, wordlist, method, threads))

async def _intruder(url, param, wordlist_name, method, threads):
    ui = BurpUI(); ui.banner()
    ui.phase(5,"Intruder",f"Fuzzing '{param}' with '{wordlist_name}' payloads via {method}")
    try:
        from cybercli.burpnext.intruder.intruder import Intruder, AttackType
        import aiohttp, ssl

        results_shown = []
        def on_result(r):
            icon = "⚡" if r.interesting else "  "
            col  = "yellow" if r.interesting else "dim"
            console.print(f"  {icon} [{r.status}] [{col}]{r.payload[:35]:<37}[/{col}] "
                          f"len={r.length:<7} {('[bold yellow]INTERESTING[/bold yellow]' if r.interesting else '')}")
            results_shown.append(r)

        intr     = Intruder(threads=threads, on_result=on_result)
        payloads = intr.BUILT_IN.get(wordlist_name, intr.BUILT_IN["fuzzing"])
        template = f"{param}=§test§"
        console.print(f"  [cyan]Payloads:[/cyan] {len(payloads)} | [cyan]Mode:[/cyan] Sniper | [cyan]Target:[/cyan] {url}")
        console.print()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ctx)) as session:
            # Get baseline
            try:
                async with session.get(f"{url}?{param}=BASELINE", ssl=False,
                    timeout=aiohttp.ClientTimeout(total=10)) as r:
                    baseline = len(await r.text())
            except: baseline = 0

            await intr.attack(url, method, template, payloads, AttackType.SNIPER,
                              baseline_len=baseline)

        interesting = intr.get_interesting()
        console.print(f"\n[green]✓[/green] Intruder complete: [white]{len(results_shown)}[/white] requests | "
                      f"[yellow]{len(interesting)}[/yellow] interesting responses")
        if interesting:
            console.print(Panel(
                "\n".join(f"[{r.status}] {r.payload[:40]:<42} len={r.length}" for r in interesting[:10]),
                title="[yellow]⚡ Interesting Responses[/yellow]", border_style="yellow"))
    except Exception as e:
        console.print(f"[red]Intruder error: {e}[/red]")
        import traceback; traceback.print_exc()
