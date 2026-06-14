# cybercli/core/report_utils.py
# -*- coding: utf-8 -*-
"""
Render HTML and PDF reports for Recon / Scan results.

Provides:
- render_html_report(result, target_dir) -> writes report.html (Jinja2)
- render_pdf_report(result, target_dir)  -> builds a multi-page PDF (ReportLab + matplotlib)
- build_html_and_pdf_report(result, target_dir, operator=None, simulate=False)
    -> convenience wrapper that renders both and returns dict with paths
"""

from jinja2 import Template
from pathlib import Path
import json, datetime, io, math, traceback
from typing import Dict, Any, List, Optional

# PDF/charting libs
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle, Paragraph, SimpleDocTemplate, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import matplotlib.pyplot as plt
import warnings

# silence matplotlib warnings in headless environments
warnings.filterwarnings("ignore", module="matplotlib")

# ---------------------------
# HTML template (kept compact)
# ---------------------------
TEMPLATE = """
<!doctype html>
<html><head><meta charset="utf-8"><title>Recon/Scan Report - {{ target }}</title>
<style>
  body { font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; background:#0b0f14; color:#e5e7eb; padding:20px;}
  h1{color:#93c5fd}
  .box { background:#071023; border:1px solid #17272f; padding:12px; border-radius:8px; margin-bottom:12px;}
  pre{background:#0b1220;padding:10px;border-radius:6px; color:#cbd5e1; white-space:pre-wrap;}
  table {width:100%; border-collapse: collapse;}
  th, td { padding:8px; border-bottom:1px solid #1f2937; text-align:left; font-family: monospace;}
  .sev-crit { color: #ff4d4f; font-weight: bold; }
  .sev-high { color: #ffb020; }
  .sev-med { color: #facc15; }
  .sev-low { color: #34d399; }
</style>
</head><body>
  <h1>Recon/Scan Report — {{ target }}</h1>
  <p>Generated: {{ generated }}</p>
  <p>Operator: {{ operator }}</p>

  <div class="box">
    <h2>Summary</h2>
    <pre>{{ summary_text }}</pre>
  </div>

  <div class="box">
    <h2>Key Findings (top-level)</h2>
    {% if key_findings %}
    <ul>
      {% for f in key_findings %}
        <li>{{ f }}</li>
      {% endfor %}
    </ul>
    {% else %}
      <p>No automated critical findings detected.</p>
    {% endif %}
  </div>

  <div class="box">
    <h2>Artifacts</h2>
    <ul>
      {% for a in artifacts %}
        <li>{{ a }}</li>
      {% endfor %}
    </ul>
  </div>

  <h2>Summary JSON (excerpt)</h2>
  <pre>{{ summary_json }}</pre>
</body></html>
"""

# ---------------------------
# HTML renderer
# ---------------------------
def render_html_report(result: Dict[str, Any], target_dir: Path, operator: Optional[str] = None) -> str:
    """
    Render attractive HTML report (report.html) in target_dir. Returns path string.
    """
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    # Prepare summary text (short)
    summary_text = []
    summary_text.append(f"Target: {result.get('target')}")
    summary_text.append(f"Base URL: {result.get('base_url')}")
    ts = result.get('timestamp') or datetime.datetime.utcnow().timestamp()
    try:
        summary_text.append(f"Timestamp: {datetime.datetime.utcfromtimestamp(ts).isoformat()}Z")
    except Exception:
        summary_text.append(f"Timestamp: {str(ts)}")
    # counts
    counts = {
        "ips": len(result.get("ips", []) or []),
        "subdomains": len(result.get("crtsh_subdomains", []) or []),
        "http_entries": len(result.get("http", {}) or {}),
        "nmap_entries": len(result.get("nmap", []) or []),
        "secrets": sum(len(v) for v in (result.get("secrets") or {}).values()) if result.get("secrets") else 0
    }
    summary_text.append("Counts: " + ", ".join([f"{k}={v}" for k,v in counts.items()]))

    # key findings extract
    key_findings = []
    if result.get("cve_hints"):
        key_findings.extend(result.get("cve_hints") or [])
    if result.get("secrets"):
        key_findings.append(f"Secrets found: {sum(len(v) for v in result['secrets'].values())}")
    if result.get("tra"):
        key_findings.append(f"TRA risk_score_5: {result['tra'].get('risk_score_5')}")

    # artifacts list (only files inside target_dir)
    artifacts = []
    for p in sorted([p.name for p in target_dir.iterdir() if p.is_file()]):
        artifacts.append(p)

    # Render template
    t = Template(TEMPLATE)
    html = t.render(
        target=result.get("target"),
        generated=datetime.datetime.utcnow().isoformat() + "Z",
        operator=operator or result.get("operator", "N/A"),
        summary_text="\n".join(summary_text),
        key_findings=key_findings,
        artifacts=artifacts,
        summary_json=json.dumps({
            "target": result.get("target"),
            "ips": result.get("ips"),
            "crtsh_subdomains": result.get("crtsh_subdomains"),
            "nmap_count": len(result.get("nmap") or []),
            "secrets_count": sum(len(v) for v in (result.get("secrets") or {}).values()) if result.get("secrets") else 0,
        }, indent=2)
    )
    out = target_dir / "report.html"
    out.write_text(html, encoding="utf-8")
    return str(out)

# ---------------------------
# PDF renderer (ReportLab + matplotlib)
# ---------------------------
def _make_severity_charts(result: Dict[str, Any], out_dir: Path) -> Dict[str, str]:
    """
    Create two charts:
    - Pie chart of severity counts (critical/high/medium/low)
    - Bar chart of counts per category (nmap/http/secrets/js_endpoints)
    Returns dict with paths to PNGs.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    pngs: Dict[str, str] = {}
    # derive severity counts from result heuristics
    sev = {"critical":0, "high":0, "medium":0, "low":0}
    if result.get("cve_hints"):
        sev["high"] += len(result.get("cve_hints") or [])
    if result.get("secrets"):
        sev["high"] += sum(len(v) for v in result.get("secrets", {}).values())
    open_ports = 0
    for nm in (result.get("nmap") or []):
        if isinstance(nm, dict):
            hosts = nm.get("hosts") or []
            for host in hosts:
                open_ports += len(host.get("ports") or [])
        elif isinstance(nm, list):
            open_ports += len(nm)
    if open_ports:
        sev["medium"] += int(min(open_ports, 50))
    # HTTP warnings
    http_warn = 0
    for k,v in (result.get("http") or {}).items():
        if isinstance(v, dict):
            if v.get("status_code") and v["status_code"] >= 500:
                http_warn += 1
            if v.get("emails"):
                http_warn += len(v.get("emails"))
    sev["low"] += http_warn

    total = sum(sev.values())
    if total == 0:
        sev["low"] = 1
        total = 1

    # Pie
    labels = [f"{k.capitalize()} ({sev[k]})" for k in ("critical","high","medium","low")]
    sizes = [sev[k] for k in ("critical","high","medium","low")]
    try:
        fig1, ax1 = plt.subplots(figsize=(4,3))
        ax1.pie(sizes, labels=labels, autopct=lambda p: f"{p:.0f}%" if p>0 else "", startangle=140)
        ax1.axis('equal')
        pie_path = out_dir / "severity_pie.png"
        fig1.savefig(pie_path, bbox_inches="tight", dpi=150)
        plt.close(fig1)
        pngs["pie"] = str(pie_path)
    except Exception:
        # ignore chart failure
        pass

    # Bar categories
    categories = ["nmap", "http", "secrets", "js_endpoints"]
    counts = [
        len(result.get("nmap") or []),
        len(result.get("http") or {}),
        sum(len(v) for v in (result.get("secrets") or {}).values()) if result.get("secrets") else 0,
        len(result.get("js_endpoints") or [])
    ]
    try:
        fig2, ax2 = plt.subplots(figsize=(5,3))
        ax2.bar(categories, counts)
        ax2.set_title("Findings by category")
        ax2.set_ylabel("Count")
        bar_path = out_dir / "category_bar.png"
        fig2.savefig(bar_path, bbox_inches="tight", dpi=150)
        plt.close(fig2)
        pngs["bar"] = str(bar_path)
    except Exception:
        pass

    return pngs

def _tabulate_cves(result: Dict[str, Any]) -> List[List[str]]:
    rows = [["CVE / Hint", "Context"]]
    for hint in (result.get("cve_hints") or []):
        rows.append([hint, "auto-detected"])
    return rows

def render_pdf_report(result: Dict[str, Any], target_dir: Path, operator: Optional[str] = None) -> str:
    """
    Creates a PDF report (report.pdf) inside target_dir and returns its path (str).
    Uses reportlab + matplotlib images.
    """
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = target_dir / "report.pdf"

    # Charts (best-effort)
    charts = _make_severity_charts(result, target_dir)

    # Document setup
    try:
        doc = SimpleDocTemplate(str(pdf_path), pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=18*mm, bottomMargin=18*mm)
        styles = getSampleStyleSheet()
        normal = styles["Normal"]
        heading = styles["Heading1"]
        small = ParagraphStyle('small', parent=styles['Normal'], fontSize=8)

        flow: List[Any] = []

        # Title / header
        title = Paragraph(f"Recon/Scan Report — {result.get('target')}", heading)
        flow.append(title)
        flow.append(Spacer(1, 6))

        meta_lines = []
        meta_lines.append(f"<b>Generated:</b> {datetime.datetime.utcnow().isoformat()}Z")
        meta_lines.append(f"<b>Base URL:</b> {result.get('base_url')}")
        meta_lines.append(f"<b>Operator:</b> {operator or result.get('operator', 'N/A')}")
        meta_lines.append(f"<b>Duration (s):</b> {result.get('duration_sec', 'N/A')}")
        for ml in meta_lines:
            flow.append(Paragraph(ml, normal))
        flow.append(Spacer(1, 8))

        # Embed charts if created
        if charts.get("pie"):
            try:
                im_pie = Image(charts["pie"], width=90*mm, height=70*mm)
                flow.append(im_pie)
            except Exception:
                pass
        if charts.get("bar"):
            try:
                im_bar = Image(charts["bar"], width=160*mm, height=60*mm)
                flow.append(Spacer(1,4))
                flow.append(im_bar)
            except Exception:
                pass
        flow.append(Spacer(1, 8))

        # TRA box
        tra = result.get("tra")
        if tra:
            tdata = [["Metric", "Value"]]
            tdata.append(["Criticality", str(tra.get("criticality"))])
            tdata.append(["Likelihood", str(tra.get("likelihood"))])
            tdata.append(["Risk (1-5)", str(tra.get("risk_score_5"))])
            tbl = Table(tdata, colWidths=[80*mm, 80*mm])
            tbl.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f1720")),
                ('TEXTCOLOR',(0,0),(-1,0), colors.white),
                ('GRID', (0,0), (-1,-1), 0.3, colors.grey),
                ('FONTNAME',(0,0),(-1,-1),"Helvetica"),
            ]))
            flow.append(Paragraph("<b>TRA (Threat Risk Assessment)</b>", normal))
            flow.append(tbl)
            flow.append(Spacer(1,8))

        # CVE table
        cve_rows = _tabulate_cves(result)
        if len(cve_rows) > 1:
            flow.append(Paragraph("<b>Potential CVE Hints / Heuristics</b>", normal))
            cve_tbl = Table(cve_rows, colWidths=[100*mm, 60*mm])
            cve_tbl.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.3, colors.grey),
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0b1220")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ]))
            flow.append(cve_tbl)
            flow.append(Spacer(1,8))

        # Key findings list
        findings = []
        if result.get("secrets"):
            findings.append(f"Secrets discovered: {sum(len(v) for v in result['secrets'].values())}")
        if result.get("cve_hints"):
            findings.append(f"CVE hints: {len(result.get('cve_hints'))}")
        if result.get("nmap"):
            findings.append(f"Nmap hosts scanned: {len(result.get('nmap'))}")
        if result.get("http"):
            findings.append(f"HTTP endpoints probed: {len(result.get('http'))}")

        flow.append(Paragraph("<b>Key Findings</b>", normal))
        for f in findings or ["No critical automated findings detected."]:
            flow.append(Paragraph(f"- {f}", normal))
        flow.append(Spacer(1, 8))

        # Attach asset graph thumbnail if exists
        if (target_dir / "asset_graph.png").exists():
            try:
                flow.append(Paragraph("<b>Asset Graph</b>", normal))
                flow.append(Image(str(target_dir / "asset_graph.png"), width=170*mm, height=90*mm))
                flow.append(Spacer(1,8))
            except Exception:
                pass

        # Add summary notes and small JSON excerpt (not entire huge JSON)
        flow.append(Paragraph("<b>Summary (excerpt)</b>", normal))
        excerpt = json.dumps({
            "target": result.get("target"),
            "ips": result.get("ips"),
            "crtsh_subdomains": result.get("crtsh_subdomains"),
            "nmap_summary_count": len(result.get("nmap") or []),
            "secrets_count": sum(len(v) for v in (result.get("secrets") or {}).values()) if result.get("secrets") else 0,
        }, indent=2)
        flow.append(Paragraph(f"<font size=8><pre>{excerpt}</pre></font>", ParagraphStyle('mono', parent=normal, fontName='Courier', fontSize=8)))
        flow.append(PageBreak())

        # Appendix: artifacts
        flow.append(Paragraph("<b>Artifacts</b>", normal))
        artifact_list = []
        for p in sorted([p.name for p in target_dir.iterdir() if p.is_file()]):
            artifact_list.append([p])
        if artifact_list:
            art_tbl = Table([["Artifact file"]] + artifact_list, colWidths=[170*mm])
            art_tbl.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25, colors.grey)]))
            flow.append(art_tbl)
        else:
            flow.append(Paragraph("No artifact files saved.", normal))

        # Build PDF
        doc.build(flow)
    except Exception as e:
        # fallback: simple PDF
        try:
            c = canvas.Canvas(str(pdf_path), pagesize=A4)
            c.setFont("Helvetica-Bold", 14)
            c.drawString(40, 800, f"Recon Report - {result.get('target')}")
            c.setFont("Helvetica", 10)
            c.drawString(40, 780, f"Operator: {operator or result.get('operator','N/A')}")
            c.drawString(40, 760, "Error building rich PDF; basic file created.")
            c.drawString(40, 740, f"Error: {str(e)}")
            c.save()
        except Exception:
            # give up silently but ensure path returned (might not exist)
            pass

    return str(pdf_path)

# ---------------------------
# Convenience wrapper
# ---------------------------
def build_html_and_pdf_report(result: Dict[str, Any], target_dir: Path, operator: Optional[str] = None, simulate: bool = False) -> Dict[str, str]:
    """
    Builds both HTML and PDF reports and returns a dict:
    {"html": "<path>", "pdf": "<path>"}
    - operator: optional operator name to embed in report
    - simulate: if True, include simulation note (not performing attacks). This function itself doesn't run attacks.
    """
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    # ensure operator value inside result for downstream rendering
    if operator:
        result["operator"] = operator

    # Add simulation note if requested
    if simulate:
        result.setdefault("vibe_warnings", []).append("Simulation mode: generated hints/animations only. No active attacks performed.")

    out = {"html": "", "pdf": ""}
    try:
        html_path = render_html_report(result, target_dir, operator=operator)
        out["html"] = html_path
    except Exception as e:
        out["html"] = ""
    try:
        pdf_path = render_pdf_report(result, target_dir, operator=operator)
        out["pdf"] = pdf_path
    except Exception as e:
        out["pdf"] = ""
    return out

