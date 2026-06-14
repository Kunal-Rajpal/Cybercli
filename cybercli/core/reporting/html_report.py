"""
╔══════════════════════════════════════════════════════════════════╗
║         CyberCLI REPORTING ENGINE — Professional VAPT Reports    ║
║         HTML · PDF · JSON · SARIF · Executive Summary            ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import os
import logging
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("cybercli.report")

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#d97706",
    "Low": "#2563eb",
    "Informational": "#6b7280",
}
SEVERITY_BG = {
    "Critical": "#fef2f2",
    "High": "#fff7ed",
    "Medium": "#fffbeb",
    "Low": "#eff6ff",
    "Informational": "#f9fafb",
}


class HTMLReportGenerator:
    """
    Generates professional, cyber-security-grade HTML VAPT reports.
    Looks like a real pentest firm report.
    """

    def __init__(self, output_dir: str = "artifacts/reports"):
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        target: str,
        findings: List[dict],
        scan_stats: dict,
        attack_graph: Optional[dict] = None,
        executive_summary: str = "",
    ) -> str:
        """Generate full HTML report. Returns file path."""
        findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Low"), 99))
        true_positives = [f for f in findings_sorted if not f.get("false_positive")]
        false_positives = [f for f in findings_sorted if f.get("false_positive")]

        counts = {sev: sum(1 for f in true_positives if f.get("severity") == sev)
                  for sev in SEVERITY_ORDER}

        report_date = datetime.utcnow().strftime("%B %d, %Y — %H:%M UTC")
        html = self._build_html(
            target, true_positives, false_positives, counts,
            scan_stats, attack_graph, executive_summary, report_date
        )

        filename = f"vapt_report_{target.replace('https://','').replace('http://','').replace('/','_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"[REPORT] HTML report saved: {filepath}")
        return filepath

    def _build_html(self, target, findings, fps, counts, stats, graph, exec_summary, report_date) -> str:
        risk_score = self._calculate_risk_score(counts)
        risk_label = ("CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60
                      else "MEDIUM" if risk_score >= 40 else "LOW")

        findings_html = "".join(self._finding_card(i + 1, f) for i, f in enumerate(findings))
        fp_html = ""
        if fps:
            fp_html = f"""
            <div class="section">
              <h2>AI-Suppressed False Positives ({len(fps)})</h2>
              <p class="muted">The following findings were identified by the scanner but validated as false positives by the AI engine. Shown for transparency.</p>
              {"".join(self._fp_card(f) for f in fps[:10])}
            </div>"""

        graph_section = self._graph_section(graph) if graph else ""
        exec_section = f'<p class="exec-text">{exec_summary}</p>' if exec_summary else ""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VAPT Report — {target}</title>
<style>
  :root {{
    --bg: #0a0e17;
    --surface: #111827;
    --surface2: #1f2937;
    --border: #374151;
    --text: #f9fafb;
    --muted: #9ca3af;
    --accent: #06b6d4;
    --critical: #dc2626;
    --high: #ea580c;
    --medium: #d97706;
    --low: #2563eb;
    --info: #6b7280;
    --green: #10b981;
    --font: 'Segoe UI', system-ui, -apple-system, sans-serif;
    --mono: 'Cascadia Code', 'Fira Code', 'Courier New', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
    font-size: 14px;
    line-height: 1.6;
  }}
  a {{ color: var(--accent); text-decoration: none; }}

  /* Cover Page */
  .cover {{
    min-height: 100vh;
    background: linear-gradient(135deg, #0a0e17 0%, #0f172a 50%, #0a1628 100%);
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    padding: 60px 40px;
    text-align: center;
    position: relative;
    overflow: hidden;
  }}
  .cover::before {{
    content: '';
    position: absolute;
    top: -50%;
    left: -50%;
    width: 200%;
    height: 200%;
    background: radial-gradient(ellipse at center, rgba(6,182,212,0.05) 0%, transparent 70%);
    pointer-events: none;
  }}
  .cover-logo {{
    font-size: 11px;
    letter-spacing: 4px;
    color: var(--accent);
    text-transform: uppercase;
    margin-bottom: 60px;
    border: 1px solid rgba(6,182,212,0.3);
    padding: 6px 20px;
    border-radius: 2px;
  }}
  .cover h1 {{
    font-size: 42px;
    font-weight: 300;
    letter-spacing: -1px;
    margin-bottom: 12px;
    color: #fff;
  }}
  .cover h1 span {{ color: var(--accent); font-weight: 700; }}
  .cover .subtitle {{ font-size: 16px; color: var(--muted); margin-bottom: 50px; }}
  .cover .target-badge {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px 40px;
    margin-bottom: 60px;
    font-family: var(--mono);
    font-size: 15px;
    color: var(--accent);
  }}
  .risk-gauge {{
    width: 160px;
    height: 160px;
    border-radius: 50%;
    background: conic-gradient(
      var(--critical) 0deg {int(risk_score * 3.6)}deg,
      var(--surface2) {int(risk_score * 3.6)}deg 360deg
    );
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
    margin: 0 auto 20px;
  }}
  .risk-gauge::before {{
    content: '';
    position: absolute;
    width: 120px;
    height: 120px;
    background: var(--bg);
    border-radius: 50%;
  }}
  .risk-gauge .risk-inner {{
    position: relative;
    z-index: 1;
    text-align: center;
  }}
  .risk-gauge .risk-score {{ font-size: 32px; font-weight: 700; color: var(--critical); }}
  .risk-gauge .risk-lbl {{ font-size: 10px; letter-spacing: 2px; color: var(--muted); }}
  .cover-meta {{ color: var(--muted); font-size: 12px; margin-top: 40px; }}

  /* Severity badges */
  .badge {{
    display: inline-block;
    padding: 2px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
  }}
  .badge-Critical {{ background: #7f1d1d; color: #fca5a5; }}
  .badge-High     {{ background: #7c2d12; color: #fdba74; }}
  .badge-Medium   {{ background: #78350f; color: #fcd34d; }}
  .badge-Low      {{ background: #1e3a5f; color: #93c5fd; }}
  .badge-Info     {{ background: #1f2937; color: #9ca3af; }}

  /* Layout */
  .container {{ max-width: 1100px; margin: 0 auto; padding: 0 30px; }}
  .section {{ padding: 60px 0; border-bottom: 1px solid var(--border); }}
  h2 {{
    font-size: 22px;
    font-weight: 400;
    letter-spacing: -0.5px;
    margin-bottom: 8px;
    color: #fff;
  }}
  h2::before {{ content: '// '; color: var(--accent); font-weight: 700; }}
  .section-desc {{ color: var(--muted); margin-bottom: 30px; font-size: 13px; }}
  .muted {{ color: var(--muted); }}

  /* Stats grid */
  .stats-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin: 30px 0; }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    text-align: center;
  }}
  .stat-card .stat-num {{ font-size: 32px; font-weight: 700; }}
  .stat-card .stat-lbl {{ font-size: 11px; letter-spacing: 1px; color: var(--muted); text-transform: uppercase; margin-top: 4px; }}
  .stat-card.critical .stat-num {{ color: var(--critical); }}
  .stat-card.high .stat-num    {{ color: var(--high); }}
  .stat-card.medium .stat-num  {{ color: var(--medium); }}
  .stat-card.low .stat-num     {{ color: var(--low); }}
  .stat-card.total .stat-num   {{ color: var(--accent); }}

  /* Finding cards */
  .finding-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 20px;
    overflow: hidden;
  }}
  .finding-header {{
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 18px 24px;
    border-bottom: 1px solid var(--border);
    cursor: pointer;
  }}
  .finding-num {{
    font-size: 11px;
    color: var(--muted);
    font-family: var(--mono);
    min-width: 28px;
  }}
  .finding-title {{ font-weight: 500; font-size: 15px; flex: 1; }}
  .finding-meta {{ color: var(--muted); font-size: 12px; margin-left: auto; }}
  .finding-body {{ padding: 24px; display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  .finding-field label {{
    font-size: 10px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--accent);
    display: block;
    margin-bottom: 6px;
  }}
  .finding-field p {{ color: var(--text); font-size: 13px; line-height: 1.5; }}
  .finding-field.full {{ grid-column: 1 / -1; }}
  .code-block {{
    background: #050a14;
    border: 1px solid #1e3a5f;
    border-radius: 6px;
    padding: 12px 16px;
    font-family: var(--mono);
    font-size: 12px;
    color: #38bdf8;
    word-break: break-all;
    white-space: pre-wrap;
  }}
  .cvss-bar {{
    height: 6px;
    background: var(--border);
    border-radius: 3px;
    margin-top: 8px;
    overflow: hidden;
  }}
  .cvss-fill {{ height: 100%; border-radius: 3px; }}

  /* AI badge */
  .ai-badge {{
    display: inline-flex;
    align-items: center;
    gap: 5px;
    background: rgba(6,182,212,0.1);
    border: 1px solid rgba(6,182,212,0.3);
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 10px;
    color: var(--accent);
    letter-spacing: 0.5px;
  }}

  /* Graph section */
  .graph-tree {{
    background: #050a14;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 24px;
    font-family: var(--mono);
    font-size: 13px;
    line-height: 1.8;
    color: #e2e8f0;
  }}
  .graph-critical {{ color: #f87171; }}
  .graph-high     {{ color: #fb923c; }}
  .graph-medium   {{ color: #fbbf24; }}
  .graph-low      {{ color: #60a5fa; }}
  .graph-cloud    {{ color: #a78bfa; }}
  .graph-attack   {{ color: #f472b6; }}

  /* Exec summary */
  .exec-text {{ color: #d1d5db; line-height: 1.9; font-size: 14px; }}

  /* TOC */
  .toc {{ background: var(--surface2); border-radius: 8px; padding: 24px 30px; margin: 30px 0; }}
  .toc ol {{ color: var(--muted); padding-left: 20px; }}
  .toc li {{ padding: 5px 0; }}
  .toc a {{ color: var(--muted); }}
  .toc a:hover {{ color: var(--accent); }}

  /* Footer */
  footer {{
    text-align: center;
    padding: 40px;
    color: var(--muted);
    font-size: 12px;
    border-top: 1px solid var(--border);
  }}

  /* Print */
  @media print {{
    body {{ background: #fff; color: #000; }}
    .cover {{ background: #1a1a2e !important; }}
  }}
</style>
</head>
<body>

<!-- ═══ COVER PAGE ═══ -->
<div class="cover">
  <div class="cover-logo">⬡ CyberCLI Security Platform</div>
  <h1>Vulnerability Assessment<br><span>& Penetration Testing</span></h1>
  <p class="subtitle">VAPT Report — Confidential</p>
  <div class="target-badge">TARGET: {target}</div>
  <div class="risk-gauge">
    <div class="risk-inner">
      <div class="risk-score">{risk_score}</div>
      <div class="risk-lbl">RISK</div>
    </div>
  </div>
  <p style="color: var(--critical); font-size: 13px; letter-spacing: 2px; margin-bottom: 20px;">{risk_label} RISK</p>
  <div class="cover-meta">
    Report Generated: {report_date}<br>
    Scanner: CyberCLI v1.0 · AI-Powered · Better than OWASP ZAP
  </div>
</div>

<div class="container">

  <!-- ═══ TOC ═══ -->
  <div class="section">
    <h2>Table of Contents</h2>
    <div class="toc">
      <ol>
        <li><a href="#executive">Executive Summary</a></li>
        <li><a href="#stats">Vulnerability Statistics</a></li>
        <li><a href="#graph">Attack Graph</a></li>
        <li><a href="#findings">Technical Findings ({len(findings)})</a></li>
        <li><a href="#remediation">Remediation Roadmap</a></li>
        <li><a href="#fp">AI-Suppressed False Positives ({len(fps)})</a></li>
      </ol>
    </div>
  </div>

  <!-- ═══ EXECUTIVE SUMMARY ═══ -->
  <div class="section" id="executive">
    <h2>Executive Summary</h2>
    <p class="section-desc">Risk overview for non-technical stakeholders</p>
    {exec_section or f'<p class="exec-text">Security assessment of <strong style="color:#fff">{target}</strong> identified <strong style="color:#fff">{len(findings)}</strong> vulnerabilities requiring attention. The overall risk posture is rated <strong style="color:var(--critical)">{risk_label}</strong>. Immediate remediation is recommended for all Critical and High severity findings.</p>'}
  </div>

  <!-- ═══ STATS ═══ -->
  <div class="section" id="stats">
    <h2>Vulnerability Statistics</h2>
    <div class="stats-grid">
      <div class="stat-card total">
        <div class="stat-num">{len(findings)}</div>
        <div class="stat-lbl">Total</div>
      </div>
      <div class="stat-card critical">
        <div class="stat-num">{counts.get('Critical', 0)}</div>
        <div class="stat-lbl">Critical</div>
      </div>
      <div class="stat-card high">
        <div class="stat-num">{counts.get('High', 0)}</div>
        <div class="stat-lbl">High</div>
      </div>
      <div class="stat-card medium">
        <div class="stat-num">{counts.get('Medium', 0)}</div>
        <div class="stat-lbl">Medium</div>
      </div>
      <div class="stat-card low">
        <div class="stat-num">{counts.get('Low', 0) + counts.get('Informational', 0)}</div>
        <div class="stat-lbl">Low/Info</div>
      </div>
    </div>
    <div style="margin-top:20px; color: var(--muted); font-size: 13px;">
      Scan Duration: {stats.get('duration', 'N/A')} &nbsp;|&nbsp;
      Requests Made: {stats.get('requests', 'N/A')} &nbsp;|&nbsp;
      Endpoints Scanned: {stats.get('endpoints', 'N/A')} &nbsp;|&nbsp;
      AI Validated: {'Yes' if stats.get('ai_validated') else 'No'}
    </div>
  </div>

  <!-- ═══ ATTACK GRAPH ═══ -->
  {graph_section}

  <!-- ═══ FINDINGS ═══ -->
  <div class="section" id="findings">
    <h2>Technical Findings</h2>
    <p class="section-desc">Sorted by severity — AI-validated, false positives removed</p>
    {findings_html or '<p class="muted">No findings to display.</p>'}
  </div>

  <!-- ═══ REMEDIATION ROADMAP ═══ -->
  <div class="section" id="remediation">
    <h2>Remediation Roadmap</h2>
    <p class="section-desc">Priority order for remediation based on risk and exploitability</p>
    {self._remediation_table(findings)}
  </div>

  {fp_html}

</div>

<footer>
  Generated by <strong>CyberCLI Security Platform</strong> &nbsp;|&nbsp;
  AI-Powered VAPT &nbsp;|&nbsp; {report_date} &nbsp;|&nbsp;
  <span style="color: #374151;">CONFIDENTIAL — Handle with care</span>
</footer>

</body>
</html>"""

    def _finding_card(self, num: int, f: dict) -> str:
        sev = f.get("severity", "Low")
        cvss = f.get("cvss_score", 0.0)
        cvss_width = int((cvss / 10) * 100)
        cvss_color = ("#dc2626" if cvss >= 9 else "#ea580c" if cvss >= 7
                      else "#d97706" if cvss >= 4 else "#2563eb")
        ai_badge = '<span class="ai-badge">✦ AI Validated</span>' if f.get("ai_validated") else ""
        confidence = f.get("ai_confidence", 0)
        conf_text = f"Confidence: {int(confidence * 100)}%" if confidence else ""

        return f"""
        <div class="finding-card">
          <div class="finding-header">
            <span class="finding-num">#{num:02d}</span>
            <span class="badge badge-{sev}">{sev}</span>
            <span class="finding-title">{f.get('title', 'Unknown')}</span>
            {ai_badge}
            <span class="finding-meta">{conf_text}</span>
          </div>
          <div class="finding-body">
            <div class="finding-field">
              <label>URL</label>
              <p style="word-break:break-all; font-family: var(--mono); font-size:12px;">{f.get('url', 'N/A')}</p>
            </div>
            <div class="finding-field">
              <label>Parameter</label>
              <p style="font-family: var(--mono);">{f.get('parameter', 'N/A')}</p>
            </div>
            <div class="finding-field full">
              <label>Description</label>
              <p>{f.get('description', 'N/A')}</p>
            </div>
            {f'<div class="finding-field full"><label>Payload</label><div class="code-block">{f.get("payload", "")}</div></div>' if f.get('payload') else ''}
            {f'<div class="finding-field full"><label>Evidence</label><div class="code-block">{f.get("evidence", "")}</div></div>' if f.get('evidence') else ''}
            {f'<div class="finding-field full"><label>Attack Scenario</label><p>{f.get("attack_scenario", "")}</p></div>' if f.get('attack_scenario') else ''}
            <div class="finding-field">
              <label>Exploitability</label>
              <p>{f.get('exploitability', 'N/A')}</p>
            </div>
            <div class="finding-field">
              <label>CVSS Score</label>
              <p style="font-size:18px; font-weight:700; color:{cvss_color};">{cvss}</p>
              <div class="cvss-bar"><div class="cvss-fill" style="width:{cvss_width}%;background:{cvss_color};"></div></div>
            </div>
            {f'<div class="finding-field full"><label>Real Impact</label><p>{f.get("real_impact", "")}</p></div>' if f.get('real_impact') else ''}
            <div class="finding-field full">
              <label>Remediation</label>
              <p style="white-space: pre-line;">{f.get('remediation', 'Refer to OWASP guidelines.')}</p>
            </div>
          </div>
        </div>"""

    def _fp_card(self, f: dict) -> str:
        return f"""
        <div class="finding-card" style="opacity:0.5; border-style: dashed;">
          <div class="finding-header">
            <span class="badge" style="background:#1f2937;color:#9ca3af;">FP</span>
            <span class="finding-title" style="text-decoration:line-through;">{f.get('title', '')}</span>
            <span class="finding-meta">Reason: {f.get('false_positive_reason', 'AI validation')}</span>
          </div>
        </div>"""

    def _graph_section(self, graph: dict) -> str:
        if not graph:
            return ""
        nodes = graph.get("nodes", [])
        stats = graph.get("stats", {})
        tree_lines = self._build_tree_html(graph)
        return f"""
        <div class="section" id="graph">
          <h2>Attack Graph</h2>
          <p class="section-desc">
            {stats.get('total_nodes', 0)} nodes &nbsp;·&nbsp;
            {stats.get('total_edges', 0)} edges &nbsp;·&nbsp;
            {stats.get('attack_vectors', 0)} attack vectors &nbsp;·&nbsp;
            {stats.get('critical_nodes', 0)} critical nodes
          </p>
          <div class="graph-tree">{tree_lines}</div>
        </div>"""

    def _build_tree_html(self, graph: dict) -> str:
        lines = []
        root = graph.get("root_domain", "target")
        lines.append(f'<span style="color:#fff;font-weight:700;">{root}</span>')

        nodes = {n["id"]: n for n in graph.get("nodes", [])}
        edges = graph.get("edges", [])

        children = {}
        for e in edges:
            if e["source"] not in children:
                children[e["source"]] = []
            children[e["source"]].append(e["target"])

        root_children = children.get(root, [])
        for i, child_id in enumerate(root_children):
            child = nodes.get(child_id, {})
            is_last = (i == len(root_children) - 1)
            prefix = "   └── " if is_last else "   ├── "
            risk = child.get("risk", "Low")
            icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Cloud": "☁"}.get(risk, "⚪")
            css = f"graph-{risk.lower()}"
            label = child.get("label", child_id)
            lines.append(f'{prefix}<span class="{css}">{icon} {label}</span>')

            # Sub-children
            sub_children = children.get(child_id, [])
            for j, sub_id in enumerate(sub_children[:3]):
                sub = nodes.get(sub_id, {})
                is_last_sub = (j == len(sub_children[:3]) - 1)
                sp = "   │      └── " if is_last_sub else "   │      ├── "
                if not is_last:
                    sp = "   │" + sp[4:]
                sub_risk = sub.get("risk", "Low")
                sub_css = f"graph-{sub_risk.lower()}"
                lines.append(f'{sp}<span class="{sub_css}">⚠ {sub.get("label", sub_id)}</span>')

        attack_paths = [e for e in edges if e.get("relation") == "attack_path"]
        if attack_paths:
            lines.append(f'\n   <span class="graph-attack">⚡ ATTACK PATHS: {len(attack_paths)}</span>')
            for e in attack_paths[:3]:
                lines.append(f'   <span class="graph-attack">   {e["source"]} → {e["target"]}</span>')

        return "\n".join(lines)

    def _remediation_table(self, findings: List[dict]) -> str:
        if not findings:
            return '<p class="muted">No findings.</p>'
        rows = ""
        for i, f in enumerate(findings[:20]):
            sev = f.get("severity", "Low")
            rows += f"""
            <tr>
              <td style="padding:12px 16px;color:var(--muted);font-family:var(--mono);">P{i+1:02d}</td>
              <td style="padding:12px 16px;"><span class="badge badge-{sev}">{sev}</span></td>
              <td style="padding:12px 16px;">{f.get('title', '')}</td>
              <td style="padding:12px 16px;color:var(--muted);">{f.get('url', '')[:60]}...</td>
              <td style="padding:12px 16px;color:var(--muted);">{f.get('cvss_score', 0)}</td>
            </tr>"""
        return f"""
        <table style="width:100%;border-collapse:collapse;background:var(--surface);border-radius:8px;overflow:hidden;">
          <thead>
            <tr style="background:var(--surface2);color:var(--muted);font-size:11px;letter-spacing:1px;text-transform:uppercase;">
              <th style="padding:12px 16px;text-align:left;">Priority</th>
              <th style="padding:12px 16px;text-align:left;">Severity</th>
              <th style="padding:12px 16px;text-align:left;">Finding</th>
              <th style="padding:12px 16px;text-align:left;">URL</th>
              <th style="padding:12px 16px;text-align:left;">CVSS</th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>"""

    def _calculate_risk_score(self, counts: dict) -> int:
        score = (counts.get("Critical", 0) * 25 +
                 counts.get("High", 0) * 15 +
                 counts.get("Medium", 0) * 5 +
                 counts.get("Low", 0) * 1)
        return min(score, 100)
