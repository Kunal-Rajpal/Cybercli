# cybercli/core/graph_utils.py
# Graph generation helpers for One-man-army (recon pipeline)
# Provides render_asset_graph(domain, data, outdir, fmt="png")

from pathlib import Path
from typing import Dict, List, Any
import subprocess
import shutil
import json
import datetime

# Optional import of python-graphviz
try:
    from graphviz import Digraph, Source
except Exception:
    Digraph = None
    Source = None


def _safe_str(s: Any) -> str:
    try:
        return str(s)
    except Exception:
        return ""


def _write_dot_file(dot_path: Path, lines: List[str]) -> None:
    dot_path.parent.mkdir(parents=True, exist_ok=True)
    dot_path.write_text("\n".join(lines), encoding="utf-8")


def _default_dot(domain: str, data: Dict[str, Any]) -> List[str]:
    """
    Build a DOT graph as list of lines.
    data expected form: {"subdomains": [...], "ips": [...], "quick_open_ports": [...], "tech_hints": {...}}
    This uses a dark theme node styling similar to recon_core's HTML CSS.
    """
    subdomains = data.get("subdomains") or []
    ips = data.get("ips") or []
    quick = data.get("quick_open_ports") or []
    tech = data.get("tech_hints") or {}

    lines = [
        'digraph G {',
        '  graph [rankdir=LR, bgcolor="#0b0f14", fontcolor="white"];',
        '  node  [style=filled, color="#1f2937", fillcolor="#1f2937", fontcolor="white", shape=box];',
        '  edge  [color="#94a3b8"];',
    ]
    # Domain node
    domain_label = _safe_str(domain).replace('"', '\\"')
    lines.append(f'  "domain::{domain_label}" [label="{domain_label}\\n(domain)", shape=box, fillcolor="#0ea5e9"];')

    # Subdomains
    for sd in subdomains[:1000]:
        sd_s = _safe_str(sd).replace('"', '\\"')
        lines.append(f'  "sub::{sd_s}" [label="{sd_s}\\n(subdomain)", shape=ellipse, fillcolor="#22c55e"];')
        lines.append(f'  "domain::{domain_label}" -> "sub::{sd_s}";')

    # IPs
    for ip in ips:
        ip_s = _safe_str(ip).replace('"', '\\"')
        lines.append(f'  "ip::{ip_s}" [label="{ip_s}\\n(IP)", shape=diamond, fillcolor="#f59e0b"];')
        lines.append(f'  "domain::{domain_label}" -> "ip::{ip_s}";')

    # Quick ports (if structured as list of {"ip": ip, "open_ports": [p, ...]})
    for item in quick:
        try:
            ip = _safe_str(item.get("ip"))
            ports = item.get("open_ports", []) or []
            for p in ports:
                # node per port
                port_node = f'port::{ip}:{p}'
                lines.append(f'  "{port_node}" [label="{p}/tcp", shape=oval, fillcolor="#ef4444"];')
                lines.append(f'  "ip::{ip}" -> "{port_node}";')
        except Exception:
            continue

    # Tech hints block (if present)
    if isinstance(tech, dict) and tech:
        label = "\\n".join([f"{k}: {v}" for k, v in tech.items() if v])
        label = label.replace('"', '\\"')
        lines.append(f'  "tech::{domain_label}" [label="{label}", shape=note, fillcolor="#6366f1"];')
        lines.append(f'  "domain::{domain_label}" -> "tech::{domain_label}";')

    lines.append("}")
    return lines


def render_asset_graph(domain: str, data: Dict[str, Any], outdir: Path, fmt: str = "png") -> str:
    """
    Render an asset graph for `domain` using `data` and write into `outdir`.
    - domain: target domain string
    - data: dict with keys like "subdomains", "ips", "quick_open_ports", "tech_hints"
    - outdir: Path or str where artifacts should be created
    - fmt: one of "png", "svg", "dot" (default "png")
    Returns path to generated artifact (png/svg/dot) as string.
    Notes:
      - Tries python-graphviz first; if not available, falls back to `dot` binary.
      - Always writes an asset_graph.dot (source). If rendering to image fails, returns .dot path.
    """
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    base_name = "asset_graph"
    dot_path = outdir / f"{base_name}.dot"
    target_format = (fmt or "png").lower()

    # Build dot lines
    lines = _default_dot(domain, data)
    try:
        _write_dot_file(dot_path, lines)
    except Exception as e:
        # If writing fails, return a safe message (raise might be okay too)
        return str(dot_path)

    # If user requested only dot, return it
    if target_format == "dot":
        return str(dot_path)

    # 1) Try python graphviz (recommended)
    if Digraph is not None and Source is not None:
        try:
            src = Source("\n".join(lines), filename=str(outdir / base_name), format=target_format)
            rendered = src.render(cleanup=True)  # returns path to rendered file (with extension)
            # On success ensure file exists and return
            p = Path(rendered)
            if p.exists():
                return str(p)
        except Exception:
            # swallow and fallback to dot binary
            pass

    # 2) Try dot binary fallback
    dot_bin = shutil.which("dot")
    if dot_bin:
        out_file = outdir / f"{base_name}.{target_format}"
        try:
            subprocess.run([dot_bin, f"-T{target_format}", str(dot_path), "-o", str(out_file)], timeout=20, check=True)
            if out_file.exists():
                return str(out_file)
        except Exception:
            # fallthrough to return .dot
            pass

    # If we reach here rendering failed: return .dot path (caller should log warnings)
    return str(dot_path)


# Small convenience: if other modules want to call with older signature (domain, result, outdir, fmt)
# they can use `render_asset_graph(domain, data, outdir, fmt="png")` directly.

