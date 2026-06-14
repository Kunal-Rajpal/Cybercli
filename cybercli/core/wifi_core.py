#!/usr/bin/env python3
# cybercli/core/wifi_core.py
# -*- coding: utf-8 -*-
"""
Wireless helpers (safe, non-destructive).

Features:
- list_interfaces() : discover wireless interfaces (uses `iw`, `nmcli`, fallback)
- scan_access_points() : perform passive scan of visible APs using `nmcli` or `iwlist` if available
- monitor_mode_check() : indicate if monitor mode is available/enabled on an interface
- analyze_pcap() : best-effort analysis of a pcap file for PMKID/handshake presence (requires scapy)
- detect_rogue_aps() : simple heuristics (duplicate SSID multiple BSSIDs, unexpected open APs)
- signal_strength_summary() : basic RSSI stats
- reporting: uses privesc_core.write_html_report if present, else writes minimal reports into reports/
All actions are conservative and non-destructive.
"""

from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any, Optional
import subprocess, shutil, datetime, json, statistics

# optional dependencies
try:
    from scapy.all import rdpcap, Dot11, EAPOL
    _HAS_SCAPY = True
except Exception:
    _HAS_SCAPY = False

# try reuse existing privesc writer if available
try:
    from cybercli.core.privesc_core import ensure_dir as _ensure_dir, write_html_report as _write_html_report, now_stamp as _now_stamp
    _HAS_PRIVESC_REPORT = True
except Exception:
    _HAS_PRIVESC_REPORT = False

def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p

def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

SIMPLE_CSS = """
body{background:#0b0f12;color:#d7fbd7;font-family:ui-monospace,Consolas,Monaco,monospace;padding:12px}
.card{background:#0f1620;padding:12px;border-radius:8px;margin-bottom:12px}
pre{white-space:pre-wrap;word-break:break-word}
"""

def simple_write_report(outdir: Path, base: str, body: str, meta: Optional[dict]=None) -> Dict[str,str]:
    outdir = ensure_dir(outdir)
    txt = outdir / f"{base}.txt"
    html = outdir / f"{base}.html"
    started = datetime.datetime.utcnow().isoformat() + "Z"
    txt.write_text(f"# {base}\n# {started}\n\n{body}\n", encoding="utf-8", errors="ignore")
    html_body = f"""<!doctype html><html><head><meta charset='utf-8'><title>{base}</title><style>{SIMPLE_CSS}</style></head>
<body>
<div class="card"><h2>{base}</h2><small>{started}</small></div>
<div class="card"><pre>{body}</pre></div>
</body></html>"""
    html.write_text(html_body, encoding="utf-8", errors="ignore")
    return {"txt": str(txt.resolve()), "html": str(html.resolve())}

def write_report_auto(outdir: Path, base: str, cmd: List[str], rc: int, out: str, err: str, started_ts: str, ended_ts: str, meta: Optional[dict]=None) -> Dict[str,str]:
    if _HAS_PRIVESC_REPORT:
        try:
            return _write_html_report(outdir, base, cmd, rc, out, err, started_ts, ended_ts, meta=meta)
        except Exception:
            pass
    # fallback
    body = f"CMD: {' '.join(cmd)}\n\nSTDOUT:\n{out}\n\nSTDERR:\n{err}\n"
    return simple_write_report(outdir, base, body, meta=meta)

# ----------------- helpers -----------------
def _run_cmd(cmd: List[str], timeout: int = 15) -> Dict[str, Any]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": p.stdout.strip(), "err": p.stderr.strip()}
    except Exception as e:
        return {"rc": -1, "out": "", "err": str(e)}

# ----------------- interface discovery -----------------
def list_wireless_interfaces() -> List[Dict[str,str]]:
    """
    Return list of candidate wireless interfaces with minimal info.
    Tries `iw dev`, `nmcli device`, and falls back to parsing /sys/class/net.
    """
    if shutil.which("iw"):
        res = _run_cmd(["iw", "dev"])
        outs = res["out"]
        interfaces = []
        # try simple parse: find "Interface <name>"
        for line in outs.splitlines():
            line = line.strip()
            if line.startswith("Interface"):
                parts = line.split()
                if len(parts) >= 2:
                    interfaces.append({"iface": parts[1], "detail": "iw"})
        if interfaces:
            return interfaces

    if shutil.which("nmcli"):
        res = _run_cmd(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"])
        if res["out"]:
            ifaces = []
            for ln in res["out"].splitlines():
                try:
                    dev, typ, state = ln.split(":")
                    if typ == "wifi":
                        ifaces.append({"iface": dev, "state": state, "detail": "nmcli"})
                except Exception:
                    continue
            if ifaces:
                return ifaces

    # fallback: look for wireless folders in /sys/class/net/<iface>/wireless
    ifaces = []
    try:
        p = Path("/sys/class/net")
        for d in p.iterdir():
            if (d / "wireless").exists() or (d / "phy80211").exists():
                ifaces.append({"iface": d.name, "detail": "sysfs"})
    except Exception:
        pass
    return ifaces

# ----------------- scanning (passive, safe) -----------------
def scan_access_points(interface: Optional[str] = None, timeout: int = 10) -> Dict[str, Any]:
    """
    Perform a passive scan of visible APs.
    Uses nmcli if available: `nmcli device wifi list`.
    Falls back to `iwlist <iface> scan` if available.
    Returns mapping of SSID -> list of BSSIDs with properties.
    NOTE: This function does NOT enable monitor mode or inject packets.
    """
    aps = {}
    # try nmcli
    if shutil.which("nmcli"):
        cmd = ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY,CHAN", "device", "wifi", "list"]
        res = _run_cmd(cmd, timeout=max(10, timeout))
        if res["rc"] == 0 and res["out"]:
            for ln in res["out"].splitlines():
                # format: SSID:BSSID:SIGNAL:SECURITY:CHAN
                parts = ln.split(":")
                if len(parts) >= 5:
                    ssid, bssid, signal, security, chan = parts[:5]
                    aps.setdefault(ssid or "<hidden>", []).append({
                        "bssid": bssid, "signal": int(signal) if signal.isdigit() else None,
                        "security": security, "chan": chan
                    })
            return {"method": "nmcli", "aps": aps}
    # try iwlist
    if interface and shutil.which("iwlist"):
        cmd = ["iwlist", interface, "scan"]
        res = _run_cmd(cmd, timeout=max(15, timeout))
        out = res["out"]
        if out:
            # crude parsing
            cur_bssid = None
            cur_ssid = None
            cur_signal = None
            cur_security = "UNKNOWN"
            for line in out.splitlines():
                line = line.strip()
                if line.lower().startswith("cell"):
                    parts = line.split()
                    if len(parts) >= 5:
                        cur_bssid = parts[4]
                elif "essid:" in line.lower():
                    try:
                        cur_ssid = line.split("ESSID:")[1].strip().strip('"')
                    except Exception:
                        cur_ssid = "<hidden>"
                elif "quality=" in line.lower() and "signal level" in line.lower():
                    # quality=70/70  signal level=-39 dBm
                    if "signal level" in line:
                        try:
                            part = line.split("signal level=")[1].split()[0]
                            cur_signal = int(part.replace("dBm","").replace("DBM","").strip())
                        except Exception:
                            cur_signal = None
                elif "encryption key" in line.lower():
                    if "on" in line.lower():
                        cur_security = "ENCRYPTED"
                    else:
                        cur_security = "OPEN"
                # at end of block, if we have bssid and ssid, record
                if cur_bssid:
                    aps.setdefault(cur_ssid or "<hidden>", []).append({
                        "bssid": cur_bssid,
                        "signal": cur_signal,
                        "security": cur_security
                    })
                    cur_bssid = None
                    cur_ssid = None
                    cur_signal = None
                    cur_security = "UNKNOWN"
            return {"method": "iwlist", "aps": aps}
    # if nothing available, return message
    return {"method": "none", "message": "No suitable scanning tool found (nmcli/iwlist). Run on host with network-manager or wireless tools installed.", "aps": {}}

# ----------------- monitor mode check -----------------
def monitor_mode_check(interface: str) -> Dict[str,Any]:
    """
    Check if monitor mode is available and whether it is enabled.
    Does NOT enable/disable monitor mode.
    """
    info = {"interface": interface, "support_monitor": False, "monitor_enabled": False, "notes": []}
    # check iw list for monitor capability
    if shutil.which("iw"):
        res = _run_cmd(["iw", "list"])
        out = res["out"]
        if "Supported interface modes" in out:
            if "monitor" in out:
                info["support_monitor"] = True
        # check current mode
        res2 = _run_cmd(["iw", "dev", interface, "info"])
        if res2["rc"] == 0 and "type monitor" in res2["out"].lower():
            info["monitor_enabled"] = True
    else:
        info["notes"].append("iw not available to check monitor capabilities.")
    return info

# ----------------- pcap analysis (best-effort, optional scapy) -----------------
def analyze_pcap(pcap_path: str) -> Dict[str,Any]:
    """
    Analyze an existing pcap for:
     - number of 802.11 frames
     - presence of EAPOL handshake frames
     - presence of PMKID (if scapy can parse)
    This function requires scapy. If scapy missing, returns explanatory message.
    This function DOES NOT extract keys or perform cracking.
    """
    p = Path(pcap_path)
    if not p.exists():
        return {"error": "pcap file not found"}
    if not _HAS_SCAPY:
        return {"error": "scapy not installed (pip install scapy) — pcap analysis unavailable"}
    try:
        pkts = rdpcap(str(p))
        total = 0
        eapol_count = 0
        pmkid_found = False
        ssids = {}
        for pkt in pkts:
            if pkt.haslayer(Dot11):
                total += 1
                # SSID (Beacon/Probe)
                try:
                    if pkt.type == 0 and pkt.subtype in (8, 5):  # beacon/probe
                        ssid = pkt.info.decode(errors="ignore") if hasattr(pkt, "info") else None
                        bssid = pkt.addr2 if hasattr(pkt, "addr2") else None
                        if ssid:
                            ssids.setdefault(ssid, set()).add(bssid)
                except Exception:
                    pass
            # EAPOL frames indicate handshake activity
            try:
                if pkt.haslayer(EAPOL):
                    eapol_count += 1
            except Exception:
                pass
            # basic PMKID heuristic: look for RSN element with PMKID (scapy doesn't parse PMKID easily)
            # Not attempting to extract PMKID content — only indicate possible presence by looking at raw bytes.
            try:
                raw = bytes(pkt)
                if b"pmkid" in raw.lower() or b"\x00\x0f\xac" in raw:  # heuristic, not exact
                    pmkid_found = True
            except Exception:
                pass
        ssid_summary = {k: len(v) for k,v in ssids.items()}
        return {"total_frames": total, "eapol_frames": eapol_count, "pmkid_possible": pmkid_found, "ssids": ssid_summary}
    except Exception as e:
        return {"error": f"pcap parse error: {e}"}

# ----------------- rogue AP detection heuristics -----------------
def detect_rogue_aps(aps: Dict[str, List[Dict[str,Any]]], known_ssids: Optional[List[str]] = None) -> Dict[str,Any]:
    """
    Simple heuristics:
     - same SSID with many BSSIDs -> suspicious (possible evil twin)
     - open SSID when expected encrypted -> suspicious
     - signal anomalies (very strong signal for corporate SSID)
    known_ssids: list of expected legitimate SSIDs to reduce false positives
    """
    found = []
    known_set = set([s.lower() for s in (known_ssids or [])])
    for ssid, entries in aps.items():
        bcount = len(entries)
        opens = [e for e in entries if (not e.get("security") or e.get("security","").upper() in ("--","NONE","OPEN"))]
        signals = [e.get("signal") for e in entries if isinstance(e.get("signal"), int)]
        avg_signal = statistics.mean(signals) if signals else None
        suspicious = False
        reasons = []
        if bcount >= 3:
            suspicious = True
            reasons.append(f"Multiple BSSIDs for SSID ({bcount})")
        if opens:
            suspicious = True
            reasons.append(f"Open/unencrypted BSSIDs present ({len(opens)})")
        if known_set and ssid.lower() not in known_set and avg_signal and avg_signal > -40:
            suspicious = True
            reasons.append("Unknown SSID with very strong signal")
        if suspicious:
            found.append({"ssid": ssid, "bssids": entries, "reasons": reasons})
    return {"suspicious": found, "checked": len(aps)}

# ----------------- signal summary -----------------
def signal_strength_summary(aps: Dict[str, List[Dict[str,Any]]]) -> Dict[str,Any]:
    vals = []
    for ssid, entries in aps.items():
        for e in entries:
            v = e.get("signal")
            if isinstance(v, int):
                vals.append(v)
    if not vals:
        return {"count": 0, "min": None, "max": None, "avg": None}
    return {"count": len(vals), "min": min(vals), "max": max(vals), "avg": sum(vals)/len(vals)}

# ----------------- high-level wrapper -----------------
def wireless_quick_scan(reports_root: Path, target_name: str, interface: Optional[str] = None, known_ssids: Optional[List[str]] = None, timeout: int = 10) -> Dict[str,Any]:
    """
    Run a safe wireless "quick scan":
     - list interfaces
     - passive AP scan (nmcli/iwlist)
     - monitor mode check (if iface provided)
     - rogue AP heuristics
     - signal summary
    Writes a simple report to reports_root/target_name/<stamp>/wireless
    """
    run_root = ensure_dir(reports_root / target_name / now_stamp())
    outdir = ensure_dir(run_root / "wireless")
    started = datetime.datetime.utcnow().isoformat() + "Z"

    ifaces = list_wireless_interfaces()
    scan_res = scan_access_points(interface=interface, timeout=timeout)
    aps = scan_res.get("aps") if isinstance(scan_res, dict) else {}
    mon = monitor_mode_check(interface) if interface else {}

    rogue = detect_rogue_aps(aps, known_ssids=known_ssids)
    sig = signal_strength_summary(aps)

    body = {
        "interfaces": ifaces,
        "scan_method": scan_res.get("method"),
        "scan_aps_count": sum(len(v) for v in (aps.values() if aps else [])) if aps else 0,
        "aps": aps,
        "monitor_info": mon,
        "rogue_findings": rogue,
        "signal_summary": sig
    }

    ended = datetime.datetime.utcnow().isoformat() + "Z"
    rep = write_report_auto(outdir, "wireless_quick_scan", ["wireless_quick_scan"], 0, json.dumps(body, indent=2), "", started, ended, meta={"tool":"wireless_quick_scan"})
    return {"report": rep, "body": body}

