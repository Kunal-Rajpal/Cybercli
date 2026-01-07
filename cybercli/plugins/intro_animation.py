# ## First Intro-Phase

# # cybercli/plugins/intro_animation.py
# """
# Ultimate hybrid cinematic intro (emoji enabled) — safe, rich-based, no markup errors.
# """

# import random
# import shutil
# import time
# from time import sleep
# from typing import List

# from rich.console import Console
# from rich.panel import Panel
# from rich.text import Text
# from rich.live import Live

# console = Console()

# # timings
# TIMING = {
#     "globe_frames": 18,
#     "globe_delay": 0.12,
#     "tunnel_lines": 18,
#     "tunnel_delay": 0.03,
#     "matrix_frames": 60,
#     "matrix_delay": 0.02,
#     "loading_delay": 1.6,
#     "decrypt_steps": 12,
#     "ai_logs": 4,
#     "module_pause": 0.85,
#     "network_frames": 18,
#     "network_delay": 0.06,
# }

# # -----------------------------------------------------
# # FIXED: Added PHASE() function
# # -----------------------------------------------------
# def phase(label: str, color: str = "cyan"):
#     console.print(
#         Panel.fit(
#             Text(f"🚀 {label}", style=f"bold {color}", justify="center"),
#             border_style=color,
#         )
#     )
#     time.sleep(0.4)

# # -----------------------------------------------------
# # Helpers
# # -----------------------------------------------------
# def clear():
#     try:
#         console.clear()
#     except:
#         print("\n" * 4)

# def title_panel():
#     console.print(
#         Panel.fit(
#             Text("CYBERCLI — NEXT-GEN CYBER OPS ENGINE", style="bold cyan", justify="center"),
#             border_style="cyan",
#         )
#     )

# def safe_glitch_line(s: str):
#     t = Text()
#     for ch in s:
#         if ch != " " and random.random() < 0.08:
#             t.append(ch, style=random.choice(["magenta", "cyan", "green"]))
#         else:
#             t.append(ch)
#     console.print(t)

# # -----------------------------------------------------
# # Phase 1
# # -----------------------------------------------------
# def rotating_globe():
#     frames = ["🌐", "◐", "◓", "◑", "◒"]
#     with Live(refresh_per_second=8, transient=True) as live:
#         for i in range(TIMING["globe_frames"]):
#             frame = frames[i % len(frames)]
#             live.update(
#                 Panel(
#                     Text(f"{frame} Rotating Cyber Globe • • •", style="bold magenta"),
#                     border_style=random.choice(["magenta", "cyan", "green"]),
#                 )
#             )
#             time.sleep(TIMING["globe_delay"])

# def neon_ascii_tunnel():
#     width = min(120, shutil.get_terminal_size().columns)
#     chars = ["█", "▓", "▒", "░"]
#     for _ in range(TIMING["tunnel_lines"]):
#         line = "".join(random.choice(chars) for _ in range(width))
#         console.print(Text(line, style="bold cyan"))
#         time.sleep(TIMING["tunnel_delay"])

# def matrix_rain():
#     width = min(120, shutil.get_terminal_size().columns)
#     charset = "01▮▯"
#     for _ in range(TIMING["matrix_frames"]):
#         row = "".join(random.choice(charset) for _ in range(width))
#         console.print(Text(row, style="green"))
#         time.sleep(TIMING["matrix_delay"])

# # -----------------------------------------------------
# # Phase 2
# # -----------------------------------------------------
# def loading_bar(label, duration):
#     total = 28
#     with Live(refresh_per_second=30, transient=True) as live:
#         for i in range(total + 1):
#             pct = int((i / total) * 100)
#             bar = "█" * i + "░" * (total - i)
#             live.update(
#                 Panel(
#                     Text(f"{label}: [{bar}] {pct}%", style="yellow"),
#                     border_style="yellow",
#                 )
#             )
#             time.sleep(duration / total)

# def decrypt_fx():
#     steps = ["PROBE", "BRUTE-SEQ", "UNLOCK", "VERIFY", "INTEGRITY"]
#     for i in range(TIMING["decrypt_steps"]):
#         step = steps[i % len(steps)]
#         bar = "█" * ((i * 3) % 40) + "-" * (40 - ((i * 3) % 40))
#         console.print(
#             Panel(
#                 Text(f"{step} [{bar}]", style="bold magenta"),
#                 border_style="magenta",
#             )
#         )
#         time.sleep(0.22)

# AI_LOGS = [
#     "AI: Sensors nominal.",
#     "AI: Correlation model online.",
#     "AI: Ingesting IOC feeds.",
#     "AI: Preparing mission summary...",
# ]
# def ai_voice_logs():
#     for line in AI_LOGS:
#         console.print(Text(line, style="cyan"))
#         time.sleep(0.9)

# # -----------------------------------------------------
# # Phase 3
# # -----------------------------------------------------
# MODULES = {
#     "Recon": ["whois --target <host>", "dnsenum --domain <domain>"],
#     "Scan": ["nmap top-ports", "nikto --host <site>"],
#     "Exploit": ["exploit search <cve>", "exploit run --target <ip>"],
#     "PrivEsc": ["linpeas.sh", "pspy64"],
#     "WebSec": ["ffuf -u https://site/FUZZ", "sqlmap -u <url> --batch"],
#     "ActiveDirectory": ["kerberoast <users>", "ldapenum --dc <ip>"],
# }

# def modules_overview():
#     console.print(Panel.fit(Text("MODULES — OVERVIEW", style="bold purple"), border_style="purple"))
#     for mod, cmds in MODULES.items():
#         console.print(Text(f"{mod:<15} — {cmds[0]}", style="cyan"))
#         time.sleep(0.08)
#     time.sleep(0.8)

# def module_deep_showcase():
#     for mod, cmds in MODULES.items():
#         console.print(
#             Panel.fit(Text(mod, style="bold green"), subtitle="Key Commands", border_style="green")
#         )
#         for c in cmds:
#             console.print(Text(f" • {c}", style="white"))
#             time.sleep(0.08)
#         time.sleep(TIMING["module_pause"])

# # -----------------------------------------------------
# # Phase 4
# # -----------------------------------------------------
# def network_graph():
#     nodes = ["●", "○", "◎", "◉", "◆"]
#     with Live(refresh_per_second=12, transient=True) as live:
#         for _ in range(TIMING["network_frames"]):
#             width = min(120, shutil.get_terminal_size().columns)
#             parts = []
#             for _ in range(max(2, width // 8)):
#                 parts.append(f"{random.choice(nodes)}──{random.choice(nodes)}")
#             live.update(
#                 Panel(
#                     Text("   ".join(parts), style="bold magenta"),
#                     border_style="magenta",
#                 )
#             )
#             time.sleep(TIMING["network_delay"])

# def final_banner():
#     console.print(
#         Panel.fit(
#             Text("✅ SYSTEM ONLINE — CYBERCLI READY", style="bold green"),
#             border_style="green",
#         )
#     )
#     time.sleep(0.9)

# # -----------------------------------------------------
# # MASTER ENTRYPOINT (NOW FIXED)
# # -----------------------------------------------------
# def run_advanced_intro():
#     clear()
#     title_panel()

#     phase("PHASE 1 — BOOT", "magenta")
#     rotating_globe()
#     neon_ascii_tunnel()
#     matrix_rain()

#     phase("PHASE 2 — INITIALIZING", "cyan")
#     loading_bar("Initializing Core Engine", TIMING["loading_delay"])
#     loading_bar("Initializing Modules Loader", TIMING["loading_delay"])
#     loading_bar("Initializing AI Layer", TIMING["loading_delay"])
#     decrypt_fx()
#     ai_voice_logs()

#     phase("PHASE 3 — MODULES", "yellow")
#     modules_overview()
#     module_deep_showcase()

#     phase("PHASE 4 — NETWORK GRAPH", "magenta")
#     network_graph()
#     final_banner()













##-------------------------------------------/\---------------------------------------------------##
#Second-Phase

# # cybercli/plugins/intro_animation.py
# from time import sleep
# from rich.console import Console
# from rich.panel import Panel
# from rich.text import Text
# from rich.live import Live
# from rich import box

# console = Console()

# def slow_print(text, delay=0.03):
#     for char in text:
#         console.print(char, end="", style="cyan")
#         sleep(delay)
#     console.print()

# def neon_tunnel():
#     frames = [
#         "[magenta]>>>>>>>>>>[/magenta]",
#         "[blue]>>>>>>>>>[/blue]",
#         "[cyan]>>>>>>[/cyan]",
#         "[green]>>>[/green]",
#         "[yellow]>[/yellow]",
#         "[green]>>>[/green]",
#         "[cyan]>>>>>>[/cyan]",
#         "[blue]>>>>>>>>>[/blue]",
#         "[magenta]>>>>>>>>>>[/magenta]",
#     ]
#     with Live(console=console, refresh_per_second=20):
#         for _ in range(12):
#             for f in frames:
#                 console.print(Panel(f, style="bold", border_style="magenta"))
#                 sleep(0.05)

# def matrix_rain():
#     chars = "01"
#     with Live(console=console, refresh_per_second=60):
#         for _ in range(30):
#             line = "".join(chars for _ in range(60))
#             console.print(f"[green]{line}[/green]")
#             sleep(0.04)

# def loading_bar(text):
#     bar = ""
#     console.print(f"[cyan]{text}[/cyan]")
#     for _ in range(30):
#         bar += "█"
#         console.print(f"[magenta]{bar}[/magenta]", end="\r")
#         sleep(0.04)
#     console.print()

# def network_graph():
#     graph = """
# [cyan]
#       ●───●────●
#      ╱     ╲
#   ●──●     ●──●──●
#      ╲     ╱
#       ●───●────●
# [/cyan]
# """
#     console.print(Panel(graph, title="[bold yellow]Network Graph Link Map[/bold yellow]", border_style="cyan"))
#     sleep(1.2)

# def rotating_globe():
#     frames = [
#         "🌍",
#         "🌎",
#         "🌏"
#     ]
#     for _ in range(12):
#         for f in frames:
#             console.print(f"[bold cyan]{f}[/bold cyan]", end="\r")
#             sleep(0.15)

# def run_advanced_intro():
#     console.clear()

#     # PHASE 1 — WELCOME
#     console.print(Panel("🔥 [bold cyan]CYBERCLI — NEXT-GEN OPS ENGINE[/bold cyan] 🔥",
#                         border_style="magenta", box=box.DOUBLE))
#     sleep(1)

#     rotating_globe()
#     neon_tunnel()

#     slow_print("Initializing modules…")
#     loading_bar("Loading Core Engine")
#     loading_bar("Loading Cyber Models")
#     matrix_rain()

#     # PHASE 2 — MODULE LIST
#     module_list = """
# [cyan]
# 🔹 recon       — Information gathering & OSINT
# 🔹 scan        — Deep scanning & service mapping
# 🔹 exploit     — Payload testing framework
# 🔹 privesc     — Local privilege escalation tools
# 🔹 websec      — Web security suite
# 🔹 wifi        — Wireless attacks & sniffing
# 🔹 ad          — Active Directory toolkit
# 🔹 redteam     — Adversary simulation modules
# 🔹 blueteam    — Defense & incident response
# [/cyan]
# """
#     console.print(Panel(module_list, title="[bold green]MODULES LOADED[/bold green]",
#                         border_style="green"))
#     sleep(1)

#     # PHASE 3 — COMMAND DEFINITION
#     command_guide = """
# [yellow]
# Example Commands:
# • recon subdomains --target google.com
# • scan ports --ip 192.168.1.1
# • exploit run --payload reverse_shell
# • privesc auto-check
# [/yellow]
# """
#     console.print(Panel(command_guide, title="[cyan]Command Usage[/cyan]", border_style="yellow"))
#     sleep(1)

#     network_graph()

#     # FINAL LAUNCH
#     console.print(Panel("[bold green]SYSTEM READY — ENTERING CYBERCLI[/bold green]",
#                         border_style="green", box=box.HEAVY))
#     sleep(1)




### Third phase

# cybercli/plugins/intro_animation.py
"""
Cinematic intro + per-module animated explainers for CyberCLI.

PHASES:
  Stage 1 (Dark Boot)    ~4s  : matrix rain, neon pulse, BIOS-like text
  Stage 2 (Network Grid) ~3s  : ascii network points + animated edges
  Stage 3 (Cyber Globe)  ~4s  : rotating globe frames + spark traces
  Stage 4 (Menu Reveal)  ~4s  : smooth menu fade-in with 1-line descriptions

Exports:
  run_advanced_intro(total_time=15)  # default tuned to ~15s
  run_module_showcase(modules, per_module_duration=2.5)
  And individual per-module helpers like recon_animation(duration=10, desc=...)
"""

from __future__ import annotations
import time
import random
import shutil
from typing import List, Dict, Callable, Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.table import Table
from rich.align import Align

console = Console()

# ---------- Helpers ----------
def _term_width() -> int:
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 80

def _center_panel(content: str, title: str = "", style: str = "cyan"):
    txt = Text(content)
    return Panel.fit(txt, title=title, border_style=style)

def _safe_print(text: str, style: Optional[str] = None):
    if style:
        console.print(Text(text, style=style))
    else:
        console.print(text)

def _spinner_frames(count=8):
    # subtle spinner frames
    return ["◐", "◓", "◑", "◒"] * max(1, count // 4)

# ---------- Stage 1: Dark Boot Sequence ----------
def _stage1_dark_boot(duration: float = 4.0):
    """
    Matrix rain + neon ASCII tunnel + BIOS-like lines.
    duration ~4s by default
    """
    start = time.time()
    width = min(120, _term_width())
    matrix_chars = "01▮▯▒▓█"
    neon_chars = ["█", "▓", "▒", "░"]
    bios_lines = [
        "Initializing Cyber Engine...",
        "Booting secure modules.",
        "Verifying integrity.",
        "AI correlation services warming up."
    ]

    # matrix + neon alternating frames
    with Live(refresh_per_second=18, transient=True) as live:
        idx = 0
        while time.time() - start < duration:
            lines = []
            # build 6 rows of matrix-like noise (small)
            for _ in range(6):
                row = "".join(random.choice(matrix_chars) for _ in range(min(48, width // 2)))
                lines.append(row)
            # neon tunnel single-line pulse
            tunnel = "".join(random.choice(neon_chars) for _ in range(min(60, width)))
            # BIOS style line rotates through list
            bios = bios_lines[idx % len(bios_lines)]
            frame = "\n".join(lines) + "\n\n" + tunnel + "\n\n" + f"[{bios}]"
            live.update(Panel(frame, title="DARK BOOT", border_style="bright_magenta"))
            idx += 1
            time.sleep(0.08)

    # small beep-ish ASCII suffix (no sound)
    for s in ("[  beep  ]", "[ beep beep ]", "[  beep  ]"):
        _safe_print(s, style="yellow")
        time.sleep(0.14)

# ---------- Stage 2: Network Grid ----------
def _stage2_network_grid(duration: float = 3.0):
    """
    Graphviz-style points + animated edges
    """
    width = min(120, _term_width())
    nodes = ["●", "○", "◎", "◉", "◆", "◇"]
    count = max(4, min(12, width // 10))
    node_positions = [random.randint(0, width - 6) for _ in range(count)]
    start = time.time()
    with Live(refresh_per_second=12, transient=True) as live:
        while time.time() - start < duration:
            # create rows with nodes and pseudo-edges
            rows = []
            for r in range(6):
                row = [" "] * min(width, 80)
                for i, pos in enumerate(node_positions):
                    ch = random.choice(nodes)
                    p = max(0, min(len(row) - 1, (pos + (i * (r % 3)) - r) % len(row)))
                    row[p] = ch
                rows.append("".join(row))
            # overlay some animated edges (random dashes)
            edges = []
            for _ in range(max(1, count // 2)):
                a = random.randint(0, len(rows) - 1)
                b = random.randint(0, len(rows) - 1)
                edges.append(f"{a}↔{b}")
            body = "\n".join(rows) + "\n\n" + "Edges: " + ", ".join(edges)
            live.update(Panel(body, title="MAPPING GLOBAL THREAT GRID", border_style="green"))
            time.sleep(0.12)

# ---------- Stage 3: Cyber Globe ----------
def _stage3_cyber_globe(duration: float = 4.0):
    """
    Rotating wireframe globe simplified frames. Spark traces animate across.
    """
    width = min(120, _term_width())
    frames = [
        "   .--.      _    ",
        "  /    \\   _/ \\   ",
        " |  ●   | / o  \\  ",
        "  \\     / \\_ _/   ",
        "   `--'            "
    ]
    sparks = ["⋆", "✦", "✶", "✺"]
    start = time.time()
    idx = 0
    with Live(refresh_per_second=8, transient=True) as live:
        while time.time() - start < duration:
            # rotate content by offsetting frames order
            rot = frames[idx % len(frames):] + frames[: idx % len(frames)]
            glow = "\n".join(rot)
            # add spark trace line
            trace = " ".join(random.choice(sparks) if random.random() < 0.12 else " " for _ in range(min(40, width // 2)))
            body = glow + "\n\n" + trace + "\n\nLoading active modules..."
            live.update(Panel(body, title="GLOBAL SCAN • ROTATING GLOBE", border_style="bright_blue"))
            idx += 1
            time.sleep(0.16)

# ---------- Stage 4: Command Menu Reveal ----------
def _stage4_menu_reveal(modules: Dict[str, str], duration: float = 4.0):
    """
    Smooth fade-in like reveal of menu list with 1-line purposes.
    modules: ordered dict-like { "recon": "desc", ... }
    """
    keys = list(modules.keys())
    start = time.time()
    per = max(0.08, duration / max(1, len(keys)))
    # progressively reveal lines
    revealed = 0
    while time.time() - start < duration and revealed < len(keys):
        revealed += 1
        console.clear()
        header = Panel(Text("CYBERCLI — MODULES LOADED", style="bold cyan"), border_style="cyan")
        console.print(header)
        for i in range(revealed):
            k = keys[i]
            line = Text.assemble((f"[{i+1}] ", "bright_magenta"), (k.ljust(14), "bold green"), (" — ", "white"), (modules[k], "dim"))
            console.print(line)
        time.sleep(per)
    # final static render
    console.print("\n[bold green]Access Granted — Type --help to list commands[/bold green]")

# ---------- Module animation helpers (per-module short cinematic) ----------
def _module_generic_banner(name: str, emoji: str = "🔹"):
    title = f"{emoji} {name.upper()} MODULE"
    console.print(Panel(Text(title, style="bold magenta"), border_style="magenta"))

def _module_keypoints_box(title: str, points: List[str], duration: float = 3.0):
    # show points one by one with a subtle ascii effect
    start = time.time()
    per = max(0.15, duration / max(1, len(points)))
    for p in points:
        console.print(Panel(Text(p, style="white"), title=title, border_style="cyan"))
        time.sleep(per)

# Individual module animations — they call the generic banner + points
def recon_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("Recon", "🛰️")
    points = [
        desc or "Passive footprinting: DNS, WHOIS, subdomains, certificates, screenshots.",
        "Collect OSINT: social, paste, public repo traces.",
        "Map attack surface: ports, services, exposed endpoints."
    ]
    _module_keypoints_box("Recon • Why", points, duration=min(6.0, duration))

def scan_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("Scan", "🔎")
    points = [
        desc or "Deep scanning: Nmap profiles, service detection, safe vuln checks.",
        "Endpoint surface mapping, sitemap & JS discovery.",
        "Produce prioritized findings for triage."
    ]
    _module_keypoints_box("Scan • Why", points, duration=min(6.0, duration))

def exploit_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("Exploit (SAFE)", "💥")
    points = [
        desc or "Intelligence-only exploit findings: CVE lookups, exploit references (no execution).",
        "Contextual mapping: impacted versions + remediation hints.",
        "Safe simulation: guidance-only payload templates."
    ]
    _module_keypoints_box("Exploit • Why", points, duration=min(6.0, duration))

def privesc_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("PrivEsc", "🔐")
    points = [
        desc or "Local enumeration helpers: linpeas/les style analysis (safe parsing).",
        "Remote checks: SSH diagnostics, kubeconfig helpers (explicit auth).",
        "Prioritized hardening suggestions."
    ]
    _module_keypoints_box("PrivEsc • Why", points, duration=min(6.0, duration))

def ad_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("ActiveDirectory", "🗂️")
    points = [
        desc or "Domain discovery, LDAP telemetry, Kerberos notes, GPO inspection (safe).",
        "Provide mapping & defensive suggestions for AD hardening.",
        "No brute-force or unauthorized attacks."
    ]
    _module_keypoints_box("ActiveDirectory • Why", points, duration=min(6.0, duration))

def forensics_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("Forensics", "🧾")
    points = [
        desc or "Artifact collection guidance, hashing, timeline generation.",
        "IOC scanning (hashes/domains) using safe APIs & local analysis.",
        "Evidence packaging for triage & reporting."
    ]
    _module_keypoints_box("Forensics • Why", points, duration=min(6.0, duration))

def threat_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("ThreatIntel", "🔎")
    points = [
        desc or "IOC enrichment, domain/IP reputation, malware hash intelligence.",
        "Triage suspicious domains & priority scoring.",
        "Integration hooks for VirusTotal or other TI (API key optional)."
    ]
    _module_keypoints_box("Threat • Why", points, duration=min(6.0, duration))

def container_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("ContainerSec", "📦")
    points = [
        desc or "Docker & Kubernetes audit checklist: RBAC, mounts, capabilities.",
        "Image scanning (Trivy-style) metadata & CIS hints (read-only).",
        "Recommendations for least-privilege policies."
    ]
    _module_keypoints_box("Container • Why", points, duration=min(6.0, duration))

def websec_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("WebSec", "🌐")
    points = [
        desc or "Crawling & fingerprinting, parameter discovery, WAF detection (passive).",
        "Safe payload guidance for testing by authorized operators.",
        "Automated report generation for findings."
    ]
    _module_keypoints_box("WebSec • Why", points, duration=min(6.0, duration))

def wifi_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("WiFi", "📡")
    points = [
        desc or "PCAP analysis guidance, rogue AP detection heuristics.",
        "Interface enumeration & monitoring tips (read-only).",
        "Safe best-practices for wireless triage."
    ]
    _module_keypoints_box("WiFi • Why", points, duration=min(6.0, duration))

def redteam_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("RedTeam (Planner)", "🎯")
    points = [
        desc or "Payload templates (display only), operational planning, pathway visualization.",
        "Lateral movement mapping (analysis-only).",
        "No automated offensive execution."
    ]
    _module_keypoints_box("RedTeam • Why", points, duration=min(6.0, duration))

def blueteam_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("BlueTeam", "🛡️")
    points = [
        desc or "Baseline creation, YARA scanning, process anomaly checks.",
        "Log monitoring guidance and alerting tips.",
        "File integrity & IOC detection workflows."
    ]
    _module_keypoints_box("BlueTeam • Why", points, duration=min(6.0, duration))

def ai_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("AI Suite", "🤖")
    points = [
        desc or "AI-driven OSINT enrichment, classification, correlation & prediction.",
        "Safe models: heuristics + deterministic engines for explainability.",
        "Report assembly & export for analysts."
    ]
    _module_keypoints_box("AI • Why", points, duration=min(6.0, duration))

def cloudsec_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("CloudSec", "☁️")
    points = [
        desc or "Multi-cloud inventory audit, public bucket checks, IAM misconfig hints.",
        "CIS checks and prioritized remediation suggestions.",
        "No credential brute force; safe audit only."
    ]
    _module_keypoints_box("CloudSec • Why", points, duration=min(6.0, duration))

def darknet_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("Darknet Intelligence", "🕳️")
    points = [
        desc or "Passive darknet indicators lookup (read-only).",
        "Breach mention triage & linkage to public signals.",
        "No scraping of illegal marketplaces."
    ]
    _module_keypoints_box("Darknet • Why", points, duration=min(6.0, duration))

def iotsec_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("IoT Sec", "📶")
    points = [
        desc or "Device fingerprinting guidance, UPnP/MDNS enumeration hints (passive).",
        "Firmware & default-credential checks (advisory).",
        "Secure network segmentation suggestions."
    ]
    _module_keypoints_box("IoT • Why", points, duration=min(6.0, duration))

def mobilesec_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("MobileSec", "📱")
    points = [
        desc or "APK/IPA static metadata: manifest, permissions, certificates.",
        "API surface mapping & privacy-sensitive endpoints detection.",
        "Secure coding & hardening suggestions for mobile teams."
    ]
    _module_keypoints_box("Mobile • Why", points, duration=min(6.0, duration))

def apisec_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("API Sec", "🔗")
    points = [
        desc or "Endpoint discovery, auth flow checks, rate-limit guidance.",
        "Schema extraction & fuzzing guidance (authorized only).",
        "Reportable findings & remediation steps."
    ]
    _module_keypoints_box("API • Why", points, duration=min(6.0, duration))

def supplychain_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("SupplyChainSec", "🔗")
    points = [
        desc or "SBOM inspection, dependency risk scoring, repo hygiene checks.",
        "Detect suspicious package names & version inconsistencies.",
        "Guidance for dependency lockdown and patching."
    ]
    _module_keypoints_box("SupplyChain • Why", points, duration=min(6.0, duration))

def malwarenet_animation(duration: float = 10.0, desc: Optional[str] = None):
    _module_generic_banner("MalwareLab", "🧬")
    points = [
        desc or "Static analysis guidance: strings, PE metadata, YARA hints.",
        "Sandboxing workflow (do not run untrusted binaries in this tool).",
        "Hash IOC lookup & behavior triage (PASSIVE only)."
    ]
    _module_keypoints_box("Malware • Why", points, duration=min(6.0, duration))

# ---------- Module showcase runner ----------
def run_module_showcase(modules: Dict[str, str], per_module_duration: float = 2.5):
    """
    Iterate modules and call short animation (fast reveal). Modules is a dict name->desc.
    per_module_duration can be increased for longer dives (e.g. 10)
    """
    for name, desc in modules.items():
        console.clear()
        # call the appropriate function if exists
        fn_name = f"{name.lower()}_animation"
        fn: Optional[Callable] = globals().get(fn_name)
        if callable(fn):
            try:
                fn(duration=per_module_duration, desc=desc)
            except Exception:
                # fallback generic show
                _module_generic_banner(name)
                _module_keypoints_box(name, [desc], duration=min(3.0, per_module_duration))
        else:
            # generic fallback
            _module_generic_banner(name)
            _module_keypoints_box(name, [desc], duration=min(3.0, per_module_duration))
        time.sleep(0.35)

# ---------- Master orchestration: 4-stage intro ----------
def run_advanced_intro(total_time: float = 15.0):
    """
    Composite intro split into 4 stages. Default total_time tuned to ~15s.
    You can pass total_time to scale sub-stages proportionally if needed.
    """
    # proportional timings
    t1 = total_time * (4 / 15)   # ~4s
    t2 = total_time * (3 / 15)   # ~3s
    t3 = total_time * (4 / 15)   # ~4s
    t4 = total_time * (4 / 15)   # ~4s

    # modules list for reveal (short descriptions)
    modules = {
        "recon": "Passive footprinting & OSINT — whois, DNS, subdomains.",
        "scan": "Port + service scanning & surface mapping (authorized).",
        "exploit": "Intelligence-only CVE mapping, no execution.",
        "privesc": "Local enumeration guidance + remediations.",
        "activeDirectory": "AD discovery, LDAP insights, Kerberos notes.",
        "forensic": "Artifact collection, hashing, timelines.",
        "threat": "IOC & reputation triage (VT optional).",
        "container": "K8s/Docker audit flags & RBAC hints.",
        "websec": "Crawl, params, WAF detection (passive).",
        "wifi": "PCAP hints, rogue AP detection tips.",
        "redteam": "Planning & payload templates (display only).",
        "blueteam": "Defensive checks & YARA scanning hints.",
        "ai": "AI suite: classify, correlate, predict, report.",
        "cloud": "Cloud inventory, public buckets, IAM hints.",
        "darknet": "Passive darknet intel & leakage triage.",
        "iot": "Device fingerprinting & segmentation suggestions.",
        "mobile": "APK/IPA metadata & API surface discovery.",
        "api": "Endpoint map, auth flow & schema guidance.",
        "supplychain": "SBOM & dependency risk checks.",
        "malware": "Static analysis guidance & passive IOCs."
    }

    try:
        console.clear()
        _stage1_dark_boot(t1)
    except Exception as e:
        console.print(f"[red]Stage1 error: {e}[/red]")

    try:
        _stage2_network_grid(t2)
    except Exception as e:
        console.print(f"[red]Stage2 error: {e}[/red]")

    try:
        _stage3_cyber_globe(t3)
    except Exception as e:
        console.print(f"[red]Stage3 error: {e}[/red]")

    try:
        _stage4_menu_reveal(modules, t4)
    except Exception as e:
        console.print(f"[red]Stage4 error: {e}[/red]")

    # final small hold
    time.sleep(0.6)
    console.clear()
    console.print(Panel.fit(Text("SYSTEM ONLINE — CYBERCLI READY", style="bold green"), border_style="green"))
    time.sleep(0.9)



# #-----------------------------
# ## Forth Phase



# # cybercli/plugins/intro_animation.py
# # REAL HACKING STYLE — NO SOUND, NO LOADING, NO CRINGE.
# # Clean, dark, military-grade cyber aesthetic.

# import random
# import shutil
# import time
# from time import sleep
# from rich.console import Console
# from rich.text import Text
# from rich.panel import Panel
# from rich.live import Live

# console = Console()

# # -------------------------------------------------------------
# # UTILS
# # -------------------------------------------------------------
# def clear():
#     try:
#         console.clear()
#     except:
#         print("\n" * 6)

# def hdr(msg, color="cyan"):
#     console.print(
#         Panel.fit(Text(msg, style=f"bold {color}", justify="center"),
#         border_style=color)
#     )
#     sleep(0.35)

# # -------------------------------------------------------------
# # EFFECT 1 — MATRIX RAIN (Sharper + More Tactical)
# # -------------------------------------------------------------
# def matrix_rain(duration=2.4):
#     charset = "01▮▯"
#     width = min(120, shutil.get_terminal_size().columns)
#     end = time.time() + duration
    
#     while time.time() < end:
#         # jagged bursts instead of full lines
#         clusters = [
#             "".join(random.choice(charset) for _ in range(random.randint(4, width)))
#         ]
#         for seq in clusters:
#             console.print(Text(seq, style="green"))
#         sleep(0.02)

# # -------------------------------------------------------------
# # EFFECT 2 — NOISE TUNNEL (Ghost Packets)
# # -------------------------------------------------------------
# def ghost_tunnel(duration=3.0):
#     width = min(110, shutil.get_terminal_size().columns)
#     chars = ["░", "▒", "▓"]
    
#     end = time.time() + duration
#     while time.time() < end:
#         core = random.randint(width // 4, width // 2)
#         left = "".join(random.choice(chars) for _ in range(core))
#         right = "".join(random.choice(chars) for _ in range(core))
#         console.print(Text(left + " " * 6 + right, style="bold cyan"))
#         sleep(0.028)

# # -------------------------------------------------------------
# # EFFECT 3 — PACKET GRID (Realistic Network Mesh)
# # -------------------------------------------------------------
# def packet_mesh(duration=4.0):
#     width = min(100, shutil.get_terminal_size().columns)
#     end = time.time() + duration
#     nodes = ["●", "○", "◉", "◎"]

#     with Live(refresh_per_second=25, transient=True) as live:
#         while time.time() < end:
#             row = []
#             hop_count = max(4, width // 12)

#             for _ in range(hop_count):
#                 n1 = random.choice(nodes)
#                 n2 = random.choice(nodes)
#                 hops = "─" * random.randint(1, 3)
#                 row.append(f"{n1}{hops}{n2}")

#             live.update(
#                 Panel(Text("   ".join(row), style="magenta"), border_style="magenta")
#             )
#             sleep(0.04)

# # -------------------------------------------------------------
# # EFFECT 4 — CYBER GLOBE (Wireframe Rotation, Clean)
# # -------------------------------------------------------------
# def wire_globe(duration=3.4):
#     frames = ["◐", "◓", "◑", "◒"]
#     end = time.time() + duration
#     i = 0

#     with Live(refresh_per_second=10, transient=True) as live:
#         while time.time() < end:
#             live.update(
#                 Panel(
#                     Text(
#                         f"{frames[i % 4]}  GLOBAL THREAT MAP SYNC…",
#                         style="bold cyan"
#                     ),
#                     border_style="cyan"
#                 )
#             )
#             i += 1
#             sleep(0.12)

# # -------------------------------------------------------------
# # MODULE DESCRIPTIONS (Ultra Clean, Tactical)
# # -------------------------------------------------------------
# MODULES = {
#     "Recon": "Surface scan • DNS • WHOIS • Subdomain footprinting",
#     "Scan": "Port sweep • Fingerprints • Service metadata",
#     "Exploit": "Weak points • CVE-matching • Config-level exposures",
#     "PrivEsc": "User perms • Capability abuse • Local misconfigs",
#     "ActiveDirectory": "Domain trust • Kerberos surface • LDAP signals",
#     "WebSec": "Input vectors • Auth flows • Broken controls",
#     "Container": "Image layers • Registry leaks • Secrets exposure",
#     "Threat": "IOC patterns • Intel correlation • Actor fingerprints",
#     "Forensics": "Timeline • Artifact correlation • Host signals",
#     "WiFi": "Wireless surface • Device mapping",
#     "BlueTeam": "Defensive posture • Monitoring surfaces",
#     "RedTeam": "Adversary simulation • Attack paths",
#     "API Security": "Endpoint permissions • Token misuse • Data flows",
#     "MobileSec": "APK analysis • Permissions • Traffic capture",
#     "IOTSec": "Endpoints • Firmware • Weak auth traces",
#     "Darknet": "Leak sources • Hidden indices • Actor trails",
#     "SupplyChain": "SBOM • Dependency stack • Package integrity",
#     "CloudSec": "IAM roles • Buckets • Exposure surface",
# }

# AI_SUBMODULES = {
#     "AI Recon": "Noise reduction • Pattern extraction",
#     "AI OSINT": "Persona linking • Digital trails",
#     "AI Exploit": "Weakness prediction • Similarity scoring",
#     "AI Defense": "Rapid response • Hardening suggestions",
#     "AI Predict": "Attack path inference • Early indicators",
#     "AI Correlate": "Multi-source fusion • Behavior clustering",
#     "AI Classifier": "Risk tagging • Context modeling",
#     "AI Report": "Readable summaries • Operator-friendly views"
# }

# def reveal_modules():
#     sleep(0.2)
#     for name, desc in MODULES.items():
#         console.print(
#             Panel.fit(
#                 Text(f"{name}\n[white]{desc}", style="bold green", justify="center"),
#                 border_style="green"
#             )
#         )
#         sleep(0.42)

# def reveal_ai():
#     hdr("AI MODULES — INTERNAL LAYERS", "magenta")
#     for name, desc in AI_SUBMODULES.items():
#         console.print(
#             Panel.fit(
#                 Text(f"{name}\n[white]{desc}", style="bold cyan", justify="center"),
#                 border_style="cyan"
#             )
#         )
#         sleep(0.38)

# # -------------------------------------------------------------
# # ENTRYPOINT — FINAL 45–50 SEC MASTER INTRO
# # -------------------------------------------------------------
# def run_advanced_intro():

#     clear()
#     hdr("CYBERCLI — NEURAL OPERATIONS ENGINE", "cyan")

#     # Stage 1 — Pure Hacking Vibe
#     matrix_rain(2.8)
#     ghost_tunnel(3.2)

#     # Stage 2 — Network Analysis Mesh
#     hdr("NETWORK MESH ACTIVATED", "magenta")
#     packet_mesh(4.0)

#     # Stage 3 — Global Threat Visualization
#     hdr("GLOBAL THREAT INTELLIGENCE SYNC", "yellow")
#     wire_globe(3.4)

#     # Stage 4 — Module Reveal
#     hdr("INITIALIZING MODULE INTELLIGENCE", "green")
#     reveal_modules()

#     # AI subsystem
#     reveal_ai()

#     # Final Banner
#     console.print(
#         Panel.fit(
#             Text("SYSTEM READY — Begin Operations", style="bold cyan", justify="center"),
#             border_style="cyan",
#         )
#     )
#     sleep(1.1)


