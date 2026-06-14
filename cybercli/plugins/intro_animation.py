# # ## First Intro-Phase

# # # cybercli/plugins/intro_animation.py
# # """
# # Ultimate hybrid cinematic intro (emoji enabled) — safe, rich-based, no markup errors.
# # """

# # import random
# # import shutil
# # import time
# # from time import sleep
# # from typing import List

# # from rich.console import Console
# # from rich.panel import Panel
# # from rich.text import Text
# # from rich.live import Live

# # console = Console()

# # # timings
# # TIMING = {
# #     "globe_frames": 18,
# #     "globe_delay": 0.12,
# #     "tunnel_lines": 18,
# #     "tunnel_delay": 0.03,
# #     "matrix_frames": 60,
# #     "matrix_delay": 0.02,
# #     "loading_delay": 1.6,
# #     "decrypt_steps": 12,
# #     "ai_logs": 4,
# #     "module_pause": 0.85,
# #     "network_frames": 18,
# #     "network_delay": 0.06,
# # }

# # # -----------------------------------------------------
# # # FIXED: Added PHASE() function
# # # -----------------------------------------------------
# # def phase(label: str, color: str = "cyan"):
# #     console.print(
# #         Panel.fit(
# #             Text(f"🚀 {label}", style=f"bold {color}", justify="center"),
# #             border_style=color,
# #         )
# #     )
# #     time.sleep(0.4)

# # # -----------------------------------------------------
# # # Helpers
# # # -----------------------------------------------------
# # def clear():
# #     try:
# #         console.clear()
# #     except:
# #         print("\n" * 4)

# # def title_panel():
# #     console.print(
# #         Panel.fit(
# #             Text("CYBERCLI — NEXT-GEN CYBER OPS ENGINE", style="bold cyan", justify="center"),
# #             border_style="cyan",
# #         )
# #     )

# # def safe_glitch_line(s: str):
# #     t = Text()
# #     for ch in s:
# #         if ch != " " and random.random() < 0.08:
# #             t.append(ch, style=random.choice(["magenta", "cyan", "green"]))
# #         else:
# #             t.append(ch)
# #     console.print(t)

# # # -----------------------------------------------------
# # # Phase 1
# # # -----------------------------------------------------
# # def rotating_globe():
# #     frames = ["🌐", "◐", "◓", "◑", "◒"]
# #     with Live(refresh_per_second=8, transient=True) as live:
# #         for i in range(TIMING["globe_frames"]):
# #             frame = frames[i % len(frames)]
# #             live.update(
# #                 Panel(
# #                     Text(f"{frame} Rotating Cyber Globe • • •", style="bold magenta"),
# #                     border_style=random.choice(["magenta", "cyan", "green"]),
# #                 )
# #             )
# #             time.sleep(TIMING["globe_delay"])

# # def neon_ascii_tunnel():
# #     width = min(120, shutil.get_terminal_size().columns)
# #     chars = ["█", "▓", "▒", "░"]
# #     for _ in range(TIMING["tunnel_lines"]):
# #         line = "".join(random.choice(chars) for _ in range(width))
# #         console.print(Text(line, style="bold cyan"))
# #         time.sleep(TIMING["tunnel_delay"])

# # def matrix_rain():
# #     width = min(120, shutil.get_terminal_size().columns)
# #     charset = "01▮▯"
# #     for _ in range(TIMING["matrix_frames"]):
# #         row = "".join(random.choice(charset) for _ in range(width))
# #         console.print(Text(row, style="green"))
# #         time.sleep(TIMING["matrix_delay"])

# # # -----------------------------------------------------
# # # Phase 2
# # # -----------------------------------------------------
# # def loading_bar(label, duration):
# #     total = 28
# #     with Live(refresh_per_second=30, transient=True) as live:
# #         for i in range(total + 1):
# #             pct = int((i / total) * 100)
# #             bar = "█" * i + "░" * (total - i)
# #             live.update(
# #                 Panel(
# #                     Text(f"{label}: [{bar}] {pct}%", style="yellow"),
# #                     border_style="yellow",
# #                 )
# #             )
# #             time.sleep(duration / total)

# # def decrypt_fx():
# #     steps = ["PROBE", "BRUTE-SEQ", "UNLOCK", "VERIFY", "INTEGRITY"]
# #     for i in range(TIMING["decrypt_steps"]):
# #         step = steps[i % len(steps)]
# #         bar = "█" * ((i * 3) % 40) + "-" * (40 - ((i * 3) % 40))
# #         console.print(
# #             Panel(
# #                 Text(f"{step} [{bar}]", style="bold magenta"),
# #                 border_style="magenta",
# #             )
# #         )
# #         time.sleep(0.22)

# # AI_LOGS = [
# #     "AI: Sensors nominal.",
# #     "AI: Correlation model online.",
# #     "AI: Ingesting IOC feeds.",
# #     "AI: Preparing mission summary...",
# # ]
# # def ai_voice_logs():
# #     for line in AI_LOGS:
# #         console.print(Text(line, style="cyan"))
# #         time.sleep(0.9)

# # # -----------------------------------------------------
# # # Phase 3
# # # -----------------------------------------------------
# # MODULES = {
# #     "Recon": ["whois --target <host>", "dnsenum --domain <domain>"],
# #     "Scan": ["nmap top-ports", "nikto --host <site>"],
# #     "Exploit": ["exploit search <cve>", "exploit run --target <ip>"],
# #     "PrivEsc": ["linpeas.sh", "pspy64"],
# #     "WebSec": ["ffuf -u https://site/FUZZ", "sqlmap -u <url> --batch"],
# #     "ActiveDirectory": ["kerberoast <users>", "ldapenum --dc <ip>"],
# # }

# # def modules_overview():
# #     console.print(Panel.fit(Text("MODULES — OVERVIEW", style="bold purple"), border_style="purple"))
# #     for mod, cmds in MODULES.items():
# #         console.print(Text(f"{mod:<15} — {cmds[0]}", style="cyan"))
# #         time.sleep(0.08)
# #     time.sleep(0.8)

# # def module_deep_showcase():
# #     for mod, cmds in MODULES.items():
# #         console.print(
# #             Panel.fit(Text(mod, style="bold green"), subtitle="Key Commands", border_style="green")
# #         )
# #         for c in cmds:
# #             console.print(Text(f" • {c}", style="white"))
# #             time.sleep(0.08)
# #         time.sleep(TIMING["module_pause"])

# # # -----------------------------------------------------
# # # Phase 4
# # # -----------------------------------------------------
# # def network_graph():
# #     nodes = ["●", "○", "◎", "◉", "◆"]
# #     with Live(refresh_per_second=12, transient=True) as live:
# #         for _ in range(TIMING["network_frames"]):
# #             width = min(120, shutil.get_terminal_size().columns)
# #             parts = []
# #             for _ in range(max(2, width // 8)):
# #                 parts.append(f"{random.choice(nodes)}──{random.choice(nodes)}")
# #             live.update(
# #                 Panel(
# #                     Text("   ".join(parts), style="bold magenta"),
# #                     border_style="magenta",
# #                 )
# #             )
# #             time.sleep(TIMING["network_delay"])

# # def final_banner():
# #     console.print(
# #         Panel.fit(
# #             Text("✅ SYSTEM ONLINE — CYBERCLI READY", style="bold green"),
# #             border_style="green",
# #         )
# #     )
# #     time.sleep(0.9)

# # # -----------------------------------------------------
# # # MASTER ENTRYPOINT (NOW FIXED)
# # # -----------------------------------------------------
# # def run_advanced_intro():
# #     clear()
# #     title_panel()

# #     phase("PHASE 1 — BOOT", "magenta")
# #     rotating_globe()
# #     neon_ascii_tunnel()
# #     matrix_rain()

# #     phase("PHASE 2 — INITIALIZING", "cyan")
# #     loading_bar("Initializing Core Engine", TIMING["loading_delay"])
# #     loading_bar("Initializing Modules Loader", TIMING["loading_delay"])
# #     loading_bar("Initializing AI Layer", TIMING["loading_delay"])
# #     decrypt_fx()
# #     ai_voice_logs()

# #     phase("PHASE 3 — MODULES", "yellow")
# #     modules_overview()
# #     module_deep_showcase()

# #     phase("PHASE 4 — NETWORK GRAPH", "magenta")
# #     network_graph()
# #     final_banner()













# ##-------------------------------------------/\---------------------------------------------------##
# #Second-Phase

# # # cybercli/plugins/intro_animation.py
# # from time import sleep
# # from rich.console import Console
# # from rich.panel import Panel
# # from rich.text import Text
# # from rich.live import Live
# # from rich import box

# # console = Console()

# # def slow_print(text, delay=0.03):
# #     for char in text:
# #         console.print(char, end="", style="cyan")
# #         sleep(delay)
# #     console.print()

# # def neon_tunnel():
# #     frames = [
# #         "[magenta]>>>>>>>>>>[/magenta]",
# #         "[blue]>>>>>>>>>[/blue]",
# #         "[cyan]>>>>>>[/cyan]",
# #         "[green]>>>[/green]",
# #         "[yellow]>[/yellow]",
# #         "[green]>>>[/green]",
# #         "[cyan]>>>>>>[/cyan]",
# #         "[blue]>>>>>>>>>[/blue]",
# #         "[magenta]>>>>>>>>>>[/magenta]",
# #     ]
# #     with Live(console=console, refresh_per_second=20):
# #         for _ in range(12):
# #             for f in frames:
# #                 console.print(Panel(f, style="bold", border_style="magenta"))
# #                 sleep(0.05)

# # def matrix_rain():
# #     chars = "01"
# #     with Live(console=console, refresh_per_second=60):
# #         for _ in range(30):
# #             line = "".join(chars for _ in range(60))
# #             console.print(f"[green]{line}[/green]")
# #             sleep(0.04)

# # def loading_bar(text):
# #     bar = ""
# #     console.print(f"[cyan]{text}[/cyan]")
# #     for _ in range(30):
# #         bar += "█"
# #         console.print(f"[magenta]{bar}[/magenta]", end="\r")
# #         sleep(0.04)
# #     console.print()

# # def network_graph():
# #     graph = """
# # [cyan]
# #       ●───●────●
# #      ╱     ╲
# #   ●──●     ●──●──●
# #      ╲     ╱
# #       ●───●────●
# # [/cyan]
# # """
# #     console.print(Panel(graph, title="[bold yellow]Network Graph Link Map[/bold yellow]", border_style="cyan"))
# #     sleep(1.2)

# # def rotating_globe():
# #     frames = [
# #         "🌍",
# #         "🌎",
# #         "🌏"
# #     ]
# #     for _ in range(12):
# #         for f in frames:
# #             console.print(f"[bold cyan]{f}[/bold cyan]", end="\r")
# #             sleep(0.15)

# # def run_advanced_intro():
# #     console.clear()

# #     # PHASE 1 — WELCOME
# #     console.print(Panel("🔥 [bold cyan]CYBERCLI — NEXT-GEN OPS ENGINE[/bold cyan] 🔥",
# #                         border_style="magenta", box=box.DOUBLE))
# #     sleep(1)

# #     rotating_globe()
# #     neon_tunnel()

# #     slow_print("Initializing modules…")
# #     loading_bar("Loading Core Engine")
# #     loading_bar("Loading Cyber Models")
# #     matrix_rain()

# #     # PHASE 2 — MODULE LIST
# #     module_list = """
# # [cyan]
# # 🔹 recon       — Information gathering & OSINT
# # 🔹 scan        — Deep scanning & service mapping
# # 🔹 exploit     — Payload testing framework
# # 🔹 privesc     — Local privilege escalation tools
# # 🔹 websec      — Web security suite
# # 🔹 wifi        — Wireless attacks & sniffing
# # 🔹 ad          — Active Directory toolkit
# # 🔹 redteam     — Adversary simulation modules
# # 🔹 blueteam    — Defense & incident response
# # [/cyan]
# # """
# #     console.print(Panel(module_list, title="[bold green]MODULES LOADED[/bold green]",
# #                         border_style="green"))
# #     sleep(1)

# #     # PHASE 3 — COMMAND DEFINITION
# #     command_guide = """
# # [yellow]
# # Example Commands:
# # • recon subdomains --target google.com
# # • scan ports --ip 192.168.1.1
# # • exploit run --payload reverse_shell
# # • privesc auto-check
# # [/yellow]
# # """
# #     console.print(Panel(command_guide, title="[cyan]Command Usage[/cyan]", border_style="yellow"))
# #     sleep(1)

# #     network_graph()

# #     # FINAL LAUNCH
# #     console.print(Panel("[bold green]SYSTEM READY — ENTERING CYBERCLI[/bold green]",
# #                         border_style="green", box=box.HEAVY))
# #     sleep(1)




# ### Third phase

# # cybercli/plugins/intro_animation.py
# """
# Cinematic intro + per-module animated explainers for CyberCLI.

# PHASES:
#   Stage 1 (Dark Boot)    ~4s  : matrix rain, neon pulse, BIOS-like text
#   Stage 2 (Network Grid) ~3s  : ascii network points + animated edges
#   Stage 3 (Cyber Globe)  ~4s  : rotating globe frames + spark traces
#   Stage 4 (Menu Reveal)  ~4s  : smooth menu fade-in with 1-line descriptions

# Exports:
#   run_advanced_intro(total_time=15)  # default tuned to ~15s
#   run_module_showcase(modules, per_module_duration=2.5)
#   And individual per-module helpers like recon_animation(duration=10, desc=...)
# """

# from __future__ import annotations
# import time
# import random
# import shutil
# from typing import List, Dict, Callable, Optional

# from rich.console import Console
# from rich.panel import Panel
# from rich.text import Text
# from rich.live import Live
# from rich.table import Table
# from rich.align import Align

# console = Console()

# # ---------- Helpers ----------
# def _term_width() -> int:
#     try:
#         return shutil.get_terminal_size().columns
#     except Exception:
#         return 80

# def _center_panel(content: str, title: str = "", style: str = "cyan"):
#     txt = Text(content)
#     return Panel.fit(txt, title=title, border_style=style)

# def _safe_print(text: str, style: Optional[str] = None):
#     if style:
#         console.print(Text(text, style=style))
#     else:
#         console.print(text)

# def _spinner_frames(count=8):
#     # subtle spinner frames
#     return ["◐", "◓", "◑", "◒"] * max(1, count // 4)

# # ---------- Stage 1: Dark Boot Sequence ----------
# def _stage1_dark_boot(duration: float = 4.0):
#     """
#     Matrix rain + neon ASCII tunnel + BIOS-like lines.
#     duration ~4s by default
#     """
#     start = time.time()
#     width = min(120, _term_width())
#     matrix_chars = "01▮▯▒▓█"
#     neon_chars = ["█", "▓", "▒", "░"]
#     bios_lines = [
#         "Initializing Cyber Engine...",
#         "Booting secure modules.",
#         "Verifying integrity.",
#         "AI correlation services warming up."
#     ]

#     # matrix + neon alternating frames
#     with Live(refresh_per_second=18, transient=True) as live:
#         idx = 0
#         while time.time() - start < duration:
#             lines = []
#             # build 6 rows of matrix-like noise (small)
#             for _ in range(6):
#                 row = "".join(random.choice(matrix_chars) for _ in range(min(48, width // 2)))
#                 lines.append(row)
#             # neon tunnel single-line pulse
#             tunnel = "".join(random.choice(neon_chars) for _ in range(min(60, width)))
#             # BIOS style line rotates through list
#             bios = bios_lines[idx % len(bios_lines)]
#             frame = "\n".join(lines) + "\n\n" + tunnel + "\n\n" + f"[{bios}]"
#             live.update(Panel(frame, title="DARK BOOT", border_style="bright_magenta"))
#             idx += 1
#             time.sleep(0.08)

#     # small beep-ish ASCII suffix (no sound)
#     for s in ("[  beep  ]", "[ beep beep ]", "[  beep  ]"):
#         _safe_print(s, style="yellow")
#         time.sleep(0.14)

# # ---------- Stage 2: Network Grid ----------
# def _stage2_network_grid(duration: float = 3.0):
#     """
#     Graphviz-style points + animated edges
#     """
#     width = min(120, _term_width())
#     nodes = ["●", "○", "◎", "◉", "◆", "◇"]
#     count = max(4, min(12, width // 10))
#     node_positions = [random.randint(0, width - 6) for _ in range(count)]
#     start = time.time()
#     with Live(refresh_per_second=12, transient=True) as live:
#         while time.time() - start < duration:
#             # create rows with nodes and pseudo-edges
#             rows = []
#             for r in range(6):
#                 row = [" "] * min(width, 80)
#                 for i, pos in enumerate(node_positions):
#                     ch = random.choice(nodes)
#                     p = max(0, min(len(row) - 1, (pos + (i * (r % 3)) - r) % len(row)))
#                     row[p] = ch
#                 rows.append("".join(row))
#             # overlay some animated edges (random dashes)
#             edges = []
#             for _ in range(max(1, count // 2)):
#                 a = random.randint(0, len(rows) - 1)
#                 b = random.randint(0, len(rows) - 1)
#                 edges.append(f"{a}↔{b}")
#             body = "\n".join(rows) + "\n\n" + "Edges: " + ", ".join(edges)
#             live.update(Panel(body, title="MAPPING GLOBAL THREAT GRID", border_style="green"))
#             time.sleep(0.12)

# # ---------- Stage 3: Cyber Globe ----------
# def _stage3_cyber_globe(duration: float = 4.0):
#     """
#     Rotating wireframe globe simplified frames. Spark traces animate across.
#     """
#     width = min(120, _term_width())
#     frames = [
#         "   .--.      _    ",
#         "  /    \\   _/ \\   ",
#         " |  ●   | / o  \\  ",
#         "  \\     / \\_ _/   ",
#         "   `--'            "
#     ]
#     sparks = ["⋆", "✦", "✶", "✺"]
#     start = time.time()
#     idx = 0
#     with Live(refresh_per_second=8, transient=True) as live:
#         while time.time() - start < duration:
#             # rotate content by offsetting frames order
#             rot = frames[idx % len(frames):] + frames[: idx % len(frames)]
#             glow = "\n".join(rot)
#             # add spark trace line
#             trace = " ".join(random.choice(sparks) if random.random() < 0.12 else " " for _ in range(min(40, width // 2)))
#             body = glow + "\n\n" + trace + "\n\nLoading active modules..."
#             live.update(Panel(body, title="GLOBAL SCAN • ROTATING GLOBE", border_style="bright_blue"))
#             idx += 1
#             time.sleep(0.16)

# # ---------- Stage 4: Command Menu Reveal ----------
# def _stage4_menu_reveal(modules: Dict[str, str], duration: float = 4.0):
#     """
#     Smooth fade-in like reveal of menu list with 1-line purposes.
#     modules: ordered dict-like { "recon": "desc", ... }
#     """
#     keys = list(modules.keys())
#     start = time.time()
#     per = max(0.08, duration / max(1, len(keys)))
#     # progressively reveal lines
#     revealed = 0
#     while time.time() - start < duration and revealed < len(keys):
#         revealed += 1
#         console.clear()
#         header = Panel(Text("CYBERCLI — MODULES LOADED", style="bold cyan"), border_style="cyan")
#         console.print(header)
#         for i in range(revealed):
#             k = keys[i]
#             line = Text.assemble((f"[{i+1}] ", "bright_magenta"), (k.ljust(14), "bold green"), (" — ", "white"), (modules[k], "dim"))
#             console.print(line)
#         time.sleep(per)
#     # final static render
#     console.print("\n[bold green]Access Granted — Type --help to list commands[/bold green]")

# # ---------- Module animation helpers (per-module short cinematic) ----------
# def _module_generic_banner(name: str, emoji: str = "🔹"):
#     title = f"{emoji} {name.upper()} MODULE"
#     console.print(Panel(Text(title, style="bold magenta"), border_style="magenta"))

# def _module_keypoints_box(title: str, points: List[str], duration: float = 3.0):
#     # show points one by one with a subtle ascii effect
#     start = time.time()
#     per = max(0.15, duration / max(1, len(points)))
#     for p in points:
#         console.print(Panel(Text(p, style="white"), title=title, border_style="cyan"))
#         time.sleep(per)

# # Individual module animations — they call the generic banner + points
# def recon_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("Recon", "🛰️")
#     points = [
#         desc or "Passive footprinting: DNS, WHOIS, subdomains, certificates, screenshots.",
#         "Collect OSINT: social, paste, public repo traces.",
#         "Map attack surface: ports, services, exposed endpoints."
#     ]
#     _module_keypoints_box("Recon • Why", points, duration=min(6.0, duration))

# def scan_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("Scan", "🔎")
#     points = [
#         desc or "Deep scanning: Nmap profiles, service detection, safe vuln checks.",
#         "Endpoint surface mapping, sitemap & JS discovery.",
#         "Produce prioritized findings for triage."
#     ]
#     _module_keypoints_box("Scan • Why", points, duration=min(6.0, duration))

# def exploit_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("Exploit (SAFE)", "💥")
#     points = [
#         desc or "Intelligence-only exploit findings: CVE lookups, exploit references (no execution).",
#         "Contextual mapping: impacted versions + remediation hints.",
#         "Safe simulation: guidance-only payload templates."
#     ]
#     _module_keypoints_box("Exploit • Why", points, duration=min(6.0, duration))

# def privesc_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("PrivEsc", "🔐")
#     points = [
#         desc or "Local enumeration helpers: linpeas/les style analysis (safe parsing).",
#         "Remote checks: SSH diagnostics, kubeconfig helpers (explicit auth).",
#         "Prioritized hardening suggestions."
#     ]
#     _module_keypoints_box("PrivEsc • Why", points, duration=min(6.0, duration))

# def ad_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("ActiveDirectory", "🗂️")
#     points = [
#         desc or "Domain discovery, LDAP telemetry, Kerberos notes, GPO inspection (safe).",
#         "Provide mapping & defensive suggestions for AD hardening.",
#         "No brute-force or unauthorized attacks."
#     ]
#     _module_keypoints_box("ActiveDirectory • Why", points, duration=min(6.0, duration))

# def forensics_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("Forensics", "🧾")
#     points = [
#         desc or "Artifact collection guidance, hashing, timeline generation.",
#         "IOC scanning (hashes/domains) using safe APIs & local analysis.",
#         "Evidence packaging for triage & reporting."
#     ]
#     _module_keypoints_box("Forensics • Why", points, duration=min(6.0, duration))

# def threat_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("ThreatIntel", "🔎")
#     points = [
#         desc or "IOC enrichment, domain/IP reputation, malware hash intelligence.",
#         "Triage suspicious domains & priority scoring.",
#         "Integration hooks for VirusTotal or other TI (API key optional)."
#     ]
#     _module_keypoints_box("Threat • Why", points, duration=min(6.0, duration))

# def container_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("ContainerSec", "📦")
#     points = [
#         desc or "Docker & Kubernetes audit checklist: RBAC, mounts, capabilities.",
#         "Image scanning (Trivy-style) metadata & CIS hints (read-only).",
#         "Recommendations for least-privilege policies."
#     ]
#     _module_keypoints_box("Container • Why", points, duration=min(6.0, duration))

# def websec_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("WebSec", "🌐")
#     points = [
#         desc or "Crawling & fingerprinting, parameter discovery, WAF detection (passive).",
#         "Safe payload guidance for testing by authorized operators.",
#         "Automated report generation for findings."
#     ]
#     _module_keypoints_box("WebSec • Why", points, duration=min(6.0, duration))

# def wifi_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("WiFi", "📡")
#     points = [
#         desc or "PCAP analysis guidance, rogue AP detection heuristics.",
#         "Interface enumeration & monitoring tips (read-only).",
#         "Safe best-practices for wireless triage."
#     ]
#     _module_keypoints_box("WiFi • Why", points, duration=min(6.0, duration))

# def redteam_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("RedTeam (Planner)", "🎯")
#     points = [
#         desc or "Payload templates (display only), operational planning, pathway visualization.",
#         "Lateral movement mapping (analysis-only).",
#         "No automated offensive execution."
#     ]
#     _module_keypoints_box("RedTeam • Why", points, duration=min(6.0, duration))

# def blueteam_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("BlueTeam", "🛡️")
#     points = [
#         desc or "Baseline creation, YARA scanning, process anomaly checks.",
#         "Log monitoring guidance and alerting tips.",
#         "File integrity & IOC detection workflows."
#     ]
#     _module_keypoints_box("BlueTeam • Why", points, duration=min(6.0, duration))

# def ai_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("AI Suite", "🤖")
#     points = [
#         desc or "AI-driven OSINT enrichment, classification, correlation & prediction.",
#         "Safe models: heuristics + deterministic engines for explainability.",
#         "Report assembly & export for analysts."
#     ]
#     _module_keypoints_box("AI • Why", points, duration=min(6.0, duration))

# def cloudsec_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("CloudSec", "☁️")
#     points = [
#         desc or "Multi-cloud inventory audit, public bucket checks, IAM misconfig hints.",
#         "CIS checks and prioritized remediation suggestions.",
#         "No credential brute force; safe audit only."
#     ]
#     _module_keypoints_box("CloudSec • Why", points, duration=min(6.0, duration))

# def darknet_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("Darknet Intelligence", "🕳️")
#     points = [
#         desc or "Passive darknet indicators lookup (read-only).",
#         "Breach mention triage & linkage to public signals.",
#         "No scraping of illegal marketplaces."
#     ]
#     _module_keypoints_box("Darknet • Why", points, duration=min(6.0, duration))

# def iotsec_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("IoT Sec", "📶")
#     points = [
#         desc or "Device fingerprinting guidance, UPnP/MDNS enumeration hints (passive).",
#         "Firmware & default-credential checks (advisory).",
#         "Secure network segmentation suggestions."
#     ]
#     _module_keypoints_box("IoT • Why", points, duration=min(6.0, duration))

# def mobilesec_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("MobileSec", "📱")
#     points = [
#         desc or "APK/IPA static metadata: manifest, permissions, certificates.",
#         "API surface mapping & privacy-sensitive endpoints detection.",
#         "Secure coding & hardening suggestions for mobile teams."
#     ]
#     _module_keypoints_box("Mobile • Why", points, duration=min(6.0, duration))

# def apisec_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("API Sec", "🔗")
#     points = [
#         desc or "Endpoint discovery, auth flow checks, rate-limit guidance.",
#         "Schema extraction & fuzzing guidance (authorized only).",
#         "Reportable findings & remediation steps."
#     ]
#     _module_keypoints_box("API • Why", points, duration=min(6.0, duration))

# def supplychain_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("SupplyChainSec", "🔗")
#     points = [
#         desc or "SBOM inspection, dependency risk scoring, repo hygiene checks.",
#         "Detect suspicious package names & version inconsistencies.",
#         "Guidance for dependency lockdown and patching."
#     ]
#     _module_keypoints_box("SupplyChain • Why", points, duration=min(6.0, duration))

# def malwarenet_animation(duration: float = 10.0, desc: Optional[str] = None):
#     _module_generic_banner("MalwareLab", "🧬")
#     points = [
#         desc or "Static analysis guidance: strings, PE metadata, YARA hints.",
#         "Sandboxing workflow (do not run untrusted binaries in this tool).",
#         "Hash IOC lookup & behavior triage (PASSIVE only)."
#     ]
#     _module_keypoints_box("Malware • Why", points, duration=min(6.0, duration))

# # ---------- Module showcase runner ----------
# def run_module_showcase(modules: Dict[str, str], per_module_duration: float = 2.5):
#     """
#     Iterate modules and call short animation (fast reveal). Modules is a dict name->desc.
#     per_module_duration can be increased for longer dives (e.g. 10)
#     """
#     for name, desc in modules.items():
#         console.clear()
#         # call the appropriate function if exists
#         fn_name = f"{name.lower()}_animation"
#         fn: Optional[Callable] = globals().get(fn_name)
#         if callable(fn):
#             try:
#                 fn(duration=per_module_duration, desc=desc)
#             except Exception:
#                 # fallback generic show
#                 _module_generic_banner(name)
#                 _module_keypoints_box(name, [desc], duration=min(3.0, per_module_duration))
#         else:
#             # generic fallback
#             _module_generic_banner(name)
#             _module_keypoints_box(name, [desc], duration=min(3.0, per_module_duration))
#         time.sleep(0.35)

# # ---------- Master orchestration: 4-stage intro ----------
# def run_advanced_intro(total_time: float = 15.0):
#     """
#     Composite intro split into 4 stages. Default total_time tuned to ~15s.
#     You can pass total_time to scale sub-stages proportionally if needed.
#     """
#     # proportional timings
#     t1 = total_time * (4 / 15)   # ~4s
#     t2 = total_time * (3 / 15)   # ~3s
#     t3 = total_time * (4 / 15)   # ~4s
#     t4 = total_time * (4 / 15)   # ~4s

#     # modules list for reveal (short descriptions)
#     modules = {
#         "recon": "Passive footprinting & OSINT — whois, DNS, subdomains.",
#         "scan": "Port + service scanning & surface mapping (authorized).",
#         "exploit": "Intelligence-only CVE mapping, no execution.",
#         "privesc": "Local enumeration guidance + remediations.",
#         "activeDirectory": "AD discovery, LDAP insights, Kerberos notes.",
#         "forensic": "Artifact collection, hashing, timelines.",
#         "threat": "IOC & reputation triage (VT optional).",
#         "container": "K8s/Docker audit flags & RBAC hints.",
#         "websec": "Crawl, params, WAF detection (passive).",
#         "wifi": "PCAP hints, rogue AP detection tips.",
#         "redteam": "Planning & payload templates (display only).",
#         "blueteam": "Defensive checks & YARA scanning hints.",
#         "ai": "AI suite: classify, correlate, predict, report.",
#         "cloud": "Cloud inventory, public buckets, IAM hints.",
#         "darknet": "Passive darknet intel & leakage triage.",
#         "iot": "Device fingerprinting & segmentation suggestions.",
#         "mobile": "APK/IPA metadata & API surface discovery.",
#         "api": "Endpoint map, auth flow & schema guidance.",
#         "supplychain": "SBOM & dependency risk checks.",
#         "malware": "Static analysis guidance & passive IOCs."
#     }

#     try:
#         console.clear()
#         _stage1_dark_boot(t1)
#     except Exception as e:
#         console.print(f"[red]Stage1 error: {e}[/red]")

#     try:
#         _stage2_network_grid(t2)
#     except Exception as e:
#         console.print(f"[red]Stage2 error: {e}[/red]")

#     try:
#         _stage3_cyber_globe(t3)
#     except Exception as e:
#         console.print(f"[red]Stage3 error: {e}[/red]")

#     try:
#         _stage4_menu_reveal(modules, t4)
#     except Exception as e:
#         console.print(f"[red]Stage4 error: {e}[/red]")

#     # final small hold
#     time.sleep(0.6)
#     console.clear()
#     console.print(Panel.fit(Text("SYSTEM ONLINE — CYBERCLI READY", style="bold green"), border_style="green"))
#     time.sleep(0.9)



# # #-----------------------------
# # ## Forth Phase



# # # cybercli/plugins/intro_animation.py
# # # REAL HACKING STYLE — NO SOUND, NO LOADING, NO CRINGE.
# # # Clean, dark, military-grade cyber aesthetic.

# # import random
# # import shutil
# # import time
# # from time import sleep
# # from rich.console import Console
# # from rich.text import Text
# # from rich.panel import Panel
# # from rich.live import Live

# # console = Console()

# # # -------------------------------------------------------------
# # # UTILS
# # # -------------------------------------------------------------
# # def clear():
# #     try:
# #         console.clear()
# #     except:
# #         print("\n" * 6)

# # def hdr(msg, color="cyan"):
# #     console.print(
# #         Panel.fit(Text(msg, style=f"bold {color}", justify="center"),
# #         border_style=color)
# #     )
# #     sleep(0.35)

# # # -------------------------------------------------------------
# # # EFFECT 1 — MATRIX RAIN (Sharper + More Tactical)
# # # -------------------------------------------------------------
# # def matrix_rain(duration=2.4):
# #     charset = "01▮▯"
# #     width = min(120, shutil.get_terminal_size().columns)
# #     end = time.time() + duration
    
# #     while time.time() < end:
# #         # jagged bursts instead of full lines
# #         clusters = [
# #             "".join(random.choice(charset) for _ in range(random.randint(4, width)))
# #         ]
# #         for seq in clusters:
# #             console.print(Text(seq, style="green"))
# #         sleep(0.02)

# # # -------------------------------------------------------------
# # # EFFECT 2 — NOISE TUNNEL (Ghost Packets)
# # # -------------------------------------------------------------
# # def ghost_tunnel(duration=3.0):
# #     width = min(110, shutil.get_terminal_size().columns)
# #     chars = ["░", "▒", "▓"]
    
# #     end = time.time() + duration
# #     while time.time() < end:
# #         core = random.randint(width // 4, width // 2)
# #         left = "".join(random.choice(chars) for _ in range(core))
# #         right = "".join(random.choice(chars) for _ in range(core))
# #         console.print(Text(left + " " * 6 + right, style="bold cyan"))
# #         sleep(0.028)

# # # -------------------------------------------------------------
# # # EFFECT 3 — PACKET GRID (Realistic Network Mesh)
# # # -------------------------------------------------------------
# # def packet_mesh(duration=4.0):
# #     width = min(100, shutil.get_terminal_size().columns)
# #     end = time.time() + duration
# #     nodes = ["●", "○", "◉", "◎"]

# #     with Live(refresh_per_second=25, transient=True) as live:
# #         while time.time() < end:
# #             row = []
# #             hop_count = max(4, width // 12)

# #             for _ in range(hop_count):
# #                 n1 = random.choice(nodes)
# #                 n2 = random.choice(nodes)
# #                 hops = "─" * random.randint(1, 3)
# #                 row.append(f"{n1}{hops}{n2}")

# #             live.update(
# #                 Panel(Text("   ".join(row), style="magenta"), border_style="magenta")
# #             )
# #             sleep(0.04)

# # # -------------------------------------------------------------
# # # EFFECT 4 — CYBER GLOBE (Wireframe Rotation, Clean)
# # # -------------------------------------------------------------
# # def wire_globe(duration=3.4):
# #     frames = ["◐", "◓", "◑", "◒"]
# #     end = time.time() + duration
# #     i = 0

# #     with Live(refresh_per_second=10, transient=True) as live:
# #         while time.time() < end:
# #             live.update(
# #                 Panel(
# #                     Text(
# #                         f"{frames[i % 4]}  GLOBAL THREAT MAP SYNC…",
# #                         style="bold cyan"
# #                     ),
# #                     border_style="cyan"
# #                 )
# #             )
# #             i += 1
# #             sleep(0.12)

# # # -------------------------------------------------------------
# # # MODULE DESCRIPTIONS (Ultra Clean, Tactical)
# # # -------------------------------------------------------------
# # MODULES = {
# #     "Recon": "Surface scan • DNS • WHOIS • Subdomain footprinting",
# #     "Scan": "Port sweep • Fingerprints • Service metadata",
# #     "Exploit": "Weak points • CVE-matching • Config-level exposures",
# #     "PrivEsc": "User perms • Capability abuse • Local misconfigs",
# #     "ActiveDirectory": "Domain trust • Kerberos surface • LDAP signals",
# #     "WebSec": "Input vectors • Auth flows • Broken controls",
# #     "Container": "Image layers • Registry leaks • Secrets exposure",
# #     "Threat": "IOC patterns • Intel correlation • Actor fingerprints",
# #     "Forensics": "Timeline • Artifact correlation • Host signals",
# #     "WiFi": "Wireless surface • Device mapping",
# #     "BlueTeam": "Defensive posture • Monitoring surfaces",
# #     "RedTeam": "Adversary simulation • Attack paths",
# #     "API Security": "Endpoint permissions • Token misuse • Data flows",
# #     "MobileSec": "APK analysis • Permissions • Traffic capture",
# #     "IOTSec": "Endpoints • Firmware • Weak auth traces",
# #     "Darknet": "Leak sources • Hidden indices • Actor trails",
# #     "SupplyChain": "SBOM • Dependency stack • Package integrity",
# #     "CloudSec": "IAM roles • Buckets • Exposure surface",
# # }

# # AI_SUBMODULES = {
# #     "AI Recon": "Noise reduction • Pattern extraction",
# #     "AI OSINT": "Persona linking • Digital trails",
# #     "AI Exploit": "Weakness prediction • Similarity scoring",
# #     "AI Defense": "Rapid response • Hardening suggestions",
# #     "AI Predict": "Attack path inference • Early indicators",
# #     "AI Correlate": "Multi-source fusion • Behavior clustering",
# #     "AI Classifier": "Risk tagging • Context modeling",
# #     "AI Report": "Readable summaries • Operator-friendly views"
# # }

# # def reveal_modules():
# #     sleep(0.2)
# #     for name, desc in MODULES.items():
# #         console.print(
# #             Panel.fit(
# #                 Text(f"{name}\n[white]{desc}", style="bold green", justify="center"),
# #                 border_style="green"
# #             )
# #         )
# #         sleep(0.42)

# # def reveal_ai():
# #     hdr("AI MODULES — INTERNAL LAYERS", "magenta")
# #     for name, desc in AI_SUBMODULES.items():
# #         console.print(
# #             Panel.fit(
# #                 Text(f"{name}\n[white]{desc}", style="bold cyan", justify="center"),
# #                 border_style="cyan"
# #             )
# #         )
# #         sleep(0.38)

# # # -------------------------------------------------------------
# # # ENTRYPOINT — FINAL 45–50 SEC MASTER INTRO
# # # -------------------------------------------------------------
# # def run_advanced_intro():

# #     clear()
# #     hdr("CYBERCLI — NEURAL OPERATIONS ENGINE", "cyan")

# #     # Stage 1 — Pure Hacking Vibe
# #     matrix_rain(2.8)
# #     ghost_tunnel(3.2)

# #     # Stage 2 — Network Analysis Mesh
# #     hdr("NETWORK MESH ACTIVATED", "magenta")
# #     packet_mesh(4.0)

# #     # Stage 3 — Global Threat Visualization
# #     hdr("GLOBAL THREAT INTELLIGENCE SYNC", "yellow")
# #     wire_globe(3.4)

# #     # Stage 4 — Module Reveal
# #     hdr("INITIALIZING MODULE INTELLIGENCE", "green")
# #     reveal_modules()

# #     # AI subsystem
# #     reveal_ai()

# #     # Final Banner
# #     console.print(
# #         Panel.fit(
# #             Text("SYSTEM READY — Begin Operations", style="bold cyan", justify="center"),
# #             border_style="cyan",
# #         )
# #     )
# #     sleep(1.1)


"""
cybercli/plugins/intro_animation.py

FULL BOOT SEQUENCE — Real hacking tool, cold military aesthetic.

STAGE 0   BIOS POST              Hardware checks, fast burst               ~4s
STAGE 1   MEMORY SCAN            Hex address sweep                         ~3s
STAGE 2   KERNEL INIT            Kernel log lines + ASCII logo             ~4s
STAGE 3   WHAT IS CYBERSECURITY  Typewriter brief — field explanation      ~7s
STAGE 4   WHY CYBERCLI EXISTS    Purpose statement — problem it solves     ~6s
STAGE 5   LIVE PANEL BOOT        eDEX-UI: left stats / right systemd log   ~20s
STAGE 6   TOOL COMMAND BRIEF     Each module: command + what you get       ~18s
STAGE 7   AI + THREAT FEEDS      AI engines + feed sync                    ~6s
STAGE 8   OPERATOR CLEARANCE     Auth policy, scope lock                   ~4s
STAGE 9   MISSION READY          Final banner + quick reference            ~3s

Total: ~75 seconds   |   Ctrl+C skips any stage
"""

from __future__ import annotations
import os, sys, time, random, shutil, socket, platform
import subprocess, threading
from typing import List, Tuple, Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from rich.console import Console
from rich.live    import Live
from rich.layout  import Layout
from rich.panel   import Panel
from rich.text    import Text

console = Console(highlight=False)

# ══════════════════════════════════════════════════════
#  IDENTITY
# ══════════════════════════════════════════════════════
VER      = "3.0.0"
BUILD    = "20250601"
CODENAME = "PHANTOM GRID"

# ══════════════════════════════════════════════════════
#  ANSI COLOURS
# ══════════════════════════════════════════════════════
RST = "\033[0m"
DIM = "\033[2m"
BLD = "\033[1m"
CY  = "\033[36m";   BCY = "\033[1m\033[96m"
GR  = "\033[32m";   BGR = "\033[1m\033[92m"
YL  = "\033[33m";   BYL = "\033[1m\033[93m"
MG  = "\033[35m";   BMG = "\033[1m\033[95m"
RD  = "\033[31m";   BRD = "\033[1m\033[91m"
WH  = "\033[97m"
GRY = "\033[2m\033[37m"
DGR = "\033[2m\033[32m"

def W() -> int:
    try:    return min(118, shutil.get_terminal_size().columns)
    except: return 80

def raw(t: str, end: str = "\n"):
    sys.stdout.write(t + end); sys.stdout.flush()

def blank(n: int = 1): raw("\n" * (n - 1))

def clr():
    sys.stdout.write("\033[2J\033[H"); sys.stdout.flush()

def hr(c: str = CY):
    raw(f"{DIM}{c}{'─' * W()}{RST}")

def titled_hr(title: str, c: str = CY):
    w = W(); pad = max(2, (w - len(title) - 4) // 2)
    raw(f"{c}{'─'*pad}  {BLD}{title}{RST}{c}  {'─'*pad}{RST}")
    time.sleep(0.12)

def typewrite(text: str, delay: float = 0.022, color: str = WH):
    raw(color, end="")
    for ch in text:
        sys.stdout.write(ch); sys.stdout.flush(); time.sleep(delay)
    raw(RST)

def tw_line(text: str, indent: int = 2, delay: float = 0.018, color: str = WH):
    typewrite(" " * indent + text, delay=delay, color=color)

def _fmt(n: int) -> str:
    for u in ["B","KB","MB","GB","TB"]:
        if n < 1024: return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}PB"

def _bar(pct: float, w: int = 18) -> str:
    f = int((pct / 100) * w)
    c = BGR if pct < 60 else (BYL if pct < 85 else BRD)
    return f"{c}{'█'*f}{GRY}{'░'*(w-f)}{RST}"

def _get_vitals() -> dict:
    v: dict = {}
    if not HAS_PSUTIL: return v
    try:
        v["cpu"]        = psutil.cpu_percent(interval=0.12)
        v["cores"]      = psutil.cpu_count(logical=True)
        freq            = psutil.cpu_freq()
        v["freq"]       = f"{freq.current:.0f}MHz" if freq else "–"
        m               = psutil.virtual_memory()
        v["mem_used"]   = m.used;  v["mem_total"] = m.total;  v["mem_pct"] = m.percent
        sw              = psutil.swap_memory()
        v["swap_used"]  = sw.used; v["swap_total"] = sw.total
        d               = psutil.disk_usage("/")
        v["disk_used"]  = d.used;  v["disk_total"] = d.total; v["disk_pct"] = d.percent
        n               = psutil.net_io_counters()
        v["net_sent"]   = n.bytes_sent; v["net_recv"] = n.bytes_recv
        v["procs"]      = len(psutil.pids())
    except Exception: pass
    return v

def _ifaces() -> List[Tuple[str,str]]:
    out = []
    if HAS_PSUTIL:
        try:
            for iface, addrs in list(psutil.net_if_addrs().items())[:4]:
                for a in addrs:
                    if a.family == socket.AF_INET:
                        out.append((iface, a.address)); break
        except Exception: pass
    return out or [("–","–")]

# ══════════════════════════════════════════════════════
#  STAGE 0 — BIOS POST  ~4s
# ══════════════════════════════════════════════════════
POST = [
    # (tag, message, ok, delay)
    ("CPU DETECT",        "x86_64 architecture  ·  multi-core detected",         True,  0.038),
    ("FPU",               "Floating point unit verified",                          True,  0.030),
    ("APIC",              "Advanced interrupt controller initialized",             True,  0.030),
    ("MEMORY",            "Scanning RAM banks  ·  ECC check",                     True,  0.050),
    ("CACHE",             "L1/L2/L3 cache hierarchy detected",                    True,  0.034),
    ("PCI BUS",           "PCI/PCIe device enumeration complete",                 True,  0.036),
    ("STORAGE",           "NVMe/SATA controller  ·  AES-256-XTS volume",         True,  0.036),
    ("NETWORK",           "Ethernet controller  ·  stealth NIC confirmed",        True,  0.038),
    ("CRYPTO ENGINE",     "AES-NI hardware acceleration active",                  True,  0.038),
    ("ENTROPY POOL",      "Hardware RNG seeded  ·  /dev/urandom ready",           True,  0.036),
    ("SECURE BOOT",       "Signature chain verified  ·  SHA-256 match",           True,  0.042),
    ("TPM 2.0",           "Trusted Platform Module detected  ·  PCR locked",      True,  0.042),
    ("STEALTH NIC",       "Promiscuous mode capability confirmed",                 True,  0.040),
    ("VIRT CHECK",        "Hypervisor detection scan complete",                   True,  0.036),
    ("ROM CHECKSUM",      "BIOS ROM integrity verified  ·  no tampering",         True,  0.042),
    ("BOOT DEVICE",       "/dev/cyberops  encrypted volume mounted",              True,  0.045),
]

def _stage0_bios():
    clr(); blank()
    raw(f"{GRY}  CyberCLI SecureBoot BIOS v4.9.0  ·  Neural Ops Firmware  ·  {BUILD}{RST}")
    raw(f"{GRY}  Copyright (C) 2025 CyberCLI Project  ·  All rights reserved{RST}")
    raw(f"{DIM}{CY}  {'─'*60}{RST}"); blank()
    for tag, msg, ok, delay in POST:
        st = f"{BGR}[ OK ]{RST}" if ok else f"{BRD}[FAIL]{RST}"
        raw(f"  {st}  {GRY}{tag:<24}{RST}  {GRY}{msg}{RST}")
        time.sleep(delay)
    blank()
    raw(f"  {BGR}POST COMPLETE  ·  all hardware checks passed{RST}  "
        f"{GRY}·  transferring to kernel loader{RST}")
    time.sleep(0.8)

# ══════════════════════════════════════════════════════
#  STAGE 1 — MEMORY SCAN  ~3s
# ══════════════════════════════════════════════════════
def _stage1_memtest():
    clr()
    raw(f"\n{BCY}  CYBERCLI MEMTEST v3.0  ·  Scanning address space{RST}\n")
    hr(CY); blank()
    addr = 0x0000
    while addr <= 0xFFFF:
        pct = int((addr / 0xFFFF) * 100)
        pattern = f"0x{random.randint(0,0xFFFFFFFF):08x}"
        raw(f"  {GRY}0x{addr:04X} – 0x{addr+0x07FF:04X}{RST}  "
            f"{_bar(pct, 22)}  {GRY}{pct:>3}%  pattern:{RST}{GR} {pattern}{RST}")
        addr += 0x0800
        time.sleep(0.026)
    blank()
    raw(f"  {BGR}Memory test PASSED  ·  no errors  ·  all banks clean{RST}")
    blank(); time.sleep(0.5)

# ══════════════════════════════════════════════════════
#  STAGE 2 — KERNEL INIT + LOGO  ~4s
# ══════════════════════════════════════════════════════
LOGO = [
    " ██████╗██╗   ██╗██████╗ ███████╗██████╗      ██████╗██╗     ██╗",
    "██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██╔════╝██║     ██║",
    "██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝    ██║     ██║     ██║",
    "██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗    ██║     ██║     ██║",
    "╚██████╗   ██║   ██████╔╝███████╗██║  ██║    ╚██████╗███████╗██║",
    " ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚═════╝╚══════╝╚═╝",
]
KLINES = [
    (0.038, f"{DGR}[    0.000000] CyberCLI kernel 6.4.0-cyberops #1 SMP PREEMPT_DYNAMIC{RST}"),
    (0.038, f"{DGR}[    0.000210] BIOS-provided physical RAM map: usable range verified{RST}"),
    (0.038, f"{DGR}[    0.000890] ACPI: RSDP 0x00000000000F05B0 000024 (v02 CYBCLI){RST}"),
    (0.038, f"{DGR}[    0.001200] PCI: Using configuration type 1 for base access{RST}"),
    (0.038, f"{DGR}[    0.003100] Initializing cgroup subsys cpuset · memory · net_cls{RST}"),
    (0.038, f"{DGR}[    0.006200] cryptographic algorithms: AES-256-XTS  SHA-512  ECDSA{RST}"),
    (0.038, f"{DGR}[    0.009400] NET: Registered PF_INET  PF_INET6  PF_PACKET families{RST}"),
    (0.042, f"{DGR}[    0.012300] cybercli-net: stealth interface registered  [eth0]{RST}"),
    (0.042, f"{DGR}[    0.014100] cybercli-crypto: AES-NI engine loaded{RST}"),
    (0.042, f"{DGR}[    0.016200] cybercli-ai: neural coprocessor interface ready{RST}"),
    (0.042, f"{DGR}[    0.018400] cybercli-core: engine v{VER} build {BUILD} starting{RST}"),
    (0.055, f"{BGR}[    0.021000] cybercli-core: kernel handoff complete — userspace{RST}"),
]

def _stage2_kernel():
    clr(); blank()
    for i, line in enumerate(LOGO):
        raw(f"{BCY if i%2==0 else CY}{line}{RST}"); time.sleep(0.048)
    blank()
    raw(f"  {GRY}v{VER}  ·  BUILD {BUILD}  ·  {CODENAME}  ·  NEXT-GEN CYBER OPERATIONS ENGINE{RST}")
    blank(); hr(CY); blank()
    for delay, line in KLINES:
        raw(line); time.sleep(delay)
    blank(); time.sleep(0.6)

# ══════════════════════════════════════════════════════
#  STAGE 3 — WHAT IS CYBERSECURITY  ~7s
# ══════════════════════════════════════════════════════
def _stage3_what_is_cybersec():
    clr(); blank()
    titled_hr("INTELLIGENCE BRIEF  ·  WHAT IS CYBERSECURITY", BCY)
    blank()

    sections = [
        (BCY, "DEFINITION",
         [
            "Cybersecurity is the practice of protecting systems, networks,",
            "applications, and data from digital attacks, unauthorized access,",
            "damage, or theft.",
            "",
            "It spans every digital surface — from a single web login form",
            "to nation-state critical infrastructure.",
         ]),
        (BYL, "THE THREAT LANDSCAPE",
         [
            "Every second, 2,200+ cyberattacks happen globally.",
            "Average cost of a data breach in 2024: USD 4.88 million.",
            "Ransomware hits every 11 seconds.",
            "97% of breaches could be prevented with proper security hygiene.",
         ]),
        (BGR, "ETHICAL HACKING  —  THE DEFENDER'S WEAPON",
         [
            "Ethical hacking is authorized penetration testing.",
            "You think like the attacker to find weaknesses BEFORE the enemy does.",
            "",
            "The methodology:",
            "  Recon → Scan → Exploit → PrivEsc → Persist → Report → Fix",
            "",
            "Without ethical hackers, every system is a ticking time bomb.",
         ]),
        (BMG, "DOMAINS OF CYBERSECURITY",
         [
            "Network Security     — firewalls, IDS/IPS, packet analysis",
            "Web Application Sec  — OWASP Top 10, injection, auth flaws",
            "Mobile Security      — APK/IPA analysis, API abuse, reverse eng",
            "Cloud Security       — IAM misconfig, exposed buckets, SaaS risk",
            "Active Directory     — Kerberos, LDAP, lateral movement paths",
            "Malware Analysis     — static/dynamic reverse engineering",
            "Threat Intelligence  — IOC feeds, actor profiling, TTPs",
            "Digital Forensics    — incident response, artifact analysis",
            "Red Team / Blue Team — attack simulation vs. active defense",
         ]),
    ]

    for color, title, lines in sections:
        time.sleep(0.3)
        raw(f"\n  {color}{BLD}{title}{RST}")
        raw(f"  {DIM}{CY}{'·'*50}{RST}")
        for line in lines:
            if line == "":
                blank()
            else:
                tw_line(line, indent=4, delay=0.012, color=WH)
        time.sleep(0.4)

    blank(); time.sleep(0.8)

# ══════════════════════════════════════════════════════
#  STAGE 4 — WHY CYBERCLI EXISTS  ~6s
# ══════════════════════════════════════════════════════
def _stage4_why_cybercli():
    clr(); blank()
    titled_hr("WHY CYBERCLI EXISTS  ·  THE PURPOSE", BYL)
    blank()

    raw(f"  {BRD}THE PROBLEM{RST}")
    raw(f"  {DIM}{CY}{'·'*50}{RST}")
    problems = [
        "A professional ethical hacker uses 40–60 different tools per engagement.",
        "Each tool has its own syntax, output format, install method.",
        "No memory between tools — findings live in scattered text files.",
        "Zero correlation between recon data, scan results, CVE matches.",
        "Writing reports takes longer than the actual pentest.",
        "Junior security teams have no guided workflow.",
    ]
    for p in problems:
        tw_line(f"✗  {p}", indent=4, delay=0.013, color=BRD)
        time.sleep(0.12)

    blank()
    raw(f"  {BGR}THE SOLUTION  —  CYBERCLI{RST}")
    raw(f"  {DIM}{CY}{'·'*50}{RST}")
    solutions = [
        ("ONE ENGINE",      "33 modules, unified CLI, single brain"),
        ("FULL LIFECYCLE",  "Recon → Scan → Exploit → PrivEsc → Report — end to end"),
        ("AI INSIDE",       "8 AI engines: correlate, predict, classify, auto-report"),
        ("REAL TOOLS",      "Wraps nmap, sqlmap, ffuf, nuclei, nikto — real output"),
        ("KNOWLEDGE GRAPH", "Every finding links to CVEs, ATT&CK TTPs, remediation"),
        ("LEGAL FIRST",     "Consent, scope, authorization baked into every workflow"),
        ("ONE REPORT",      "Auto-generated pentest report from all findings combined"),
        ("OPERATOR GRADE",  "Terminal-first, keyboard-driven, zero GUI overhead"),
    ]
    for label, desc in solutions:
        raw(f"  {BGR}  ✓  {BLD}{label:<18}{RST}  {GRY}{desc}{RST}")
        time.sleep(0.32)

    blank()
    time.sleep(0.3)
    raw(f"  {BCY}{'═'*60}{RST}")
    tw_line(
        "CyberCLI is not a collection of scripts.",
        indent=4, delay=0.016, color=BCY)
    tw_line(
        "It is the operating system of the modern ethical hacker.",
        indent=4, delay=0.016, color=BCY)
    tw_line(
        "Every domain of cybersecurity — one terminal.",
        indent=4, delay=0.016, color=BCY)
    raw(f"  {BCY}{'═'*60}{RST}")
    blank(); time.sleep(0.8)

# ══════════════════════════════════════════════════════
#  STAGE 5 — LIVE PANEL BOOT  ~20s
# ══════════════════════════════════════════════════════
MODULES = [
    ("recon",           1820, "Passive footprint  ·  DNS WHOIS subdomains certs"),
    ("scan",            2341, "Port sweep  ·  service detect OS fingerprint NSE"),
    ("exploit",         3102, "CVE intelligence  ·  exploit-DB CVSS patch refs"),
    ("privesc",         2890, "Privilege paths  ·  SUID cron sudo linpeas parse"),
    ("websec",          3410, "Web surface  ·  params headers WAF OWASP checks"),
    ("activeDirectory", 4201, "AD topology  ·  LDAP Kerberos GPO trust SPN map"),
    ("forensic",        2654, "Incident timeline  ·  hashing IOC artifacts chain"),
    ("wifi",            1923, "Wireless  ·  PCAP rogue-AP monitor mode (passive)"),
    ("threat",          2780, "IOC enrichment  ·  IP/domain rep malware hash actor"),
    ("container",       3150, "Container risk  ·  Docker K8s RBAC image CVEs CIS"),
    ("redteam",         3820, "Op planning  ·  adversary sim payload templates"),
    ("blueteam",        2940, "Defense  ·  YARA anomaly detection log gap analysis"),
    ("sslscan",         1710, "TLS audit  ·  ciphers cert chain protocol grades"),
    ("ai",              4100, "AI suite  ·  OSINT enrich risk predict auto-report"),
    ("cloud",           3560, "Cloud exposure  ·  IAM buckets policies CIS checks"),
    ("mobile",          2830, "App static  ·  APK IPA permissions hardcoded secrets"),
    ("api",             2470, "API model  ·  endpoints auth schema rate-limits"),
    ("malware",         3210, "Static analysis  ·  strings PE YARA hash IOC lookup"),
    ("supplychain",     2680, "Dep risk  ·  SBOM typosquatting CVE-matched packages"),
    ("iot",             1890, "IoT surface  ·  device enum firmware default-cred"),
    ("darknet",         2340, "Passive intel  ·  breach mentions leak linkage"),
    ("engagement",      1650, "Scope mgmt  ·  targets RoE stakeholder contacts"),
    ("consent",         1420, "Legal  ·  authorization records scope boundaries"),
    ("assets",          2100, "Asset brain  ·  host service inventory tech stack"),
    ("vuln",            2560, "Vuln lifecycle  ·  CVE track patch delta SLA"),
    ("risk",            2920, "Risk matrix  ·  CVSS business impact heatmap"),
    ("attackpath",      3340, "Kill chain  ·  MITRE ATT&CK mapping pivot viz"),
    ("compliance",      2780, "Regulatory  ·  ISO27001 NIST PCI-DSS GDPR gaps"),
    ("knowledge",       3890, "Sec brain  ·  CVE technique tool knowledge graph"),
    ("automation",      2230, "Pipeline  ·  scheduled scans alerts workflow hooks"),
    ("zap",             4500, "Full VAPT  ·  spider→scan→AI→graph→PDF report"),
    ("graph",           3970, "Attack graph  ·  domain cloud trust kill chains"),
    ("burp",            4200, "WAPT engine  ·  OWASP Top10 intercept scanner"),
]

def _stats_panel(v: dict, net0: tuple, tick: int) -> Panel:
    if not v:
        return Panel(Text("  psutil not available\n  pip install psutil", style="dim"),
                     border_style="cyan",
                     title=f"[bold cyan]SYSTEM[/bold cyan]")
    cpu = v.get("cpu", 0)
    bw  = 14
    def rb(pct, w=bw):
        f = int((pct/100)*w)
        c = "bold green" if pct<60 else ("bold yellow" if pct<85 else "bold red")
        return Text.assemble((f"{'█'*f}", c), (f"{'░'*(w-f)}", "dim"))

    t = Text()
    spin = ["◐","◓","◑","◒"][tick % 4]
    t.append(f"\n  {spin} ", style="bold cyan")
    t.append(f"CYBERCLI v{VER}\n\n", style="bold white")

    t.append("  CPU    ", style="cyan")
    t.append(rb(cpu)); t.append(f" {cpu:5.1f}%\n")
    t.append(f"         {v.get('cores','?')} cores  {v.get('freq','–')}\n\n", style="dim")

    mp = v.get("mem_pct", 0)
    t.append("  MEM    ", style="cyan")
    t.append(rb(mp)); t.append(f" {mp:5.1f}%\n")
    t.append(f"         {_fmt(v.get('mem_used',0))} / {_fmt(v.get('mem_total',1))}\n\n", style="dim")

    sp = (v.get("swap_used",0)/max(v.get("swap_total",1),1))*100
    t.append("  SWAP   ", style="cyan")
    t.append(rb(sp)); t.append(f" {sp:5.1f}%\n\n")

    dp = v.get("disk_pct", 0)
    t.append("  DISK   ", style="cyan")
    t.append(rb(dp)); t.append(f" {dp:5.1f}%\n")
    t.append(f"         {_fmt(v.get('disk_used',0))} / {_fmt(v.get('disk_total',1))}\n\n", style="dim")

    net_s = net_r = "–"
    if HAS_PSUTIL:
        try:
            n = psutil.net_io_counters()
            net_s = _fmt(max(0, n.bytes_sent - net0[0]))
            net_r = _fmt(max(0, n.bytes_recv - net0[1]))
        except Exception: pass

    t.append("  NET    ", style="cyan")
    t.append(f"↑{net_s:>8}  ↓{net_r:>8}\n\n", style="bold green")
    t.append("  PROCS  ", style="cyan"); t.append(f"{v.get('procs','–')}\n\n", style="white")
    t.append("  HOST   ", style="cyan"); t.append(f"{socket.gethostname()}\n", style="white")
    t.append("  OS     ", style="cyan"); t.append(f"{platform.system()} {platform.release()}\n", style="white")
    t.append("  ARCH   ", style="cyan"); t.append(f"{platform.machine()}\n\n", style="white")
    for iface, ip in _ifaces()[:3]:
        t.append(f"  {iface:<7}", style="cyan"); t.append(f"{ip}\n", style="dim")
    t.append(f"\n  {time.strftime('%H:%M:%S')}", style="dim cyan")
    return Panel(t, border_style="cyan",
                 title="[bold cyan]SYSTEM VITALS[/bold cyan]")

def _log_panel(loaded: List[str], loading: Optional[str], total: int) -> Panel:
    pct  = int((len(loaded)/total)*100) if total else 0
    fill = int((len(loaded)/total)*28) if total else 0
    t = Text()
    t.append("\n  [", style="dim"); t.append("█"*fill, style="bold green")
    t.append("░"*(28-fill), style="dim")
    t.append(f"]  {pct:>3}%  {len(loaded)}/{total}\n\n", style="dim")
    for name in loaded[-14:]:
        t.append("  [  OK  ] ", style="bold green")
        t.append("Started ", style="white")
        t.append(f"cybercli.{name}.service\n", style="bold cyan")
    if loading:
        t.append(f"  [ INIT ] ", style="bold yellow")
        t.append("Starting ", style="white")
        t.append(f"cybercli.{loading}.service", style="bold yellow")
        t.append(" ...\n", style="dim")
    return Panel(t, border_style="green",
                 title="[bold green]MODULE INIT  ·  SYSTEMD[/bold green]")

def _stage5_live_panel():
    layout = Layout()
    layout.split_row(Layout(name="l", ratio=2), Layout(name="r", ratio=3))
    loaded: List[str]       = []
    loading: Optional[str]  = None
    vitals: dict            = {}
    net0: tuple             = (0, 0)
    tick: int               = 0
    done = threading.Event()

    def vitals_worker():
        nonlocal vitals, net0
        if HAS_PSUTIL:
            try:
                n = psutil.net_io_counters(); net0 = (n.bytes_sent, n.bytes_recv)
            except Exception: pass
        while not done.is_set():
            vitals = _get_vitals()
            if HAS_PSUTIL:
                try:
                    n = psutil.net_io_counters(); net0 = (n.bytes_sent, n.bytes_recv)
                except Exception: pass
            time.sleep(0.35)

    threading.Thread(target=vitals_worker, daemon=True).start()
    total = len(MODULES)

    with Live(layout, refresh_per_second=7, screen=True) as live:
        for name, _, _ in MODULES:
            loading = name
            layout["l"].update(_stats_panel(vitals, net0, tick))
            layout["r"].update(_log_panel(loaded, loading, total))
            tick += 1
            time.sleep(max(0.12, 0.30 + random.uniform(-0.04, 0.08)))
            loaded.append(name); loading = None
            layout["l"].update(_stats_panel(vitals, net0, tick))
            layout["r"].update(_log_panel(loaded, loading, total))
            tick += 1; time.sleep(0.055)
        for _ in range(10):
            layout["l"].update(_stats_panel(vitals, net0, tick)); tick += 1; time.sleep(0.18)
    done.set(); time.sleep(0.2)

# ══════════════════════════════════════════════════════
#  STAGE 6 — TOOL COMMAND BRIEF  ~18s
# ══════════════════════════════════════════════════════
TOOL_BRIEF = [
    # (module, command_example, purpose, what_you_get)
    ("recon",
     "cybercli recon --target example.com",
     "Passive information gathering before touching the target.",
     "Subdomains · DNS records · WHOIS · cert SANs · email leaks · screenshots"),

    ("scan",
     "cybercli scan --ip 192.168.1.0/24",
     "Map every open port, service, OS fingerprint on the target.",
     "Open ports · service versions · OS guess · NSE script output · entry points"),

    ("exploit",
     "cybercli exploit --target 192.168.1.10 --port 443",
     "Match target services to known CVEs and exploit references.",
     "CVE IDs · CVSS scores · exploit-DB links · affected versions · patch refs"),

    ("privesc",
     "cybercli privesc --host 192.168.1.20 --user www-data",
     "Enumerate local privilege escalation paths after initial access.",
     "SUID binaries · writable paths · cron jobs · kernel CVEs · sudo misconfigs"),

    ("websec",
     "cybercli websec --url https://target.com",
     "Full web application security audit against OWASP Top 10.",
     "Endpoint map · param injection points · auth flaws · WAF type · headers"),

    ("activeDirectory",
     "cybercli activeDirectory --dc 10.0.0.1 --domain corp.local",
     "Map and audit the Active Directory environment.",
     "Users · groups · SPN list · Kerberoastable accounts · trust paths · GPOs"),

    ("forensic",
     "cybercli forensic --host 192.168.1.5 --collect all",
     "Collect and correlate digital evidence from a compromised host.",
     "File timeline · hashes · IOC hits · process tree · network artifacts"),

    ("wifi",
     "cybercli wifi --interface wlan0 --pcap capture.pcap",
     "Analyze wireless traffic and detect rogue access points.",
     "AP list · BSSID/SSID/channel · rogue AP flags · client associations"),

    ("threat",
     "cybercli threat --ioc 1.2.3.4 --type ip",
     "Enrich an IOC with threat intelligence data from multiple feeds.",
     "Reputation score · threat category · actor attribution · VT score"),

    ("container",
     "cybercli container --target k8s-cluster --audit",
     "Audit Docker and Kubernetes for security misconfigurations.",
     "RBAC gaps · privileged containers · secrets in env · CIS failures"),

    ("redteam",
     "cybercli redteam --target-org corp.com --scenario apt",
     "Plan and visualize adversary simulation attack paths.",
     "Attack chain · MITRE TTPs · lateral movement map · payload refs"),

    ("blueteam",
     "cybercli blueteam --host 192.168.1.0/24 --baseline",
     "Establish defensive baseline and detect anomalies.",
     "YARA hits · process anomalies · log gaps · hardening checklist"),

    ("sslscan",
     "cybercli sslscan --host target.com --port 443",
     "Deep TLS/SSL audit using testssl.sh engine.",
     "Cert validity · cipher grades · protocol support · HSTS status"),

    ("ai",
     "cybercli ai --mode correlate --engagement-id ENG-001",
     "AI-driven correlation across all findings in an engagement.",
     "Risk prediction · attack probability · enriched IOCs · report draft"),

    ("cloud",
     "cybercli cloud --provider aws --profile default",
     "Audit cloud environment for exposure and misconfigurations.",
     "Public S3 buckets · IAM issues · open SGs · CIS findings · risk score"),

    ("mobile",
     "cybercli mobile --apk app.apk",
     "Static analysis of Android/iOS applications.",
     "Permission risks · hardcoded secrets · exported components · API endpoints"),

    ("api",
     "cybercli api --url https://api.target.com --spec openapi.yaml",
     "Map and audit REST/GraphQL API attack surface.",
     "Endpoint list · auth type · rate-limit gaps · BOLA findings · schema map"),

    ("malware",
     "cybercli malware --file suspicious.exe --mode static",
     "Static malware analysis without executing the binary.",
     "YARA matches · PE headers · string dump · hash IOC · behavioral hints"),

    ("supplychain",
     "cybercli supplychain --repo github.com/org/repo",
     "Audit software supply chain and dependency risk.",
     "SBOM diff · CVE-matched deps · typosquatted packages · license risks"),

    ("zap",
     "cybercli zap --target https://target.com --depth full",
     "Full VAPT pipeline — spider to PDF report in one command.",
     "Spider map · scan findings · AI analysis · attack graph · PDF report"),

    ("graph",
     "cybercli graph --domain corp.com --mode full",
     "Generate visual attack graph of domain, cloud, and trust paths.",
     "Domain topology · cloud pivots · kill chain · lateral movement tree"),

    ("burp",
     "cybercli burp --target https://target.com --mode active",
     "Full WAPT — OWASP Top 10 active scanning engine.",
     "Intercepted requests · active scan results · severity-ranked findings"),

    ("risk",
     "cybercli risk --engagement ENG-001 --generate-matrix",
     "Generate risk matrix and business impact scores from all findings.",
     "CVSS scores · business impact · likelihood matrix · executive heatmap"),

    ("attackpath",
     "cybercli attackpath --engagement ENG-001",
     "Map full kill chain with MITRE ATT&CK technique coverage.",
     "ATT&CK mapping · pivot points · blast radius · lateral path diagram"),

    ("compliance",
     "cybercli compliance --standard pci-dss --engagement ENG-001",
     "Map findings to regulatory and compliance frameworks.",
     "Control failures · ISO/NIST/PCI gaps · remediation priority · audit doc"),
]

def _stage6_tool_brief():
    clr(); blank()
    titled_hr("TOOL ARSENAL  ·  COMMANDS  ·  PURPOSE  ·  OUTPUT", BCY)

    for module, cmd, purpose, output in TOOL_BRIEF:
        blank()
        # Module header
        raw(f"  {BMG}┌─  {module.upper()}{RST}")
        # Command
        raw(f"  {BMG}│{RST}  {CY}❯{RST}  {WH}{cmd}{RST}")
        # Purpose
        raw(f"  {BMG}│{RST}  {GRY}WHY   {RST}{YL}{purpose}{RST}")
        # Output
        raw(f"  {BMG}│{RST}  {GRY}GET   {RST}{BGR}{output}{RST}")
        raw(f"  {BMG}└{'─'*60}{RST}")
        time.sleep(0.38)

    blank(); time.sleep(0.6)

# ══════════════════════════════════════════════════════
#  STAGE 7 — AI ENGINES + THREAT FEEDS  ~6s
# ══════════════════════════════════════════════════════
AI_ENGINES = [
    ("ai.recon",     "OSINT noise reduction · pattern extraction · persona linking"),
    ("ai.osint",     "Digital trail correlation · open-source intelligence fusion"),
    ("ai.exploit",   "CVE similarity scoring · weakness prediction · version delta"),
    ("ai.defense",   "Hardening suggestion engine · rapid response routing"),
    ("ai.predict",   "Attack path inference · early indicator detection"),
    ("ai.correlate", "Multi-source data fusion · behavioral clustering"),
    ("ai.classify",  "Risk tagging · threat context modeling · severity scoring"),
    ("ai.report",    "Operator summary · executive brief · PDF pipeline"),
]
THREAT_FEEDS = [
    ("MITRE ATT&CK v15",  "14 tactics · 196 techniques · 411 sub-techniques"),
    ("NVD CVE Database",  "4.2M+ vulnerability records  ·  delta sync active"),
    ("Abuse.ch URLHAUS",  "malicious URL live feed  ·  IOC stream"),
    ("AlienVault OTX",    "community threat intel pulses  ·  API sync"),
    ("Emerging Threats",  "IDS/IPS signature feed  ·  rule import"),
    ("Shodan InternetDB", "passive host intelligence  ·  banner cache"),
    ("CIRCL CVE Feed",    "enriched CVE metadata  ·  MITRE mapping"),
    ("VirusTotal Feed",   "hash & domain reputation  ·  score cache"),
]

def _stage7_ai_feeds():
    clr(); blank()
    titled_hr("AI ENGINE INITIALIZATION", BCY); blank()
    for name, desc in AI_ENGINES:
        pid = random.randint(10000, 29999)
        raw(f"  {BCY}[ INIT ]{RST}  {BCY}{name:<18}{RST}  {GRY}{desc}{RST}")
        time.sleep(0.40)
    blank()
    raw(f"  {BGR}✓  8 AI engines online  ·  neural coprocessor active{RST}")
    blank(); time.sleep(0.3)
    titled_hr("THREAT INTELLIGENCE  ·  FEED SYNCHRONIZATION", BYL); blank()
    for feed, detail in THREAT_FEEDS:
        ms = random.randint(22, 148)
        raw(f"  {BGR}[SYNC]{RST}  {YL}{feed:<26}{RST}  {GRY}{detail}  ·  {ms}ms{RST}")
        time.sleep(0.44)
    blank()
    raw(f"  {BGR}✓  8 threat feeds synchronized{RST}")
    blank(); time.sleep(0.5)

# ══════════════════════════════════════════════════════
#  STAGE 8 — OPERATOR CLEARANCE  ~4s
# ══════════════════════════════════════════════════════
def _stage8_clearance():
    clr(); blank()
    titled_hr("OPERATOR CLEARANCE  ·  AUTHORIZATION POLICY", BYL); blank()
    policies = [
        ("authorization mode",   "EXPLICIT WRITTEN CONSENT REQUIRED"),
        ("scope enforcement",    "active  ·  out-of-scope requests blocked"),
        ("passive-first policy", "active  ·  no unsolicited writes or sends"),
        ("data retention",       "session-only  ·  zero persistence to disk"),
        ("audit log",            f"~/.cybercli/audit-{BUILD}.log"),
        ("legal framework",      "consent module preflight active"),
        ("safe mode",            "CVE display-only  ·  no live exploitation"),
        ("session",              f"PID {os.getpid()}  ·  {time.strftime('%Y-%m-%d %H:%M:%S')}"),
    ]
    for label, val in policies:
        raw(f"  {BYL}[AUTH]{RST}  {YL}{label:<26}{RST}  {GRY}{val}{RST}")
        time.sleep(0.30)
    blank()
    for line in [
        "verifying module integrity checksums ...",
        "sealing memory pages ...",
        "flushing entropy pool ...",
        "establishing operator shell ...",
    ]:
        typewrite(f"  {line}", delay=0.015, color=GRY)
        time.sleep(0.15)
    blank(); time.sleep(0.5)

# ══════════════════════════════════════════════════════
#  STAGE 9 — MISSION READY  ~3s
# ══════════════════════════════════════════════════════
READY_ART = [
    "  ██████╗ ███████╗ █████╗ ██████╗ ██╗   ██╗",
    "  ██╔══██╗██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝",
    "  ██████╔╝█████╗  ███████║██║  ██║ ╚████╔╝ ",
    "  ██╔══██╗██╔══╝  ██╔══██║██║  ██║  ╚██╔╝  ",
    "  ██║  ██║███████╗██║  ██║██████╔╝   ██║   ",
    "  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝    ╚═╝  ",
]
QUICK_REF = [
    ("cybercli --help",                  "list all modules"),
    ("cybercli <module> --help",         "module command reference"),
    ("cybercli recon --target <host>",   "passive recon on a target"),
    ("cybercli scan --ip <ip>",          "full port + service scan"),
    ("cybercli websec --url <url>",      "web application security audit"),
    ("cybercli zap --target <url>",      "full VAPT pipeline — one command"),
    ("cybercli ai report --eng ENG-001", "AI-powered pentest report"),
    ("cybercli graph --domain <d>",      "attack graph visualization"),
    ("cybercli burp --target <url>",     "WAPT  ·  OWASP Top 10 scan"),
    ("cybercli risk --engagement <id>",  "risk matrix + business impact"),
]

def _stage9_ready():
    clr(); w = W()
    raw(f"\n{BGR}{'═'*w}{RST}"); blank()
    for i, line in enumerate(READY_ART):
        raw(f"{BGR if i%2==0 else GR}{line}{RST}"); time.sleep(0.052)
    blank()
    raw(f"  {BCY}SYSTEM ONLINE  ·  {len(MODULES)} MODULES  ·  8 AI ENGINES  ·  ALL SYSTEMS NOMINAL{RST}")
    raw(f"  {GRY}v{VER}  ·  {CODENAME}  ·  BUILD {BUILD}  ·  {time.strftime('%Y-%m-%d %H:%M:%S')}{RST}")
    blank(); raw(f"{BGR}{'═'*w}{RST}"); blank()
    titled_hr("QUICK REFERENCE", CY); blank()
    for cmd, desc in QUICK_REF:
        raw(f"  {CY}❯{RST}  {WH}{cmd:<42}{RST}  {GRY}{desc}{RST}")
        time.sleep(0.09)
    blank(); raw(f"{DIM}{CY}{'─'*w}{RST}"); blank()
    time.sleep(1.2)

# ══════════════════════════════════════════════════════
#  MODULE BANNER
# ══════════════════════════════════════════════════════
def run_module_banner(module_name: str):
    match = next(((n, ms, d) for n, ms, d in MODULES if n == module_name), None)
    if not match: return
    name, _, desc = match
    blank(); w = W()
    raw(f"{CY}{'─'*w}{RST}")
    raw(f"  {BCY}MODULE{RST}  ·  {BMG}{name.upper()}{RST}")
    raw(f"  {GRY}{desc}{RST}")
    raw(f"{CY}{'─'*w}{RST}"); blank(); time.sleep(0.3)

# ══════════════════════════════════════════════════════
#  MASTER ENTRYPOINT
# ══════════════════════════════════════════════════════
STAGES = [
    ("BIOS POST",         _stage0_bios),
    ("memory scan",       _stage1_memtest),
    ("kernel init",       _stage2_kernel),
    ("what is cybersec",  _stage3_what_is_cybersec),
    ("why cybercli",      _stage4_why_cybercli),
    ("live panel boot",   _stage5_live_panel),
    ("tool brief",        _stage6_tool_brief),
    ("AI + feeds",        _stage7_ai_feeds),
    ("clearance",         _stage8_clearance),
    ("mission ready",     _stage9_ready),
]

def run_advanced_intro(skip_to: int = 0):
    """
    Full CyberCLI boot sequence. ~75 seconds.
    Ctrl+C skips current stage cleanly.
    Args:
        skip_to: 0=BIOS 1=memtest 2=kernel 3=cybersec 4=why
                 5=livepanel 6=toolbrief 7=ai 8=clearance 9=ready
    """
    for i, (name, fn) in enumerate(STAGES):
        if i < skip_to: continue
        try:
            fn()
        except KeyboardInterrupt:
            blank(); raw(f"  {GRY}↳ skipped: {name}{RST}"); time.sleep(0.2)
        except Exception as exc:
            raw(f"  {BRD}[ERR] {name}: {exc}{RST}"); time.sleep(0.3)

# ══════════════════════════════════════════════════════
#  CLI ENTRY
# ══════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="CyberCLI Boot Sequence")
    ap.add_argument("--skip", type=int, default=0, metavar="N",
                    help="Skip to stage N (0–9)")
    ap.add_argument("--module", type=str, default=None,
                    help="Show module banner")
    args = ap.parse_args()
    if args.module:
        run_module_banner(args.module)
    else:
        run_advanced_intro(skip_to=args.skip)