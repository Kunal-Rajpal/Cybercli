# #First Phase
# # cybercli/main.py

# import typer
# import sys
# from rich import print as rprint
# from cybercli.plugins.intro_animation import run_advanced_intro

# from cybercli.plugins import (
#     recon, scan, exploit, privesc, websec,
#     ad, forensics, wifi, threatintel,
#     container, redteam, blue
# )

# app = typer.Typer(help="One-Man-Army Cyber CLI")

# app.add_typer(recon.app, name="recon")
# app.add_typer(scan.app, name="scan")
# app.add_typer(exploit.app, name="exploit")
# app.add_typer(privesc.app, name="privesc")
# app.add_typer(websec.app, name="websec")
# app.add_typer(ad.app, name="activeDirectory")
# app.add_typer(forensics.app, name="forensic")
# app.add_typer(wifi.app, name="wifi")
# app.add_typer(threatintel.app, name="threat")
# app.add_typer(container.app, name="container")
# app.add_typer(redteam.app, name="redteam")
# app.add_typer(blue.app, name="blueteam")

# def main():
#     if len(sys.argv) > 1:
#         app()
#         return
#     try:
#         run_advanced_intro()
#     except Exception as e:
#         rprint(f"[red]Animation error:[/red] {e}")
#     app()

# if __name__ == "__main__":
#     main()


#SecondPhase
# # cybercli/main.py — FINAL ERROR-FREE VERSION

# import typer
# import sys
# from rich import print as rprint

# from cybercli.plugins.intro_animation import run_advanced_intro

# # Import plugin modules
# from cybercli.plugins import (
#     recon, scan, exploit, privesc, websec,
#     ad, forensics, wifi, threatintel,
#     container, redteam, blue
# )

# app = typer.Typer(help="One-Man-Army Cyber CLI")

# # Register modules
# app.add_typer(recon.app, name="recon")
# app.add_typer(scan.app, name="scan")
# app.add_typer(exploit.app, name="exploit")
# app.add_typer(privesc.app, name="privesc")
# app.add_typer(websec.app, name="websec")
# app.add_typer(ad.app, name="activeDirectory")
# app.add_typer(forensics.app, name="forensic")
# app.add_typer(wifi.app, name="wifi")
# app.add_typer(threatintel.app, name="threat")
# app.add_typer(container.app, name="container")
# app.add_typer(redteam.app, name="redteam")
# app.add_typer(blue.app, name="blueteam")

# def main():
#     # If user passed arguments → skip intro
#     if len(sys.argv) > 1:
#         app()
#         return

#     # Otherwise play cinematic intro
#     try:
#         run_advanced_intro()
#     except Exception as e:
#         rprint(f"[red]Animation error:[/red] {e}")

#     app()

# if __name__ == "__main__":
#     main()



#------------------

# # cybercli/main.py — FINAL 20-MODULE EDITION

# import typer
# import sys
# from rich import print as rprint

# from cybercli.plugins.intro_animation import run_advanced_intro

# # === CORE BUILT-IN 12 MODULES ===
# from cybercli.plugins import (
#     recon, scan, exploit, privesc, websec,
#     ad, forensics, wifi, threatintel,
#     container, redteam, blue
# )

# # === NEW GEN-AI MODULES (8 AI SUBMODULES INSIDE) ===
# from cybercli.plugins.ai import ai_app

# # === NEW 7 TOP-LEVEL MODULES ===
# from cybercli.plugins import (
#     cloudsec,
#     mobilesec,
#     apisec,
#     malwarenet as malwarelab,   # FIXED: correct import for malware module
#     supplychain,
#     iotsec,
#     darknet
# )

# # MAIN APP
# app = typer.Typer(help="⚡ One-Man-Army CyberCLI — 20 Modules Activated")


# # ------------------------------------------------------
# # REGISTER OLD 12 MODULES
# # ------------------------------------------------------
# app.add_typer(recon.app,        name="recon")
# app.add_typer(scan.app,         name="scan")
# app.add_typer(exploit.app,      name="exploit")
# app.add_typer(privesc.app,      name="privesc")
# app.add_typer(websec.app,       name="websec")
# app.add_typer(ad.app,           name="activeDirectory")
# app.add_typer(forensics.app,    name="forensic")
# app.add_typer(wifi.app,         name="wifi")
# app.add_typer(threatintel.app,  name="threat")
# app.add_typer(container.app,    name="container")
# app.add_typer(redteam.app,      name="redteam")
# app.add_typer(blue.app,         name="blueteam")


# # ------------------------------------------------------
# # REGISTER AI SUPER-MODULE (with 8 subtools inside)
# # ------------------------------------------------------
# app.add_typer(ai_app, name="ai")


# # ------------------------------------------------------
# # REGISTER NEW 7 MAJOR SECURITY MODULES
# # ------------------------------------------------------
# app.add_typer(cloudsec.app,      name="cloud")
# app.add_typer(mobilesec.app,     name="mobile")
# app.add_typer(apisec.app,        name="api")
# app.add_typer(malwarelab.app,    name="malware")
# app.add_typer(supplychain.app,   name="supply")
# app.add_typer(iotsec.app,        name="iot")
# app.add_typer(darknet.app,       name="darknet")


# # ------------------------------------------------------
# # MAIN ENTRY LOGIC
# # ------------------------------------------------------
# def main():
#     # If CLI used → skip animation
#     if len(sys.argv) > 1:
#         app()
#         return

#     # Otherwise play the cinematic intro
#     try:
#         run_advanced_intro()
#     except Exception as e:
#         rprint(f"[red]Intro animation error:[/red] {e}")

#     app()


# if __name__ == "__main__":
#     main()





# # cybercli/main.py — FINAL 20+ MODULE ENTERPRISE EDITION

# import typer
# import sys
# from rich import print as rprint

# from cybercli.plugins.intro_animation import run_advanced_intro

# # ======================================================
# # CORE BUILT-IN 12 MODULES (STABLE)
# # ======================================================
# from cybercli.plugins import (
#     recon,
#     scan,
#     exploit,
#     privesc,
#     websec,
#     ad,
#     forensics,
#     wifi,
#     threatintel,
#     container,
#     redteam,
#     blue,
# )

# # ======================================================
# # AI SUPER-MODULE (8 SUBMODULES INSIDE)
# # ======================================================
# from cybercli.plugins.ai import ai_app

# # ======================================================
# # NEXT-GEN TOP LEVEL MODULES
# # ======================================================
# from cybercli.plugins import (
#     cloudsec,
#     mobilesec,
#     apisec,
#     malwarenet as malwarelab,  # alias safe
#     supplychain,
#     iotsec,
#     darknet,
# )

# # ======================================================
# # GOVERNANCE & AUTOMATION ENGINES (PHASE 1–10)
# # ======================================================
# from cybercli.plugins import automation

# # ======================================================
# # MAIN CLI APP
# # ======================================================
# app = typer.Typer(
#     help="⚡ One-Man-Army CyberCLI — Governed Offensive & Defensive Security Platform"
# )

# # ------------------------------------------------------
# # REGISTER CORE 12 MODULES
# # ------------------------------------------------------
# app.add_typer(recon.app,       name="recon")
# app.add_typer(scan.app,        name="scan")
# app.add_typer(exploit.app,     name="exploit")
# app.add_typer(privesc.app,     name="privesc")
# app.add_typer(websec.app,      name="websec")
# app.add_typer(ad.app,          name="activeDirectory")
# app.add_typer(forensics.app,   name="forensic")
# app.add_typer(wifi.app,        name="wifi")
# app.add_typer(threatintel.app, name="threat")
# app.add_typer(container.app,   name="container")
# app.add_typer(redteam.app,     name="redteam")
# app.add_typer(blue.app,        name="blueteam")

# # ------------------------------------------------------
# # REGISTER AI MODULE
# # ------------------------------------------------------
# app.add_typer(ai_app, name="ai")

# # ------------------------------------------------------
# # REGISTER NEW SECURITY DOMAINS
# # ------------------------------------------------------
# app.add_typer(cloudsec.app,    name="cloud")
# app.add_typer(mobilesec.app,   name="mobile")
# app.add_typer(apisec.app,      name="api")
# app.add_typer(malwarelab.app,  name="malware")
# app.add_typer(supplychain.app, name="supply")
# app.add_typer(iotsec.app,      name="iot")
# app.add_typer(darknet.app,     name="darknet")

# # ------------------------------------------------------
# # REGISTER SAFE AUTOMATION ENGINE (PHASE 10)
# # ------------------------------------------------------
# app.add_typer(automation.app, name="automation")

# # ------------------------------------------------------
# # MAIN ENTRYPOINT
# # ------------------------------------------------------
# def main():
#     # If arguments passed → skip intro animation
#     if len(sys.argv) > 1:
#         app()
#         return

#     # Otherwise run cinematic intro
#     try:
#         run_advanced_intro()
#     except Exception as e:
#         rprint(f"[red]Intro animation error:[/red] {e}")

#     app()


# if __name__ == "__main__":
#     main()





##Final version that to be test
# cybercli/main.py
# ⚡ CyberCLI — Unified Ethical Hacking & Security Governance Platform

import sys
import typer
from rich import print as rprint

from cybercli.plugins.intro_animation import run_advanced_intro

# ======================================================
# BASE APP
# ======================================================
app = typer.Typer(
    help="⚡ CyberCLI — Offensive, Defensive & Governed Security Platform"
)

# ======================================================
# CORE SECURITY MODULES (FOUNDATION)
# ======================================================
from cybercli.plugins import (
    recon,
    scan,
    exploit,
    privesc,
    websec,
    ad,
    forensics,
    wifi,
    threatintel,
    container,
    redteam,
    blue,
    sslscan,
    keycloaksec
)

# ======================================================
# AI SUPER MODULE (MULTI-SUBSYSTEM)
# ======================================================
from cybercli.plugins.ai import ai_app

# ======================================================
# EXTENDED SECURITY DOMAINS
# ======================================================
from cybercli.plugins import (
    cloudsec,
    mobilesec,
    apisec,
    malwarenet,
    supplychain,
    iotsec,
    darknet,
)

# ======================================================
# GOVERNANCE & INTELLIGENCE ENGINES
# ======================================================
from cybercli.plugins import (
    engagement,
    consent,
    assets,
    vuln,
    risk,
    attackpath,
    compliance,
    knowledge,
    automation,
)

# ======================================================
# REGISTER CORE SECURITY MODULES
# ======================================================
app.add_typer(recon.app,        name="recon")
app.add_typer(scan.app,         name="scan")
app.add_typer(exploit.app,      name="exploit")
app.add_typer(privesc.app,      name="privesc")
app.add_typer(websec.app,       name="websec")
app.add_typer(ad.app,           name="activeDirectory")
app.add_typer(forensics.app,    name="forensic")
app.add_typer(wifi.app,         name="wifi")
app.add_typer(threatintel.app,  name="threat")
app.add_typer(container.app,    name="container")
app.add_typer(redteam.app,      name="redteam")
app.add_typer(blue.app,         name="blueteam")
app.add_typer(sslscan.app,      name="sslscan")
app.add_typer(keycloaksec.app,  name="keycloak")


# ======================================================
# REGISTER AI MODULE
# ======================================================
app.add_typer(ai_app, name="ai")

# ======================================================
# REGISTER EXTENDED SECURITY DOMAINS
# ======================================================
app.add_typer(cloudsec.app,     name="cloud")
app.add_typer(mobilesec.app,    name="mobile")
app.add_typer(apisec.app,       name="api")
app.add_typer(malwarenet.app,   name="malware")
app.add_typer(supplychain.app,  name="supplychain")
app.add_typer(iotsec.app,       name="iot")
app.add_typer(darknet.app,      name="darknet")

# ======================================================
# REGISTER GOVERNANCE & CONTROL ENGINES
# (ORDER MATTERS — THIS IS YOUR USP)
# ======================================================
app.add_typer(engagement.app,   name="engagement")     # scope, ROE
app.add_typer(consent.app,      name="consent")        # legal proof
app.add_typer(assets.app,       name="assets")         # inventory brain
app.add_typer(vuln.app,         name="vuln")           # vuln lifecycle
app.add_typer(risk.app,         name="risk")           # business impact
app.add_typer(attackpath.app,   name="attackpath")     # kill-chain
app.add_typer(compliance.app,   name="compliance")     # ISO/NIST/etc
app.add_typer(knowledge.app,    name="knowledge")      # graph engine
app.add_typer(automation.app,   name="automation")     # safety guard

# ======================================================
# MAIN ENTRYPOINT
# ======================================================
def main():
    """
    Entry point for CyberCLI
    - No args  → cinematic intro
    - With args → direct CLI execution
    """

    if len(sys.argv) > 1:
        app()
        return

    try:
        run_advanced_intro()
    except Exception as e:
        rprint(f"[red]Intro animation failed:[/red] {e}")

    app()


if __name__ == "__main__":
    main()


# # #First Phase
# # # cybercli/main.py

# # import typer
# # import sys
# # from rich import print as rprint
# # from cybercli.plugins.intro_animation import run_advanced_intro

# # from cybercli.plugins import (
# #     recon, scan, exploit, privesc, websec,
# #     ad, forensics, wifi, threatintel,
# #     container, redteam, blue
# # )

# # app = typer.Typer(help="One-Man-Army Cyber CLI")

# # app.add_typer(recon.app, name="recon")
# # app.add_typer(scan.app, name="scan")
# # app.add_typer(exploit.app, name="exploit")
# # app.add_typer(privesc.app, name="privesc")
# # app.add_typer(websec.app, name="websec")
# # app.add_typer(ad.app, name="activeDirectory")
# # app.add_typer(forensics.app, name="forensic")
# # app.add_typer(wifi.app, name="wifi")
# # app.add_typer(threatintel.app, name="threat")
# # app.add_typer(container.app, name="container")
# # app.add_typer(redteam.app, name="redteam")
# # app.add_typer(blue.app, name="blueteam")

# # def main():
# #     if len(sys.argv) > 1:
# #         app()
# #         return
# #     try:
# #         run_advanced_intro()
# #     except Exception as e:
# #         rprint(f"[red]Animation error:[/red] {e}")
# #     app()

# # if __name__ == "__main__":
# #     main()


# #SecondPhase
# # # cybercli/main.py — FINAL ERROR-FREE VERSION

# # import typer
# # import sys
# # from rich import print as rprint

# # from cybercli.plugins.intro_animation import run_advanced_intro

# # # Import plugin modules
# # from cybercli.plugins import (
# #     recon, scan, exploit, privesc, websec,
# #     ad, forensics, wifi, threatintel,
# #     container, redteam, blue
# # )

# # app = typer.Typer(help="One-Man-Army Cyber CLI")

# # # Register modules
# # app.add_typer(recon.app, name="recon")
# # app.add_typer(scan.app, name="scan")
# # app.add_typer(exploit.app, name="exploit")
# # app.add_typer(privesc.app, name="privesc")
# # app.add_typer(websec.app, name="websec")
# # app.add_typer(ad.app, name="activeDirectory")
# # app.add_typer(forensics.app, name="forensic")
# # app.add_typer(wifi.app, name="wifi")
# # app.add_typer(threatintel.app, name="threat")
# # app.add_typer(container.app, name="container")
# # app.add_typer(redteam.app, name="redteam")
# # app.add_typer(blue.app, name="blueteam")

# # def main():
# #     # If user passed arguments → skip intro
# #     if len(sys.argv) > 1:
# #         app()
# #         return

# #     # Otherwise play cinematic intro
# #     try:
# #         run_advanced_intro()
# #     except Exception as e:
# #         rprint(f"[red]Animation error:[/red] {e}")

# #     app()

# # if __name__ == "__main__":
# #     main()



# #------------------

# # # cybercli/main.py — FINAL 20-MODULE EDITION

# # import typer
# # import sys
# # from rich import print as rprint

# # from cybercli.plugins.intro_animation import run_advanced_intro

# # # === CORE BUILT-IN 12 MODULES ===
# # from cybercli.plugins import (
# #     recon, scan, exploit, privesc, websec,
# #     ad, forensics, wifi, threatintel,
# #     container, redteam, blue
# # )

# # # === NEW GEN-AI MODULES (8 AI SUBMODULES INSIDE) ===
# # from cybercli.plugins.ai import ai_app

# # # === NEW 7 TOP-LEVEL MODULES ===
# # from cybercli.plugins import (
# #     cloudsec,
# #     mobilesec,
# #     apisec,
# #     malwarenet as malwarelab,   # FIXED: correct import for malware module
# #     supplychain,
# #     iotsec,
# #     darknet
# # )

# # # MAIN APP
# # app = typer.Typer(help="⚡ One-Man-Army CyberCLI — 20 Modules Activated")


# # # ------------------------------------------------------
# # # REGISTER OLD 12 MODULES
# # # ------------------------------------------------------
# # app.add_typer(recon.app,        name="recon")
# # app.add_typer(scan.app,         name="scan")
# # app.add_typer(exploit.app,      name="exploit")
# # app.add_typer(privesc.app,      name="privesc")
# # app.add_typer(websec.app,       name="websec")
# # app.add_typer(ad.app,           name="activeDirectory")
# # app.add_typer(forensics.app,    name="forensic")
# # app.add_typer(wifi.app,         name="wifi")
# # app.add_typer(threatintel.app,  name="threat")
# # app.add_typer(container.app,    name="container")
# # app.add_typer(redteam.app,      name="redteam")
# # app.add_typer(blue.app,         name="blueteam")


# # # ------------------------------------------------------
# # # REGISTER AI SUPER-MODULE (with 8 subtools inside)
# # # ------------------------------------------------------
# # app.add_typer(ai_app, name="ai")


# # # ------------------------------------------------------
# # # REGISTER NEW 7 MAJOR SECURITY MODULES
# # # ------------------------------------------------------
# # app.add_typer(cloudsec.app,      name="cloud")
# # app.add_typer(mobilesec.app,     name="mobile")
# # app.add_typer(apisec.app,        name="api")
# # app.add_typer(malwarelab.app,    name="malware")
# # app.add_typer(supplychain.app,   name="supply")
# # app.add_typer(iotsec.app,        name="iot")
# # app.add_typer(darknet.app,       name="darknet")


# # # ------------------------------------------------------
# # # MAIN ENTRY LOGIC
# # # ------------------------------------------------------
# # def main():
# #     # If CLI used → skip animation
# #     if len(sys.argv) > 1:
# #         app()
# #         return

# #     # Otherwise play the cinematic intro
# #     try:
# #         run_advanced_intro()
# #     except Exception as e:
# #         rprint(f"[red]Intro animation error:[/red] {e}")

# #     app()


# # if __name__ == "__main__":
# #     main()





# # # cybercli/main.py — FINAL 20+ MODULE ENTERPRISE EDITION

# # import typer
# # import sys
# # from rich import print as rprint

# # from cybercli.plugins.intro_animation import run_advanced_intro

# # # ======================================================
# # # CORE BUILT-IN 12 MODULES (STABLE)
# # # ======================================================
# # from cybercli.plugins import (
# #     recon,
# #     scan,
# #     exploit,
# #     privesc,
# #     websec,
# #     ad,
# #     forensics,
# #     wifi,
# #     threatintel,
# #     container,
# #     redteam,
# #     blue,
# # )

# # # ======================================================
# # # AI SUPER-MODULE (8 SUBMODULES INSIDE)
# # # ======================================================
# # from cybercli.plugins.ai import ai_app

# # # ======================================================
# # # NEXT-GEN TOP LEVEL MODULES
# # # ======================================================
# # from cybercli.plugins import (
# #     cloudsec,
# #     mobilesec,
# #     apisec,
# #     malwarenet as malwarelab,  # alias safe
# #     supplychain,
# #     iotsec,
# #     darknet,
# # )

# # # ======================================================
# # # GOVERNANCE & AUTOMATION ENGINES (PHASE 1–10)
# # # ======================================================
# # from cybercli.plugins import automation

# # # ======================================================
# # # MAIN CLI APP
# # # ======================================================
# # app = typer.Typer(
# #     help="⚡ One-Man-Army CyberCLI — Governed Offensive & Defensive Security Platform"
# # )

# # # ------------------------------------------------------
# # # REGISTER CORE 12 MODULES
# # # ------------------------------------------------------
# # app.add_typer(recon.app,       name="recon")
# # app.add_typer(scan.app,        name="scan")
# # app.add_typer(exploit.app,     name="exploit")
# # app.add_typer(privesc.app,     name="privesc")
# # app.add_typer(websec.app,      name="websec")
# # app.add_typer(ad.app,          name="activeDirectory")
# # app.add_typer(forensics.app,   name="forensic")
# # app.add_typer(wifi.app,        name="wifi")
# # app.add_typer(threatintel.app, name="threat")
# # app.add_typer(container.app,   name="container")
# # app.add_typer(redteam.app,     name="redteam")
# # app.add_typer(blue.app,        name="blueteam")

# # # ------------------------------------------------------
# # # REGISTER AI MODULE
# # # ------------------------------------------------------
# # app.add_typer(ai_app, name="ai")

# # # ------------------------------------------------------
# # # REGISTER NEW SECURITY DOMAINS
# # # ------------------------------------------------------
# # app.add_typer(cloudsec.app,    name="cloud")
# # app.add_typer(mobilesec.app,   name="mobile")
# # app.add_typer(apisec.app,      name="api")
# # app.add_typer(malwarelab.app,  name="malware")
# # app.add_typer(supplychain.app, name="supply")
# # app.add_typer(iotsec.app,      name="iot")
# # app.add_typer(darknet.app,     name="darknet")

# # # ------------------------------------------------------
# # # REGISTER SAFE AUTOMATION ENGINE (PHASE 10)
# # # ------------------------------------------------------
# # app.add_typer(automation.app, name="automation")

# # # ------------------------------------------------------
# # # MAIN ENTRYPOINT
# # # ------------------------------------------------------
# # def main():
# #     # If arguments passed → skip intro animation
# #     if len(sys.argv) > 1:
# #         app()
# #         return

# #     # Otherwise run cinematic intro
# #     try:
# #         run_advanced_intro()
# #     except Exception as e:
# #         rprint(f"[red]Intro animation error:[/red] {e}")

# #     app()


# # if __name__ == "__main__":
# #     main()





# ##Final version that to be test
# # cybercli/main.py
# # ⚡ CyberCLI — Unified Ethical Hacking & Security Governance Platform

# import sys
# import typer
# from rich import print as rprint

# from cybercli.plugins.intro_animation import run_advanced_intro

# # ======================================================
# # BASE APP
# # ======================================================
# app = typer.Typer(
#     help="⚡ CyberCLI — Offensive, Defensive & Governed Security Platform"
# )

# # ======================================================
# # CORE SECURITY MODULES (FOUNDATION)
# # ======================================================
# from cybercli.plugins import (
#     recon,
#     scan,
#     exploit,
#     privesc,
#     websec,
#     ad,
#     forensics,
#     wifi,
#     threatintel,
#     container,
#     redteam,
#     blue,
#     sslscan,
#     keycloaksec
# )

# # ======================================================
# # AI SUPER MODULE (MULTI-SUBSYSTEM)
# # ======================================================
# from cybercli.plugins.ai import ai_app

# # ======================================================
# # EXTENDED SECURITY DOMAINS
# # ======================================================
# from cybercli.plugins import (
#     cloudsec,
#     mobilesec,
#     apisec,
#     malwarenet,
#     supplychain,
#     iotsec,
#     darknet,
# )

# # ======================================================
# # GOVERNANCE & INTELLIGENCE ENGINES
# # ======================================================
# from cybercli.plugins import (
#     engagement,
#     consent,
#     assets,
#     vuln,
#     risk,
#     attackpath,
#     compliance,
#     knowledge,
#     automation,
# )

# # ======================================================
# # REGISTER CORE SECURITY MODULES
# # ======================================================
# app.add_typer(recon.app,        name="recon")
# app.add_typer(scan.app,         name="scan")
# app.add_typer(exploit.app,      name="exploit")
# app.add_typer(privesc.app,      name="privesc")
# app.add_typer(websec.app,       name="websec")
# app.add_typer(ad.app,           name="activeDirectory")
# app.add_typer(forensics.app,    name="forensic")
# app.add_typer(wifi.app,         name="wifi")
# app.add_typer(threatintel.app,  name="threat")
# app.add_typer(container.app,    name="container")
# app.add_typer(redteam.app,      name="redteam")
# app.add_typer(blue.app,         name="blueteam")
# app.add_typer(sslscan.app,      name="sslscan")
# app.add_typer(keycloaksec.app,  name="keycloak")


# # ======================================================
# # REGISTER AI MODULE
# # ======================================================
# app.add_typer(ai_app, name="ai")

# # ======================================================
# # REGISTER EXTENDED SECURITY DOMAINS
# # ======================================================
# app.add_typer(cloudsec.app,     name="cloud")
# app.add_typer(mobilesec.app,    name="mobile")
# app.add_typer(apisec.app,       name="api")
# app.add_typer(malwarenet.app,   name="malware")
# app.add_typer(supplychain.app,  name="supplychain")
# app.add_typer(iotsec.app,       name="iot")
# app.add_typer(darknet.app,      name="darknet")

# # ======================================================
# # REGISTER GOVERNANCE & CONTROL ENGINES
# # (ORDER MATTERS — THIS IS YOUR USP)
# # ======================================================
# app.add_typer(engagement.app,   name="engagement")     # scope, ROE
# app.add_typer(consent.app,      name="consent")        # legal proof
# app.add_typer(assets.app,       name="assets")         # inventory brain
# app.add_typer(vuln.app,         name="vuln")           # vuln lifecycle
# app.add_typer(risk.app,         name="risk")           # business impact
# app.add_typer(attackpath.app,   name="attackpath")     # kill-chain
# app.add_typer(compliance.app,   name="compliance")     # ISO/NIST/etc
# app.add_typer(knowledge.app,    name="knowledge")      # graph engine
# app.add_typer(automation.app,   name="automation")     # safety guard

# # ======================================================
# # MAIN ENTRYPOINT
# # ======================================================
# def main():
#     """
#     Entry point for CyberCLI
#     - No args  → cinematic intro
#     - With args → direct CLI execution
#     """

#     if len(sys.argv) > 1:
#         app()
#         return

#     try:
#         run_advanced_intro()
#     except Exception as e:
#         rprint(f"[red]Intro animation failed:[/red] {e}")

#     app()


# if __name__ == "__main__":
#     main()

# cybercli/main.py
# ⚡ CyberCLI — Unified Ethical Hacking & Security Governance Platform
# + AI-Powered VAPT Engine (ZAP-style · Better · Less False Positives)

import sys
import typer
from rich import print as rprint
from rich.console import Console

console = Console()

from cybercli.plugins.intro_animation import run_advanced_intro

# ======================================================
# BASE APP
# ======================================================
app = typer.Typer(
    help="⚡ CyberCLI — Offensive, Defensive & Governed Security Platform"
)

# ======================================================
# CORE SECURITY MODULES (FOUNDATION)
# ======================================================
from cybercli.plugins import (
    recon,
    scan,
    exploit,
    privesc,
    websec,
    ad,
    forensics,
    wifi,
    threatintel,
    container,
    redteam,
    blue,
    sslscan,
    keycloaksec
)

# ======================================================
# AI SUPER MODULE (MULTI-SUBSYSTEM)
# ======================================================
from cybercli.plugins.ai import ai_app

# ======================================================
# EXTENDED SECURITY DOMAINS
# ======================================================
from cybercli.plugins import (
    cloudsec,
    mobilesec,
    apisec,
    malwarenet,
    supplychain,
    iotsec,
    darknet,
)

# ======================================================
# GOVERNANCE & INTELLIGENCE ENGINES
# ======================================================
from cybercli.plugins import (
    engagement,
    consent,
    assets,
    vuln,
    risk,
    attackpath,
    compliance,
    knowledge,
    automation,
)

# ======================================================
# REGISTER CORE SECURITY MODULES
# ======================================================
app.add_typer(recon.app,        name="recon")
app.add_typer(scan.app,         name="scan")
app.add_typer(exploit.app,      name="exploit")
app.add_typer(privesc.app,      name="privesc")
app.add_typer(websec.app,       name="websec")
app.add_typer(ad.app,           name="activeDirectory")
app.add_typer(forensics.app,    name="forensic")
app.add_typer(wifi.app,         name="wifi")
app.add_typer(threatintel.app,  name="threat")
app.add_typer(container.app,    name="container")
app.add_typer(redteam.app,      name="redteam")
app.add_typer(blue.app,         name="blueteam")
app.add_typer(sslscan.app,      name="sslscan")
app.add_typer(keycloaksec.app,  name="keycloak")

# ======================================================
# REGISTER AI MODULE
# ======================================================
app.add_typer(ai_app, name="ai")

# ======================================================
# REGISTER EXTENDED SECURITY DOMAINS
# ======================================================
app.add_typer(cloudsec.app,     name="cloud")
app.add_typer(mobilesec.app,    name="mobile")
app.add_typer(apisec.app,       name="api")
app.add_typer(malwarenet.app,   name="malware")
app.add_typer(supplychain.app,  name="supplychain")
app.add_typer(iotsec.app,       name="iot")
app.add_typer(darknet.app,      name="darknet")

# ======================================================
# REGISTER GOVERNANCE & CONTROL ENGINES
# (ORDER MATTERS — THIS IS YOUR USP)
# ======================================================
app.add_typer(engagement.app,   name="engagement")     # scope, ROE
app.add_typer(consent.app,      name="consent")        # legal proof
app.add_typer(assets.app,       name="assets")         # inventory brain
app.add_typer(vuln.app,         name="vuln")           # vuln lifecycle
app.add_typer(risk.app,         name="risk")           # business impact
app.add_typer(attackpath.app,   name="attackpath")     # kill-chain
app.add_typer(compliance.app,   name="compliance")     # ISO/NIST/etc
app.add_typer(knowledge.app,    name="knowledge")      # graph engine
app.add_typer(automation.app,   name="automation")     # safety guard

# ======================================================
# ZAP ENGINE — AI-Powered VAPT (NEW · ISOLATED)
# Spider → Passive → Active → AI Validation → Graph → Report
# Safe: if this fails, NOTHING above breaks
# ======================================================
try:
    from cybercli.plugins.zapengine import app as zap_app
    app.add_typer(
        zap_app,
        name="zap",
        help="🔥 Full VAPT — Spider → Active Scan → AI → Attack Graph → Report"
    )
except Exception as _e:
    console.print(f"[dim yellow]⚠  ZAP engine unavailable: {_e}[/dim yellow]")

# ======================================================
# ATTACK GRAPH ENGINE — Maltego/BloodHound Style (NEW · ISOLATED)
# Subdomain · Cloud · K8s · Trust Paths · Attack Chains
# Safe: if this fails, NOTHING above breaks
# ======================================================
try:
    _graph_app = typer.Typer(
        help="🕸  Attack Graph — Domain · Cloud · Trust Paths · Kill Chains"
    )

    @_graph_app.command("build")
    def _graph_build(
        target: str = typer.Option(..., "--target", "-t", help="Target domain or URL"),
        output: str = typer.Option("artifacts/attack_graphs", "--output", "-o", help="Output directory"),
    ):
        """Build and display Maltego-style attack graph for a target"""
        import asyncio, os, time
        from cybercli.core.attackgraph.graph_builder import AttackGraph

        console.print(f"[cyan]⬡  Building attack graph:[/cyan] {target}")
        graph = asyncio.run(AttackGraph(target).build())
        console.print(graph.render_terminal())
        os.makedirs(output, exist_ok=True)
        path = os.path.join(output, f"graph_{int(time.time())}.json")
        graph.export_json(path)
        console.print(f"\n[green]✓  Graph saved:[/green] {path}")

    app.add_typer(_graph_app, name="graph")

except Exception as _e:
    console.print(f"[dim yellow]⚠  Graph engine unavailable: {_e}[/dim yellow]")
    

# ════════════════════════════════════════════════════════════
# ADD THIS BLOCK TO YOUR EXISTING cybercli/main.py
# Place AFTER all your existing app.add_typer() calls
# FULLY ISOLATED — if burpnext fails, nothing else breaks
# ════════════════════════════════════════════════════════════

try:
    from cybercli.plugins.burpnext import app as burpnext_app
    app.add_typer(
        burpnext_app,
        name="burp",
        help="🔥 BurpNext — Full WAPT · OWASP Top 10 · Better than Burp Suite Pro"
    )
except Exception as _burp_err:
    # BurpNext failed to load — other modules unaffected
    try:
        console.print(f"[dim yellow]⚠  BurpNext unavailable: {_burp_err}[/dim yellow]")
    except Exception:
        pass


 
   


# ======================================================
# MAIN ENTRYPOINT
# ======================================================
def main():
    """
    Entry point for CyberCLI
    - No args  → cinematic intro
    - With args → direct CLI execution
    """
    if len(sys.argv) > 1:
        app()
        return

    try:
        run_advanced_intro()
    except Exception as e:
        rprint(f"[red]Intro animation failed:[/red] {e}")

    app()


if __name__ == "__main__":
    main()
