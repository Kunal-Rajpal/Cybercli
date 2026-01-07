## First Phase Testing------
# # Keycloak CLI Plugin – FINAL
# # Domain → Redirect → Login → Screenshots → Reports

# import typer
# from rich.console import Console
# from rich.panel import Panel
# from rich.prompt import Confirm, Prompt
# from cybercli.core.keycloaksec_core import KeycloakSecCore

# app = typer.Typer()
# console = Console()


# def banner():
#     console.print(Panel.fit(
#         "[bold magenta]🔥 KEYCLOAK SECURITY SCANNER — FINAL[/bold magenta]\n"
#         "[cyan]Auto Redirect • UI Login • Screenshots • Reports[/cyan]",
#         border_style="magenta"
#     ))


# @app.command("scan")
# def scan(
#     target: str = typer.Argument(..., help="Domain or full URL")
# ):
#     banner()
#     console.print(f"[yellow]🚀 Target:[/yellow] [green]{target}[/green]")

#     engine = KeycloakSecCore(target, headless=True)

#     creds = None
#     if Confirm.ask("Do you want to login with username/password?", default=False):
#         creds = {
#             "username": Prompt.ask("Username"),
#             "password": Prompt.ask("Password", password=True)
#         }

#     console.print("\n[magenta]⚡ Running scan...[/magenta]")
#     result = engine.run(creds)

#     console.print("\n[green]✔ Scan complete[/green]")
#     console.print("[cyan]Evidence → reports/output/evidence[/cyan]")
#     console.print("[cyan]JSON     → reports/output/logs/results.json[/cyan]")
#     console.print("[cyan]HTML     → reports/output/html/index.html[/cyan]")


# def main():
#     app()


# if __name__ == "__main__":
#     main()



## Second Phase Testing --------
# # cybercli/plugins/keycloaksec.py
# # Keycloak Security CLI — FINAL

# import typer
# from rich.console import Console
# from rich.panel import Panel
# from rich.prompt import Confirm, Prompt

# from cybercli.core.keycloaksec_core import KeycloakSecCore

# app = typer.Typer()
# console = Console()


# def banner():
#     console.print(Panel.fit(
#         "🔥 KEYCLOAK SECURITY SCANNER — FINAL\n"
#         "Auto Redirect • UI Login • Screenshots • Reports",
#         border_style="cyan"
#     ))


# @app.command("scan")
# def scan(target: str):
#     banner()
#     console.print(f"[yellow]🚀 Target:[/yellow] [green]{target}[/green]")

#     engine = KeycloakSecCore(target, headless=True)

#     creds = None
#     if Confirm.ask("Do you want to login with username/password?"):
#         creds = {
#             "username": Prompt.ask("Username"),
#             "password": Prompt.ask("Password", password=True)
#         }

#     console.print("[magenta]⚡ Running scan...[/magenta]")
#     result = engine.run(creds)

#     console.print("[green]✔ Scan complete[/green]")
#     console.print("[cyan]Evidence → reports/output/evidence[/cyan]")
#     console.print("[cyan]Report → reports/output/reports/result.json[/cyan]")


# def main():
#     app()


# if __name__ == "__main__":
#     main()



# ## Third Phase Testing -----------
# # cybercli/plugins/keycloaksec.py
# # Keycloak Security CLI — FINAL EXTENDED

# import typer
# from rich.console import Console
# from rich.panel import Panel
# from rich.prompt import Confirm, Prompt
# from cybercli.core.keycloaksec_core import KeycloakSecCore

# app = typer.Typer()
# console = Console()


# def banner():
#     console.print(Panel.fit(
#         "🔥 KEYCLOAK SECURITY SCANNER — FINAL EXTENDED\n"
#         "Auto Redirect • Dynamic Login • OWASP Intelligence • Screenshots",
#         border_style="cyan"
#     ))


# @app.command("scan")
# def scan(target: str):
#     banner()
#     console.print(f"[yellow]🚀 Target:[/yellow] [green]{target}[/green]")

#     engine = KeycloakSecCore(target, headless=True)

#     creds = None
#     if Confirm.ask("Do you want to login with username/password?"):
#         creds = {
#             "username": Prompt.ask("Username"),
#             "password": Prompt.ask("Password", password=True)
#         }

#     console.print("[magenta]⚡ Running scan...[/magenta]")
#     engine.run(creds)

#     console.print("[green]✔ Scan complete[/green]")
#     console.print("[cyan]Evidence → reports/output/evidence[/cyan]")
#     console.print("[cyan]Report → reports/output/reports/result.json[/cyan]")


# def main():
#     app()


# if __name__ == "__main__":
#     main()




# cybercli/plugins/keycloaksec.py
# KEYCLOAK SECURITY CLI — STABLE FINAL

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from cybercli.core.keycloaksec_core import KeycloakSecCore

app = typer.Typer()
console = Console()


def banner():
    console.print(Panel.fit(
        "🔥 KEYCLOAK SECURITY SCANNER — FULL ENGINE\n"
        "UI Login • Screenshots • OWASP • Tokens • PDF Report",
        border_style="cyan"
    ))


@app.command("scan")
def scan(target: str):
    banner()
    console.print(f"[yellow]🎯 Target:[/yellow] [green]{target}[/green]")

    engine = KeycloakSecCore(target, headless=True)

    creds = None
    if Confirm.ask("UI login (safe, no brute)?"):
        creds = {
            "username": Prompt.ask("Username"),
            "password": Prompt.ask("Password", password=True)
        }

    console.print("[magenta]⚡ Running scan...[/magenta]")
    engine.run(creds)

    console.print("[green]✔ Scan complete[/green]")
    console.print("[cyan]📸 Evidence → reports/output/evidence[/cyan]")
    console.print("[cyan]📄 JSON → reports/output/reports/result.json[/cyan]")
    console.print("[cyan]📕 PDF → reports/output/pdf/keycloak_report.pdf[/cyan]")


def main():
    app()


if __name__ == "__main__":
    main()



