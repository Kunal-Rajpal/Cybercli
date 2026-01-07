# cybercli/plugins/ai/__init__.py
import typer

from .recon import ai_recon_app
from .osint import ai_osint_app
from .exploit import ai_exploit_app
from .defense import ai_defense_app
from .predict import ai_predict_app
from .correlate import ai_correlate_app
from .classifier import ai_classifier_app
from .report import ai_report_app

ai_app = typer.Typer(name="ai", help="AI-powered Cyber Suite (recon, osint, exploit-sim, defense, predict, correlate, classify, report)")

ai_app.add_typer(ai_recon_app, name="recon")
ai_app.add_typer(ai_osint_app, name="osint")
ai_app.add_typer(ai_exploit_app, name="exploit")
ai_app.add_typer(ai_defense_app, name="defense")
ai_app.add_typer(ai_predict_app, name="predict")
ai_app.add_typer(ai_correlate_app, name="correlate")
ai_app.add_typer(ai_classifier_app, name="classifier")
ai_app.add_typer(ai_report_app, name="report")

