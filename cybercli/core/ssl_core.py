import subprocess
import json
from pathlib import Path

REPORT_DIR = Path("reports/ssl")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

def run_testssl(target: str):
    """Runs testssl and returns JSON data"""
    cmd = ["testssl", "--jsonfile", "-", target]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def save_html(target: str, html_body: str):
    filename = REPORT_DIR / f"{target.replace(':','_')}.html"
    filename.write_text(html_body, encoding="utf-8")
    return filename

