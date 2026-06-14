# cybercli/plugins/cloudsec.py
import json
import typer
from rich.console import Console
from pathlib import Path

console = Console()
app = typer.Typer(help="Cloud security helpers (safe analysis)")

def load_json(path: str):
    p = Path(path)
    if not p.exists():
        console.print(f"[red]File not found: {path}[/red]")
        raise typer.Exit()
    return json.loads(p.read_text(encoding="utf-8"))

@app.command("aws-enum")
def aws_enum(cfg: str = typer.Option(..., "--config", "-c", help="AWS exported JSON (sts/iam resources)")):
    data = load_json(cfg)
    findings = []
    # safe heuristics
    for user in data.get("iam_users", []):
        if user.get("password_last_used") is None:
            findings.append(f"User {user.get('user_name')} might not have used password recently.")
    console.print({"summary": f"{len(findings)} findings", "findings": findings})

@app.command("s3-audit")
def s3_audit(cfg: str = typer.Option(..., help="S3 inventory JSON")):
    data = load_json(cfg)
    issues = []
    for b in data.get("buckets", []):
        if b.get("public", False):
            issues.append({"bucket": b["name"], "issue": "public"})
    console.print({"buckets_scanned": len(data.get("buckets", [])), "issues": issues})

@app.command("iam-weak-keys")
def iam_weak_keys(cfg: str = typer.Option(..., help="IAM credentials JSON")):
    data = load_json(cfg)
    weak = []
    for cred in data.get("credentials", []):
        if cred.get("access_key_age_days", 0) > 365:
            weak.append(cred)
    console.print({"weak_keys": len(weak), "items": weak})

@app.command("cloud-attack-path")
def cloud_attack_path(cfgs: str = typer.Option(..., help="JSON list file describing resources and relations")):
    data = load_json(cfgs)
    # safe: produce a graph-like summary showing risky links
    paths = []
    for rel in data.get("relations", [])[:30]:
        if rel.get("privilege") == "high":
            paths.append(rel)
    console.print({"risk_paths_count": len(paths), "paths_sample": paths[:10]})

