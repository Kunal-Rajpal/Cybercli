"""
ATTACK PATH & KILL CHAIN ENGINE
--------------------------------
Builds realistic attacker paths using graph logic
"""

from pathlib import Path
from datetime import datetime
import json

DB = Path("artifacts/attack_paths.json")


class AttackPathEngine:
    def __init__(self):
        DB.parent.mkdir(parents=True, exist_ok=True)
        if not DB.exists():
            DB.write_text(json.dumps({"paths": []}, indent=2))

    def _read(self):
        return json.loads(DB.read_text())

    def _write(self, data):
        DB.write_text(json.dumps(data, indent=2))

    # -----------------------------------------
    # CREATE ATTACK PATH
    # -----------------------------------------
    def create_path(
        self,
        entry_asset: str,
        target_asset: str,
        techniques: list,
        likelihood: int,
        impact: str,
    ):
        """
        techniques = list of dicts:
        {
            phase: "Initial Access",
            technique_id: "T1190",
            name: "Exploit Public-Facing App",
            description: "Unauth RCE on API"
        }
        """

        path = {
            "path_id": f"PATH-{len(self._read()['paths'])+1:05}",
            "entry_asset": entry_asset,
            "target_asset": target_asset,
            "kill_chain": techniques,
            "steps": len(techniques),
            "likelihood": likelihood,
            "impact": impact,
            "risk_level": self._risk(likelihood, len(techniques)),
            "created": datetime.utcnow().isoformat(),
        }

        data = self._read()
        data["paths"].append(path)
        self._write(data)
        return path

    # -----------------------------------------
    # RISK CALCULATION
    # -----------------------------------------
    def _risk(self, likelihood, steps):
        score = (likelihood * steps) / 5
        if score >= 4:
            return "CRITICAL"
        if score >= 3:
            return "HIGH"
        if score >= 2:
            return "MEDIUM"
        return "LOW"

    # -----------------------------------------
    # LIST PATHS
    # -----------------------------------------
    def list_paths(self):
        return self._read()["paths"]

