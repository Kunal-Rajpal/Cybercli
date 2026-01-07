"""
RISK & BUSINESS IMPACT ENGINE
----------------------------
Transforms vulnerabilities into business-level risk
"""

from pathlib import Path
from datetime import datetime
import json

RISK_DB = Path("artifacts/risk_register.json")


class RiskEngine:
    def __init__(self):
        RISK_DB.parent.mkdir(parents=True, exist_ok=True)
        if not RISK_DB.exists():
            RISK_DB.write_text(json.dumps({"risks": []}, indent=2))

    def _read(self):
        return json.loads(RISK_DB.read_text())

    def _write(self, data):
        RISK_DB.write_text(json.dumps(data, indent=2))

    # -------------------------------------------------
    # CALCULATE BUSINESS IMPACT SCORE
    # -------------------------------------------------
    def calculate_impact_score(
        self,
        financial: int,
        operational: int,
        compliance: int,
        reputation: int,
        strategic: int,
    ) -> int:
        """
        Scores: 1 (low) → 5 (critical)
        """
        return round(
            (financial * 0.3) +
            (operational * 0.2) +
            (compliance * 0.2) +
            (reputation * 0.2) +
            (strategic * 0.1)
        )

    # -------------------------------------------------
    # REGISTER RISK
    # -------------------------------------------------
    def register_risk(
        self,
        vuln_id: str,
        likelihood: int,
        impact_breakdown: dict,
        affected_service: str,
        owner: str,
    ):
        impact_score = self.calculate_impact_score(**impact_breakdown)

        overall_risk = round((likelihood * impact_score) / 5)

        risk_level = self.map_risk(overall_risk)

        risk = {
            "risk_id": f"RISK-{len(self._read()['risks'])+1:05}",
            "vuln_id": vuln_id,
            "affected_service": affected_service,

            "likelihood": likelihood,
            "impact_score": impact_score,
            "overall_risk_score": overall_risk,
            "risk_level": risk_level,

            "impact_breakdown": impact_breakdown,
            "owner": owner,

            "status": "OPEN",
            "created": datetime.utcnow().isoformat(),
        }

        data = self._read()
        data["risks"].append(risk)
        self._write(data)
        return risk

    # -------------------------------------------------
    # RISK MAPPING
    # -------------------------------------------------
    def map_risk(self, score: int) -> str:
        if score >= 4:
            return "CRITICAL"
        if score >= 3:
            return "HIGH"
        if score >= 2:
            return "MEDIUM"
        return "LOW"

    # -------------------------------------------------
    # LIST RISKS
    # -------------------------------------------------
    def list(self, level: str = None):
        risks = self._read()["risks"]
        if level:
            risks = [r for r in risks if r["risk_level"] == level]
        return risks

