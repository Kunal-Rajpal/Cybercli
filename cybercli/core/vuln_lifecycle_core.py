"""
VULNERABILITY LIFECYCLE ENGINE
------------------------------
Tracks vulnerabilities end-to-end:
- Discovery
- Attack Vector
- Severity vs Risk
- Fix & Verification
"""

from pathlib import Path
from datetime import datetime
import json
from typing import Dict, List


VULN_DB = Path("artifacts/vulnerabilities.json")


class VulnerabilityCore:
    def __init__(self):
        VULN_DB.parent.mkdir(parents=True, exist_ok=True)
        if not VULN_DB.exists():
            self._write({"vulnerabilities": []})

    def _read(self) -> Dict:
        return json.loads(VULN_DB.read_text())

    def _write(self, data: Dict):
        VULN_DB.write_text(json.dumps(data, indent=2))

    # -------------------------------------------------
    # ADD VULNERABILITY
    # -------------------------------------------------
    def add_vulnerability(
        self,
        engagement_id: str,
        asset_id: str,
        title: str,
        category: str,
        attack_vector: str,
        description: str,
        severity: str,
        confidence: str,
        discovered_by: str,
        references: List[str] = None,
    ):
        data = self._read()

        vuln = {
            "vuln_id": f"VULN-{len(data['vulnerabilities'])+1:06}",
            "engagement_id": engagement_id,
            "asset_id": asset_id,

            "title": title,
            "category": category,                # web | network | cloud | auth | logic
            "attack_vector": attack_vector,      # external | internal | adjacent
            "description": description,

            "severity": severity,                # info | low | medium | high | critical
            "confidence": confidence,            # low | medium | high

            "business_impact": "unknown",
            "risk_rating": "unrated",

            "status": "DISCOVERED",

            "evidence": [],
            "references": references or [],

            "discovered_by": discovered_by,
            "timestamps": {
                "discovered": datetime.utcnow().isoformat(),
                "last_update": datetime.utcnow().isoformat(),
            }
        }

        data["vulnerabilities"].append(vuln)
        self._write(data)
        return vuln

    # -------------------------------------------------
    # ADD EVIDENCE
    # -------------------------------------------------
    def add_evidence(self, vuln_id: str, evidence: str):
        data = self._read()
        for v in data["vulnerabilities"]:
            if v["vuln_id"] == vuln_id:
                v["evidence"].append({
                    "data": evidence,
                    "time": datetime.utcnow().isoformat()
                })
                v["timestamps"]["last_update"] = datetime.utcnow().isoformat()
                self._write(data)
                return v
        raise ValueError("Vulnerability not found")

    # -------------------------------------------------
    # TRIAGE (RISK CALCULATION)
    # -------------------------------------------------
    def triage(
        self,
        vuln_id: str,
        business_impact: str,
        exploitability: str,
    ):
        """
        Risk logic (simple but real):
        severity + exploitability + business impact
        """
        data = self._read()

        for v in data["vulnerabilities"]:
            if v["vuln_id"] == vuln_id:
                v["business_impact"] = business_impact

                risk_matrix = {
                    ("critical", "high"): "critical",
                    ("high", "high"): "high",
                    ("medium", "high"): "high",
                    ("medium", "medium"): "medium",
                    ("low", "high"): "medium",
                }

                key = (v["severity"], exploitability)
                v["risk_rating"] = risk_matrix.get(key, "low")
                v["status"] = "TRIAGED"
                v["timestamps"]["last_update"] = datetime.utcnow().isoformat()

                self._write(data)
                return v

        raise ValueError("Vulnerability not found")

    # -------------------------------------------------
    # STATUS UPDATE
    # -------------------------------------------------
    def update_status(self, vuln_id: str, status: str):
        data = self._read()
        for v in data["vulnerabilities"]:
            if v["vuln_id"] == vuln_id:
                v["status"] = status
                v["timestamps"]["last_update"] = datetime.utcnow().isoformat()
                self._write(data)
                return v
        raise ValueError("Vulnerability not found")

    # -------------------------------------------------
    # QUERY
    # -------------------------------------------------
    def list(self, engagement_id: str = None, status: str = None):
        vulns = self._read()["vulnerabilities"]

        if engagement_id:
            vulns = [v for v in vulns if v["engagement_id"] == engagement_id]
        if status:
            vulns = [v for v in vulns if v["status"] == status]

        return vulns

