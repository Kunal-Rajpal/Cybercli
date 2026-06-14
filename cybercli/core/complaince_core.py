"""
COMPLIANCE & FRAMEWORK ENGINE
----------------------------
Maps findings & attack paths to security frameworks
"""

from pathlib import Path
from datetime import datetime
import json

DB = Path("artifacts/compliance_map.json")

DEFAULT_MAP = {
    "ISO27001": {
        "A.12.6.1": {
            "title": "Management of Technical Vulnerabilities",
            "applies_to": ["vuln", "exploit", "patch"],
        },
        "A.9.2.3": {
            "title": "Privileged Access Management",
            "applies_to": ["privesc", "credential", "access"],
        },
    },
    "SOC2": {
        "CC7.2": {
            "title": "Detection of Malicious Activity",
            "applies_to": ["exploit", "malware", "lateral"],
        },
        "CC6.6": {
            "title": "Logical Access Controls",
            "applies_to": ["access", "authentication"],
        },
    },
    "PCI-DSS": {
        "6.5": {
            "title": "Secure Application Development",
            "applies_to": ["web", "api", "injection"],
        },
        "10.2": {
            "title": "Audit Logs",
            "applies_to": ["logging", "detection"],
        },
    },
}


class ComplianceEngine:
    def __init__(self):
        DB.parent.mkdir(parents=True, exist_ok=True)
        if not DB.exists():
            DB.write_text(json.dumps(DEFAULT_MAP, indent=2))

    def load(self):
        return json.loads(DB.read_text())

    def map_finding(self, finding: dict):
        """
        finding = {
            "type": "vuln",
            "category": "web",
            "description": "SQL Injection"
        }
        """
        results = []
        db = self.load()

        keywords = f"{finding.get('type','')} {finding.get('category','')} {finding.get('description','')}".lower()

        for framework, controls in db.items():
            for cid, meta in controls.items():
                if any(k in keywords for k in meta["applies_to"]):
                    results.append({
                        "framework": framework,
                        "control_id": cid,
                        "title": meta["title"]
                    })

        return results

    def compliance_score(self, total_controls: int, violated: int):
        if total_controls == 0:
            return 100.0
        return round(((total_controls - violated) / total_controls) * 100, 2)

