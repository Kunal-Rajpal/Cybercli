"""
DETECTION & DEFENSE MAPPING ENGINE
----------------------------------
Maps attack techniques to blue team controls
"""

from pathlib import Path
from datetime import datetime
import json

DB = Path("artifacts/defense_map.json")


DEFAULT_CONTROLS = {
    "T1190": {
        "technique": "Exploit Public-Facing Application",
        "detect": [
            "WAF logs",
            "Web server access logs",
            "API gateway anomaly alerts"
        ],
        "prevent": [
            "WAF rules",
            "Input validation",
            "Patch management"
        ],
        "controls": ["WAF", "SIEM"],
    },
    "T1059": {
        "technique": "Command Execution",
        "detect": [
            "EDR process telemetry",
            "Shell spawn alerts"
        ],
        "prevent": [
            "Application allowlisting",
            "EDR blocking rules"
        ],
        "controls": ["EDR"],
    },
    "T1003": {
        "technique": "Credential Dumping",
        "detect": [
            "LSASS access alerts",
            "Memory dump detection"
        ],
        "prevent": [
            "Credential Guard",
            "LSASS protection"
        ],
        "controls": ["EDR", "OS Hardening"],
    },
    "T1486": {
        "technique": "Data Encryption / Exfiltration",
        "detect": [
            "File entropy anomalies",
            "DLP alerts",
            "Unusual outbound traffic"
        ],
        "prevent": [
            "DLP enforcement",
            "Network egress filtering"
        ],
        "controls": ["DLP", "NDR"],
    },
}


class DefenseMappingEngine:
    def __init__(self):
        DB.parent.mkdir(parents=True, exist_ok=True)
        if not DB.exists():
            DB.write_text(json.dumps(DEFAULT_CONTROLS, indent=2))

    def get_mapping(self, technique_id: str):
        data = json.loads(DB.read_text())
        return data.get(technique_id)

    def enrich_attack_path(self, kill_chain: list):
        """
        Add detection & defense info to each kill chain step
        """
        enriched = []
        for step in kill_chain:
            mapping = self.get_mapping(step["technique_id"])
            enriched.append({
                **step,
                "defense": mapping if mapping else "NO DEFENSE MAPPED"
            })
        return enriched

    def coverage_score(self, kill_chain: list):
        covered = 0
        for step in kill_chain:
            if self.get_mapping(step["technique_id"]):
                covered += 1
        return round((covered / len(kill_chain)) * 100, 2)

