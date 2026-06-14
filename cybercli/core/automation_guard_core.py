"""
SAFE AUTOMATION RULE ENGINE
--------------------------
Controls what automation is allowed, when, and why.
"""

from datetime import datetime
from pathlib import Path
import json
import uuid

RULE_DB = Path("artifacts/automation_rules.json")
AUDIT_DB = Path("artifacts/automation_audit.log")


class AutomationEngine:
    def __init__(self):
        RULE_DB.parent.mkdir(parents=True, exist_ok=True)

        if not RULE_DB.exists():
            RULE_DB.write_text(json.dumps({
                "rules": {},
                "global_kill_switch": False
            }, indent=2))

        if not AUDIT_DB.exists():
            AUDIT_DB.write_text("")

    # -----------------------------
    # INTERNAL HELPERS
    # -----------------------------
    def _load(self):
        return json.loads(RULE_DB.read_text())

    def _save(self, data):
        RULE_DB.write_text(json.dumps(data, indent=2))

    def _audit(self, msg):
        AUDIT_DB.write_text(
            f"{datetime.utcnow().isoformat()} | {msg}\n",
            append=True
        )

    # -----------------------------
    # RULE MANAGEMENT
    # -----------------------------
    def add_rule(
        self,
        name: str,
        allowed_actions: list,
        max_severity: str = "medium",
        requires_consent: bool = True
    ):
        data = self._load()
        rule_id = str(uuid.uuid4())

        data["rules"][rule_id] = {
            "id": rule_id,
            "name": name,
            "allowed_actions": allowed_actions,
            "max_severity": max_severity,
            "requires_consent": requires_consent,
            "enabled": True,
            "created_at": datetime.utcnow().isoformat()
        }

        self._save(data)
        self._audit(f"RULE CREATED: {name}")
        return rule_id

    # -----------------------------
    # EXECUTION GATE
    # -----------------------------
    def is_action_allowed(
        self,
        action: str,
        severity: str,
        consent: bool
    ) -> bool:
        data = self._load()

        if data["global_kill_switch"]:
            self._audit("BLOCKED: Global kill switch enabled")
            return False

        for rule in data["rules"].values():
            if not rule["enabled"]:
                continue

            if action in rule["allowed_actions"]:
                if rule["requires_consent"] and not consent:
                    self._audit(f"BLOCKED: Consent missing for {action}")
                    return False

                if severity_priority(severity) > severity_priority(rule["max_severity"]):
                    self._audit(f"BLOCKED: Severity too high for {action}")
                    return False

                self._audit(f"ALLOWED: {action}")
                return True

        self._audit(f"BLOCKED: No rule for {action}")
        return False

    # -----------------------------
    # EMERGENCY STOP
    # -----------------------------
    def kill_switch(self, state: bool):
        data = self._load()
        data["global_kill_switch"] = state
        self._save(data)
        self._audit(f"KILL SWITCH SET TO {state}")


# -----------------------------
# SEVERITY LOGIC
# -----------------------------
def severity_priority(level: str) -> int:
    return {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }.get(level.lower(), 0)

