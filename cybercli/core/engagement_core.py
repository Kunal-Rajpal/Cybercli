"""
ENGAGEMENT & SCOPE ENGINE
-------------------------
Controls:
- Client engagement lifecycle
- Scope validation
- Time window enforcement

This engine MUST be called before any active operation.
SAFE | LEGAL | AUDITABLE
"""

from datetime import datetime
from typing import List, Dict
import json
from pathlib import Path


ENGAGEMENT_DB = Path("artifacts/engagement.json")


class EngagementError(Exception):
    pass


class EngagementCore:
    def __init__(self):
        self.db = ENGAGEMENT_DB
        self.db.parent.mkdir(parents=True, exist_ok=True)
        if not self.db.exists():
            self._write({"engagements": []})

    def _read(self) -> Dict:
        return json.loads(self.db.read_text())

    def _write(self, data: Dict):
        self.db.write_text(json.dumps(data, indent=2))

    # -------------------------------------------------
    # CREATE ENGAGEMENT
    # -------------------------------------------------
    def create_engagement(
        self,
        client: str,
        scope: List[str],
        start_date: str,
        end_date: str,
        owner: str,
    ):
        data = self._read()
        engagement = {
            "id": f"ENG-{len(data['engagements'])+1:03}",
            "client": client,
            "scope": scope,
            "start_date": start_date,
            "end_date": end_date,
            "owner": owner,
            "created_at": datetime.utcnow().isoformat(),
            "active": True,
        }
        data["engagements"].append(engagement)
        self._write(data)
        return engagement

    # -------------------------------------------------
    # VALIDATION (CALLED BY MODULES)
    # -------------------------------------------------
    def validate_target(self, target: str):
        data = self._read()
        now = datetime.utcnow().date()

        for eng in data["engagements"]:
            if not eng["active"]:
                continue

            start = datetime.fromisoformat(eng["start_date"]).date()
            end = datetime.fromisoformat(eng["end_date"]).date()

            if not (start <= now <= end):
                continue

            for allowed in eng["scope"]:
                if target.endswith(allowed) or target == allowed:
                    return eng

        raise EngagementError(
            f"❌ Target '{target}' is NOT in active engagement scope"
        )

