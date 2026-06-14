"""
CONSENT & LEGAL PROOF ENGINE
---------------------------
Ensures:
- Written consent exists
- Engagement ID linked
- Evidence stored

NO CONSENT = NO ACTION
"""

import json
from pathlib import Path
from datetime import datetime


CONSENT_DIR = Path("data/consent")
CONSENT_DIR.mkdir(parents=True, exist_ok=True)


class ConsentError(Exception):
    pass


class ConsentCore:
    def __init__(self):
        self.index = CONSENT_DIR / "index.json"
        if not self.index.exists():
            self.index.write_text(json.dumps({"consents": []}, indent=2))

    def _read(self):
        return json.loads(self.index.read_text())

    def _write(self, data):
        self.index.write_text(json.dumps(data, indent=2))

    def add_consent(
        self,
        engagement_id: str,
        signed_by: str,
        proof_file: str,
    ):
        data = self._read()
        entry = {
            "engagement_id": engagement_id,
            "signed_by": signed_by,
            "proof_file": proof_file,
            "timestamp": datetime.utcnow().isoformat(),
        }
        data["consents"].append(entry)
        self._write(data)
        return entry

    def validate(self, engagement_id: str):
        data = self._read()
        for c in data["consents"]:
            if c["engagement_id"] == engagement_id:
                return True
        raise ConsentError(
            f"❌ No legal consent found for {engagement_id}"
        )

