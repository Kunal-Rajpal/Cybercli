"""
ASSET INVENTORY CORE (BRAIN MEMORY)
----------------------------------
Tracks:
- Domains
- IPs
- APIs
- Cloud resources
- Applications

Every asset is:
- Engagement-linked
- Owner-tagged
- Risk-ready
"""

from pathlib import Path
from datetime import datetime
import json
from typing import Dict, List


ASSET_DB = Path("artifacts/assets.json")


class AssetInventoryCore:
    def __init__(self):
        ASSET_DB.parent.mkdir(parents=True, exist_ok=True)
        if not ASSET_DB.exists():
            self._write({"assets": []})

    def _read(self) -> Dict:
        return json.loads(ASSET_DB.read_text())

    def _write(self, data: Dict):
        ASSET_DB.write_text(json.dumps(data, indent=2))

    # -------------------------------------------------
    # ADD ASSET
    # -------------------------------------------------
    def add_asset(
        self,
        engagement_id: str,
        asset_type: str,
        identifier: str,
        owner: str = "unknown",
        criticality: str = "medium",
        tags: List[str] = None,
        source: str = "manual",
    ):
        data = self._read()

        asset = {
            "asset_id": f"AST-{len(data['assets'])+1:05}",
            "engagement_id": engagement_id,
            "type": asset_type,           # domain | ip | api | cloud | app
            "identifier": identifier,     # example.com | 1.1.1.1
            "owner": owner,
            "criticality": criticality,   # low | medium | high | critical
            "tags": tags or [],
            "source": source,             # recon | scan | osint | manual
            "first_seen": datetime.utcnow().isoformat(),
            "last_seen": datetime.utcnow().isoformat(),
            "metadata": {},
        }

        data["assets"].append(asset)
        self._write(data)
        return asset

    # -------------------------------------------------
    # UPDATE ASSET METADATA
    # -------------------------------------------------
    def update_asset(self, asset_id: str, metadata: Dict):
        data = self._read()
        for asset in data["assets"]:
            if asset["asset_id"] == asset_id:
                asset["metadata"].update(metadata)
                asset["last_seen"] = datetime.utcnow().isoformat()
                self._write(data)
                return asset
        raise ValueError("Asset not found")

    # -------------------------------------------------
    # QUERY
    # -------------------------------------------------
    def list_assets(self, engagement_id: str = None):
        data = self._read()
        if engagement_id:
            return [
                a for a in data["assets"]
                if a["engagement_id"] == engagement_id
            ]
        return data["assets"]

    def find_by_identifier(self, identifier: str):
        data = self._read()
        for asset in data["assets"]:
            if asset["identifier"] == identifier:
                return asset
        return None

