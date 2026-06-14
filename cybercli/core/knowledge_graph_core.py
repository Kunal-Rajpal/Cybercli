"""
KNOWLEDGE GRAPH ENGINE
---------------------
Unified graph for assets, vulnerabilities, attacks, risks & compliance
"""

from datetime import datetime
from pathlib import Path
import json
import uuid

GRAPH_DB = Path("artifacts/knowledge_graph.json")


class KnowledgeGraph:
    def __init__(self):
        GRAPH_DB.parent.mkdir(parents=True, exist_ok=True)
        if not GRAPH_DB.exists():
            GRAPH_DB.write_text(json.dumps({
                "nodes": {},
                "edges": []
            }, indent=2))

    def load(self):
        return json.loads(GRAPH_DB.read_text())

    def save(self, data):
        GRAPH_DB.write_text(json.dumps(data, indent=2))

    # -------------------------
    # NODE MANAGEMENT
    # -------------------------
    def add_node(self, node_type: str, label: str, metadata: dict = None):
        data = self.load()
        node_id = str(uuid.uuid4())

        data["nodes"][node_id] = {
            "id": node_id,
            "type": node_type,
            "label": label,
            "metadata": metadata or {},
            "created_at": datetime.utcnow().isoformat()
        }

        self.save(data)
        return node_id

    # -------------------------
    # EDGE MANAGEMENT
    # -------------------------
    def link(self, src: str, relation: str, dst: str):
        data = self.load()
        data["edges"].append({
            "from": src,
            "to": dst,
            "relation": relation,
            "created_at": datetime.utcnow().isoformat()
        })
        self.save(data)

    # -------------------------
    # QUERY ENGINE
    # -------------------------
    def find_by_type(self, node_type: str):
        data = self.load()
        return [
            n for n in data["nodes"].values()
            if n["type"] == node_type
        ]

    def attack_path(self, asset_label: str):
        """
        Find connected vulnerabilities and attacks
        """
        data = self.load()
        paths = []

        asset_nodes = [
            n for n in data["nodes"].values()
            if n["label"] == asset_label
        ]

        for asset in asset_nodes:
            for e in data["edges"]:
                if e["from"] == asset["id"]:
                    target = data["nodes"].get(e["to"])
                    if target:
                        paths.append((asset, e["relation"], target))

        return paths

