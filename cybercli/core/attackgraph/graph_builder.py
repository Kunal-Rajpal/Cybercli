"""
╔══════════════════════════════════════════════════════════════════╗
║       CyberCLI ATTACK GRAPH ENGINE                               ║
║       Maltego + BloodHound Style Attack Path Mapping             ║
║       Subdomain · API · Cloud · K8s · Trust Relationships        ║
╚══════════════════════════════════════════════════════════════════╝
"""

import asyncio
import socket
import logging
import json
import re
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger("cybercli.graph")


@dataclass
class GraphNode:
    id: str
    label: str
    node_type: str       # domain, subdomain, endpoint, service, cloud, k8s, auth
    risk_level: str = "Unknown"  # Critical / High / Medium / Low / Safe
    metadata: Dict = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str        # resolves_to, api_calls, trusts, redirects_to, auth_via
    weight: float = 1.0
    attack_vector: bool = False


class AttackGraph:
    """
    Builds a full attack graph from a target domain.
    Maps: subdomains, endpoints, trust relationships, cloud assets, attack paths.
    Produces Maltego/BloodHound style output.
    Isolated — failure does NOT affect other modules.
    """

    def __init__(self, target: str):
        self.target = target
        self.root_domain = self._extract_root(target)
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self._visited: Set[str] = set()

    def _extract_root(self, target: str) -> str:
        t = target.replace("https://", "").replace("http://", "").split("/")[0]
        parts = t.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return t

    async def build(self) -> "AttackGraph":
        """Full graph build pipeline"""
        logger.info(f"[GRAPH] Building attack graph for {self.target}")
        try:
            await self._map_root_domain()
            await self._enumerate_subdomains()
            await self._resolve_ips()
            await self._detect_cloud_assets()
            await self._map_trust_relationships()
            self._calculate_attack_paths()
            logger.info(f"[GRAPH] Graph complete: {len(self.nodes)} nodes, {len(self.edges)} edges")
        except Exception as e:
            logger.error(f"[GRAPH] Build error: {e}")
        return self

    async def _map_root_domain(self):
        node = GraphNode(
            id=self.root_domain,
            label=self.root_domain,
            node_type="domain",
            metadata={"target": True}
        )
        self._add_node(node)

    async def _enumerate_subdomains(self):
        """Enumerate subdomains via DNS bruteforce + wordlist"""
        common_subs = [
            "www", "api", "admin", "app", "dev", "staging", "test",
            "mail", "smtp", "ftp", "cdn", "static", "assets",
            "login", "auth", "sso", "oauth", "id",
            "mobile", "m", "beta", "portal", "dashboard",
            "vpn", "remote", "citrix", "jenkins", "gitlab",
            "jira", "confluence", "grafana", "kibana", "prometheus",
            "k8s", "kubernetes", "docker", "registry",
            "s3", "storage", "files", "backup",
            "ws", "websocket", "stream", "push",
        ]

        tasks = [self._resolve_subdomain(f"{sub}.{self.root_domain}") for sub in common_subs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for sub, result in zip(common_subs, results):
            if isinstance(result, str):  # IP returned
                fqdn = f"{sub}.{self.root_domain}"
                risk = self._assess_subdomain_risk(sub)
                node = GraphNode(
                    id=fqdn,
                    label=f"{sub}.{self.root_domain}",
                    node_type="subdomain",
                    risk_level=risk,
                    metadata={"ip": result, "subdomain_prefix": sub}
                )
                self._add_node(node)
                self._add_edge(GraphEdge(
                    source=self.root_domain,
                    target=fqdn,
                    relation="has_subdomain",
                    attack_vector=(risk in ("High", "Critical"))
                ))

    async def _resolve_subdomain(self, fqdn: str) -> Optional[str]:
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, socket.gethostbyname, fqdn)
            return result
        except Exception:
            return None

    def _assess_subdomain_risk(self, prefix: str) -> str:
        critical = {"admin", "jenkins", "gitlab", "k8s", "kubernetes"}
        high = {"api", "auth", "sso", "oauth", "login", "vpn", "grafana", "kibana"}
        medium = {"dev", "staging", "test", "beta", "dashboard", "portal"}

        if prefix in critical:
            return "Critical"
        if prefix in high:
            return "High"
        if prefix in medium:
            return "Medium"
        return "Low"

    async def _resolve_ips(self):
        """Resolve IPs and detect cloud providers"""
        CLOUD_RANGES = {
            "AWS": ["52.", "54.", "34.", "35.", "18.", "44.", "50.", "3."],
            "GCP": ["34.", "35.", "104.", "130."],
            "Azure": ["13.", "20.", "40.", "51.", "52.", "23."],
            "Cloudflare": ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21."],
        }

        for node_id, node in list(self.nodes.items()):
            ip = node.metadata.get("ip", "")
            if not ip:
                continue
            for provider, prefixes in CLOUD_RANGES.items():
                if any(ip.startswith(p) for p in prefixes):
                    node.metadata["cloud_provider"] = provider
                    cloud_node = GraphNode(
                        id=f"cloud:{provider}",
                        label=provider,
                        node_type="cloud",
                        risk_level="Medium",
                        metadata={"provider": provider}
                    )
                    self._add_node(cloud_node)
                    self._add_edge(GraphEdge(
                        source=node_id,
                        target=f"cloud:{provider}",
                        relation="hosted_on"
                    ))
                    break

    async def _detect_cloud_assets(self):
        """Detect misconfigured S3 buckets, exposed cloud storage"""
        common_bucket_names = [
            self.root_domain,
            self.root_domain.replace(".", "-"),
            f"{self.root_domain}-backup",
            f"{self.root_domain}-assets",
            f"{self.root_domain}-dev",
            f"{self.root_domain}-prod",
            f"{self.root_domain}-staging",
        ]

        tasks = [self._check_s3_bucket(name) for name in common_bucket_names]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_s3_bucket(self, bucket_name: str):
        try:
            import aiohttp
            url = f"https://{bucket_name}.s3.amazonaws.com/"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                    if resp.status in (200, 403):
                        risk = "Critical" if resp.status == 200 else "High"
                        node = GraphNode(
                            id=f"s3:{bucket_name}",
                            label=f"S3: {bucket_name}",
                            node_type="cloud",
                            risk_level=risk,
                            metadata={
                                "bucket_name": bucket_name,
                                "status": resp.status,
                                "public": resp.status == 200
                            },
                            vulnerabilities=(["Public S3 Bucket — Data Exposure"] if resp.status == 200 else
                                             ["S3 Bucket Exists — Access Control Review Needed"])
                        )
                        self._add_node(node)
                        self._add_edge(GraphEdge(
                            source=self.root_domain,
                            target=f"s3:{bucket_name}",
                            relation="uses_storage",
                            attack_vector=(resp.status == 200)
                        ))
        except Exception:
            pass

    async def _map_trust_relationships(self):
        """Map OAuth/SSO/third-party trust relationships from discovered endpoints"""
        # Heuristic: known OAuth providers, SSO patterns
        sso_indicators = {
            "okta": "Okta SSO",
            "auth0": "Auth0",
            "azure.com/oauth": "Azure AD",
            "accounts.google.com": "Google OAuth",
            "login.microsoftonline.com": "Microsoft Identity",
            "cognito": "AWS Cognito",
            "keycloak": "Keycloak",
            "ping": "PingIdentity",
        }
        for node_id, node in list(self.nodes.items()):
            label = node.label.lower()
            for indicator, provider in sso_indicators.items():
                if indicator in label:
                    trust_node = GraphNode(
                        id=f"trust:{provider}",
                        label=provider,
                        node_type="auth",
                        risk_level="Medium",
                        metadata={"provider": provider}
                    )
                    self._add_node(trust_node)
                    self._add_edge(GraphEdge(
                        source=node_id,
                        target=f"trust:{provider}",
                        relation="auth_via",
                        weight=2.0
                    ))

    def _calculate_attack_paths(self):
        """Find highest-risk attack paths through the graph"""
        # Find all critical/high nodes as attack targets
        targets = [n for n in self.nodes.values() if n.risk_level in ("Critical", "High")]

        # Simple path: entry points (low risk subdomains) → high risk services
        entry_points = [n for n in self.nodes.values() if n.risk_level == "Low"]

        for entry in entry_points[:3]:
            for target in targets[:5]:
                # Check if there's a path (direct edge or via intermediate)
                if self._has_path(entry.id, target.id):
                    self._add_edge(GraphEdge(
                        source=entry.id,
                        target=target.id,
                        relation="attack_path",
                        weight=3.0,
                        attack_vector=True
                    ))

    def _has_path(self, source: str, target: str, depth: int = 3) -> bool:
        if depth == 0:
            return False
        direct = [e for e in self.edges if e.source == source]
        for edge in direct:
            if edge.target == target:
                return True
            if self._has_path(edge.target, target, depth - 1):
                return True
        return False

    def _add_node(self, node: GraphNode):
        self.nodes[node.id] = node

    def _add_edge(self, edge: GraphEdge):
        # Avoid duplicate edges
        for e in self.edges:
            if e.source == edge.source and e.target == edge.target and e.relation == edge.relation:
                return
        self.edges.append(edge)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "root_domain": self.root_domain,
            "nodes": [
                {
                    "id": n.id,
                    "label": n.label,
                    "type": n.node_type,
                    "risk": n.risk_level,
                    "metadata": n.metadata,
                    "vulnerabilities": n.vulnerabilities,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "relation": e.relation,
                    "weight": e.weight,
                    "attack_vector": e.attack_vector,
                }
                for e in self.edges
            ],
            "stats": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "attack_vectors": sum(1 for e in self.edges if e.attack_vector),
                "critical_nodes": sum(1 for n in self.nodes.values() if n.risk_level == "Critical"),
            }
        }

    def render_terminal(self) -> str:
        """Render ASCII attack tree for terminal"""
        lines = []
        lines.append(f"\n  {self.root_domain}")

        # Group by type
        subdomains = [n for n in self.nodes.values() if n.node_type == "subdomain"]
        clouds = [n for n in self.nodes.values() if n.node_type == "cloud"]
        auths = [n for n in self.nodes.values() if n.node_type == "auth"]
        attack_paths = [e for e in self.edges if e.relation == "attack_path"]

        for i, sub in enumerate(subdomains):
            is_last = (i == len(subdomains) - 1 and not clouds and not auths)
            prefix = "  └──" if is_last else "  ├──"
            risk_color = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(sub.risk_level, "⚪")
            lines.append(f"{prefix} {risk_color} {sub.label}")
            if sub.vulnerabilities:
                for vuln in sub.vulnerabilities:
                    lines.append(f"  │      └── ⚠  {vuln}")

        for cloud in clouds:
            lines.append(f"  ├── ☁  {cloud.label} [{cloud.risk_level}]")
            if cloud.metadata.get("public"):
                lines.append(f"  │      └── 🔴 PUBLIC ACCESS DETECTED")

        for auth in auths:
            lines.append(f"  ├── 🔑 {auth.label}")

        if attack_paths:
            lines.append(f"\n  ATTACK PATHS DETECTED: {len(attack_paths)}")
            path_nodes = set()
            for e in attack_paths:
                path_nodes.add(e.source)
                path_nodes.add(e.target)
            chain = " → ".join(list(path_nodes)[:5])
            lines.append(f"  {chain}")

        return "\n".join(lines)

    def export_networkx(self):
        """Export to networkx graph for visualization"""
        try:
            import networkx as nx
            G = nx.DiGraph()
            for node in self.nodes.values():
                G.add_node(node.id, **{"label": node.label, "type": node.node_type, "risk": node.risk_level})
            for edge in self.edges:
                G.add_edge(edge.source, edge.target, relation=edge.relation, weight=edge.weight)
            return G
        except ImportError:
            logger.warning("[GRAPH] networkx not installed — pip install networkx")
            return None

    def export_json(self, path: str):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info(f"[GRAPH] Exported to {path}")
