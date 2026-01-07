# cybercli/core/classifier_core.py
"""
Lightweight, deterministic classifier for security artifacts.

Features:
- SAFE (no ML file required)
- Fast + explainable scoring
- Keyword-heuristic matching
- Returns categories, scores, matched keywords

Usage:
    from cybercli.core.classifier_core import ClassifierCore
    clf = ClassifierCore()
    print(clf.classify("Open SSH on 22, banner shows OpenSSH 7.2"))
"""

from __future__ import annotations
from typing import List, Dict
import re

# Base keyword → category map
classifier_map: Dict[str, List[str]] = {
    "recon": [
        "nmap", "open port", "port", "scan", "banner", "whois",
        "dns", "subdomain", "enum", "shodan"
    ],
    "osint": [
        "email", "breach", "paste", "profile", "social",
        "github", "public"
    ],
    "vuln": [
        "cve", "vulnerability", "exploit", "cvss", "rce",
        "sql injection", "xss", "buffer overflow"
    ],
    "malware": [
        "malware", "trojan", "ransom", "yara", "pe32",
        "hash", "sha256", "payload"
    ],
    "cloud": [
        "s3", "bucket", "iam", "lambda", "aws",
        "azure", "gcp", "service account"
    ],
    "defense": [
        "patch", "mitigate", "harden", "firewall",
        "epp", "edr", "siem"
    ],
    "access": [
        "credential", "password", "token", "api_key", "secret"
    ],
    "supplychain": [
        "sbom", "dependency", "npm", "pip", "artifact", "package"
    ],
}


class ClassifierCore:
    """
    Deterministic keyword-based classifier for cybersecurity text.

    Methods:
        classify(text: str) -> Dict
    """

    def __init__(self, mapping: Dict[str, List[str]] | None = None):
        self.mapping = mapping or classifier_map

    def _tokenize(self, text: str) -> List[str]:
        """Convert input into normalized lowercase tokens."""
        text = text.lower()
        return re.findall(r"[a-z0-9]+", text)

    def classify(self, text: str) -> Dict:
        """
        Classify input text into categories.

        Returns:
            {
                "matched": [...],
                "scores": {...},
                "matches": {...},
                "raw": text
            }
        """
        tokens = self._tokenize(text)
        tokset = set(tokens)

        matches: Dict[str, List[str]] = {}
        scores: Dict[str, float] = {}

        # category-level matching
        for category, keywords in self.mapping.items():
            found = []
            for kw in keywords:
                # token match or substring match
                if kw in tokset or any(kw in t for t in tokens):
                    found.append(kw)

            if found:
                matches[category] = found
                # heuristic confidence score
                base = max(3, len(keywords))
                clip_score = min(1.0, len(found) / base)
                scores[category] = round(float(clip_score), 2)

        matched_categories = list(matches.keys()) if matches else ["unknown"]

        # normalize scores so they sum to <= 1
        if scores:
            total = sum(scores.values())
            if total > 0:
                for k in scores:
                    scores[k] = round(scores[k] / total, 2)

        return {
            "matched": matched_categories,
            "scores": scores,
            "matches": matches,
            "raw": text
        }

