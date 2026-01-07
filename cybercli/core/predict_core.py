# cybercli/core/predict_core.py
"""
Predictive scoring engine (rule-based, safe).
- Given indicators and environment metadata, returns a risk score and recommended actions.
- No external calls required in core function (deterministic).
Usage:
    from cybercli.core.predict_core import PredictCore
    pc = PredictCore()
    pc.predict({"open_ports": 12, "outdated_packages": 3, "weak_passwords": True})
"""
from __future__ import annotations
from typing import Dict, Any, List

class PredictCore:
    def __init__(self):
        # weights for various indicator types (tweakable)
        self.weights = {
            "open_ports": 3,           # per port
            "outdated_packages": 10,   # per outdated package
            "weak_passwords": 40,      # boolean
            "public_buckets": 30,      # count presence multiplier
            "exposed_ssh": 20
        }

    def predict(self, indicators: Dict[str, Any]) -> Dict[str, Any]:
        """
        indicators example:
            {
                "open_ports": 12,
                "outdated_packages": 3,
                "weak_passwords": True,
                "public_buckets": 0,
                "exposed_ssh": True
            }
        Returns:
            { "score": int 0-100, "level": "low|medium|high", "recommended_actions": [...] }
        """
        score = 0
        # open ports
        open_ports = int(indicators.get("open_ports", 0))
        score += open_ports * self.weights["open_ports"]

        outdated = int(indicators.get("outdated_packages", 0))
        score += outdated * self.weights["outdated_packages"]

        if indicators.get("weak_passwords"):
            score += self.weights["weak_passwords"]

        score += int(indicators.get("public_buckets", 0)) * self.weights["public_buckets"]

        if indicators.get("exposed_ssh"):
            score += self.weights["exposed_ssh"]

        # cap
        score = max(0, min(100, score))

        if score >= 75:
            level = "high"
        elif score >= 40:
            level = "medium"
        else:
            level = "low"

        recs = self._recommendations(level, indicators)

        return {"score": score, "level": level, "recommended_actions": recs}

    def _recommendations(self, level: str, indicators: Dict[str, Any]) -> List[str]:
        recs: List[str] = []
        if level in ("medium", "high"):
            recs.append("Perform prioritized patching for outdated software.")
            recs.append("Review public cloud buckets and tighten ACLs.")
            recs.append("Rotate credentials and enforce MFA where applicable.")
        if indicators.get("exposed_ssh"):
            recs.append("Consider disabling password SSH and enforce key-based auth.")
        if indicators.get("open_ports", 0) > 50:
            recs.append("Perform network segmentation and limit public exposure.")
        if level == "low":
            recs.append("Monitor logs and schedule routine scans.")
        return recs

