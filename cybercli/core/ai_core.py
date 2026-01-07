# cybercli/core/ai_core.py

import json
from datetime import datetime
from .classifier_core import ClassifierCore
from .correlation_core import CorrelationCore
from .predict_core import PredictCore
from .threat_intel_core import ThreatIntelCore


class CyberAICore:
    """
    SAFE AI engine that performs:
    - OSINT metadata extraction
    - Passive vulnerability pattern detection (no exploitation)
    - Correlation of signals
    - Risk classification
    - Predictive trend scoring
    - Threat intel summarization
    """

    def __init__(self):
        self.classifier = ClassifierCore()
        self.correlation = CorrelationCore()
        self.predictor = PredictCore()
        self.intel = ThreatIntelCore()

    def analyze_osint(self, data: dict) -> dict:
        """Analyze passive OSINT and return structured results."""
        keywords = data.get("keywords", [])
        metadata = {
            "total_keywords": len(keywords),
            "high_risk_terms": [k for k in keywords if k.lower() in ["breach", "leak", "login", "exposed"]],
            "sources": data.get("sources", []),
            "timestamp": datetime.utcnow().isoformat(),
        }
        metadata["risk_score"] = self.classifier.score_keywords(keywords)
        return metadata

    def detect_risks(self, scan_output: dict) -> dict:
        """Classify risk level based on safe scan metadata."""
        return self.classifier.classify_scan(scan_output)

    def correlate(self, input_blocks: list) -> dict:
        """Fuse multiple signals into unified risk profile."""
        return self.correlation.combine_signals(input_blocks)

    def predict_trends(self, indicators: dict) -> dict:
        """Predict future security posture (safe statistical model)."""
        return self.predictor.predict(indicators)

    def enrich_with_intel(self, domain: str) -> dict:
        """Fetch passive TI (WHOIS, malware mentions, breach mentions)."""
        return self.intel.lookup(domain)

    def full_ai_pipeline(self, osint_data, scan_data, intel_domain):
        """One-shot full AI pipeline used by plugins/ai/*.py"""

        osint = self.analyze_osint(osint_data)
        risks = self.detect_risks(scan_data)
        correlation = self.correlate([osint, risks])
        prediction = self.predict_trends(risks)
        intel = self.enrich_with_intel(intel_domain)

        return {
            "osint": osint,
            "scan_risk": risks,
            "correlation": correlation,
            "prediction": prediction,
            "intel": intel,
            "generated": datetime.utcnow().isoformat()
        }

