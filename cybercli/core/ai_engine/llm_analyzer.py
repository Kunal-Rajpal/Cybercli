"""
╔══════════════════════════════════════════════════════════════════╗
║         CyberCLI AI ENGINE — False Positive Reduction            ║
║         LLM-Powered · Exploitability Scoring · Confidence AI     ║
╚══════════════════════════════════════════════════════════════════╝

THIS IS THE USP — What beats OWASP ZAP.
ZAP gives raw findings. We validate each one through AI:
  - Is the vulnerability actually exploitable?
  - Is there auth context that blocks exploitation?
  - Is the payload truly reflected / executed?
  - What is the real business impact?
  - Auto-generate remediation + executive language.
"""

import json
import logging
import asyncio
import aiohttp
from typing import List, Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger("cybercli.ai")

ANTHROPIC_API = "https://api.anthropic.com/v1/messages"
MODEL = "claude-opus-4-5"


@dataclass
class ValidationResult:
    is_true_positive: bool
    confidence: float          # 0.0 – 1.0
    adjusted_severity: str     # Original or downgraded
    exploitability: str        # Easy / Medium / Hard / Theoretical
    real_impact: str
    attack_scenario: str
    remediation: str
    executive_summary: str
    false_positive_reason: str = ""  # Filled if FP


class AIEngine:
    """
    AI-powered security analysis layer.
    Runs AFTER active/passive scan to validate findings.
    Isolated — if AI fails, raw findings still returned unchanged.
    """

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self._cache: Dict[str, ValidationResult] = {}

    async def validate_findings(
        self,
        findings: List[dict],
        target: str,
        tech_stack: Optional[Dict] = None,
    ) -> List[dict]:
        """
        Validate each finding through AI.
        Returns enriched findings with FP removed/marked.
        """
        if not findings:
            return findings

        validated = []
        tasks = [self._validate_one(f, target, tech_stack) for f in findings]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for finding, result in zip(findings, results):
            if isinstance(result, Exception):
                logger.debug(f"[AI] Validation error: {result}")
                finding["ai_validated"] = False
                validated.append(finding)
                continue

            if result.is_true_positive:
                finding.update({
                    "ai_validated": True,
                    "ai_confidence": result.confidence,
                    "severity": result.adjusted_severity,
                    "exploitability": result.exploitability,
                    "real_impact": result.real_impact,
                    "attack_scenario": result.attack_scenario,
                    "remediation": result.remediation,
                    "executive_summary": result.executive_summary,
                    "false_positive": False,
                })
                validated.append(finding)
            else:
                # Mark as false positive but keep for transparency
                finding.update({
                    "ai_validated": True,
                    "ai_confidence": result.confidence,
                    "false_positive": True,
                    "false_positive_reason": result.false_positive_reason,
                })
                logger.info(f"[AI] FP suppressed: {finding.get('title')} — {result.false_positive_reason}")

        return validated

    async def _validate_one(
        self,
        finding: dict,
        target: str,
        tech_stack: Optional[Dict]
    ) -> ValidationResult:
        """Single finding validation via Claude API"""

        cache_key = f"{finding.get('title')}:{finding.get('url')}:{finding.get('payload')}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        prompt = self._build_prompt(finding, target, tech_stack)
        response_text = await self._call_claude(prompt)

        result = self._parse_response(response_text, finding)
        self._cache[cache_key] = result
        return result

    def _build_prompt(self, finding: dict, target: str, tech_stack: Optional[Dict]) -> str:
        stack_info = json.dumps(tech_stack or {}, indent=2)
        return f"""You are a senior penetration tester and security engineer reviewing a security scanner finding.

TARGET: {target}
TECH STACK: {stack_info}

FINDING TO VALIDATE:
Title: {finding.get('title')}
Severity: {finding.get('severity')}
URL: {finding.get('url')}
Parameter: {finding.get('parameter', 'N/A')}
Payload: {finding.get('payload', 'N/A')}
Evidence: {finding.get('evidence', 'N/A')}
Description: {finding.get('description', 'N/A')}
Scanner: {finding.get('scanner', 'active')}

Analyze this finding with expert judgment:
1. Is this a TRUE POSITIVE or FALSE POSITIVE?
2. Consider: Is the payload actually executed/reflected? Is there auth context? Real exploitability?
3. What is the real business impact?
4. Adjusted severity (may downgrade if FP risk high)?

Respond ONLY in this JSON format, no other text:
{{
  "is_true_positive": true,
  "confidence": 0.92,
  "adjusted_severity": "High",
  "exploitability": "Easy",
  "real_impact": "Attacker can steal session cookies from any user visiting a crafted URL",
  "attack_scenario": "Attacker sends victim a link to https://target.com/search?q=<script>..., victim's browser executes the script",
  "remediation": "1. HTML-encode all reflected input\\n2. Implement strict CSP with nonce\\n3. Enable X-XSS-Protection header",
  "executive_summary": "A reflected XSS vulnerability allows attackers to execute arbitrary JavaScript in users' browsers, enabling session hijacking and credential theft.",
  "false_positive_reason": ""
}}"""

    async def _call_claude(self, prompt: str) -> str:
        """Call Claude API — returns empty string on any failure"""
        if not self.api_key:
            return ""
        try:
            headers = {
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            }
            body = {
                "model": MODEL,
                "max_tokens": 800,
                "messages": [{"role": "user", "content": prompt}],
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    ANTHROPIC_API, headers=headers, json=body, timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data["content"][0]["text"]
        except Exception as e:
            logger.debug(f"[AI] API call failed: {e}")
        return ""

    def _parse_response(self, text: str, finding: dict) -> ValidationResult:
        """Parse AI JSON response — graceful fallback on parse error"""
        if not text:
            return self._fallback_validation(finding)
        try:
            # Strip any accidental markdown
            text = text.strip()
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            data = json.loads(text.strip())
            return ValidationResult(
                is_true_positive=data.get("is_true_positive", True),
                confidence=float(data.get("confidence", 0.7)),
                adjusted_severity=data.get("adjusted_severity", finding.get("severity", "Medium")),
                exploitability=data.get("exploitability", "Medium"),
                real_impact=data.get("real_impact", ""),
                attack_scenario=data.get("attack_scenario", ""),
                remediation=data.get("remediation", finding.get("remediation", "")),
                executive_summary=data.get("executive_summary", ""),
                false_positive_reason=data.get("false_positive_reason", ""),
            )
        except Exception as e:
            logger.debug(f"[AI] Parse error: {e}")
            return self._fallback_validation(finding)

    def _fallback_validation(self, finding: dict) -> ValidationResult:
        """When AI unavailable — use heuristics for basic confidence scoring"""
        confidence = 0.6
        # High confidence if evidence is strong
        evidence = finding.get("evidence", "")
        if "root:x:0:" in evidence:
            confidence = 0.98  # LFI confirmed
        elif "sleep" in finding.get("payload", "").lower() and "delay" in evidence.lower():
            confidence = 0.85
        elif finding.get("scanner") == "passive":
            confidence = 0.75

        return ValidationResult(
            is_true_positive=True,
            confidence=confidence,
            adjusted_severity=finding.get("severity", "Medium"),
            exploitability="Medium",
            real_impact="See finding description",
            attack_scenario="Manual verification recommended",
            remediation=finding.get("remediation", "Refer to OWASP guidelines"),
            executive_summary=f"{finding.get('title', 'Vulnerability')} detected. Manual verification recommended.",
        )

    async def generate_executive_summary(
        self,
        findings: List[dict],
        target: str,
        scan_stats: dict
    ) -> str:
        """Generate a full executive summary from all findings"""
        if not self.api_key:
            return self._basic_executive_summary(findings, target, scan_stats)

        critical = [f for f in findings if f.get("severity") == "Critical"]
        high = [f for f in findings if f.get("severity") == "High"]
        medium = [f for f in findings if f.get("severity") == "Medium"]

        prompt = f"""You are writing an executive summary for a VAPT (Vulnerability Assessment and Penetration Testing) report.

TARGET: {target}
SCAN DATE: {scan_stats.get('date', 'N/A')}
TOTAL FINDINGS: {len(findings)}
CRITICAL: {len(critical)}, HIGH: {len(high)}, MEDIUM: {len(medium)}

TOP CRITICAL/HIGH FINDINGS:
{json.dumps([f.get('title') for f in (critical + high)[:10]], indent=2)}

Write a professional executive summary (3-4 paragraphs) suitable for a C-level audience.
Cover: overall risk posture, most critical findings, potential business impact, immediate actions needed.
Use professional security report language. No bullet points in this section."""

        text = await self._call_claude(prompt)
        return text if text else self._basic_executive_summary(findings, target, scan_stats)

    def _basic_executive_summary(self, findings, target, stats) -> str:
        critical = len([f for f in findings if f.get("severity") == "Critical"])
        high = len([f for f in findings if f.get("severity") == "High"])
        return (
            f"Security assessment of {target} identified {len(findings)} vulnerabilities "
            f"including {critical} critical and {high} high severity issues. "
            f"Immediate remediation is recommended for critical findings. "
            f"A full remediation plan is provided in the technical section of this report."
        )
