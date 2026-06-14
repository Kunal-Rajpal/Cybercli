"""
CyberCLI AI Engine — Claude · OpenAI · Gemini · Groq
Multi-provider false positive reduction + executive summary generation
"""
import json, logging, asyncio, aiohttp
from typing import List, Optional
logger = logging.getLogger("cybercli.ai")

PROVIDERS = {
    "claude":  {"url":"https://api.anthropic.com/v1/messages",                                             "model":"claude-opus-4-5"},
    "openai":  {"url":"https://api.openai.com/v1/chat/completions",                                        "model":"gpt-4o"},
    "gemini":  {"url":"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent","model":"gemini-1.5-pro"},
    "groq":    {"url":"https://api.groq.com/openai/v1/chat/completions",                                   "model":"llama-3.3-70b-versatile"},
}

class AIProvider:
    def __init__(self, provider: str, api_key: str):
        self.provider = provider.lower()
        self.api_key = api_key

    async def validate_findings(self, findings, target: str):
        if not self.api_key or not findings: return findings
        tasks = [self._validate_one(f, target) for f in findings[:8]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for finding, result in zip(findings, results):
            if isinstance(result, Exception): continue
            finding.ai_validated = True
            finding.ai_confidence = result.get("confidence", 0.7)
            finding.ai_analysis   = result.get("analysis", "")
            finding.false_positive= not result.get("is_true_positive", True)
            if result.get("adjusted_severity"):
                finding.severity = result["adjusted_severity"]
        return findings

    async def _validate_one(self, finding, target: str) -> dict:
        prompt = f"""You are a senior penetration tester reviewing a VAPT scanner finding.
TARGET: {target}
FINDING:
  Title: {finding.title}
  Severity: {finding.severity}
  URL: {finding.url}
  Parameter: {finding.parameter}
  Payload: {finding.payload}
  Evidence: {finding.evidence[:200]}

Is this a TRUE POSITIVE or FALSE POSITIVE? Consider: is evidence conclusive? Is path reachable? Auth context?
Respond ONLY in JSON, no other text:
{{"is_true_positive":true,"confidence":0.92,"adjusted_severity":"{finding.severity}","analysis":"Validated: evidence confirms exploitable vulnerability."}}"""
        resp = await self._call(prompt)
        if not resp: return {"is_true_positive":True,"confidence":0.6,"analysis":""}
        try:
            text = resp.strip().lstrip("```json").rstrip("```").strip()
            return json.loads(text)
        except Exception:
            return {"is_true_positive":True,"confidence":0.6,"analysis":resp[:150]}

    async def generate_executive_summary(self, findings, target: str, stats: dict) -> str:
        if not self.api_key: return self._fallback(findings, target)
        crits = [f.title for f in findings if f.severity=="Critical"][:5]
        highs = [f.title for f in findings if f.severity=="High"][:5]
        prompt = f"""Write a professional VAPT executive summary for a security report.
TARGET: {target}
TOTAL FINDINGS: {len(findings)} | CRITICAL: {len(crits)} | HIGH: {len(highs)}
CRITICAL: {json.dumps(crits)}
HIGH: {json.dumps(highs)}
SCAN DURATION: {stats.get('duration','N/A')} | REQUESTS: {stats.get('requests','N/A')}

Write 4 paragraphs (plain prose, no markdown, no bullets):
1. Overall security posture and risk rating with justification
2. Critical/High findings and their real business impact
3. Regulatory implications (GDPR, PCI-DSS, ISO 27001 where applicable)  
4. Prioritized immediate action recommendations
Use professional pentest firm language appropriate for C-level audience."""
        result = await self._call(prompt)
        return result or self._fallback(findings, target)

    def _fallback(self, findings, target) -> str:
        c=sum(1 for f in findings if f.severity=="Critical")
        h=sum(1 for f in findings if f.severity=="High")
        risk = "CRITICAL" if c>0 else "HIGH" if h>2 else "MEDIUM"
        return (f"The security assessment of {target} identified {len(findings)} vulnerabilities "
                f"including {c} critical and {h} high severity issues, resulting in an overall "
                f"{risk} risk posture. Immediate remediation is required for all critical findings. "
                f"A complete remediation roadmap with prioritized actions is provided in the technical section.")

    async def _call(self, prompt: str) -> Optional[str]:
        fn = {"claude":self._claude,"openai":self._openai_compat,"groq":self._openai_compat,"gemini":self._gemini}
        return await fn.get(self.provider, self._openai_compat)(prompt)

    async def _claude(self, prompt: str) -> Optional[str]:
        try:
            cfg = PROVIDERS["claude"]
            async with aiohttp.ClientSession() as s:
                async with s.post(cfg["url"],
                    headers={"Content-Type":"application/json","x-api-key":self.api_key,"anthropic-version":"2023-06-01"},
                    json={"model":cfg["model"],"max_tokens":800,"messages":[{"role":"user","content":prompt}]},
                    timeout=aiohttp.ClientTimeout(total=30)) as r:
                    if r.status==200:
                        d=await r.json(); return d["content"][0]["text"]
                    else:
                        logger.debug(f"Claude {r.status}: {await r.text()}")
        except Exception as e: logger.debug(f"AI/claude: {e}")
        return None

    async def _openai_compat(self, prompt: str) -> Optional[str]:
        try:
            cfg = PROVIDERS.get(self.provider, PROVIDERS["openai"])
            async with aiohttp.ClientSession() as s:
                async with s.post(cfg["url"],
                    headers={"Content-Type":"application/json","Authorization":f"Bearer {self.api_key}"},
                    json={"model":cfg["model"],"messages":[{"role":"user","content":prompt}],"max_tokens":800,"temperature":0.1},
                    timeout=aiohttp.ClientTimeout(total=30)) as r:
                    if r.status==200:
                        d=await r.json(); return d["choices"][0]["message"]["content"]
                    else:
                        logger.debug(f"AI/{self.provider} {r.status}: {await r.text()}")
        except Exception as e: logger.debug(f"AI/{self.provider}: {e}")
        return None

    async def _gemini(self, prompt: str) -> Optional[str]:
        try:
            cfg = PROVIDERS["gemini"]
            url = f"{cfg['url']}?key={self.api_key}"
            async with aiohttp.ClientSession() as s:
                async with s.post(url,
                    json={"contents":[{"parts":[{"text":prompt}]}]},
                    timeout=aiohttp.ClientTimeout(total=30)) as r:
                    if r.status==200:
                        d=await r.json(); return d["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e: logger.debug(f"AI/gemini: {e}")
        return None
