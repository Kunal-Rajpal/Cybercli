"""BurpNext AI Engine — Multi-Provider: Claude · OpenAI · Gemini · Groq · Ollama"""
import json, logging, asyncio, aiohttp
from typing import List, Optional
logger = logging.getLogger("burpnext.ai")

PROVIDERS = {
    "claude": {"url":"https://api.anthropic.com/v1/messages",      "model":"claude-opus-4-5"},
    "openai": {"url":"https://api.openai.com/v1/chat/completions", "model":"gpt-4o"},
    "gemini": {"url":"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent","model":"gemini-1.5-pro"},
    "groq":   {"url":"https://api.groq.com/openai/v1/chat/completions","model":"llama-3.3-70b-versatile"},
    "ollama": {"url":"http://localhost:11434/api/generate",          "model":"llama3"},
}

class BurpAI:
    def __init__(self, provider: str, api_key: str=""):
        self.provider = provider.lower()
        self.api_key  = api_key

    async def validate_finding(self, finding: dict, target: str) -> dict:
        prompt = (
            f"You are a senior penetration tester validating a WAPT scanner finding.\n"
            f"TARGET: {target}\n"
            f"FINDING:\n"
            f"  Title: {finding.get('title')}\n"
            f"  Severity: {finding.get('severity')}\n"
            f"  URL: {finding.get('url')}\n"
            f"  Parameter: {finding.get('parameter','')}\n"
            f"  Payload: {finding.get('payload','')}\n"
            f"  Evidence: {str(finding.get('evidence',''))[:300]}\n"
            f"  OWASP: {finding.get('owasp','')}\n\n"
            f"Analyze as professional pentester:\n"
            f"1. True positive or false positive?\n"
            f"2. Is evidence conclusive?\n"
            f"3. Real-world exploitability?\n"
            f"4. Precise attack scenario (2-3 sentences)?\n\n"
            f"Respond ONLY in JSON, no markdown:\n"
            f'{{ "is_true_positive":true,"confidence":0.94,"adjusted_severity":"{finding.get("severity","Medium")}","analysis":"Technical validation in 1-2 sentences.","attack_scenario":"How attacker exploits this step by step." }}'
        )
        resp = await self._call(prompt)
        if not resp:
            return {"is_true_positive":True,"confidence":0.6,"analysis":"","attack_scenario":""}
        try:
            text = resp.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
            return json.loads(text)
        except Exception:
            return {"is_true_positive":True,"confidence":0.6,"analysis":resp[:200],"attack_scenario":""}

    async def validate_findings(self, findings: list, target: str) -> list:
        if not findings: return findings
        tasks = [self.validate_finding(
            f.to_dict() if hasattr(f,'to_dict') else f, target
        ) for f in findings[:12]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for finding, result in zip(findings, results):
            if isinstance(result, Exception): continue
            if hasattr(finding,'ai_validated'):
                finding.ai_validated       = True
                finding.ai_confidence      = result.get("confidence", 0.7)
                finding.ai_analysis        = result.get("analysis","")
                finding.ai_attack_scenario = result.get("attack_scenario","")
                finding.false_positive     = not result.get("is_true_positive",True)
                if result.get("adjusted_severity"): finding.severity = result["adjusted_severity"]
            else:
                finding["ai_validated"]       = True
                finding["ai_confidence"]      = result.get("confidence",0.7)
                finding["ai_analysis"]        = result.get("analysis","")
                finding["ai_attack_scenario"] = result.get("attack_scenario","")
                finding["false_positive"]     = not result.get("is_true_positive",True)
        return findings

    async def generate_executive_summary(self, findings: list, target: str, stats: dict) -> str:
        if not (self.api_key or self.provider=="ollama"):
            return self._fallback_exec(findings, target, stats)
        c=stats.get("critical",0); h=stats.get("high",0)
        crits=[(f.get("title") if isinstance(f,dict) else f.title) for f in findings if (f.get("severity") if isinstance(f,dict) else f.severity)=="Critical"][:5]
        highs=[(f.get("title") if isinstance(f,dict) else f.title) for f in findings if (f.get("severity") if isinstance(f,dict) else f.severity)=="High"][:5]
        prompt = (
            f"Write a professional WAPT executive summary report section.\n"
            f"TARGET: {target}\n"
            f"STATS: Total={stats.get('total',0)} | Critical={c} | High={h} | "
            f"Medium={stats.get('medium',0)} | Low={stats.get('low',0)}\n"
            f"DURATION: {stats.get('duration','N/A')} | REQUESTS: {stats.get('requests',0)} | "
            f"ENDPOINTS: {stats.get('endpoints',0)}\n"
            f"CRITICAL: {json.dumps(crits)}\n"
            f"HIGH: {json.dumps(highs)}\n\n"
            f"Write 5 paragraphs (professional pentest firm tone, C-level audience, no markdown):\n"
            f"1. Executive overview and overall risk rating\n"
            f"2. Critical/High findings with specific business impact\n"
            f"3. Regulatory implications (GDPR Article 83, PCI-DSS, ISO 27001)\n"
            f"4. Prioritized 30-60-90 day remediation plan\n"
            f"5. Positive observations and risk trajectory"
        )
        result = await self._call(prompt)
        return result or self._fallback_exec(findings, target, stats)

    def _fallback_exec(self, findings, target, stats) -> str:
        c=stats.get('critical',0); h=stats.get('high',0)
        risk="CRITICAL" if c>0 else "HIGH" if h>2 else "MEDIUM" if h>0 else "LOW"
        return (
            f"Web Application Penetration Testing of {target} identified "
            f"{stats.get('total',0)} security vulnerabilities across "
            f"{stats.get('endpoints',0)} discovered endpoints. "
            f"Risk posture: {risk}. {c} critical and {h} high severity "
            f"findings require immediate attention. Assessment completed in "
            f"{stats.get('duration','N/A')} with {stats.get('requests',0)} HTTP requests."
        )

    async def generate_attack_chain(self, findings: list, target: str) -> str:
        if not findings: return ""
        crits = [(f.get("title","") if isinstance(f,dict) else f.title)
                 for f in findings
                 if (f.get("severity") if isinstance(f,dict) else f.severity) in ("Critical","High")][:5]
        prompt = (
            f"You are an expert penetration tester. Given these vulnerabilities in {target}:\n"
            f"{json.dumps(crits, indent=2)}\n\n"
            f"Write a realistic multi-step attack chain showing how an attacker would chain "
            f"these vulnerabilities together.\n"
            f"Format: numbered steps, each explains what attacker does and what they gain.\n"
            f"Be specific and technical. 5-8 steps max. No markdown headers."
        )
        return await self._call(prompt) or "Attack chain generation unavailable."

    async def explain_vulnerability(self, finding: dict) -> str:
        prompt = (
            f"Explain this vulnerability in simple terms for a developer:\n"
            f"Title: {finding.get('title')}\n"
            f"Evidence: {str(finding.get('evidence',''))[:200]}\n"
            f"OWASP: {finding.get('owasp','')}\n\n"
            f"3 paragraphs:\n"
            f"1. What is this? (simple analogy welcome)\n"
            f"2. How would attacker exploit it? (specific steps)\n"
            f"3. How to fix? (specific code example if possible)"
        )
        return await self._call(prompt) or "Explanation unavailable."

    async def _call(self, prompt: str) -> Optional[str]:
        fn = {
            "claude": self._claude,
            "openai": self._openai,
            "groq":   self._openai,
            "gemini": self._gemini,
            "ollama": self._ollama,
        }
        return await fn.get(self.provider, self._openai)(prompt)

    async def _claude(self, prompt: str) -> Optional[str]:
        try:
            async with aiohttp.ClientSession() as s:
                async with s.post("https://api.anthropic.com/v1/messages",
                    headers={"x-api-key":self.api_key,
                             "anthropic-version":"2023-06-01",
                             "Content-Type":"application/json"},
                    json={"model":"claude-opus-4-5","max_tokens":1200,
                          "messages":[{"role":"user","content":prompt}]},
                    timeout=aiohttp.ClientTimeout(total=40)) as r:
                    if r.status==200:
                        d=await r.json(); return d["content"][0]["text"]
                    logger.debug(f"Claude {r.status}: {await r.text()}")
        except Exception as e: logger.debug(f"Claude: {e}")
        return None

    async def _openai(self, prompt: str) -> Optional[str]:
        try:
            cfg=PROVIDERS.get(self.provider, PROVIDERS["openai"])
            async with aiohttp.ClientSession() as s:
                async with s.post(cfg["url"],
                    headers={"Authorization":f"Bearer {self.api_key}",
                             "Content-Type":"application/json"},
                    json={"model":cfg["model"],
                          "messages":[{"role":"user","content":prompt}],
                          "max_tokens":1200,"temperature":0.1},
                    timeout=aiohttp.ClientTimeout(total=40)) as r:
                    if r.status==200:
                        d=await r.json(); return d["choices"][0]["message"]["content"]
                    logger.debug(f"{self.provider} {r.status}")
        except Exception as e: logger.debug(f"{self.provider}: {e}")
        return None

    async def _gemini(self, prompt: str) -> Optional[str]:
        try:
            url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
                   f"gemini-1.5-pro:generateContent?key={self.api_key}")
            async with aiohttp.ClientSession() as s:
                async with s.post(url,
                    json={"contents":[{"parts":[{"text":prompt}]}]},
                    timeout=aiohttp.ClientTimeout(total=40)) as r:
                    if r.status==200:
                        d=await r.json()
                        return d["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e: logger.debug(f"Gemini: {e}")
        return None

    async def _ollama(self, prompt: str) -> Optional[str]:
        try:
            async with aiohttp.ClientSession() as s:
                async with s.post("http://localhost:11434/api/generate",
                    json={"model":self.api_key or "llama3",
                          "prompt":prompt,"stream":False},
                    timeout=aiohttp.ClientTimeout(total=90)) as r:
                    if r.status==200:
                        d=await r.json(); return d.get("response","")
        except Exception as e: logger.debug(f"Ollama: {e}")
        return None
