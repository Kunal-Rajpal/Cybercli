# One-man-army (cybercli)

This is a reconnaissance CLI skeleton (educational / authorized testing only).
It performs passive and basic active recon: whois, DNS, crt.sh, HTTP probing,
quick TCP connect scan, optional nmap, screenshots, basic dir brute, secret scans,
asset graph and a single-file HTML report.

**Run example**:
  python3 -m cybercli.main recon start example.com --osint --deep --screens --tra --graph --report --verbose --vibes

**Important**: Only run against assets you are authorized to test.

See `bootstrap.sh` for required system deps.

# ⬡ CyberCLI — AI-Powered Offensive Security Platform

> **Better than OWASP ZAP · Less False Positives · Full VAPT Reports**

---

## Architecture Overview

```
Target URL/Domain
       ↓
  Phase 1: Spider & Endpoint Discovery    ← crawler.py
       ↓
  Phase 2: Passive Scan (no attack)       ← passive_scan.py
       ↓
  Phase 3: Active Scanning                ← active_scan/scanner.py
       │   ├── sqli.py
       │   ├── xss.py
       │   ├── ssrf.py
       │   ├── path_traversal.py
       │   ├── jwt_attack.py
       │   └── open_redirect.py + more
       ↓
  Phase 4: AI False Positive Reduction    ← ai_engine/llm_analyzer.py
       ↓
  Phase 5: Attack Graph Generation        ← attackgraph/graph_builder.py
       ↓
  Phase 6: Professional VAPT Report       ← reporting/html_report.py
```

---

## Installation (Kali Linux)

```bash
# Clone or copy the project
cd /opt
git clone <your-repo> cybercli
cd cybercli

# Install dependencies
pip install -r requirements.txt --break-system-packages

# Install as CLI tool
pip install -e . --break-system-packages

# Install playwright browsers (for browser engine)
playwright install chromium
```

---

## Usage

### Full VAPT Scan
```bash
# Basic scan
python3 -m cybercli.main zap scan --target https://testphp.vulnweb.com

# With AI validation (reduces false positives significantly)
python3 -m cybercli.main zap scan \
  --target https://testphp.vulnweb.com \
  --ai-key sk-ant-YOUR_KEY_HERE

# Custom modules
python3 -m cybercli.main zap scan \
  --target https://example.com \
  --modules sqli,xss,ssrf,jwt_attack

# Quiet mode
python3 -m cybercli.main zap scan --target https://example.com --quiet
```

### Passive Scan Only (no attack traffic)
```bash
python3 -m cybercli.main zap passive-only --target https://example.com
```

### Attack Graph Only
```bash
python3 -m cybercli.main graph build --target https://company.com
```

### Check version / module status
```bash
python3 -m cybercli.main version
```

---

## Module Reference

### Active Scan Modules

| Module | Checks |
|--------|--------|
| `sqli` | Error-based, Boolean-based, Time-based SQL Injection |
| `xss` | Reflected XSS (HTML context, attribute context) |
| `ssrf` | AWS/GCP/Azure metadata, internal service access |
| `path_traversal` | LFI, directory traversal (`../../etc/passwd`) |
| `jwt_attack` | None algorithm, algorithm confusion, weak secrets |
| `open_redirect` | URL parameter hijacking |
| `cors` | Wildcard CORS, reflected origin + credentials |
| `csrf` | Missing CSRF tokens |
| `header_injection` | HTTP response splitting |
| `cache_poison` | Web cache deception/poisoning |
| `request_smuggling` | HTTP request smuggling (TE-CL, CL-TE) |

### Passive Scan Checks

| Check | Severity |
|-------|----------|
| Missing HSTS | Medium |
| Missing CSP | Medium |
| CSP unsafe-inline | Medium |
| CORS wildcard | Medium |
| Cookie missing Secure flag | Medium |
| Cookie missing HttpOnly | Medium |
| Cookie missing SameSite | Low |
| Stack trace exposure | Medium |
| Internal IP disclosure | Low |
| JWT weak algorithm in response | High |
| JWT None algorithm in request | Critical |
| Server technology disclosure | Low |
| Missing X-Content-Type-Options | Low |

---

## File Structure

```
cybercli/
├── main.py                     ← Entry point
├── core/
│   ├── proxy/
│   │   ├── proxy_server.py     ← MITM proxy engine
│   │   ├── passive_scan.py     ← Passive scanner (20+ checks)
│   │   ├── support_modules.py  ← Parser, interceptor, session, logger
│   │   └── crawler.py          ← Async spider
│   ├── active_scan/
│   │   └── scanner.py          ← Active scan orchestrator + modules
│   ├── attackgraph/
│   │   └── graph_builder.py    ← Attack graph (Maltego-style)
│   ├── ai_engine/
│   │   └── llm_analyzer.py     ← AI false positive reduction
│   └── reporting/
│       └── html_report.py      ← Professional HTML VAPT report
└── plugins/
    └── zapengine.py            ← CLI plugin (typer app)

artifacts/
├── reports/                    ← Generated VAPT reports
├── attack_graphs/              ← JSON attack graphs
├── proxy_logs/                 ← Traffic logs
└── screenshots/                ← Browser screenshots
```

---

## Integration Rules (IMPORTANT)

1. **Each module is isolated** — if proxy fails, active scan still runs
2. **Each phase is try/catch wrapped** — one crash = that phase skipped, not full abort
3. **AI is optional** — if no API key or AI fails, raw findings still reported
4. **Graph is optional** — if networkx missing, report still generated
5. **Never blocks other services** in your existing cybercli architecture

---

## AI False Positive Reduction (USP vs OWASP ZAP)

ZAP gives raw scanner output. CyberCLI validates each finding through Claude AI:

```
Finding Detected
      ↓
AI validates:
  - Is payload actually executed/reflected?
  - Is there auth context blocking exploitation?
  - Is the path reachable from the internet?
  - What is the real business impact?
  - Confidence score: 0.0 – 1.0
      ↓
True Positive (confidence > 0.7) → Include in report
False Positive                    → Suppress (still logged)
```

---

## VAPT Report Contents

The generated HTML report includes:
- **Cover Page** — Risk score gauge, overall rating
- **Executive Summary** — C-level language, business impact
- **Statistics** — Critical/High/Medium/Low breakdown
- **Attack Graph** — Visual domain/service map
- **Technical Findings** — Full details per vulnerability
  - URL, parameter, payload, evidence
  - CVSS score with visual bar
  - Real-world attack scenario
  - Step-by-step remediation
- **Remediation Roadmap** — Priority-ordered fix table
- **AI-Suppressed FPs** — Transparent false positive log

---

## Legal

**Use only on systems you have explicit written authorization to test.**
Unauthorized scanning is illegal. This tool is for authorized penetration testing only.



# ⬡ CyberCLI — AI-Powered VAPT Platform

## Install (Kali Linux)
```bash
pip install -r requirements.txt --break-system-packages
pip install -e . --break-system-packages
```

## Usage
```bash
# Basic VAPT scan → generates HTML report
cybercli zap scan --target https://testphp.vulnweb.com

# With Claude AI validation (best)
cybercli zap scan --target https://example.com --ai-provider claude --ai-key sk-ant-...

# With Groq (free tier available)
cybercli zap scan --target https://example.com --ai-provider groq --ai-key gsk_...

# With OpenAI GPT-4
cybercli zap scan --target https://example.com --ai-provider openai --ai-key sk-proj-...

# With Google Gemini
cybercli zap scan --target https://example.com --ai-provider gemini --ai-key AIza...

# Passive scan only (no attack traffic)
cybercli zap passive-only --target https://example.com

# Build attack graph
cybercli graph build --target https://example.com

# Auto-open report in browser
cybercli zap scan --target https://example.com --open
```

## What the Report Contains
1. Risk gauge + overall score
2. Radar chart (OWASP Top 10)
3. Severity donut chart
4. Bug category bar chart
5. CVSS score distribution chart
6. Attack surface polar chart
7. Discovery timeline
8. SVG attack graph flowchart
9. Security headers analysis (with WHY it matters + exact fix)
10. Endpoint table (all discovered URLs)
11. Full vulnerability findings (expandable, with proof/evidence)
12. Remediation roadmap table
13. Executive summary (AI-generated if key provided)
