# cybercli/core/supply_chain.py
# -*- coding: utf-8 -*-
"""
Advanced Supply Chain Mapping
- 3rd-party resources (JS/CSS/img/iframe) detect
- DNS-based vendor inference (MX/NS/CNAME/CDN)
- Header tech hints (CDN / X-Powered-By / Server)
- Package manifests (package.json) + JS lib heuristics
- Wayback & page external domains aggregation
- Output multiple JSON artifacts under target dir
"""

from pathlib import Path
from typing import Any, Dict, List, Tuple
import re, json
import requests
from bs4 import BeautifulSoup
import tldextract

# -------------- helpers --------------

def _save_json(p: Path, data: Any):
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def _norm_domain(d: str) -> str:
    if not d:
        return ""
    ex = tldextract.extract(d)
    return f"{ex.domain}.{ex.suffix}" if ex.suffix else d

def _same_org_domain(a: str, b: str) -> bool:
    return _norm_domain(a) == _norm_domain(b)

def _abs_url(base: str, href: str) -> str:
    if not href:
        return ""
    if href.startswith("http://") or href.startswith("https://"):
        return href
    if href.startswith("//"):
        return "https:" + href
    if href.startswith("/"):
        return base.rstrip("/") + href
    return base.rstrip("/") + "/" + href

# -------------- extractors --------------

def extract_3p_resources(base_url: str, html_text: str, target_domain: str) -> List[Dict[str, str]]:
    out = []
    try:
        soup = BeautifulSoup(html_text or "", "html.parser")
    except Exception:
        return out

    nodes = []
    # JS, CSS
    nodes += [(x.get("src"), "script") for x in soup.find_all("script", src=True)]
    nodes += [(x.get("href"), "link") for x in soup.find_all("link", href=True)]
    # images
    nodes += [(x.get("src"), "img") for x in soup.find_all("img", src=True)]
    # iframes
    nodes += [(x.get("src"), "iframe") for x in soup.find_all("iframe", src=True)]

    seen = set()
    for href, typ in nodes:
        url = _abs_url(base_url, href)
        if not url or url in seen:
            continue
        seen.add(url)
        dom = _norm_domain(url)
        if dom and not _same_org_domain(dom, target_domain):
            out.append({"type": typ, "url": url, "domain": dom})
    return out

VENDOR_HINTS = {
    # email/MX
    "google": ["google.com", "gmail.com", "googlemail.com", "aspmx.l.google.com"],
    "office365": ["outlook.com", "protection.outlook.com", "office365.com"],
    "zoho": ["zoho.com"],
    "sendgrid": ["sendgrid.net"],
    "mailgun": ["mailgun.org", "mailgun.net"],
    "amazonses": ["amazonses.com"],
    # cdn / hosting / edge
    "cloudflare": ["cloudflare.com", "cdn.cloudflare.net", "cf-ipaddress", "cf-ray", "cf-cache-status"],
    "akamai": ["akamai.net", "akamaiedge.net", "akamaitechnologies.com"],
    "fastly": ["fastly.net"],
    "cloudfront": ["cloudfront.net"],
    "netlify": ["netlify.com", "netlify.app"],
    "vercel": ["vercel.com", "vercel-dns.com", "now.sh"],
    "heroku": ["herokuapp.com", "herokudns.com"],
    "github_pages": ["github.io"],
    "squarespace": ["squarespace.com"],
    "shopify": ["shopify.com", "myshopify.com"],
    # analytics/payment/helpdesk/etc.
    "google_analytics": ["googletagmanager.com", "google-analytics.com"],
    "segment": ["segment.com", "cdn.segment.com"],
    "stripe": ["stripe.com", "js.stripe.com"],
    "paypal": ["paypal.com"],
    "hotjar": ["hotjar.com"],
    "intercom": ["intercom.io"],
    "zendesk": ["zendesk.com"],
}

def infer_providers_from_dns(dns_records: Dict[str, List[str]]) -> Dict[str, Dict[str, List[str]]]:
    res: Dict[str, Dict[str, List[str]]] = {"mx": {}, "ns": {}, "cname": {}, "txt": {}}
    # MX
    for rec in dns_records.get("MX", []):
        for vendor, hints in VENDOR_HINTS.items():
            if any(h in rec.lower() for h in hints):
                res["mx"].setdefault(vendor, []).append(rec)
    # NS
    for rec in dns_records.get("NS", []):
        for vendor, hints in VENDOR_HINTS.items():
            if any(h in rec.lower() for h in hints):
                res["ns"].setdefault(vendor, []).append(rec)
    # TXT
    for rec in dns_records.get("TXT", []):
        low = rec.lower()
        # SPF includes
        for vendor, hints in VENDOR_HINTS.items():
            if any(h in low for h in hints):
                res["txt"].setdefault(vendor, []).append(rec)
    # CNAME (if SOA or A record text lines leak them — sometimes tools dump CNAME text together)
    for rtype in ["A", "AAAA", "SOA"]:
        for rec in dns_records.get(rtype, []):
            low = rec.lower()
            if "cname" in low or any(h in low for hs in VENDOR_HINTS.values() for h in hs):
                for vendor, hints in VENDOR_HINTS.items():
                    if any(h in low for h in hints):
                        res["cname"].setdefault(vendor, []).append(rec)
    return res

def header_tech_hints(headers: Dict[str, str]) -> Dict[str, Any]:
    if not headers:
        return {}
    H = {k.lower(): v for k, v in headers.items()}
    hints = {
        "server": H.get("server"),
        "x_powered_by": H.get("x-powered-by"),
        "via": H.get("via"),
        "cf": {k: v for k, v in H.items() if k.startswith("cf-")},  # cloudflare headers
    }
    # CDN inference via headers
    cdn = []
    if hints["cf"]:
        cdn.append("cloudflare")
    if hints["via"] and "akamai" in hints["via"].lower():
        cdn.append("akamai")
    if hints["server"]:
        s = hints["server"].lower()
        if "cloudfront" in s:
            cdn.append("cloudfront")
        if "fastly" in s:
            cdn.append("fastly")
        if "vercel" in s:
            cdn.append("vercel")
        if "netlify" in s:
            cdn.append("netlify")
    if cdn:
        hints["cdn_inferred"] = sorted(list(set(cdn)))
    return hints

LIB_REGEX = {
    "react": r"react(?:[-.]dom)?(?:@|\-)(\d+\.\d+\.\d+)|react(?:[-.]dom)?[-/](\d+\.\d+\.\d+)",
    "vue": r"vue(?:@|\-)(\d+\.\d+\.\d+)|vue[-/](\d+\.\d+\.\d+)",
    "angular": r"angular(?:@|\-)(\d+\.\d+\.\d+)|angular[-/](\d+\.\d+\.\d+)",
    "jquery": r"jquery(?:@|\-)(\d+\.\d+\.\d+)|jquery[-/](\d+\.\d+\.\d+)",
    "bootstrap": r"bootstrap(?:@|\-)(\d+\.\d+\.\d+)|bootstrap[-/](\d+\.\d+\.\d+)",
}

def guess_libs_from_html(html_text: str) -> Dict[str, str]:
    out = {}
    if not html_text:
        return out
    for lib, rgx in LIB_REGEX.items():
        m = re.findall(rgx, html_text, flags=re.IGNORECASE)
        # m is list of tuples (g1,g2); pick first non-empty
        ver = None
        for g1, g2 in m:
            if g1:
                ver = g1; break
            if g2:
                ver = g2; break
        if m:
            out[lib] = ver or "unknown"
    return out

def try_package_manifests(base_url: str) -> Dict[str, Any]:
    # try a few common locations for package.json (front-end builds sometimes expose it)
    paths = ["/package.json", "/static/package.json", "/assets/package.json"]
    out = {"fetched": [], "dependencies": {}}
    for p in paths:
        url = base_url.rstrip("/") + p
        try:
            r = requests.get(url, timeout=6)
            if r.status_code < 400 and r.headers.get("Content-Type", "").lower().startswith("application/json"):
                j = r.json()
                out["fetched"].append(url)
                for sec in ["dependencies", "devDependencies", "peerDependencies"]:
                    for k, v in (j.get(sec, {}) or {}).items():
                        out["dependencies"][k] = v
        except Exception:
            continue
    return out

def aggregate_external_domains(threep: List[Dict[str, str]], wayback: List[str]) -> List[str]:
    doms = set()
    for x in threep:
        doms.add(x.get("domain"))
    for u in (wayback or []):
        ex = tldextract.extract(u)
        d = f"{ex.domain}.{ex.suffix}" if ex.suffix else ""
        if d:
            doms.add(d)
    return sorted([d for d in doms if d])

def related_domains_from_whois_org(org_name: str, ext_domains: List[str], target_domain: str) -> List[str]:
    if not org_name:
        return []
    # naive heuristic: tokens from org in domain name string
    tokens = [t for t in re.split(r"[\W_]+", org_name.lower()) if len(t) >= 4]
    out = []
    for d in ext_domains:
        if _same_org_domain(d, target_domain):
            continue
        s = d.lower()
        if any(t in s for t in tokens):
            out.append(d)
    return sorted(list(set(out)))

# -------------- main --------------

def enumerate_supply_chain(
    domain: str,
    base_url: str,
    http_info: Dict[str, Any],
    dns_records: Dict[str, List[str]],
    wayback_urls: List[str],
    whois_obj: Dict[str, Any],
    out_dir: Path
) -> Dict[str, Any]:
    page = http_info or {}
    headers = page.get("headers", {}) or {}
    html_title = page.get("title")
    html_links = page.get("links", []) or []
    # fetch full HTML (for libs + resources) if needed
    html_text = ""
    try:
        url = page.get("final_url") or base_url
        r = requests.get(url, timeout=8, allow_redirects=True, verify=False, headers={"User-Agent": "cybercli/1.0"})
        html_text = r.text
    except Exception:
        pass

    # 3rd-party resource inventory
    third_party = extract_3p_resources(base_url, html_text, domain)

    # DNS → providers
    dns_vendors = infer_providers_from_dns(dns_records or {})

    # header hints
    hdr_hints = header_tech_hints(headers)

    # libs & pkgs
    html_libs = guess_libs_from_html(html_text)
    pkg = try_package_manifests(base_url)

    # external domains (from resources + wayback)
    ext_domains = aggregate_external_domains(third_party, wayback_urls or [])

    # WHOIS related org → related domains (heuristic)
    org_name = ""
    for k in ["org", "organization", "registrant_organization", "registrar", "name"]:
        v = whois_obj.get(k)
        if v and isinstance(v, str):
            org_name = v; break
    related_by_org = related_domains_from_whois_org(org_name, ext_domains, domain)

    # classify SaaS fingerprints from third-party domains
    saas_hits: Dict[str, List[str]] = {}
    for row in third_party:
        d = (row.get("domain") or "").lower()
        for vendor, hints in VENDOR_HINTS.items():
            if any(h in d for h in hints):
                saas_hits.setdefault(vendor, []).append(row["url"])

    result = {
        "target": domain,
        "base_url": base_url,
        "title": html_title,
        "third_party_resources": third_party,     # list of dicts
        "external_domains": ext_domains,          # list
        "dns_vendor_fingerprints": dns_vendors,   # dict
        "header_tech_hints": hdr_hints,           # dict
        "js_libs_detected": html_libs,            # dict
        "package_manifests": pkg,                 # dict {fetched, dependencies}
        "saas_integrations": {k: sorted(list(set(v))) for k, v in saas_hits.items()},
        "whois_org": org_name or None,
        "org_related_domains_guess": related_by_org,
        "summary": {
            "3p_count": len(third_party),
            "ext_domain_count": len(ext_domains),
            "vendors_mx": list((dns_vendors.get("mx") or {}).keys()),
            "vendors_cdn": list(set((hdr_hints.get("cdn_inferred") or []) + list((dns_vendors.get("ns") or {}).keys()))),
            "libs_count": len(html_libs),
            "pkg_dep_count": len(pkg.get("dependencies", {})),
            "saas_vendor_count": len(saas_hits),
        }
    }

    # write multiple artifacts
    _save_json(out_dir / "supply_chain.json", result)
    _save_json(out_dir / "third_party_resources.json", third_party)
    _save_json(out_dir / "external_domains.json", ext_domains)
    _save_json(out_dir / "dns_vendor_fingerprints.json", dns_vendors)
    _save_json(out_dir / "header_tech_hints.json", hdr_hints)
    _save_json(out_dir / "js_libs_detected.json", html_libs)
    _save_json(out_dir / "package_dependencies.json", pkg)
    _save_json(out_dir / "saas_integrations.json", {k: sorted(list(set(v))) for k, v in saas_hits.items()})
    _save_json(out_dir / "org_related_domains_guess.json", related_by_org)

    return result
