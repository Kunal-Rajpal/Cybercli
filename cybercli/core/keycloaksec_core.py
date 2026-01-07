## First Phase Testing -----------
# # Keycloak Security Core – UI Login + Discovery + Screenshots
# # Ethical | Playwright | Headless | Keycloak v26+

# import os
# import re
# import json
# import time
# import requests
# from datetime import datetime
# from urllib.parse import urlparse
# from playwright.sync_api import sync_playwright

# requests.packages.urllib3.disable_warnings()


# class KeycloakSecCore:
#     def __init__(self, target, outdir="reports/output", headless=True):
#         self.raw_target = target
#         self.base_url = self._normalize(target)
#         self.outdir = outdir
#         self.headless = headless

#         self.evidence = os.path.join(outdir, "evidence")
#         self.logs = os.path.join(outdir, "logs")
#         self.html = os.path.join(outdir, "html")

#         for d in [self.evidence, self.logs, self.html]:
#             os.makedirs(d, exist_ok=True)

#         self.final_url = None
#         self.realm = None

#     # -----------------------
#     def _normalize(self, url):
#         if not url.startswith("http"):
#             return f"https://{url.strip('/')}"
#         return url.rstrip("/")

#     # -----------------------
#     def auto_redirect_discovery(self):
#         """
#         Open site in browser to allow redirect to Keycloak
#         """
#         with sync_playwright() as p:
#             browser = p.chromium.launch(headless=True)
#             page = browser.new_page(ignore_https_errors=True)
#             page.goto(self.base_url, timeout=60000)
#             page.wait_for_load_state("networkidle")
#             self.final_url = page.url
#             browser.close()

#         return self.final_url

#     # -----------------------
#     def extract_realm(self):
#         if not self.final_url:
#             return None
#         match = re.search(r"/realms/([^/]+)/", self.final_url)
#         if match:
#             self.realm = match.group(1)
#         return self.realm

#     # -----------------------
#     def take_public_screenshot(self):
#         with sync_playwright() as p:
#             browser = p.chromium.launch(headless=self.headless)
#             page = browser.new_page(ignore_https_errors=True)
#             page.goto(self.final_url or self.base_url, timeout=60000)
#             page.wait_for_load_state("networkidle")
#             page.screenshot(
#                 path=f"{self.evidence}/01_public_login.png",
#                 full_page=True
#             )
#             browser.close()

#     # -----------------------
#     def ui_login(self, username, password):
#         """
#         Perform UI login using Keycloak standard locators
#         """
#         with sync_playwright() as p:
#             browser = p.chromium.launch(headless=self.headless)
#             context = browser.new_context(ignore_https_errors=True)
#             page = context.new_page()

#             page.goto(self.final_url, timeout=60000)
#             page.wait_for_load_state("networkidle")

#             # Fill username
#             page.fill(
#                 "input[name='username'], input#username, input[type='text']",
#                 username
#             )

#             # Fill password
#             page.fill(
#                 "input[name='password'], input#password, input[type='password']",
#                 password
#             )

#             # Click Keycloak login button
#             page.click("//input[@id='kc-login']")

#             page.wait_for_load_state("networkidle")
#             time.sleep(3)

#             # After login screenshot
#             page.screenshot(
#                 path=f"{self.evidence}/02_after_login.png",
#                 full_page=True
#             )

#             self.final_url = page.url
#             browser.close()

#     # -----------------------
#     def generate_report(self, data):
#         # JSON
#         with open(f"{self.logs}/results.json", "w") as f:
#             json.dump(data, f, indent=2)

#         # HTML
#         html = f"""
#         <html>
#         <head><title>Keycloak Scan</title></head>
#         <body style="background:black;color:#00ffee;font-family:monospace">
#         <h1>Keycloak Security Scan</h1>
#         <pre>{json.dumps(data, indent=2)}</pre>
#         </body>
#         </html>
#         """
#         with open(f"{self.html}/index.html", "w") as f:
#             f.write(html)

#     # -----------------------
#     def run(self, creds=None):
#         result = {
#             "target": self.raw_target,
#             "normalized": self.base_url,
#             "start_time": datetime.utcnow().isoformat()
#         }

#         # Step 1: Redirect discovery
#         result["redirect_url"] = self.auto_redirect_discovery()

#         # Step 2: Realm extraction
#         result["realm"] = self.extract_realm()

#         # Step 3: Public screenshot
#         self.take_public_screenshot()

#         # Step 4: Optional login
#         if creds:
#             self.ui_login(
#                 creds["username"],
#                 creds["password"]
#             )
#             result["login"] = "success"
#             result["post_login_url"] = self.final_url
#         else:
#             result["login"] = "skipped"

#         result["end_time"] = datetime.utcnow().isoformat()
#         self.generate_report(result)

#         return result



## Second Phase Testing ------------
# cybercli/core/keycloaksec_core.py
# Keycloak Security Core — FINAL STABLE BUILD
# Playwright only | Dynamic Login | Token Capture | Security Intelligence

# import os
# import re
# import json
# import time
# import requests
# from datetime import datetime
# from urllib.parse import urlparse, urljoin
# import jwt

# requests.packages.urllib3.disable_warnings()

# from playwright.sync_api import sync_playwright


# class KeycloakSecCore:
#     def __init__(self, target, outdir="reports/output", headless=True):
#         self.raw_target = target
#         self.base_url = self._normalize(target)
#         self.outdir = outdir
#         self.headless = headless

#         self.session = requests.Session()
#         self.session.verify = False

#         self.evidence_dir = os.path.join(outdir, "evidence")
#         self.report_dir = os.path.join(outdir, "reports")

#         os.makedirs(self.evidence_dir, exist_ok=True)
#         os.makedirs(self.report_dir, exist_ok=True)

#         self.result = {
#             "target": self.raw_target,
#             "normalized": self.base_url,
#             "start_time": datetime.utcnow().isoformat(),
#             "redirect_url": None,
#             "realm": None,
#             "well_known": {},
#             "headers": {},
#             "mfa": {},
#             "admin_console": {},
#             "tokens": {},
#             "roles": {},
#             "post_login_urls": []
#         }

#     # ------------------ UTIL ------------------

#     def _normalize(self, url):
#         if url.startswith("http://") or url.startswith("https://"):
#             return url
#         return f"https://{url}"

#     def _save_json(self):
#         with open(os.path.join(self.report_dir, "result.json"), "w") as f:
#             json.dump(self.result, f, indent=2)

#     # ------------------ DISCOVERY ------------------

#     def auto_redirect_discovery(self):
#         with sync_playwright() as p:
#             browser = p.chromium.launch(headless=self.headless)
#             page = browser.new_page(ignore_https_errors=True)
#             page.goto(self.base_url, timeout=60000)
#             page.wait_for_load_state("networkidle")
#             final_url = page.url
#             browser.close()

#         self.result["redirect_url"] = final_url
#         return final_url

#     def extract_realm(self):
#         url = self.result["redirect_url"]
#         if not url:
#             return None
#         m = re.search(r"/realms/([^/]+)", url)
#         if m:
#             self.result["realm"] = m.group(1)
#             return m.group(1)
#         return None

#     def well_known_discovery(self):
#         if not self.result["realm"]:
#             return
#         wk = f"{urlparse(self.result['redirect_url']).scheme}://{urlparse(self.result['redirect_url']).netloc}/realms/{self.result['realm']}/.well-known/openid-configuration"
#         try:
#             r = self.session.get(wk, timeout=10)
#             if r.status_code == 200:
#                 self.result["well_known"] = r.json()
#         except:
#             pass

#     # ------------------ HEADERS ------------------

#     def check_headers(self):
#         try:
#             r = self.session.get(self.base_url, timeout=10)
#             self.result["headers"] = {
#                 "csp": r.headers.get("Content-Security-Policy"),
#                 "hsts": r.headers.get("Strict-Transport-Security"),
#                 "xfo": r.headers.get("X-Frame-Options"),
#                 "referrer": r.headers.get("Referrer-Policy"),
#                 "cookies": r.headers.get("Set-Cookie")
#             }
#         except:
#             pass

#     # ------------------ ADMIN ------------------

#     def admin_console_check(self):
#         paths = ["/admin/", "/auth/admin/"]
#         base = f"{urlparse(self.result['redirect_url']).scheme}://{urlparse(self.result['redirect_url']).netloc}"
#         for p in paths:
#             try:
#                 r = self.session.get(base + p, timeout=5)
#                 self.result["admin_console"][p] = r.status_code
#             except:
#                 pass

#     # ------------------ LOGIN ENGINE ------------------

#     def ui_login(self, username, password):
#         with sync_playwright() as p:
#             browser = p.chromium.launch(headless=self.headless)
#             context = browser.new_context(ignore_https_errors=True)
#             page = context.new_page()

#             page.goto(self.base_url, timeout=60000)
#             page.wait_for_load_state("networkidle")

#             page.screenshot(path=f"{self.evidence_dir}/before_login.png")

#             # Dynamic locator hunt
#             def find(selectors):
#                 for s in selectors:
#                     el = page.query_selector(s)
#                     if el:
#                         return el
#                 return None

#             user = find([
#                 "input[name*=user i]",
#                 "input[name*=email i]",
#                 "input[type='text']"
#             ])
#             pwd = find([
#                 "input[type='password']"
#             ])
#             btn = find([
#                 "#kc-login",
#                 "button[type='submit']",
#                 "button:has-text('Log in')",
#                 "button:has-text('Sign in')",
#                 "input[type='submit']"
#             ])

#             if user and pwd and btn:
#                 user.fill(username)
#                 pwd.fill(password)
#                 btn.click()
#                 page.wait_for_load_state("networkidle")
#                 time.sleep(3)

#             page.screenshot(path=f"{self.evidence_dir}/after_login.png")

#             # Capture tokens
#             storage = context.storage_state()
#             self.result["tokens"]["storage"] = storage

#             # Decode JWT if found
#             for origin in storage.get("origins", []):
#                 for item in origin.get("localStorage", []):
#                     if "token" in item["name"].lower():
#                         try:
#                             decoded = jwt.decode(item["value"], options={"verify_signature": False})
#                             self.result["tokens"]["decoded"] = decoded
#                             self.result["roles"] = decoded.get("realm_access", {})
#                         except:
#                             pass

#             # Mini crawl
#             links = page.query_selector_all("a")
#             for a in links[:5]:
#                 href = a.get_attribute("href")
#                 if href and href.startswith("/"):
#                     self.result["post_login_urls"].append(href)

#             browser.close()

#     # ------------------ MFA ------------------

#     def detect_mfa(self):
#         url = self.result["redirect_url"]
#         if url and any(x in url.lower() for x in ["otp", "totp", "authenticator"]):
#             self.result["mfa"] = {"enabled": True}
#         else:
#             self.result["mfa"] = {"enabled": False}

#     # ------------------ RUN ------------------

#     def run(self, creds=None):
#         self.auto_redirect_discovery()
#         self.extract_realm()
#         self.well_known_discovery()
#         self.check_headers()
#         self.admin_console_check()
#         self.detect_mfa()

#         if creds:
#             self.ui_login(creds["username"], creds["password"])

#         self.result["end_time"] = datetime.utcnow().isoformat()
#         self._save_json()
#         return self.result





# ## Third Phase Testing ------------------------
# # cybercli/core/keycloaksec_core.py
# # Keycloak Security Core — FINAL EXTENDED BUILD
# # Stable + Advanced Intelligence (NON-DESTRUCTIVE)

# import os, re, json, time, requests
# from datetime import datetime
# from urllib.parse import urlparse
# import jwt

# requests.packages.urllib3.disable_warnings()

# from playwright.sync_api import sync_playwright


# class KeycloakSecCore:
#     def __init__(self, target, outdir="reports/output", headless=True):
#         self.raw_target = target
#         self.base_url = self._normalize(target)
#         self.outdir = outdir
#         self.headless = headless

#         self.session = requests.Session()
#         self.session.verify = False

#         self.evidence_dir = os.path.join(outdir, "evidence")
#         self.report_dir = os.path.join(outdir, "reports")
#         self.pdf_dir = os.path.join(outdir, "pdf")

#         for d in [self.evidence_dir, self.report_dir, self.pdf_dir]:
#             os.makedirs(d, exist_ok=True)

#         self.result = {
#             "target": self.raw_target,
#             "normalized": self.base_url,
#             "start_time": datetime.utcnow().isoformat(),
#             "redirect_url": None,
#             "realm": None,
#             "keycloak_detected": False,
#             "confidence": 0,
#             "well_known": {},
#             "headers": {},
#             "mfa": {},
#             "admin_console": {},
#             "tokens": {},
#             "roles": {},
#             "post_login_urls": [],
#             "owasp_findings": [],
#             "misconfigurations": []
#         }

#     # ------------------ UTIL ------------------

#     def _normalize(self, url):
#         if url.startswith("http://") or url.startswith("https://"):
#             return url
#         return f"https://{url}"

#     def _save_json(self):
#         with open(os.path.join(self.report_dir, "result.json"), "w") as f:
#             json.dump(self.result, f, indent=2)

#     # ------------------ AUTO REDIRECT ------------------

#     def auto_redirect_discovery(self):
#         with sync_playwright() as p:
#             browser = p.chromium.launch(headless=self.headless)
#             page = browser.new_page(ignore_https_errors=True)
#             page.goto(self.base_url, timeout=60000)
#             page.wait_for_load_state("networkidle")
#             final_url = page.url
#             browser.close()

#         self.result["redirect_url"] = final_url
#         return final_url

#     # ------------------ REALM ------------------

#     def extract_realm(self):
#         url = self.result["redirect_url"]
#         if not url:
#             return None
#         m = re.search(r"/realms/([^/]+)", url)
#         if m:
#             self.result["realm"] = m.group(1)
#             return m.group(1)
#         return None

#     # ------------------ WELL KNOWN ------------------

#     def well_known_discovery(self):
#         if not self.result["realm"]:
#             return
#         parsed = urlparse(self.result["redirect_url"])
#         wk = f"{parsed.scheme}://{parsed.netloc}/realms/{self.result['realm']}/.well-known/openid-configuration"
#         try:
#             r = self.session.get(wk, timeout=10)
#             if r.status_code == 200:
#                 self.result["well_known"] = r.json()
#                 self.result["keycloak_detected"] = True
#                 self.result["confidence"] += 40
#         except:
#             pass

#     # ------------------ HEADERS ------------------

#     def check_headers(self):
#         try:
#             r = self.session.get(self.result["redirect_url"], timeout=10)
#             h = r.headers
#             self.result["headers"] = {
#                 "csp": h.get("Content-Security-Policy"),
#                 "hsts": h.get("Strict-Transport-Security"),
#                 "xfo": h.get("X-Frame-Options"),
#                 "referrer": h.get("Referrer-Policy"),
#                 "cookies": h.get("Set-Cookie")
#             }

#             if not h.get("Strict-Transport-Security"):
#                 self._owasp("Missing HSTS", "Medium", "A2: Cryptographic Failures")

#         except:
#             pass

#     # ------------------ ADMIN ------------------

#     def admin_console_check(self):
#         parsed = urlparse(self.result["redirect_url"])
#         base = f"{parsed.scheme}://{parsed.netloc}"
#         for p in ["/admin/", "/auth/admin/"]:
#             try:
#                 r = self.session.get(base + p, timeout=5)
#                 self.result["admin_console"][p] = r.status_code
#                 if r.status_code == 200:
#                     self._owasp("Admin console exposed", "High", "A5: Security Misconfiguration")
#             except:
#                 pass

#     # ------------------ LOGIN ------------------

#     def ui_login(self, username, password):
#         with sync_playwright() as p:
#             browser = p.chromium.launch(headless=self.headless)
#             context = browser.new_context(ignore_https_errors=True)
#             page = context.new_page()

#             page.goto(self.base_url, timeout=60000)
#             page.wait_for_load_state("networkidle")
#             page.screenshot(path=f"{self.evidence_dir}/before_login.png")

#             def find(selectors):
#                 for s in selectors:
#                     el = page.query_selector(s)
#                     if el:
#                         return el
#                 return None

#             user = find([
#                 "input[name*=user i]",
#                 "input[name*=email i]",
#                 "input[type='text']"
#             ])
#             pwd = find(["input[type='password']"])
#             btn = find([
#                 "#kc-login",
#                 "button[type='submit']",
#                 "button:has-text('Log in')",
#                 "button:has-text('Sign in')",
#                 "input[type='submit']"
#             ])

#             if user and pwd and btn:
#                 user.fill(username)
#                 pwd.fill(password)
#                 btn.click()
#                 page.wait_for_load_state("networkidle")
#                 time.sleep(3)

#             page.screenshot(path=f"{self.evidence_dir}/after_login.png")

#             storage = context.storage_state()
#             self.result["tokens"]["storage"] = storage

#             for origin in storage.get("origins", []):
#                 for item in origin.get("localStorage", []):
#                     if "token" in item["name"].lower():
#                         try:
#                             decoded = jwt.decode(item["value"], options={"verify_signature": False})
#                             self.result["tokens"]["decoded"] = decoded
#                             self.result["roles"] = decoded.get("realm_access", {})
#                             self._analyze_token(decoded)
#                         except:
#                             pass

#             links = page.query_selector_all("a")
#             for a in links[:5]:
#                 href = a.get_attribute("href")
#                 if href and href.startswith("/"):
#                     self.result["post_login_urls"].append(href)

#             browser.close()

#     # ------------------ MFA ------------------

#     def detect_mfa(self):
#         url = self.result["redirect_url"]
#         if url and any(x in url.lower() for x in ["otp", "totp", "authenticator"]):
#             self.result["mfa"] = {"enabled": True}
#             self._owasp("MFA enforced", "Info", "Best Practice")
#         else:
#             self.result["mfa"] = {"enabled": False}
#             self._owasp("MFA not enforced", "Medium", "A2: Auth Failures")

#     # ------------------ TOKEN ANALYSIS ------------------

#     def _analyze_token(self, decoded):
#         exp = decoded.get("exp", 0)
#         iat = decoded.get("iat", 0)
#         if exp and iat and (exp - iat) > 3600:
#             self._owasp("Long-lived access token", "Medium", "A5: Misconfiguration")

#         roles = decoded.get("realm_access", {}).get("roles", [])
#         if any(r in roles for r in ["admin", "realm-admin"]):
#             self._owasp("Admin role in user token", "High", "A1: Broken Access Control")

#     # ------------------ OWASP ------------------

#     def _owasp(self, issue, severity, category):
#         self.result["owasp_findings"].append({
#             "issue": issue,
#             "severity": severity,
#             "category": category
#         })

#     # ------------------ RUN ------------------

#     def run(self, creds=None):
#         self.auto_redirect_discovery()
#         self.extract_realm()
#         self.well_known_discovery()
#         self.check_headers()
#         self.admin_console_check()
#         self.detect_mfa()

#         if creds:
#             self.ui_login(creds["username"], creds["password"])

#         self.result["end_time"] = datetime.utcnow().isoformat()
#         self._save_json()
#         return self.result





# cybercli/core/keycloaksec_core.py
# KEYCLOAK SECURITY CORE — STABLE + FULLY INTEGRATED
# Ethical • Non-destructive • Playwright • Advanced Analysis

import os, re, json, time, requests
from datetime import datetime
from urllib.parse import urlparse
import jwt

from playwright.sync_api import sync_playwright
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

requests.packages.urllib3.disable_warnings()


class KeycloakSecCore:
    def __init__(self, target, outdir="reports/output", headless=True):
        self.raw_target = target
        self.base_url = self._normalize(target)
        self.headless = headless

        self.session = requests.Session()
        self.session.verify = False

        self.outdir = outdir
        self.evidence = os.path.join(outdir, "evidence")
        self.reports = os.path.join(outdir, "reports")
        self.pdfdir = os.path.join(outdir, "pdf")

        for d in [self.evidence, self.reports, self.pdfdir]:
            os.makedirs(d, exist_ok=True)

        self.result = {
            "target": self.raw_target,
            "normalized": self.base_url,
            "start_time": datetime.utcnow().isoformat(),
            "redirect_url": None,
            "realm": None,
            "keycloak_detected": False,
            "confidence": 0,
            "well_known": {},
            "headers": {},
            "csp_analysis": {},
            "mfa": {},
            "admin_console": {},
            "tokens": {},
            "api_permissions": {},
            "realm_export": {},
            "owasp_findings": [],
            "post_login_urls": []
        }

    # ---------------- UTIL ----------------

    def _normalize(self, url):
        if url.startswith("http"):
            return url.rstrip("/")
        return f"https://{url.rstrip('/')}"

    def _save_json(self):
        with open(os.path.join(self.reports, "result.json"), "w") as f:
            json.dump(self.result, f, indent=2)

    def _owasp(self, issue, severity, category):
        self.result["owasp_findings"].append({
            "issue": issue,
            "severity": severity,
            "category": category
        })

    # ---------------- DISCOVERY ----------------

    def auto_redirect_discovery(self):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            page = browser.new_page(ignore_https_errors=True)
            page.goto(self.base_url, timeout=60000)
            page.wait_for_load_state("networkidle")
            self.result["redirect_url"] = page.url
            browser.close()

    def extract_realm(self):
        url = self.result["redirect_url"]
        if not url:
            return
        m = re.search(r"/realms/([^/]+)", url)
        if m:
            self.result["realm"] = m.group(1)

    def well_known_discovery(self):
        if not self.result["realm"]:
            return
        parsed = urlparse(self.result["redirect_url"])
        wk = f"{parsed.scheme}://{parsed.netloc}/realms/{self.result['realm']}/.well-known/openid-configuration"
        r = self.session.get(wk, timeout=10)
        if r.status_code == 200 and "json" in r.headers.get("content-type", ""):
            self.result["well_known"] = r.json()
            self.result["keycloak_detected"] = True
            self.result["confidence"] += 40

    # ---------------- HEADERS + CSP ----------------

    def check_headers(self):
        r = self.session.get(self.result["redirect_url"], timeout=10)
        h = r.headers
        self.result["headers"] = dict(h)

        csp = h.get("Content-Security-Policy")
        if not csp:
            self._owasp("Missing CSP", "Medium", "A5: Security Misconfiguration")
        else:
            self._analyze_csp(csp)

    def _analyze_csp(self, csp):
        issues = []
        if "'unsafe-inline'" in csp:
            issues.append("unsafe-inline")
        if "'unsafe-eval'" in csp:
            issues.append("unsafe-eval")
        if "*" in csp:
            issues.append("wildcard")

        self.result["csp_analysis"] = {
            "policy": csp,
            "issues": issues
        }

        if issues:
            self._owasp("Weak CSP detected", "Medium", "A3: Injection")

    # ---------------- ADMIN ----------------

    def admin_console_check(self):
        parsed = urlparse(self.result["redirect_url"])
        base = f"{parsed.scheme}://{parsed.netloc}"
        for p in ["/admin/", "/auth/admin/"]:
            r = self.session.get(base + p, timeout=5)
            self.result["admin_console"][p] = r.status_code
            if r.status_code == 200:
                self._owasp("Admin console exposed", "High", "A5: Misconfiguration")

    # ---------------- MFA ----------------

    def detect_mfa(self):
        url = self.result["redirect_url"].lower()
        enabled = any(x in url for x in ["otp", "totp", "authenticator"])
        self.result["mfa"] = {"enabled": enabled}
        if not enabled:
            self._owasp("MFA not enforced", "Medium", "A2: Auth Failures")

    # ---------------- UI LOGIN ----------------

    def ui_login(self, username, password):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()

            page.goto(self.base_url, timeout=60000)
            page.wait_for_load_state("networkidle")
            page.screenshot(path=f"{self.evidence}/01_before_login.png", full_page=True)

            def find(selectors):
                for s in selectors:
                    el = page.query_selector(s)
                    if el:
                        return el
                return None

            user = find(["input[name*=user i]", "input[type='text']"])
            pwd = find(["input[type='password']"])
            btn = find([
                "#kc-login",
                "button[type='submit']",
                "input[type='submit']"
            ])

            if user and pwd and btn:
                user.fill(username)
                pwd.fill(password)
                btn.click()
                page.wait_for_load_state("networkidle")
                time.sleep(3)

            page.screenshot(path=f"{self.evidence}/02_after_login.png", full_page=True)

            storage = context.storage_state()
            self._analyze_tokens(storage)

            links = page.query_selector_all("a")
            for a in links[:10]:
                href = a.get_attribute("href")
                if href:
                    self.result["post_login_urls"].append(href)

            browser.close()

    # ---------------- TOKEN + API PERMS ----------------

    def _analyze_tokens(self, storage):
        self.result["tokens"]["raw"] = storage
        for origin in storage.get("origins", []):
            for item in origin.get("localStorage", []):
                if "token" in item["name"].lower():
                    try:
                        decoded = jwt.decode(
                            item["value"],
                            options={"verify_signature": False}
                        )
                        self.result["tokens"]["decoded"] = decoded
                        self._analyze_api_permissions(decoded)
                    except:
                        pass

    def _analyze_api_permissions(self, decoded):
        scopes = decoded.get("scope", "")
        roles = decoded.get("realm_access", {}).get("roles", [])
        self.result["api_permissions"] = {
            "scopes": scopes,
            "roles": roles
        }

        if "admin" in " ".join(roles).lower():
            self._owasp("Admin role in access token", "High", "A1: Broken Access Control")

    # ---------------- REALM EXPORT PARSER ----------------

    def realm_export_check(self):
        if not self.result["realm"]:
            return
        parsed = urlparse(self.result["redirect_url"])
        url = f"{parsed.scheme}://{parsed.netloc}/realms/{self.result['realm']}"
        r = self.session.get(url, timeout=10)
        self.result["realm_export"] = {
            "status": r.status_code,
            "accessible": r.status_code == 200
        }
        if r.status_code == 200:
            self._owasp("Realm metadata accessible", "Medium", "A5: Misconfiguration")

    # ---------------- PDF REPORT ----------------

    def generate_pdf(self):
        path = os.path.join(self.pdfdir, "keycloak_report.pdf")
        c = canvas.Canvas(path, pagesize=A4)
        text = c.beginText(50, 250)
        text.setFont("Helvetica", 9)

        for k, v in self.result.items():
            text.textLine(f"{k}: {str(v)[:120]}")
            text.textLine("")

        c.drawText(text)
        c.save()

    # ---------------- RUN ----------------

    def run(self, creds=None):
        self.auto_redirect_discovery()
        self.extract_realm()
        self.well_known_discovery()
        self.check_headers()
        self.admin_console_check()
        self.detect_mfa()
        self.realm_export_check()

        if creds:
            self.ui_login(creds["username"], creds["password"])

        self.result["end_time"] = datetime.utcnow().isoformat()
        self._save_json()
        self.generate_pdf()
        return self.result





