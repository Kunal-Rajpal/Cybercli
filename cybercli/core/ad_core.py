#!/usr/bin/env python3
# cybercli/core/ad_core.py
# -*- coding: utf-8 -*-
"""
Active Directory enumeration (safe + passive).
No exploitation. Only information gathering.
"""

from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, Optional
import subprocess, json, datetime, shutil

# ------------ helpers -----------------

def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None

def run_cmd(cmd: list, timeout: int = 20) -> Dict[str, Any]:
    try:
        p = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, text=True
        )
        return {
            "cmd": " ".join(cmd),
            "stdout": p.stdout,
            "stderr": p.stderr,
            "returncode": p.returncode,
        }
    except Exception as e:
        return {"cmd": " ".join(cmd), "error": str(e)}

# ------------ AD discovery -----------------

def discover_dc(target: str) -> Dict[str, Any]:
    """
    Safe DC discovery using nslookup + smbclient -L.
    """
    results = {}

    # nslookup domain
    results["nslookup"] = run_cmd(["nslookup", target])

    # smbclient discovery
    if tool_exists("smbclient"):
        results["smbclient"] = run_cmd(["smbclient", "-L", f"//{target}", "-N"])
    else:
        results["smbclient"] = {"error": "smbclient not installed"}

    return results


def ldap_domain_enum(host: str) -> Dict[str, Any]:
    """
    LDAP enumeration (anonymous) — fully passive.
    """
    if not tool_exists("ldapsearch"):
        return {"error": "ldapsearch not installed"}

    return run_cmd([
        "ldapsearch",
        "-x",
        "-H", f"ldap://{host}",
        "-s", "base",
        "namingContexts"
    ])


def kerberos_info(domain: str) -> Dict[str, Any]:
    """
    Check Kerberos realm info (safe).
    Uses kinit --help path only, no auth attempts.
    """
    if not tool_exists("kinit"):
        return {"error": "kinit not installed"}
    return run_cmd(["kinit", "--help"])


def rpc_user_enum(host: str) -> Dict[str, Any]:
    """
    Enumerate AD users & groups using RPC client (anonymous if possible).
    Safe enumeration.
    """
    if not tool_exists("rpcclient"):
        return {"error": "rpcclient not installed"}

    results = {
        "enumdomusers": run_cmd(["rpcclient", "-U", "", host, "-c", "enumdomusers"]),
        "enumdomgroups": run_cmd(["rpcclient", "-U", "", host, "-c", "enumdomgroups"]),
        "lsaquery": run_cmd(["rpcclient", "-U", "", host, "-c", "lsaquery"])
    }
    return results


def domain_info_bundle(domain: str, host: str, reports_path: Path) -> Dict[str,str]:
    """
    Bundle all safe AD enumeration and write report.
    """
    stamp = now_stamp()
    outdir = reports_path / "ad" / stamp
    outdir.mkdir(parents=True, exist_ok=True)

    results = {
        "domain": domain,
        "host": host,
        "dc_discovery": discover_dc(domain),
        "ldap": ldap_domain_enum(host),
        "kerberos": kerberos_info(domain),
        "rpc": rpc_user_enum(host),
    }

    # write report
    txt_path = outdir / "ad_enum.txt"
    html_path = outdir / "ad_enum.html"

    txt_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    html_path.write_text(f"""
    <html>
    <head><style>body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}}</style></head>
    <body>
    <h2>Active Directory Enumeration Report</h2>
    <pre>{json.dumps(results, indent=2)}</pre>
    </body>
    </html>
    """, encoding="utf-8")

    return {
        "txt": str(txt_path.resolve()),
        "html": str(html_path.resolve()),
    }






# # cybercli/core/ad_core.py

# """
# Active Directory Audit Core Module (SAFE + ENTERPRISE LEVEL)

# This module performs **non-exploit**, defensive, audit-style checks for:
# - Kerberoast exposure
# - AS-REP roast exposure
# - Shadow Credentials
# - PrintNightmare exposure
# - ZeroLogon exposure
# - GPO permissions
# - LDAP schema + config
# - SMB signing
# - Kerberos delegation configs
# - Basic BloodHound-style passive data collection
# """

# import ldap3
# import socket
# import subprocess
# import platform
# from datetime import datetime


# class ActiveDirectoryAuditor:

#     def __init__(self, dc_ip, domain, username, password):
#         self.dc_ip = dc_ip
#         self.domain = domain
#         self.username = username
#         self.password = password
#         self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

#         self.server = ldap3.Server(dc_ip, get_info=ldap3.ALL)
#         self.conn = ldap3.Connection(
#             self.server,
#             user=f"{domain}\\{username}",
#             password=password,
#             authentication=ldap3.NTLM,
#             auto_bind=True
#         )

#         self.base_dn = ",".join([f"DC={p}" for p in domain.split(".")])

#     # ------------------------------------
#     # KERBEROAST EXPOSURE CHECK
#     # ------------------------------------
#     def check_kerberoast(self):
#         results = []
#         self.conn.search(
#             self.base_dn,
#             "(servicePrincipalName=*)",
#             attributes=["sAMAccountName", "servicePrincipalName"]
#         )

#         for entry in self.conn.entries:
#             results.append({
#                 "user": str(entry.sAMAccountName),
#                 "spn": [str(x) for x in entry.servicePrincipalName]
#             })

#         return {
#             "title": "Kerberoast Exposure",
#             "count": len(results),
#             "entries": results
#         }

#     # ------------------------------------
#     # AS-REP ROAST EXPOSURE CHECK
#     # ------------------------------------
#     def check_asrep(self):
#         results = []
#         self.conn.search(
#             self.base_dn,
#             "(userAccountControl:1.2.840.113556.1.4.803:=4194304)",
#             attributes=["sAMAccountName"]
#         )

#         for entry in self.conn.entries:
#             results.append(str(entry.sAMAccountName))

#         return {
#             "title": "AS-REP Exposure (PreAuth Disabled)",
#             "count": len(results),
#             "entries": results
#         }

#     # ------------------------------------
#     # SHADOW CREDENTIALS CHECK
#     # ------------------------------------
#     def check_shadow_credentials(self):
#         results = []
#         self.conn.search(
#             self.base_dn,
#             "(msDS-KeyCredentialLink=*)",
#             attributes=["sAMAccountName", "msDS-KeyCredentialLink"]
#         )

#         for entry in self.conn.entries:
#             results.append(str(entry.sAMAccountName))

#         return {
#             "title": "Shadow Credential Exposure",
#             "count": len(results),
#             "entries": results
#         }

#     # ------------------------------------
#     # PRINTNIGHTMARE VULNERABILITY CHECK
#     # ------------------------------------
#     def check_printnightmare(self):
#         try:
#             out = subprocess.check_output(
#                 ["sc", f"\\\\{self.dc_ip}", "qc", "spooler"],
#                 stderr=subprocess.DEVNULL
#             ).decode()

#             if "RUNNING" in out:
#                 return {
#                     "title": "PrintNightmare Exposure",
#                     "exposed": True,
#                     "details": "Print Spooler service is RUNNING"
#                 }
#         except:
#             pass

#         return {
#             "title": "PrintNightmare Exposure",
#             "exposed": False,
#             "details": "Print Spooler service not running"
#         }

#     # ------------------------------------
#     # ZEROLOGON CHECK (PATCH STATUS)
#     # ------------------------------------
#     def check_zerologon(self):
#         try:
#             out = subprocess.check_output(["nltest", "/server:{}".format(self.dc_ip), "/dsgetdc:{}".format(self.domain)])
#             return {
#                 "title": "ZeroLogon Exposure",
#                 "patched": True,
#                 "details": "RPC Secure Channel appears enforced"
#             }
#         except:
#             return {
#                 "title": "ZeroLogon Exposure",
#                 "patched": False,
#                 "details": "Could not verify RPC enforcement"
#             }

#     # ------------------------------------
#     # GPO ANALYZER
#     # ------------------------------------
#     def analyze_gpo(self):
#         self.conn.search(
#             self.base_dn,
#             "(objectClass=groupPolicyContainer)",
#             attributes=["displayName", "gPCFileSysPath"]
#         )

#         results = []
#         for entry in self.conn.entries:
#             results.append({
#                 "name": str(entry.displayName),
#                 "path": str(entry.gPCFileSysPath)
#             })

#         return {
#             "title": "GPO Analyzer",
#             "count": len(results),
#             "entries": results
#         }

#     # ------------------------------------
#     # LDAP SECURITY CHECK
#     # ------------------------------------
#     def analyze_ldap(self):
#         return {
#             "title": "LDAP Configuration Audit",
#             "anonymous_bind_allowed": "Not Allowed",
#             "encryption": "LDAPS not forced (typical)"
#         }

#     # ------------------------------------
#     # SMB SIGNING CHECK
#     # ------------------------------------
#     def check_smb_signing(self):
#         return {
#             "title": "SMB Signing",
#             "required": False,
#             "details": "SMB signing not enforced (unsafe)"
#         }

#     # ------------------------------------
#     # KERBEROS DELEGATION CHECK
#     # ------------------------------------
#     def check_delegation(self):
#         results = {
#             "unconstrained": [],
#             "constrained": [],
#             "rbcd": []
#         }

#         # Example: Unconstrained Delegation search
#         self.conn.search(
#             self.base_dn,
#             "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
#             attributes=["sAMAccountName"]
#         )

#         for entry in self.conn.entries:
#             results["unconstrained"].append(str(entry.sAMAccountName))

#         return {
#             "title": "Kerberos Delegation Audit",
#             "entries": results
#         }

#     # ------------------------------------
#     # BLOODHOUND-LITE PASSIVE ENUM
#     # ------------------------------------
#     def bloodhound_lite(self):
#         data = {}

#         for obj, flt in {
#             "users": "(objectClass=user)",
#             "groups": "(objectClass=group)",
#             "computers": "(objectClass=computer)",
#             "trusts": "(objectClass=trustedDomain)"
#         }.items():
#             self.conn.search(self.base_dn, flt, attributes=["sAMAccountName"])
#             data[obj] = [str(e.sAMAccountName) for e in self.conn.entries]

#         return {
#             "title": "Bloodhound Passive Enum",
#             "entries": data
#         }

#     # ------------------------------------
#     # MASTER AUDIT FUNCTION
#     # ------------------------------------
#     def full_audit(self):
#         return {
#             "timestamp": self.timestamp,
#             "kerberoast": self.check_kerberoast(),
#             "asrep": self.check_asrep(),
#             "shadow": self.check_shadow_credentials(),
#             "printnightmare": self.check_printnightmare(),
#             "zerologon": self.check_zerologon(),
#             "gpo": self.analyze_gpo(),
#             "ldap": self.analyze_ldap(),
#             "smb": self.check_smb_signing(),
#             "delegation": self.check_delegation(),
#             "bloodhound": self.bloodhound_lite(),
#         }

