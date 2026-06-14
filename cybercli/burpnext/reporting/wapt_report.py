"""
BurpNext WAPT Report — Burp Suite Pro Style
COMPLETELY DIFFERENT from VAPT report:
  VAPT: IBM Plex font, #060b14 bg, #00d4ff cyan, top navbar ONLY
  WAPT: JetBrains Mono, #0e0e0e bg, #4fc3f7 blue, topbar + LEFT SIDEBAR
Data injected via base64 (atob) — immune to XSS payload injection
All getElementById calls null-safe — never crashes
"""
import json, os, base64, logging
from datetime import datetime
from pathlib import Path
logger = logging.getLogger("burpnext.report")

CSS = """
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap');
:root{
  --bg:#0e0e0e;--panel:#141414;--panel2:#1a1a1a;--panel3:#202020;
  --bdr:#2a2a2a;--bdr2:#333;
  --txt:#d4d4d4;--txt2:#a0a0a0;--txt3:#6a6a6a;
  --acc:#4fc3f7;--grn:#66bb6a;
  --crit:#ef5350;--high:#ff7043;--med:#ffca28;--low:#42a5f5;--inf:#78909c;
  --font:'Inter',sans-serif;--mono:'JetBrains Mono',monospace;
  --r:4px;--r2:6px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--txt);font-family:var(--font);font-size:13px;line-height:1.5;min-height:100vh}
::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-track{background:#111}
::-webkit-scrollbar-thumb{background:#333;border-radius:3px}

/* TOPBAR */
.topbar{position:fixed;top:0;left:0;right:0;height:42px;background:#111;
  border-bottom:1px solid var(--bdr);z-index:9999;display:flex;align-items:center;
  padding:0 16px;gap:0}
.tb-brand{font-family:var(--mono);font-size:12px;color:var(--acc);letter-spacing:2px;
  text-transform:uppercase;padding:0 16px 0 0;border-right:1px solid var(--bdr);
  margin-right:8px;display:flex;align-items:center;gap:8px}
.tb-dot{width:8px;height:8px;background:var(--crit);border-radius:50%;animation:blink 1.5s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.tb-tabs{display:flex;flex:1;height:100%;overflow-x:auto}
.tb-tab{padding:0 14px;height:100%;display:flex;align-items:center;font-size:11px;
  color:var(--txt3);cursor:pointer;border-right:1px solid var(--bdr);
  transition:all .15s;white-space:nowrap;user-select:none}
.tb-tab:hover{color:var(--txt2);background:#161616}
.tb-tab.active{color:var(--acc);background:#0d1a24;border-bottom:2px solid var(--acc)}
.tb-right{display:flex;align-items:center;gap:8px;flex-shrink:0;margin-left:8px}
.tb-pill{padding:3px 10px;border-radius:2px;font-size:10px;font-family:var(--mono);
  font-weight:700;letter-spacing:1px;text-transform:uppercase}
.tb-btn{padding:5px 12px;background:transparent;border:1px solid var(--bdr2);
  border-radius:var(--r);color:var(--txt2);font-size:11px;cursor:pointer;
  font-family:var(--mono);transition:all .15s}
.tb-btn:hover{border-color:var(--acc);color:var(--acc)}

/* LAYOUT — topbar + LEFT SIDEBAR (completely different from VAPT top-nav-only) */
.layout{display:grid;grid-template-columns:200px 1fr;min-height:100vh;padding-top:42px}
.sidebar{background:#111;border-right:1px solid var(--bdr);position:fixed;
  top:42px;left:0;bottom:0;width:200px;overflow-y:auto}
.sb-sect{padding:6px 0;border-bottom:1px solid var(--bdr)}
.sb-title{padding:8px 14px 4px;font-size:9px;letter-spacing:2px;color:var(--txt3);
  text-transform:uppercase;font-family:var(--mono);font-weight:600}
.sb-item{padding:7px 14px;font-size:12px;color:var(--txt2);cursor:pointer;
  display:flex;align-items:center;gap:8px;border-left:2px solid transparent;transition:all .12s}
.sb-item:hover{color:var(--txt);background:#161616}
.sb-item.active{color:var(--acc);background:#0d1a24;border-left-color:var(--acc)}
.sb-badge{margin-left:auto;padding:1px 6px;border-radius:2px;font-size:9px;
  font-family:var(--mono);font-weight:700}
.sb-stats{padding:10px 14px}
.sb-stat{display:flex;justify-content:space-between;align-items:center;padding:3px 0}
.sb-lbl{font-size:11px;color:var(--txt3)}
.sb-val{font-family:var(--mono);font-size:12px;font-weight:600}

.main{margin-left:200px;padding:20px}
.page{display:none}.page.active{display:block}

/* TARGET BAR */
.tbar{background:var(--panel);border:1px solid var(--bdr);border-radius:var(--r2);
  padding:12px 16px;margin-bottom:14px;display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.turl{font-family:var(--mono);font-size:13px;color:var(--acc);flex:1;min-width:200px}
.meta-row{display:flex;gap:16px;flex-wrap:wrap}
.meta{display:flex;align-items:center;gap:6px;font-size:11px}
.mlbl{color:var(--txt3);font-family:var(--mono)}.mval{color:var(--txt);font-family:var(--mono)}

/* OVERVIEW */
.ov-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px}
.ov-card{background:var(--panel);border:1px solid var(--bdr);border-radius:var(--r2);
  padding:16px;position:relative;overflow:hidden}
.ov-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.c-crit::before{background:var(--crit)}.c-high::before{background:var(--high)}
.c-med::before{background:var(--med)}.c-low::before{background:var(--low)}
.c-acc::before{background:var(--acc)}
.ov-num{font-size:34px;font-weight:700;font-family:var(--mono);line-height:1;margin-bottom:4px}
.ov-lbl{font-size:9px;letter-spacing:1.5px;color:var(--txt3);text-transform:uppercase;font-family:var(--mono)}

/* RISK + OWASP ROW */
.risk-row{display:grid;grid-template-columns:180px 1fr;gap:14px;margin-bottom:14px;align-items:start}
.gauge-box{background:var(--panel);border:1px solid var(--bdr);border-radius:var(--r2);padding:18px;text-align:center}
.gauge-wrap{position:relative;width:140px;height:140px;margin:0 auto 10px}
.gauge-wrap svg{transform:rotate(-90deg)}
.gauge-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.gnum{font-size:32px;font-weight:700;font-family:var(--mono);line-height:1}
.gsub{font-size:9px;color:var(--txt3);letter-spacing:1.5px;text-transform:uppercase;margin-top:2px}
.glbl{font-family:var(--mono);font-size:11px;letter-spacing:2px;font-weight:600;margin-bottom:8px}
.gbr{display:grid;grid-template-columns:1fr 1fr;gap:4px}
.gi{display:flex;align-items:center;gap:5px;font-size:10px;font-family:var(--mono)}
.gd{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.owasp-box{background:var(--panel);border:1px solid var(--bdr);border-radius:var(--r2);padding:14px}
.ow-title{font-size:9px;letter-spacing:2px;color:var(--txt3);text-transform:uppercase;font-family:var(--mono);margin-bottom:10px}
.ow-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:5px}
.ow-cell{padding:8px 6px;border-radius:var(--r);text-align:center;border:1px solid var(--bdr);background:var(--panel2)}
.ow-cell.hit{border-color:rgba(239,83,80,.4);background:rgba(239,83,80,.08)}
.ow-id{font-family:var(--mono);font-size:9px;font-weight:700;margin-bottom:2px}
.ow-count{font-size:16px;font-weight:700;font-family:var(--mono);margin:2px 0}
.ow-name{font-size:8px;color:var(--txt3);line-height:1.3}

/* TECH */
.tech-row{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px}
.tech-chip{padding:4px 10px;border:1px solid var(--bdr2);border-radius:3px;font-size:10px;
  font-family:var(--mono);color:var(--acc);background:rgba(79,195,247,.05)}

/* CHARTS */
.charts-row{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:14px}
.chart-box{background:var(--panel);border:1px solid var(--bdr);border-radius:var(--r2);padding:14px}
.clbl{font-size:9px;letter-spacing:2px;color:var(--txt3);text-transform:uppercase;font-family:var(--mono);margin-bottom:3px}
.csub{font-size:12px;color:var(--txt);margin-bottom:10px;font-weight:500}
.ch{position:relative;height:160px}

/* FINDINGS */
.fbar{display:flex;align-items:center;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.fbtn{padding:5px 12px;border:1px solid var(--bdr);border-radius:var(--r);
  font-size:11px;color:var(--txt2);cursor:pointer;font-family:var(--mono);
  transition:all .15s;background:transparent}
.fbtn:hover{border-color:var(--acc);color:var(--acc)}
.fbtn.active{color:#000!important;font-weight:700}
.fa.active{background:var(--acc);border-color:var(--acc)}
.fCritical.active{background:var(--crit);border-color:var(--crit)}
.fHigh.active{background:var(--high);border-color:var(--high)}
.fMedium.active{background:var(--med);border-color:var(--med)}
.fLow.active{background:var(--low);border-color:var(--low)}
.fcnt{font-size:11px;color:var(--txt3);font-family:var(--mono);margin-left:auto}

.fr{background:var(--panel);border:1px solid var(--bdr);border-radius:var(--r);
  margin-bottom:6px;overflow:hidden;transition:border-color .15s}
.fr:hover{border-color:var(--bdr2)}
.frh{display:grid;grid-template-columns:4px 90px 1fr 80px 80px 36px;
  align-items:center;height:38px;cursor:pointer}
.frbar{height:100%;width:4px}
.frsev{padding:0 10px;height:100%;display:flex;align-items:center;justify-content:center;
  font-size:9px;font-weight:700;letter-spacing:1px;text-transform:uppercase;
  font-family:var(--mono);border-right:1px solid var(--bdr);white-space:nowrap}
.frtitle{padding:0 12px;font-size:12px;font-weight:500;color:var(--txt)}
.frowasp{padding:0 8px;font-family:var(--mono);font-size:10px;color:var(--txt3);
  border-left:1px solid var(--bdr);height:100%;display:flex;align-items:center}
.frcvss{padding:0 8px;font-family:var(--mono);font-size:11px;font-weight:700;
  border-left:1px solid var(--bdr);height:100%;display:flex;align-items:center}
.frtog{padding:0 10px;border-left:1px solid var(--bdr);height:100%;
  display:flex;align-items:center;justify-content:center;color:var(--txt3);font-size:10px}
.frbody{display:none;border-top:1px solid var(--bdr)}
.frbody.open{display:block}
.frtabs{display:flex;border-bottom:1px solid var(--bdr);background:var(--panel2)}
.frtab{padding:8px 14px;font-size:11px;font-family:var(--mono);color:var(--txt3);
  cursor:pointer;border-right:1px solid var(--bdr);transition:all .12s}
.frtab:hover{color:var(--txt2)}
.frtab.active{color:var(--acc);background:var(--panel3)}
.frpane{display:none;padding:14px}.frpane.active{display:block}

.fl{font-size:9px;letter-spacing:2px;color:var(--acc);text-transform:uppercase;font-family:var(--mono);margin-bottom:5px}
.fv{font-size:12px;color:var(--txt);line-height:1.6}
.fg2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:12px}
.fg3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:12px}
.ff{margin-bottom:12px}
.codebox{background:#0a0a0a;border:1px solid #222;border-radius:var(--r);
  padding:10px 13px;font-family:var(--mono);font-size:11px;color:#a8d8ea;
  white-space:pre-wrap;word-break:break-all;margin-top:5px;max-height:180px;overflow-y:auto}
.whybox{background:rgba(239,83,80,.04);border:1px solid rgba(239,83,80,.12);
  border-radius:var(--r);padding:11px 13px;margin-top:5px}
.whybox p{font-size:12px;color:#ffcdd2;line-height:1.7}
.impbox{background:rgba(255,112,67,.04);border:1px solid rgba(255,112,67,.12);
  border-radius:var(--r);padding:11px 13px;margin-top:5px}
.impbox p{font-size:12px;color:#ffe0b2;line-height:1.7}
.fixbox{background:rgba(102,187,106,.04);border:1px solid rgba(102,187,106,.12);
  border-radius:var(--r);padding:11px 13px;margin-top:5px}
.fixbox p{font-size:12px;color:#c8e6c9;line-height:1.7;margin-bottom:8px}
.steps{counter-reset:s;list-style:none}
.steps li{counter-increment:s;padding:5px 0 5px 26px;position:relative;
  font-size:11px;color:#a5d6a7;border-bottom:1px solid rgba(102,187,106,.1)}
.steps li:last-child{border-bottom:none}
.steps li::before{content:counter(s);position:absolute;left:0;top:5px;
  width:17px;height:17px;background:rgba(102,187,106,.15);border:1px solid rgba(102,187,106,.3);
  border-radius:50%;font-size:9px;color:#66bb6a;display:flex;align-items:center;
  justify-content:center;font-family:var(--mono)}
.cvss-bar{height:4px;background:var(--bdr);border-radius:2px;margin-top:6px;overflow:hidden}
.cvss-fill{height:100%;border-radius:2px}
.aibox{background:linear-gradient(135deg,rgba(171,71,188,.08),rgba(79,195,247,.04));
  border:1px solid rgba(171,71,188,.2);border-radius:var(--r);padding:12px 14px;margin-top:8px}
.ailbl{font-size:9px;letter-spacing:1.5px;color:#ce93d8;font-family:var(--mono);text-transform:uppercase;margin-bottom:6px}
.aibox p{font-size:12px;color:#e1bee7;line-height:1.7}
.scbox{background:rgba(255,112,67,.06);border:1px solid rgba(255,112,67,.2);
  border-radius:var(--r);padding:10px 12px;margin-top:8px}
.sclbl{font-size:9px;color:#ff8a65;letter-spacing:1.5px;font-family:var(--mono);text-transform:uppercase;margin-bottom:5px}
.scbox p{font-size:12px;color:#ffccbc;line-height:1.7}

/* ENDPOINTS */
.eptbl{width:100%;border-collapse:collapse}
.eptbl th{padding:9px 12px;background:var(--panel2);color:var(--txt3);font-size:9px;
  letter-spacing:1.5px;text-transform:uppercase;text-align:left;
  border-bottom:1px solid var(--bdr);font-family:var(--mono);font-weight:400;position:sticky;top:0;z-index:1}
.eptbl td{padding:8px 12px;border-bottom:1px solid var(--bdr);font-family:var(--mono);font-size:11px;vertical-align:middle}
.eptbl tr:hover td{background:var(--panel2)}.eptbl tr:last-child td{border-bottom:none}
.mGET{background:rgba(79,195,247,.15);color:#4fc3f7}.mPOST{background:rgba(102,187,106,.15);color:#66bb6a}
.mPUT{background:rgba(255,202,40,.15);color:#ffca28}.mDELETE{background:rgba(239,83,80,.15);color:#ef5350}
.mb{display:inline-block;padding:2px 7px;border-radius:2px;font-size:9px;font-weight:700}
.s2{background:rgba(102,187,106,.12);color:#66bb6a}.s3{background:rgba(255,202,40,.1);color:#ffca28}
.s4{background:rgba(255,112,67,.1);color:#ff7043}.s5{background:rgba(239,83,80,.1);color:#ef5350}
.sbadge{display:inline-block;padding:2px 7px;border-radius:2px;font-size:10px}
.src-spider{background:rgba(79,195,247,.1);color:#4fc3f7;font-size:9px;padding:1px 7px;border-radius:10px;font-family:var(--mono)}
.src-brute{background:rgba(171,71,188,.1);color:#ab47bc;font-size:9px;padding:1px 7px;border-radius:10px;font-family:var(--mono)}
.chip{font-size:10px;padding:1px 6px;border-radius:2px;margin:1px;display:inline-block;
  background:rgba(79,195,247,.08);color:var(--acc)}
.ichip{background:rgba(239,83,80,.08);color:#ef9a9a}

/* HEADERS */
.hdrgrid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
.hcard{background:var(--panel);border:1px solid var(--bdr);border-radius:var(--r2);overflow:hidden}
.htop{display:flex;align-items:center;gap:10px;padding:11px 14px;border-bottom:1px solid var(--bdr)}
.hdot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.hname{font-family:var(--mono);font-size:12px;font-weight:600;color:var(--txt)}
.hstatus{font-size:10px;margin-left:auto;font-family:var(--mono);font-weight:600}
.hbody{padding:11px 14px}
.hslbl{font-size:9px;letter-spacing:1.5px;color:var(--acc);text-transform:uppercase;font-family:var(--mono);margin:7px 0 3px}
.htxt{font-size:11px;color:var(--txt2);line-height:1.6}
.hfix{margin-top:7px;padding:6px 10px;background:#0a1628;border:1px solid rgba(79,195,247,.2);
  border-radius:var(--r);font-family:var(--mono);font-size:10px;color:var(--acc);word-break:break-all}

/* ATTACK CHAIN */
.chain{position:relative;padding-left:28px}
.chain::before{content:'';position:absolute;left:8px;top:0;bottom:0;width:2px;
  background:linear-gradient(180deg,var(--crit),var(--high),var(--med),var(--low))}
.cstep{position:relative;margin-bottom:18px}
.cdot{position:absolute;left:-22px;top:4px;width:12px;height:12px;border-radius:50%;border:2px solid}
.ccard{background:var(--panel);border:1px solid var(--bdr);border-radius:var(--r2);padding:12px 14px}
.cnum{font-size:9px;letter-spacing:1.5px;color:var(--txt3);font-family:var(--mono);margin-bottom:3px;text-transform:uppercase}
.ctitle{font-size:13px;font-weight:600;color:var(--txt);margin-bottom:5px}
.cbody{font-size:12px;color:var(--txt2);line-height:1.6}

/* GRAPH */
.gwrap{background:var(--panel);border:1px solid var(--bdr);border-radius:var(--r2);
  padding:20px;overflow-x:auto;min-height:460px}
#gsvg{width:100%;min-height:440px;font-family:var(--mono)}
.gleg{display:flex;gap:14px;flex-wrap:wrap;padding:10px 14px;
  background:var(--panel2);border:1px solid var(--bdr);border-radius:var(--r);margin-top:10px}
.gli{display:flex;align-items:center;gap:6px;font-size:10px;color:var(--txt3)}
.gld{width:9px;height:9px;border-radius:50%}

/* REMEDIATION */
.remtbl{width:100%;border-collapse:collapse}
.remtbl th{padding:9px 12px;background:var(--panel2);color:var(--txt3);font-size:9px;
  letter-spacing:1.5px;text-transform:uppercase;text-align:left;
  border-bottom:1px solid var(--bdr);font-family:var(--mono);font-weight:400}
.remtbl td{padding:11px 12px;border-bottom:1px solid var(--bdr);font-size:11px;vertical-align:middle}
.remtbl tr:hover td{background:var(--panel2)}.remtbl tr:last-child td{border-bottom:none}
.pbadge{width:24px;height:24px;border-radius:50%;display:inline-flex;align-items:center;
  justify-content:center;font-size:10px;font-weight:700;font-family:var(--mono)}
.sevbadge{padding:2px 8px;border-radius:2px;font-size:9px;font-weight:700;
  letter-spacing:1px;text-transform:uppercase;font-family:var(--mono)}

/* EXECUTIVE */
.exec-hero{background:linear-gradient(135deg,#0a0f1e,#0d1526);border:1px solid var(--bdr);
  border-radius:var(--r2);padding:28px;margin-bottom:14px;position:relative;overflow:hidden}
.exec-hero::after{content:'CONFIDENTIAL';position:absolute;top:14px;right:14px;
  font-size:9px;letter-spacing:3px;color:rgba(239,83,80,.4);font-family:var(--mono);
  border:1px solid rgba(239,83,80,.2);padding:2px 8px;border-radius:2px}
.exec-tgt{font-family:var(--mono);font-size:11px;color:var(--acc);margin-bottom:8px;letter-spacing:1px}
.exec-h{font-size:26px;font-weight:300;color:#fff;line-height:1.2;margin-bottom:6px}
.exec-h strong{color:var(--acc);font-weight:700}
.exec-meta{display:flex;gap:20px;flex-wrap:wrap;margin-top:14px}
.exec-mi .lbl{font-size:9px;letter-spacing:1.5px;color:var(--txt3);text-transform:uppercase;font-family:var(--mono);margin-bottom:2px}
.exec-mi .val{font-size:12px;color:var(--txt);font-family:var(--mono)}
.exec-risk{display:inline-block;padding:5px 16px;border-radius:var(--r);font-family:var(--mono);
  font-size:12px;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-top:12px}
.exec-sect{background:var(--panel);border:1px solid var(--bdr);border-radius:var(--r2);
  padding:18px 22px;margin-bottom:10px}
.exec-sect h3{font-size:9px;letter-spacing:2px;color:var(--acc);text-transform:uppercase;
  font-family:var(--mono);margin-bottom:10px;display:flex;align-items:center;gap:8px}
.exec-sect h3::after{content:'';flex:1;height:1px;background:var(--bdr)}
.exec-sect p{font-size:13px;color:var(--txt2);line-height:1.85}
.exec-sect strong{color:var(--txt)}

/* SECRETS */
.scard{background:rgba(239,83,80,.06);border:1px solid rgba(239,83,80,.2);
  border-radius:var(--r2);padding:12px;margin-bottom:8px}
.stype{font-family:var(--mono);font-size:10px;color:var(--crit);font-weight:700;
  margin-bottom:3px;text-transform:uppercase;letter-spacing:1px}
.sval{font-family:var(--mono);font-size:11px;color:#ffcdd2;word-break:break-all}
.ssrc{font-size:10px;color:var(--txt3);margin-top:5px}
.comcard{background:var(--panel2);border:1px solid var(--bdr);border-radius:var(--r);
  padding:9px 12px;margin-bottom:5px}
.comtext{font-family:var(--mono);font-size:11px;color:#fff9c4}
.empty{text-align:center;padding:40px;color:var(--txt3);font-family:var(--mono);font-size:12px}

@media print{.topbar,.sidebar,.fbar{display:none}.layout{display:block}.main{margin:0;padding:0}.page{display:block!important}}
"""

JS = r"""
var D = {};
var OWASP_NAMES = {
  'A01:2021':'Broken Access Control','A02:2021':'Cryptographic Failures',
  'A03:2021':'Injection','A04:2021':'Insecure Design',
  'A05:2021':'Security Misconfiguration','A06:2021':'Vulnerable Components',
  'A07:2021':'Authentication Failures','A08:2021':'Software Integrity Failures',
  'A09:2021':'Logging Failures','A10:2021':'SSRF'
};
var SV_ORDER = {Critical:0,High:1,Medium:2,Low:3,Informational:4};
var SV_HEX   = {Critical:'#ef5350',High:'#ff7043',Medium:'#ffca28',Low:'#42a5f5',Informational:'#78909c'};
var OW_COL   = {
  'A01:2021':'#ef5350','A02:2021':'#ff7043','A03:2021':'#ff4081','A04:2021':'#ffca28',
  'A05:2021':'#4fc3f7','A06:2021':'#ab47bc','A07:2021':'#ff7043','A08:2021':'#e040fb',
  'A09:2021':'#40c4ff','A10:2021':'#ef5350'
};

function el(id){return document.getElementById(id);}
function setText(id,v){var e=el(id);if(e)e.textContent=String(v||'');}
function setHtml(id,v){var e=el(id);if(e)e.innerHTML=v||'';}
function setStyle(id,p,v){var e=el(id);if(e)e.style[p]=v;}

function esc(s){
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function showPage(id){
  document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active');});
  document.querySelectorAll('.sb-item').forEach(function(s){s.classList.remove('active');});
  document.querySelectorAll('.tb-tab').forEach(function(t){t.classList.remove('active');});
  var pg=el('pg-'+id);if(pg)pg.classList.add('active');
  document.querySelectorAll('[data-pg="'+id+'"]').forEach(function(e){e.classList.add('active');});
}

function countSev(s){return (D.findings||[]).filter(function(f){return f.severity===s;}).length;}
function bycat(){var c={};(D.findings||[]).forEach(function(f){c[f.category]=(c[f.category]||0)+1;});return c;}
function byowasp(){var c={};(D.findings||[]).forEach(function(f){if(f.owasp)c[f.owasp]=(c[f.owasp]||0)+1;});return c;}

function init(){
  var c=countSev('Critical'),h=countSev('High'),m=countSev('Medium'),
      l=countSev('Low'),inf=countSev('Informational'),tot=(D.findings||[]).length;
  var score=Math.min(100,c*25+h*12+m*4+l*1);
  var rlabel=score>=75?'CRITICAL':score>=50?'HIGH':score>=25?'MEDIUM':'LOW';
  var rhex=score>=75?'#ef5350':score>=50?'#ff7043':score>=25?'#ffca28':'#42a5f5';

  setText('sb-total',tot);setText('sb-crit',c);setText('sb-high',h);
  setText('sb-med',m);setText('sb-low',l);
  setText('sb-eps',(D.endpoints||[]).length);
  setText('sb-reqs',D.requests||D.totalRequests||0);
  setText('sb-dur',D.duration||'—');

  var pill=el('tb-pill');
  if(pill){pill.textContent=rlabel;pill.style.background=rhex+'22';
    pill.style.color=rhex;pill.style.border='1px solid '+rhex+'44';}

  setText('ov-total',tot);setText('ov-crit',c);setText('ov-high',h);
  setText('ov-med',m);setText('ov-low',l);
  setText('ov-eps',(D.endpoints||[]).length);
  setText('ov-reqs',D.requests||0);
  setText('ov-js',(D.jsEndpoints||[]).length);

  setText('tb-target',D.target||'—');setText('tb-domain',D.domain||'—');
  var dt=new Date(D.scanDate||D.startTime||Date.now());
  setText('tb-date',dt.toLocaleString('en-GB',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'}));
  setText('tb-dur2',D.duration||'—');setText('tb-reqs2',D.requests||0);
  setText('tb-ai',(D.aiProvider&&D.aiProvider!=='none')?D.aiProvider.toUpperCase():'None');
  setText('tb-swagger',D.swaggerFound?'Found':'Not found');
  setText('tb-graphql',D.graphqlFound?'Found':'Not found');

  var tg=el('tech-grid');
  if(tg){
    var techs=D.technologies||[];
    tg.innerHTML=techs.length?techs.map(function(t){return '<span class="tech-chip">'+esc(t)+'</span>';}).join('')
      :'<span style="color:var(--txt3);font-size:11px;font-family:var(--mono)">None detected</span>';
  }

  animGauge(score,rhex);
  setText('glbl',rlabel+' RISK');setStyle('glbl','color',rhex);
  var bd=el('gbr');
  if(bd){bd.innerHTML=[{l:'Critical',n:c,col:SV_HEX.Critical},{l:'High',n:h,col:SV_HEX.High},
    {l:'Medium',n:m,col:SV_HEX.Medium},{l:'Low/Info',n:l+inf,col:SV_HEX.Low}
  ].map(function(r){return '<div class="gi"><div class="gd" style="background:'+r.col+'"></div>'
    +'<span style="color:#666">'+r.l+': <span style="color:'+r.col+'">'+r.n+'</span></span></div>';}).join('');}

  renderOWASP();renderCharts(c,h,m,l,inf);
  renderFindings();renderEndpoints();renderGraph(D.graph||{});
  renderHeaders();renderRemediation();renderExec(score,rlabel,rhex,c,h,m);
  renderChain();renderSecrets();
  showPage('overview');
}

function animGauge(score,hex){
  var arc=el('garc'),num=el('gnum');if(!arc||!num)return;
  var C=2*Math.PI*60;arc.style.stroke=hex;num.style.color=hex;
  var tgt=C-(score/100)*C,off=C,n=0;
  function step(){off=Math.max(tgt,off-9);n=Math.min(score,n+2);
    arc.style.strokeDashoffset=off;num.textContent=Math.floor(n);
    if(off>tgt||n<score)requestAnimationFrame(step);}step();
}

function renderOWASP(){
  var owasp=byowasp();
  var ALL=['A01:2021','A02:2021','A03:2021','A04:2021','A05:2021',
           'A06:2021','A07:2021','A08:2021','A09:2021','A10:2021'];
  var g=el('ow-grid');if(!g)return;
  g.innerHTML=ALL.map(function(id){
    var count=owasp[id]||0,hit=count>0,col=hit?(OW_COL[id]||'#ef5350'):'#444';
    var name=(OWASP_NAMES[id]||id).split(' ').slice(0,2).join(' ');
    return '<div class="ow-cell'+(hit?' hit':'') +'">'
      +'<div class="ow-id" style="color:'+col+'">'+id+'</div>'
      +'<div class="ow-count" style="color:'+(hit?col:'#333')+'">'+count+'</div>'
      +'<div class="ow-name">'+name+'</div></div>';
  }).join('');
}

function renderCharts(c,h,m,l,inf){
  if(typeof Chart==='undefined')return;
  Chart.defaults.color='#666';Chart.defaults.borderColor='#2a2a2a';
  Chart.defaults.font.family="'JetBrains Mono',monospace";Chart.defaults.font.size=10;
  var COLS=['rgba(239,83,80,.8)','rgba(255,112,67,.8)','rgba(255,202,40,.8)',
            'rgba(66,165,245,.8)','rgba(171,71,188,.8)','rgba(102,187,106,.8)',
            'rgba(38,166,154,.8)','rgba(79,195,247,.8)'];
  var dc=el('ch-donut');
  if(dc)new Chart(dc,{type:'doughnut',data:{labels:['Critical','High','Medium','Low','Info'],
    datasets:[{data:[c,h,m,l,inf],
      backgroundColor:['rgba(239,83,80,.9)','rgba(255,112,67,.9)','rgba(255,202,40,.9)','rgba(66,165,245,.9)','rgba(120,144,156,.7)'],
      borderColor:['#ef5350','#ff7043','#ffca28','#42a5f5','#78909c'],borderWidth:1.5,hoverOffset:5}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'70%',
      plugins:{legend:{position:'bottom',labels:{padding:10,boxWidth:8,font:{size:9}}}}}});
  var cats=bycat(),ce=Object.entries(cats).sort(function(a,b){return b[1]-a[1];}).slice(0,7);
  var cc=el('ch-cats');
  if(cc)new Chart(cc,{type:'bar',data:{labels:ce.map(function(x){return x[0];}),
    datasets:[{label:'Findings',data:ce.map(function(x){return x[1];}),
      backgroundColor:ce.map(function(_,i){return COLS[i%8];}),borderRadius:2}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
      scales:{y:{grid:{color:'#1e1e1e'},ticks:{stepSize:1}},x:{grid:{display:false}}}}});
  var cr={'9-10':0,'7-9':0,'4-7':0,'0-4':0};
  (D.findings||[]).forEach(function(f){var s=f.cvss_score||0;
    if(s>=9)cr['9-10']++;else if(s>=7)cr['7-9']++;else if(s>=4)cr['4-7']++;else cr['0-4']++;});
  var cv=el('ch-cvss');
  if(cv)new Chart(cv,{type:'bar',data:{labels:Object.keys(cr),
    datasets:[{label:'Count',data:Object.values(cr),indexAxis:'y',
      backgroundColor:['rgba(239,83,80,.8)','rgba(255,112,67,.8)','rgba(255,202,40,.8)','rgba(66,165,245,.8)'],
      borderRadius:2}]},
    options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',
      plugins:{legend:{display:false}},scales:{x:{grid:{color:'#1e1e1e'},ticks:{stepSize:1}},y:{grid:{display:false}}}}});
}

var _filter='all';
function filterFindings(f){
  _filter=f;
  document.querySelectorAll('.fbtn').forEach(function(b){b.classList.remove('active');});
  var btn=el('fb-'+f);if(btn)btn.classList.add('active');
  document.querySelectorAll('.fr').forEach(function(row){
    row.style.display=(f==='all'||row.dataset.sev===f)?'':'none';});
  var vis=document.querySelectorAll('.fr:not([style*="none"])').length;
  setText('fcnt',vis+' findings');
}

function renderFindings(){
  var sorted=(D.findings||[]).slice().sort(function(a,b){
    return (SV_ORDER[a.severity]||5)-(SV_ORDER[b.severity]||5);});
  var list=el('findings-list');if(!list)return;
  list.innerHTML=sorted.map(function(f,i){
    var sev=f.severity||'Low',cvss=f.cvss_score||0;
    var ch=SV_HEX[sev]||'#78909c';
    var cc=cvss>=9?'var(--crit)':cvss>=7?'var(--high)':cvss>=4?'var(--med)':'var(--low)';
    var oid=f.owasp||'',ocol=OW_COL[oid]||'#6b7fa3';
    var stepsHtml='';
    if(f.steps&&f.steps.length)stepsHtml='<ol class="steps">'+f.steps.map(function(s){return '<li>'+esc(s)+'</li>';}).join('')+'</ol>';
    var aiHtml='<p style="color:#444;font-family:var(--mono);font-size:11px">No AI validation — add --ai-provider to enable</p>';
    if(f.ai_validated){
      aiHtml='<div class="aibox"><div class="ailbl">'+esc((D.aiProvider||'AI').toUpperCase())+' — '+Math.round((f.ai_confidence||0)*100)+'% confidence</div>'
        +'<p>'+esc(f.ai_analysis||'')+'</p></div>';
      if(f.ai_attack_scenario)aiHtml+='<div class="scbox"><div class="sclbl">Attack Scenario</div><p>'+esc(f.ai_attack_scenario)+'</p></div>';
    }
    var ov='<div class="fg2"><div><div class="fl">Affected URL</div><div class="fv" style="font-family:var(--mono);font-size:11px;word-break:break-all">'+esc(f.url||'')+'</div></div>'
      +'<div><div class="fl">Method / Parameter</div><div class="fv" style="font-family:var(--mono)">'+esc(f.method||'GET')+' · '+esc(f.parameter||'N/A')+'</div></div></div>'
      +'<div class="fg3"><div><div class="fl">Severity</div><div class="fv" style="color:'+ch+';font-size:15px;font-weight:700;font-family:var(--mono)">'+sev+'</div></div>'
      +'<div><div class="fl">CVSS v3.1</div><div class="fv" style="color:'+cc+';font-size:20px;font-weight:700;font-family:var(--mono)">'+(cvss>0?cvss.toFixed(1):'N/A')+'</div>'
      +(cvss>0?'<div class="cvss-bar"><div class="cvss-fill" style="width:'+(cvss*10)+'%;background:'+cc+'"></div></div>':'')+'</div>'
      +'<div><div class="fl">Confidence</div><div class="fv" style="font-family:var(--mono)">'+esc(f.confidence||'Medium')+'</div></div></div>'
      +'<div class="fg2"><div><div class="fl">OWASP 2021</div><div class="fv" style="font-family:var(--mono);color:'+ocol+'">'+esc(oid)+' — '+esc(f.owasp_name||OWASP_NAMES[oid]||'')+'</div></div>'
      +'<div><div class="fl">CWE</div><div class="fv" style="font-family:var(--mono);color:#666">'+esc(f.cwe||'N/A')+'</div></div></div>'
      +'<div class="ff"><div class="fl">Description</div><div class="fv">'+esc(f.description||'')+'</div></div>';
    var ev=(f.why?'<div class="ff"><div class="fl">Why Dangerous?</div><div class="whybox"><p>'+esc(f.why)+'</p></div></div>':'')
      +(f.business_impact?'<div class="ff"><div class="fl">Business Impact</div><div class="impbox"><p>'+esc(f.business_impact)+'</p></div></div>':'')
      +(f.payload?'<div class="ff"><div class="fl">Attack Payload</div><div class="codebox">'+esc(f.payload)+'</div></div>':'')
      +(f.evidence?'<div class="ff"><div class="fl">Evidence / Proof</div><div class="codebox">'+esc(f.evidence)+'</div></div>':'')
      +(f.request_raw?'<div class="ff"><div class="fl">HTTP Request</div><div class="codebox">'+esc(f.request_raw)+'</div></div>':'');
    var fx='<div class="ff"><div class="fl">Remediation</div><div class="fixbox"><p>'+esc(f.remediation||'')+'</p>'+stepsHtml+'</div></div>';
    return '<div class="fr" data-sev="'+sev+'" id="fr'+i+'">'
      +'<div class="frh" onclick="togFR('+i+')">'
      +'<div class="frbar" style="background:'+ch+'"></div>'
      +'<div class="frsev" style="background:'+ch+'22;color:'+ch+'">'+sev+'</div>'
      +'<div class="frtitle">'+esc(f.title||'')+'</div>'
      +'<div class="frowasp">'+esc(oid)+'</div>'
      +'<div class="frcvss" style="color:'+cc+'">'+(cvss>0?cvss.toFixed(1):'—')+'</div>'
      +'<div class="frtog" id="ft'+i+'">&#9660;</div></div>'
      +'<div class="frbody" id="fb'+i+'">'
      +'<div class="frtabs">'
      +'<div class="frtab active" id="frt'+i+'-ov" onclick="showFT('+i+',\'ov\')">Overview</div>'
      +'<div class="frtab" id="frt'+i+'-ev" onclick="showFT('+i+',\'ev\')">Evidence</div>'
      +'<div class="frtab" id="frt'+i+'-fx" onclick="showFT('+i+',\'fx\')">Remediation</div>'
      +'<div class="frtab" id="frt'+i+'-ai" onclick="showFT('+i+',\'ai\')">AI Analysis</div>'
      +'</div>'
      +'<div class="frpane active" id="fp'+i+'-ov">'+ov+'</div>'
      +'<div class="frpane" id="fp'+i+'-ev">'+ev+'</div>'
      +'<div class="frpane" id="fp'+i+'-fx">'+fx+'</div>'
      +'<div class="frpane" id="fp'+i+'-ai">'+aiHtml+'</div>'
      +'</div></div>';
  }).join('');
  setText('fcnt',sorted.length+' findings');
}

function togFR(i){
  var b=el('fb'+i),t=el('ft'+i),row=el('fr'+i);if(!b||!t)return;
  var open=b.classList.contains('open');b.classList.toggle('open',!open);
  if(row)row.style.borderColor=open?'var(--bdr)':'var(--bdr2)';
  t.innerHTML=open?'&#9660;':'&#9650;';
}
function showFT(i,tab){
  ['ov','ev','fx','ai'].forEach(function(t){
    var tc=el('fp'+i+'-'+t),th=el('frt'+i+'-'+t);
    if(tc)tc.classList.toggle('active',t===tab);
    if(th)th.classList.toggle('active',t===tab);
  });
}

function renderEndpoints(){
  var tb=el('ep-tbody');if(!tb)return;
  var eps=(D.endpoints||[]).slice(0,200);
  tb.innerHTML=eps.map(function(ep,i){
    var st=ep.status,sc=st<300?'s2':st<400?'s3':st<500?'s4':'s5';
    var m=(ep.method||'GET'),src=ep.source||'spider';
    var params=(ep.params||[]).map(function(p){return '<span class="chip">'+esc(p)+'</span>';}).join('')||'<span style="color:#333">—</span>';
    var issues=(ep.issues||[]).map(function(iss){return '<span class="chip ichip">'+esc(iss)+'</span>';}).join('')||'—';
    return '<tr><td style="color:#444">'+(i+1)+'</td>'
      +'<td><span class="mb m'+m+'">'+m+'</span></td>'
      +'<td style="color:var(--acc);max-width:280px;word-break:break-all">'+esc(ep.path||'')+'</td>'
      +'<td><span class="sbadge '+sc+'">'+st+'</span></td>'
      +'<td style="color:#555">'+esc((ep.contentType||'—').split(';')[0])+'</td>'
      +'<td>'+params+'</td>'
      +'<td><span class="src-'+(src==='spider'?'spider':'brute')+'">'+esc(src)+'</span></td>'
      +'<td>'+issues+'</td>'
      +'<td style="color:#444">'+(ep.responseTime||'—')+'</td></tr>';
  }).join('');
}

function renderGraph(graph){
  var svg=el('gsvg');if(!svg)return;
  if(!graph||!graph.nodes||!graph.nodes.length){svg.innerHTML='<text x="50" y="50" fill="#333">No graph data</text>';return;}
  var nodes=graph.nodes,edges=graph.edges||[];
  var sx=960/1000,sy=400/500,ox=30,oy=20;
  var h='<defs>'
    +'<marker id="mn" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto"><path d="M0,0L0,6L7,3z" fill="#333"/></marker>'
    +'<marker id="ma" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto"><path d="M0,0L0,6L7,3z" fill="#ef5350"/></marker>'
    +'<marker id="mw" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto"><path d="M0,0L0,6L7,3z" fill="#ff7043"/></marker>'
    +'<filter id="gl"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>'
    +'</defs>';
  var nm={};nodes.forEach(function(n){nm[n.id]=n;});
  edges.forEach(function(e){
    var f=nm[e.from],t=nm[e.to];if(!f||!t)return;
    var x1=f.x*sx+ox,y1=f.y*sy+oy,x2=t.x*sx+ox,y2=t.y*sy+oy,mx=(x1+x2)/2,my=(y1+y2)/2;
    var col=e.type==='attack'?'#ef5350':e.type==='warn'?'#ff7043':'#2a2a2a';
    var dash=e.type==='attack'?' stroke-dasharray="6,3"':'';
    var mk='url(#m'+(e.type==='attack'?'a':e.type==='warn'?'w':'n')+')';
    h+='<line x1="'+x1+'" y1="'+y1+'" x2="'+x2+'" y2="'+y2+'" stroke="'+col+'" stroke-width="'+(e.type==='attack'?2:1.5)+'"'+dash+' marker-end="'+mk+'" opacity=".8"/>';
    if(e.label){var ll=e.label.length;
      h+='<rect x="'+(mx-ll*3.2)+'" y="'+(my-12)+'" width="'+(ll*6.4)+'" height="13" rx="2" fill="rgba(14,14,14,.9)"/>';
      h+='<text x="'+mx+'" y="'+(my-2)+'" text-anchor="middle" fill="'+col+'" font-size="9">'+esc(e.label)+'</text>';}
  });
  var TS={attacker:{fill:'#1a0808',stroke:'#ef5350',sw:2.5,r:32,tc:'#ef5350'},
    entry:{fill:'#081414',stroke:'#26a69a',sw:1.5,r:26,tc:'#26a69a'},
    target:{fill:'#081420',stroke:'#4fc3f7',sw:3,r:36,tc:'#4fc3f7'},
    service:{fill:'#141414',stroke:'#2a2a2a',sw:1.5,r:28,tc:'#555'},
    danger:{fill:'#1a0e00',stroke:'#ff7043',sw:2,r:28,tc:'#ff7043'},
    vuln:{fill:'#1a0505',stroke:'#ef5350',sw:1.5,r:26,tc:'#ef9a9a'}};
  nodes.forEach(function(n){
    var x=n.x*sx+ox,y=n.y*sy+oy,s=TS[n.type]||TS.service;
    var gl=(n.type==='target'||n.type==='attacker')?' filter="url(#gl)"':'';
    var lines=n.label.split('\n');
    if(n.type==='attacker'){
      h+='<polygon points="'+x+','+(y-32)+' '+(x+28)+','+(y+20)+' '+(x-28)+','+(y+20)+'" fill="'+s.fill+'" stroke="'+s.stroke+'" stroke-width="'+s.sw+'"'+gl+'/>';
      h+='<text x="'+x+'" y="'+(y-4)+'" text-anchor="middle" font-size="9" fill="'+s.tc+'" font-weight="700">ATTACKER</text>';
    } else {
      h+='<rect x="'+(x-s.r)+'" y="'+(y-20)+'" width="'+(s.r*2)+'" height="40" rx="5" fill="'+s.fill+'" stroke="'+s.stroke+'" stroke-width="'+s.sw+'"'+gl+'/>';
      lines.forEach(function(ln,idx){h+='<text x="'+x+'" y="'+(y+(idx-(lines.length-1)/2)*14)+'" text-anchor="middle" font-size="'+(n.type==='target'?12:10)+'" fill="'+s.tc+'" font-weight="'+(n.type==='target'?600:400)+'">'+esc(ln)+'</text>';});
      if(n.type==='danger')h+='<text x="'+(x+s.r-9)+'" y="'+(y-10)+'" font-size="11">&#9888;</text>';
      if(n.type==='vuln')h+='<text x="'+(x+s.r-11)+'" y="'+(y-10)+'" font-size="11">&#128308;</text>';
    }
  });
  svg.innerHTML=h;
}

var HDR_META={
  'Strict-Transport-Security':{why:'Without HSTS browsers allow HTTP. MITM attacker captures ALL traffic in plaintext.',fix:'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'},
  'Content-Security-Policy':{why:'No CSP = unrestricted JS. Any XSS runs with full trust.',fix:"Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'"},
  'X-Frame-Options':{why:'Pages embeddable in iframes. Clickjacking attacks possible.',fix:'X-Frame-Options: DENY'},
  'X-Content-Type-Options':{why:'MIME sniffing may execute uploaded files as scripts.',fix:'X-Content-Type-Options: nosniff'},
  'Referrer-Policy':{why:'URL tokens leak via Referer to third-party analytics.',fix:'Referrer-Policy: strict-origin-when-cross-origin'},
  'Permissions-Policy':{why:'XSS/iframes access camera/mic/geolocation without permission.',fix:'Permissions-Policy: geolocation=(), microphone=(), camera=()'},
  'Server':{why:'Version disclosure enables targeted CVE exploitation.',fix:'server_tokens off; / ServerTokens Prod'},
  'X-Powered-By':{why:'Framework version enables targeted CVE attacks.',fix:"app.disable('x-powered-by') / expose_php=Off"},
};
var ALL_HDRS=['Strict-Transport-Security','Content-Security-Policy','X-Frame-Options',
  'X-Content-Type-Options','Referrer-Policy','Permissions-Policy','Server','X-Powered-By'];

function renderHeaders(){
  var g=el('hdr-grid');if(!g)return;
  g.innerHTML=ALL_HDRS.map(function(hdr){
    var finding=(D.findings||[]).find(function(f){return f.parameter===hdr;});
    var meta=HDR_META[hdr]||{why:'Security header.',fix:'Add to server config.'};
    var isMiss=!!finding,col=isMiss?'#ef5350':'#66bb6a';
    var desc=finding?finding.description:hdr+' is correctly configured.';
    return '<div class="hcard">'
      +'<div class="htop"><div class="hdot" style="background:'+col+'"></div>'
      +'<div class="hname">'+esc(hdr)+'</div>'
      +'<div class="hstatus" style="color:'+col+'">'+(isMiss?'&#10007; Missing':'&#10003; Present')+'</div></div>'
      +'<div class="hbody">'
      +'<div class="hslbl">Description</div><div class="htxt">'+esc(desc.substring(0,200))+'</div>'
      +'<div class="hslbl">Why It Matters</div><div class="htxt">'+esc(meta.why)+'</div>'
      +(isMiss?'<div class="hfix">'+esc(meta.fix)+'</div>':'')
      +'</div></div>';
  }).join('');
}

function renderRemediation(){
  var EFFORT={Critical:'24-72 hours',High:'1-2 weeks',Medium:'2-4 weeks',Low:'Next sprint'};
  var OWNER={Critical:'Security Lead + Dev Lead',High:'Backend Dev',Medium:'Dev Team',Low:'Dev / QA'};
  var sorted=(D.findings||[]).filter(function(f){return f.severity!=='Informational';})
    .slice().sort(function(a,b){return (SV_ORDER[a.severity]||5)-(SV_ORDER[b.severity]||5);});
  var tb=el('rem-tbody');if(!tb)return;
  tb.innerHTML=sorted.map(function(f,i){
    var ch=SV_HEX[f.severity]||'#78909c',cvss=f.cvss_score||0,oid=f.owasp||'';
    var first=(f.steps&&f.steps[0])||(f.remediation||'').substring(0,70);
    return '<tr>'
      +'<td><div class="pbadge" style="background:'+ch+'22;color:'+ch+';border:1px solid '+ch+'44">P'+(i+1)+'</div></td>'
      +'<td><span class="sevbadge" style="background:'+ch+'22;color:'+ch+'">'+f.severity+'</span></td>'
      +'<td style="max-width:220px;white-space:normal;font-size:11px">'+esc(f.title||'')+'</td>'
      +'<td style="font-family:var(--mono);font-size:10px;color:#555">'+esc(oid)+'</td>'
      +'<td style="font-family:var(--mono);color:'+ch+';font-weight:600">'+(cvss>0?cvss.toFixed(1):'—')+'</td>'
      +'<td style="color:#555;font-size:11px">'+(EFFORT[f.severity]||'—')+'</td>'
      +'<td style="color:#555;font-size:11px">'+(OWNER[f.severity]||'Dev')+'</td>'
      +'<td style="color:#444;font-size:11px;max-width:200px;white-space:normal">'+esc(first.substring(0,85))+'</td>'
      +'</tr>';
  }).join('');
}

function renderExec(score,rlabel,rhex,c,h,m){
  setText('exec-target',D.target||'—');
  var dt=new Date(D.scanDate||D.startTime||Date.now());
  setText('exec-date',dt.toLocaleDateString('en-GB',{day:'numeric',month:'long',year:'numeric'}));
  setText('exec-dur',D.duration||'—');setText('exec-reqs',D.requests||0);
  var rb=el('exec-risk');
  if(rb){rb.textContent=rlabel+' RISK';rb.style.background=rhex+'22';rb.style.color=rhex;rb.style.border='1px solid '+rhex+'44';}
  var l=countSev('Low')+countSev('Informational');
  var content='';
  if(D.execSummary&&D.execSummary.length>30){
    content='<div class="exec-sect"><h3>AI-Generated Summary</h3><p>'+esc(D.execSummary)+'</p></div>';
  } else {
    var cards=[
      {t:'OVERALL SECURITY POSTURE',p:'Assessment of <strong>'+esc(D.domain||'')+'</strong> identified <strong>'+(D.findings||[]).length+' vulnerabilities</strong> across <strong>'+(D.endpoints||[]).length+' endpoints</strong>. Risk posture: <strong style="color:'+rhex+'">'+rlabel+'</strong> (score: '+score+'/100). '+(D.requests||0)+' HTTP requests in '+esc(D.duration||'—')+'. '+(D.swaggerFound?'Swagger API documentation found. ':'')+((D.technologies||[]).length?'Technologies detected: '+(D.technologies||[]).join(', ')+'.':'')},
      {t:'CRITICAL & HIGH FINDINGS',p:c+' critical and '+h+' high severity vulnerabilities require immediate attention. '+(c>0?'Critical findings represent directly exploitable attack vectors enabling complete compromise without advanced skills.':'')+( h>0?' High severity findings should be remediated within the next sprint.':'')},
      {t:'BUSINESS & REGULATORY IMPACT',p:'Key risks: (1) <strong>Data Privacy (GDPR Art. 83)</strong> — Injection and access control issues could expose customer PII, risking penalties up to €20M or 4% of annual global turnover. (2) <strong>Operational Risk</strong> — '+(m>0?m+' medium-severity misconfigurations expand attack surface.':' ')+' (3) <strong>Reputational</strong> — Client-facing vulnerabilities erode user trust and enable targeted attacks.'},
      {t:'PRIORITIZED ACTION PLAN',p:'<strong style="color:#ef5350">Immediate (24-72h):</strong> Remediate all Critical findings. Rotate potentially exposed credentials. <strong style="color:#ff7043">Week 1:</strong> Deploy missing security headers. Fix cookie flags. Address High severity. <strong style="color:#ffca28">Month 1:</strong> Code review of all database interactions. Rate limiting on auth endpoints. CORS audit.'},
      {t:'POSITIVE OBSERVATIONS',p:'Positive indicators: '+(D.target&&D.target.startsWith('https')?'HTTPS correctly deployed. ':'')+( c===0?'No critical injection vulnerabilities confirmed. ':'')+' Implementing the remediation roadmap will significantly reduce risk posture to Low at next assessment.'},
    ];
    content=cards.map(function(card){return '<div class="exec-sect"><h3>'+card.t+'</h3><p>'+card.p+'</p></div>';}).join('');
  }
  setHtml('exec-content',content);
}

function renderChain(){
  var cont=el('chain-content');if(!cont)return;
  var crits=(D.findings||[]).filter(function(f){return f.severity==='Critical'||f.severity==='High';})
    .sort(function(a,b){return (SV_ORDER[a.severity]||5)-(SV_ORDER[b.severity]||5);}).slice(0,5);
  if(!crits.length){cont.innerHTML='<div class="empty">No critical/high findings to build chain from.</div>';return;}
  var steps=[{title:'Reconnaissance',body:'Attacker discovers target. '+(D.swaggerFound?'Swagger docs found — API mapped instantly. ':'')+((D.jsEndpoints||[]).length?' '+D.jsEndpoints.length+' hidden endpoints extracted from JS. ':'')+((D.technologies||[]).length?'Stack: '+(D.technologies||[]).join(', ')+'.':''),col:'#42a5f5'}]
    .concat(crits.map(function(f){return {title:f.title,body:f.why||f.description||'',col:SV_HEX[f.severity]||'#ef5350'};}))
    .concat([{title:'Impact & Persistence',body:'Attacker achieves objective: data exfiltration, persistent access, or compromise. Establishes foothold for future attacks.',col:'#ef5350'}]);
  cont.innerHTML='<div class="chain">'+steps.map(function(step,i){
    return '<div class="cstep"><div class="cdot" style="background:'+step.col+';border-color:'+step.col+'"></div>'
      +'<div class="ccard"><div class="cnum">Step '+(i+1)+'</div>'
      +'<div class="ctitle">'+esc(step.title)+'</div>'
      +'<div class="cbody">'+esc(step.body)+'</div></div>'
      +(i<steps.length-1?'<div style="text-align:center;font-size:16px;color:var(--crit);margin:4px 0">&#8595;</div>':'')
      +'</div>';}).join('')+'</div>';
}

function renderSecrets(){
  var cont=el('secrets-content');if(!cont)return;
  var secrets=D.secretsFound||[],comments=D.commentsFound||[],emails=D.emailsFound||[];
  var html='';
  if(secrets.length){
    html+='<div class="fl" style="margin-bottom:8px">Hardcoded Secrets in JavaScript</div>';
    html+=secrets.map(function(s){return '<div class="scard"><div class="stype">'+esc(s.type||'Secret')+'</div>'
      +'<div class="sval">'+esc(s.value||'')+'</div><div class="ssrc">Found in: '+esc(s.file||'')+'</div></div>';}).join('');
  }
  if(emails.length){
    html+='<div class="fl" style="margin:14px 0 6px">Email Addresses ('+emails.length+')</div>';
    html+='<div style="display:flex;flex-wrap:wrap;gap:6px">'+emails.map(function(e){return '<span class="chip">'+esc(e)+'</span>';}).join('')+'</div>';
  }
  if(comments.length){
    html+='<div class="fl" style="margin:14px 0 6px">Interesting HTML Comments ('+comments.length+')</div>';
    html+=comments.map(function(c){return '<div class="comcard"><div class="comtext">'+esc(c)+'</div></div>';}).join('');
  }
  if(!html)html='<div class="empty">No sensitive data found in JavaScript or HTML.</div>';
  cont.innerHTML=html;
}

function exportJSON(){
  var blob=new Blob([JSON.stringify(D,null,2)],{type:'application/json'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='wapt_'+D.domain+'_'+Date.now()+'.json';a.click();
}

window.addEventListener('DOMContentLoaded',function(){init();});
"""

def generate_wapt_report(result_dict: dict) -> str:
    data_json = json.dumps(result_dict, ensure_ascii=True, separators=(',',':'))
    data_b64  = base64.b64encode(data_json.encode('utf-8')).decode('ascii')
    domain    = result_dict.get('domain','')

    h  = "<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
    h += "<meta charset='UTF-8'>\n"
    h += "<meta name='viewport' content='width=device-width,initial-scale=1.0'>\n"
    h += f"<title>WAPT Report — {domain}</title>\n"
    h += "<script src='https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js'></script>\n"
    h += "<style>" + CSS + "</style>\n</head>\n<body>\n"

    # Base64 data injection — 100% immune to XSS payload in data
    h += "<script>\n"
    h += "(function(){\n"
    h += "  try{\n"
    h += "    window.D=JSON.parse(atob('" + data_b64 + "'));\n"
    h += "  }catch(e){\n"
    h += "    window.D={findings:[],endpoints:[],technologies:[],stats:{},graph:{nodes:[],edges:[]}};\n"
    h += "    console.error('BurpNext data error',e);\n"
    h += "  }\n"
    h += "})();\n"
    h += "</script>\n"

    # TOPBAR
    TABS = [
        ('overview','Dashboard'),('findings','Findings'),('endpoints','Endpoints'),
        ('graph','Attack Graph'),('headers','Headers'),('chain','Attack Chain'),
        ('secrets','Secrets'),('remediation','Remediation'),('executive','Executive'),
    ]
    h += "<div class='topbar'>\n"
    h += "  <div class='tb-brand'><div class='tb-dot'></div>BURPNEXT</div>\n"
    h += "  <div class='tb-tabs'>\n"
    for pid, plbl in TABS:
        h += f"    <div class='tb-tab' data-pg='{pid}' onclick=\"showPage('{pid}')\">{plbl}</div>\n"
    h += "  </div>\n"
    h += "  <div class='tb-right'>\n"
    h += "    <span id='tb-pill' class='tb-pill'></span>\n"
    h += "    <button class='tb-btn' onclick='window.print()'>PDF</button>\n"
    h += "    <button class='tb-btn' onclick='exportJSON()'>JSON</button>\n"
    h += "  </div>\n</div>\n"

    # LAYOUT
    h += "<div class='layout'>\n"

    # SIDEBAR — LEFT (completely different from VAPT top-nav-only)
    SB_ITEMS = [
        ('overview','⬡','Dashboard',None),
        ('findings','⚠','Findings','sb-total'),
        ('endpoints','↗','Endpoints','sb-eps'),
        ('graph','⊕','Attack Graph',None),
        ('headers','▤','Headers',None),
        ('chain','⚡','Attack Chain',None),
        ('secrets','⚿','Secrets',None),
        ('remediation','✓','Remediation',None),
        ('executive','◈','Executive',None),
    ]
    h += "<div class='sidebar'>\n"
    h += "  <div class='sb-sect'>\n"
    h += "    <div class='sb-title'>Navigation</div>\n"
    for pid, icon, lbl, badge_id in SB_ITEMS:
        badge = f"<span class='sb-badge' id='{badge_id}' style='background:#1a1a1a;color:#ef5350'>0</span>" if badge_id else ""
        h += f"    <div class='sb-item' data-pg='{pid}' onclick=\"showPage('{pid}')\">{icon} {lbl}{badge}</div>\n"
    h += "  </div>\n"
    h += "  <div class='sb-sect'>\n"
    h += "    <div class='sb-title'>Severity</div>\n"
    h += "    <div class='sb-stats'>\n"
    for sid, slbl, scol in [('sb-crit','Critical','#ef5350'),('sb-high','High','#ff7043'),
                              ('sb-med','Medium','#ffca28'),('sb-low','Low','#42a5f5')]:
        h += f"      <div class='sb-stat'><span class='sb-lbl'>{slbl}</span><span class='sb-val' id='{sid}' style='color:{scol}'>0</span></div>\n"
    h += "    </div>\n  </div>\n"
    h += "  <div class='sb-sect'>\n"
    h += "    <div class='sb-title'>Scan Stats</div>\n"
    h += "    <div class='sb-stats'>\n"
    for sid, slbl in [('sb-reqs','Requests'),('sb-dur','Duration')]:
        h += f"      <div class='sb-stat'><span class='sb-lbl'>{slbl}</span><span class='sb-val' id='{sid}' style='color:#666'>—</span></div>\n"
    h += "    </div>\n  </div>\n</div>\n"

    # MAIN
    h += "<div class='main'>\n"

    # PAGE: OVERVIEW
    h += "<div class='page active' id='pg-overview'>\n"
    h += "  <div class='tbar'>\n"
    h += "    <div class='turl' id='tb-target'>—</div>\n"
    h += "    <div class='meta-row'>\n"
    for mid, mlbl in [('tb-domain','Domain'),('tb-date','Date'),('tb-dur2','Duration'),
                       ('tb-reqs2','Requests'),('tb-ai','AI'),('tb-swagger','Swagger'),('tb-graphql','GraphQL')]:
        h += f"      <div class='meta'><span class='mlbl'>{mlbl}:</span><span class='mval' id='{mid}'>—</span></div>\n"
    h += "    </div>\n  </div>\n"
    h += "  <div class='ov-grid'>\n"
    for oid, olbl, ocls, ocol in [
        ('ov-crit','Critical','c-crit','#ef5350'),('ov-high','High','c-high','#ff7043'),
        ('ov-med','Medium','c-med','#ffca28'),('ov-low','Low','c-low','#42a5f5'),
        ('ov-total','Total','c-acc','#4fc3f7'),('ov-eps','Endpoints','c-acc','#4fc3f7'),
        ('ov-reqs','Requests','c-acc','#4fc3f7'),('ov-js','JS Endpoints','c-acc','#ab47bc'),
    ]:
        h += f"    <div class='ov-card {ocls}'><div class='ov-num' id='{oid}' style='color:{ocol}'>0</div><div class='ov-lbl'>{olbl}</div></div>\n"
    h += "  </div>\n"
    h += "  <div class='risk-row'>\n"
    h += "    <div class='gauge-box'>\n"
    h += "      <div class='gauge-wrap'>\n"
    h += "        <svg viewBox='0 0 140 140' width='150' height='150'>\n"
    h += "          <circle cx='70' cy='70' r='60' fill='none' stroke='#1a1a1a' stroke-width='10'/>\n"
    h += "          <circle id='garc' cx='70' cy='70' r='60' fill='none' stroke='#ef5350'\n"
    h += "            stroke-width='10' stroke-dasharray='377' stroke-dashoffset='377' stroke-linecap='round'/>\n"
    h += "        </svg>\n"
    h += "        <div class='gauge-center'><div class='gnum' id='gnum' style='color:#ef5350'>0</div><div class='gsub'>RISK</div></div>\n"
    h += "      </div>\n"
    h += "      <div class='glbl' id='glbl'>—</div>\n"
    h += "      <div class='gbr' id='gbr'></div>\n"
    h += "    </div>\n"
    h += "    <div class='owasp-box'>\n"
    h += "      <div class='ow-title'>OWASP TOP 10 (2021) — COVERAGE MATRIX</div>\n"
    h += "      <div class='ow-grid' id='ow-grid'></div>\n"
    h += "    </div>\n  </div>\n"
    h += "  <div style='margin-bottom:8px;font-size:9px;letter-spacing:2px;color:#444;text-transform:uppercase;font-family:var(--mono)'>Technology Stack</div>\n"
    h += "  <div class='tech-row' id='tech-grid'></div>\n"
    h += "  <div class='charts-row'>\n"
    h += "    <div class='chart-box'><div class='clbl'>Severity Distribution</div><div class='csub'>By risk level</div><div class='ch'><canvas id='ch-donut'></canvas></div></div>\n"
    h += "    <div class='chart-box'><div class='clbl'>Vulnerability Categories</div><div class='csub'>Bug types found</div><div class='ch'><canvas id='ch-cats'></canvas></div></div>\n"
    h += "    <div class='chart-box'><div class='clbl'>CVSS Score Ranges</div><div class='csub'>Distribution</div><div class='ch'><canvas id='ch-cvss'></canvas></div></div>\n"
    h += "  </div>\n</div>\n"

    # PAGE: FINDINGS
    h += "<div class='page' id='pg-findings'>\n"
    h += "  <div class='fbar'>\n"
    for fid, flbl, fstyle in [
        ('a','All',''),
        ('Critical','Critical','color:var(--crit);border-color:rgba(239,83,80,.3)'),
        ('High','High','color:var(--high);border-color:rgba(255,112,67,.3)'),
        ('Medium','Medium','color:var(--med);border-color:rgba(255,202,40,.3)'),
        ('Low','Low','color:var(--low);border-color:rgba(66,165,245,.3)'),
    ]:
        active = " active" if fid == 'a' else ""
        style  = f" style='{fstyle}'" if fstyle else ""
        key    = fid if fid != 'a' else 'all'
        h += f"    <button class='fbtn f{fid}{active}' id='fb-{key}'{style} onclick=\"filterFindings('{key}')\">{flbl}</button>\n"
    h += "    <span class='fcnt' id='fcnt'></span>\n  </div>\n"
    h += "  <div id='findings-list'></div>\n</div>\n"

    # PAGE: ENDPOINTS
    h += "<div class='page' id='pg-endpoints'>\n"
    h += "  <div style='margin-bottom:10px;font-size:11px;color:#555;font-family:var(--mono)'>All discovered endpoints. 403=Blocked but exists. 429=Rate limited but exists. Source: brute=common paths | spider=HTML crawl</div>\n"
    h += "  <div style='overflow-x:auto'><table class='eptbl'>\n"
    h += "    <thead><tr>\n"
    for th in ['#','Method','Path','Status','Content-Type','Parameters','Source','Issues','Time(s)']:
        h += f"      <th>{th}</th>\n"
    h += "    </tr></thead>\n    <tbody id='ep-tbody'></tbody>\n  </table></div>\n</div>\n"

    # PAGE: GRAPH
    h += "<div class='page' id='pg-graph'>\n"
    h += "  <div style='margin-bottom:10px;font-size:11px;color:#555;font-family:var(--mono)'>Attack path flowchart. Red dashed = confirmed attack vector.</div>\n"
    h += "  <div class='gwrap'><svg id='gsvg' viewBox='0 0 1100 460'></svg></div>\n"
    h += "  <div class='gleg'>\n"
    for gcol, glbl in [('#ef5350','Critical Attack'),('#ff7043','High Risk'),('#4fc3f7','Target/Entry'),('#333','Service')]:
        h += f"    <div class='gli'><div class='gld' style='background:{gcol}'></div>{glbl}</div>\n"
    h += "    <div class='gli'><svg width='30' height='12'><line x1='2' y1='6' x2='26' y2='6' stroke='#ef5350' stroke-width='2' stroke-dasharray='5,3'/></svg>Attack Path</div>\n"
    h += "    <div class='gli'><svg width='30' height='12'><line x1='2' y1='6' x2='26' y2='6' stroke='#2a2a2a' stroke-width='1.5'/></svg>Normal Flow</div>\n"
    h += "  </div>\n</div>\n"

    # PAGE: HEADERS
    h += "<div class='page' id='pg-headers'>\n"
    h += "  <div style='margin-bottom:12px;font-size:11px;color:#555;font-family:var(--mono)'>All critical security headers — green=configured, red=missing. Exact fix shown for each.</div>\n"
    h += "  <div class='hdrgrid' id='hdr-grid'></div>\n</div>\n"

    # PAGE: CHAIN
    h += "<div class='page' id='pg-chain'>\n"
    h += "  <div style='margin-bottom:12px;font-size:11px;color:#555;font-family:var(--mono)'>Multi-step attack path showing how vulnerabilities chain for maximum impact.</div>\n"
    h += "  <div id='chain-content'></div>\n</div>\n"

    # PAGE: SECRETS
    h += "<div class='page' id='pg-secrets'>\n"
    h += "  <div style='margin-bottom:12px;font-size:11px;color:#555;font-family:var(--mono)'>Sensitive data discovered — secrets in JS, dev comments, email addresses.</div>\n"
    h += "  <div id='secrets-content'></div>\n</div>\n"

    # PAGE: REMEDIATION
    h += "<div class='page' id='pg-remediation'>\n"
    h += "  <div style='margin-bottom:10px;font-size:11px;color:#555;font-family:var(--mono)'>Priority-ordered fix plan with OWASP mapping, effort estimates, and owner assignments.</div>\n"
    h += "  <div style='overflow-x:auto'><table class='remtbl'>\n"
    h += "    <thead><tr>\n"
    for th in ['P#','Severity','Finding','OWASP','CVSS','Effort','Owner','First Action']:
        h += f"      <th>{th}</th>\n"
    h += "    </tr></thead>\n    <tbody id='rem-tbody'></tbody>\n  </table></div>\n</div>\n"

    # PAGE: EXECUTIVE
    h += "<div class='page' id='pg-executive'>\n"
    h += "  <div class='exec-hero'>\n"
    h += "    <div class='exec-tgt' id='exec-target'>—</div>\n"
    h += "    <div class='exec-h'>Web Application<br><strong>Penetration Testing Report</strong></div>\n"
    h += "    <div class='exec-meta'>\n"
    for eid, elbl in [('exec-date','Assessment Date'),('exec-dur','Duration'),('exec-reqs','Requests')]:
        h += f"      <div class='exec-mi'><div class='lbl'>{elbl}</div><div class='val' id='{eid}'>—</div></div>\n"
    h += "      <div class='exec-mi'><div class='lbl'>Scanner</div><div class='val'>BurpNext v3</div></div>\n"
    h += "      <div class='exec-mi'><div class='lbl'>Classification</div><div class='val' style='color:#ef5350'>CONFIDENTIAL</div></div>\n"
    h += "    </div>\n"
    h += "    <div class='exec-risk' id='exec-risk'>—</div>\n"
    h += "  </div>\n"
    h += "  <div id='exec-content'></div>\n</div>\n"

    h += "</div>\n"  # /main
    h += "</div>\n"  # /layout

    # Single clean JS block
    h += "<script>\n" + JS + "\n</script>\n"
    h += "</body>\n</html>"
    return h


class WAPTReportGenerator:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def generate(self, result, exec_summary: str="", attack_chain: str="") -> str:
        d = result.to_dict()
        d["execSummary"] = exec_summary
        d["attackChain"]  = attack_chain
        html = generate_wapt_report(d)
        domain_safe = result.domain.replace(".","_").replace("/","_")
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"wapt_{domain_safe}_{ts}.html"
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath,"w",encoding="utf-8") as f:
            f.write(html)
        logger.info(f"[REPORT] {filepath}")
        return filepath
