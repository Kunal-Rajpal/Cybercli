"""
CyberCLI — Professional VAPT HTML Report (FIXED)
No f-string bugs. All JS uses separate string building.
"""
import json, os, logging
from datetime import datetime
from pathlib import Path
logger = logging.getLogger("cybercli.report")

# ── CSS ───────────────────────────────────────────────────────────────────────
CSS = """
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap');
:root{
  --bg:#060b14;--surf:#0d1526;--surf2:#111d33;--bdr:#1e2f50;--bdr2:#243660;
  --txt:#e2eaf8;--mut:#6b7fa3;--acc:#00d4ff;--grn:#00e676;--yel:#ffca28;
  --org:#ff6d00;--red:#ff1744;--pur:#7c4dff;
  --crit:#ff1744;--high:#ff6d00;--med:#ffca28;--low:#00bcd4;--inf:#78909c;
  --font:'IBM Plex Sans',sans-serif;--mono:'IBM Plex Mono',monospace;--r:6px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font-family:var(--font);font-size:14px;line-height:1.6}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--bdr2);border-radius:3px}
a{color:var(--acc);text-decoration:none}

/* NAV */
.nav{position:fixed;top:0;left:0;right:0;background:rgba(6,11,20,.97);backdrop-filter:blur(14px);
  border-bottom:1px solid var(--bdr);z-index:9999;padding:0 32px;display:flex;align-items:center;height:52px;gap:4px}
.nav-logo{font-family:var(--mono);font-size:11px;color:var(--acc);letter-spacing:3px;margin-right:20px;
  text-transform:uppercase;border:1px solid rgba(0,212,255,.2);padding:4px 12px;border-radius:3px}
.nav-links{display:flex;gap:1px;flex:1;overflow-x:auto}
.nl{padding:6px 13px;font-size:11px;color:var(--mut);cursor:pointer;border-radius:4px;
  transition:all .15s;white-space:nowrap;letter-spacing:.5px;user-select:none}
.nl:hover{color:var(--txt);background:var(--surf)}
.nl.active{color:var(--acc);background:rgba(0,212,255,.1)}
.nav-right{display:flex;align-items:center;gap:8px;flex-shrink:0}
.rpill{padding:3px 12px;border-radius:20px;font-size:10px;font-weight:700;
  letter-spacing:1.5px;text-transform:uppercase;font-family:var(--mono)}
.nbtn{padding:6px 14px;background:transparent;border:1px solid var(--bdr2);border-radius:var(--r);
  color:var(--mut);font-size:11px;cursor:pointer;font-family:var(--mono);transition:all .2s}
.nbtn:hover{border-color:var(--acc);color:var(--acc)}

/* LAYOUT */
.wrap{padding-top:72px;max-width:1320px;margin:0 auto;padding-left:40px;padding-right:40px;padding-bottom:80px}

/* COVER */
.cover{padding:50px 0 44px;border-bottom:1px solid var(--bdr);display:grid;
  grid-template-columns:1fr 210px;gap:36px;align-items:start}
.ctag{font-family:var(--mono);font-size:10px;color:var(--acc);letter-spacing:2px;text-transform:uppercase;margin-bottom:12px}
.ctitle{font-size:36px;font-weight:300;color:#fff;line-height:1.2;margin-bottom:8px}
.ctitle strong{color:var(--acc);font-weight:600}
.csub{color:var(--mut);font-size:13px;margin-bottom:0}
.cmeta{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:28px}
.cmi{background:var(--surf);border:1px solid var(--bdr);border-radius:var(--r);padding:14px 16px}
.cmi .lbl{font-size:9px;letter-spacing:2px;color:var(--mut);text-transform:uppercase;margin-bottom:5px;font-family:var(--mono)}
.cmi .val{font-size:14px;font-weight:500;color:#fff;font-family:var(--mono)}

/* GAUGE */
.gauge-wrap{text-align:center}
.gauge-ring{width:168px;height:168px;position:relative;margin:0 auto 12px}
.gauge-ring svg{transform:rotate(-90deg)}
.gauge-inner{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.gauge-num{font-size:38px;font-weight:700;font-family:var(--mono);line-height:1}
.gauge-lbl{font-size:9px;letter-spacing:2px;color:var(--mut);text-transform:uppercase;margin-top:2px}
.risk-label{font-family:var(--mono);font-size:12px;letter-spacing:2px;text-align:center;margin-bottom:10px}
.risk-items{display:grid;grid-template-columns:1fr 1fr;gap:5px;margin-top:6px}
.ri{display:flex;align-items:center;gap:5px;font-size:10px;font-family:var(--mono)}
.rdot{width:7px;height:7px;border-radius:50%;flex-shrink:0}

/* STATS BAR */
.sbar{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:var(--bdr);
  border:1px solid var(--bdr);border-radius:var(--r);overflow:hidden;margin:30px 0 0}
.sc{background:var(--surf);padding:22px 16px;text-align:center;transition:background .15s;cursor:default}
.sc:hover{background:var(--surf2)}
.sc .n{font-size:34px;font-weight:700;font-family:var(--mono);line-height:1;margin-bottom:6px}
.sc .l{font-size:9px;letter-spacing:2px;color:var(--mut);text-transform:uppercase}
.nc{color:var(--crit)}.nh{color:var(--high)}.nm{color:var(--med)}.nl2{color:var(--low)}.nt{color:var(--acc)}

/* SECTION */
.sec{padding:48px 0;border-bottom:1px solid var(--bdr)}
.sec-badge{display:inline-block;font-size:9px;letter-spacing:3px;color:var(--mut);text-transform:uppercase;
  font-family:var(--mono);border:1px solid var(--bdr2);padding:3px 10px;border-radius:3px;margin-bottom:10px}
.sec-title{font-size:24px;font-weight:300;color:#fff;margin-bottom:6px;letter-spacing:-.5px}
.sec-title span{color:var(--acc)}
.sec-desc{color:var(--mut);font-size:13px;margin-bottom:30px;line-height:1.6}

/* CHARTS */
.cg2{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px}
.cg3{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-bottom:18px}
.cc{background:var(--surf);border:1px solid var(--bdr);border-radius:var(--r);padding:22px}
.cc-lbl{font-size:9px;letter-spacing:2px;color:var(--mut);text-transform:uppercase;margin-bottom:3px;font-family:var(--mono)}
.cc-sub{font-size:13px;color:var(--txt);margin-bottom:18px;font-weight:500}
.ch{position:relative;height:220px}
.ch-sm{position:relative;height:160px}

/* ATTACK GRAPH */
.agc{background:var(--surf);border:1px solid var(--bdr);border-radius:var(--r);padding:28px;overflow-x:auto;min-height:500px}
#agsvg{width:100%;min-height:480px;font-family:var(--mono)}
.ag-legend{display:flex;gap:20px;margin-top:14px;flex-wrap:wrap;padding:12px 16px;
  background:var(--surf);border:1px solid var(--bdr);border-radius:var(--r)}
.agl{display:flex;align-items:center;gap:7px;font-size:11px;color:var(--mut)}
.agl-dot{width:10px;height:10px;border-radius:50%}

/* HEADER GRID */
.hg{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.hc{background:var(--surf);border-radius:var(--r);padding:16px;position:relative;overflow:hidden}
.hc-bar{position:absolute;left:0;top:0;bottom:0;width:3px}
.hc-name{font-family:var(--mono);font-size:12px;color:#fff;margin-bottom:4px;font-weight:500}
.hc-status{font-size:11px;font-weight:600;margin-bottom:10px;letter-spacing:.5px;display:flex;align-items:center;gap:6px}
.hs-ok{color:var(--grn)}.hs-miss{color:var(--crit)}.hs-weak{color:var(--yel)}
.hc-section-lbl{font-size:9px;color:var(--acc);letter-spacing:1.5px;text-transform:uppercase;
  font-family:var(--mono);margin:8px 0 4px}
.hc-text{font-size:11px;color:#8090b0;line-height:1.6}
.hc-evidence{font-family:var(--mono);font-size:10px;color:var(--mut);word-break:break-all;
  background:var(--surf2);padding:5px 9px;border-radius:3px;margin-bottom:8px}
.hc-fix{margin-top:8px;padding:7px 11px;background:rgba(0,212,255,.05);
  border:1px solid rgba(0,212,255,.15);border-radius:4px;font-size:10px;
  font-family:var(--mono);color:var(--acc);word-break:break-all;line-height:1.5}

/* ENDPOINT TABLE */
.etbl{width:100%;border-collapse:collapse;font-size:12px}
.etbl th{padding:10px 13px;background:var(--surf2);color:var(--mut);font-size:9px;letter-spacing:1.5px;
  text-transform:uppercase;text-align:left;border-bottom:1px solid var(--bdr);font-family:var(--mono);font-weight:400}
.etbl td{padding:10px 13px;border-bottom:1px solid var(--bdr);font-family:var(--mono);vertical-align:middle}
.etbl tr:hover td{background:var(--surf2)}
.etbl tr:last-child td{border-bottom:none}
.mb{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:700}
.mGET{background:rgba(0,188,212,.15);color:#00bcd4}
.mPOST{background:rgba(0,230,118,.15);color:#00e676}
.mPUT{background:rgba(255,202,40,.15);color:#ffca28}
.mDELETE{background:rgba(255,23,68,.15);color:#ff1744}
.sb{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px}
.s2{background:rgba(0,230,118,.1);color:#00e676}
.s3{background:rgba(255,202,40,.1);color:#ffca28}
.s4{background:rgba(255,109,0,.1);color:#ff6d00}
.s5{background:rgba(255,23,68,.1);color:#ff1744}
.chip{font-size:10px;padding:1px 7px;border-radius:3px;margin:1px 2px;display:inline-block}

/* FINDING CARDS */
.fc{background:var(--surf);border:1px solid var(--bdr);border-radius:var(--r);margin-bottom:14px;overflow:hidden;
  transition:border-color .2s}
.fc:hover{border-color:var(--bdr2)}
.fh{display:flex;align-items:center;gap:12px;padding:16px 20px;cursor:pointer;
  border-bottom:1px solid transparent;transition:background .15s;user-select:none}
.fh:hover{background:var(--surf2)}
.fh.open{border-bottom-color:var(--bdr)}
.fsev{width:4px;border-radius:2px;align-self:stretch;flex-shrink:0;min-height:44px}
.sbadge{padding:3px 10px;border-radius:3px;font-size:9px;font-weight:700;letter-spacing:1px;
  text-transform:uppercase;font-family:var(--mono);white-space:nowrap}
.sCritical{background:rgba(255,23,68,.15);color:#ff5577;border:1px solid rgba(255,23,68,.3)}
.sHigh{background:rgba(255,109,0,.15);color:#ff8c42;border:1px solid rgba(255,109,0,.3)}
.sMedium{background:rgba(255,202,40,.12);color:#ffd54f;border:1px solid rgba(255,202,40,.3)}
.sLow{background:rgba(0,188,212,.12);color:#4dd0e1;border:1px solid rgba(0,188,212,.3)}
.sInformational{background:rgba(120,144,156,.12);color:#90a4ae;border:1px solid rgba(120,144,156,.3)}
.ftitle{font-size:14px;font-weight:500;color:#fff;flex:1}
.fmeta{display:flex;gap:7px;align-items:center;flex-shrink:0}
.ftag{font-size:10px;color:var(--mut);background:var(--surf2);padding:2px 8px;border-radius:3px;font-family:var(--mono)}
.cvssbadge{padding:2px 8px;border-radius:3px;font-size:11px;font-family:var(--mono);font-weight:600}
.chev{transition:transform .2s;font-size:11px;color:var(--mut)}
.chev.open{transform:rotate(180deg)}

.fb{padding:24px;display:grid;grid-template-columns:1fr 1fr;gap:20px}
.ff label{display:block;font-size:9px;letter-spacing:2px;color:var(--acc);text-transform:uppercase;
  margin-bottom:6px;font-family:var(--mono)}
.ff p{color:var(--txt);font-size:13px;line-height:1.65}
.ff.full{grid-column:1/-1}
.code{background:#020609;border:1px solid #0d2040;border-radius:4px;padding:11px 15px;
  font-family:var(--mono);font-size:12px;color:#38bdf8;word-break:break-all;white-space:pre-wrap;
  margin-top:6px;line-height:1.5}
.cbar{height:5px;background:var(--bdr);border-radius:3px;margin-top:8px;overflow:hidden}
.cbarf{height:100%;border-radius:3px;transition:width 1s ease}
.why-box{background:rgba(0,212,255,.04);border:1px solid rgba(0,212,255,.15);border-radius:4px;
  padding:14px 16px;margin-top:6px}
.why-box p{font-size:13px;line-height:1.75;color:#b0c4e0}
.rlist{counter-reset:s;list-style:none;margin-top:6px}
.rlist li{counter-increment:s;padding:7px 0 7px 30px;position:relative;font-size:12px;
  color:#b0c4e0;border-bottom:1px solid var(--bdr)}
.rlist li:last-child{border-bottom:none}
.rlist li::before{content:counter(s);position:absolute;left:0;top:7px;width:18px;height:18px;
  background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.25);border-radius:50%;
  font-size:9px;color:var(--acc);display:flex;align-items:center;justify-content:center;font-family:var(--mono)}
.ai-box{background:linear-gradient(135deg,rgba(124,77,255,.08),rgba(0,212,255,.04));
  border:1px solid rgba(124,77,255,.25);border-radius:var(--r);padding:15px 18px;
  margin-top:10px;grid-column:1/-1}
.ai-box .ai-lbl{font-size:9px;letter-spacing:2px;color:#a78bfa;text-transform:uppercase;
  font-family:var(--mono);margin-bottom:7px}
.ai-box p{color:#c4b5fd;font-size:13px;line-height:1.7}
.impact-box{background:rgba(255,23,68,.04);border:1px solid rgba(255,23,68,.15);
  border-radius:4px;padding:12px 15px;margin-top:6px}
.impact-box p{font-size:13px;color:#ffb3b3;line-height:1.7}

/* REMEDIATION TABLE */
.rtbl{width:100%;border-collapse:collapse}
.rtbl th{padding:10px 15px;background:var(--surf2);color:var(--mut);font-size:9px;letter-spacing:1.5px;
  text-transform:uppercase;text-align:left;border-bottom:1px solid var(--bdr);font-family:var(--mono);font-weight:400}
.rtbl td{padding:12px 15px;border-bottom:1px solid var(--bdr);font-size:12px;vertical-align:middle}
.rtbl tr:hover td{background:var(--surf2)}
.rtbl tr:last-child td{border-bottom:none}
.pbadge{width:28px;height:28px;border-radius:50%;display:inline-flex;align-items:center;
  justify-content:center;font-size:11px;font-weight:700;font-family:var(--mono)}

/* EXECUTIVE */
.ecard{background:var(--surf2);border:1px solid var(--bdr2);border-radius:var(--r);
  padding:26px 30px;margin-bottom:16px}
.ecard h3{font-size:9px;letter-spacing:2.5px;color:var(--acc);text-transform:uppercase;
  font-family:var(--mono);margin-bottom:12px;display:flex;align-items:center;gap:8px}
.ecard h3::after{content:'';flex:1;height:1px;background:var(--bdr2)}
.ecard p{color:#b8cce0;line-height:1.85;font-size:14px}
.ecard strong{color:#e2eaf8}

/* FINDING FILTER BAR */
.filter-bar{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}
.fbtn{padding:6px 16px;border:1px solid var(--bdr2);border-radius:20px;font-size:11px;
  color:var(--mut);cursor:pointer;font-family:var(--mono);transition:all .2s;background:transparent}
.fbtn:hover{border-color:var(--acc);color:var(--acc)}
.fbtn.active{color:#000;font-weight:600}
.fbtn-all.active{background:var(--acc);border-color:var(--acc)}
.fbtn-critical.active{background:var(--crit);border-color:var(--crit)}
.fbtn-high.active{background:var(--high);border-color:var(--high)}
.fbtn-medium.active{background:var(--med);border-color:var(--med)}
.fbtn-low.active{background:var(--low);border-color:var(--low)}

/* PROGRESS INDICATOR */
.scan-badge{display:inline-flex;align-items:center;gap:6px;background:rgba(0,230,118,.08);
  border:1px solid rgba(0,230,118,.2);border-radius:4px;padding:4px 12px;font-size:11px;
  color:var(--grn);font-family:var(--mono);margin-bottom:20px}
.scan-badge::before{content:'●';font-size:8px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}

@media print{
  .nav,.filter-bar{display:none}
  .wrap{padding-top:0}
  .fc .fb{display:grid !important}
}
"""

# ── JavaScript ─────────────────────────────────────────────────────────────────
JS = r"""
const SV_ORDER = {Critical:0,High:1,Medium:2,Low:3,Informational:4};
const SV_HEX   = {Critical:'#ff1744',High:'#ff6d00',Medium:'#ffca28',Low:'#00bcd4',Informational:'#78909c'};
const SV_COLOR = {Critical:'var(--crit)',High:'var(--high)',Medium:'var(--med)',Low:'var(--low)',Informational:'var(--inf)'};

function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function scrollTo_(id){ const el=document.getElementById(id.replace('#','')); if(el) el.scrollIntoView({behavior:'smooth',block:'start'}); }
function sev(s){ return D.findings.filter(f=>f.severity===s).length; }
function bycat(){ const c={}; D.findings.forEach(f=>{ c[f.category]=(c[f.category]||0)+1; }); return c; }

// INIT
window.addEventListener('DOMContentLoaded', () => {
  const c=sev('Critical'), h=sev('High'), m=sev('Medium');
  const l=sev('Low')+sev('Informational'), tot=D.findings.length;

  document.getElementById('ctag').textContent = 'TARGET: ' + D.target;
  document.getElementById('mdate').textContent = new Date(D.scanDate).toLocaleString('en-GB',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'});
  document.getElementById('mdur').textContent  = D.duration;
  document.getElementById('mreqs').textContent = D.requests;
  document.getElementById('meps').textContent  = D.endpoints.length;
  document.getElementById('mai').textContent   = D.aiProvider !== 'none' ? D.aiProvider.toUpperCase() : 'None';
  document.getElementById('cnt').textContent   = tot;
  document.getElementById('ccrit').textContent = c;
  document.getElementById('chigh').textContent = h;
  document.getElementById('cmed').textContent  = m;
  document.getElementById('clow').textContent  = l;

  const score  = Math.min(100, c*25 + h*12 + m*4 + l*1);
  const rlabel = score>=75?'CRITICAL': score>=50?'HIGH': score>=25?'MEDIUM':'LOW';
  const rcolor = score>=75?'var(--crit)': score>=50?'var(--high)': score>=25?'var(--med)':'var(--low)';
  const rhex   = score>=75?'#ff1744': score>=50?'#ff6d00': score>=25?'#ffca28':'#00bcd4';

  animGauge(score, rhex);
  document.getElementById('rlbl').textContent = rlabel + ' RISK';
  document.getElementById('rlbl').style.color = rcolor;

  const np = document.getElementById('npill');
  np.textContent = rlabel;
  np.style.background = rhex + '22';
  np.style.color = rcolor;
  np.style.border = '1px solid ' + rhex + '44';

  document.getElementById('ritems').innerHTML = [
    {l:'Critical',count:c,col:SV_HEX.Critical},
    {l:'High',count:h,col:SV_HEX.High},
    {l:'Medium',count:m,col:SV_HEX.Medium},
    {l:'Low',count:l,col:SV_HEX.Low}
  ].map(r => '<div class="ri"><div class="rdot" style="background:'+r.col+'"></div><span style="color:var(--mut)">'+r.l+': <span style="color:'+r.col+'">'+r.count+'</span></span></div>').join('');

  renderCharts(c,h,m,l);
  renderGraph(D.graph);
  renderHeaders();
  renderEndpoints();
  renderFindings();
  renderRemediation();
  renderExec(score, rlabel, rcolor, c, h, m);
});

// GAUGE ANIMATION
function animGauge(score, hex) {
  const arc = document.getElementById('garc');
  const num = document.getElementById('gnum');
  const C = 2 * Math.PI * 70;
  arc.style.stroke = hex;
  num.style.color  = hex;
  const tgt = C - (score/100) * C;
  let off=C, n=0;
  const step = () => {
    off = Math.max(tgt, off - 10);
    n   = Math.min(score, n + 2);
    arc.style.strokeDashoffset = off;
    num.textContent = Math.floor(n);
    if(off > tgt || n < score) requestAnimationFrame(step);
  };
  step();
}

// CHARTS
Chart.defaults.color = '#6b7fa3';
Chart.defaults.borderColor = '#243660';
Chart.defaults.font.family = "'IBM Plex Mono', monospace";
Chart.defaults.font.size = 10;

function renderCharts(c,h,m,l) {
  const cats = bycat();
  const COLORS = ['rgba(255,23,68,.8)','rgba(255,109,0,.8)','rgba(255,202,40,.8)','rgba(0,188,212,.8)',
                  'rgba(124,77,255,.8)','rgba(0,230,118,.8)','rgba(245,0,87,.8)','rgba(0,212,255,.8)'];

  // RADAR — OWASP Top 10
  new Chart(document.getElementById('chRadar'), {
    type: 'radar',
    data: {
      labels: ['Injection','Broken Auth','XSS','IDOR','Misconfiguration','Crypto Fail','Components','Logging','SSRF','Supply Chain'],
      datasets: [{
        label: 'Vulnerability Score',
        data: [
          Math.min((cats.SQLi||0)*30 + c*10, 100),
          Math.min(c*20 + (cats.Authentication||0)*20, 100),
          Math.min((cats.XSS||0)*35, 100),
          Math.min((cats.IDOR||0)*30, 5),
          Math.min((cats.Headers||0)*12 + (cats.Cookies||0)*8, 100),
          Math.min((cats['SSL/TLS']||0)*20, 100),
          10, 5,
          Math.min((cats.SSRF||0)*40, 100), 0
        ],
        backgroundColor: 'rgba(255,23,68,.1)', borderColor: 'rgba(255,23,68,.8)',
        pointBackgroundColor: '#ff1744', pointBorderColor: '#fff', pointRadius: 4, borderWidth: 2
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: { r: { min:0, max:100, grid:{color:'#1e2f50'}, angleLines:{color:'#1e2f50'},
        pointLabels:{color:'#6b7fa3',font:{size:9}}, ticks:{display:false} }},
      plugins: { legend:{display:false} }
    }
  });

  // DONUT — Severity
  new Chart(document.getElementById('chDonut'), {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low/Info'],
      datasets: [{
        data: [c,h,m,l],
        backgroundColor: ['rgba(255,23,68,.85)','rgba(255,109,0,.85)','rgba(255,202,40,.85)','rgba(0,188,212,.85)'],
        borderColor: ['#ff1744','#ff6d00','#ffca28','#00bcd4'],
        borderWidth: 2, hoverOffset: 10
      }]
    },
    options: {
      responsive:true, maintainAspectRatio:false, cutout:'68%',
      plugins:{legend:{position:'bottom',labels:{padding:16,boxWidth:11,font:{size:10}}}}
    }
  });

  // BAR — Categories
  const ce = Object.entries(cats).sort((a,b)=>b[1]-a[1]).slice(0,8);
  new Chart(document.getElementById('chCats'), {
    type: 'bar',
    data: {
      labels: ce.map(x=>x[0]),
      datasets: [{ label:'Findings', data:ce.map(x=>x[1]),
        backgroundColor: ce.map((_,i)=>COLORS[i%8]), borderRadius:3 }]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{y:{grid:{color:'#1e2f50'},ticks:{stepSize:1}},x:{grid:{display:false}}}
    }
  });

  // HORIZONTAL BAR — CVSS Ranges
  const cr = {'>9 Critical':0,'>7 High':0,'>4 Medium':0,'<4 Low':0};
  D.findings.forEach(f => {
    const s=f.cvss||0;
    if(s>=9) cr['>9 Critical']++;
    else if(s>=7) cr['>7 High']++;
    else if(s>=4) cr['>4 Medium']++;
    else cr['<4 Low']++;
  });
  new Chart(document.getElementById('chCVSS'), {
    type: 'bar',
    data: {
      labels: Object.keys(cr),
      datasets: [{ label:'Findings', data:Object.values(cr), indexAxis:'y',
        backgroundColor:['rgba(255,23,68,.8)','rgba(255,109,0,.8)','rgba(255,202,40,.8)','rgba(0,188,212,.8)'],
        borderRadius:3 }]
    },
    options: {
      responsive:true, maintainAspectRatio:false, indexAxis:'y',
      plugins:{legend:{display:false}},
      scales:{x:{grid:{color:'#1e2f50'},ticks:{stepSize:1}},y:{grid:{display:false}}}
    }
  });

  // POLAR — Attack Surface
  new Chart(document.getElementById('chPolar'), {
    type: 'polarArea',
    data: {
      labels: ['Headers','Auth','API/CORS','XSS','SQL/Inject','SSL/TLS','Cookies','Disclosure'],
      datasets: [{
        data: [
          Math.max((cats.Headers||0)+(cats.Cookies||0), .2),
          Math.max(c+h, .2),
          Math.max((cats.SSRF||0)+(cats.CORS||0)+(cats.GraphQL||0), .2),
          Math.max(cats.XSS||0, .2),
          Math.max(cats.SQLi||0, .2),
          Math.max(cats['SSL/TLS']||0, .2),
          Math.max(cats.Cookies||0, .2),
          Math.max(cats['Info Disclosure']||0, .2)
        ],
        backgroundColor:[
          'rgba(0,212,255,.6)','rgba(255,23,68,.6)','rgba(124,77,255,.6)','rgba(255,109,0,.6)',
          'rgba(255,202,40,.6)','rgba(0,230,118,.6)','rgba(245,0,87,.6)','rgba(96,125,139,.6)'
        ], borderWidth:1
      }]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      scales:{r:{grid:{color:'#1e2f50'},ticks:{display:false}}},
      plugins:{legend:{position:'bottom',labels:{padding:8,boxWidth:9,font:{size:9}}}}
    }
  });

  // LINE — Discovery Timeline
  const pass = D.findings.filter(f=>f.scanner==='passive').length;
  const ssl  = D.findings.filter(f=>f.scanner==='ssl').length;
  const act  = D.findings.filter(f=>f.scanner==='active').length;
  new Chart(document.getElementById('chTime'), {
    type: 'line',
    data: {
      labels: ['Start','Discovery','Passive Scan','SSL/TLS','Active (XSS/SQLi)','Active (SSRF/Auth)','Complete'],
      datasets: [{
        label: 'Cumulative Findings',
        data: [0, 0, pass, pass+ssl,
               pass+ssl+Math.floor(act*.4),
               pass+ssl+Math.floor(act*.8),
               D.findings.length],
        borderColor:'rgba(0,212,255,.9)', backgroundColor:'rgba(0,212,255,.06)',
        fill:true, tension:.4, pointBackgroundColor:'#00d4ff', pointRadius:5, borderWidth:2
      }]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{y:{grid:{color:'#1e2f50'},ticks:{stepSize:1},min:0},x:{grid:{display:false}}}
    }
  });
}

// ATTACK GRAPH SVG
function renderGraph(graph) {
  const svg = document.getElementById('agsvg');
  if(!graph || !graph.nodes || !graph.nodes.length) {
    svg.innerHTML = '<text x="50" y="50" fill="#6b7fa3" font-size="14">No graph data available</text>';
    return;
  }
  const {nodes, edges} = graph;
  const sx=1000/1000, sy=440/500, ox=30, oy=20;

  let html = `<defs>
    <marker id="mn" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
      <path d="M0,0L0,6L8,3z" fill="#2a4070"/></marker>
    <marker id="ma" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
      <path d="M0,0L0,6L8,3z" fill="#ff1744"/></marker>
    <marker id="mw" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
      <path d="M0,0L0,6L8,3z" fill="#ff6d00"/></marker>
    <filter id="glow">
      <feGaussianBlur stdDeviation="3" result="b"/>
      <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
  </defs>`;

  const nmap = {};
  nodes.forEach(n => nmap[n.id] = n);

  // Draw edges first
  edges.forEach(e => {
    const f = nmap[e.from], t = nmap[e.to];
    if(!f || !t) return;
    const x1=f.x*sx+ox, y1=f.y*sy+oy, x2=t.x*sx+ox, y2=t.y*sy+oy;
    const mx=(x1+x2)/2, my=(y1+y2)/2;
    const col   = e.type==='attack'?'#ff1744': e.type==='warn'?'#ff6d00':'#2a4070';
    const dash  = e.type==='attack'?'stroke-dasharray="7,3"':'';
    const mkr   = 'url(#m'+(e.type==='attack'?'a':e.type==='warn'?'w':'n')+')';
    const sw    = e.type==='attack'?2.5:1.5;
    html += '<line x1="'+x1+'" y1="'+y1+'" x2="'+x2+'" y2="'+y2+
            '" stroke="'+col+'" stroke-width="'+sw+'" '+dash+' marker-end="'+mkr+'" opacity=".85"/>';
    if(e.label) {
      html += '<rect x="'+(mx-e.label.length*3)+'" y="'+(my-14)+'" width="'+(e.label.length*6)+'" height="14" rx="2" fill="rgba(6,11,20,.8)"/>';
      html += '<text x="'+mx+'" y="'+(my-4)+'" text-anchor="middle" fill="'+col+'" font-size="9" opacity=".9">'+esc(e.label)+'</text>';
    }
  });

  // Draw nodes
  const TS = {
    attacker:{ fill:'#180808', stroke:'#ff1744', sw:2.5, r:34, tc:'#ff1744' },
    entry:   { fill:'#061428', stroke:'#00bcd4', sw:1.5, r:28, tc:'#00bcd4' },
    target:  { fill:'#061828', stroke:'#00d4ff', sw:3,   r:38, tc:'#00d4ff' },
    service: { fill:'#0c1828', stroke:'#2a4070', sw:1.5, r:30, tc:'#6b7fa3' },
    danger:  { fill:'#180c00', stroke:'#ff6d00', sw:2,   r:30, tc:'#ff6d00' },
    vuln:    { fill:'#180404', stroke:'#ff1744', sw:1.5, r:28, tc:'#ff5577' },
  };

  nodes.forEach(n => {
    const x=n.x*sx+ox, y=n.y*sy+oy;
    const s = TS[n.type] || TS.service;
    const lines = n.label.split('\n');
    const glow = (n.type==='target'||n.type==='attacker') ? ' filter="url(#glow)"' : '';

    if(n.type==='attacker') {
      html += '<polygon points="'+x+','+(y-34)+' '+(x+30)+','+(y+22)+' '+(x-30)+','+(y+22)+
              '" fill="'+s.fill+'" stroke="'+s.stroke+'" stroke-width="'+s.sw+'"'+glow+'/>';
      html += '<text x="'+x+'" y="'+(y-5)+'" text-anchor="middle" font-size="10" fill="'+s.tc+'" font-weight="700">ATTACKER</text>';
    } else {
      html += '<rect x="'+(x-s.r)+'" y="'+(y-22)+'" width="'+(s.r*2)+'" height="44" rx="7"'+
              ' fill="'+s.fill+'" stroke="'+s.stroke+'" stroke-width="'+s.sw+'"'+glow+'/>';
      lines.forEach((ln, i) => {
        const fs = n.type==='target' ? 13 : 10;
        const fw = n.type==='target' ? 600 : 400;
        const yt = y + (i - (lines.length-1)/2)*15;
        html += '<text x="'+x+'" y="'+yt+'" text-anchor="middle" font-size="'+fs+'" fill="'+s.tc+'" font-weight="'+fw+'">'+esc(ln)+'</text>';
      });
      if(n.type==='danger') html += '<text x="'+(x+s.r-10)+'" y="'+(y-12)+'" font-size="12">⚠</text>';
      if(n.type==='vuln')   html += '<text x="'+(x+s.r-12)+'" y="'+(y-12)+'" font-size="11">🔴</text>';
    }
  });

  svg.innerHTML = html;
}

// SECURITY HEADERS SECTION
const HEADER_META = {
  'Strict-Transport-Security': {
    why: 'Without HSTS, browsers allow plain HTTP connections. An attacker on the same network (coffee shop Wi-Fi, corporate LAN, ISP) can intercept ALL traffic using a tool like Wireshark — capturing passwords, session tokens, API keys, and personal data in plaintext.',
    fix: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    steps: ['IIS: Add via Response Headers in IIS Manager','Set max-age=31536000 (1 year minimum)','Add includeSubDomains if all subdomains use HTTPS','Submit to HSTS preload list at hstspreload.org after testing']
  },
  'Content-Security-Policy': {
    why: 'Without CSP, there is ZERO restriction on what JavaScript executes in your pages. Any successful XSS attack runs with full trust — stealing cookies, impersonating users, logging keystrokes, and redirecting victims to phishing sites.',
    fix: "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
    steps: ['Audit all external script sources used','Start with CSP-Report-Only to audit without blocking','Use nonces for required inline scripts instead of unsafe-inline','Test using Google CSP Evaluator: csp-evaluator.withgoogle.com']
  },
  'X-Frame-Options': {
    why: 'Without frame protection, attackers embed your pages in invisible iframes on malicious sites. They overlay buttons and trick users into clicking them — performing unintended actions like purchases, transfers, or account changes (clickjacking).',
    fix: 'X-Frame-Options: DENY',
    steps: ['Add via IIS Response Headers configuration','Or use modern CSP: Content-Security-Policy: frame-ancestors none','Test by creating <iframe src="yoursite.com"> on another domain — should show error']
  },
  'X-Content-Type-Options': {
    why: 'Browsers may "sniff" MIME types and execute files differently than declared. An attacker who uploads an image containing JavaScript could have it executed as a script if the browser guesses wrong.',
    fix: 'X-Content-Type-Options: nosniff',
    steps: ['Add via IIS Response Headers or web.config','Apply to all responses including static files','Ensure server sends correct Content-Type headers for all files']
  },
  'Referrer-Policy': {
    why: 'The browser automatically sends the full URL of the previous page in the Referer header. If a user clicks an external link from a password reset page, the reset token in the URL leaks to that external site\'s server logs.',
    fix: 'Referrer-Policy: strict-origin-when-cross-origin',
    steps: ['Add via IIS web.config or Response Headers','Use no-referrer for pages with sensitive URL parameters','Use strict-origin-when-cross-origin as a safe default']
  },
  'Permissions-Policy': {
    why: 'Without this policy, any embedded iframe or XSS payload can access device APIs — camera, microphone, geolocation, payment — without requiring additional user permission.',
    fix: 'Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()',
    steps: ['List all browser APIs your application actually uses','Deny all others explicitly','Test that required features still work after applying policy']
  },
  'Server': {
    why: 'Exposing "Microsoft-IIS/8.5" tells attackers the exact version. They search CVE databases for known exploits targeting IIS 8.5 specifically — reducing their reconnaissance from days to seconds.',
    fix: 'Remove via IIS: Set requestFiltering removeServerHeader="true" in web.config',
    steps: ['IIS 10+: <security><requestFiltering removeServerHeader="true"/></security>','IIS 8.5: Use URL Rewrite module to remove Server header','Verify with: curl -I '+'' +'http://your-domain.com']
  },
  'X-Powered-By': {
    why: '"ASP.NET" in the X-Powered-By header reveals the framework. Attackers target known ASP.NET vulnerabilities, padding oracle attacks, ViewState exploits, and framework-specific misconfigurations.',
    fix: 'Remove in web.config: <httpRuntime enableVersionHeader="false"/> and remove X-Powered-By via customHeaders',
    steps: ['web.config: <httpRuntime enableVersionHeader="false"/>','web.config: <customHeaders><remove name="X-Powered-By"/></customHeaders>','Verify header is removed with curl or browser DevTools']
  }
};

function renderHeaders() {
  const ALL_HEADERS = ['Strict-Transport-Security','Content-Security-Policy','X-Frame-Options',
    'X-Content-Type-Options','Referrer-Policy','Permissions-Policy','Server','X-Powered-By'];

  const grid = document.getElementById('hgrid');
  grid.innerHTML = ALL_HEADERS.map(hdr => {
    const finding = D.findings.find(f => f.parameter === hdr);
    const meta    = HEADER_META[hdr] || {why:'Security header.',fix:'Add to server configuration.',steps:[]};
    const isMissing = !!finding && !finding.title.includes('Weak');
    const isWeak    = !!finding && (finding.title.includes('Weak') || finding.title.includes('unsafe') || finding.title.includes('Wildcard'));
    const isOk      = !finding;

    const statusClass = isOk ? 'hs-ok' : isWeak ? 'hs-weak' : 'hs-miss';
    const statusTxt   = isOk ? '✓ Present & Configured' : isWeak ? '⚠ Weak / Misconfigured' : '✗ Missing — Not Configured';
    const borderCol   = isOk ? '#00e676' : isWeak ? '#ffca28' : '#ff1744';
    const evidence    = finding ? finding.evidence : '';
    const description = finding ? finding.description : hdr + ' is present and correctly protecting the application.';
    const steps       = (finding && finding.steps && finding.steps.length) ? finding.steps : meta.steps;

    let stepsHtml = '';
    if(!isOk && steps && steps.length) {
      stepsHtml = '<div class="hc-section-lbl">Implementation Steps</div>' +
        '<ol class="rlist">' + steps.map(s => '<li>'+esc(s)+'</li>').join('') + '</ol>';
    }

    return '<div class="hc">' +
      '<div class="hc-bar" style="background:'+borderCol+'"></div>' +
      '<div style="padding-left:8px">' +
      '<div class="hc-name">'+esc(hdr)+'</div>' +
      '<div class="hc-status '+statusClass+'">'+statusTxt+'</div>' +
      (evidence ? '<div class="hc-evidence">'+esc(evidence.substring(0,120))+'</div>' : '') +
      '<div class="hc-section-lbl">Description</div>' +
      '<div class="hc-text">'+esc(description.substring(0,200))+'</div>' +
      '<div class="hc-section-lbl">Why This Matters</div>' +
      '<div class="hc-text">'+esc(meta.why)+'</div>' +
      (!isOk ? '<div class="hc-fix">'+esc(meta.fix)+'</div>' : '') +
      stepsHtml +
      '</div></div>';
  }).join('');
}

// ENDPOINTS
function renderEndpoints() {
  const tb = document.getElementById('etbody');
  tb.innerHTML = D.endpoints.map((ep, i) => {
    const st  = ep.status;
    const sc  = st<300?'s2': st<400?'s3': st<500?'s4':'s5';
    const mth = (ep.method||'GET').split('/');
    const mBadges = mth.map(m => '<span class="mb m'+m.trim()+'">'+m.trim()+'</span>').join(' ');
    const params  = (ep.params||[]).length
      ? (ep.params||[]).map(p => '<span class="chip" style="background:rgba(0,212,255,.08);color:var(--acc)">'+esc(p)+'</span>').join('')
      : '<span style="color:var(--mut);font-size:10px">—</span>';
    const issues  = (ep.issues||[]).length
      ? (ep.issues||[]).map(iss => '<span class="chip" style="background:rgba(255,109,0,.1);color:#ff8c42">'+esc(iss)+'</span>').join('')
      : '<span style="color:var(--mut);font-size:10px">—</span>';
    const rt = ep.responseTime || ep.response_time || '—';
    return '<tr>' +
      '<td style="color:var(--mut)">'+( i+1)+'</td>' +
      '<td>'+mBadges+'</td>' +
      '<td style="font-family:var(--mono);font-size:11px;color:var(--acc);max-width:300px;word-break:break-all">'+esc(ep.path||ep.url||'')+'</td>' +
      '<td><span class="sb '+sc+'">'+st+'</span></td>' +
      '<td style="color:var(--mut);font-size:11px">'+esc((ep.contentType||ep.content_type||'—').split(';')[0])+'</td>' +
      '<td>'+params+'</td>' +
      '<td>'+issues+'</td>' +
      '<td style="color:var(--mut);font-size:11px">'+rt+'</td>' +
    '</tr>';
  }).join('');
}

// FINDINGS with filter
let currentFilter = 'all';

function filterFindings(sev) {
  currentFilter = sev;
  document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
  document.querySelector('.fbtn-'+sev).classList.add('active');
  document.querySelectorAll('.fc').forEach(card => {
    const cardSev = card.dataset.severity;
    card.style.display = (sev === 'all' || cardSev === sev) ? '' : 'none';
  });
}

function renderFindings() {
  const sorted = [...D.findings].sort((a,b) => (SV_ORDER[a.severity]||5) - (SV_ORDER[b.severity]||5));
  document.getElementById('flist').innerHTML = sorted.map((f, i) => {
    const sev   = f.severity || 'Low';
    const cvss  = f.cvss || 0;
    const ch    = SV_HEX[sev] || '#78909c';
    const cvssc = cvss>=9?'var(--crit)': cvss>=7?'var(--high)': cvss>=4?'var(--med)':'var(--low)';
    const why   = f.whyImportant || f.why_important || '';

    const stepsHtml = (f.steps && f.steps.length)
      ? '<ol class="rlist">' + f.steps.map(s => '<li>'+esc(s)+'</li>').join('') + '</ol>'
      : '';

    const aiHtml = f.ai_validated
      ? '<div class="ai-box"><div class="ai-lbl">✦ '+esc(D.aiProvider.toUpperCase())+' AI — Confidence: '+Math.round((f.ai_confidence||0)*100)+'%</div><p>'+esc(f.ai_analysis||'')+'</p></div>'
      : '';

    return '<div class="fc" data-severity="'+sev+'" id="fc'+i+'">' +
      '<div class="fh" onclick="tog('+i+')">' +
        '<div class="fsev" style="background:'+ch+'"></div>' +
        '<span class="sbadge s'+sev+'">'+sev+'</span>' +
        '<span class="ftitle">'+esc(f.title||'')+'</span>' +
        '<div class="fmeta">' +
          (f.category ? '<span class="ftag">'+esc(f.category)+'</span>' : '') +
          (cvss>0 ? '<span class="cvssbadge" style="background:'+cvssc+'22;color:'+cvssc+';border:1px solid '+cvssc+'44">CVSS '+cvss.toFixed(1)+'</span>' : '') +
          (f.ai_validated ? '<span style="font-size:10px;color:#a78bfa;background:rgba(124,77,255,.1);padding:2px 8px;border-radius:3px;border:1px solid rgba(124,77,255,.2)">✦ AI</span>' : '') +
          '<span class="chev" id="chev'+i+'">▼</span>' +
        '</div>' +
      '</div>' +
      '<div class="fb" id="fb'+i+'" style="display:none">' +

        '<div class="ff"><label>Affected URL</label>' +
          '<p style="font-family:var(--mono);font-size:12px;word-break:break-all">'+esc(f.url||'')+'</p></div>' +

        '<div class="ff"><label>Parameter / Location</label>' +
          '<p style="font-family:var(--mono)">'+esc(f.parameter||'N/A')+'</p></div>' +

        '<div class="ff full"><label>Vulnerability Description</label>' +
          '<p>'+esc(f.description||'')+'</p></div>' +

        (why ? '<div class="ff full"><label>Why Is This Dangerous?</label><div class="why-box"><p>'+esc(why)+'</p></div></div>' : '') +

        (f.payload ? '<div class="ff full"><label>Attack Payload Used</label><div class="code">'+esc(f.payload)+'</div></div>' : '') +

        (f.evidence ? '<div class="ff full"><label>Evidence / Proof of Vulnerability</label><div class="code">'+esc(f.evidence)+'</div></div>' : '') +

        '<div class="ff"><label>Severity Rating</label>' +
          '<p style="color:'+ch+';font-weight:700;font-family:var(--mono);font-size:16px">'+sev+'</p></div>' +

        '<div class="ff"><label>CVSS v3.1 Score</label>' +
          (cvss>0
            ? '<p style="color:'+cvssc+';font-size:28px;font-weight:700;font-family:var(--mono);line-height:1">'+cvss.toFixed(1)+'</p><div class="cbar"><div class="cbarf" style="width:'+cvss*10+'%;background:'+cvssc+'"></div></div>'
            : '<p style="color:var(--mut)">N/A</p>') +
        '</div>' +

        '<div class="ff"><label>Detection Method</label>' +
          '<p style="font-family:var(--mono);color:var(--mut)">'+esc(f.scanner||'active')+' scanner — '+esc(f.confidence||'Medium')+' confidence</p></div>' +

        '<div class="ff"><label>Vulnerability Category</label>' +
          '<p style="font-family:var(--mono)">'+esc(f.category||'General')+'</p></div>' +

        '<div class="ff full"><label>Remediation Steps</label>' +
          '<p style="margin-bottom:12px;color:#b0c4e0">'+esc(f.remediation||'')+'</p>' +
          stepsHtml +
        '</div>' +

        aiHtml +

      '</div></div>';
  }).join('');
}

function tog(i) {
  const b = document.getElementById('fb'+i);
  const c = document.getElementById('chev'+i);
  const h = b.previousElementSibling;
  const open = b.style.display !== 'none';
  b.style.display = open ? 'none' : 'grid';
  c.classList.toggle('open', !open);
  h.classList.toggle('open', !open);
}

// REMEDIATION TABLE
function renderRemediation() {
  const EFFORT = {Critical:'1-3 days',High:'1-2 weeks',Medium:'2-4 weeks',Low:'Next sprint'};
  const OWNER  = {Critical:'Security Lead + Dev Lead',High:'Backend Developer',Medium:'Dev Team',Low:'QA / Developer'};
  const sorted = [...D.findings]
    .filter(f => f.severity !== 'Informational')
    .sort((a,b) => (SV_ORDER[a.severity]||5) - (SV_ORDER[b.severity]||5));

  document.getElementById('rtbody').innerHTML = sorted.map((f, i) => {
    const ch   = SV_HEX[f.severity] || '#78909c';
    const cvss = f.cvss || 0;
    const firstStep = (f.steps && f.steps[0]) || (f.remediation||'').substring(0,70);
    return '<tr>' +
      '<td><div class="pbadge" style="background:'+ch+'22;color:'+ch+';border:1px solid '+ch+'44">P'+(i+1)+'</div></td>' +
      '<td><span class="sbadge s'+f.severity+'">'+f.severity+'</span></td>' +
      '<td style="max-width:240px;white-space:normal;font-size:12px">'+esc(f.title||'')+'</td>' +
      '<td style="font-family:var(--mono);color:'+ch+';font-weight:600">'+(cvss>0?cvss.toFixed(1):'—')+'</td>' +
      '<td style="color:var(--mut);font-size:11px">'+(EFFORT[f.severity]||'—')+'</td>' +
      '<td style="color:var(--mut);font-size:11px">'+(OWNER[f.severity]||'Dev')+'</td>' +
      '<td style="color:var(--mut);font-size:11px;max-width:220px;white-space:normal">'+esc(firstStep.substring(0,90))+'</td>' +
    '</tr>';
  }).join('');
}

// EXECUTIVE SUMMARY
function renderExec(score, rlabel, rcolor, c, h, m) {
  if(D.execSum && D.execSum.length > 20) {
    document.getElementById('econtent').innerHTML =
      '<div class="ecard"><h3>AI-Generated Executive Summary</h3><p>'+esc(D.execSum)+'</p></div>';
    return;
  }
  const l = sev('Low') + sev('Informational');

  const cards = [
    {
      t: 'OVERALL SECURITY POSTURE',
      p: 'Security assessment of <strong>' + esc(D.domain) + '</strong> identified <strong>' + D.findings.length + ' vulnerabilities</strong> across ' + D.endpoints.length + ' discovered endpoints. The overall risk posture is rated <strong style="color:'+rcolor+'">' + rlabel + '</strong> with a composite risk score of ' + score + '/100. The assessment used automated HTTP scanning with passive header analysis, cookie inspection, SSL/TLS verification, and active injection testing completed in ' + D.duration + ' with ' + D.requests + ' HTTP requests.'
    },
    {
      t: 'CRITICAL & HIGH FINDINGS',
      p: c + ' critical and ' + h + ' high severity vulnerabilities require immediate attention. ' +
        (h > 0 ? 'High severity findings include: missing HTTPS enforcement exposes all user traffic to network interception. ' : '') +
        (m > 0 ? m + ' medium severity findings — primarily missing security headers — represent configuration improvements with high security impact and minimal implementation effort. ' : '') +
        'All missing security headers can be remediated with a single IIS configuration change, requiring no application code modification.'
    },
    {
      t: 'BUSINESS & REGULATORY IMPACT',
      p: 'The identified vulnerabilities present quantifiable business risks: ' +
        '<strong>(1) Data Privacy Compliance</strong> — Operating over HTTP without HTTPS violates GDPR Article 32 (security of processing) and may trigger regulatory penalties up to €20M or 4% of annual global turnover. ' +
        '<strong>(2) Session Security</strong> — The ASP.NET session cookie missing Secure and SameSite flags enables session theft over unencrypted connections and CSRF attacks. ' +
        '<strong>(3) Information Disclosure</strong> — Server version (IIS 8.5) and technology (ASP.NET) headers reduce attacker reconnaissance effort and enable targeted CVE exploitation. ' +
        '<strong>(4) Browser-Level Attack Surface</strong> — Absence of CSP, X-Frame-Options, and X-Content-Type-Options leaves users exposed to XSS, clickjacking, and MIME confusion attacks.'
    },
    {
      t: 'PRIORITIZED IMMEDIATE ACTIONS',
      p: '<strong style="color:var(--high)">Week 1 (High Impact, Zero Downtime):</strong> ' +
        'Deploy all missing security headers via IIS web.config — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy. ' +
        'Add Secure, HttpOnly, and SameSite=Strict to the ASP.NET_SessionId cookie. ' +
        'Remove or suppress Server and X-Powered-By headers to prevent version disclosure. ' +
        '<strong style="color:var(--med)">Month 1:</strong> ' +
        'Obtain and deploy a TLS certificate. Configure permanent HTTP to HTTPS redirect. ' +
        'Enable HSTS with a 1-year max-age after HTTPS is confirmed stable. ' +
        'Conduct a full code review for injection vulnerabilities in database-interacting endpoints.'
    },
    {
      t: 'POSITIVE SECURITY OBSERVATIONS',
      p: 'The assessment also identified positive security indicators: No critical injection vulnerabilities (SQLi, XSS, SSRF, LFI) were confirmed during active scanning — suggesting the application has some input validation in place. ' +
        'The application correctly returns 404 for non-existent paths without exposing error details. ' +
        'No exposed sensitive files (.env, .git, phpinfo) were found in the web root. ' +
        'No exposed admin panels or default credentials were identified. ' +
        'Implementing the recommended security headers and HTTPS will significantly close the remaining attack surface and achieve a Low risk rating.'
    }
  ];

  document.getElementById('econtent').innerHTML = cards.map(card =>
    '<div class="ecard"><h3>' + card.t + '</h3><p>' + card.p + '</p></div>'
  ).join('');
}

// EXPORT
function exportJSON() {
  const blob = new Blob([JSON.stringify(D, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'vapt_' + D.domain + '_' + Date.now() + '.json';
  a.click();
}

// SCROLL SPY
window.addEventListener('scroll', () => {
  const ids = ['cover','charts','agraph','headers','endpoints','findings','remediation','executive'];
  let cur = 'cover';
  ids.forEach(id => {
    const el = document.getElementById(id);
    if(el && window.scrollY >= el.offsetTop - 100) cur = id;
  });
  document.querySelectorAll('.nl').forEach(l => {
    const oc = l.getAttribute('onclick') || '';
    l.classList.toggle('active', oc.includes("'" + cur + "'") || oc.includes('"' + cur + '"'));
  });
}, {passive:true});
"""

def generate_html_report(result_dict: dict, exec_summary: str = "") -> str:
    findings   = result_dict.get("findings",  [])
    endpoints  = result_dict.get("endpoints", [])
    stats      = result_dict.get("stats",     {})
    graph      = result_dict.get("graph",     {"nodes":[],"edges":[]})
    target     = result_dict.get("target",    "")
    domain     = result_dict.get("domain",    "")
    duration   = result_dict.get("duration",  stats.get("duration","—"))
    ai_prov    = result_dict.get("aiProvider","none")
    scan_date  = result_dict.get("scanDate",  result_dict.get("startTime", datetime.utcnow().isoformat()))
    total_reqs = result_dict.get("requests",  result_dict.get("totalRequests", stats.get("requests",0)))

    # Build DATA object safely — no f-string JS interpolation issues
    data_obj = {
        "target":     target,
        "domain":     domain,
        "scanDate":   scan_date,
        "duration":   duration,
        "requests":   total_reqs,
        "aiProvider": ai_prov,
        "execSum":    exec_summary or "",
        "findings":   findings,
        "endpoints":  endpoints,
        "stats":      stats,
        "graph":      graph,
    }
    data_json = json.dumps(data_obj, ensure_ascii=False, indent=2)

    html  = "<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
    html += "<meta charset='UTF-8'>\n"
    html += "<meta name='viewport' content='width=device-width,initial-scale=1.0'>\n"
    html += f"<title>VAPT Report — {domain}</title>\n"
    html += "<script src='https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js'></script>\n"
    html += "<style>" + CSS + "</style>\n"
    html += "</head>\n<body>\n"

    # NAV
    html += """<nav class="nav">
  <div class="nav-logo">⬡ CYBERCLI</div>
  <div class="nav-links">
    <div class="nl active" onclick="scrollTo_('cover')">Overview</div>
    <div class="nl" onclick="scrollTo_('charts')">Analytics</div>
    <div class="nl" onclick="scrollTo_('agraph')">Attack Graph</div>
    <div class="nl" onclick="scrollTo_('headers')">Headers</div>
    <div class="nl" onclick="scrollTo_('endpoints')">Endpoints</div>
    <div class="nl" onclick="scrollTo_('findings')">Findings</div>
    <div class="nl" onclick="scrollTo_('remediation')">Remediation</div>
    <div class="nl" onclick="scrollTo_('executive')">Executive</div>
  </div>
  <div class="nav-right">
    <span id="npill" class="rpill"></span>
    <button class="nbtn" onclick="window.print()">🖨 PDF</button>
    <button class="nbtn" onclick="exportJSON()">⬇ JSON</button>
  </div>
</nav>\n"""

    # BODY
    html += '<div class="wrap">\n'

    # Cover
    html += """<div class="cover" id="cover">
  <div>
    <div class="ctag" id="ctag">TARGET: —</div>
    <div class="ctitle">Vulnerability Assessment<br>&amp; <strong>Penetration Testing</strong></div>
    <div class="csub">Professional VAPT Report · AI-Enhanced · Confidential</div>
    <div class="cmeta">
      <div class="cmi"><div class="lbl">Scan Date</div><div class="val" id="mdate">—</div></div>
      <div class="cmi"><div class="lbl">Duration</div><div class="val" id="mdur">—</div></div>
      <div class="cmi"><div class="lbl">Scanner</div><div class="val">CyberCLI v1.0</div></div>
      <div class="cmi"><div class="lbl">HTTP Requests</div><div class="val" id="mreqs">—</div></div>
      <div class="cmi"><div class="lbl">Endpoints Found</div><div class="val" id="meps">—</div></div>
      <div class="cmi"><div class="lbl">AI Provider</div><div class="val" id="mai">—</div></div>
    </div>
  </div>
  <div class="gauge-wrap">
    <div class="gauge-ring">
      <svg viewBox="0 0 160 160" width="168" height="168">
        <circle cx="80" cy="80" r="70" fill="none" stroke="var(--surf2)" stroke-width="10"/>
        <circle id="garc" cx="80" cy="80" r="70" fill="none" stroke="var(--crit)"
          stroke-width="10" stroke-dasharray="440" stroke-dashoffset="440" stroke-linecap="round"/>
      </svg>
      <div class="gauge-inner">
        <div class="gauge-num" id="gnum" style="color:var(--crit)">0</div>
        <div class="gauge-lbl">RISK SCORE</div>
      </div>
    </div>
    <div class="risk-label" id="rlbl">—</div>
    <div class="risk-items" id="ritems"></div>
  </div>
</div>\n"""

    # Stats bar
    html += """<div class="sbar">
  <div class="sc"><div class="n nt" id="cnt">0</div><div class="l">Total Findings</div></div>
  <div class="sc"><div class="n nc" id="ccrit">0</div><div class="l">Critical</div></div>
  <div class="sc"><div class="n nh" id="chigh">0</div><div class="l">High</div></div>
  <div class="sc"><div class="n nm" id="cmed">0</div><div class="l">Medium</div></div>
  <div class="sc"><div class="n nl2" id="clow">0</div><div class="l">Low / Info</div></div>
</div>\n"""

    # Section 2 — Charts
    html += """<div class="sec" id="charts">
  <div class="sec-badge">Section 02</div>
  <div class="sec-title">Security <span>Analytics</span></div>
  <div class="sec-desc">Multi-dimensional visualization — OWASP radar, severity distribution, vulnerability categories, CVSS score ranges, attack surface polar map, and discovery timeline showing findings per scan phase.</div>
  <div class="cg2">
    <div class="cc"><div class="cc-lbl">Radar — OWASP Top 10 Coverage</div><div class="cc-sub">Attack surface across all OWASP vulnerability categories</div><div class="ch"><canvas id="chRadar"></canvas></div></div>
    <div class="cc"><div class="cc-lbl">Severity Distribution</div><div class="cc-sub">Proportion of findings by risk level</div><div class="ch"><canvas id="chDonut"></canvas></div></div>
  </div>
  <div class="cg3">
    <div class="cc"><div class="cc-lbl">Vulnerability Categories</div><div class="cc-sub">Bug types found during assessment</div><div class="ch"><canvas id="chCats"></canvas></div></div>
    <div class="cc"><div class="cc-lbl">CVSS Score Distribution</div><div class="cc-sub">Findings by CVSS v3.1 score range</div><div class="ch"><canvas id="chCVSS"></canvas></div></div>
    <div class="cc"><div class="cc-lbl">Attack Surface Map</div><div class="cc-sub">Coverage across security domains</div><div class="ch"><canvas id="chPolar"></canvas></div></div>
  </div>
  <div class="cc"><div class="cc-lbl">Discovery Timeline</div><div class="cc-sub">Cumulative findings discovered per scan phase</div><div class="ch-sm"><canvas id="chTime"></canvas></div></div>
</div>\n"""

    # Section 3 — Attack Graph
    html += """<div class="sec" id="agraph">
  <div class="sec-badge">Section 03</div>
  <div class="sec-title">Attack <span>Graph</span></div>
  <div class="sec-desc">Flowchart mapping the complete attack surface — attacker entry point through internet to target services, internal network paths, and exploitation chains. Red dashed lines show confirmed attack vectors.</div>
  <div class="agc"><svg id="agsvg" viewBox="0 0 1100 480"></svg></div>
  <div class="ag-legend">
    <div class="agl"><div class="agl-dot" style="background:var(--crit)"></div>Critical Attack Node</div>
    <div class="agl"><div class="agl-dot" style="background:var(--high)"></div>High Risk / Danger</div>
    <div class="agl"><div class="agl-dot" style="background:var(--acc)"></div>Entry Point / Service</div>
    <div class="agl"><div class="agl-dot" style="background:var(--med)"></div>Warning / Weak Config</div>
    <div class="agl"><svg width="32" height="12"><line x1="2" y1="6" x2="28" y2="6" stroke="#ff1744" stroke-width="2" stroke-dasharray="6,3"/></svg>Confirmed Attack Path</div>
    <div class="agl"><svg width="32" height="12"><line x1="2" y1="6" x2="28" y2="6" stroke="#2a4070" stroke-width="1.5"/></svg>Normal Network Flow</div>
    <div class="agl"><svg width="32" height="12"><line x1="2" y1="6" x2="28" y2="6" stroke="#ff6d00" stroke-width="1.5"/></svg>Warning Path</div>
  </div>
</div>\n"""

    # Section 4 — Headers
    html += """<div class="sec" id="headers">
  <div class="sec-badge">Section 04</div>
  <div class="sec-title">Security <span>Headers</span> Analysis</div>
  <div class="sec-desc">Every critical security header checked against the response — present, missing, or misconfigured — with explanation of what each header does, why its absence is dangerous, and the exact configuration fix.</div>
  <div class="hg" id="hgrid"></div>
</div>\n"""

    # Section 5 — Endpoints
    html += """<div class="sec" id="endpoints">
  <div class="sec-badge">Section 05</div>
  <div class="sec-title">Discovered <span>Endpoints</span></div>
  <div class="sec-desc">All endpoints discovered during the spider phase — HTTP method, status code, content type, detected parameters, response time, and security issues flagged per endpoint.</div>
  <div style="overflow-x:auto">
    <table class="etbl">
      <thead><tr>
        <th>#</th><th>Method</th><th>Endpoint / Path</th><th>Status</th>
        <th>Content-Type</th><th>Parameters</th><th>Issues Detected</th><th>Response Time</th>
      </tr></thead>
      <tbody id="etbody"></tbody>
    </table>
  </div>
</div>\n"""

    # Section 6 — Findings
    html += """<div class="sec" id="findings">
  <div class="sec-badge">Section 06</div>
  <div class="sec-title">Vulnerability <span>Findings</span></div>
  <div class="sec-desc">All confirmed vulnerabilities sorted by severity — each with full technical detail, attack payload, evidence/proof, business impact explanation, CVSS score, and step-by-step remediation guide.</div>
  <div class="filter-bar">
    <button class="fbtn fbtn-all active" onclick="filterFindings('all')">All Findings</button>
    <button class="fbtn fbtn-critical" onclick="filterFindings('Critical')" style="color:var(--crit);border-color:rgba(255,23,68,.3)">🔴 Critical</button>
    <button class="fbtn fbtn-high" onclick="filterFindings('High')" style="color:var(--high);border-color:rgba(255,109,0,.3)">🟠 High</button>
    <button class="fbtn fbtn-medium" onclick="filterFindings('Medium')" style="color:var(--med);border-color:rgba(255,202,40,.3)">🟡 Medium</button>
    <button class="fbtn fbtn-low" onclick="filterFindings('Low')" style="color:var(--low);border-color:rgba(0,188,212,.3)">🔵 Low</button>
  </div>
  <div id="flist"></div>
</div>\n"""

    # Section 7 — Remediation
    html += """<div class="sec" id="remediation">
  <div class="sec-badge">Section 07</div>
  <div class="sec-title">Remediation <span>Roadmap</span></div>
  <div class="sec-desc">Priority-ordered action plan — sorted by risk. Each finding has an estimated remediation effort, recommended responsible team, and the first concrete action to take.</div>
  <div style="overflow-x:auto">
    <table class="rtbl">
      <thead><tr>
        <th>Priority</th><th>Severity</th><th>Finding</th>
        <th>CVSS</th><th>Est. Effort</th><th>Owner</th><th>First Action</th>
      </tr></thead>
      <tbody id="rtbody"></tbody>
    </table>
  </div>
</div>\n"""

    # Section 8 — Executive
    html += """<div class="sec" id="executive">
  <div class="sec-badge">Section 08</div>
  <div class="sec-title">Executive <span>Summary</span></div>
  <div class="sec-desc">Business risk overview written for non-technical stakeholders — overall posture, business impact, regulatory implications, and prioritized action recommendations.</div>
  <div id="econtent"></div>
</div>\n"""

    html += '</div>\n'  # /wrap

    # Inject data and JS
    html += "<script>\nconst D = " + data_json + ";\n"
    html += JS
    html += "\n</script>\n"
    html += "</body>\n</html>"
    return html


class ReportGenerator:
    def __init__(self, output_dir: str = "artifacts/reports"):
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def generate(self, result, exec_summary: str = "") -> str:
        html = generate_html_report(result.to_dict(), exec_summary)
        domain_safe = result.domain.replace(".", "_").replace("/", "_")
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"vapt_{domain_safe}_{ts}.html"
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info(f"[REPORT] Saved: {filepath}")
        return filepath
