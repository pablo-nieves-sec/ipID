"""
report.py — export a single self-contained HTML report from the history DB.

Produces one .html file with all data baked in as JSON. No server, no Python,
no internet needed to open it: double-click and it renders the inventory,
category breakdown, Qualys/Defender coverage, and per-asset detail with history.
It's READ-ONLY (no scanning, no editing) — a shareable snapshot for a teammate,
a ticket, or an audit trail.

    python report.py                       # reads ipid.db -> ipID_report.html
    python report.py --db ipid.db -o out.html
    # or from the scanner:
    python ipident.py targets.xlsx --db ipid.db --report report.html
"""

import argparse
import datetime
import json
import os

from store import Store


def build_report(db_path="ipid.db", out_path="ipID_report.html"):
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"database not found: {db_path}")
    st = Store(db_path)
    summary = st.summary()
    assets = [st.asset_detail(a["asset_key"]) for a in st.inventory()]
    cov = st.coverage()
    st.close()

    has_known = cov["summary"]["has_qualys"] or cov["summary"]["has_defender"]
    payload = {
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "summary": summary,
        "assets": assets,
        "coverage": cov if has_known else None,
    }
    blob = json.dumps(payload).replace("</", "<\\/")  # keep it inside <script>
    out = TEMPLATE.replace("/*__DATA__*/", blob)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(out)
    return out_path


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ipID report</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#161616;--bg2:#0a0a0a;--panel:#1c1c1c;--panel2:#242424;--line:#353535;--line2:#474747;
--text:#f4f4f4;--muted:#a0a0a0;--muted2:#6a6a6a;--scan:#2ee6d6;--scan-soft:rgba(46,230,214,.16);
--blue:#3b82f6;--purple:#a855f7;--amber:#f59e0b;--green:#22c55e;--red:#ef4444;--cyan:#38bdf8;--pink:#ec4899;--teal:#14b8a6;--gray:#64748b;
--mono:'JetBrains Mono',ui-monospace,monospace;--display:'Space Grotesk',system-ui,sans-serif;--body:'Inter',system-ui,sans-serif;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:var(--body);-webkit-font-smoothing:antialiased;padding:22px}
.wrap{max-width:1200px;margin:0 auto}
.top{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.logo{font-family:var(--display);font-weight:700;font-size:25px}.logo b{color:var(--scan)}
.fp{width:22px;height:22px;color:var(--scan);filter:drop-shadow(0 0 6px rgba(46,230,214,.5))}
.tag{font-family:var(--mono);font-size:11px;color:var(--muted2);letter-spacing:1px;text-transform:uppercase}
.ro{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--muted2)}
.sub{font-family:var(--mono);font-size:12px;color:var(--muted);margin-bottom:18px}
.sec{font-family:var(--display);font-weight:600;font-size:15px;margin:24px 2px 12px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:11px;margin-bottom:8px}
.scard{position:relative;background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:12px;padding:13px 14px;cursor:pointer;overflow:hidden;transition:.15s}
.scard::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--cc)}
.scard:hover{border-color:var(--cc);transform:translateY(-2px)}.scard.sel{border-color:var(--cc);box-shadow:0 0 0 1px var(--cc) inset}
.scard .cn{font-size:12px;color:var(--muted);margin-bottom:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.scard .cc{font-family:var(--mono);font-weight:700;font-size:26px}
.filters{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0 12px;align-items:center}
.search{flex:1;min-width:220px;display:flex;align-items:center;gap:9px;background:var(--panel);border:1px solid var(--line2);border-radius:9px;padding:9px 12px}
.search input{background:transparent;border:none;outline:none;color:var(--text);font-family:var(--body);font-size:13px;width:100%}
.filters select{background:var(--panel);border:1px solid var(--line2);color:var(--text);border-radius:9px;padding:9px 11px;font-family:var(--mono);font-size:12px;cursor:pointer}
.twrap{background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden}
table{width:100%;border-collapse:collapse}
thead th{text-align:left;font-family:var(--mono);font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--muted2);padding:12px 16px;border-bottom:1px solid var(--line);font-weight:500;background:var(--bg2)}
tbody td{padding:11px 16px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:middle}
tbody tr{cursor:pointer}tbody tr:last-child td{border-bottom:none}tbody tr:hover{background:rgba(46,230,214,.04)}
.td-ip{font-family:var(--mono);color:var(--scan);white-space:nowrap}.td-name{font-weight:500}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:500;padding:3px 10px;border-radius:20px;white-space:nowrap;background:color-mix(in srgb,var(--cc) 14%,transparent);color:var(--cc);border:1px solid color-mix(in srgb,var(--cc) 32%,transparent)}
.pill::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--cc)}
.ovr{font-family:var(--mono);font-size:9px;color:var(--amber);border:1px solid rgba(245,158,11,.4);border-radius:4px;padding:1px 4px;margin-left:6px}
.conf{font-family:var(--mono);font-size:10px;text-transform:uppercase;padding:3px 9px;border-radius:20px}
.conf.high{background:rgba(34,197,94,.12);color:#4ade80}.conf.medium{background:rgba(245,158,11,.12);color:#fbbf24}.conf.low{background:rgba(100,116,139,.14);color:#94a3b8}.conf.none{background:rgba(100,116,139,.1);color:var(--muted2)}
.st-missing{color:var(--red);font-family:var(--mono);font-size:11px}.st-present{color:var(--muted2);font-family:var(--mono);font-size:11px}
.covbadge{display:inline-flex;align-items:center;gap:5px;font-family:var(--mono);font-size:10px;padding:3px 8px;border-radius:20px}
.covbadge.yes{background:rgba(34,197,94,.12);color:#4ade80}.covbadge.warn{background:rgba(239,68,68,.14);color:#f87171}.covbadge.na{background:rgba(100,116,139,.08);color:var(--muted2)}
.empty{padding:40px;text-align:center;color:var(--muted2);font-family:var(--mono);font-size:12px}
.scrim{position:fixed;inset:0;background:rgba(3,6,10,.6);opacity:0;pointer-events:none;transition:.2s;z-index:40}
.scrim.open{opacity:1;pointer-events:auto}
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(520px,92vw);background:var(--bg2);border-left:1px solid var(--line2);transform:translateX(100%);transition:.25s;z-index:50;overflow-y:auto;padding:22px}
.drawer.open{transform:none}
.dh{display:flex;align-items:flex-start;gap:12px}.dh .dip{font-family:var(--mono);font-size:13px;color:var(--scan)}
.dh .dname{font-family:var(--display);font-weight:700;font-size:21px}.dh .x{margin-left:auto;background:var(--panel);border:1px solid var(--line2);color:var(--muted);border-radius:8px;width:32px;height:32px;cursor:pointer;font-size:16px}
.dsub{font-family:var(--mono);font-size:11px;color:var(--muted2);margin:6px 0 16px}
.sec-t{font-family:var(--mono);font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--muted2);margin:18px 0 9px}
.kv{display:grid;grid-template-columns:120px 1fr;gap:6px 12px;font-size:12.5px}.kv .k{color:var(--muted2);font-family:var(--mono);font-size:11px}.kv .v{word-break:break-word}.kv .v.mono{font-family:var(--mono);font-size:11px;color:var(--muted)}
.ev{display:flex;gap:10px;font-family:var(--mono);font-size:11px;align-items:baseline;margin-bottom:7px}
.ev .ety{padding:1px 7px;border-radius:5px;font-size:9px;text-transform:uppercase;flex:none;background:rgba(100,116,139,.16);color:var(--muted)}
.ev .ed{color:var(--muted)}.ev .et{color:var(--muted2);margin-left:auto}
.foot{margin-top:26px;font-family:var(--mono);font-size:11px;color:var(--muted2);text-align:center}
</style></head><body><div class="wrap">
<div class="top"><span class="logo">ip<b>ID</b></span>
<svg class="fp" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12C2 6.5 6.5 2 12 2a10 10 0 0 1 8 4"/><path d="M5 19.5C5.5 18 6 15 6 12c0-.7.12-1.37.34-2"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .13-5.35 0-6"/><path d="M9 6.8a6 6 0 0 1 9 5.2c0 .47 0 1.17-.02 2"/></svg>
<span class="tag">asset report</span><span class="ro" id="ro">read-only snapshot</span></div>
<div class="sub" id="sub"></div>

<div class="sec">Discovered assets</div>
<div class="cards" id="cards"></div>
<div class="filters">
  <div class="search"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--muted2)" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg><input id="q" placeholder="Search name, IP, ports, evidence, SNMP…" oninput="render()"></div>
  <select id="fCat" onchange="render()"><option value="">All categories</option></select>
  <select id="fConf" onchange="render()"><option value="">Any confidence</option><option>high</option><option>medium</option><option>low</option></select>
  <select id="fStat" onchange="render()"><option value="">Present + missing</option><option value="present">Present</option><option value="missing">Missing</option></select>
  <select id="fSort" onchange="render()"><option value="name">Sort: name</option><option value="ip">Sort: IP</option><option value="category">Sort: category</option><option value="confidence">Sort: confidence</option></select>
</div>
<div class="twrap"><table><thead><tr><th>IP</th><th>Name</th><th>Category</th><th>Confidence</th><th>Ports</th><th>Status</th></tr></thead><tbody id="body"></tbody></table><div class="empty" id="empty" style="display:none">No assets.</div></div>

<div id="covSec" style="display:none">
  <div class="sec">Coverage — Qualys / Defender</div>
  <div class="cards" id="covCards"></div>
  <div class="twrap" style="margin-top:8px"><table><thead><tr><th>IP</th><th>Name</th><th>Category</th><th>Qualys</th><th>Defender</th><th>Gap</th></tr></thead><tbody id="covBody"></tbody></table></div>
</div>

<div class="foot" id="foot"></div>
</div>
<div class="scrim" id="scrim" onclick="closeD()"></div>
<div class="drawer" id="drawer"></div>
<script>
const DATA = /*__DATA__*/;
const CC={"Windows Endpoints":"var(--blue)","Mac Endpoints":"var(--cyan)","Endpoint/Server (Linux)":"var(--teal)","Servers / Hypervisors":"var(--purple)","Server":"var(--purple)","Server/Mgmt (BMC)":"var(--purple)","Printers / MFPs":"var(--amber)","Switches / Routers":"var(--green)","Firewalls":"var(--red)","Wireless AP":"var(--green)","Cameras / IoT":"var(--pink)","VoIP Devices":"var(--teal)","UPS / Power":"var(--amber)","Miscellaneous":"var(--gray)","Unknown":"var(--gray)","No response":"var(--gray)"};
const color=c=>CC[c]||"var(--gray)";
const byKey={}; DATA.assets.forEach(a=>byKey[a.asset_key]=a);
let curCat="";

const ls=DATA.summary.last_scan;
document.getElementById('sub').textContent=`Generated ${DATA.generated} · ${DATA.summary.total} assets present · ${DATA.summary.missing} missing · ${DATA.summary.review} in review`+(ls?` · latest scan #${ls.id}`:'');
document.getElementById('foot').textContent=`ipID report · ${DATA.generated} · read-only snapshot (no live scanning)`;

// summary cards
(function(){const s=DATA.summary.counts;const cats=Object.keys(s);
 document.getElementById('fCat').innerHTML='<option value="">All categories</option>'+cats.map(c=>`<option>${c}</option>`).join('');
 document.getElementById('cards').innerHTML=Object.entries(s).sort((a,b)=>b[1]-a[1]).map(([c,n])=>
  `<div class="scard" style="--cc:${color(c)}" data-cat="${c}" onclick="pickCat('${c.replace(/'/g,'')}')"><div class="cn">${c}</div><div class="cc">${n}</div></div>`).join('')||'<div class="empty" style="grid-column:1/-1">No assets.</div>';
})();
function pickCat(c){curCat=(curCat===c)?"":c;document.getElementById('fCat').value=curCat;render();}

function render(){
  const q=document.getElementById('q').value.toLowerCase();
  const fc=document.getElementById('fCat').value, ff=document.getElementById('fConf').value, fs=document.getElementById('fStat').value, so=document.getElementById('fSort').value;
  curCat=fc;
  document.querySelectorAll('.scard').forEach(el=>el.classList.toggle('sel',el.dataset.cat===fc));
  let rows=DATA.assets.filter(a=>{
    const cat=a.effective_category||a.category;
    if(fc&&cat!==fc)return false;
    if(ff&&a.confidence!==ff)return false;
    if(fs&&a.status!==fs)return false;
    if(q){const h=[a.name,a.current_ip,a.ports,a.evidence,a.snmp_descr,a.http_title].join(' ').toLowerCase();if(!h.includes(q))return false;}
    return true;
  });
  const key={name:'name',ip:'current_ip',category:'category',confidence:'confidence'}[so]||'name';
  rows.sort((a,b)=>String(a[key]||'').localeCompare(String(b[key]||'')));
  document.getElementById('empty').style.display=rows.length?'none':'block';
  document.getElementById('body').innerHTML=rows.map(a=>{
    const cat=a.effective_category||a.category, ov=a.overridden?'<span class="ovr">manual</span>':'';
    const st=a.status==='missing'?'<span class="st-missing">● missing</span>':'<span class="st-present">present</span>';
    return `<tr onclick="openD('${encodeURIComponent(a.asset_key)}')"><td class="td-ip">${a.current_ip||'—'}</td>
      <td class="td-name">${a.name||'<span style=color:var(--muted2)>unnamed</span>'}</td>
      <td><span class="pill" style="--cc:${color(cat)}">${cat}</span>${ov}</td>
      <td><span class="conf ${a.confidence}">${a.confidence}</span></td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--muted)">${a.ports||'—'}</td><td>${st}</td></tr>`;
  }).join('');
}

// coverage
(function(){const c=DATA.coverage;if(!c)return;const s=c.summary;
  document.getElementById('covSec').style.display='block';
  const card=(l,v,cc)=>`<div class="scard" style="--cc:${cc}"><div class="cn">${l}</div><div class="cc">${v}</div></div>`;
  document.getElementById('covCards').innerHTML=card('On network',s.present,'var(--scan)')+
    (s.has_qualys?card('Not in Qualys',s.not_qualys,'var(--amber)'):'')+
    (s.has_defender?card('Missing Defender agent',s.missing_edr,'var(--red)'):'')+
    card('Known but not seen',s.known_not_seen,'var(--gray)');
  document.getElementById('covBody').innerHTML=c.rows.map(r=>{
    const q=!s.has_qualys?'<span class="covbadge na">n/a</span>':r.in_qualys?'<span class="covbadge yes">✓ tracked</span>':'<span class="covbadge warn">✕ absent</span>';
    let d=!s.has_defender?'<span class="covbadge na">n/a</span>':r.in_defender?'<span class="covbadge yes">✓ onboarded</span>':(r.agent_capable?'<span class="covbadge warn">✕ no agent</span>':'<span class="covbadge na">n/a</span>');
    const g=[];if(s.has_qualys&&!r.in_qualys)g.push('<span class="covbadge warn">unmanaged</span>');if(r.missing_edr)g.push('<span class="covbadge warn">EDR gap</span>');
    return `<tr onclick="openD('${encodeURIComponent(r.asset_key)}')"><td class="td-ip">${r.ip}</td><td class="td-name">${r.name||'—'}</td>
      <td><span class="pill" style="--cc:${color(r.category)}">${r.category}</span></td><td>${q}</td><td>${d}</td><td>${g.join(' ')||'—'}</td></tr>`;
  }).join('');
})();

function openD(ek){const a=byKey[decodeURIComponent(ek)];if(!a)return;
  const cat=a.effective_category||a.category;
  const evs=(a.events||[]).map(e=>`<div class="ev"><span class="ety">${(e.type||'').replace('_',' ')}</span><span class="ed">${e.detail||''}</span><span class="et">${(e.ts||'').slice(5,16).replace('T',' ')}</span></div>`).join('')||'<div style="color:var(--muted2);font-family:var(--mono);font-size:11px">no history</div>';
  const kq=a.known&&a.known.qualys, kd=a.known&&a.known.defender;
  let kqm={},kdm={};try{kqm=kq&&kq.meta?JSON.parse(kq.meta):{}}catch(e){}try{kdm=kd&&kd.meta?JSON.parse(kd.meta):{}}catch(e){}
  const ips=[...new Set((a.observations||[]).map(o=>o.ip))].join(', ');
  document.getElementById('drawer').innerHTML=`
    <div class="dh"><div><div class="dip">${a.current_ip||'—'}</div><div class="dname">${a.name||'Unidentified host'}</div></div><button class="x" onclick="closeD()">✕</button></div>
    <div class="dsub">${a.overridden?'manually classified':'auto-classified'} · ${a.status} · confidence ${a.confidence}</div>
    ${(kq||kd||DATA.coverage)?`<div class="sec-t">Coverage</div><div class="kv">
      <div class="k">Qualys</div><div class="v">${kq?`<span class="covbadge yes">✓ tracked</span> <span class="v mono">${kq.os||''} ${kqm.tracking?('· '+kqm.tracking):''}</span>`:'<span class="covbadge warn">✕ not in Qualys</span>'}</div>
      <div class="k">Defender</div><div class="v">${kd?`<span class="covbadge yes">✓ ${kdm.onboarding||'onboarded'}</span> <span class="v mono">${kdm.health||''}</span>`:'<span class="covbadge warn">✕ no Defender agent</span>'}</div></div>`:''}
    <div class="sec-t">Signals</div><div class="kv">
      <div class="k">PTR</div><div class="v mono">${a.ptr||'—'}</div>
      <div class="k">NetBIOS</div><div class="v mono">${a.netbios||'—'}</div>
      <div class="k">TLS CN</div><div class="v mono">${a.tls_cn||'—'}</div>
      <div class="k">HTTP title</div><div class="v mono">${a.http_title||'—'}</div>
      <div class="k">SNMP</div><div class="v mono">${a.snmp_descr||'—'}</div>
      <div class="k">MAC / OUI</div><div class="v mono">${a.mac||'—'} ${a.oui_vendor?('('+a.oui_vendor+')'):''}</div>
      <div class="k">Ports</div><div class="v mono">${a.ports||'—'}</div>
      <div class="k">Evidence</div><div class="v mono">${a.evidence||'—'}</div>
      <div class="k">IPs seen</div><div class="v mono">${ips||a.current_ip||'—'}</div>
      <div class="k">First seen</div><div class="v mono">${(a.first_seen||'').replace('T',' ')}</div>
      <div class="k">Last seen</div><div class="v mono">${(a.last_seen||'').replace('T',' ')}</div></div>
    <div class="sec-t">History</div>${evs}`;
  document.getElementById('scrim').classList.add('open');document.getElementById('drawer').classList.add('open');
}
function closeD(){document.getElementById('scrim').classList.remove('open');document.getElementById('drawer').classList.remove('open');}
render();
</script></body></html>"""


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Export a static HTML report from the ipID history DB.")
    ap.add_argument("--db", default="ipid.db", help="History DB (default ipid.db)")
    ap.add_argument("-o", "--output", default="ipID_report.html", help="Output HTML file")
    args = ap.parse_args()
    path = build_report(args.db, args.output)
    print(f"[+] Wrote {path}")
