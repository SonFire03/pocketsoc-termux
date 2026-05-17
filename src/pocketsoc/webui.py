from __future__ import annotations

from pathlib import Path

from .output.files import ensure_data_dir


def write_web_ui(data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / "webui.html"
    target.write_text(
        """<!doctype html><html><head><meta charset='utf-8'><title>PocketSOC Dashboard</title>
<style>body{font-family:sans-serif;max-width:1100px;margin:20px auto}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:6px}</style></head>
<body><h1>PocketSOC Dashboard</h1>
<div>
<label>Severity filter <select id='sev'><option value=''>all</option><option>high</option><option>medium</option><option>low</option></select></label>
<button onclick='loadAll()'>Refresh</button>
</div>
<h2>Alerts</h2><table id='alerts'><thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>Action</th></tr></thead><tbody></tbody></table>
<h2>Timeline</h2><table id='timeline'><thead><tr><th>Timestamp</th><th>Type</th><th>Details</th></tr></thead><tbody></tbody></table>
<script>
async function get(path){const token=localStorage.getItem('pocketsoc_token')||'';const r=await fetch(path,{headers:{'X-PocketSOC-Token':token}});return r.json();}
async function post(path, body){const token=localStorage.getItem('pocketsoc_token')||'';const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-PocketSOC-Token':token},body:JSON.stringify(body)});return r.json();}
async function ack(id, sev){await post('/alert-state',{alert_id:id,severity:sev,status:'investigating',owner:'local-ui',comment:'ack from ui'});loadAll();}
async function loadAll(){const sev=document.getElementById('sev').value;const q=sev?`?severity=${sev}`:'';const a=await get('/alerts'+q);const t=await get('/trends?limit=20');
const ab=document.querySelector('#alerts tbody');ab.innerHTML='';(a.alerts||[]).forEach(x=>ab.innerHTML+=`<tr><td>${x.id}</td><td>${x.severity}</td><td>${x.title}</td><td><button onclick="ack('${x.id}','${x.severity}')">ack</button></td></tr>`);
const tb=document.querySelector('#timeline tbody');tb.innerHTML='';(t.items||[]).slice(-20).forEach(x=>tb.innerHTML+=`<tr><td>${x.timestamp||''}</td><td>scan</td><td>risk=${x.risk_score||0}, alerts=${(x.alerts||[]).length}</td></tr>`);
}
loadAll();
</script></body></html>""",
        encoding="utf-8",
    )
    return target
