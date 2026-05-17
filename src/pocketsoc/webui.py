from __future__ import annotations

from pathlib import Path

from .output.files import ensure_data_dir


def write_web_ui(data_dir: Path | None = None) -> Path:
    root = ensure_data_dir(data_dir)
    target = root / "webui.html"
    target.write_text(
        """<!doctype html><html><head><meta charset='utf-8'><title>PocketSOC Dashboard</title>
<style>body{font-family:sans-serif;max-width:1000px;margin:20px auto}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:6px}</style></head>
<body><h1>PocketSOC Dashboard</h1><p>Configure token in localStorage key <code>pocketsoc_token</code>.</p>
<button onclick='loadAll()'>Refresh</button><h2>Alerts</h2><table id='alerts'><thead><tr><th>ID</th><th>Severity</th><th>Title</th></tr></thead><tbody></tbody></table>
<h2>Trends</h2><table id='trends'><thead><tr><th>Timestamp</th><th>Risk</th><th>Alerts</th></tr></thead><tbody></tbody></table>
<script>
async function get(path){const token=localStorage.getItem('pocketsoc_token')||'';const r=await fetch(path,{headers:{'X-PocketSOC-Token':token}});return r.json();}
async function loadAll(){const a=await get('/alerts');const t=await get('/trends');const ab=document.querySelector('#alerts tbody');ab.innerHTML='';(a.alerts||[]).forEach(x=>ab.innerHTML+=`<tr><td>${x.id}</td><td>${x.severity}</td><td>${x.title}</td></tr>`);
const tb=document.querySelector('#trends tbody');tb.innerHTML='';(t.items||[]).slice(-20).forEach(x=>tb.innerHTML+=`<tr><td>${x.timestamp||''}</td><td>${x.risk_score||0}</td><td>${(x.alerts||[]).length}</td></tr>`);}
loadAll();
</script></body></html>""",
        encoding="utf-8",
    )
    return target
