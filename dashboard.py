"""
CVM Attestation Dashboard  —  multi-protocol with live push
"""
import json, sys, os, base64, datetime, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server as cvm_server
from protocols import REGISTRY
import protocol_loader
import protocol_builder
from flask import Flask, render_template_string, request as flask_request, jsonify

app = Flask(__name__)

# ── In-memory results store ───────────────────────────────────────────────────
# { protocol_id: { timestamp, results, all_pass, cvm_success, error } }
results_store = {}
store_lock    = threading.Lock()


# ── Evidence tree walker (generic) ───────────────────────────────────────────
def decode_verdict(b):
    try:    s = base64.b64decode(b).decode()
    except: s = b
    return ('PASS', '') if s == '' else ('FAIL', s.strip("'"))

def walk_et(node, raw_ev, idx):
    results = []
    if not node: return results
    ctor = node.get('EvidenceT_CONSTRUCTOR', '')
    body = node.get('EvidenceT_BODY', [])
    if ctor == 'mt_evt':
        return results
    if ctor == 'split_evt':
        for child in body:
            results += walk_et(child, raw_ev, idx)
    elif ctor in ('left_evt', 'right_evt'):
        results += walk_et(body, raw_ev, idx)
    elif ctor == 'asp_evt':
        place, params, sub = body
        asp_id   = params['ASP_ID']
        asp_args = params.get('ASP_ARGS', {})
        if asp_id.endswith('_appr'):
            v, msg = decode_verdict(raw_ev[idx[0]] if idx[0] < len(raw_ev) else '')
            idx[0] += 1
            target = asp_id[:-5]
            fp = asp_args.get('filepath') or asp_args.get('filepath_golden', '')
            fp = fp.split('/')[-1] if fp else ''
            results.append({'appr': asp_id, 'target': target,
                            'filepath': fp, 'verdict': v, 'msg': msg})
        results += walk_et(sub, raw_ev, idx)
    return results


def run_protocol(protocol_id):
    """Run a protocol by ID and return parsed appraisal results."""
    proto = REGISTRY[protocol_id]
    manifest, req = proto['build']()
    raw = cvm_server.run_attestation(manifest, req)
    response = json.loads(raw) if isinstance(raw, str) else raw
    cvm_success = response.get('SUCCESS', False)
    error = None
    results = []
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if cvm_success:
        try:
            raw_ev  = response['PAYLOAD'][0]['RawEv']
            et      = response['PAYLOAD'][1]
            results = walk_et(et, raw_ev, [0])
            for row in results:
                row['timestamp'] = ts
        except Exception as e:
            error = str(e)
    else:
        error = response.get('PAYLOAD', 'CVM execution failed')
    return {
        'protocol_id':  protocol_id,
        'cvm_success':  cvm_success,
        'results':      results,
        'all_pass':     cvm_success and all(r['verdict'] == 'PASS' for r in results),
        'pass_count':   sum(1 for r in results if r['verdict'] == 'PASS'),
        'fail_count':   sum(1 for r in results if r['verdict'] != 'PASS'),
        'error':        error,
        'timestamp':    ts,
    }


def store_result(data):
    with store_lock:
        results_store[data['protocol_id']] = data


def protocol_any_tampered(protocol_id):
    """Return True if any measurement target for this protocol is currently non-compliant."""
    proto = REGISTRY.get(protocol_id)
    if not proto:
        return False
    return any(not t['get_state']()['compliant'] for t in proto.get('tamper_targets', {}).values())


# ── HTML templates ────────────────────────────────────────────────────────────
BASE_STYLE = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'SF Mono','Fira Code',monospace; background:#0d1117; color:#e6edf3;
       min-height:100vh; padding:20px; }
a { color:inherit; text-decoration:none; }

.header { display:flex; align-items:center; gap:14px; margin-bottom:20px;
          border-bottom:1px solid #21262d; padding-bottom:16px; flex-wrap:wrap; }
.header h1 { font-size:1.3rem; font-weight:600; }
.header .sub { font-size:0.75rem; color:#8b949e; margin-top:3px; }

.badge-pass { background:#1a4731; color:#3fb950; border:1px solid #238636;
              padding:3px 10px; border-radius:20px; font-size:0.72rem; font-weight:600; }
.badge-fail { background:#4a1a1a; color:#f85149; border:1px solid #da3633;
              padding:3px 10px; border-radius:20px; font-size:0.72rem; font-weight:600; }
.badge-idle { background:#1c2128; color:#8b949e; border:1px solid #30363d;
              padding:3px 10px; border-radius:20px; font-size:0.72rem; }
.badge-tampered { background:#3d1a00; color:#e3b341; border:1px solid #9e6a03;
                  padding:2px 8px; border-radius:20px; font-size:0.68rem; font-weight:600; }
.badge-compliant { background:#1a4731; color:#3fb950; border:1px solid #238636;
                   padding:2px 8px; border-radius:20px; font-size:0.68rem; font-weight:600; }

.card { background:#161b22; border:1px solid #21262d; border-radius:10px; padding:18px; margin-bottom:16px; }
.card-title { font-size:0.68rem; text-transform:uppercase; letter-spacing:.08em;
              color:#8b949e; margin-bottom:14px; }

.dot-g { width:10px;height:10px;border-radius:50%;background:#3fb950;box-shadow:0 0 6px #3fb950;display:inline-block; }
.dot-r { width:10px;height:10px;border-radius:50%;background:#f85149;box-shadow:0 0 6px #f85149;display:inline-block; }
.dot-d { width:10px;height:10px;border-radius:50%;background:#30363d;display:inline-block; }
.dot-o { width:10px;height:10px;border-radius:50%;background:#e3b341;box-shadow:0 0 6px #e3b341;display:inline-block; }
.dot-lg{ width:12px;height:12px;border-radius:50%;background:#3fb950;box-shadow:0 0 8px #3fb950;display:inline-block; }
.dot-lr{ width:12px;height:12px;border-radius:50%;background:#f85149;box-shadow:0 0 8px #f85149;display:inline-block; }

.stats { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-bottom:16px; }
.stat-card { background:#161b22; border:1px solid #21262d; border-radius:10px;
             padding:14px 12px; text-align:center; }
.stat-num  { font-size:1.8rem; font-weight:700; line-height:1; }
.stat-label{ font-size:0.65rem; color:#8b949e; margin-top:4px; text-transform:uppercase; letter-spacing:.06em; }
.num-pass  { color:#3fb950; }
.num-fail  { color:#f85149; }
.num-total { color:#79c0ff; }

table { width:100%; border-collapse:collapse; font-size:0.82rem; table-layout:fixed; }
th { text-align:left; padding:8px 12px; font-size:0.68rem; text-transform:uppercase;
     letter-spacing:.08em; color:#8b949e; border-bottom:1px solid #21262d; }
td { padding:11px 12px; border-bottom:1px solid #161b22; vertical-align:middle; overflow:hidden; text-overflow:ellipsis; }
tr:last-child td { border-bottom:none; }
tr:hover td { background:#1c2128; }

.vpass { display:inline-flex;align-items:center;gap:6px;color:#3fb950;font-weight:600; }
.vfail { display:inline-flex;align-items:center;gap:6px;color:#f85149;font-weight:600; }
.fail-msg { font-size:0.72rem;color:#f85149;margin-top:3px;opacity:.85; }
.asp-pill { display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.72rem;font-weight:500; }
.asp-hashfile_appr { background:#0d1f2e;color:#58a6ff;border:1px solid #1f6feb; }
.asp-sig_appr      { background:#1a1200;color:#e3b341;border:1px solid #9e6a03; }
.asp-default       { background:#1c2128;color:#8b949e;border:1px solid #30363d; }
.target-file { color:#a5d6ff; }
.target-sig  { color:#e3b341; }
.target-hsh  { color:#d2a8ff; }

.flow { display:flex;align-items:center;gap:0;flex-wrap:wrap; }
.flow-node { background:#21262d;border:1px solid #30363d;border-radius:6px;
             padding:7px 12px;font-size:0.78rem;color:#79c0ff;white-space:nowrap; }
.fn-bseq { border-color:#553098;background:#1a1230;color:#d2a8ff;padding:6px 10px; }
.fn-sig  { border-color:#9e6a03;background:#1a1200;color:#e3b341; }
.fn-appr { border-color:#1f6feb;background:#0d1a2e;color:#58a6ff; }
.fn-hsh  { border-color:#553098;background:#1a1230;color:#d2a8ff; }
.fn-file { border-color:#1f6feb;background:#0d1f2e;color:#a5d6ff;font-size:.72rem; }
.fn-default { border-color:#30363d;background:#21262d;color:#8b949e; }
.flow-arrow { color:#30363d;font-size:1.1rem;padding:0 6px;flex-shrink:0; }
.flow-sub { display:flex;flex-direction:column;gap:4px;padding:4px 0; }
.bseq-label { font-size:0.65rem;color:#8b949e;margin-bottom:4px; }

.proto-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:14px; margin-bottom:16px; }
.proto-card { background:#161b22;border:1px solid #21262d;border-radius:10px;
              padding:16px;cursor:pointer;transition:border-color .15s; }
.proto-card:hover { border-color:#388bfd; }
.proto-card-header { display:flex;align-items:center;gap:10px;margin-bottom:8px; }
.proto-name   { font-size:0.9rem;font-weight:600; }
.proto-desc   { font-size:0.75rem;color:#8b949e;margin-bottom:10px; }
.proto-copland{ font-size:0.68rem;color:#6e7681;font-family:monospace; }
.proto-stats  { display:flex;gap:10px;margin-top:10px;font-size:0.75rem; }
.ps-pass { color:#3fb950; }
.ps-fail { color:#f85149; }
.ps-idle { color:#8b949e; }

.back-link { font-size:0.78rem;color:#8b949e;margin-bottom:16px;display:inline-block; }
.back-link:hover { color:#e6edf3; }
.timestamp { font-size:0.72rem;color:#8b949e;margin-top:16px;text-align:right; }
.live-dot { width:8px;height:8px;border-radius:50%;background:#3fb950;
            display:inline-block;animation:pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }

.run-btn { background:#21262d;border:1px solid #388bfd;color:#58a6ff;border-radius:6px;
           padding:5px 12px;font-size:0.75rem;font-family:inherit;cursor:pointer;
           transition:background .15s,opacity .15s;white-space:nowrap; }
.run-btn:hover:not(:disabled) { background:#1f6feb;color:#fff; }
.run-btn:disabled { opacity:.5;cursor:not-allowed; }
.run-btn-lg { padding:7px 16px;font-size:0.82rem; }
.prov-btn { background:#21262d;border:1px solid #9e6a03;color:#e3b341;border-radius:6px;
            padding:5px 12px;font-size:0.75rem;font-family:inherit;cursor:pointer;
            transition:background .15s,opacity .15s;white-space:nowrap; }
.prov-btn:hover:not(:disabled) { background:#3a2800;color:#ffd700; }
.prov-btn:disabled { opacity:.5;cursor:not-allowed; }
.prov-btn-lg { padding:7px 16px;font-size:0.82rem; }
.prov-result { background:#1a1200;border:1px solid #9e6a03;border-radius:8px;
               padding:14px 16px;margin-top:12px;font-size:0.78rem; }
.prov-row { display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #2a1f00;flex-wrap:wrap; }
.prov-row:last-child { border-bottom:none; }
.prov-label { color:#8b949e;min-width:130px;flex-shrink:0; }
.prov-file  { color:#e3b341; }
.prov-hash  { color:#6e7681;font-size:0.7rem;font-family:monospace;word-break:break-all;flex:1;min-width:0; }
.proto-card-body { display:block;color:inherit;text-decoration:none; }
.proto-card-footer { display:flex;align-items:center;justify-content:space-between;
                     margin-top:10px; }

.tamper-btn { background:#1a0000;border:1px solid #da3633;color:#f85149;border-radius:6px;
              padding:4px 10px;font-size:0.72rem;font-family:inherit;cursor:pointer;
              transition:background .15s,opacity .15s;white-space:nowrap; }
.tamper-btn:hover:not(:disabled) { background:#3d0000;color:#ff8080; }
.tamper-btn:disabled { opacity:.5;cursor:not-allowed; }
.repair-btn { background:#001a00;border:1px solid #238636;color:#3fb950;border-radius:6px;
              padding:4px 10px;font-size:0.72rem;font-family:inherit;cursor:pointer;
              transition:background .15s,opacity .15s;white-space:nowrap; }
.repair-btn:hover:not(:disabled) { background:#003000;color:#5aff5a; }
.repair-btn:disabled { opacity:.5;cursor:not-allowed; }
.reset-btn  { background:#0d1117;border:1px solid #30363d;color:#8b949e;border-radius:6px;
              padding:4px 10px;font-size:0.72rem;font-family:inherit;cursor:pointer;
              transition:background .15s,opacity .15s;white-space:nowrap; }
.reset-btn:hover:not(:disabled) { background:#21262d;color:#e6edf3; }
.reset-btn:disabled { opacity:.5;cursor:not-allowed; }
.tamper-action-group { display:flex;align-items:center;gap:6px;margin-left:auto;flex-shrink:0; }
.inspect-btn { background:#0d1117;border:1px solid #30363d;color:#6e7681;border-radius:6px;
               padding:3px 8px;font-size:0.68rem;font-family:inherit;cursor:pointer;
               transition:border-color .15s,color .15s;white-space:nowrap; }
.inspect-btn:hover { border-color:#8b949e;color:#e6edf3; }
.inspect-btn.open { border-color:#79c0ff;color:#79c0ff; }
.inspect-panel { background:#0d1117;border:1px solid #30363d;border-top:none;
                 border-radius:0 0 6px 6px;padding:14px 16px;margin-bottom:4px; }
.inspect-pre  { background:#161b22;border:1px solid #30363d;border-radius:4px;
                padding:8px 10px;font-size:0.72rem;color:#e6edf3;white-space:pre-wrap;
                word-break:break-all;margin:4px 0 0; font-family:'SF Mono','Fira Code',monospace; }
.diff-block   { background:#161b22;border:1px solid #30363d;border-radius:4px;
                padding:6px 10px;font-family:'SF Mono','Fira Code',monospace;font-size:0.72rem;margin-top:4px; }
.diff-add  { color:#3fb950;display:block; }
.diff-del  { color:#f85149;display:block; }
.diff-hdr  { color:#79c0ff;display:block; }
.diff-meta { color:#6e7681;display:block; }
.diff-ctx  { color:#6e7681;display:block; }
.badge-custom { background:#1a2340;color:#79c0ff;border:1px solid #1f4080;
                padding:2px 7px;border-radius:20px;font-size:0.65rem;font-weight:600;letter-spacing:.04em; }
.load-panel { background:#161b22;border:1px solid #21262d;border-radius:10px;
              padding:14px 18px;margin-bottom:16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap; }
.load-panel label { color:#8b949e;font-size:0.75rem;white-space:nowrap; }
.load-input { flex:1;min-width:260px;background:#0d1117;border:1px solid #30363d;border-radius:6px;
              color:#e6edf3;font-size:0.8rem;padding:5px 10px;outline:none; }
.load-input:focus { border-color:#388bfd; }
.load-btn   { background:#1f4080;color:#79c0ff;border:1px solid #1f4080;border-radius:6px;
              padding:5px 14px;font-size:0.78rem;cursor:pointer;white-space:nowrap; }
.load-btn:hover { background:#2d5ba8; }
.remove-btn { background:transparent;color:#6e7681;border:1px solid #30363d;border-radius:6px;
              padding:3px 9px;font-size:0.72rem;cursor:pointer; }
.remove-btn:hover { color:#f85149;border-color:#f85149; }
.load-error { color:#f85149;font-size:0.75rem; }
"""

HOME_TMPL = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>CVM Dashboard</title>
<style>{{ style }}</style>
</head><body>
<div class="header">
  <span class="live-dot"></span>
  <div><h1>CVM Attestation Dashboard</h1>
       <div class="sub">{{ protocols|length }} protocol{{ 's' if protocols|length != 1 }} registered</div></div>
  <a href="/build" class="run-btn" style="margin-left:auto;">⊕ Build Protocol</a>
</div>

<div class="proto-grid" id="proto-grid">
{% for p in protocols %}
  {% set r = results.get(p.id) %}
  {% set any_tampered = tamper_states.get(p.id, false) %}
  <div class="proto-card" id="card-{{ p.id }}">
    <a href="/protocol/{{ p.id }}" class="proto-card-body">
      <div class="proto-card-header">
        {% if r %}
          {% if r.all_pass %}<span class="dot-g"></span>
          {% else %}<span class="dot-r"></span>{% endif %}
        {% else %}<span class="dot-d"></span>{% endif %}
        <span class="proto-name">{{ p.name }}</span>
        {% if p.custom_source %}
          <span class="badge-custom" style="margin-left:auto;">⊕ custom</span>
        {% elif any_tampered %}
          <span class="badge-tampered" style="margin-left:auto;">⚠ TAMPERED</span>
        {% endif %}
        {% if any_tampered and p.custom_source %}
          <span class="badge-tampered">⚠ TAMPERED</span>
        {% endif %}
      </div>
      <div class="proto-desc">{{ p.description }}</div>
      <div class="proto-copland">{{ p.copland }}</div>
    </a>
    <div class="proto-card-footer">
      <div class="proto-stats" id="stats-{{ p.id }}">
        {% if r %}
          <span class="ps-pass">✓ {{ r.pass_count }} passed</span>
          {% if r.fail_count > 0 %}<span class="ps-fail">✗ {{ r.fail_count }} failed</span>{% endif %}
          <span class="ps-idle" style="margin-left:auto;">{{ r.timestamp[11:] }}</span>
        {% else %}
          <span class="ps-idle">Not yet run</span>
        {% endif %}
      </div>
      <div style="display:flex;gap:6px;">
        <button class="prov-btn" id="provbtn-{{ p.id }}"
                onclick="provisionProtocol('{{ p.id }}')">⚙ Provision</button>
        <button class="run-btn" id="runbtn-{{ p.id }}"
                onclick="runProtocol('{{ p.id }}')">▶ Run</button>
        {% if p.custom_source %}
          <button class="remove-btn" id="rmbtn-{{ p.id }}"
                  onclick="removeProtocol('{{ p.id }}')">× Remove</button>
        {% endif %}
      </div>
    </div>
  </div>
{% endfor %}
</div>

<div class="load-panel">
  <label>Load protocol from JSON file:</label>
  <input class="load-input" id="load-path-input" type="text"
         placeholder="/path/to/protocol.json" spellcheck="false">
  <button class="load-btn" onclick="loadProtocol()">⊕ Load</button>
  <span class="load-error" id="load-error" style="display:none;"></span>
</div>

<script>
async function runProtocol(id) {
  const btn  = document.getElementById('runbtn-' + id);
  const card = document.getElementById('card-' + id);
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Running…'; }
  try {
    const res  = await fetch('/api/run/' + id);
    const r    = await res.json();
    const dot = card.querySelector('.dot-g, .dot-r, .dot-d');
    if (dot) dot.className = r.all_pass ? 'dot-g' : 'dot-r';
    const stats = document.getElementById('stats-' + id);
    if (stats) {
      const failPart = r.fail_count > 0 ? `<span class="ps-fail">✗ ${r.fail_count} failed</span>` : '';
      stats.innerHTML = `<span class="ps-pass">✓ ${r.pass_count} passed</span>${failPart}
                         <span class="ps-idle" style="margin-left:auto;">${r.timestamp.slice(11)}</span>`;
    }
  } catch(e) {}
  if (btn) { btn.disabled = false; btn.textContent = '▶ Run'; }
}

async function provisionProtocol(id) {
  const btn = document.getElementById('provbtn-' + id);
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Provisioning…'; }
  try { await fetch('/api/provision/' + id); } catch(e) {}
  if (btn) { btn.disabled = false; btn.textContent = '⚙ Provision'; }
}
// (Provision on home page updates golden files; visit detail page to see new hashes)

async function loadProtocol() {
  const input = document.getElementById('load-path-input');
  const errEl = document.getElementById('load-error');
  const path  = input.value.trim();
  if (!path) return;
  errEl.style.display = 'none';
  try {
    const res  = await fetch('/api/load_protocol', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path}),
    });
    const data = await res.json();
    if (!res.ok) { errEl.textContent = data.error || 'Load failed'; errEl.style.display = ''; return; }
    input.value = '';
    location.reload();
  } catch(e) {
    errEl.textContent = 'Error: ' + e.message; errEl.style.display = '';
  }
}

async function removeProtocol(id) {
  const btn = document.getElementById('rmbtn-' + id);
  if (btn) { btn.disabled = true; btn.textContent = '⟳'; }
  try {
    const res = await fetch('/api/protocols/' + id, {method: 'DELETE'});
    if (res.ok) { location.reload(); return; }
    const data = await res.json();
    alert(data.error || 'Remove failed');
  } catch(e) { alert('Error: ' + e.message); }
  if (btn) { btn.disabled = false; btn.textContent = '× Remove'; }
}

document.getElementById('load-path-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') loadProtocol();
});

// Poll for live updates (from MCP pushes) every 3 seconds
async function poll() {
  try {
    const res = await fetch('/api/results');
    const data = await res.json();
    Object.entries(data).forEach(([id, r]) => {
      const card = document.getElementById('card-' + id);
      if (!card) return;
      const dot = card.querySelector('.dot-g, .dot-r, .dot-d');
      if (dot) dot.className = r.all_pass ? 'dot-g' : 'dot-r';
      const stats = document.getElementById('stats-' + id);
      if (stats) {
        const failPart = r.fail_count > 0 ? `<span class="ps-fail">✗ ${r.fail_count} failed</span>` : '';
        stats.innerHTML = `<span class="ps-pass">✓ ${r.pass_count} passed</span>${failPart}
                           <span class="ps-idle" style="margin-left:auto;">${r.timestamp.slice(11)}</span>`;
      }
    });
  } catch(e) {}
}
setInterval(poll, 3000);
</script>
</body></html>
"""

DETAIL_TMPL = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>{{ proto.name }} — CVM Dashboard</title>
<style>{{ style }}</style>
</head><body>
<div class="header">
  {% if r %}
    {% if r.all_pass %}<span class="dot-lg"></span><span class="badge-pass">ATTESTED</span>
    {% else %}<span class="dot-lr"></span><span class="badge-fail">FAILED</span>{% endif %}
  {% else %}<span class="dot-d"></span>{% endif %}
  <div>
    <h1>{{ proto.name }}</h1>
    <div class="sub">{{ proto.copland }}</div>
  </div>
  <div style="display:flex;align-items:center;gap:8px;margin-left:auto;">
    <button class="prov-btn prov-btn-lg" id="prov-btn"
            onclick="provisionProtocol('{{ proto.id }}')">⚙ Provision</button>
    <button class="run-btn run-btn-lg" id="run-btn"
            onclick="runProtocol('{{ proto.id }}')">▶ Run</button>
    {% if proto.custom_source %}
    <a href="/build?edit={{ proto.id }}" class="run-btn run-btn-lg">✎ Edit</a>
    {% endif %}
    <a href="/" class="back-link" style="margin-left:4px;">← All protocols</a>
  </div>
</div>

{% if r %}
<div class="stats">
  <div class="stat-card"><div class="stat-num num-total">{{ r.results|length }}</div><div class="stat-label">Checks</div></div>
  <div class="stat-card"><div class="stat-num num-pass">{{ r.pass_count }}</div><div class="stat-label">Passed</div></div>
  <div class="stat-card"><div class="stat-num num-fail">{{ r.fail_count }}</div><div class="stat-label">Failed</div></div>
</div>
{% endif %}

<div class="card">
  <div class="card-title">Copland Protocol</div>
  <div class="flow">
    {% for node in proto.flow %}
      {% if node.type == 'arrow' %}
        <span class="flow-arrow">→</span>
      {% elif node.type == 'bseq' %}
        <div class="flow-node fn-bseq">
          <div class="bseq-label">{{ node.label }}</div>
          <div class="flow-sub">
            {% for child in node.children %}
              <div class="flow-node fn-file">{{ child }}</div>
            {% endfor %}
          </div>
        </div>
      {% else %}
        <div class="flow-node fn-{{ node.style }}">{{ node.label }}</div>
      {% endif %}
    {% endfor %}
  </div>
</div>

<div class="card" style="border-color:#9e6a03;">
  <div class="card-title" style="color:#e3b341;">Golden Evidence — Last Provisioned</div>
  {% if prov %}
  <div>
    {% for e in prov %}
    <div>
      <div class="prov-row" id="prov-row-{{ e.tamper_id or loop.index }}">
        <span class="prov-label">{{ e.target }}</span>
        <span class="prov-file">{{ e.golden }}</span>
        {% if e.sha256 %}
          <span class="prov-hash" title="{{ e.sha256 }}">{{ e.sha256[:16] }}…</span>
          <span style="color:#6e7681;font-size:0.7rem;white-space:nowrap;">{{ e.timestamp }}</span>
        {% else %}
          <span style="color:#8b949e;font-size:0.75rem;font-style:italic;">not provisioned</span>
        {% endif %}
        {% if e.tamper_id and e.tamper_state %}
          <div class="tamper-action-group">
            {% if e.tamper_state.compliant %}
              <span class="badge-compliant">✓ COMPLIANT</span>
              <button class="tamper-btn" id="tamper-btn-{{ e.tamper_id }}"
                      onclick="tamperTarget('{{ proto.id }}', '{{ e.tamper_id }}')">⚡ Tamper</button>
            {% else %}
              <span class="badge-tampered">⚠ TAMPERED</span>
              <button class="repair-btn" id="repair-btn-{{ e.tamper_id }}"
                      onclick="repairTarget('{{ proto.id }}', '{{ e.tamper_id }}')">⚕ Repair</button>
            {% endif %}
            <button class="reset-btn" id="reset-btn-{{ e.tamper_id }}"
                    onclick="resetTarget('{{ proto.id }}', '{{ e.tamper_id }}')">↺ Reset</button>
            <span style="border-left:1px solid #30363d;height:14px;"></span>
            <button class="inspect-btn" id="inspect-btn-{{ e.tamper_id }}"
                    onclick="toggleInspect('{{ proto.id }}', '{{ e.tamper_id }}')">⊞ Inspect</button>
          </div>
        {% endif %}
      </div>
      {% if e.tamper_id %}
      <div class="inspect-panel" id="inspect-panel-{{ e.tamper_id }}" style="display:none;"></div>
      {% endif %}
    </div>
    {% endfor %}
  </div>
  {% else %}
  <div style="color:#8b949e;font-size:0.78rem;font-style:italic;">No golden evidence configured for this protocol.</div>
  {% endif %}
</div>

{% if r %}
  {% if r.error %}
    <div class="card" style="border-color:#da3633;">
      <div class="card-title" style="color:#f85149;">Error</div>
      <div style="color:#f85149;font-size:.82rem;">{{ r.error }}</div>
    </div>
  {% else %}
  <div class="card">
    <div class="card-title">Appraisal Results</div>
    <table>
      <colgroup><col style="width:24%"><col style="width:36%"><col style="width:20%"><col style="width:20%"></colgroup>
      <thead><tr><th>Appraiser</th><th>Target</th><th>Verdict</th><th>Appraised At</th></tr></thead>
      <tbody>
        {% for row in r.results %}
        <tr>
          <td><span class="asp-pill asp-{{ row.appr }}">{{ row.appr }}</span></td>
          <td>
            {% if row.filepath %}
              <span class="target-file">{{ row.target }}({{ row.filepath }})</span>
            {% elif row.target == 'sig' %}
              <span class="target-sig">{{ row.target }}</span>
            {% else %}
              <span class="target-hsh">{{ row.target }}</span>
            {% endif %}
          </td>
          <td>
            {% if row.verdict == 'PASS' %}
              <div class="vpass"><span class="dot-g"></span> PASS</div>
            {% else %}
              <div class="vfail"><span class="dot-r"></span> FAIL</div>
              {% if row.msg %}<div class="fail-msg">{{ row.msg }}</div>{% endif %}
            {% endif %}
          </td>
          <td style="color:#6e7681;font-size:0.72rem;">{{ row.timestamp or r.timestamp }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}
  <div class="timestamp">Last run: {{ r.timestamp }}</div>
{% else %}
  <div class="card" style="text-align:center;color:#8b949e;padding:40px;">
    No results yet — run this protocol via the MCP server or use the Run button above.
  </div>
{% endif %}

<script>
const PROTOCOL_ID = '{{ proto.id }}';
const _PANELS_KEY = 'cvm_open_panels_' + PROTOCOL_ID;
const _inspectIntervals = {};

function _getOpenPanels() {
  try { return JSON.parse(sessionStorage.getItem(_PANELS_KEY) || '{}'); } catch { return {}; }
}
function _saveOpenPanels(obj) { sessionStorage.setItem(_PANELS_KEY, JSON.stringify(obj)); }

async function _loadInspectPanel(protocolId, targetId) {
  const panel = document.getElementById('inspect-panel-' + targetId);
  if (!panel || panel.style.display === 'none') return;
  try {
    const res  = await fetch('/api/inspect/' + protocolId + '/' + targetId);
    const data = await res.json();
    panel.innerHTML = renderInspect(data);
  } catch(e) {
    panel.innerHTML = `<span style="color:#f85149;font-size:0.75rem;">Error: ${escHtml(e.message)}</span>`;
  }
}

async function _restoreInspectPanels() {
  for (const [targetId, protocolId] of Object.entries(_getOpenPanels())) {
    const panel = document.getElementById('inspect-panel-' + targetId);
    const btn   = document.getElementById('inspect-btn-'   + targetId);
    if (!panel) continue;
    panel.style.display = 'block';
    if (btn) { btn.textContent = '⊟ Inspect'; btn.classList.add('open'); }
    panel.innerHTML = '<span style="color:#8b949e;font-size:0.75rem;font-style:italic;">Loading…</span>';
    await _loadInspectPanel(protocolId, targetId);
    _inspectIntervals[targetId] = setInterval(() => _loadInspectPanel(protocolId, targetId), 2000);
  }
}
document.addEventListener('DOMContentLoaded', _restoreInspectPanels);

async function runProtocol(id) {
  const btn = document.getElementById('run-btn');
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Running…'; }
  try {
    await fetch('/api/run/' + id);
    location.reload();
  } catch(e) {
    if (btn) { btn.disabled = false; btn.textContent = '▶ Run'; }
  }
}

async function provisionProtocol(id) {
  const btn = document.getElementById('prov-btn');
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Provisioning…'; }
  try {
    await fetch('/api/provision/' + id);
    location.reload();
  } catch(e) {
    if (btn) { btn.disabled = false; btn.textContent = '⚙ Provision'; }
  }
}

async function tamperTarget(protocolId, targetId) {
  const btn = document.getElementById('tamper-btn-' + targetId);
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Tampering…'; }
  try {
    const res = await fetch('/api/tamper/' + protocolId + '/' + targetId, {method: 'POST'});
    if (res.ok) { location.reload(); return; }
  } catch(e) {}
  if (btn) { btn.disabled = false; btn.textContent = '⚡ Tamper'; }
}

async function repairTarget(protocolId, targetId) {
  const btn = document.getElementById('repair-btn-' + targetId);
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Repairing…'; }
  try {
    const res = await fetch('/api/repair/' + protocolId + '/' + targetId, {method: 'POST'});
    if (res.ok) { location.reload(); return; }
  } catch(e) {}
  if (btn) { btn.disabled = false; btn.textContent = '⚕ Repair'; }
}

async function resetTarget(protocolId, targetId) {
  const btn = document.getElementById('reset-btn-' + targetId);
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Resetting…'; }
  try {
    const res = await fetch('/api/reset/' + protocolId + '/' + targetId, {method: 'POST'});
    if (res.ok) { location.reload(); return; }
  } catch(e) {}
  if (btn) { btn.disabled = false; btn.textContent = '↺ Reset'; }
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function renderInspect(data) {
  if (data.error) return `<span style="color:#f85149;font-size:0.75rem;">${escHtml(data.error)}</span>`;

  const hdr = (t) => `<div style="color:#8b949e;font-size:0.68rem;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">${t}</div>`;

  if (data.type === 'hsh') {
    const match = data.compliant;
    return hdr('Evidence Hash (SHA-256 of empty input)') + `
      <div style="display:flex;gap:24px;flex-wrap:wrap;font-size:0.75rem;">
        <div><div style="color:#8b949e;font-size:0.68rem;margin-bottom:2px;">Expected</div>
             <code style="color:#79c0ff;">${data.expected_sha256}</code></div>
        <div><div style="color:#8b949e;font-size:0.68rem;margin-bottom:2px;">Actual golden</div>
             <code style="color:${match?'#3fb950':'#f85149'};">${data.actual_sha256}</code></div>
      </div>`;
  }

  // file type
  if (data.compliant) {
    return hdr('File Content — matches golden') +
      `<pre class="inspect-pre">${escHtml(data.current)}</pre>
       <div style="color:#8b949e;font-size:0.68rem;margin-top:6px;">
         SHA-256 <code style="color:#3fb950;">${data.current_sha256}</code>
       </div>`;
  }

  if (data.diff && data.diff.length) {
    const lines = data.diff.map(line => {
      const e = escHtml(line.trimEnd());
      if (line.startsWith('+++') || line.startsWith('---')) return `<span class="diff-meta">${e}</span>`;
      if (line.startsWith('+'))  return `<span class="diff-add">${e}</span>`;
      if (line.startsWith('-'))  return `<span class="diff-del">${e}</span>`;
      if (line.startsWith('@@')) return `<span class="diff-hdr">${e}</span>`;
      return `<span class="diff-ctx">${e}</span>`;
    }).join('');
    return hdr('Diff — last provisioned → current') +
      `<div class="diff-block">${lines}</div>`;
  }

  // No .src file — just show current vs golden hash mismatch
  return hdr('Content — no provisioned snapshot available') +
    `<pre class="inspect-pre" style="border-color:#da3633;">${escHtml(data.current)}</pre>
     <div style="color:#8b949e;font-size:0.68rem;margin-top:6px;">
       Current SHA-256 <code style="color:#f85149;">${data.current_sha256}</code><br>
       Golden SHA-256&nbsp; <code style="color:#f85149;">${data.golden_sha256}</code>
     </div>`;
}

async function toggleInspect(protocolId, targetId) {
  const panel = document.getElementById('inspect-panel-' + targetId);
  const btn   = document.getElementById('inspect-btn-'   + targetId);
  if (!panel) return;
  if (panel.style.display !== 'none') {
    panel.style.display = 'none';
    if (btn) { btn.textContent = '⊞ Inspect'; btn.classList.remove('open'); }
    clearInterval(_inspectIntervals[targetId]);
    delete _inspectIntervals[targetId];
    const panels = _getOpenPanels(); delete panels[targetId]; _saveOpenPanels(panels);
    return;
  }
  panel.style.display = 'block';
  if (btn) { btn.textContent = '⊟ Inspect'; btn.classList.add('open'); }
  panel.innerHTML = '<span style="color:#8b949e;font-size:0.75rem;font-style:italic;">Loading…</span>';
  const panels = _getOpenPanels(); panels[targetId] = protocolId; _saveOpenPanels(panels);
  await _loadInspectPanel(protocolId, targetId);
  _inspectIntervals[targetId] = setInterval(() => _loadInspectPanel(protocolId, targetId), 2000);
}
</script>
</body></html>
"""


BUILD_TMPL = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>Build Protocol — CVM Dashboard</title>
<style>{{ style }}
.build-grid { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
@media(max-width:700px){ .build-grid { grid-template-columns:1fr; } }
.build-ta { width:100%;background:#0d1117;color:#e6edf3;border:1px solid #30363d;
            border-radius:6px;padding:10px;font-family:'SF Mono','Fira Code',monospace;
            font-size:0.75rem;resize:vertical;outline:none;min-height:140px; }
.build-ta:focus { border-color:#388bfd; }
.build-input { width:100%;background:#0d1117;color:#e6edf3;border:1px solid #30363d;
               border-radius:6px;padding:7px 10px;font-family:inherit;font-size:0.8rem;
               outline:none; }
.build-input:focus { border-color:#388bfd; }
.build-label { font-size:0.68rem;text-transform:uppercase;letter-spacing:.06em;
               color:#8b949e;margin-bottom:6px;display:block; }
.file-row { display:flex;gap:6px;align-items:center;margin-bottom:8px; }
.file-path { flex:1;background:#0d1117;color:#8b949e;border:1px solid #21262d;
             border-radius:6px;padding:5px 9px;font-family:'SF Mono','Fira Code',monospace;
             font-size:0.72rem;outline:none; }
.file-path:focus { border-color:#30363d;color:#e6edf3; }
.file-load-btn { background:#1c2128;border:1px solid #30363d;color:#8b949e;border-radius:6px;
                 padding:4px 11px;font-size:0.72rem;font-family:inherit;cursor:pointer;
                 white-space:nowrap;transition:border-color .15s,color .15s; }
.file-load-btn:hover { border-color:#8b949e;color:#e6edf3; }
.file-load-btn:disabled { opacity:.45;cursor:not-allowed; }
.file-err { color:#f85149;font-size:0.7rem;margin-left:4px; }
.derive-btn { background:#1f3a1f;border:1px solid #238636;color:#3fb950;border-radius:6px;
              padding:6px 16px;font-size:0.78rem;font-family:inherit;cursor:pointer;
              transition:background .15s; white-space:nowrap; }
.derive-btn:hover { background:#1a4731; }
.derive-btn:disabled { opacity:.5;cursor:not-allowed; }
.register-btn { background:#0d2340;border:1px solid #1f6feb;color:#58a6ff;border-radius:6px;
                padding:8px 22px;font-size:0.85rem;font-family:inherit;cursor:pointer;
                transition:background .15s; }
.register-btn:hover:not(:disabled) { background:#1f4080; }
.register-btn:disabled { opacity:.5;cursor:not-allowed; }
.target-row { display:flex;gap:10px;align-items:baseline;font-size:0.75rem;
              padding:5px 0;border-bottom:1px solid #21262d;flex-wrap:wrap; }
.target-row:last-child { border-bottom:none; }
.target-id  { color:#79c0ff;min-width:100px; }
.target-fp  { color:#6e7681;font-size:0.7rem;flex:1;min-width:0;word-break:break-all; }
.err-banner { background:#2a0000;border:1px solid #da3633;border-radius:8px;
              padding:10px 14px;color:#f85149;font-size:0.78rem;margin-bottom:12px; }
.ok-banner  { background:#001a00;border:1px solid #238636;border-radius:8px;
              padding:10px 14px;color:#3fb950;font-size:0.78rem;margin-bottom:12px; }
.path-dropdown { position:fixed;background:#161b22;border:1px solid #388bfd;border-radius:6px;
                 max-height:220px;overflow-y:auto;box-shadow:0 6px 24px rgba(0,0,0,.6);
                 z-index:9999;font-family:'SF Mono','Fira Code',monospace;
                 max-width:90vw;overflow-x:hidden; }
.path-dropdown-item { padding:5px 11px;font-size:0.72rem;color:#8b949e;cursor:pointer;
                      white-space:pre-wrap;word-break:break-all;line-height:1.4; }
.path-dropdown-item.active { background:#21262d;color:#e6edf3; }
</style>
</head><body>
<div class="header">
  <div>
    <h1>Build Protocol</h1>
    <div class="sub">Derive session context, manifest &amp; targets from a Copland term</div>
  </div>
  <a href="/" class="back-link" style="margin-left:auto;">← All protocols</a>
</div>

<div id="banner"></div>

<!-- Metadata -->
<div class="card" style="margin-bottom:14px;">
  <div class="card-title">Protocol Metadata</div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:10px;">
    <div>
      <label class="build-label">Protocol ID <span style="color:#6e7681;text-transform:none;font-size:0.65rem;">(no spaces)</span></label>
      <input class="build-input" id="meta-id" placeholder="my_protocol" spellcheck="false">
    </div>
    <div>
      <label class="build-label">Name</label>
      <input class="build-input" id="meta-name" placeholder="My Protocol">
    </div>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
    <div>
      <label class="build-label">Description</label>
      <input class="build-input" id="meta-desc" placeholder="What this protocol does">
    </div>
    <div>
      <label class="build-label">Copland Expression <span style="color:#6e7681;text-transform:none;font-size:0.65rem;">(human-readable)</span></label>
      <input class="build-input" id="meta-copland" placeholder="lseq( hashfile(f), APPR )">
    </div>
  </div>
</div>

<!-- Term JSON -->
<div class="card" style="margin-bottom:14px;">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
    <div class="card-title" style="margin-bottom:0;">Copland Term JSON</div>
    <button class="derive-btn" id="derive-btn" onclick="deriveFromTerm()">▶ Derive</button>
  </div>
  <div class="file-row">
    <input class="file-path" id="term-file" placeholder="/path/to/term.json" spellcheck="false">
    <button class="file-load-btn" id="term-load-btn"
            onclick="loadFromFile('term-file','term-json','term-load-btn','term-file-err')">↓ Load file</button>
    <span class="file-err" id="term-file-err"></span>
  </div>
  <textarea class="build-ta" id="term-json" rows="10"
            placeholder='{"TERM_CONSTRUCTOR":"lseq","TERM_BODY":[...]}' spellcheck="false"></textarea>
  <div id="derive-error" style="display:none;margin-top:8px;" class="err-banner"></div>
</div>

<!-- Flow preview -->
<div class="card" style="margin-bottom:14px;">
  <div class="card-title">Protocol Flow <span style="color:#6e7681;font-size:0.65rem;text-transform:none;">(auto-derived)</span></div>
  <div class="flow" id="flow-preview">
    <span style="color:#6e7681;font-size:0.78rem;font-style:italic;">Load a term and click Derive.</span>
  </div>
</div>

<!-- Manifest + Session Context -->
<div class="build-grid" style="margin-bottom:14px;">
  <div class="card">
    <div class="card-title">Manifest</div>
    <div class="file-row">
      <input class="file-path" id="manifest-file" placeholder="/path/to/manifest.json" spellcheck="false">
      <button class="file-load-btn" id="manifest-load-btn"
              onclick="loadFromFile('manifest-file','manifest-json','manifest-load-btn','manifest-file-err')">↓ Load file</button>
      <span class="file-err" id="manifest-file-err"></span>
    </div>
    <textarea class="build-ta" id="manifest-json" rows="8" spellcheck="false"
              placeholder='{"ASPS":[],"ASP_FS_MAP":{},"POLICY":[]}'></textarea>
  </div>
  <div class="card">
    <div class="card-title">Attestation Session</div>
    <div class="file-row">
      <input class="file-path" id="session-file" placeholder="/path/to/attestation_session.json" spellcheck="false">
      <button class="file-load-btn" id="session-load-btn"
              onclick="loadFromFile('session-file','session-json','session-load-btn','session-file-err')">↓ Load file</button>
      <span class="file-err" id="session-file-err"></span>
    </div>
    <textarea class="build-ta" id="session-json" rows="8" spellcheck="false"
              placeholder='{"Session_Plc":"P0","Plc_Mapping":{},"PubKey_Mapping":{},"Session_Context":{"ASP_Types":{},"ASP_Comps":{}}}'></textarea>
  </div>
</div>

<!-- Initial Evidence -->
<div class="card" style="margin-bottom:14px;">
  <div class="card-title">Initial Evidence</div>
  <textarea class="build-ta" id="evidence-json" rows="3" spellcheck="false"
>[{"RawEv":[]},{"EvidenceT_CONSTRUCTOR":"mt_evt"}]</textarea>
</div>

<!-- Targets preview -->
<div class="card" style="margin-bottom:20px;">
  <div class="card-title">Targets <span style="color:#6e7681;font-size:0.65rem;text-transform:none;">(auto-derived from file paths in term)</span></div>
  <div id="targets-preview">
    <span style="color:#6e7681;font-size:0.78rem;font-style:italic;">None detected yet.</span>
  </div>
</div>

<!-- Register -->
<div style="text-align:right;margin-bottom:30px;">
  <button class="register-btn" id="register-btn" onclick="registerProtocol()">⊕ Register Protocol</button>
</div>

<script>
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function renderFlow(flow) {
  if (!flow || !flow.length)
    return '<span style="color:#6e7681;font-size:0.78rem;font-style:italic;">No flow derived.</span>';
  return flow.map(node => {
    if (node.type === 'arrow') return '<span class="flow-arrow">→</span>';
    if (node.type === 'bseq') {
      const children = (node.children || []).map(c =>
        `<div class="flow-node fn-file">${escHtml(c)}</div>`).join('');
      return `<div class="flow-node fn-bseq">
        <div class="bseq-label">${escHtml(node.label)}</div>
        <div class="flow-sub">${children}</div>
      </div>`;
    }
    return `<div class="flow-node fn-${escHtml(node.style||'default')}">${escHtml(node.label)}</div>`;
  }).join('');
}

function renderTargets(targets) {
  if (!targets || !targets.length)
    return '<span style="color:#6e7681;font-size:0.78rem;font-style:italic;">No file targets detected in term.</span>';
  return targets.map(t => `
    <div class="target-row">
      <span class="target-id">${escHtml(t.id)}</span>
      <span class="target-fp" title="${escHtml(t.file)}">${escHtml(t.label)}</span>
      <span class="target-fp" style="color:#9e6a03;" title="${escHtml(t.golden)}">golden: ${escHtml(t.golden.split('/').pop())}</span>
    </div>`).join('');
}

async function loadFromFile(pathInputId, textareaId, btnId, errId) {
  const path  = document.getElementById(pathInputId).value.trim();
  const errEl = document.getElementById(errId);
  const btn   = document.getElementById(btnId);
  errEl.textContent = '';
  if (!path) { errEl.textContent = 'Enter a file path first.'; return; }
  btn.disabled = true; btn.textContent = '⟳';
  try {
    const res  = await fetch('/api/read_file?path=' + encodeURIComponent(path));
    const data = await res.json();
    if (!res.ok) { errEl.textContent = data.error || 'Read failed'; }
    else { document.getElementById(textareaId).value = data.content; }
  } catch(e) { errEl.textContent = e.message; }
  btn.disabled = false; btn.textContent = '↓ Load file';
}

// ── Path tab-completion ───────────────────────────────────────────────────────
function setupPathComplete(inputId) {
  const input = document.getElementById(inputId);
  let dropdown = null;
  let items    = [];
  let selIdx   = -1;
  let debounce = null;

  async function fetchItems(path) {
    try {
      const res = await fetch('/api/complete_path?path=' + encodeURIComponent(path));
      return (await res.json()).completions || [];
    } catch { return []; }
  }

  function reposition() {
    if (!dropdown) return;
    const r = input.getBoundingClientRect();
    dropdown.style.top      = (r.bottom + window.scrollY) + 'px';
    dropdown.style.left     = (r.left   + window.scrollX) + 'px';
    dropdown.style.minWidth = r.width + 'px';
  }

  function show(list) {
    hide();
    if (!list.length) return;
    items  = list;
    selIdx = -1;
    dropdown = document.createElement('div');
    dropdown.className = 'path-dropdown';
    // use absolute positioning anchored to document origin
    dropdown.style.position = 'absolute';
    reposition();
    list.forEach((item, i) => {
      const el = document.createElement('div');
      el.className = 'path-dropdown-item';
      el.textContent = item;
      el.addEventListener('mousemove', () => highlight(i));
      el.addEventListener('mousedown', ev => { ev.preventDefault(); select(i); });
      dropdown.appendChild(el);
    });
    document.body.appendChild(dropdown);
  }

  function hide() {
    if (dropdown) { dropdown.remove(); dropdown = null; }
    items = []; selIdx = -1;
  }

  function highlight(i) {
    if (!dropdown) return;
    selIdx = i;
    Array.from(dropdown.children).forEach((el, j) => el.classList.toggle('active', j === i));
    // scroll item into view within dropdown
    const el = dropdown.children[i];
    if (el) el.scrollIntoView({block: 'nearest'});
  }

  function select(i) {
    if (i >= 0 && i < items.length) {
      input.value = items[i];
      input.scrollLeft = input.scrollWidth;  // show end of path, not beginning
    }
    hide();
    input.focus();
  }

  // Trigger completions as the user types (debounced)
  input.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(async () => {
      const list = await fetchItems(input.value);
      // Only pop up automatically when there's more than one match, or the
      // single match differs from what's already typed (i.e. it added a /)
      if (list.length > 1 || (list.length === 1 && list[0] !== input.value))
        show(list);
      else
        hide();
    }, 180);
  });

  input.addEventListener('keydown', async e => {
    if (e.key === 'Tab') {
      e.preventDefault();
      if (dropdown && selIdx >= 0) { select(selIdx); return; }
      if (dropdown && items.length)  { select(0);      return; }
      // No dropdown yet — fetch and either fill or show
      const list = await fetchItems(input.value);
      if (list.length === 1) { input.value = list[0]; input.scrollLeft = input.scrollWidth; hide(); }
      else if (list.length > 1) { show(list); highlight(0); }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (dropdown) highlight(Math.min(selIdx + 1, items.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (dropdown) highlight(Math.max(selIdx - 1, 0));
    } else if (e.key === 'Enter') {
      if (dropdown && selIdx >= 0) { e.preventDefault(); select(selIdx); }
      // otherwise fall through to load-button Enter handler below
    } else if (e.key === 'Escape') {
      hide();
    }
  });

  // Close on blur (delay so mousedown on item fires first)
  input.addEventListener('blur', () => setTimeout(hide, 160));

  // Reposition if window scrolls or resizes while open
  window.addEventListener('scroll', reposition, true);
  window.addEventListener('resize', reposition);
}

// Wire up the three path inputs
['term-file', 'manifest-file', 'session-file'].forEach(id => setupPathComplete(id));

// Enter key in path inputs triggers the load button
const _loadBtnMap = {'term-file':'term-load-btn','manifest-file':'manifest-load-btn','session-file':'session-load-btn'};
['term-file','manifest-file','session-file'].forEach(id => {
  document.getElementById(id).addEventListener('keydown', e => {
    if (e.key === 'Enter' && !document.querySelector('.path-dropdown'))
      document.getElementById(_loadBtnMap[id]).click();
  });
});

async function deriveFromTerm() {
  const btn     = document.getElementById('derive-btn');
  const errEl   = document.getElementById('derive-error');
  const termStr = document.getElementById('term-json').value.trim();
  errEl.style.display = 'none';
  if (!termStr) { errEl.textContent = 'Load or paste a term JSON first.'; errEl.style.display = ''; return; }
  btn.textContent = '⟳ Deriving…'; btn.disabled = true;
  try {
    const res  = await fetch('/api/derive_term', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({term_json: termStr}),
    });
    const data = await res.json();
    if (!res.ok) { errEl.textContent = data.error || 'Derivation failed'; errEl.style.display = ''; }
    else {
      document.getElementById('manifest-json').value = JSON.stringify(data.manifest, null, 2);
      document.getElementById('session-json').value  = JSON.stringify(data.attestation_session, null, 2);
      document.getElementById('flow-preview').innerHTML    = renderFlow(data.flow);
      document.getElementById('targets-preview').innerHTML = renderTargets(data.targets);
    }
  } catch(e) {
    errEl.textContent = 'Error: ' + e.message; errEl.style.display = '';
  }
  btn.textContent = '▶ Derive'; btn.disabled = false;
}

// ── Edit mode: pre-populate from existing protocol spec ──────────────────────
async function maybeLoadEdit() {
  const editId = new URLSearchParams(window.location.search).get('edit');
  if (!editId) return;

  document.querySelector('h1').textContent        = 'Edit Protocol';
  document.querySelector('.sub').textContent      = 'Update the fields below and click Update Protocol';
  document.getElementById('register-btn').textContent = '✎ Update Protocol';
  document.getElementById('meta-id').readOnly     = true;
  document.getElementById('meta-id').style.opacity = '0.6';

  const banner = document.getElementById('banner');
  try {
    const res  = await fetch('/api/protocol_spec/' + encodeURIComponent(editId));
    const spec = await res.json();
    if (!res.ok) {
      banner.innerHTML = `<div class="err-banner">${escHtml(spec.error || 'Could not load protocol spec')}</div>`;
      return;
    }

    document.getElementById('meta-id').value      = spec.id          || editId;
    document.getElementById('meta-name').value    = spec.name        || '';
    document.getElementById('meta-desc').value    = spec.description || '';
    document.getElementById('meta-copland').value = spec.copland     || '';

    const term = spec.request && spec.request.TERM;
    if (term) {
      document.getElementById('term-json').value = JSON.stringify(term, null, 2);
      await deriveFromTerm();   // auto-populate flow + targets preview
    }

    // Manifest and session may have been hand-edited — use saved values directly
    if (spec.manifest)
      document.getElementById('manifest-json').value =
        JSON.stringify(spec.manifest, null, 2);

    const attest = spec.request && spec.request.ATTESTATION_SESSION;
    if (attest)
      document.getElementById('session-json').value =
        JSON.stringify(attest, null, 2);

    const evidence = spec.request && spec.request.EVIDENCE;
    if (evidence)
      document.getElementById('evidence-json').value =
        JSON.stringify(evidence, null, 2);

  } catch(e) {
    banner.innerHTML = `<div class="err-banner">Error loading spec: ${escHtml(e.message)}</div>`;
  }
}
document.addEventListener('DOMContentLoaded', maybeLoadEdit);

async function registerProtocol() {
  const banner = document.getElementById('banner');
  const btn    = document.getElementById('register-btn');
  banner.innerHTML = '';
  const id = document.getElementById('meta-id').value.trim();
  if (!id) { banner.innerHTML = '<div class="err-banner">Protocol ID is required.</div>'; return; }
  btn.disabled = true; btn.textContent = '⟳ Registering…';
  try {
    const res  = await fetch('/api/register_builder', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        id:           id,
        name:         document.getElementById('meta-name').value.trim() || id,
        description:  document.getElementById('meta-desc').value.trim(),
        copland:      document.getElementById('meta-copland').value.trim(),
        term_json:    document.getElementById('term-json').value.trim(),
        manifest_json:  document.getElementById('manifest-json').value.trim(),
        session_json:   document.getElementById('session-json').value.trim(),
        evidence_json:  document.getElementById('evidence-json').value.trim(),
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      banner.innerHTML = `<div class="err-banner">${escHtml(data.error || 'Registration failed')}</div>`;
    } else {
      banner.innerHTML = `<div class="ok-banner">✓ Protocol <strong>${escHtml(data.name)}</strong> registered. <a href="/protocol/${escHtml(data.id)}" style="color:#3fb950;">View →</a></div>`;
    }
  } catch(e) {
    banner.innerHTML = `<div class="err-banner">Error: ${escHtml(e.message)}</div>`;
  }
  btn.disabled = false; btn.textContent = '⊕ Register Protocol';
  window.scrollTo({top: 0, behavior: 'smooth'});
}
</script>
</body></html>
"""


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    with store_lock:
        snap = dict(results_store)
    protocols = list(REGISTRY.values())
    tamper_states = {pid: protocol_any_tampered(pid) for pid in REGISTRY}
    return render_template_string(HOME_TMPL, style=BASE_STYLE,
                                  protocols=protocols, results=snap,
                                  tamper_states=tamper_states)


@app.route('/protocol/<protocol_id>')
def protocol_detail(protocol_id):
    if protocol_id not in REGISTRY:
        return f"Unknown protocol: {protocol_id}", 404
    proto = REGISTRY[protocol_id]
    with store_lock:
        r = results_store.get(protocol_id)
    # If no cached result, run it now
    if r is None:
        r = run_protocol(protocol_id)
        store_result(r)
    prov = proto['golden_state']() if 'golden_state' in proto else []
    # Augment prov entries with live tamper state
    tamper_targets = proto.get('tamper_targets', {})
    for entry in prov:
        tid = entry.get('tamper_id')
        if tid and tid in tamper_targets:
            entry['tamper_state'] = tamper_targets[tid]['get_state']()
        else:
            entry['tamper_id'] = None
            entry['tamper_state'] = None
    return render_template_string(DETAIL_TMPL, style=BASE_STYLE, proto=proto, r=r, prov=prov)


@app.route('/api/run/<protocol_id>')
def api_run(protocol_id):
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    r = run_protocol(protocol_id)
    store_result(r)
    return jsonify(r)


@app.route('/api/provision/<protocol_id>')
def api_provision(protocol_id):
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    proto = REGISTRY[protocol_id]
    if 'provision' not in proto:
        return jsonify({'error': 'Protocol has no provisioning function'}), 400
    entries = proto['provision']()
    return jsonify({'protocol_id': protocol_id, 'entries': entries})


@app.route('/api/tamper/<protocol_id>/<target_id>', methods=['POST'])
def api_tamper(protocol_id, target_id):
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    tamper_targets = REGISTRY[protocol_id].get('tamper_targets', {})
    if target_id not in tamper_targets:
        return jsonify({'error': f'Unknown target: {target_id}'}), 404
    tamper_targets[target_id]['tamper']()
    return jsonify({'ok': True, 'protocol_id': protocol_id, 'target_id': target_id, 'tampered': True})


@app.route('/api/repair/<protocol_id>/<target_id>', methods=['POST'])
def api_repair(protocol_id, target_id):
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    tamper_targets = REGISTRY[protocol_id].get('tamper_targets', {})
    if target_id not in tamper_targets:
        return jsonify({'error': f'Unknown target: {target_id}'}), 404
    tamper_targets[target_id]['repair']()
    return jsonify({'ok': True, 'protocol_id': protocol_id, 'target_id': target_id})


@app.route('/api/inspect/<protocol_id>/<target_id>')
def api_inspect(protocol_id, target_id):
    import difflib
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    tamper_targets = REGISTRY[protocol_id].get('tamper_targets', {})
    if target_id not in tamper_targets or 'inspect' not in tamper_targets[target_id]:
        return jsonify({'error': f'Unknown target: {target_id}'}), 404
    data = tamper_targets[target_id]['inspect']()
    if (not data.get('compliant') and data.get('type') == 'file'
            and data.get('provisioned') is not None):
        data['diff'] = list(difflib.unified_diff(
            data['provisioned'].splitlines(keepends=True),
            data['current'].splitlines(keepends=True),
            fromfile='last provisioned',
            tofile='current',
        ))
    return jsonify(data)


@app.route('/api/reset/<protocol_id>/<target_id>', methods=['POST'])
def api_reset(protocol_id, target_id):
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    tamper_targets = REGISTRY[protocol_id].get('tamper_targets', {})
    if target_id not in tamper_targets:
        return jsonify({'error': f'Unknown target: {target_id}'}), 404
    tamper_targets[target_id]['reset']()
    return jsonify({'ok': True, 'protocol_id': protocol_id, 'target_id': target_id})


@app.route('/api/load_protocol', methods=['POST'])
def api_load_protocol():
    data = flask_request.get_json(force=True)
    path = (data or {}).get('path', '').strip()
    if not path:
        return jsonify({'error': 'Missing path'}), 400
    try:
        proto_id = protocol_loader.add_protocol_file(path)
        return jsonify({'ok': True, 'id': proto_id, 'name': REGISTRY[proto_id]['name']})
    except FileNotFoundError:
        return jsonify({'error': f'File not found: {path}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/protocols/<protocol_id>', methods=['DELETE'])
def api_remove_protocol(protocol_id):
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    if not protocol_loader.remove_protocol(protocol_id):
        return jsonify({'error': 'Cannot remove built-in protocol'}), 400
    return jsonify({'ok': True, 'id': protocol_id})


@app.route('/api/push', methods=['POST'])
def api_push():
    """Receive pushed results from the MCP run_protocol tool."""
    data = flask_request.get_json(force=True)
    if not data or 'protocol_id' not in data:
        return jsonify({'error': 'Missing protocol_id'}), 400
    store_result(data)
    return jsonify({'ok': True, 'protocol_id': data['protocol_id']})


@app.route('/api/results')
def api_results():
    with store_lock:
        snap = dict(results_store)
    return jsonify(snap)


@app.route('/build')
def build_page():
    return render_template_string(BUILD_TMPL, style=BASE_STYLE)


@app.route('/api/complete_path')
def api_complete_path():
    partial = flask_request.args.get('path', '')
    partial = os.path.expanduser(partial)
    if not partial:
        return jsonify({'completions': []})
    # Split into directory + prefix-to-match
    if partial.endswith(os.sep):
        directory, prefix = partial, ''
    else:
        directory, prefix = os.path.dirname(partial) or os.sep, os.path.basename(partial)
    try:
        entries = os.listdir(directory)
    except OSError:
        return jsonify({'completions': []})
    matches = []
    hidden  = []
    for entry in sorted(entries, key=str.lower):
        if not entry.startswith(prefix):
            continue
        full    = os.path.join(directory, entry)
        display = full + (os.sep if os.path.isdir(full) else '')
        (hidden if entry.startswith('.') else matches).append(display)
    return jsonify({'completions': (matches + hidden)[:30]})


@app.route('/api/read_file')
def api_read_file():
    path = flask_request.args.get('path', '').strip()
    if not path:
        return jsonify({'error': 'Missing path parameter'}), 400
    path = os.path.abspath(os.path.expanduser(path))
    try:
        content = open(path).read()
    except FileNotFoundError:
        return jsonify({'error': f'File not found: {path}'}), 404
    except OSError as e:
        return jsonify({'error': str(e)}), 400
    # Validate that it's parseable JSON before sending back
    try:
        json.loads(content)
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Not valid JSON: {e}'}), 400
    return jsonify({'content': content})


@app.route('/api/derive_term', methods=['POST'])
def api_derive_term():
    data = flask_request.get_json(force=True) or {}
    term_json = data.get('term_json', '').strip()
    if not term_json:
        return jsonify({'error': 'Missing term_json'}), 400
    try:
        term_dict = json.loads(term_json)
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid JSON: {e}'}), 400
    derived = protocol_builder.derive_from_term(term_dict)
    manifest = {
        'ASPS':       derived['asps'],
        'ASP_FS_MAP': {},
        'POLICY':     [],
    }
    attestation_session = {
        'Session_Plc':    'P0',
        'Plc_Mapping':    {},
        'PubKey_Mapping': {},
        'Session_Context': {
            'ASP_Types': derived['asp_types'],
            'ASP_Comps': derived['asp_comps'],
        },
    }
    return jsonify({
        'asps':                derived['asps'],
        'targets':             derived['targets'],
        'flow':                derived['flow'],
        'manifest':            manifest,
        'attestation_session': attestation_session,
    })


@app.route('/api/protocol_spec/<protocol_id>')
def api_protocol_spec(protocol_id):
    """Return the raw spec JSON for a custom protocol (used by the edit page)."""
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    entry = REGISTRY[protocol_id]
    source = entry.get('custom_source')
    if not source:
        return jsonify({'error': 'Built-in protocols cannot be edited here'}), 400
    try:
        spec = json.load(open(source))
    except FileNotFoundError:
        return jsonify({'error': f'Source file not found: {source}'}), 404
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Malformed source file: {e}'}), 400
    return jsonify(spec)


@app.route('/api/register_builder', methods=['POST'])
def api_register_builder():
    data = flask_request.get_json(force=True) or {}

    proto_id         = data.get('id', '').strip()
    name             = data.get('name', '').strip() or proto_id
    description      = data.get('description', '').strip()
    copland          = data.get('copland', '').strip()
    term_json        = data.get('term_json', '').strip()
    manifest_json    = data.get('manifest_json', '').strip()
    attestation_json = data.get('session_json', '').strip()
    evidence_json    = data.get('evidence_json', '').strip()

    if not proto_id:
        return jsonify({'error': 'Protocol ID is required'}), 400
    if not term_json:
        return jsonify({'error': 'Term JSON is required'}), 400

    try:
        term_dict = json.loads(term_json)
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid term JSON: {e}'}), 400

    try:
        manifest_obj = json.loads(manifest_json) if manifest_json else None
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid manifest JSON: {e}'}), 400

    try:
        attestation_obj = json.loads(attestation_json) if attestation_json else None
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid attestation session JSON: {e}'}), 400

    try:
        evidence_obj = json.loads(evidence_json) if evidence_json else \
                       [{"RawEv": []}, {"EvidenceT_CONSTRUCTOR": "mt_evt"}]
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid evidence JSON: {e}'}), 400

    # Always re-derive targets and flow from the term
    derived = protocol_builder.derive_from_term(term_dict)

    # Fall back to derived values if user left sections blank
    if manifest_obj is None:
        manifest_obj = {'ASPS': derived['asps'], 'ASP_FS_MAP': {}, 'POLICY': []}
    if attestation_obj is None:
        attestation_obj = {
            'Session_Plc':    'P0',
            'Plc_Mapping':    {},
            'PubKey_Mapping': {},
            'Session_Context': {
                'ASP_Types': derived['asp_types'],
                'ASP_Comps': derived['asp_comps'],
            },
        }

    if not copland:
        copland = term_json[:80] + ('…' if len(term_json) > 80 else '')

    # If overwriting an existing custom protocol, deregister the old entry first
    # so the config file doesn't accumulate stale paths.
    if proto_id in REGISTRY and REGISTRY[proto_id].get('custom_source'):
        protocol_loader.remove_protocol(proto_id)

    try:
        protocol_builder.save_and_register(
            proto_id, name, description, copland,
            term_dict, manifest_obj, attestation_obj,
            evidence_obj, derived['targets'], derived['flow'],
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({'ok': True, 'id': proto_id, 'name': name})


if __name__ == '__main__':
    app.run(port=5050, debug=False)
