"""
CVM Attestation Dashboard  —  multi-protocol with live push
"""
import json, sys, os, base64, datetime, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server as cvm_server
from protocols import REGISTRY
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

.card { background:#161b22; border:1px solid #21262d; border-radius:10px; padding:18px; margin-bottom:16px; }
.card-title { font-size:0.68rem; text-transform:uppercase; letter-spacing:.08em;
              color:#8b949e; margin-bottom:14px; }

.dot-g { width:10px;height:10px;border-radius:50%;background:#3fb950;box-shadow:0 0 6px #3fb950;display:inline-block; }
.dot-r { width:10px;height:10px;border-radius:50%;background:#f85149;box-shadow:0 0 6px #f85149;display:inline-block; }
.dot-d { width:10px;height:10px;border-radius:50%;background:#30363d;display:inline-block; }
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
.prov-row { display:flex;align-items:baseline;gap:8px;padding:4px 0;border-bottom:1px solid #2a1f00; }
.prov-row:last-child { border-bottom:none; }
.prov-label { color:#8b949e;min-width:130px;flex-shrink:0; }
.prov-file  { color:#e3b341; }
.prov-hash  { color:#6e7681;font-size:0.7rem;font-family:monospace;word-break:break-all; }
.proto-card-body { display:block;color:inherit;text-decoration:none; }
.proto-card-footer { display:flex;align-items:center;justify-content:space-between;
                     margin-top:10px; }
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
</div>

<div class="proto-grid" id="proto-grid">
{% for p in protocols %}
  {% set r = results.get(p.id) %}
  <div class="proto-card" id="card-{{ p.id }}">
    <a href="/protocol/{{ p.id }}" class="proto-card-body">
      <div class="proto-card-header">
        {% if r %}
          {% if r.all_pass %}<span class="dot-g"></span>
          {% else %}<span class="dot-r"></span>{% endif %}
        {% else %}<span class="dot-d"></span>{% endif %}
        <span class="proto-name">{{ p.name }}</span>
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
      </div>
    </div>
  </div>
{% endfor %}
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
    <div class="prov-row">
      <span class="prov-label">{{ e.target }}</span>
      <span class="prov-file">{{ e.golden }}</span>
      {% if e.sha256 %}
        <span class="prov-hash">{{ e.sha256 }}</span>
        <span style="color:#6e7681;font-size:0.7rem;margin-left:auto;white-space:nowrap;">{{ e.timestamp }}</span>
      {% else %}
        <span style="color:#8b949e;font-size:0.75rem;font-style:italic;">not provisioned</span>
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
</script>
</body></html>
"""


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    with store_lock:
        snap = dict(results_store)
    protocols = list(REGISTRY.values())
    return render_template_string(HOME_TMPL, style=BASE_STYLE,
                                  protocols=protocols, results=snap)


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


if __name__ == '__main__':
    app.run(port=5050, debug=False)
