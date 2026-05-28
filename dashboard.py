"""
CVM Attestation Dashboard  —  multi-protocol with live push
"""
import json, sys, os, base64, datetime, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server as cvm_server
from protocols import REGISTRY
import protocol_loader
import protocol_builder
import place_manager
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

def _target_label_from_args(asp_id, asp_args):
    """
    Build a human-readable (target, detail, filepath_basename) triple from an
    appraisal ASP's args so that targets sharing the same source file are
    distinguishable in the results table.

    target:  Primary label — encodes file + range/marker so each row is unique.
    detail:  Secondary sub-label shown beneath target (e.g. full marker text).
             Empty string when target is already fully descriptive.
    fp:      Basename of the measured file (used for CSS colour class).
    """
    raw_fp = (asp_args.get('filepath') or asp_args.get('filepath_golden', ''))
    fp     = raw_fp.split('/')[-1] if raw_fp else ''

    start = asp_args.get('start_index')
    end   = asp_args.get('end_index')
    bm    = asp_args.get('begin_marker')
    em    = asp_args.get('end_marker')

    if start is not None and end is not None:
        # Line-range target  →  filename.ext:305–308
        range_str = f':{start}' if start == end else f':{start}–{end}'
        target = f'{fp}{range_str}' if fp else f'lines {start}–{end}'
        detail = ''
    elif bm is not None:
        # Marker-range target  →  filename.ext [section name]
        # Strip the conventional "BEGIN " / "END " prefix to get the section name.
        section = bm[len('BEGIN '):] if bm.upper().startswith('BEGIN ') else bm
        section_short = (section[:32] + '…') if len(section) > 32 else section
        target = f'{fp} [{section_short}]' if fp else section_short
        detail = bm + (f' → {em}' if em else '')
    else:
        # Fallback: use filepath basename, or derive from asp_id
        target = fp or (asp_id[:-5] if asp_id.endswith('_appr') else asp_id)
        detail = raw_fp if raw_fp and raw_fp != fp else ''

    return target, detail, fp


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
            target, detail, fp = _target_label_from_args(asp_id, asp_args)
            results.append({'appr': asp_id, 'target': target, 'detail': detail,
                            'filepath': fp, 'verdict': v, 'msg': msg})
        results += walk_et(sub, raw_ev, idx)
    return results


def run_protocol(protocol_id, log_level='Info'):
    """Run a protocol by ID and return parsed appraisal results."""
    proto = REGISTRY[protocol_id]
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Guard: if this protocol requires golden injection, ensure it has been provisioned.
    if 'prepare' in proto and 'golden_state' in proto:
        unprovisioned = True
        try:
            gs = proto['golden_state']()
            # If golden_state is empty the protocol has no file targets to provision;
            # treat that as already-provisioned so Run is not blocked.
            unprovisioned = bool(gs) and not any(e.get('timestamp') for e in gs)
        except Exception:
            pass  # golden_state() failed — treat as unprovisioned below
        if unprovisioned:
            return {
                'protocol_id': protocol_id,
                'cvm_success': False,
                'results':     [],
                'all_pass':    False,
                'pass_count':  0,
                'fail_count':  0,
                'error':       'Not provisioned — run Provision before attesting',
                'timestamp':   ts,
            }

    # Load manifest + request from protocol_dirs/ when available; fall back to build()
    if protocol_loader.has_protocol_dir(protocol_id):
        manifest, req = protocol_loader.build_from_dir(protocol_id)
    else:
        manifest, req = proto['build']()
        req = json.loads(req) if isinstance(req, str) else req
    if 'prepare' in proto:
        req = proto['prepare'](req) or req   # inject golden_b64 from evidence bundle

    # Build plc_mapping from protocol's places config and check reachability
    places_config = proto.get('places', {})
    if places_config:
        plc_mapping = {pid: f"{cfg['host']}:{cfg['port']}" for pid, cfg in places_config.items()}
        unreachable = [
            f"{pid} ({cfg['host']}:{cfg['port']})"
            for pid, cfg in places_config.items()
            if not place_manager.is_place_reachable(cfg['host'], int(cfg['port']))
        ]
        if unreachable:
            return {
                'protocol_id': protocol_id,
                'cvm_success': False,
                'results':     [],
                'all_pass':    False,
                'pass_count':  0,
                'fail_count':  0,
                'error':       'Place(s) unreachable — start them first: ' + ', '.join(unreachable),
                'timestamp':   ts,
            }
        attest = req.get('ATTESTATION_SESSION', {})
        attest  = {**attest, 'Plc_Mapping': {**attest.get('Plc_Mapping', {}), **plc_mapping}}
        req = {**req, 'ATTESTATION_SESSION': attest}

    raw = cvm_server.run_attestation(
        manifest if isinstance(manifest, str) else json.dumps(manifest),
        json.dumps(req),
        log_level=log_level,
    )
    response = json.loads(raw) if isinstance(raw, str) else raw
    cvm_success = response.get('SUCCESS', False)
    error = None
    results = []
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # update to run time
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


def check_protocol_dir_staleness(proto_id):
    """
    For a dynamic protocol, check whether term.json is older than any source
    file it references.  Returns a dict:
      {'dynamic': bool, 'stale': bool, 'stale_files': [str]}
    'stale' is False for non-dynamic protocols.
    """
    meta = protocol_loader.get_protocol_dir_meta(proto_id)
    if not meta.get('dynamic'):
        return {'dynamic': False, 'stale': False, 'stale_files': []}

    try:
        term_path = os.path.join(protocol_loader._protocol_dir(proto_id), 'term.json')
        term_mtime = os.path.getmtime(term_path)
        term = protocol_loader._read_dir_json(proto_id, 'term.json')
    except FileNotFoundError:
        return {'dynamic': True, 'stale': True, 'stale_files': ['term.json missing']}

    # Collect all filepath values from ASP_ARGS in the term tree
    stale_files = []
    def _walk(node):
        if not isinstance(node, dict):
            return
        if node.get('TERM_CONSTRUCTOR') == 'asp':
            body = node.get('TERM_BODY', {})
            if isinstance(body, dict) and body.get('ASP_CONSTRUCTOR') == 'ASPC':
                args = body.get('ASP_BODY', {}).get('ASP_ARGS', {})
                fp = args.get('filepath', '')
                if fp and os.path.exists(fp):
                    if os.path.getmtime(fp) > term_mtime:
                        stale_files.append(fp)
        body = node.get('TERM_BODY')
        if isinstance(body, list):
            for child in body:
                _walk(child)
    _walk(term)

    return {'dynamic': True, 'stale': bool(stale_files), 'stale_files': stale_files}



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
.target-file   { color:#a5d6ff; }
.target-sig    { color:#e3b341; }
.target-hsh    { color:#d2a8ff; }
.target-detail { font-size:0.70rem;color:#6e7681;margin-top:2px;font-style:italic; }

.flow { display:flex;align-items:center;gap:0;flex-wrap:wrap; }
.flow-node { background:#21262d;border:1px solid #30363d;border-radius:6px;
             padding:7px 12px;font-size:0.78rem;color:#79c0ff;white-space:nowrap; }
.fn-bseq { border-color:#553098;background:#1a1230;color:#d2a8ff;padding:6px 10px; }
.fn-bpar { border-color:#0d6e6e;background:#0d2626;color:#56d4d4;padding:6px 10px; }
.fn-sig  { border-color:#9e6a03;background:#1a1200;color:#e3b341; }
.fn-appr { border-color:#1f6feb;background:#0d1a2e;color:#58a6ff; }
.fn-hsh  { border-color:#553098;background:#1a1230;color:#d2a8ff; }
.fn-file { border-color:#1f6feb;background:#0d1f2e;color:#a5d6ff;font-size:.72rem; }
.fn-default { border-color:#30363d;background:#21262d;color:#8b949e; }
.flow-arrow { color:#30363d;font-size:1.1rem;padding:0 6px;flex-shrink:0; }
.flow-sub { display:flex;flex-direction:column;gap:4px;padding:4px 0; }
.bseq-label { font-size:0.65rem;color:#8b949e;margin-bottom:4px; }
.clickable-asp { cursor:pointer;transition:border-color .15s,background .15s; }
.clickable-asp:hover { border-color:#58a6ff !important;background:#0d2030 !important; }
.clickable-asp.asp-selected { border-color:#58a6ff !important;background:#0d2030 !important;box-shadow:0 0 0 2px rgba(88,166,255,.25); }
.asp-edit-hint { font-size:0.65rem;opacity:0;margin-left:5px;transition:opacity .15s; }
.clickable-asp:hover .asp-edit-hint,.clickable-asp.asp-selected .asp-edit-hint { opacity:0.6; }
.arg-editor-card { background:#161b22;border:1px solid #388bfd;border-radius:8px;padding:14px;margin-bottom:14px; }
.arg-row { display:grid;grid-template-columns:170px 1fr;gap:8px;align-items:center;margin-bottom:8px; }
.arg-key { font-size:0.78rem;color:#8b949e;font-family:monospace; }
.arg-val { background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:4px;
           padding:5px 8px;font-size:0.8rem;font-family:monospace;width:100%;box-sizing:border-box; }
.arg-val:focus { outline:none;border-color:#58a6ff; }

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
.copy-btn { background:#21262d;border:1px solid #30363d;color:#8b949e;border-radius:6px;
            padding:7px 14px;font-size:0.82rem;cursor:pointer;text-decoration:none;
            white-space:nowrap;display:inline-block; }
.copy-btn:hover { border-color:#8b949e;color:#e6edf3; }
.copy-btn.copied { border-color:#3fb950;color:#3fb950; }
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
.check-btn { background:#21262d;border:1px solid #1b6e4f;color:#56d364;border-radius:6px;
             padding:5px 12px;font-size:0.75rem;font-family:inherit;cursor:pointer;
             transition:background .15s,opacity .15s;white-space:nowrap; }
.check-btn:hover:not(:disabled) { background:#1a4731;color:#3fb950; }
.check-btn:disabled { opacity:.5;cursor:not-allowed; }
.check-btn-lg { padding:7px 16px;font-size:0.82rem; }
.prov-btn { background:#21262d;border:1px solid #9e6a03;color:#e3b341;border-radius:6px;
            padding:5px 12px;font-size:0.75rem;font-family:inherit;cursor:pointer;
            transition:background .15s,opacity .15s;white-space:nowrap; }
.prov-btn:hover:not(:disabled) { background:#3a2800;color:#ffd700; }
.prov-btn:disabled { opacity:.5;cursor:not-allowed; }
.prov-btn-lg { padding:7px 16px;font-size:0.82rem; }
.prov-split { display:inline-flex;position:relative; }
.prov-split .prov-btn { border-radius:6px 0 0 6px;border-right:none; }
.prov-split .prov-btn-lg { border-radius:6px 0 0 6px; }
.prov-arrow { background:#21262d;border:1px solid #9e6a03;color:#e3b341;border-radius:0 6px 6px 0;
              padding:0 7px;font-size:0.7rem;cursor:pointer;transition:background .15s; }
.prov-arrow:hover { background:#3a2800;color:#ffd700; }
.prov-popover { display:none;position:absolute;top:calc(100% + 4px);right:0;left:auto;z-index:100;
                background:#161b22;border:1px solid #9e6a03;border-radius:6px;
                padding:8px 10px;width:max(260px,min(420px,55vw)); }
.prov-popover.open { display:flex;flex-direction:column;gap:4px; }
.prov-popover-row { display:flex;gap:6px;align-items:center; }
.prov-history { display:flex;flex-direction:column;margin-top:2px; }
.prov-hist-item { padding:3px 6px;font-size:0.72rem;color:#8b949e;cursor:pointer;border-radius:3px;
                  overflow:hidden;white-space:nowrap; }
.prov-hist-item:hover { background:#21262d;color:#e3b341; }
.prov-path-input { background:#0d1117;border:1px solid #444;color:#e6edf3;padding:4px 8px;
                   border-radius:4px;font-size:0.78rem;font-family:inherit;flex:1;min-width:0; }
.prov-path-input::placeholder { color:#555; }
.prov-result { background:#1a1200;border:1px solid #9e6a03;border-radius:8px;
               padding:14px 16px;margin-top:12px;font-size:0.78rem; }
.prov-row { display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #2a1f00;flex-wrap:wrap; }
.prov-row:last-child { border-bottom:none; }
.prov-label { color:#8b949e;min-width:130px;flex-shrink:0; }
.prov-file  { color:#e3b341; }
.prov-hash  { color:#6e7681;font-size:0.7rem;font-family:monospace;word-break:break-all;flex:1;min-width:0; }
.proto-card-body { display:block;color:inherit;text-decoration:none; }
.proto-card-footer { display:flex;align-items:center;justify-content:space-between;
                     margin-top:10px;flex-wrap:wrap;gap:6px;min-width:0; }

.badge-custom { background:#1a2340;color:#79c0ff;border:1px solid #1f4080;
                padding:2px 7px;border-radius:20px;font-size:0.65rem;font-weight:600;letter-spacing:.04em; }
.load-btn   { background:#1f4080;color:#79c0ff;border:1px solid #1f4080;border-radius:6px;
              padding:5px 14px;font-size:0.78rem;cursor:pointer;white-space:nowrap; }
.load-btn:hover { background:#2d5ba8; }
.remove-btn { background:transparent;color:#6e7681;border:1px solid #30363d;border-radius:6px;
              padding:3px 9px;font-size:0.72rem;cursor:pointer; }
.remove-btn:hover { color:#f85149;border-color:#f85149; }
.copy-btn { background:transparent;color:#6e7681;border:1px solid #30363d;border-radius:6px;
            padding:3px 9px;font-size:0.72rem;cursor:pointer; }
.copy-btn:hover { color:#58a6ff;border-color:#388bfd; }
.load-error { color:#f85149;font-size:0.75rem; }
.path-dropdown { position:fixed;background:#161b22;border:1px solid #388bfd;border-radius:6px;
                 max-height:220px;overflow-y:auto;box-shadow:0 6px 24px rgba(0,0,0,.6);
                 z-index:9999;font-family:'SF Mono','Fira Code',monospace;
                 max-width:90vw;overflow-x:hidden; }
.path-dropdown-item { padding:5px 11px;font-size:0.72rem;color:#8b949e;cursor:pointer;
                      white-space:pre-wrap;word-break:break-all;line-height:1.4; }
.path-dropdown-item.active { background:#21262d;color:#e6edf3; }
.place-row  { display:flex;align-items:center;gap:10px;padding:7px 0;
              border-bottom:1px solid #21262d;flex-wrap:wrap; }
.place-row:last-child { border-bottom:none; }
.place-id   { color:#79c0ff;font-family:'SF Mono','Fira Code',monospace;
              min-width:60px;font-size:0.82rem;font-weight:600; }
.place-addr { color:#6e7681;font-size:0.75rem;font-family:'SF Mono','Fira Code',monospace;
              min-width:140px; }
.place-start-btn { background:#001a00;border:1px solid #238636;color:#3fb950;
                   border-radius:6px;padding:3px 10px;font-size:0.72rem;cursor:pointer; }
.place-start-btn:hover { background:#0d2c0d; }
.place-stop-btn  { background:#1a0000;border:1px solid #da3633;color:#f85149;
                   border-radius:6px;padding:3px 10px;font-size:0.72rem;cursor:pointer; }
.place-stop-btn:hover  { background:#2d0000; }
.places-row { display:grid;
              grid-template-columns:80px 110px 65px 1fr 1fr auto;
              gap:6px;align-items:center;margin-bottom:6px;font-size:0.78rem; }
.places-row input { background:#0d1117;color:#e6edf3;border:1px solid #30363d;
                    border-radius:4px;padding:4px 7px;font-family:inherit;
                    font-size:0.75rem;outline:none;width:100%; }
.places-row input:focus { border-color:#388bfd; }
.dir-config-path { font-family:'SF Mono','Fira Code',monospace;font-size:0.72rem;
                   color:#6e7681;margin-bottom:10px;word-break:break-all; }
.dir-config-file { margin-bottom:8px;border:1px solid #21262d;border-radius:6px;
                   background:#0d1117;overflow:hidden; }
.dir-config-file > summary { list-style:none;cursor:pointer;padding:7px 12px;
                             font-family:'SF Mono','Fira Code',monospace;font-size:0.78rem;
                             color:#79c0ff;display:flex;align-items:center;gap:8px;
                             user-select:none;transition:background .15s; }
.dir-config-file > summary::-webkit-details-marker { display:none; }
.dir-config-file > summary:hover { background:#161b22; }
.dir-config-file > summary::before { content:'▸';color:#6e7681;font-size:0.7rem;
                                     transition:transform .15s;display:inline-block; }
.dir-config-file[open] > summary::before { transform:rotate(90deg); }
.dir-config-pre { margin:0;padding:10px 14px;border-top:1px solid #21262d;
                  background:#010409;color:#c9d1d9;font-family:'SF Mono','Fira Code',monospace;
                  font-size:0.72rem;line-height:1.45;max-height:420px;overflow:auto;
                  white-space:pre;word-break:normal; }
"""

BASE_JS = """
// ── Shared utilities ──────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Path tab-completion (shared across pages) ────────────────────────────────
function setupPathComplete(inputId, onEnter) {
  const input = document.getElementById(inputId);
  if (!input) return;
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
    const el = dropdown.children[i];
    if (el) el.scrollIntoView({block: 'nearest'});
  }

  function select(i) {
    if (i >= 0 && i < items.length) {
      input.value = items[i];
      input.scrollLeft = input.scrollWidth;
    }
    hide();
    input.focus();
  }

  input.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(async () => {
      const list = await fetchItems(input.value);
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
      if (dropdown && selIdx >= 0) { e.preventDefault(); select(selIdx); return; }
      if (!document.querySelector('.path-dropdown') && onEnter) onEnter();
    } else if (e.key === 'Escape') {
      hide();
    }
  });

  input.addEventListener('blur', () => setTimeout(hide, 160));
  window.addEventListener('scroll', reposition, true);
  window.addEventListener('resize', reposition);
}
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
        {% endif %}
      </div>
      <div class="proto-desc">{{ p.description }}</div>
      <div class="proto-copland">{{ p.copland }}</div>
      {% if p.places %}
      <div style="display:flex;align-items:center;gap:5px;margin-top:5px;">
        <span style="font-size:0.63rem;color:#6e7681;letter-spacing:.04em;text-transform:uppercase;">places</span>
        <span id="place-strip-{{ p.id }}" style="display:flex;gap:3px;align-items:center;">
          {% for pid in p.places %}<span class="dot-d" style="width:8px;height:8px;" title="{{ pid }}"></span>{% endfor %}
        </span>
      </div>
      {% endif %}
    </a>
    <div class="proto-card-footer">
      <div class="proto-stats" id="stats-{{ p.id }}" style="min-width:0;">
        {% if r %}
          <span class="ps-pass">✓ {{ r.pass_count }} passed</span>
          {% if r.fail_count > 0 %}<span class="ps-fail">✗ {{ r.fail_count }} failed</span>{% endif %}
          <span class="ps-idle" style="margin-left:auto;">{{ r.timestamp[11:] }}</span>
        {% else %}
          <span class="ps-idle">Not yet run</span>
        {% endif %}
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;">
        {% if p.provision %}
        <div class="prov-split">
          <button class="prov-btn" id="provbtn-{{ p.id }}"
                  onclick="provisionWithPath('{{ p.id }}')">⚙ Provision</button>
          <button class="prov-arrow" onclick="toggleProvPopover('{{ p.id }}', event)" title="Custom evidence path">▾</button>
          <div class="prov-popover" id="prov-popover-{{ p.id }}">
            <div class="prov-popover-row">
              <input type="text" class="prov-path-input" id="prov-path-{{ p.id }}"
                     placeholder="Custom evidence path…" autocomplete="off">
              <button class="prov-btn" onclick="provisionWithPath('{{ p.id }}')">Provision</button>
            </div>
            <div class="prov-history" id="prov-history-{{ p.id }}"></div>
          </div>
        </div>
        {% endif %}
        <button class="run-btn" id="runbtn-{{ p.id }}"
                onclick="runProtocol('{{ p.id }}')">▶ Run</button>
        {% if p.steps %}
        <button class="check-btn" id="checkbtn-{{ p.id }}"
                onclick="checkProtocol('{{ p.id }}')">⚡ Check</button>
        {% endif %}
        {% if p.places %}
          {% set all_sim = namespace(v=true) %}
          {% for cfg in p.places.values() %}{% if not cfg.manifest or not cfg.asp_bin %}{% set all_sim.v = false %}{% endif %}{% endfor %}
          {% if all_sim.v %}
          <button class="run-btn" style="border-color:#238636;color:#3fb950;padding:3px 9px;font-size:0.72rem;"
                  id="startallbtn-{{ p.id }}"
                  onclick="startAllPlaces('{{ p.id }}', event)">▶ Places</button>
          {% endif %}
        {% endif %}
        <button class="copy-btn"
                onclick="location.href='/build?copy={{ p.id }}'">⎘ Copy</button>
        {% if p.custom_source %}
          <button class="remove-btn" id="rmbtn-{{ p.id }}"
                  onclick="removeProtocol('{{ p.id }}')">× Remove</button>
        {% endif %}
      </div>
    </div>
  </div>
{% endfor %}
</div>

<!-- Import Protocol Directory panel -->
<div style="max-width:820px;margin:28px auto 0;padding:0 16px;">
  <details id="import-dir-section">
    <summary style="cursor:pointer;font-size:0.85rem;color:#8b949e;user-select:none;padding:6px 0;">
      ▸ Import protocol directory
    </summary>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-top:8px;">
      <div style="font-size:0.82rem;color:#8b949e;margin-bottom:10px;">
        Enter the path to a protocol directory (e.g. from rust-am-clients) that contains
        <code style="color:#c9d1d9;">meta.json</code>, <code style="color:#c9d1d9;">term.json</code>,
        <code style="color:#c9d1d9;">session.json</code>, and <code style="color:#c9d1d9;">manifest.json</code>.
      </div>
      <div style="display:flex;gap:8px;align-items:flex-start;">
        <input type="text" id="import-dir-path" placeholder="/path/to/protocol_dirs/my_protocol"
               style="flex:1;background:#0d1117;border:1px solid #30363d;border-radius:6px;
                      color:#c9d1d9;padding:7px 10px;font-size:0.82rem;font-family:monospace;"
               oninput="clearImportPreview()" />
        <button onclick="previewImportDir()"
                style="background:#21262d;border:1px solid #30363d;color:#c9d1d9;
                       padding:7px 14px;border-radius:6px;cursor:pointer;font-size:0.82rem;
                       white-space:nowrap;">
          Preview
        </button>
        <button id="import-dir-btn" onclick="confirmImportDir()" disabled
                style="background:#238636;border:1px solid #2ea043;color:#fff;
                       padding:7px 14px;border-radius:6px;cursor:pointer;font-size:0.82rem;
                       white-space:nowrap;opacity:0.5;">
          Import
        </button>
      </div>
      <div id="import-preview" style="margin-top:12px;"></div>
    </div>
  </details>
</div>

<script>
// After triggering a run/check, poll rapidly until the result lands,
// then let the normal 3-second loop take over.
function _startEagerPoll(id) {
  let attempts = 0;
  const MAX = 40;           // give up after 40 × 250ms = 10 s
  const INTERVAL = 250;     // ms between eager polls
  const timer = setInterval(async () => {
    attempts++;
    await poll();
    // Stop eager polling once this protocol is no longer running,
    // or after the safety limit.
    try {
      const res  = await fetch('/api/results');
      const data = await res.json();
      const r    = data[id];
      if (!r || !r.running || attempts >= MAX) clearInterval(timer);
    } catch(e) { clearInterval(timer); }
  }, INTERVAL);
}

async function runProtocol(id) {
  const btn      = document.getElementById('runbtn-' + id);
  const checkBtn = document.getElementById('checkbtn-' + id);
  if (btn)      { btn.disabled = true; btn.textContent = '⟳ Running…'; }
  if (checkBtn) { checkBtn.disabled = true; }
  try {
    await fetch('/api/run/' + id);
    _startEagerPoll(id);
  } catch(e) {
    if (btn)      { btn.disabled = false; btn.textContent = '▶ Run'; }
    if (checkBtn) { checkBtn.disabled = false; checkBtn.textContent = '⚡ Check'; }
  }
}

async function checkProtocol(id) {
  const btn      = document.getElementById('runbtn-' + id);
  const checkBtn = document.getElementById('checkbtn-' + id);
  if (checkBtn) { checkBtn.disabled = true; checkBtn.textContent = '⟳ Checking…'; }
  if (btn)      { btn.disabled = true; }
  try {
    await fetch('/api/check/' + id);
    _startEagerPoll(id);
  } catch(e) {
    if (checkBtn) { checkBtn.disabled = false; checkBtn.textContent = '⚡ Check'; }
    if (btn)      { btn.disabled = false; btn.textContent = '▶ Run'; }
  }
}

async function toggleProvPopover(id, ev) {
  ev.stopPropagation();
  const pop = document.getElementById('prov-popover-' + id);
  if (!pop) return;
  const opening = !pop.classList.contains('open');
  document.querySelectorAll('.prov-popover.open').forEach(p => p.classList.remove('open'));
  if (opening) {
    pop.classList.add('open');
    const inp  = document.getElementById('prov-path-' + id);
    const hist = document.getElementById('prov-history-' + id);
    try {
      const d        = await (await fetch('/api/provision_history/' + id)).json();
      const current  = d.current_path || (d.paths && d.paths[0]) || '';
      const allPaths = d.paths || [];
      if (inp) { inp.value = current; inp.scrollLeft = inp.scrollWidth; }
      if (hist) {
        hist.innerHTML = '';
        allPaths.filter(p => p !== current).forEach(p => {
          const el = document.createElement('div');
          el.className = 'prov-hist-item';
          // Trim to a slash boundary so the filename is always visible
          const max = 48;
          if (p.length > max) {
            const cut   = p.length - max;
            const slash = p.indexOf('/', cut);
            el.textContent = '\u2026' + (slash >= 0 ? p.slice(slash) : p.slice(cut));
          } else {
            el.textContent = p;
          }
          el.title = p;
          el.addEventListener('click', ev => {
            ev.stopPropagation();
            if (inp) { inp.value = p; inp.scrollLeft = inp.scrollWidth; inp.focus(); }
          });
          hist.appendChild(el);
        });
      }
    } catch(e) {}
    if (inp) inp.focus();
  }
}
document.addEventListener('click', () => {
  document.querySelectorAll('.prov-popover.open').forEach(p => p.classList.remove('open'));
});

async function provisionWithPath(id) {
  const inp = document.getElementById('prov-path-' + id);
  const customPath = inp ? inp.value.trim() : '';
  const pop = document.getElementById('prov-popover-' + id);
  if (pop) pop.classList.remove('open');
  await provisionProtocol(id, customPath || null);
}

async function provisionProtocol(id, customPath) {
  const btn = document.getElementById('provbtn-' + id);
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Provisioning…'; }
  const url = '/api/provision/' + id +
    (customPath ? '?golden_path=' + encodeURIComponent(customPath) : '');
  try {
    const res = await fetch(url);
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      alert(data.error || 'Provision failed');
      if (btn) { btn.disabled = false; btn.textContent = '⚙ Provision'; }
      return;
    }
    location.reload();
  } catch(e) {
    if (btn) { btn.disabled = false; btn.textContent = '⚙ Provision'; }
  }
}

async function removeProtocol(id) {
  const btn = document.getElementById('rmbtn-' + id);
  if (btn) { btn.disabled = true; btn.textContent = '⟳'; }
  let files = [];
  try {
    const fr = await fetch('/api/protocols/' + id + '/files');
    if (fr.ok) { const fd = await fr.json(); files = fd.files || []; }
  } catch(e) {}

  // Build modal
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:9999;display:flex;align-items:center;justify-content:center;';
  const box = document.createElement('div');
  box.style.cssText = 'background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px 28px;max-width:560px;width:90%;color:#e6edf3;font-family:inherit;';
  const title = document.createElement('div');
  title.style.cssText = 'font-size:1rem;font-weight:600;margin-bottom:12px;color:#f85149;';
  title.textContent = 'Remove protocol: ' + id;
  box.appendChild(title);
  if (files.length > 0) {
    const sub = document.createElement('div');
    sub.style.cssText = 'font-size:0.82rem;color:#8b949e;margin-bottom:8px;';
    sub.textContent = 'The following files will be permanently deleted:';
    box.appendChild(sub);
    const ul = document.createElement('ul');
    ul.style.cssText = 'margin:0 0 16px 0;padding:0 0 0 16px;list-style:disc;font-size:0.76rem;color:#c9d1d9;max-height:220px;overflow-y:auto;';
    files.forEach(f => {
      const li = document.createElement('li');
      li.style.cssText = 'word-break:break-all;padding:2px 0;font-family:monospace;';
      li.textContent = f;
      ul.appendChild(li);
    });
    box.appendChild(ul);
  } else {
    const sub = document.createElement('div');
    sub.style.cssText = 'font-size:0.82rem;color:#8b949e;margin-bottom:16px;';
    sub.textContent = 'This will remove the protocol from the registry (no extra files to delete).';
    box.appendChild(sub);
  }
  const btns = document.createElement('div');
  btns.style.cssText = 'display:flex;gap:10px;justify-content:flex-end;';
  const cancelBtn = document.createElement('button');
  cancelBtn.textContent = 'Cancel';
  cancelBtn.style.cssText = 'background:transparent;color:#8b949e;border:1px solid #30363d;border-radius:6px;padding:6px 16px;cursor:pointer;font-size:0.85rem;';
  const confirmBtn = document.createElement('button');
  confirmBtn.textContent = files.length > 0 ? 'Delete Files & Remove' : 'Remove';
  confirmBtn.style.cssText = 'background:#b62324;color:#fff;border:none;border-radius:6px;padding:6px 16px;cursor:pointer;font-size:0.85rem;';
  btns.appendChild(cancelBtn); btns.appendChild(confirmBtn);
  box.appendChild(btns);
  overlay.appendChild(box);
  document.body.appendChild(overlay);

  cancelBtn.onclick = () => {
    document.body.removeChild(overlay);
    if (btn) { btn.disabled = false; btn.textContent = '× Remove'; }
  };
  confirmBtn.onclick = async () => {
    confirmBtn.disabled = true; confirmBtn.textContent = '⟳';
    try {
      const cleanup = files.length > 0 ? '?cleanup=true' : '';
      const res = await fetch('/api/protocols/' + id + cleanup, {method: 'DELETE'});
      if (res.ok) { document.body.removeChild(overlay); location.reload(); return; }
      const data = await res.json();
      alert(data.error || 'Remove failed');
    } catch(e) { alert('Error: ' + e.message); }
    document.body.removeChild(overlay);
    if (btn) { btn.disabled = false; btn.textContent = '× Remove'; }
  };
}

// Poll for live updates (from MCP pushes or background runs) every 3 seconds
async function poll() {
  try {
    const res = await fetch('/api/results');
    const data = await res.json();
    Object.entries(data).forEach(([id, r]) => {
      const card  = document.getElementById('card-' + id);
      const btn   = document.getElementById('runbtn-' + id);
      if (!card) return;

      const checkBtn = document.getElementById('checkbtn-' + id);
      if (r.running) {
        // Protocol is in-flight — amber dot, disable both buttons
        const dot = card.querySelector('.dot-g, .dot-r, .dot-d, .dot-o');
        if (dot) dot.className = 'dot-o';
        const done  = (r.results || []).length;
        const total = r.total_steps || 0;
        const isCheck = r.operation === 'check';
        const activeTxt = (total > 0 && done > 0)
          ? `⟳ ${done}/${total}…` : '⟳ Running…';
        if (btn)      { btn.disabled = true;
                        btn.textContent = (!isCheck && total > 0 && done > 0) ? activeTxt : (isCheck ? '▶ Run' : '⟳ Running…'); }
        if (checkBtn) { checkBtn.disabled = true;
                        checkBtn.textContent = isCheck ? activeTxt : '⚡ Check'; }
        // Live progress in the mini stats strip
        const stats = document.getElementById('stats-' + id);
        if (stats && total > 0) {
          const passCount = (r.results || []).filter(x => x.verdict === 'PASS').length;
          const failCount = done - passCount;
          const failPart  = failCount > 0 ? `<span class="ps-fail">✗ ${failCount} failed</span>` : '';
          stats.innerHTML = `<span class="ps-pass">✓ ${passCount} passed</span>${failPart}`
            + `<span class="ps-idle" style="margin-left:auto;color:#e3b341;">${done}/${total} complete…</span>`;
        }
        return;
      }

      // Run/check complete — update dot, stats, re-enable both buttons
      const dot = card.querySelector('.dot-g, .dot-r, .dot-d, .dot-o');
      if (dot) dot.className = r.all_pass ? 'dot-g' : 'dot-r';
      const stats = document.getElementById('stats-' + id);
      if (stats && r.timestamp) {
        const tag      = r.result_type === 'check' ? ' ⚡' : '';
        const failPart = r.fail_count > 0 ? `<span class="ps-fail">✗ ${r.fail_count} failed</span>` : '';
        stats.innerHTML = `<span class="ps-pass">✓ ${r.pass_count} passed</span>${failPart}`
          + `<span class="ps-idle" style="margin-left:auto;">${r.timestamp.slice(11)}${tag}</span>`;
      }
      if (btn)      { btn.disabled = false; btn.textContent = '▶ Run'; }
      if (checkBtn) { checkBtn.disabled = false; checkBtn.textContent = '⚡ Check'; }
    });
  } catch(e) {}
}
setInterval(poll, 3000);

const PROTO_IDS_WITH_PLACES = [{% for p in protocols %}{% if p.places %}'{{ p.id }}',{% endif %}{% endfor %}];
async function pollPlaces() {
  for (const id of PROTO_IDS_WITH_PLACES) {
    try {
      const res  = await fetch('/api/protocols/' + id + '/places');
      const data = await res.json();
      const strip = document.getElementById('place-strip-' + id);
      if (!strip) continue;
      strip.innerHTML = Object.entries(data.places || {}).map(([pid, info]) =>
        `<span class="${info.reachable ? 'dot-g' : 'dot-r'}"
               style="width:8px;height:8px;"
               title="${escHtml(pid + ': ' + (info.reachable ? 'reachable' : 'unreachable'))}"></span>`
      ).join('');
    } catch(e) {}
  }
}
async function startAllPlaces(protoId, ev) {
  ev.stopPropagation();
  const btn = document.getElementById('startallbtn-' + protoId);
  if (btn) { btn.disabled = true; btn.textContent = '⟳'; }
  try {
    const res  = await fetch('/api/protocols/' + protoId + '/places');
    const data = await res.json();
    await Promise.all(Object.keys(data.places || {}).map(pid =>
      fetch('/api/protocols/' + protoId + '/places/' + encodeURIComponent(pid) + '/start', {method:'POST'})
    ));
    await pollPlaces();
  } catch(e) {}
  if (btn) { btn.disabled = false; btn.textContent = '▶ Places'; }
}
if (PROTO_IDS_WITH_PLACES.length) { pollPlaces(); setInterval(pollPlaces, 3000); }

// ── Import Protocol Directory ─────────────────────────────────────────────────
let _importPreviewOk = false;

function clearImportPreview() {
  document.getElementById('import-preview').innerHTML = '';
  const btn = document.getElementById('import-dir-btn');
  btn.disabled = true; btn.style.opacity = '0.5';
  _importPreviewOk = false;
}

async function previewImportDir() {
  const path = document.getElementById('import-dir-path').value.trim();
  if (!path) return;
  const preview = document.getElementById('import-preview');
  preview.innerHTML = '<span style="color:#8b949e;font-size:0.82rem;">Loading…</span>';
  _importPreviewOk = false;
  const btn = document.getElementById('import-dir-btn');
  btn.disabled = true; btn.style.opacity = '0.5';
  try {
    const res  = await fetch('/api/preview_protocol_dir?path=' + encodeURIComponent(path));
    const data = await res.json();
    if (data.error) {
      preview.innerHTML = `<div class="err-banner" style="margin:0;">${escHtml(data.error)}</div>`;
      return;
    }
    const targets = Object.entries(data.inferred_targets || {});
    const stubs   = data.stubs_needed || [];
    const warns   = data.warnings    || [];
    let html = `
      <div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;font-size:0.82rem;">
        <div style="display:flex;gap:16px;margin-bottom:8px;">
          <div><span style="color:#8b949e;">ID</span> <strong style="color:#c9d1d9;">${escHtml(data.proto_id)}</strong></div>
          <div><span style="color:#8b949e;">Name</span> <strong style="color:#c9d1d9;">${escHtml(data.name || '')}</strong></div>
        </div>`;
    if (data.description) {
      html += `<div style="color:#8b949e;margin-bottom:6px;">${escHtml(data.description)}</div>`;
    }
    if (data.copland) {
      html += `<div style="font-family:monospace;color:#79c0ff;font-size:0.78rem;margin-bottom:8px;">${escHtml(data.copland)}</div>`;
    }
    if (targets.length) {
      html += `<div style="color:#8b949e;font-size:0.75rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px;">Measurement targets (${targets.length})</div>
               <ul style="margin:0 0 8px 18px;padding:0;color:#c9d1d9;">`;
      for (const [tid, cfg] of targets) {
        const isStub = stubs.includes(cfg.target_file);
        html += `<li>${escHtml(cfg.label || tid)}
                   <code style="font-size:0.75rem;color:${isStub ? '#f0883e' : '#3fb950'};">
                     ${escHtml(cfg.target_file || '')}${isStub ? ' ⚠ stub' : ' ✓'}
                   </code></li>`;
      }
      html += '</ul>';
    }
    for (const w of warns) {
      const isInfo = w.includes('meta.json not found');
      const color  = isInfo ? '#8b949e' : '#f0883e';
      const icon   = isInfo ? 'ℹ' : '⚠';
      html += `<div style="color:${color};margin-top:4px;">${icon} ${escHtml(w)}</div>`;
    }
    html += `<div style="color:#8b949e;margin-top:8px;font-size:0.78rem;">
               Files found: ${escHtml(data.files_found.join(', '))}
             </div></div>`;
    preview.innerHTML = html;
    const hasBlocker = warns.some(w => w.includes('built-in'));
    if (!hasBlocker) {
      _importPreviewOk = true;
      btn.disabled = false; btn.style.opacity = '1';
    }
  } catch(e) {
    preview.innerHTML = `<div class="err-banner" style="margin:0;">${escHtml(String(e))}</div>`;
  }
}

async function confirmImportDir() {
  if (!_importPreviewOk) return;
  const path = document.getElementById('import-dir-path').value.trim();
  const btn  = document.getElementById('import-dir-btn');
  btn.disabled = true; btn.textContent = '⟳ Importing…';
  try {
    const res  = await fetch('/api/import_protocol_dir', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({source_path: path}),
    });
    const data = await res.json();
    if (data.error) {
      document.getElementById('import-preview').innerHTML +=
        `<div class="err-banner" style="margin-top:8px;">${escHtml(data.error)}</div>`;
      btn.disabled = false; btn.textContent = 'Import'; btn.style.opacity = '1';
      return;
    }
    // Success — reload page to show new card
    window.location.reload();
  } catch(e) {
    document.getElementById('import-preview').innerHTML +=
      `<div class="err-banner" style="margin-top:8px;">${escHtml(String(e))}</div>`;
    btn.disabled = false; btn.textContent = 'Import'; btn.style.opacity = '1';
  }
}

{{ base_js | safe }}
{% for p in protocols %}
setupPathComplete('prov-path-{{ p.id }}', () => provisionWithPath('{{ p.id }}'));
fetch('/api/provision_history/{{ p.id }}').then(r => r.json()).then(d => {
  const fill = d.current_path || (d.paths && d.paths[0]) || '';
  if (fill) {
    const inp = document.getElementById('prov-path-{{ p.id }}');
    if (inp && !inp.value) { inp.value = fill; inp.scrollLeft = inp.scrollWidth; }
  }
}).catch(() => {});
{% endfor %}
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
    {% if staleness.dynamic %}
    <button class="prov-btn prov-btn-lg" id="refresh-cfg-btn"
            onclick="refreshProtocolConfig('{{ proto.id }}')"
            title="Re-run generator to capture latest source file line numbers">↻ Refresh Config</button>
    {% endif %}
    {% if proto.provision %}
    <div class="prov-split">
      <button class="prov-btn prov-btn-lg" id="provbtn-{{ proto.id }}"
              onclick="provisionWithPath('{{ proto.id }}')">⚙ Provision</button>
      <button class="prov-arrow" style="padding:0 9px;font-size:0.75rem;"
              onclick="toggleProvPopover('{{ proto.id }}', event)" title="Custom evidence path">▾</button>
      <div class="prov-popover" id="prov-popover-{{ proto.id }}">
        <div class="prov-popover-row">
          <input type="text" class="prov-path-input" id="prov-path-{{ proto.id }}"
                 placeholder="Custom evidence path…" autocomplete="off">
          <button class="prov-btn" onclick="provisionWithPath('{{ proto.id }}')">Provision</button>
        </div>
        <div class="prov-history" id="prov-history-{{ proto.id }}"></div>
      </div>
    </div>
    {% endif %}
    <button class="run-btn run-btn-lg" id="run-btn-detail"
            onclick="runProtocol('{{ proto.id }}')">▶ Run</button>
    {% if proto.steps %}
    <button class="check-btn check-btn-lg" id="check-btn-detail"
            onclick="checkProtocol('{{ proto.id }}')">⚡ Check</button>
    {% endif %}
    {% if proto.id in proto_dir_ids %}
    <button class="copy-btn" id="summary-copy-btn-{{ proto.id }}"
            onclick="copySummary('{{ proto.id }}')" title="Copy Markdown summary to clipboard">⎘ Markdown</button>
    <a class="copy-btn" id="summary-dl-btn-{{ proto.id }}"
       href="/api/run_summary/{{ proto.id }}"
       download="{{ proto.id }}_summary.md"
       title="Download Markdown summary">↓ .md</a>
    {% endif %}
    <a href="/" class="back-link" style="margin-left:4px;">← All protocols</a>
  </div>
</div>

{% if staleness.stale %}
<div id="stale-banner" style="background:#3a1f00;border:1px solid #9e6a03;border-radius:8px;padding:10px 16px;margin-bottom:12px;display:flex;align-items:center;gap:12px;">
  <span style="font-size:1.1rem;">⚠️</span>
  <span style="color:#e3b341;font-size:0.85rem;">
    <strong>Term config may be stale.</strong>
    Source file(s) have changed since <code>term.json</code> was last generated.
    Click <strong>↻ Refresh Config</strong> to regenerate before provisioning or running.
  </span>
  <button onclick="document.getElementById('stale-banner').style.display='none'"
          style="margin-left:auto;background:none;border:none;color:#8b949e;cursor:pointer;font-size:1rem;">✕</button>
</div>
{% endif %}

{% if proto.imported_dir %}
<div id="import-info-banner" style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:10px 16px;margin-bottom:12px;font-size:0.82rem;color:#8b949e;">
  <span style="color:#58a6ff;">⊕ Imported protocol</span>
  — source: <code style="color:#c9d1d9;">{{ proto.custom_source }}</code>
  <span id="stub-warning-area"></span>
</div>
{% endif %}

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
      {% elif node.type == 'bpar' %}
        <div class="flow-node fn-bpar">
          <div class="bseq-label">{{ node.label }}</div>
          <div class="flow-sub">
            {% for child in node.children %}
              <div class="flow-node fn-file">{{ child }}</div>
            {% endfor %}
          </div>
        </div>
      {% elif node.type == 'att' %}
        <div class="flow-node fn-default" style="border-color:#553098;color:#d2a8ff;"
             title="Remote attestation at {{ node.place }}">{{ node.label }}</div>
      {% else %}
        <div class="flow-node fn-{{ node.style }}">{{ node.label }}</div>
      {% endif %}
    {% endfor %}
  </div>
</div>

{% if dir_files %}
<div class="card">
  <div class="card-title">Protocol Directory Configuration</div>
  {% if proto.imported_dir %}
  <div class="dir-config-path">{{ proto.imported_dir }}</div>
  {% endif %}
  {% for fn, raw in dir_files %}
  <details class="dir-config-file">
    <summary>{{ fn }}</summary>
    <pre class="dir-config-pre">{{ raw }}</pre>
  </details>
  {% endfor %}
</div>
{% endif %}

<div class="card" style="border-color:#9e6a03;">
  <div class="card-title" style="color:#e3b341;">Golden Evidence — Last Provisioned</div>
  {% if prov %}
  <div>
    {% for e in prov %}
    <div>
      <div class="prov-row" id="prov-row-{{ loop.index }}">
        <span class="prov-label">{{ e.target }}</span>
        {% if e.timestamp %}
        <span class="prov-file" title="{{ e.golden_path or e.golden }}">{{ e.golden }}</span>
        {% endif %}
        {% if e.timestamp %}
          <span style="color:#6e7681;font-size:0.7rem;white-space:nowrap;">{{ e.timestamp }}</span>
        {% else %}
          <span style="color:#8b949e;font-size:0.75rem;font-style:italic;">not provisioned</span>
        {% endif %}
      </div>
    </div>
    {% endfor %}
  </div>
  {% else %}
  {% if 'provision' in proto %}
  <div style="color:#8b949e;font-size:0.78rem;font-style:italic;">No per-file targets defined — click <strong style="color:#e3b341;">⚙ Provision</strong> to capture the golden evidence bundle.</div>
  {% else %}
  <div style="color:#8b949e;font-size:0.78rem;font-style:italic;">No golden evidence configured for this protocol.</div>
  {% endif %}
  {% endif %}
</div>

{% if proto.places %}
<div class="card" style="border-color:#553098;">
  <div class="card-title" style="color:#d2a8ff;">Remote Places</div>
  <div id="places-panel">
    {% for pid, cfg in proto.places.items() %}
    <div class="place-row" id="place-row-{{ pid }}">
      <span class="place-id">{{ pid }}</span>
      <span class="place-addr">{{ cfg.host }}:{{ cfg.port }}</span>
      <span class="dot-d" id="place-dot-{{ pid }}" title="Checking…" style="flex-shrink:0;"></span>
      <span id="place-pid-{{ pid }}" style="color:#6e7681;font-size:0.7rem;font-family:monospace;"></span>
      <div class="place-btns" style="display:flex;gap:6px;margin-left:auto;">
        {% if cfg.manifest and cfg.asp_bin %}
        <button class="place-start-btn" id="place-start-{{ pid }}"
                onclick="startPlace('{{ proto.id }}', '{{ pid }}')">▶ Start</button>
        <button class="place-stop-btn" id="place-stop-{{ pid }}"
                onclick="stopPlace('{{ proto.id }}', '{{ pid }}')">■ Stop</button>
        {% else %}
        <span style="color:#6e7681;font-size:0.7rem;font-style:italic;">external</span>
        {% endif %}
      </div>
    </div>
    {% endfor %}
  </div>
</div>
{% endif %}

{% if not r %}
  <div class="card" style="border-color:#21262d;">
    <div class="card-title" style="color:#8b949e;">Appraisal Results</div>
    {% if not provisioned %}
    <div style="color:#8b949e;font-size:.82rem;">Run <strong style="color:#e3b341;">⚙ Provision</strong> to establish a golden baseline, then click <strong style="color:#3fb950;">▶ Run</strong> to attest.</div>
    {% else %}
    <div style="color:#8b949e;font-size:.82rem;">Click <strong style="color:#3fb950;">▶ Run</strong> to attest this protocol.</div>
    {% endif %}
  </div>
{% elif r %}
  {% if r.error %}
    {% if 'Not provisioned' in r.error %}
    <div class="card" style="border-color:#9e6a03;">
      <div class="card-title" style="color:#d29922;">Not Provisioned</div>
      <div style="color:#d29922;font-size:.82rem;">Run <strong>⚙ Provision</strong> to establish a golden baseline, then click <strong>▶ Run</strong> to attest.</div>
    </div>
    {% else %}
    <div class="card" style="border-color:#da3633;">
      <div class="card-title" style="color:#f85149;">Error</div>
      <div style="color:#f85149;font-size:.82rem;">{{ r.error }}</div>
    </div>
    {% endif %}
  {% else %}
  <div class="card">
    <div class="card-title">Appraisal Results
      {% if r.result_type == 'check' %}
        <span style="margin-left:8px;font-size:0.68rem;background:#1a4731;color:#56d364;
                     border:1px solid #1b6e4f;padding:2px 8px;border-radius:20px;">⚡ checked</span>
      {% else %}
        <span style="margin-left:8px;font-size:0.68rem;background:#0d1a2e;color:#58a6ff;
                     border:1px solid #1f6feb;padding:2px 8px;border-radius:20px;">🔒 attested</span>
      {% endif %}
    </div>
    <table>
      <colgroup><col style="width:20%"><col style="width:42%"><col style="width:18%"><col style="width:20%"></colgroup>
      <thead><tr><th>Appraiser</th><th>Target</th><th>Verdict</th><th>Appraised At</th></tr></thead>
      <tbody>
        {% for row in r.results %}
        <tr>
          <td><span class="asp-pill asp-{{ row.appr }}">{{ row.appr }}</span></td>
          <td>
            {% if row.filepath %}
              <span class="target-file">{{ row.target }}</span>
              {% if row.detail %}<div class="target-detail">{{ row.detail }}</div>{% endif %}
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

function _renderProgressTable(r) {
  const done  = (r.results || []).length;
  const total = r.total_steps || done;
  const step  = r.current_step ? ` — running: <em>${escHtml(r.current_step)}</em>` : '';
  const rows  = (r.results || []).map(row => {
    const v   = row.verdict === 'PASS';
    const dot = v ? 'dot-g' : 'dot-r';
    const cls = v ? 'vpass' : 'vfail';
    const targetCls = row.filepath ? 'target-file' : 'target-hsh';
    const detail = row.detail ? `<div class="target-detail">${escHtml(row.detail)}</div>` : '';
    return `<tr>
      <td><span class="asp-pill asp-default">${escHtml(row.appr)}</span></td>
      <td><span class="${targetCls}">${escHtml(row.target)}</span>${detail}</td>
      <td><div class="${cls}"><span class="${dot}"></span> ${row.verdict}</div>
          ${row.msg ? `<div class="fail-msg">${escHtml(row.msg)}</div>` : ''}</td>
      <td style="color:#6e7681;font-size:0.72rem;">${escHtml(row.timestamp || '')}</td>
    </tr>`;
  }).join('');
  return `<div class="card-title" style="color:#e3b341;">
    ⟳ Live Progress — ${done}/${total} complete${step}
  </div>
  <table>
    <colgroup><col style="width:20%"><col style="width:42%"><col style="width:18%"><col style="width:20%"></colgroup>
    <thead><tr><th>Appraiser</th><th>Target</th><th>Verdict</th><th>Appraised At</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="4" style="color:#8b949e;font-style:italic;">Waiting for first step…</td></tr>'}</tbody>
  </table>`;
}

function _startDetailPoll(id, runBtn, checkBtn) {
  const pollDetail = setInterval(async () => {
    try {
      const res  = await fetch('/api/results');
      const data = await res.json();
      const r    = data[id];
      if (!r) return;
      if (r.running) {
        // Show or update live progress card if this is a stepped protocol
        if (r.total_steps) {
          let prog = document.getElementById('live-progress-card');
          if (!prog) {
            prog = document.createElement('div');
            prog.id = 'live-progress-card';
            prog.className = 'card';
            prog.style.borderColor = '#9e6a03';
            const firstCard = document.querySelector('.card');
            if (firstCard) firstCard.parentNode.insertBefore(prog, firstCard);
            else document.body.appendChild(prog);
          }
          prog.innerHTML = _renderProgressTable(r);
        }
        return;
      }
      clearInterval(pollDetail);
      location.reload();
    } catch(e) { clearInterval(pollDetail); }
  }, 2000);
}

async function refreshProtocolConfig(id) {
  const btn = document.getElementById('refresh-cfg-btn');
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Refreshing…'; }
  try {
    const resp = await fetch('/api/refresh_protocol_config/' + id, {method: 'POST'});
    const data = await resp.json();
    if (data.ok) {
      window.location.reload();
    } else {
      alert('Refresh failed: ' + (data.error || 'Unknown error'));
      if (btn) { btn.disabled = false; btn.textContent = '↻ Refresh Config'; }
    }
  } catch(e) {
    alert('Refresh error: ' + e);
    if (btn) { btn.disabled = false; btn.textContent = '↻ Refresh Config'; }
  }
}

async function runProtocol(id) {
  const btn      = document.getElementById('run-btn-detail');
  const checkBtn = document.getElementById('check-btn-detail');
  if (btn)      { btn.disabled = true; btn.textContent = '⟳ Running…'; }
  if (checkBtn) { checkBtn.disabled = true; }
  try {
    await fetch('/api/run/' + id);
    _startDetailPoll(id, btn, checkBtn);
  } catch(e) {
    if (btn)      { btn.disabled = false; btn.textContent = '▶ Run'; }
    if (checkBtn) { checkBtn.disabled = false; checkBtn.textContent = '⚡ Check'; }
  }
}

async function checkProtocol(id) {
  const btn      = document.getElementById('run-btn-detail');
  const checkBtn = document.getElementById('check-btn-detail');
  if (checkBtn) { checkBtn.disabled = true; checkBtn.textContent = '⟳ Checking…'; }
  if (btn)      { btn.disabled = true; }
  try {
    await fetch('/api/check/' + id);
    _startDetailPoll(id, btn, checkBtn);
  } catch(e) {
    if (checkBtn) { checkBtn.disabled = false; checkBtn.textContent = '⚡ Check'; }
    if (btn)      { btn.disabled = false; btn.textContent = '▶ Run'; }
  }
}

async function toggleProvPopover(id, ev) {
  ev.stopPropagation();
  const pop = document.getElementById('prov-popover-' + id);
  if (!pop) return;
  const opening = !pop.classList.contains('open');
  document.querySelectorAll('.prov-popover.open').forEach(p => p.classList.remove('open'));
  if (opening) {
    pop.classList.add('open');
    const inp  = document.getElementById('prov-path-' + id);
    const hist = document.getElementById('prov-history-' + id);
    try {
      const d        = await (await fetch('/api/provision_history/' + id)).json();
      const current  = d.current_path || (d.paths && d.paths[0]) || '';
      const allPaths = d.paths || [];
      if (inp) { inp.value = current; inp.scrollLeft = inp.scrollWidth; }
      if (hist) {
        hist.innerHTML = '';
        allPaths.filter(p => p !== current).forEach(p => {
          const el = document.createElement('div');
          el.className = 'prov-hist-item';
          // Trim to a slash boundary so the filename is always visible
          const max = 48;
          if (p.length > max) {
            const cut   = p.length - max;
            const slash = p.indexOf('/', cut);
            el.textContent = '\u2026' + (slash >= 0 ? p.slice(slash) : p.slice(cut));
          } else {
            el.textContent = p;
          }
          el.title = p;
          el.addEventListener('click', ev => {
            ev.stopPropagation();
            if (inp) { inp.value = p; inp.scrollLeft = inp.scrollWidth; inp.focus(); }
          });
          hist.appendChild(el);
        });
      }
    } catch(e) {}
    if (inp) inp.focus();
  }
}
document.addEventListener('click', () => {
  document.querySelectorAll('.prov-popover.open').forEach(p => p.classList.remove('open'));
});

async function provisionWithPath(id) {
  const inp = document.getElementById('prov-path-' + id);
  const customPath = inp ? inp.value.trim() : '';
  const pop = document.getElementById('prov-popover-' + id);
  if (pop) pop.classList.remove('open');
  await provisionProtocol(id, customPath || null);
}

async function provisionProtocol(id, customPath) {
  const btn = document.getElementById('provbtn-' + id);
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Provisioning…'; }
  const url = '/api/provision/' + id +
    (customPath ? '?golden_path=' + encodeURIComponent(customPath) : '');
  try {
    const res = await fetch(url);
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      alert(data.error || 'Provision failed');
      if (btn) { btn.disabled = false; btn.textContent = '⚙ Provision'; }
      return;
    }
    location.reload();
  } catch(e) {
    if (btn) { btn.disabled = false; btn.textContent = '⚙ Provision'; }
  }
}

async function copySummary(id) {
  const btn = document.getElementById('summary-copy-btn-' + id);
  try {
    const res = await fetch('/api/run_summary/' + id);
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      alert(d.error || 'Summary unavailable');
      return;
    }
    const text = await res.text();
    await navigator.clipboard.writeText(text);
    if (btn) {
      btn.textContent = '✓ Copied';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = '⎘ Markdown'; btn.classList.remove('copied'); }, 2000);
    }
  } catch(e) {
    alert('Copy failed: ' + e);
  }
}

{{ base_js | safe }}
setupPathComplete('prov-path-{{ proto.id }}', () => provisionWithPath('{{ proto.id }}'));
fetch('/api/provision_history/{{ proto.id }}').then(r => r.json()).then(d => {
  const fill = d.current_path || (d.paths && d.paths[0]) || '';
  if (fill) {
    const inp = document.getElementById('prov-path-{{ proto.id }}');
    if (inp && !inp.value) { inp.value = fill; inp.scrollLeft = inp.scrollWidth; }
  }
}).catch(() => {});

{% if proto.places %}
async function refreshPlaces() {
  try {
    const res  = await fetch('/api/protocols/{{ proto.id }}/places');
    const data = await res.json();
    let anyUnreachable = false;
    Object.entries(data.places || {}).forEach(([pid, info]) => {
      const dot = document.getElementById('place-dot-' + pid);
      if (dot) {
        dot.className = info.reachable ? 'dot-g' : 'dot-r';
        dot.title     = info.reachable
          ? (info.running ? `Running (PID ${info.pid})` : 'Reachable (external)')
          : 'Unreachable — click Start';
      }
      const pidEl = document.getElementById('place-pid-' + pid);
      if (pidEl) pidEl.textContent = info.running ? `PID ${info.pid}` : '';
      if (!info.reachable) anyUnreachable = true;
    });
    const runBtn = document.getElementById('run-btn-detail');
    if (runBtn) {
      runBtn.disabled = anyUnreachable;
      runBtn.title    = anyUnreachable ? 'One or more places unreachable — start them first' : '';
    }
  } catch(e) {}
}
async function startPlace(protoId, placeId) {
  const btn = document.getElementById('place-start-' + placeId);
  if (btn) { btn.disabled = true; btn.textContent = '⟳'; }
  try {
    const res  = await fetch('/api/protocols/' + protoId + '/places/' + encodeURIComponent(placeId) + '/start', {method:'POST'});
    const data = await res.json().catch(() => ({}));
    if (!res.ok) alert(data.error || 'Start failed');
  } catch(e) { alert('Error: ' + e.message); }
  if (btn) { btn.disabled = false; btn.textContent = '▶ Start'; }
  await refreshPlaces();
}
async function stopPlace(protoId, placeId) {
  const btn = document.getElementById('place-stop-' + placeId);
  if (btn) { btn.disabled = true; btn.textContent = '⟳'; }
  try {
    await fetch('/api/protocols/' + protoId + '/places/' + encodeURIComponent(placeId) + '/stop', {method:'POST'});
  } catch(e) {}
  if (btn) { btn.disabled = false; btn.textContent = '■ Stop'; }
  await refreshPlaces();
}
refreshPlaces();
setInterval(refreshPlaces, 3000);
{% endif %}

{% if proto.imported_dir %}
// Load stub info for this imported protocol
(async () => {
  try {
    const res  = await fetch('/api/protocols/{{ proto.id }}/import_info');
    const data = await res.json();
    if (!data.imported || !data.stubs || !data.stubs.length) return;
    const area = document.getElementById('stub-warning-area');
    if (!area) return;
    const names = data.stubs.map(s => escHtml(s.label || s.tid)).join(', ');
    area.innerHTML = ` &nbsp;·&nbsp; <span style="color:#f0883e;">⚠ ${data.stubs.length} stub target(s): ${names}</span>
      <span style="color:#8b949e;"> — provision will fail until real files are provided in
      <code style="color:#c9d1d9;">${escHtml(data.local_dir)}/targets/</code></span>`;
  } catch(e) {}
})();
{% endif %}
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
      <input class="build-input" id="meta-id" placeholder="my_protocol" spellcheck="false"
             oninput="_clearOverwriteWarn()" onblur="_checkOverwrite()">
      <span id="id-overwrite-warn" style="display:none;font-size:0.72rem;color:#e3b341;margin-top:4px;"></span>
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

<!-- ASP Args Editor (shown when a flow node is clicked) -->
<div id="arg-editor" style="display:none;margin-bottom:14px;">
  <div class="arg-editor-card">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
      <span id="arg-editor-title" style="font-size:0.85rem;font-weight:600;color:#58a6ff;"></span>
      <button class="remove-btn" onclick="closeArgEditor()">✕ Close</button>
    </div>
    <div id="arg-editor-fields"></div>
    <div style="display:flex;gap:8px;margin-top:14px;">
      <button class="run-btn" onclick="applyArgChanges()">✓ Apply to Term</button>
      <button class="remove-btn" onclick="closeArgEditor()">Cancel</button>
    </div>
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

<!-- Remote Places (optional) -->
<div class="card" style="margin-bottom:14px;">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
    <div class="card-title" style="margin-bottom:0;">Remote Places
      <span style="color:#6e7681;font-size:0.65rem;text-transform:none;font-weight:normal;">
        — optional, for att(P, …) terms
      </span>
    </div>
    <button class="copy-btn" onclick="addPlaceRow()">+ Add Place</button>
  </div>
  <div class="places-row" style="color:#6e7681;font-size:0.65rem;text-transform:uppercase;letter-spacing:.05em;padding-bottom:4px;border-bottom:1px solid #21262d;margin-bottom:6px;">
    <span>Place ID</span><span>Host</span><span>Port</span>
    <span>Manifest path</span><span>asp_bin path</span><span></span>
  </div>
  <div id="places-list"></div>
</div>

<!-- Register -->
<div style="text-align:right;margin-bottom:30px;">
  <button class="register-btn" id="register-btn" onclick="registerProtocol()">⊕ Register Protocol</button>
</div>

<script>
let _flowItems = [];   // only ASPC nodes (those with term_path), in render order
let _argEditorIdx = null;

// Render a single non-bseq flow node; registers it in _flowItems if clickable
function _renderFlowNode(node) {
  if (node.term_path) {
    const idx = _flowItems.length;
    _flowItems.push(node);
    return `<div class="flow-node fn-${escHtml(node.style||'default')} clickable-asp"
                 onclick="openArgEditor(this,${idx})" title="Click to edit ASP_ARGS"
            >${escHtml(node.label)}<span class="asp-edit-hint">✎</span></div>`;
  }
  return `<div class="flow-node fn-${escHtml(node.style||'default')}">${escHtml(node.label)}</div>`;
}

function renderFlow(flow) {
  _flowItems = [];
  if (!flow || !flow.length)
    return '<span style="color:#6e7681;font-size:0.78rem;font-style:italic;">No flow derived.</span>';
  return flow.map(node => {
    if (node.type === 'arrow') return '<span class="flow-arrow">→</span>';
    if (node.type === 'bseq') {
      // Use children_flow (full items with term_path) when available; fall back to strings
      let childrenHtml;
      if (node.children_flow) {
        childrenHtml = node.children_flow.map(branch =>
          branch.map(_renderFlowNode).join('')
        ).join('');
      } else {
        childrenHtml = (node.children || []).map(c =>
          `<div class="flow-node fn-file">${escHtml(c)}</div>`).join('');
      }
      return `<div class="flow-node fn-bseq">
        <div class="bseq-label">${escHtml(node.label)}</div>
        <div class="flow-sub">${childrenHtml}</div>
      </div>`;
    }
    return _renderFlowNode(node);
  }).join('');
}

function addArgRow(container, key, val, focusKey) {
  // Insert before the last child (the "+ Add arg" button), or append if none yet
  const row = document.createElement('div');
  row.className = 'arg-row';
  row.dataset.newRow = '1';
  row.innerHTML = `
    <input class="arg-val" type="text" placeholder="key" data-role="arg-key"
           style="font-size:0.78rem;" value="${escHtml(key)}">
    <input class="arg-val" type="text" placeholder="value" data-role="arg-val"
           value="${escHtml(val)}">`;
  const addBtn = container.querySelector('button');
  if (addBtn) container.insertBefore(row, addBtn);
  else        container.appendChild(row);
  if (focusKey) row.querySelector('[data-role="arg-key"]').focus();
}

function openArgEditor(el, idx) {
  _argEditorIdx = idx;
  const flowItem = _flowItems[idx];
  const editorEl = document.getElementById('arg-editor');
  const titleEl  = document.getElementById('arg-editor-title');
  const fieldsEl = document.getElementById('arg-editor-fields');

  const termStr = document.getElementById('term-json').value.trim();
  if (!termStr) {
    titleEl.textContent  = 'No term loaded';
    fieldsEl.innerHTML   = '<span style="color:#f85149;font-size:0.8rem;">Load a term JSON first.</span>';
    editorEl.style.display = '';
    return;
  }
  let term;
  try { term = JSON.parse(termStr); }
  catch(e) {
    titleEl.textContent  = 'Parse error';
    fieldsEl.innerHTML   = `<span style="color:#f85149;font-size:0.8rem;">Invalid term JSON: ${escHtml(e.message)}</span>`;
    editorEl.style.display = '';
    return;
  }

  // Navigate to ASP_BODY using term_path
  let aspBody = term;
  for (const key of flowItem.term_path) {
    if (aspBody == null) break;
    aspBody = aspBody[key];
  }
  if (!aspBody || !aspBody.ASP_ID) {
    titleEl.textContent  = 'Navigation error';
    fieldsEl.innerHTML   = '<span style="color:#f85149;font-size:0.8rem;">Could not locate ASP node in term tree. Try clicking ▶ Derive to refresh the flow.</span>';
    editorEl.style.display = '';
    return;
  }

  titleEl.textContent = aspBody.ASP_ID + ' — ASP_ARGS';
  const args = aspBody.ASP_ARGS || {};
  fieldsEl.innerHTML = '';
  Object.entries(args).forEach(([key, val]) => addArgRow(fieldsEl, key, String(val)));

  // "+ Add arg" button always present
  const addBtn = document.createElement('button');
  addBtn.className   = 'copy-btn';
  addBtn.textContent = '+ Add arg';
  addBtn.style.marginTop = '6px';
  addBtn.onclick = () => { addArgRow(fieldsEl, '', '', true); addBtn.scrollIntoView({block:'nearest'}); };
  fieldsEl.appendChild(addBtn);

  document.querySelectorAll('.clickable-asp.asp-selected').forEach(n => n.classList.remove('asp-selected'));
  el.classList.add('asp-selected');
  editorEl.style.display = '';
  editorEl.scrollIntoView({behavior: 'smooth', block: 'nearest'});
}

function closeArgEditor() {
  document.getElementById('arg-editor').style.display = 'none';
  document.querySelectorAll('.clickable-asp.asp-selected').forEach(n => n.classList.remove('asp-selected'));
  _argEditorIdx = null;
}

function applyArgChanges() {
  if (_argEditorIdx === null) return;
  const flowItem = _flowItems[_argEditorIdx];
  const termStr  = document.getElementById('term-json').value.trim();
  let term;
  try { term = JSON.parse(termStr); }
  catch(e) { alert('Invalid term JSON: ' + e.message); return; }

  let aspBody = term;
  for (const key of flowItem.term_path) aspBody = aspBody[key];
  if (!aspBody.ASP_ARGS) aspBody.ASP_ARGS = {};

  // Existing args (key fixed, only value editable)
  document.querySelectorAll('#arg-editor-fields input[data-arg-key]').forEach(inp => {
    aspBody.ASP_ARGS[inp.dataset.argKey] = inp.value;
  });
  // New rows added via "+ Add arg" (both key and value are inputs)
  document.querySelectorAll('#arg-editor-fields [data-new-row="1"]').forEach(row => {
    const k = row.querySelector('[data-role="arg-key"]').value.trim();
    const v = row.querySelector('[data-role="arg-val"]').value;
    if (k) aspBody.ASP_ARGS[k] = v;
  });

  document.getElementById('term-json').value = JSON.stringify(term, null, 2);
  closeArgEditor();
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
    else {
      document.getElementById(textareaId).value = data.content;
      localStorage.setItem('cvm_fp_' + pathInputId, path);
      if (textareaId === 'term-json') deriveFromTerm(true);
    }
  } catch(e) { errEl.textContent = e.message; }
  btn.disabled = false; btn.textContent = '↓ Load file';
}

{{ base_js | safe }}

// Wire up the three path inputs
const _loadBtnMap = {'term-file':'term-load-btn','manifest-file':'manifest-load-btn','session-file':'session-load-btn'};
// Only restore saved file paths when opening a blank new-protocol form.
// In copy mode the form is pre-populated from the source protocol,
// so stale paths from a previous session must not bleed in.
const _isBlankForm = !new URLSearchParams(window.location.search).get('copy');
['term-file', 'manifest-file', 'session-file'].forEach(id => {
  setupPathComplete(id, () => document.getElementById(_loadBtnMap[id]).click());
  if (_isBlankForm) {
    const saved = localStorage.getItem('cvm_fp_' + id);
    if (saved) document.getElementById(id).value = saved;
  }
});

// Auto-derive flow when term textarea is edited (debounced 600ms)
let _termDeriveTimer = null;
document.getElementById('term-json').addEventListener('input', () => {
  clearTimeout(_termDeriveTimer);
  _termDeriveTimer = setTimeout(() => deriveFromTerm(true), 600);
});

// silent=true: update flow/targets only, no button state or error UI changes
async function deriveFromTerm(silent) {
  const btn     = document.getElementById('derive-btn');
  const errEl   = document.getElementById('derive-error');
  const termStr = document.getElementById('term-json').value.trim();
  if (!silent) {
    errEl.style.display = 'none';
    if (!termStr) { errEl.textContent = 'Load or paste a term JSON first.'; errEl.style.display = ''; return; }
    btn.textContent = '⟳ Deriving…'; btn.disabled = true;
  } else {
    if (!termStr) return;
  }
  try {
    const res  = await fetch('/api/derive_term', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({term_json: termStr}),
    });
    const data = await res.json();
    if (!res.ok) {
      if (!silent) { errEl.textContent = data.error || 'Derivation failed'; errEl.style.display = ''; }
    } else {
      // Always update the visual previews (they are derived from the term)
      document.getElementById('flow-preview').innerHTML    = renderFlow(data.flow);
      document.getElementById('targets-preview').innerHTML = renderTargets(data.targets);
      // Only fill manifest / session when those fields are empty — never overwrite
      // content the user loaded or hand-crafted.
      const mEl = document.getElementById('manifest-json');
      if (!mEl.value.trim()) mEl.value = JSON.stringify(data.manifest, null, 2);
      const sEl = document.getElementById('session-json');
      if (!sEl.value.trim()) sEl.value = JSON.stringify(data.attestation_session, null, 2);
    }
  } catch(e) {
    if (!silent) { errEl.textContent = 'Error: ' + e.message; errEl.style.display = ''; }
  }
  if (!silent) { btn.textContent = '▶ Derive'; btn.disabled = false; }
}

// ── Copy mode: pre-populate from any protocol, leave ID editable ──────────────
async function maybeLoadCopy() {
  const copyId = new URLSearchParams(window.location.search).get('copy');
  if (!copyId) return;

  document.querySelector('h1').textContent   = 'Copy Protocol';
  document.querySelector('.sub').textContent = 'Edit the fields below and click Register Protocol to save as a new protocol';

  const banner = document.getElementById('banner');
  try {
    const res  = await fetch('/api/protocol_copy_spec/' + encodeURIComponent(copyId));
    const spec = await res.json();
    if (!res.ok) {
      banner.innerHTML = `<div class="err-banner">${escHtml(spec.error || 'Could not load protocol spec')}</div>`;
      return;
    }

    // Suggest a unique new ID and name — leave both editable
    const suggestedId   = spec._suggested_copy_id || ('copy_of_' + (spec.id || copyId));
    const baseCopyId    = 'copy_of_' + (spec.id || copyId);
    const baseName      = 'Copy of ' + (spec.name || spec.id || copyId);
    const numSuffix     = suggestedId !== baseCopyId
                            ? suggestedId.slice(baseCopyId.length + 1)  // e.g. "2", "3"
                            : null;
    document.getElementById('meta-id').value   = suggestedId;
    document.getElementById('meta-name').value = numSuffix ? `${baseName} (${numSuffix})` : baseName;
    document.getElementById('meta-desc').value    = spec.description || '';
    document.getElementById('meta-copland').value = spec.copland     || '';

    const term = spec.request && spec.request.TERM;
    if (term)
      document.getElementById('term-json').value = JSON.stringify(term, null, 2);

    if (spec.manifest)
      document.getElementById('manifest-json').value = JSON.stringify(spec.manifest, null, 2);

    const attest = spec.request && spec.request.ATTESTATION_SESSION;
    if (attest)
      document.getElementById('session-json').value = JSON.stringify(attest, null, 2);

    const evidence = spec.request && spec.request.EVIDENCE;
    if (evidence)
      document.getElementById('evidence-json').value = JSON.stringify(evidence, null, 2);

    if (spec.flow)
      document.getElementById('flow-preview').innerHTML = renderFlow(spec.flow);
    if (spec.targets && spec.targets.length)
      document.getElementById('targets-preview').innerHTML = renderTargets(spec.targets);
    deriveFromTerm(true);

    if (spec.places && typeof spec.places === 'object') {
      document.getElementById('places-list').innerHTML = '';
      Object.entries(spec.places).forEach(([pid, cfg]) =>
        addPlaceRow(pid, cfg.host||'localhost', cfg.port||'', cfg.manifest||'', cfg.asp_bin||''));
    }

  } catch(e) {
    banner.innerHTML = `<div class="err-banner">Error loading spec: ${escHtml(e.message)}</div>`;
  }
}
document.addEventListener('DOMContentLoaded', maybeLoadCopy);

// ── Places configuration ───────────────────────────────────────────────────────
let _placeCounter = 0;
function addPlaceRow(pid='', host='localhost', port='', manifest='', asp_bin='') {
  const idx  = _placeCounter++;
  const list = document.getElementById('places-list');
  const row  = document.createElement('div');
  row.className    = 'places-row';
  row.dataset.pidx = idx;
  row.innerHTML = `
    <input type="text"   data-role="pid"      placeholder="P1"        value="${escHtml(pid)}"      style="font-family:monospace;">
    <input type="text"   data-role="host"     placeholder="localhost"  value="${escHtml(host)}">
    <input type="number" data-role="port"     placeholder="8081"       value="${escHtml(String(port))}" min="1" max="65535">
    <input type="text"   data-role="manifest" placeholder="/path/to/manifest.json" value="${escHtml(manifest)}">
    <input type="text"   data-role="asp_bin"  placeholder="/path/to/asps"          value="${escHtml(asp_bin)}">
    <button class="remove-btn" onclick="this.closest('.places-row').remove()" style="padding:2px 8px;font-size:0.7rem;">×</button>`;
  list.appendChild(row);
}
function collectPlaces() {
  const rows = document.querySelectorAll('#places-list .places-row');
  const result = {};
  rows.forEach(row => {
    const pid      = row.querySelector('[data-role="pid"]').value.trim();
    const host     = row.querySelector('[data-role="host"]').value.trim() || 'localhost';
    const port     = parseInt(row.querySelector('[data-role="port"]').value.trim(), 10);
    const manifest = row.querySelector('[data-role="manifest"]').value.trim();
    const asp_bin  = row.querySelector('[data-role="asp_bin"]').value.trim();
    if (pid && port) result[pid] = {host, port, manifest, asp_bin};
  });
  return Object.keys(result).length ? result : null;
}
function showPortConflictWarning(newId, conflicts) {
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:9999;display:flex;align-items:center;justify-content:center;';
  const box = document.createElement('div');
  box.style.cssText = 'background:#161b22;border:2px solid #9e6a03;border-radius:10px;padding:24px 28px;max-width:520px;width:90%;color:#e6edf3;font-family:inherit;';
  const rows = conflicts.map(c =>
    `<li style="font-family:monospace;padding:2px 0;font-size:0.78rem;color:#e3b341;">
       Port ${c.port} (place <strong>${escHtml(c.place_id)}</strong>) already used by <strong>${escHtml(c.conflicts_with)}</strong>
     </li>`
  ).join('');
  box.innerHTML = `
    <div style="color:#e3b341;font-size:1rem;font-weight:600;margin-bottom:10px;">⚠ Port Conflict Warning</div>
    <div style="font-size:0.82rem;color:#8b949e;margin-bottom:10px;">
      Protocol <strong style="color:#e6edf3;">${escHtml(newId)}</strong> shares ports with existing protocols that have different configurations:
    </div>
    <ul style="margin:0 0 16px 16px;padding:0;">${rows}</ul>
    <div style="font-size:0.75rem;color:#6e7681;margin-bottom:16px;">
      Running both simultaneously will cause ZMQ bind conflicts. Ensure only one protocol's places are running at a time.
    </div>
    <div style="text-align:right;">
      <button style="background:#21262d;color:#e3b341;border:1px solid #9e6a03;border-radius:6px;padding:6px 18px;cursor:pointer;font-size:0.85rem;"
              onclick="this.closest('div[style*=inset]').remove()">Understood</button>
    </div>`;
  overlay.appendChild(box);
  document.body.appendChild(overlay);
}

function _clearOverwriteWarn() {
  const w = document.getElementById('id-overwrite-warn');
  if (w) { w.style.display = 'none'; w.textContent = ''; }
}

async function _checkOverwrite() {
  const idEl = document.getElementById('meta-id');
  if (!idEl) return;
  const id = idEl.value.trim();
  if (!id) return;
  try {
    const res  = await fetch('/api/proto_overwrite_check?id=' + encodeURIComponent(id));
    const data = await res.json();
    const w    = document.getElementById('id-overwrite-warn');
    if (!w) return;
    if (data.would_overwrite) {
      const who  = data.existing_name ? `"${data.existing_name}"` : `"${id}"`;
      const kind = data.is_builtin ? 'a built-in protocol' : 'an existing protocol';
      const file = data.file_path  ? ` (${data.file_path.split('/').pop()})` : '';
      w.textContent = `⚠ ID conflicts with ${kind} ${who}${file} — registering will overwrite it.`;
      w.style.display = 'block';
    } else {
      _clearOverwriteWarn();
    }
  } catch(e) {}
}

async function registerProtocol() {
  const banner = document.getElementById('banner');
  const btn    = document.getElementById('register-btn');
  banner.innerHTML = '';
  const id = document.getElementById('meta-id').value.trim();
  if (!id) { banner.innerHTML = '<div class="err-banner">Protocol ID is required.</div>'; return; }

  // Warn before overwriting an existing protocol file or registry entry.
  try {
    const chk  = await fetch('/api/proto_overwrite_check?id=' + encodeURIComponent(id));
    const info = await chk.json();
    if (info.would_overwrite) {
      const who  = info.existing_name ? `"${info.existing_name}"` : `"${id}"`;
      const kind = info.is_builtin ? 'built-in protocol' : 'existing protocol';
      const file = info.file_path  ? `\n\nFile: ${info.file_path}` : '';
      const ok   = confirm(
        `Registering as "${id}" will overwrite the ${kind} ${who}.${file}\n\nContinue?`
      );
      if (!ok) return;
    }
  } catch(e) {}

  btn.disabled = true; btn.textContent = '⟳ Registering…';
  try {
    const places = collectPlaces();
    const res  = await fetch('/api/register_builder', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        id:            id,
        name:          document.getElementById('meta-name').value.trim() || id,
        description:   document.getElementById('meta-desc').value.trim(),
        copland:       document.getElementById('meta-copland').value.trim(),
        term_json:     document.getElementById('term-json').value.trim(),
        manifest_json: document.getElementById('manifest-json').value.trim(),
        session_json:  document.getElementById('session-json').value.trim(),
        evidence_json: document.getElementById('evidence-json').value.trim(),
        places_json:   places ? JSON.stringify(places) : '',
        copy_source:   new URLSearchParams(window.location.search).get('copy') || '',
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      banner.innerHTML = `<div class="err-banner">${escHtml(data.error || 'Registration failed')}</div>`;
    } else {
      if (data.port_conflicts && data.port_conflicts.length)
        showPortConflictWarning(data.id, data.port_conflicts);
      banner.innerHTML = `<div class="ok-banner">✓ Protocol <strong>${escHtml(data.name)}</strong> registered. <a href="/protocol/${escHtml(data.id)}" style="color:#3fb950;">View →</a>${data.saved_path ? `<br><span style="font-size:0.78rem;color:#8b949e;font-family:monospace;">Saved to: ${escHtml(data.saved_path)}</span>` : ''}</div>`;
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
    # Enrich REGISTRY entries with metadata from protocol_dirs/ where available
    protocols = []
    for p in REGISTRY.values():
        meta = protocol_loader.get_protocol_dir_meta(p['id'])
        if meta:
            p = {**p,
                 'name':        meta.get('name',        p.get('name', p['id'])),
                 'description': meta.get('description', p.get('description', '')),
                 'copland':     meta.get('copland',     p.get('copland', '')),
                 'flow':        meta.get('flow',        p.get('flow', []))}
        protocols.append(p)
    return render_template_string(HOME_TMPL, style=BASE_STYLE, base_js=BASE_JS,
                                  protocols=protocols, results=snap)


@app.route('/protocol/<protocol_id>')
def protocol_detail(protocol_id):
    if protocol_id not in REGISTRY:
        return f"Unknown protocol: {protocol_id}", 404
    proto = REGISTRY[protocol_id]
    with store_lock:
        r = results_store.get(protocol_id)
    prov = proto['golden_state']() if 'golden_state' in proto else []
    provisioned = any(e.get('timestamp') for e in prov) if prov else True
    staleness = check_protocol_dir_staleness(protocol_id)
    proto_dir_ids = set(protocol_loader.list_protocol_dir_ids())
    dir_files = (protocol_loader.get_protocol_dir_files(protocol_id)
                 if protocol_id in proto_dir_ids else [])
    return render_template_string(DETAIL_TMPL, style=BASE_STYLE, base_js=BASE_JS,
                                  proto=proto, r=r, prov=prov, provisioned=provisioned,
                                  staleness=staleness, proto_dir_ids=proto_dir_ids,
                                  dir_files=dir_files)


# Track which protocols are currently running so the UI can show a spinner.
_running_protocols  = set()
_running_operations = {}   # protocol_id -> 'run' | 'check'
_running_lock       = threading.Lock()


def _run_stepped(protocol_id, steps):
    """Run a stepped protocol incrementally.

    Executes each step as a separate CVM call (one lseq/APPR per step),
    publishing partial results to results_store after every step so the
    UI poll loop can display live progress.

    If all individual steps pass, the full build() term is executed once
    more to produce the canonical single-bundle evidence result that gets
    stored as the final outcome.  If any step fails, the partial failure
    is stored immediately and no further steps are run.
    """
    asp_bin = os.environ.get(
        'CVM_ASP_BIN',
        os.path.expanduser('~/Claude_workspace/asp-libs/target/release'),
    )
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    total = len(steps)
    partial = []
    failed  = False

    for step_idx, (step_id, label, build_fn) in enumerate(steps):
        # Publish progress snapshot *before* this step starts so the UI
        # shows which step is currently executing.
        with store_lock:
            results_store[protocol_id] = {
                'protocol_id':  protocol_id,
                'cvm_success':  True,
                'results':      list(partial),
                'all_pass':     False,
                'pass_count':   sum(1 for r in partial if r['verdict'] == 'PASS'),
                'fail_count':   sum(1 for r in partial if r['verdict'] != 'PASS'),
                'error':        None,
                'timestamp':    ts,
                'current_step': label,
                'total_steps':  total,
            }

        # Run this single step.
        try:
            manifest, request = build_fn()
            raw = cvm_server.run_attestation(
                manifest if isinstance(manifest, str) else json.dumps(manifest),
                json.dumps(request) if isinstance(request, dict) else request,
                log_level='Info',
            )
            response = json.loads(raw) if isinstance(raw, str) else raw
        except Exception as exc:
            store_result({
                'protocol_id': protocol_id,
                'cvm_success': False,
                'results':     partial,
                'all_pass':    False,
                'pass_count':  sum(1 for r in partial if r['verdict'] == 'PASS'),
                'fail_count':  len(partial) - sum(1 for r in partial if r['verdict'] == 'PASS'),
                'error':       str(exc),
                'timestamp':   ts,
            })
            return

        step_ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if not response.get('SUCCESS'):
            partial.append({
                'appr': 'run_command_hamr_appr', 'target': label, 'filepath': '',
                'verdict': 'FAIL',
                'msg': str(response.get('PAYLOAD', 'CVM error')),
                'timestamp': step_ts,
            })
            failed = True
            break

        try:
            raw_ev = response['PAYLOAD'][0]['RawEv']
            et     = response['PAYLOAD'][1]
            rows   = walk_et(et, raw_ev, [0])
            for row in rows:
                row['timestamp'] = step_ts
                # Use the step label from the steps list rather than anything
                # embedded in ASP_ARGS — keeps display metadata out of the
                # evidence channel.
                row['target'] = label
            partial.extend(rows)
            if any(row['verdict'] != 'PASS' for row in rows):
                failed = True
                break
        except Exception as exc:
            store_result({
                'protocol_id': protocol_id,
                'cvm_success': False,
                'results':     partial,
                'all_pass':    False,
                'pass_count':  sum(1 for r in partial if r['verdict'] == 'PASS'),
                'fail_count':  len(partial) - sum(1 for r in partial if r['verdict'] == 'PASS'),
                'error':       str(exc),
                'timestamp':   ts,
            })
            return

    if not failed:
        # All steps passed individually — run the full combined term once to
        # produce the canonical single Copland evidence bundle.
        final = run_protocol(protocol_id)
        store_result(final)
    else:
        store_result({
            'protocol_id': protocol_id,
            'cvm_success': True,
            'results':     partial,
            'all_pass':    False,
            'pass_count':  sum(1 for r in partial if r['verdict'] == 'PASS'),
            'fail_count':  sum(1 for r in partial if r['verdict'] != 'PASS'),
            'error':       None,
            'timestamp':   ts,
        })


def _run_check(protocol_id, steps):
    """Run all steps in parallel and store results with result_type='check'.

    Each step is dispatched to its own thread via ThreadPoolExecutor.
    Results are written into ordered slots so the table always shows steps
    in canonical order regardless of which finishes first.
    The progress snapshot is pushed to results_store after each future
    resolves so the UI poll loop can render incremental updates.
    No final combined run — the result is the set of individual attestations.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    ts    = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    total = len(steps)
    slots = [None] * total   # ordered result slots
    fail  = [False]
    slots_lock = threading.Lock()

    def _step(idx, label, build_fn):
        manifest, request = build_fn()
        raw = cvm_server.run_attestation(
            manifest if isinstance(manifest, str) else json.dumps(manifest),
            json.dumps(request) if isinstance(request, dict) else request,
            log_level='Info',
        )
        response = json.loads(raw) if isinstance(raw, str) else raw
        step_ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if not response.get('SUCCESS'):
            return idx, [{'appr': 'run_command_hamr_appr', 'target': label,
                          'filepath': '', 'verdict': 'FAIL',
                          'msg': str(response.get('PAYLOAD', 'CVM error')),
                          'timestamp': step_ts}]
        rows = walk_et(response['PAYLOAD'][1], response['PAYLOAD'][0]['RawEv'], [0])
        for row in rows:
            row['timestamp'] = step_ts
        return idx, rows

    with ThreadPoolExecutor(max_workers=total) as executor:
        futures = {
            executor.submit(_step, i, label, build_fn): label
            for i, (sid, label, build_fn) in enumerate(steps)
        }
        for future in as_completed(futures):
            try:
                idx, rows = future.result()
            except Exception as exc:
                store_result({'protocol_id': protocol_id, 'cvm_success': False,
                              'results': [], 'all_pass': False,
                              'pass_count': 0, 'fail_count': 0,
                              'error': str(exc), 'timestamp': ts,
                              'result_type': 'check'})
                return
            with slots_lock:
                slots[idx] = rows
                if any(r['verdict'] != 'PASS' for r in rows):
                    fail[0] = True
                partial = [row for s in slots if s is not None for row in s]
                done    = sum(1 for s in slots if s is not None)
            with store_lock:
                results_store[protocol_id] = {
                    'protocol_id': protocol_id,
                    'cvm_success': True,
                    'results':     partial,
                    'all_pass':    False,
                    'pass_count':  sum(1 for r in partial if r['verdict'] == 'PASS'),
                    'fail_count':  sum(1 for r in partial if r['verdict'] != 'PASS'),
                    'error':       None,
                    'timestamp':   ts,
                    'total_steps': total,
                    'result_type': 'check',
                }

    # All futures done — write the final result (running flag removed by caller)
    all_rows = [row for s in slots if s is not None for row in s]
    store_result({
        'protocol_id': protocol_id,
        'cvm_success': True,
        'results':     all_rows,
        'all_pass':    not fail[0] and len(all_rows) == total,
        'pass_count':  sum(1 for r in all_rows if r['verdict'] == 'PASS'),
        'fail_count':  sum(1 for r in all_rows if r['verdict'] != 'PASS'),
        'error':       None,
        'timestamp':   ts,
        'result_type': 'check',
    })


@app.route('/api/check/<protocol_id>')
def api_check(protocol_id):
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    proto = REGISTRY[protocol_id]
    if not proto.get('steps'):
        return jsonify({'error': 'Protocol has no check steps defined'}), 400

    with _running_lock:
        already_running = protocol_id in _running_protocols
        if not already_running:
            _running_protocols.add(protocol_id)
            _running_operations[protocol_id] = 'check'

    if already_running:
        return jsonify({'running': True, 'protocol_id': protocol_id})

    steps = proto['steps']

    def _check():
        try:
            _run_check(protocol_id, steps)
        except Exception as exc:
            ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            store_result({
                'protocol_id': protocol_id,
                'cvm_success': False,
                'results':     [],
                'all_pass':    False,
                'pass_count':  0,
                'fail_count':  0,
                'error':       str(exc),
                'timestamp':   ts,
            })
        finally:
            with _running_lock:
                _running_protocols.discard(protocol_id)
                _running_operations.pop(protocol_id, None)

    threading.Thread(target=_check, daemon=True).start()
    return jsonify({'running': True, 'operation': 'check', 'protocol_id': protocol_id})


@app.route('/api/run/<protocol_id>')
def api_run(protocol_id):
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404

    with _running_lock:
        already_running = protocol_id in _running_protocols
        if not already_running:
            _running_protocols.add(protocol_id)
            _running_operations[protocol_id] = 'run'

    if already_running:
        return jsonify({'running': True, 'protocol_id': protocol_id})

    proto = REGISTRY[protocol_id]
    steps = proto.get('steps')

    def _run():
        try:
            if steps:
                _run_stepped(protocol_id, steps)
            else:
                r = run_protocol(protocol_id)
                store_result(r)
        except Exception as exc:
            ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            store_result({
                'protocol_id': protocol_id,
                'cvm_success': False,
                'results':     [],
                'all_pass':    False,
                'pass_count':  0,
                'fail_count':  0,
                'error':       str(exc),
                'timestamp':   ts,
            })
        finally:
            with _running_lock:
                _running_protocols.discard(protocol_id)
                _running_operations.pop(protocol_id, None)

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({'running': True, 'operation': 'run', 'protocol_id': protocol_id})


@app.route('/api/provision/<protocol_id>')
def api_provision(protocol_id):
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    proto = REGISTRY[protocol_id]
    if not proto.get('provision'):
        return jsonify({'error': 'Protocol has no provisioning function'}), 400
    golden_path = flask_request.args.get('golden_path') or None
    try:
        entries = proto['provision'](golden_path=golden_path)
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 409
    # Clear any stale run result so the page reloads without an old error card
    with store_lock:
        results_store.pop(protocol_id, None)
    return jsonify({'protocol_id': protocol_id, 'entries': entries})




@app.route('/api/run_summary/<protocol_id>')
def api_run_summary(protocol_id):
    """Return a Markdown run summary for a protocol, reading config from protocol_dirs/."""
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    if not protocol_loader.has_protocol_dir(protocol_id):
        return jsonify({'error': f"Protocol '{protocol_id}' has no protocol_dirs entry — config is code-defined"}), 400
    with store_lock:
        result_data = results_store.get(protocol_id)
    import summary_generator
    md = summary_generator.generate_run_summary(
        protocol_id, result_data, REGISTRY[protocol_id]
    )
    fmt = flask_request.args.get('format', 'text')
    if fmt == 'json':
        return jsonify({'protocol_id': protocol_id, 'markdown': md})
    from flask import Response
    return Response(md, mimetype='text/plain; charset=utf-8')


@app.route('/api/protocols/<protocol_id>/places', methods=['GET'])
def api_protocol_places(protocol_id):
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    proto  = REGISTRY[protocol_id]
    places = proto.get('places', {})
    status = place_manager.get_place_status(protocol_id, places)
    return jsonify({'places': status})


@app.route('/api/protocols/<protocol_id>/places/<place_id>/start', methods=['POST'])
def api_place_start(protocol_id, place_id):
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    places = REGISTRY[protocol_id].get('places', {})
    cfg    = places.get(place_id)
    if not cfg:
        return jsonify({'error': f'Unknown place: {place_id}'}), 404
    try:
        result = place_manager.start_place(protocol_id, place_id, cfg)
        return jsonify({'ok': True, **result})
    except FileNotFoundError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/protocols/<protocol_id>/places/<place_id>/stop', methods=['POST'])
def api_place_stop(protocol_id, place_id):
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    result = place_manager.stop_place(protocol_id, place_id)
    return jsonify({'ok': True, **result})


@app.route('/api/protocols/<protocol_id>/files', methods=['GET'])
def api_protocol_files(protocol_id):
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    files = protocol_loader.list_cleanup_files(protocol_id)
    return jsonify({'files': files})


@app.route('/api/protocols/<protocol_id>', methods=['DELETE'])
def api_remove_protocol(protocol_id):
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    cleanup = flask_request.args.get('cleanup', '').lower() == 'true'
    if not protocol_loader.remove_protocol(protocol_id, delete_files=cleanup):
        return jsonify({'error': 'Cannot remove built-in protocol'}), 400
    with store_lock:
        results_store.pop(protocol_id, None)
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
    with _running_lock:
        running    = set(_running_protocols)
        operations = dict(_running_operations)
    # Inject a sentinel entry for each in-flight run/check so the poll loop
    # can show a spinner and knows which button is active.
    for pid in running:
        op = operations.get(pid, 'run')
        if pid not in snap:
            snap[pid] = {'protocol_id': pid, 'running': True, 'operation': op}
        else:
            snap[pid] = {**snap[pid], 'running': True, 'operation': op}
    return jsonify(snap)


@app.route('/build')
def build_page():
    return render_template_string(BUILD_TMPL, style=BASE_STYLE, base_js=BASE_JS)


@app.route('/api/provision_history/<protocol_id>')
def api_provision_history(protocol_id):
    from evidence_slice import load_provision_history
    paths = load_provision_history(protocol_id)
    current_path = ''
    proto = REGISTRY.get(protocol_id)
    if proto and 'golden_state' in proto:
        try:
            gs = proto['golden_state']()
            if gs:
                current_path = gs[0].get('golden_path', '') or ''
        except Exception:
            pass
    return jsonify({'paths': paths, 'current_path': current_path})


@app.route('/api/refresh_protocol_config/<protocol_id>', methods=['POST'])
def api_refresh_protocol_config(protocol_id):
    """Regenerate protocol_dirs/<protocol_id>/ by re-running the generator."""
    if protocol_id not in REGISTRY:
        return jsonify({'error': f"Unknown protocol '{protocol_id}'"}), 404
    meta = protocol_loader.get_protocol_dir_meta(protocol_id)
    if not meta.get('dynamic'):
        return jsonify({'error': f"Protocol '{protocol_id}' is not dynamic"}), 400
    try:
        import subprocess
        gen = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'generate_protocol_dirs.py')
        out_dir = protocol_loader._protocol_dirs_root()
        result = subprocess.run(
            ['python3', gen, '--protocols', protocol_id, '-o', out_dir],
            capture_output=True, text=True, timeout=60,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        if result.returncode != 0:
            return jsonify({'error': result.stdout + result.stderr}), 500
        return jsonify({'ok': True, 'output': result.stdout})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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


def _unique_copy_id(base_id):
    """Return 'copy_of_<base_id>' if unused, else 'copy_of_<base_id>_2', '_3', …"""
    candidate = f'copy_of_{base_id}'
    if candidate not in REGISTRY:
        return candidate
    n = 2
    while f'{candidate}_{n}' in REGISTRY:
        n += 1
    return f'{candidate}_{n}'


@app.route('/api/protocol_copy_spec/<protocol_id>')
def api_protocol_copy_spec(protocol_id):
    """Return a spec dict for any protocol (built-in or custom) for use by the copy page."""
    if protocol_id not in REGISTRY:
        return jsonify({'error': f'Unknown protocol: {protocol_id}'}), 404
    entry = REGISTRY[protocol_id]
    from flask import Response

    # Custom protocol backed by a single JSON file — return raw file bytes so
    # key order is preserved exactly, but inject a unique suggested_copy_id field.
    # (Dir-backed protocols also carry a custom_source, but it points at a
    # directory, so guard on isfile() and let them fall through to the
    # build_from_dir reconstruction branch below.)
    source = entry.get('custom_source')
    if source and os.path.isfile(source):
        try:
            raw = open(source).read()
            spec = json.loads(raw)
        except FileNotFoundError:
            return jsonify({'error': f'Source file not found: {source}'}), 404
        except json.JSONDecodeError as e:
            return jsonify({'error': f'Malformed source file: {e}'}), 400
        spec['_suggested_copy_id'] = _unique_copy_id(spec.get('id', protocol_id))
        return Response(json.dumps(spec), mimetype='application/json')

    # Built-in protocol — reconstruct spec from protocol_dirs/ or build()
    if protocol_loader.has_protocol_dir(entry['id']):
        manifest_obj, request_obj = protocol_loader.build_from_dir(entry['id'])
    else:
        manifest_str, request_str = entry['build']()
        manifest_obj = json.loads(manifest_str) if isinstance(manifest_str, str) else manifest_str
        request_obj  = json.loads(request_str)  if isinstance(request_str,  str) else request_str
    meta = protocol_loader.get_protocol_dir_meta(entry['id'])
    spec = {
        'id':                  entry['id'],
        'name':                meta.get('name',        entry.get('name', entry['id'])),
        'description':         meta.get('description', entry.get('description', '')),
        'copland':             meta.get('copland',     entry.get('copland', '')),
        'flow':                meta.get('flow',        entry.get('flow', [])),
        'manifest':            manifest_obj,
        'request':             request_obj,
        'targets':             [],
        '_suggested_copy_id':  _unique_copy_id(entry['id']),
    }
    return Response(json.dumps(spec), mimetype='application/json')


@app.route('/api/proto_overwrite_check')
def api_proto_overwrite_check():
    """
    Return whether registering a protocol with the given ID would overwrite
    an existing file on disk or shadow a built-in protocol.
    """
    proto_id = flask_request.args.get('id', '').strip()
    if not proto_id:
        return jsonify({'would_overwrite': False})

    # Check whether the built_protocols JSON file already exists
    built_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        'built_protocols', f'{proto_id}.json',
    )
    file_exists = os.path.exists(built_path)

    # Check registry membership (catches both custom and built-in collisions)
    in_registry  = proto_id in REGISTRY
    is_custom    = in_registry and bool(REGISTRY[proto_id].get('custom_source'))
    is_builtin   = in_registry and not is_custom
    existing_name = REGISTRY[proto_id].get('name', proto_id) if in_registry else None

    return jsonify({
        'would_overwrite': file_exists or in_registry,
        'file_exists':     file_exists,
        'file_path':       built_path if file_exists else None,
        'in_registry':     in_registry,
        'is_builtin':      is_builtin,
        'existing_name':   existing_name,
    })


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
    places_json      = data.get('places_json', '').strip()
    copy_source      = data.get('copy_source', '').strip()

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

    try:
        places_obj = json.loads(places_json) if places_json else None
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid places JSON: {e}'}), 400

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

    # If this is a copy of a stepped protocol, carry the steps forward.
    source_steps = None
    if copy_source and copy_source in REGISTRY:
        source_steps = REGISTRY[copy_source].get('steps') or None

    try:
        _, saved_path = protocol_builder.save_and_register(
            proto_id, name, description, copland,
            term_dict, manifest_obj, attestation_obj,
            evidence_obj, derived['targets'], derived['flow'],
            places=places_obj,
            steps=source_steps,
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    # Detect port conflicts with other registered protocols
    port_conflicts = []
    if places_obj:
        for existing_id, existing_entry in REGISTRY.items():
            if existing_id == proto_id:
                continue
            for ex_pid, ex_cfg in existing_entry.get('places', {}).items():
                for new_pid, new_cfg in places_obj.items():
                    if (int(ex_cfg.get('port', 0)) == int(new_cfg.get('port', 0)) and
                            ex_cfg.get('host', 'localhost') == new_cfg.get('host', 'localhost') and
                            ex_cfg != new_cfg):
                        port_conflicts.append({
                            'place_id':       new_pid,
                            'port':           new_cfg['port'],
                            'conflicts_with': existing_id,
                        })

    return jsonify({'ok': True, 'id': proto_id, 'name': name,
                    'saved_path': saved_path, 'port_conflicts': port_conflicts})


# ── Import-protocol-directory API ────────────────────────────────────────────

@app.route('/api/preview_protocol_dir')
def api_preview_protocol_dir():
    source = flask_request.args.get('path', '').strip()
    if not source:
        return jsonify({'error': 'path parameter required'}), 400
    result = protocol_loader.preview_protocol_dir(source)
    return jsonify(result)


@app.route('/api/import_protocol_dir', methods=['POST'])
def api_import_protocol_dir():
    data        = flask_request.get_json(force=True) or {}
    source_path = data.get('source_path', '').strip()
    if not source_path:
        return jsonify({'error': 'source_path required'}), 400
    try:
        proto_id = protocol_loader.add_protocol_dir(source_path)
    except (FileNotFoundError, ValueError) as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception as exc:
        return jsonify({'error': f'Import failed: {exc}'}), 500
    return jsonify({'ok': True, 'proto_id': proto_id})


@app.route('/api/protocols/<protocol_id>/import_info')
def api_import_info(protocol_id):
    """Return import metadata (source, stubs) for an imported protocol."""
    if protocol_id not in REGISTRY:
        return jsonify({'error': 'unknown protocol'}), 404
    entry = REGISTRY[protocol_id]
    if 'imported_dir' not in entry:
        return jsonify({'imported': False})
    local_dir = entry['imported_dir']
    return jsonify({
        'imported':  True,
        'source':    entry.get('custom_source', ''),
        'local_dir': local_dir,
    })


# ── Startup ───────────────────────────────────────────────────────────────────

# Auto-register every protocol_dirs/<id>/ directory at startup.
# This ensures that protocol_dir-backed protocols (which may use a different
# provision strategy than the code-defined REGISTRY entries in protocols.py)
# always override any stale builtin REGISTRY entries.
import sys as _sys
for _pid in protocol_loader.list_protocol_dir_ids():
    try:
        protocol_loader.register_protocol_dir(_pid)
    except Exception as _e:
        print(f'[dashboard] WARNING: could not auto-register protocol_dir {_pid!r}: {_e}',
              file=_sys.stderr)

# Re-register any protocol directories that were imported in previous sessions.
try:
    protocol_loader.load_saved_protocol_dirs()
except Exception as _e:
    print(f'[dashboard] WARNING: load_saved_protocol_dirs failed: {_e}', file=_sys.stderr)

# Re-register any protocol JSON files that were loaded in previous sessions.
_cfg = protocol_loader._load_config()
for _fpath in _cfg.get('files', []):
    try:
        protocol_loader.register_protocol_file(_fpath)
    except Exception as _e:
        import sys as _sys
        print(f'[dashboard] WARNING: could not re-register {_fpath}: {_e}', file=_sys.stderr)


if __name__ == '__main__':
    app.run(port=5050, debug=False, threaded=True)
