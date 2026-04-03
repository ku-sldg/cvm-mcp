"""
CVM Protocol Registry
Each entry defines a named Copland protocol with its term, session context,
manifest, and display metadata. Add new protocols here.
"""
import hashlib, datetime, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server as cvm

EXAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'examples')

ASP_REPLACE1 = {'FWD': {'FWD': 'REPLACE', '_BODY': 1}, 'ATTRS': []}
ASP_EXTEND1  = {'FWD': {'FWD': 'EXTEND',  '_BODY': 1, 'EvInSig': 'ALL'}, 'ATTRS': []}

def _hf_args(filepath, golden):
    return {'filepath': filepath, 'env_var': '',
            'filepath_golden': golden, 'env_var_golden': '',
            'asp_id_appr': 'hashfile_appr'}


# ── Protocol builders ─────────────────────────────────────────────────────────

def build_hsh_sig_appr():
    """lseq( lseq( hsh, SIG ), APPR )"""
    GOLDEN = f'{EXAMPLES}/hsh_golden.bin'
    hsh = cvm.term_custom_asp('hsh', asp_args={'env_var_golden': '', 'filepath_golden': GOLDEN})
    term = cvm.term_lseq(cvm.term_lseq(hsh, cvm.term_sig_asp()), cvm.term_appr_asp())
    sc = {
        'ASP_Types': {
            'hsh':          ASP_REPLACE1,
            'sig':          ASP_EXTEND1,
            'sig_appr':     ASP_REPLACE1,
            'hashfile_appr': ASP_REPLACE1,
        },
        'ASP_Comps': {'hsh': 'hashfile_appr', 'sig': 'sig_appr'},
    }
    manifest = cvm.build_manifest(asps=['hsh', 'sig', 'sig_appr', 'hashfile_appr'], asp_fs_map={}, policy=[])
    request  = cvm.build_run_request(session_plc='P0', req_plc='P0', term=term, session_context=sc)
    return manifest, request


def build_dual_hashfile_sig_appr():
    """lseq( lseq( bseq/both_paths( hashfile×2 ), SIG ), APPR )"""
    FILE1, FILE2 = f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/file2.txt'
    G1,    G2    = f'{EXAMPLES}/golden_file1.bin', f'{EXAMPLES}/golden_file2.bin'
    hf1  = cvm.term_custom_asp('hashfile', asp_args=_hf_args(FILE1, G1))
    hf2  = cvm.term_custom_asp('hashfile', asp_args=_hf_args(FILE2, G2))
    term = cvm.term_lseq(
        cvm.term_lseq(cvm.term_bseq('both_paths', hf1, hf2), cvm.term_sig_asp()),
        cvm.term_appr_asp()
    )
    sc = {
        'ASP_Types': {
            'hashfile':      ASP_REPLACE1,
            'sig':           ASP_EXTEND1,
            'sig_appr':      ASP_REPLACE1,
            'hashfile_appr': ASP_REPLACE1,
        },
        'ASP_Comps': {'hashfile': 'hashfile_appr', 'sig': 'sig_appr'},
    }
    manifest = cvm.build_manifest(asps=['hashfile', 'sig', 'sig_appr', 'hashfile_appr'], asp_fs_map={}, policy=[])
    request  = cvm.build_run_request(session_plc='P0', req_plc='P0', term=term, session_context=sc)
    return manifest, request


def build_single_hashfile_appr():
    """lseq( hashfile(file1), APPR )"""
    FILE1, G1 = f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/golden_file1.bin'
    hf   = cvm.term_custom_asp('hashfile', asp_args=_hf_args(FILE1, G1))
    term = cvm.term_lseq(hf, cvm.term_appr_asp())
    sc = {
        'ASP_Types': {'hashfile': ASP_REPLACE1, 'hashfile_appr': ASP_REPLACE1},
        'ASP_Comps': {'hashfile': 'hashfile_appr'},
    }
    manifest = cvm.build_manifest(asps=['hashfile', 'hashfile_appr'], asp_fs_map={}, policy=[])
    request  = cvm.build_run_request(session_plc='P0', req_plc='P0', term=term, session_context=sc)
    return manifest, request


# ── Provisioning helpers ──────────────────────────────────────────────────────

def _write_golden(path, data):
    """Hash data with SHA-256, write raw digest to path, and save source data to path.src."""
    digest = hashlib.sha256(data).digest()
    with open(path, 'wb') as f:
        f.write(digest)
    with open(path + '.src', 'wb') as f:
        f.write(data)
    return digest.hex()


def _read_golden(path):
    """Read an existing golden file and return its hex digest + mtime, or None."""
    import os
    try:
        mtime = os.path.getmtime(path)
        ts    = datetime.datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
        data  = open(path, 'rb').read()
        return {'sha256': data.hex(), 'timestamp': ts}
    except FileNotFoundError:
        return None


def _provision_builtin(proto_id, manifest_fn, request_fn, file_snapshots):
    """
    Run CVM (measurement-only term) and store the output as a golden evidence bundle.

    proto_id:       used to name the evidence file (examples/{proto_id}_evidence.json)
    manifest_fn:    callable returning (manifest_str, request_str) — same as build()
    request_fn:     same callable (manifest_fn == request_fn == build())
    file_snapshots: list of (file_path, golden_path) for .src/.original sidecar writes
    """
    from cvm_client import run_cvm
    from evidence_slice import store_golden_evidence
    from protocol_builder import _make_measurement_term

    ev_path = f'{EXAMPLES}/{proto_id}_evidence.json'
    asp_bin = os.environ.get(
        'CVM_ASP_BIN',
        os.path.expanduser('~/Claude_workspace/asp-libs/target/release'),
    )

    manifest_str, request_str = manifest_fn()
    request_obj = request_str if isinstance(request_str, dict) else json.loads(request_str)

    # Save per-file snapshots for repair/reset (alongside target file, not golden)
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    for file_path, golden_path in file_snapshots:
        try:
            content = open(file_path, 'rb').read()
            orig = file_path + '.original'
            if not os.path.exists(orig):
                open(orig, 'wb').write(content)
            open(file_path + '.src', 'wb').write(content)
        except FileNotFoundError:
            pass

    meas_term    = _make_measurement_term(request_obj.get('TERM', {}))
    meas_request = {**request_obj, 'TERM': meas_term}

    response = run_cvm(manifest_str, meas_request, asp_bin)
    if not response.get('SUCCESS'):
        raise RuntimeError(
            f"CVM provision failed for {proto_id}: {response.get('PAYLOAD', 'unknown')}"
        )

    payload = response['PAYLOAD']
    store_golden_evidence(ev_path, payload)

    # Populate shared target golden store for each measurement ASP in the term
    from evidence_slice import do_evidence_slice, store_target_golden
    from protocol_builder import inject_golden_b64   # re-use ASPC walker
    raw_ev    = payload[0].get('RawEv', [])
    et        = payload[1]
    asp_types = (request_obj.get('ATTESTATION_SESSION', {})
                             .get('Session_Context', {})
                             .get('ASP_Types', {}))

    def _collect_targets(term):
        if not isinstance(term, dict):
            return []
        ctor = term.get('TERM_CONSTRUCTOR', '')
        body = term.get('TERM_BODY')
        if ctor == 'asp' and isinstance(body, dict):
            if body.get('ASP_CONSTRUCTOR') == 'ASPC':
                ab = body.get('ASP_BODY', {})
                if ab.get('ASP_ARGS', {}).get('asp_id_appr'):
                    return [(ab.get('ASP_ID', ''), ab.get('ASP_ARGS', {}))]
            return []
        if ctor in ('lseq', 'bseq', 'bpar') and isinstance(body, list):
            return [t for c in body for t in _collect_targets(c)]
        if ctor == 'att' and isinstance(body, list) and len(body) == 2:
            return _collect_targets(body[1])
        return []

    for asp_id, asp_args in _collect_targets(request_obj.get('TERM', {})):
        ev_slice = do_evidence_slice(et, raw_ev, asp_types, asp_id, asp_args)
        if ev_slice:
            store_target_golden(asp_id, asp_args, ev_slice[0], proto_id, ev_path, ts)
            # Save original-golden sidecar for reset semantics (never overwritten)
            fp = os.path.abspath(os.path.expanduser(asp_args.get('filepath', '')))
            orig_golden = fp + '.original_golden.json' if fp else None
            if orig_golden and not os.path.exists(orig_golden):
                with open(orig_golden, 'w') as _f:
                    json.dump({
                        'golden_b64':      ev_slice[0],
                        'timestamp':       ts,
                        'asp_id':          asp_id,
                        'asp_args':        asp_args,
                        'protocol_id':     proto_id,
                        'evidence_bundle': os.path.basename(ev_path),
                    }, _f)

    return ev_path, ts


def _golden_state_builtin(proto_id, targets):
    """
    Return golden state list from the stored evidence bundle.

    targets: list of {'target', 'tamper_id'} dicts
    """
    from evidence_slice import load_golden_evidence
    ev_path = f'{EXAMPLES}/{proto_id}_evidence.json'
    _, _, ts = load_golden_evidence(ev_path)
    ev_name  = f'{proto_id}_evidence.json'
    return [
        {
            'target':    t['target'],
            'golden':    ev_name,
            'sha256':    None,
            'timestamp': ts,
            'tamper_id': t['tamper_id'],
        }
        for t in targets
    ]


def provision_single_hashfile_appr():
    FILE1, G1 = f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/golden_file1.bin'
    ev_path, ts = _provision_builtin(
        'single_hashfile_appr', build_single_hashfile_appr, build_single_hashfile_appr,
        [(FILE1, G1)],
    )
    return [{'target': 'file1.txt', 'golden': os.path.basename(ev_path),
             'sha256': None, 'timestamp': ts, 'tamper_id': 'file1'}]

def golden_state_single_hashfile_appr():
    return _golden_state_builtin('single_hashfile_appr',
                                 [{'target': 'file1.txt', 'tamper_id': 'file1'}])


def provision_hsh_sig_appr():
    GOLDEN = f'{EXAMPLES}/hsh_golden.bin'
    ev_path, ts = _provision_builtin(
        'hsh_sig_appr', build_hsh_sig_appr, build_hsh_sig_appr, [],
    )
    # hsh operates on empty evidence — snapshot the golden as a byte blob
    open(GOLDEN + '.src', 'wb').write(b'')
    if not os.path.exists(GOLDEN + '.original'):
        open(GOLDEN + '.original', 'wb').write(b'')
    return [{'target': '(empty evidence)', 'golden': os.path.basename(ev_path),
             'sha256': None, 'timestamp': ts, 'tamper_id': 'hsh_golden'}]

def golden_state_hsh_sig_appr():
    return _golden_state_builtin('hsh_sig_appr',
                                 [{'target': '(empty evidence)', 'tamper_id': 'hsh_golden'}])


def provision_dual_hashfile_sig_appr():
    FILE1, FILE2 = f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/file2.txt'
    G1,    G2    = f'{EXAMPLES}/golden_file1.bin', f'{EXAMPLES}/golden_file2.bin'
    ev_path, ts = _provision_builtin(
        'dual_hashfile_sig_appr', build_dual_hashfile_sig_appr, build_dual_hashfile_sig_appr,
        [(FILE1, G1), (FILE2, G2)],
    )
    ev_name = os.path.basename(ev_path)
    return [
        {'target': 'file1.txt', 'golden': ev_name, 'sha256': None,
         'timestamp': ts, 'tamper_id': 'file1'},
        {'target': 'file2.txt', 'golden': ev_name, 'sha256': None,
         'timestamp': ts, 'tamper_id': 'file2'},
    ]

def golden_state_dual_hashfile_sig_appr():
    return _golden_state_builtin('dual_hashfile_sig_appr', [
        {'target': 'file1.txt', 'tamper_id': 'file1'},
        {'target': 'file2.txt', 'tamper_id': 'file2'},
    ])


# ── Tamper / Repair helpers ───────────────────────────────────────────────────

_ORIG_HSH_GOLDEN = hashlib.sha256(b'').digest()
_BAD_HSH_GOLDEN  = bytes([0xff] * 32)


def _file_compliant(file_path, golden_path):
    """Return True if SHA256(current file) matches the binary golden (legacy fallback)."""
    try:
        current_hash = hashlib.sha256(open(file_path, 'rb').read()).digest()
        golden       = open(golden_path, 'rb').read()
        return current_hash == golden
    except FileNotFoundError:
        return False


def _tamper_file(file_path, golden_path, bad_bytes):
    """Write bad_bytes to file_path. golden_path kept for API compat (unused)."""
    open(file_path, 'wb').write(bad_bytes)


def _make_builtin_file_target(target_id, label, file_path, golden_path,
                               proto_id, asp_id, asp_args, asp_types):
    """
    Build a file tamper target that checks compliance via the shared target
    golden store (load_target_golden) rather than a binary golden file.
    """
    bad_bytes = f"[TAMPERED] {label} - modified to fail appraisal.".encode()

    def _get_golden_hash():
        from evidence_slice import load_target_golden
        import base64
        entry = load_target_golden(asp_id, asp_args)
        if entry:
            try:
                return base64.b64decode(entry['golden_b64'])
            except Exception:
                pass
        return None

    def tamper():
        golden_hash = _get_golden_hash()
        content, nonce = bad_bytes, 0
        while golden_hash and hashlib.sha256(content).digest() == golden_hash:
            nonce += 1
            content = bad_bytes + f'\n[TAMPER-NONCE-{nonce}]'.encode()
        open(file_path, 'wb').write(content)

    def repair():
        src     = file_path + '.src'
        default = file_path + '.default'
        if os.path.exists(src):
            content = open(src, 'rb').read()
        elif os.path.exists(default):
            content = open(default, 'rb').read()
        else:
            return
        open(file_path, 'wb').write(content)

    def reset():
        orig    = file_path + '.original'
        default = file_path + '.default'
        if os.path.exists(orig):
            content = open(orig, 'rb').read()
        elif os.path.exists(default):
            content = open(default, 'rb').read()
        else:
            return
        open(file_path, 'wb').write(content)
        # Restore original golden so compliance check passes after reset
        orig_golden = file_path + '.original_golden.json'
        if os.path.exists(orig_golden):
            from evidence_slice import store_target_golden
            try:
                entry = json.loads(open(orig_golden).read())
                store_target_golden(
                    asp_id, asp_args,
                    entry['golden_b64'],
                    entry.get('protocol_id', ''),
                    entry.get('evidence_bundle', ''),
                    entry.get('timestamp', ''),
                )
            except Exception:
                pass

    def get_state():
        golden_hash = _get_golden_hash()
        if golden_hash is None:
            return {'compliant': None}
        try:
            current = hashlib.sha256(open(file_path, 'rb').read()).digest()
            return {'compliant': current == golden_hash}
        except Exception:
            return {'compliant': None}

    def inspect():
        try:
            current_bytes = open(file_path, 'rb').read()
        except FileNotFoundError:
            return {'error': f'Target file not found: {label}'}
        result = {
            'type':           'file',
            'current':        current_bytes.decode('utf-8', errors='replace'),
            'current_sha256': hashlib.sha256(current_bytes).hexdigest(),
        }
        from evidence_slice import load_target_golden
        entry = load_target_golden(asp_id, asp_args)
        if entry is None:
            return {**result, 'error': 'No golden evidence — run Provision first'}
        import base64
        try:
            expected = base64.b64decode(entry['golden_b64'])
            result.update({
                'golden_sha256':   expected.hex(),
                'compliant':       hashlib.sha256(current_bytes).digest() == expected,
                'golden_timestamp': entry['timestamp'],
                'golden_protocol': entry['protocol_id'],
                'evidence_bundle': entry['evidence_bundle'],
            })
        except Exception as e:
            result['evidence_slice_error'] = str(e)
        src = file_path + '.src'
        if os.path.exists(src):
            result['provisioned'] = open(src, 'rb').read().decode('utf-8', errors='replace')
        return result

    return {
        'label':     label,
        'tamper':    tamper,
        'repair':    repair,
        'reset':     reset,
        'get_state': get_state,
        'inspect':   inspect,
    }


def tamper_hsh_golden():
    open(f'{EXAMPLES}/hsh_golden.bin', 'wb').write(_BAD_HSH_GOLDEN)

def repair_hsh_golden():
    open(f'{EXAMPLES}/hsh_golden.bin', 'wb').write(_ORIG_HSH_GOLDEN)

def reset_hsh_golden():
    open(f'{EXAMPLES}/hsh_golden.bin', 'wb').write(_ORIG_HSH_GOLDEN)

def get_state_hsh_golden():
    try:
        return {'compliant': open(f'{EXAMPLES}/hsh_golden.bin', 'rb').read() == _ORIG_HSH_GOLDEN}
    except FileNotFoundError:
        return {'compliant': False}

def inspect_hsh_golden():
    try:
        golden = open(f'{EXAMPLES}/hsh_golden.bin', 'rb').read()
    except FileNotFoundError:
        return {'error': 'Golden file not found — run Provision first'}
    return {
        'type':            'hsh',
        'compliant':       golden == _ORIG_HSH_GOLDEN,
        'expected_sha256': _ORIG_HSH_GOLDEN.hex(),
        'actual_sha256':   golden.hex(),
    }

def _prepare(req):
    """
    Inject golden_b64 into every ASPC's ASP_ARGS from the shared target golden
    store before each attestation run.  Protocol-agnostic — works for all protocols.
    """
    from protocol_builder import inject_golden_b64
    return {**req, 'TERM': inject_golden_b64(req.get('TERM', {}))}


_TAMPER_TARGET_HSH = {
    'label':     'hsh golden',
    'tamper':    tamper_hsh_golden,
    'repair':    repair_hsh_golden,
    'reset':     reset_hsh_golden,
    'get_state': get_state_hsh_golden,
    'inspect':   inspect_hsh_golden,
}


# ── Registry ──────────────────────────────────────────────────────────────────
# Flow entries:
#   {'type': 'asp',   'label': str, 'style': 'hsh|sig|appr|file|default'}
#   {'type': 'bseq',  'label': str, 'children': [str, ...]}
#   {'type': 'arrow'}

REGISTRY = {
    'single_hashfile_appr': {
        'id':          'single_hashfile_appr',
        'name':        'Single File Integrity',
        'description': 'Hash one file and appraise it against a golden value',
        'copland':     'lseq( hashfile(file1), APPR )',
        'flow': [
            {'type': 'asp', 'label': 'hashfile(file1.txt)', 'style': 'file'},
            {'type': 'arrow'},
            {'type': 'asp', 'label': 'APPR', 'style': 'appr'},
        ],
        'build':          build_single_hashfile_appr,
        'provision':      provision_single_hashfile_appr,
        'golden_state':   golden_state_single_hashfile_appr,
        'prepare':        _prepare,
        'tamper_targets': {
            'file1': _make_builtin_file_target(
                'file1', 'file1.txt',
                f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/golden_file1.bin',
                'single_hashfile_appr', 'hashfile',
                _hf_args(f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/golden_file1.bin'),
                {},
            ),
        },
    },
    'hsh_sig_appr': {
        'id':          'hsh_sig_appr',
        'name':        'Evidence Hash + Signature',
        'description': 'Hash evidence, sign it, then appraise both layers',
        'copland':     'lseq( lseq( hsh, SIG ), APPR )',
        'flow': [
            {'type': 'asp', 'label': 'hsh', 'style': 'hsh'},
            {'type': 'arrow'},
            {'type': 'asp', 'label': 'SIG', 'style': 'sig'},
            {'type': 'arrow'},
            {'type': 'asp', 'label': 'APPR', 'style': 'appr'},
        ],
        'build':          build_hsh_sig_appr,
        'provision':      provision_hsh_sig_appr,
        'golden_state':   golden_state_hsh_sig_appr,
        'tamper_targets': {'hsh_golden': _TAMPER_TARGET_HSH},
    },
    'dual_hashfile_sig_appr': {
        'id':          'dual_hashfile_sig_appr',
        'name':        'Dual File Hash + Signature',
        'description': 'Hash two files in parallel, sign combined evidence, appraise all layers',
        'copland':     'lseq( lseq( bseq/both_paths( hashfile×2 ), SIG ), APPR )',
        'flow': [
            {'type': 'bseq', 'label': 'bseq / both_paths',
             'children': ['hashfile(file1.txt)', 'hashfile(file2.txt)']},
            {'type': 'arrow'},
            {'type': 'asp', 'label': 'SIG', 'style': 'sig'},
            {'type': 'arrow'},
            {'type': 'asp', 'label': 'APPR', 'style': 'appr'},
        ],
        'build':          build_dual_hashfile_sig_appr,
        'provision':      provision_dual_hashfile_sig_appr,
        'golden_state':   golden_state_dual_hashfile_sig_appr,
        'prepare':        _prepare,
        'tamper_targets': {
            'file1': _make_builtin_file_target(
                'file1', 'file1.txt',
                f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/golden_file1.bin',
                'dual_hashfile_sig_appr', 'hashfile',
                _hf_args(f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/golden_file1.bin'),
                {},
            ),
            'file2': _make_builtin_file_target(
                'file2', 'file2.txt',
                f'{EXAMPLES}/file2.txt', f'{EXAMPLES}/golden_file2.bin',
                'dual_hashfile_sig_appr', 'hashfile',
                _hf_args(f'{EXAMPLES}/file2.txt', f'{EXAMPLES}/golden_file2.bin'),
                {},
            ),
        },
    },
}

# Load any protocol JSON files that were previously added via the dashboard
from protocol_loader import load_saved_protocols as _load_saved
for _path, _err in _load_saved():
    import sys
    print(f"[protocols] warning: could not load '{_path}': {_err}", file=sys.stderr)
