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


def build_bpar_dual_hashfile():
    """lseq( lseq( bpar/both_paths( hashfile×2 ), SIG ), APPR )

    Like dual_hashfile_sig_appr but uses bpar instead of bseq — the left
    branch runs as a CVM subprocess (Phase 1 parallel execution).
    """
    FILE1, FILE2 = f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/file2.txt'
    G1,    G2    = f'{EXAMPLES}/golden_file1.bin', f'{EXAMPLES}/golden_file2.bin'
    hf1  = cvm.term_custom_asp('hashfile', asp_args=_hf_args(FILE1, G1))
    hf2  = cvm.term_custom_asp('hashfile', asp_args=_hf_args(FILE2, G2))
    term = cvm.term_lseq(
        cvm.term_lseq(cvm.term_bpar('both_paths', hf1, hf2), cvm.term_sig_asp()),
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
    manifest = cvm.build_manifest(
        asps=['hashfile', 'sig', 'sig_appr', 'hashfile_appr'], asp_fs_map={}, policy=[])
    request  = cvm.build_run_request(
        session_plc='P0', req_plc='P0', term=term, session_context=sc)
    return manifest, request


def provision_bpar_dual_hashfile(golden_path=None):
    FILE1, FILE2 = f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/file2.txt'
    G1,    G2    = f'{EXAMPLES}/golden_file1.bin', f'{EXAMPLES}/golden_file2.bin'
    ev_path, ts = _provision_builtin(
        'bpar_dual_hashfile', build_bpar_dual_hashfile, build_bpar_dual_hashfile,
        [(FILE1, G1), (FILE2, G2)], golden_path=golden_path,
    )
    ev_name = os.path.basename(ev_path)
    return [
        {'target': 'file1.txt', 'golden': ev_name, 'sha256': None,
         'timestamp': ts, 'tamper_id': 'file1'},
        {'target': 'file2.txt', 'golden': ev_name, 'sha256': None,
         'timestamp': ts, 'tamper_id': 'file2'},
    ]


def golden_state_bpar_dual_hashfile():
    FILE1, FILE2 = f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/file2.txt'
    return _golden_state_builtin('bpar_dual_hashfile', [
        {'target': 'file1.txt', 'tamper_id': 'file1', 'filepath': FILE1},
        {'target': 'file2.txt', 'tamper_id': 'file2', 'filepath': FILE2},
    ])


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


def _provision_builtin(proto_id, manifest_fn, request_fn, file_snapshots,
                       golden_path=None):
    """
    Run CVM (measurement-only term) and store the output as a golden evidence bundle.

    proto_id:       used to name the evidence file (examples/{proto_id}_evidence.json)
    manifest_fn:    callable returning (manifest_str, request_str) — same as build()
    request_fn:     same callable (manifest_fn == request_fn == build())
    file_snapshots: list of (file_path, golden_path) for .original sidecar writes
    golden_path:    optional override for the output evidence bundle path
    """
    from cvm_client import run_cvm
    from evidence_slice import store_golden_evidence, load_golden_evidence
    from protocol_builder import _make_measurement_term

    ev_path = (os.path.abspath(os.path.expanduser(golden_path))
               if golden_path else f'{EXAMPLES}/{proto_id}_evidence.json')

    # Conflict check: refuse to overwrite a bundle owned by a different protocol
    _, _, _, owner = load_golden_evidence(ev_path)
    if owner and owner != proto_id:
        raise RuntimeError(
            f"Bundle '{os.path.basename(ev_path)}' was provisioned by "
            f"'{owner}', not '{proto_id}'. Choose a different path."
        )
    asp_bin = os.environ.get(
        'CVM_ASP_BIN',
        os.path.expanduser('~/Claude_workspace/asp-libs/target/release'),
    )

    manifest_str, request_str = manifest_fn()
    request_obj = request_str if isinstance(request_str, dict) else json.loads(request_str)

    # Save .original snapshot for reset (first provision only, never overwritten)
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    for file_path, golden_path in file_snapshots:
        try:
            orig = file_path + '.original'
            if not os.path.exists(orig):
                open(orig, 'wb').write(open(file_path, 'rb').read())
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
    store_golden_evidence(ev_path, payload, proto_id)

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
            orig_golden = fp + f'.{proto_id}.original_golden.json' if fp else None
            if orig_golden and not os.path.exists(orig_golden):
                # Always use the default bundle path in the sidecar so reset()
                # shows the protocol's canonical bundle name, not a custom path.
                default_ev_path = f'{EXAMPLES}/{proto_id}_evidence.json'
                with open(orig_golden, 'w') as _f:
                    json.dump({
                        'golden_b64':           ev_slice[0],
                        'timestamp':            ts,
                        'asp_id':               asp_id,
                        'asp_args':             asp_args,
                        'protocol_id':          proto_id,
                        'evidence_bundle':      os.path.basename(default_ev_path),
                        'evidence_bundle_path': default_ev_path,
                    }, _f)

    from evidence_slice import store_provision_path
    store_provision_path(proto_id, ev_path)

    return ev_path, ts


def _golden_state_builtin(proto_id, targets):
    """
    Return golden state list from the shared target golden store.

    targets: list of {'target', 'tamper_id', 'filepath'(optional)} dicts.
    When 'filepath' is present, the timestamp and bundle name are read from
    target_goldens.json so they stay accurate after a custom-path provision.
    """
    from evidence_slice import load_target_golden_by_file
    default_ev_name = f'{proto_id}_evidence.json'
    default_ev_path = f'{EXAMPLES}/{default_ev_name}'

    result = []
    for t in targets:
        ts, golden, golden_path = None, None, None
        if t.get('filepath'):
            # Source of truth is target_goldens.json — don't fall back to the
            # bundle file, which may exist from a prior/different provision.
            entry = load_target_golden_by_file(t['filepath'], proto_id=proto_id)
            if entry:
                ts          = entry.get('timestamp', '')
                golden      = entry.get('evidence_bundle')
                golden_path = entry.get('evidence_bundle_path') or None
        result.append({
            'target':      t['target'],
            'golden':      golden,
            'golden_path': golden_path,
            'sha256':      None,
            'timestamp':   ts,
            'tamper_id':   t['tamper_id'],
        })
    return result


def provision_single_hashfile_appr(golden_path=None):
    FILE1, G1 = f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/golden_file1.bin'
    ev_path, ts = _provision_builtin(
        'single_hashfile_appr', build_single_hashfile_appr, build_single_hashfile_appr,
        [(FILE1, G1)], golden_path=golden_path,
    )
    return [{'target': 'file1.txt', 'golden': os.path.basename(ev_path),
             'sha256': None, 'timestamp': ts, 'tamper_id': 'file1'}]

def golden_state_single_hashfile_appr():
    FILE1 = f'{EXAMPLES}/file1.txt'
    return _golden_state_builtin('single_hashfile_appr',
                                 [{'target': 'file1.txt', 'tamper_id': 'file1',
                                   'filepath': FILE1}])


def provision_hsh_sig_appr(golden_path=None):
    GOLDEN = f'{EXAMPLES}/hsh_golden.bin'
    ev_path, ts = _provision_builtin(
        'hsh_sig_appr', build_hsh_sig_appr, build_hsh_sig_appr, [],
        golden_path=golden_path,
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


def provision_dual_hashfile_sig_appr(golden_path=None):
    FILE1, FILE2 = f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/file2.txt'
    G1,    G2    = f'{EXAMPLES}/golden_file1.bin', f'{EXAMPLES}/golden_file2.bin'
    ev_path, ts = _provision_builtin(
        'dual_hashfile_sig_appr', build_dual_hashfile_sig_appr, build_dual_hashfile_sig_appr,
        [(FILE1, G1), (FILE2, G2)], golden_path=golden_path,
    )
    ev_name = os.path.basename(ev_path)
    return [
        {'target': 'file1.txt', 'golden': ev_name, 'sha256': None,
         'timestamp': ts, 'tamper_id': 'file1'},
        {'target': 'file2.txt', 'golden': ev_name, 'sha256': None,
         'timestamp': ts, 'tamper_id': 'file2'},
    ]

def golden_state_dual_hashfile_sig_appr():
    FILE1, FILE2 = f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/file2.txt'
    return _golden_state_builtin('dual_hashfile_sig_appr', [
        {'target': 'file1.txt', 'tamper_id': 'file1', 'filepath': FILE1},
        {'target': 'file2.txt', 'tamper_id': 'file2', 'filepath': FILE2},
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
        entry = load_target_golden(asp_id, asp_args, proto_id)
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
        try:
            open(file_path + '.src', 'wb').write(open(file_path, 'rb').read())
        except FileNotFoundError:
            pass
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
        orig_golden = file_path + f'.{proto_id}.original_golden.json'
        if os.path.exists(orig_golden):
            from evidence_slice import store_target_golden
            try:
                entry = json.loads(open(orig_golden).read())
                store_target_golden(
                    asp_id, asp_args,
                    entry['golden_b64'],
                    entry.get('protocol_id', ''),
                    entry.get('evidence_bundle_path', entry.get('evidence_bundle', '')),
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
        entry = load_target_golden(asp_id, asp_args, proto_id)
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
            result['pre_tamper'] = open(src, 'rb').read().decode('utf-8', errors='replace')
        orig = file_path + '.original'
        if os.path.exists(orig):
            result['original'] = open(orig, 'rb').read().decode('utf-8', errors='replace')
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

def _make_prepare(proto_id):
    """Return a prepare() function that injects golden_b64 for the given protocol."""
    def _prepare(req):
        from protocol_builder import inject_golden_b64
        return {**req, 'TERM': inject_golden_b64(req.get('TERM', {}), proto_id)}
    return _prepare


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
        'prepare':        _make_prepare('single_hashfile_appr'),
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
        'prepare':        _make_prepare('dual_hashfile_sig_appr'),
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
    'bpar_dual_hashfile': {
        'id':          'bpar_dual_hashfile',
        'name':        'Parallel Dual File Hash (bpar)',
        'description': (
            'Hash two files using bpar (branching parallel) — left branch runs '
            'as a CVM subprocess, right branch in the current process. '
            'Sign the combined evidence, then appraise all layers.'
        ),
        'copland':     'lseq( lseq( bpar/both_paths( hashfile×2 ), SIG ), APPR )',
        'flow': [
            {'type': 'bpar', 'label': 'bpar / both_paths',
             'children': ['hashfile(file1.txt)', 'hashfile(file2.txt)']},
            {'type': 'arrow'},
            {'type': 'asp', 'label': 'SIG', 'style': 'sig'},
            {'type': 'arrow'},
            {'type': 'asp', 'label': 'APPR', 'style': 'appr'},
        ],
        'build':          build_bpar_dual_hashfile,
        'provision':      provision_bpar_dual_hashfile,
        'golden_state':   golden_state_bpar_dual_hashfile,
        'prepare':        _make_prepare('bpar_dual_hashfile'),
        'tamper_targets': {
            'file1': _make_builtin_file_target(
                'file1', 'file1.txt',
                f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/golden_file1.bin',
                'bpar_dual_hashfile', 'hashfile',
                _hf_args(f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/golden_file1.bin'),
                {},
            ),
            'file2': _make_builtin_file_target(
                'file2', 'file2.txt',
                f'{EXAMPLES}/file2.txt', f'{EXAMPLES}/golden_file2.bin',
                'bpar_dual_hashfile', 'hashfile',
                _hf_args(f'{EXAMPLES}/file2.txt', f'{EXAMPLES}/golden_file2.bin'),
                {},
            ),
        },
    },
}

# ── GUMBO Contract Integrity Protocols ────────────────────────────────────────
#
# Two-level attestation for HAMR-generated GUMBO contracts:
#
#   gumbo_l1  (Level 1 — fast path)
#     Hashes the AADL model files and GumboX oracle files as a whole.
#     Fast check: if these files are unmodified we know the "do not edit"
#     artifacts are intact.  Component implementation files are intentionally
#     excluded here because developers legitimately add implementation code.
#
#   gumbo_l2  (Level 2 — attribution)
#     Per-contract range measurements that identify WHICH specific contract
#     was tampered when Level 1 fails (or as a standalone invariant check).
#     Uses readfile_range for AADL clauses and GumboX predicates (stable line
#     numbers in "do not edit" files) and readfile_marker_range for component
#     BEGIN/END contract blocks (stable marker strings despite shifting line
#     numbers as implementation code grows).

_BASE_TC  = os.path.expanduser('~/Claude_workspace/temp-control-jvm')
_AADL_TC  = f'{_BASE_TC}/aadl/packages/TempControlSystem.aadl'
_AADL_TS  = f'{_BASE_TC}/aadl/packages/TempSensor.aadl'
_GUMBOX_TC = (f'{_BASE_TC}/slang/src/main/bridge/tc/TempControlSoftwareSystem/'
              'TempControlPeriodic_p_tcproc_tempControl_GumboX.scala')
_GUMBOX_TS = (f'{_BASE_TC}/slang/src/main/bridge/tc/TempSensor/'
              'TempSensorPeriodic_p_tcproc_tempSensor_GumboX.scala')
_COMP_TC   = (f'{_BASE_TC}/slang/src/main/component/tc/TempControlSoftwareSystem/'
              'TempControlPeriodic_p_tcproc_tempControl.scala')
_COMP_TS   = (f'{_BASE_TC}/slang/src/main/component/tc/TempSensor/'
              'TempSensorPeriodic_p_tcproc_tempSensor.scala')


def _rfr_args(filepath, start_index, end_index):
    """ASP args for readfile_range + readfile_appr appraiser."""
    return {
        'filepath':       filepath,
        'start_index':    start_index,
        'end_index':      end_index,
        'env_var_golden': '',
        'filepath_golden': '',   # golden_b64 injected at attestation time
        'asp_id_appr':   'readfile_appr',
    }


def _rfmr_args(filepath, begin_marker, end_marker):
    """ASP args for readfile_marker_range + readfile_appr appraiser."""
    return {
        'filepath':       filepath,
        'begin_marker':   begin_marker,
        'end_marker':     end_marker,
        'env_var_golden': '',
        'filepath_golden': '',   # golden_b64 injected at attestation time
        'asp_id_appr':   'readfile_appr',
    }


def _bseq_chain(terms):
    """Left-fold a list of Copland terms into nested bseq(both_paths, ...)."""
    if not terms:
        return cvm.term_null_asp()
    result = terms[0]
    for t in terms[1:]:
        result = cvm.term_bseq('both_paths', result, t)
    return result


def _bpar_chain(terms):
    """Right-fold a list of Copland terms into nested bpar(both_paths, ...).

    Each bpar spawns a CVM subprocess for its left branch while the main
    process continues into the right branch.  Right-folding means all N terms
    are dispatched before any result is awaited, so all N run concurrently.
    Wall time ≈ max(individual step times) rather than their sum.
    """
    if not terms:
        return cvm.term_null_asp()
    if len(terms) == 1:
        return terms[0]
    result = terms[-1]
    for t in reversed(terms[:-1]):
        result = cvm.term_bpar('both_paths', t, result)
    return result


# ── Content-extraction helpers (mirror Rust ASP behavior) ──────────────────────

def _extract_line_range(filepath, start_index, end_index):
    """Extract lines [start_index, end_index] (1-based, inclusive) as flat bytes.
    Matches readfile_range ASP: lines joined without newline separators."""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    selected = lines[start_index - 1: end_index]
    return b''.join(line.rstrip('\n').encode('utf-8', errors='replace')
                    for line in selected)


def _marker_matches_comment(line, marker):
    """Exact comment-line match: marker must be sole content after optional //.

    Mirrors marker_matches() in readfile_marker_range/src/main.rs.
    Prevents developer comments that merely *contain* a marker string from
    triggering a false boundary match.
    """
    stripped = line.strip()
    if stripped.startswith('//'):
        content = stripped[2:].strip()
    else:
        content = stripped
    return content == marker


def _extract_marker_range(filepath, begin_marker, end_marker):
    """Extract content between begin/end marker strings as flat bytes.
    Matches readfile_marker_range ASP: lines joined without newline separators.
    Markers are matched by exact comment-line comparison (see _marker_matches_comment)."""
    result = []
    in_range = False
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for raw_line in f:
            line = raw_line.rstrip('\n')
            if not in_range and _marker_matches_comment(line, begin_marker):
                in_range = True
                result.append(line.encode('utf-8', errors='replace'))
                continue
            if in_range:
                result.append(line.encode('utf-8', errors='replace'))
                if _marker_matches_comment(line, end_marker):
                    break
    return b''.join(result)


# ── Per-contract tamper helpers ────────────────────────────────────────────────

def _corrupt_lines(filepath, start_index, end_index, label):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    for i in range(start_index - 1, min(end_index, len(lines))):
        indent = len(lines[i]) - len(lines[i].lstrip())
        lines[i] = ' ' * indent + f'// [TAMPERED: {label}]\n'
    with open(filepath, 'w', encoding='utf-8') as f:
        f.writelines(lines)


def _corrupt_marker_range(filepath, begin_marker, end_marker, label):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    in_range = False
    for i, line in enumerate(lines):
        stripped = line.rstrip('\n')
        if not in_range and _marker_matches_comment(stripped, begin_marker):
            in_range = True
            continue
        if in_range:
            if _marker_matches_comment(stripped, end_marker):
                break
            indent = len(line) - len(line.lstrip())
            lines[i] = ' ' * indent + f'// [TAMPERED: {label}]\n'
    with open(filepath, 'w', encoding='utf-8') as f:
        f.writelines(lines)


# ── Generic per-contract tamper target factory ────────────────────────────────

def _make_contract_target(label, filepath, asp_id, args_fn, proto_id, extract_fn):
    """
    Build a tamper target dict for a per-contract range measurement.

    args_fn:    callable() -> dict   returns current ASP args (called live so
                line-number resolution is always up to date)
    extract_fn: callable(filepath) -> bytes   extracts current contract content
    """
    def _get_golden_bytes():
        from evidence_slice import load_target_golden
        import base64
        entry = load_target_golden(asp_id, args_fn(), proto_id)
        if entry is None:
            return None
        return base64.b64decode(entry['golden_b64'])

    def tamper():
        try:
            open(filepath + '.src', 'wb').write(open(filepath, 'rb').read())
        except FileNotFoundError:
            pass
        args = args_fn()
        if asp_id == 'readfile_range':
            _corrupt_lines(filepath, args['start_index'], args['end_index'], label)
        elif asp_id == 'readfile_marker_range':
            _corrupt_marker_range(filepath, args['begin_marker'],
                                  args['end_marker'], label)

    def repair():
        src = filepath + '.src'
        if os.path.exists(src):
            open(filepath, 'wb').write(open(src, 'rb').read())

    def reset():
        orig = filepath + '.original'
        if os.path.exists(orig):
            open(filepath, 'wb').write(open(orig, 'rb').read())

    def get_state():
        golden = _get_golden_bytes()
        if golden is None:
            return {'compliant': None}
        try:
            current = extract_fn(filepath)
            return {'compliant': current == golden}
        except Exception:
            return {'compliant': None}

    def inspect():
        try:
            current_bytes = extract_fn(filepath)
        except Exception as e:
            return {'error': str(e)}
        result = {
            'type':           'contract_range',
            'current_sha256': hashlib.sha256(current_bytes).hexdigest(),
            'current':        current_bytes.decode('utf-8', errors='replace'),
        }
        golden = _get_golden_bytes()
        if golden is None:
            return {**result, 'error': 'No golden — run Provision first'}
        result['compliant']      = current_bytes == golden
        result['golden_sha256']  = hashlib.sha256(golden).hexdigest()
        return result

    return {
        'label':     label,
        'tamper':    tamper,
        'repair':    repair,
        'reset':     reset,
        'get_state': get_state,
        'inspect':   inspect,
    }


# ── Level 1: whole-file hashfile measurements ─────────────────────────────────

_GUMBO_L1_FILES = [
    (_AADL_TC,   'TempControlSystem.aadl',        'aadl_tc'),
    (_AADL_TS,   'TempSensor.aadl',               'aadl_ts'),
    (_GUMBOX_TC, 'TempControl_GumboX.scala',      'gumbox_tc'),
    (_GUMBOX_TS, 'TempSensor_GumboX.scala',       'gumbox_ts'),
]


def build_gumbo_l1():
    """lseq( lseq( bseq_chain( 4 hashfiles ), SIG ), APPR )"""
    measurements = [
        cvm.term_custom_asp('hashfile', asp_args=_hf_args(fp, ''))
        for fp, _, _ in _GUMBO_L1_FILES
    ]
    term = cvm.term_lseq(
        cvm.term_lseq(_bseq_chain(measurements), cvm.term_sig_asp()),
        cvm.term_appr_asp(),
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
    manifest = cvm.build_manifest(
        asps=['hashfile', 'sig', 'sig_appr', 'hashfile_appr'], asp_fs_map={}, policy=[])
    request = cvm.build_run_request(
        session_plc='P0', req_plc='P0', term=term, session_context=sc)
    return manifest, request


def provision_gumbo_l1(golden_path=None):
    file_snapshots = [(fp, '') for fp, _, _ in _GUMBO_L1_FILES]
    ev_path, ts = _provision_builtin(
        'gumbo_l1', build_gumbo_l1, build_gumbo_l1,
        file_snapshots, golden_path=golden_path,
    )
    ev_name = os.path.basename(ev_path)
    return [
        {'target': label, 'golden': ev_name, 'sha256': None,
         'timestamp': ts, 'tamper_id': tid}
        for _, label, tid in _GUMBO_L1_FILES
    ]


def golden_state_gumbo_l1():
    return _golden_state_builtin('gumbo_l1', [
        {'target': label, 'tamper_id': tid, 'filepath': fp}
        for fp, label, tid in _GUMBO_L1_FILES
    ])


def _gumbo_l1_tamper_targets():
    targets = {}
    for fp, label, tid in _GUMBO_L1_FILES:
        args = _hf_args(fp, '')
        targets[tid] = _make_builtin_file_target(
            tid, label, fp, '', 'gumbo_l1', 'hashfile', args, {})
    return targets


# ── Level 2: per-contract range measurements ──────────────────────────────────
#
# Contract spec types:
#   aadl_clause  — scans for 'guarantee/assume NAME' at provision time, measures
#                  by line range (readfile_range).  Line numbers resolved live so
#                  they track the current file state.
#   strictpure   — scans for '@strictpure def NAME' at provision time, measures
#                  by line range (readfile_range).
#   marker       — uses stable BEGIN/END marker strings (readfile_marker_range).
#                  Immune to line number drift; intended for component files.
#
# Rows: (label, tamper_id, filepath, spec_dict)

_GUMBO_L2_CONTRACTS = [
    # ── AADL TempControlSystem.aadl data invariant ───────────────────────────
    ('AADL: inv SetPoint_Data_Invariant',    'aadl_tc_inv_setpoint',  _AADL_TC,
     {'type': 'aadl_inv', 'name': 'SetPoint_Data_Invariant'}),
    # ── AADL TempControlSystem.aadl GUMBO clauses ────────────────────────────
    ('AADL: assume currentTempInputRange',   'aadl_tc_assume_range',  _AADL_TC,
     {'type': 'aadl_clause', 'name': 'currentTempInputRange'}),
    ('AADL: guarantee initLatestFanCmd',     'aadl_tc_init_fan_cmd',  _AADL_TC,
     {'type': 'aadl_clause', 'name': 'initLatestFanCmd'}),
    ('AADL: guarantee initFanCmd',           'aadl_tc_init_fan',      _AADL_TC,
     {'type': 'aadl_clause', 'name': 'initFanCmd'}),
    ('AADL: guarantee altTempLTSetPoint',    'aadl_tc_lt',            _AADL_TC,
     {'type': 'aadl_clause', 'name': 'altCurrentTempLTSetPoint'}),
    ('AADL: guarantee altTempGTSetPoint',    'aadl_tc_gt',            _AADL_TC,
     {'type': 'aadl_clause', 'name': 'altCurrentTempGTSetPoint'}),
    ('AADL: guarantee altTempInRange',       'aadl_tc_inrange',       _AADL_TC,
     {'type': 'aadl_clause', 'name': 'altCurrentTempInRange'}),
    # ── AADL TempSensor.aadl GUMBO clauses ───────────────────────────────────
    ('AADL: guarantee currentTempOutputRange', 'aadl_ts_output_range', _AADL_TS,
     {'type': 'aadl_clause', 'name': 'currentTempOutputRange'}),
    ('AADL: guarantee currentTempInitialVal',  'aadl_ts_init_val',     _AADL_TS,
     {'type': 'aadl_clause', 'name': 'currentTempInitialVal'}),
    # ── GumboX TempControl @strictpure predicates ─────────────────────────────
    ('GumboX TC: I_Assm_currentTemp',          'gumbox_tc_assm',       _GUMBOX_TC,
     {'type': 'strictpure', 'name': 'I_Assm_currentTemp'}),
    ('GumboX TC: initialize_initLatestFanCmd', 'gumbox_tc_init_lfc',   _GUMBOX_TC,
     {'type': 'strictpure', 'name': 'initialize_initLatestFanCmd'}),
    ('GumboX TC: initialize_initFanCmd',       'gumbox_tc_init_fc',    _GUMBOX_TC,
     {'type': 'strictpure', 'name': 'initialize_initFanCmd'}),
    ('GumboX TC: compute_spec_LTSetPoint',     'gumbox_tc_spec_lt',    _GUMBOX_TC,
     {'type': 'strictpure', 'name': 'compute_spec_altCurrentTempLTSetPoint_guarantee'}),
    ('GumboX TC: compute_spec_GTSetPoint',     'gumbox_tc_spec_gt',    _GUMBOX_TC,
     {'type': 'strictpure', 'name': 'compute_spec_altCurrentTempGTSetPoint_guarantee'}),
    ('GumboX TC: compute_spec_InRange',        'gumbox_tc_spec_inrange', _GUMBOX_TC,
     {'type': 'strictpure', 'name': 'compute_spec_altCurrentTempInRange_guarantee'}),
    ('GumboX TC: compute_case_LTSetPoint',    'gumbox_tc_case_lt',    _GUMBOX_TC,
     {'type': 'strictpure', 'name': 'compute_case_currentTempLTSetPoint'}),
    ('GumboX TC: compute_case_GTSetPoint',    'gumbox_tc_case_gt',    _GUMBOX_TC,
     {'type': 'strictpure', 'name': 'compute_case_currentTempGTSetPoint'}),
    ('GumboX TC: compute_case_InRange',       'gumbox_tc_case_inrange', _GUMBOX_TC,
     {'type': 'strictpure', 'name': 'compute_case_currentTempInRange'}),
    # ── GumboX TempSensor @strictpure predicates ──────────────────────────────
    ('GumboX TS: I_Guar_currentTemp',          'gumbox_ts_guar',       _GUMBOX_TS,
     {'type': 'strictpure', 'name': 'I_Guar_currentTemp'}),
    ('GumboX TS: initialize_initializes',      'gumbox_ts_init',       _GUMBOX_TS,
     {'type': 'strictpure', 'name': 'initialize_initializes'}),
    ('GumboX TS: inititialize_IEP_Post',      'gumbox_ts_iep_post',   _GUMBOX_TS,
     {'type': 'strictpure', 'name': 'inititialize_IEP_Post'}),
    ('GumboX TS: compute_CEP_Post',           'gumbox_ts_cep_post',   _GUMBOX_TS,
     {'type': 'strictpure', 'name': 'compute_CEP_Post'}),
    # ── Component TempControl BEGIN/END contract blocks ───────────────────────
    ('TC Component: STATE VARS',               'comp_tc_state_vars',   _COMP_TC,
     {'type': 'marker', 'begin': 'BEGIN STATE VARS',
                        'end':   'END STATE VARS'}),
    ('TC Component: COMPUTE MODIFIES',         'comp_tc_compute_mod',  _COMP_TC,
     {'type': 'marker', 'begin': 'BEGIN COMPUTE MODIFIES timeTriggered',
                        'end':   'END COMPUTE MODIFIES timeTriggered'}),
    ('TC Component: COMPUTE ENSURES',          'comp_tc_compute_ens',  _COMP_TC,
     {'type': 'marker', 'begin': 'BEGIN COMPUTE ENSURES timeTriggered',
                        'end':   'END COMPUTE ENSURES timeTriggered'}),
    ('TC Component: INITIALIZES MODIFIES',       'comp_tc_init_mod',     _COMP_TC,
     {'type': 'marker', 'begin': 'BEGIN INITIALIZES MODIFIES',
                        'end':   'END INITIALIZES MODIFIES'}),
    ('TC Component: INITIALIZES ENSURES',        'comp_tc_init_ens',     _COMP_TC,
     {'type': 'marker', 'begin': 'BEGIN INITIALIZES ENSURES',
                        'end':   'END INITIALIZES ENSURES'}),
    # ── Component TempSensor BEGIN/END contract blocks ────────────────────────
    ('TS Component: INITIALIZES ENSURES',      'comp_ts_init_ens',     _COMP_TS,
     {'type': 'marker', 'begin': 'BEGIN INITIALIZES ENSURES',
                        'end':   'END INITIALIZES ENSURES'}),
]


# ── File scanners: resolve line numbers at provision / build time ──────────────

def _find_aadl_clause_lines(filepath, clause_name):
    """Return (start, end) 1-based line numbers for 'guarantee/assume clause_name'.

    Scans from the matching keyword line to the first ';' terminator.
    Called live so line numbers always reflect the current file state.
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    start = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if (f'guarantee {clause_name}' in stripped or
                f'assume {clause_name}' in stripped):
            start = i + 1   # 1-based
            break
    if start is None:
        raise ValueError(f"AADL clause '{clause_name}' not found in {filepath}")
    end = start
    for i in range(start - 1, len(lines)):
        end = i + 1
        if ';' in lines[i]:
            break
    return start, end


def _find_aadl_inv_lines(filepath, inv_name):
    """Return (start, end) 1-based line numbers for 'inv inv_name' in an AADL GUMBO annex.

    Scans from the matching 'inv NAME' line to the first ';' terminator.
    Called live so line numbers always reflect the current file state.
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    start = None
    for i, line in enumerate(lines):
        if f'inv {inv_name}' in line.strip():
            start = i + 1   # 1-based
            break
    if start is None:
        raise ValueError(f"AADL invariant '{inv_name}' not found in {filepath}")
    end = start
    for i in range(start - 1, len(lines)):
        end = i + 1
        if ';' in lines[i]:
            break
    return start, end


def _find_strictpure_lines(filepath, func_name):
    """Return (start, end) 1-based line numbers for '@strictpure def func_name'.

    Scans from the matching @strictpure line to the last non-blank line before
    the next blank line (which separates predicates in GumboX files).
    Called live so line numbers always reflect the current file state.
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    start = None
    for i, line in enumerate(lines):
        if '@strictpure def ' + func_name in line:
            start = i + 1   # 1-based
            break
    if start is None:
        raise ValueError(
            f"@strictpure def {func_name} not found in {filepath}")
    end = start
    body_started = False
    for i in range(start - 1, len(lines)):
        stripped = lines[i].rstrip()
        if stripped:
            end = i + 1     # last non-blank line so far
            body_started = True
        elif body_started:
            break           # blank line ends the predicate body
    return start, end


# ── Spec → ASP helpers ────────────────────────────────────────────────────────

def _asp_id_for_spec(spec):
    return 'readfile_marker_range' if spec['type'] == 'marker' else 'readfile_range'


def _resolve_args(filepath, spec):
    """Build ASP args by resolving line numbers from the current file state."""
    stype = spec['type']
    if stype == 'aadl_clause':
        start, end = _find_aadl_clause_lines(filepath, spec['name'])
        return _rfr_args(filepath, start, end)
    elif stype == 'aadl_inv':
        start, end = _find_aadl_inv_lines(filepath, spec['name'])
        return _rfr_args(filepath, start, end)
    elif stype == 'strictpure':
        start, end = _find_strictpure_lines(filepath, spec['name'])
        return _rfr_args(filepath, start, end)
    else:   # marker
        return _rfmr_args(filepath, spec['begin'], spec['end'])


def _resolve_extract_fn(filepath, spec):
    """Return a callable(path) -> bytes that extracts the contract content."""
    stype = spec['type']
    if stype == 'marker':
        b, e = spec['begin'], spec['end']
        return lambda path, b=b, e=e: _extract_marker_range(path, b, e)
    elif stype == 'aadl_clause':
        name = spec['name']
        def _extract(path, n=name):
            s, e = _find_aadl_clause_lines(path, n)
            return _extract_line_range(path, s, e)
        return _extract
    elif stype == 'aadl_inv':
        name = spec['name']
        def _extract(path, n=name):
            s, e = _find_aadl_inv_lines(path, n)
            return _extract_line_range(path, s, e)
        return _extract
    else:   # strictpure
        name = spec['name']
        def _extract(path, n=name):
            s, e = _find_strictpure_lines(path, n)
            return _extract_line_range(path, s, e)
        return _extract


# ── build / provision / golden_state / tamper_targets ────────────────────────

def build_gumbo_l2():
    """lseq( lseq( bseq_chain( 28 per-contract measurements ), SIG ), APPR )

    Line numbers for AADL and GumboX entries are resolved by scanning the
    current file state at build time.
    """
    measurements = [
        cvm.term_custom_asp(_asp_id_for_spec(spec),
                            asp_args=_resolve_args(fp, spec))
        for _, _, fp, spec in _GUMBO_L2_CONTRACTS
    ]
    term = cvm.term_lseq(
        cvm.term_lseq(_bseq_chain(measurements), cvm.term_sig_asp()),
        cvm.term_appr_asp(),
    )
    sc = {
        'ASP_Types': {
            'readfile_range':        ASP_REPLACE1,
            'readfile_marker_range': ASP_REPLACE1,
            'readfile_appr':         ASP_REPLACE1,
            'sig':                   ASP_EXTEND1,
            'sig_appr':              ASP_REPLACE1,
        },
        'ASP_Comps': {
            'readfile_range':        'readfile_appr',
            'readfile_marker_range': 'readfile_appr',
            'sig':                   'sig_appr',
        },
    }
    manifest = cvm.build_manifest(
        asps=['readfile_range', 'readfile_marker_range', 'readfile_appr',
              'sig', 'sig_appr'],
        asp_fs_map={}, policy=[])
    request = cvm.build_run_request(
        session_plc='P0', req_plc='P0', term=term, session_context=sc)
    return manifest, request


def provision_gumbo_l2(golden_path=None):
    seen = set()
    file_snapshots = []
    for _, _, fp, _ in _GUMBO_L2_CONTRACTS:
        if fp not in seen:
            seen.add(fp)
            file_snapshots.append((fp, ''))
    ev_path, ts = _provision_builtin(
        'gumbo_l2', build_gumbo_l2, build_gumbo_l2,
        file_snapshots, golden_path=golden_path,
    )
    ev_name = os.path.basename(ev_path)
    return [
        {'target': label, 'golden': ev_name, 'sha256': None,
         'timestamp': ts, 'tamper_id': tid}
        for label, tid, _, _ in _GUMBO_L2_CONTRACTS
    ]


def golden_state_gumbo_l2():
    from evidence_slice import load_target_golden
    result = []
    for label, tid, fp, spec in _GUMBO_L2_CONTRACTS:
        asp_id = _asp_id_for_spec(spec)
        try:
            args = _resolve_args(fp, spec)
        except Exception:
            args = {}
        entry = load_target_golden(asp_id, args, 'gumbo_l2')
        result.append({
            'target':      label,
            'golden':      entry['evidence_bundle'] if entry else None,
            'golden_path': entry.get('evidence_bundle_path') if entry else None,
            'sha256':      None,
            'timestamp':   entry['timestamp'] if entry else None,
            'tamper_id':   tid,
        })
    return result


def _gumbo_l2_tamper_targets():
    targets = {}
    for label, tid, fp, spec in _GUMBO_L2_CONTRACTS:
        asp_id     = _asp_id_for_spec(spec)
        extract_fn = _resolve_extract_fn(fp, spec)
        # args_fn resolves line numbers live each time it is called
        def make_args_fn(filepath, s):
            return lambda: _resolve_args(filepath, s)
        targets[tid] = _make_contract_target(
            label, fp, asp_id, make_args_fn(fp, spec), 'gumbo_l2', extract_fn)
    return targets


# ── Register both protocols ────────────────────────────────────────────────────

REGISTRY['gumbo_l1'] = {
    'id':          'gumbo_l1',
    'name':        'GUMBO File Integrity (Level 1)',
    'description': (
        'Hash AADL model files and GumboX oracle files as a whole. '
        'Fast check: detects any change to "do not edit" contract artifacts. '
        'Run Level 2 on failure for per-contract attribution.'
    ),
    'copland':     'lseq( lseq( bseq_chain( hashfile×4 ), SIG ), APPR )',
    'flow': [
        {'type': 'bseq', 'label': 'bseq / both_paths',
         'children': ['hashfile(TempControlSystem.aadl)',
                      'hashfile(TempSensor.aadl)',
                      'hashfile(TempControl_GumboX.scala)',
                      'hashfile(TempSensor_GumboX.scala)']},
        {'type': 'arrow'},
        {'type': 'asp', 'label': 'SIG', 'style': 'sig'},
        {'type': 'arrow'},
        {'type': 'asp', 'label': 'APPR', 'style': 'appr'},
    ],
    'build':          build_gumbo_l1,
    'provision':      provision_gumbo_l1,
    'golden_state':   golden_state_gumbo_l1,
    'prepare':        _make_prepare('gumbo_l1'),
    'tamper_targets': _gumbo_l1_tamper_targets(),
}

REGISTRY['gumbo_l2'] = {
    'id':          'gumbo_l2',
    'name':        'GUMBO Contract Attribution (Level 2)',
    'description': (
        'Per-contract range measurements linking AADL GUMBO clauses to '
        'GumboX oracle predicates and component BEGIN/END contract blocks. '
        'Identifies which specific contract was tampered. '
        'AADL and GumboX contracts measured by line range; '
        'component contracts measured by BEGIN/END marker strings (stable '
        'regardless of implementation code growth).'
    ),
    'copland':     'lseq( lseq( bseq_chain( readfile_range×16 + readfile_marker_range×4 ), SIG ), APPR )',
    'flow': [
        {'type': 'bseq', 'label': 'bseq / both_paths',
         'children': [f'{row[0]}({row[1]})' for row in _GUMBO_L2_CONTRACTS]},
        {'type': 'arrow'},
        {'type': 'asp', 'label': 'SIG', 'style': 'sig'},
        {'type': 'arrow'},
        {'type': 'asp', 'label': 'APPR', 'style': 'appr'},
    ],
    'build':          build_gumbo_l2,
    'provision':      provision_gumbo_l2,
    'golden_state':   golden_state_gumbo_l2,
    'prepare':        _make_prepare('gumbo_l2'),
    'tamper_targets': _gumbo_l2_tamper_targets(),
}


# ── GUMBO Behavioral Validation Protocol ─────────────────────────────────────
#
# Invokes live HAMR validation tools (not golden comparison) over the
# TempControl project.  The appraiser checks tool exit codes — no provisioning
# needed because the tools themselves are the source of truth.
#
# Measurements:
#   1. sireum proyek tipe  — Slang type check over all project modules
#   2. sireum proyek logika — Logika formal verification of TempControl GumboX
#   3. sireum proyek logika — Logika formal verification of TempSensor GumboX
#   4. sireum proyek test   — GumboX random unit tests for TempControl
#   5. sireum proyek test   — GumboX random unit tests for TempSensor
#
# Logika and test require the Sireum logika solver dependencies (cvc4/cvc5 +
# z3) to be installed.  tipe runs without them.

_TC_PROJECT  = os.path.join(_BASE_TC, 'slang')

_TC_GUMBOX_CLASS = ('tc.TempControlSoftwareSystem.'
                    'TempControlPeriodic_p_tcproc_tempControl_GumboX_UnitTests')
_TS_GUMBOX_CLASS = ('tc.TempSensor.'
                    'TempSensorPeriodic_p_tcproc_tempSensor_GumboX_UnitTests')


def _hamr_args(label, exe_args):
    """Build ASP args for run_command_hamr with this project's sireum installation.

    label is passed through as an ASP arg so the dashboard result table can show
    a meaningful step name instead of the raw ASP id.

    Note: sireum_bin and sireum_home are intentionally omitted — the ASP
    resolves the sireum executable from PATH and inherits SIREUM_HOME from
    the CVM process environment, preventing callers from supplying arbitrary
    binary paths or environment overrides.
    """
    return {
        'exe_args': exe_args,
    }


# Labels used in the flow diagram and result table (order matches bseq chain).
_GUMBO_VALIDATION_STEPS = [
    ('tipe',      'Type Check (tipe)',              ['proyek', 'tipe', _TC_PROJECT]),
    ('logika_tc', 'Logika: TempControl GumboX',    ['proyek', 'logika', '--solver-valid', 'z3',
                                                     _TC_PROJECT, _GUMBOX_TC]),
    ('logika_ts', 'Logika: TempSensor GumboX',     ['proyek', 'logika', '--solver-valid', 'z3',
                                                     _TC_PROJECT, _GUMBOX_TS]),
    ('test_tc',   'GumboX Unit Tests: TempControl',['proyek', 'test',
                                                     '--classes', _TC_GUMBOX_CLASS,
                                                     _TC_PROJECT]),
    ('test_ts',   'GumboX Unit Tests: TempSensor', ['proyek', 'test',
                                                     '--classes', _TS_GUMBOX_CLASS,
                                                     _TC_PROJECT]),
]


def _step_builder(label, exe_args):
    """Return a zero-arg callable that builds a single validation step term."""
    def _build():
        return build_gumbo_validation_step(label, exe_args)
    return _build


def build_gumbo_validation_step(label, exe_args):
    """Single-step validation: lseq( run_command_hamr(args), APPR )

    Used by the stepped runner to show incremental progress.
    Each call runs exactly one sireum tool and appraises it immediately.
    """
    measurement = cvm.term_custom_asp('run_command_hamr', asp_args=_hamr_args(label, exe_args))
    term = cvm.term_lseq(measurement, cvm.term_appr_asp())
    sc = {
        'ASP_Types': {
            'run_command_hamr':      ASP_REPLACE1,
            'run_command_hamr_appr': ASP_REPLACE1,
        },
        'ASP_Comps': {'run_command_hamr': 'run_command_hamr_appr'},
    }
    manifest = cvm.build_manifest(
        asps=['run_command_hamr', 'run_command_hamr_appr'],
        asp_fs_map={}, policy=[])
    request = cvm.build_run_request(
        session_plc='P0', req_plc='P0', term=term, session_context=sc)
    return manifest, request


def build_gumbo_validation():
    """lseq( bseq_chain( run_command_hamr×5 ), APPR )

    Each run_command_hamr invocation runs one sireum validation tool.
    The appraiser (run_command_hamr_appr) checks exit_code == 0 for each.
    No provisioning or golden comparison is needed.
    """
    measurements = [
        cvm.term_custom_asp('run_command_hamr', asp_args=_hamr_args(label, args))
        for _, label, args in _GUMBO_VALIDATION_STEPS
    ]
    term = cvm.term_lseq(_bseq_chain(measurements), cvm.term_appr_asp())
    sc = {
        'ASP_Types': {
            'run_command_hamr':      ASP_REPLACE1,
            'run_command_hamr_appr': ASP_REPLACE1,
        },
        'ASP_Comps': {
            'run_command_hamr': 'run_command_hamr_appr',
        },
    }
    manifest = cvm.build_manifest(
        asps=['run_command_hamr', 'run_command_hamr_appr'],
        asp_fs_map={}, policy=[])
    request = cvm.build_run_request(
        session_plc='P0', req_plc='P0', term=term, session_context=sc)
    return manifest, request


REGISTRY['gumbo_validation'] = {
    'id':          'gumbo_validation',
    'name':        'GUMBO Behavioral Validation',
    'description': (
        'Runs live HAMR validation tools over the GUMBO contract implementation. '
        'Sireum proyek tipe type-checks all modules; proyek logika formally '
        'verifies the GumboX @strictpure predicates; proyek test exercises '
        'randomised GumboX unit tests for both TempControl and TempSensor. '
        'Pass means all tools exit clean — no provisioned golden required.'
    ),
    'copland': 'lseq( bseq_chain( run_command_hamr×5 ), APPR )',
    'flow': [
        {'type': 'bseq', 'label': 'bseq / both_paths',
         'children': [label for _, label, _ in _GUMBO_VALIDATION_STEPS]},
        {'type': 'arrow'},
        {'type': 'asp', 'label': 'APPR', 'style': 'appr'},
    ],
    'build':  build_gumbo_validation,
    # Per-step builders for incremental progress display.
    # Each step is a (step_id, label, build_fn) tuple where build_fn() returns
    # (manifest, request) for a single lseq(run_command_hamr, APPR) term.
    'steps': [
        (sid, label, _step_builder(label, args))
        for sid, label, args in _GUMBO_VALIDATION_STEPS
    ],
    # No provision / golden_state / prepare — the appraiser is self-contained.
    'tamper_targets': {},
}


# ── GUMBO Behavioral Validation (bpar) ───────────────────────────────────────
#
# Parallel variant of gumbo_validation using bpar instead of bseq_chain.
#
# Split into two independent tracks:
#   Left  (main process):   tipe + logika_tc + test_tc   (TempControl track)
#   Right (CVM subprocess): logika_ts + test_ts           (TempSensor track)
#
# The two tracks have no data dependency — sireum logika and test are self-
# contained invocations — so they can run simultaneously.  Expected speedup
# is roughly 2x: sequential ≈ sum of all steps, parallel ≈ max of the two
# branch totals.


def build_gumbo_validation_bpar():
    """lseq( bpar/both_paths( bseq_chain(tipe+logika_tc+test_tc),
                               bseq_chain(logika_ts+test_ts) ), APPR )"""
    # Left branch: tipe runs first (covers all modules), then TC-specific tools.
    left_ids  = ('tipe', 'logika_tc', 'test_tc')
    right_ids = ('logika_ts', 'test_ts')

    left_terms = [
        cvm.term_custom_asp('run_command_hamr', asp_args=_hamr_args(label, args))
        for sid, label, args in _GUMBO_VALIDATION_STEPS if sid in left_ids
    ]
    right_terms = [
        cvm.term_custom_asp('run_command_hamr', asp_args=_hamr_args(label, args))
        for sid, label, args in _GUMBO_VALIDATION_STEPS if sid in right_ids
    ]

    par  = cvm.term_bpar('both_paths', _bseq_chain(left_terms), _bseq_chain(right_terms))
    term = cvm.term_lseq(par, cvm.term_appr_asp())
    sc = {
        'ASP_Types': {
            'run_command_hamr':      ASP_REPLACE1,
            'run_command_hamr_appr': ASP_REPLACE1,
        },
        'ASP_Comps': {'run_command_hamr': 'run_command_hamr_appr'},
    }
    manifest = cvm.build_manifest(
        asps=['run_command_hamr', 'run_command_hamr_appr'],
        asp_fs_map={}, policy=[])
    request = cvm.build_run_request(
        session_plc='P0', req_plc='P0', term=term, session_context=sc)
    return manifest, request


REGISTRY['gumbo_validation_bpar'] = {
    'id':          'gumbo_validation_bpar',
    'name':        'GUMBO Behavioral Validation (bpar)',
    'description': (
        'Parallel variant of GUMBO Behavioral Validation using bpar. '
        'Left branch (main process): tipe + Logika TempControl + GumboX tests TempControl. '
        'Right branch (subprocess): Logika TempSensor + GumboX tests TempSensor. '
        'Both tracks are independent, so they run concurrently. '
        'No provisioned golden required — appraiser checks tool exit codes.'
    ),
    'copland': (
        'lseq( bpar/both_paths('
        '  bseq_chain(tipe, logika_tc, test_tc),'
        '  bseq_chain(logika_ts, test_ts)'
        '), APPR )'
    ),
    'flow': [
        {'type': 'bpar', 'label': 'bpar / both_paths', 'children': [
            'Type Check (tipe)',
            'Logika: TempControl GumboX',
            'GumboX Unit Tests: TempControl',
            '‖ Logika: TempSensor GumboX',
            '‖ GumboX Unit Tests: TempSensor',
        ]},
        {'type': 'arrow'},
        {'type': 'asp', 'label': 'APPR', 'style': 'appr'},
    ],
    'build':  build_gumbo_validation_bpar,
    # No provision / golden_state / prepare — appraiser is self-contained.
    'tamper_targets': {},
}


# ── GUMBO Behavioral Validation (full bpar) ──────────────────────────────────
#
# Fully-parallel variant: every step runs as its own bpar branch simultaneously.
# Structure: lseq( bpar(step1, bpar(step2, bpar(step3, bpar(step4, step5)))), APPR )
#
# All five steps are data-independent — each sireum invocation reads source
# files but writes nothing that another step depends on — so running them
# concurrently is safe.  Expected wall time ≈ max(step times) ≈ 28s vs 66s
# sequential, a ~2.4× theoretical speedup.


def build_gumbo_validation_full_par():
    """lseq( bpar_chain( run_command_hamr×5 ), APPR )

    All five sireum validation steps run simultaneously as individual bpar
    branches.  The appraiser checks exit_code == 0 for each.
    """
    measurements = [
        cvm.term_custom_asp('run_command_hamr', asp_args=_hamr_args(label, args))
        for _, label, args in _GUMBO_VALIDATION_STEPS
    ]
    term = cvm.term_lseq(_bpar_chain(measurements), cvm.term_appr_asp())
    sc = {
        'ASP_Types': {
            'run_command_hamr':      ASP_REPLACE1,
            'run_command_hamr_appr': ASP_REPLACE1,
        },
        'ASP_Comps': {'run_command_hamr': 'run_command_hamr_appr'},
    }
    manifest = cvm.build_manifest(
        asps=['run_command_hamr', 'run_command_hamr_appr'],
        asp_fs_map={}, policy=[])
    request = cvm.build_run_request(
        session_plc='P0', req_plc='P0', term=term, session_context=sc)
    return manifest, request


REGISTRY['gumbo_validation_full_par'] = {
    'id':          'gumbo_validation_full_par',
    'name':        'GUMBO Behavioral Validation (full parallel)',
    'description': (
        'Fully-parallel variant of GUMBO Behavioral Validation. '
        'All five sireum steps (tipe, logika TC, logika TS, test TC, test TS) '
        'run simultaneously as individual bpar branches — each step is '
        'data-independent, reading source files without shared write state. '
        'Expected wall time ≈ max(step times) ≈ 28s vs 66s sequential. '
        'No provisioned golden required — appraiser checks tool exit codes.'
    ),
    'copland': (
        'lseq( bpar(tipe, bpar(logika_tc, bpar(logika_ts,'
        ' bpar(test_tc, test_ts)))), APPR )'
    ),
    'flow': [
        {'type': 'bpar', 'label': 'bpar / both_paths (×4 nested)', 'children': [
            'Type Check (tipe)',
            '‖ Logika: TempControl GumboX',
            '‖ Logika: TempSensor GumboX',
            '‖ GumboX Unit Tests: TempControl',
            '‖ GumboX Unit Tests: TempSensor',
        ]},
        {'type': 'arrow'},
        {'type': 'asp', 'label': 'APPR', 'style': 'appr'},
    ],
    'build':  build_gumbo_validation_full_par,
    'tamper_targets': {},
}


# Load any protocol JSON files that were previously added via the dashboard
from protocol_loader import load_saved_protocols as _load_saved
for _path, _err in _load_saved():
    import sys
    print(f"[protocols] warning: could not load '{_path}': {_err}", file=sys.stderr)
