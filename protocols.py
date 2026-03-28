"""
CVM Protocol Registry
Each entry defines a named Copland protocol with its term, session context,
manifest, and display metadata. Add new protocols here.
"""
import hashlib, datetime, os, sys
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


def provision_single_hashfile_appr():
    FILE1, G1 = f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/golden_file1.bin'
    h = _write_golden(G1, open(FILE1, 'rb').read())
    return [{'target': 'file1.txt', 'golden': 'golden_file1.bin', 'sha256': h,
             'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]

def golden_state_single_hashfile_appr():
    G1 = f'{EXAMPLES}/golden_file1.bin'
    g  = _read_golden(G1)
    return [{'target': 'file1.txt', 'golden': 'golden_file1.bin',
             'sha256': g['sha256'] if g else None,
             'timestamp': g['timestamp'] if g else None,
             'tamper_id': 'file1'}]


def provision_hsh_sig_appr():
    """hsh operates on mt_evt (empty initial evidence = empty bytes)."""
    GOLDEN = f'{EXAMPLES}/hsh_golden.bin'
    h = _write_golden(GOLDEN, b'')
    return [{'target': '(empty evidence)', 'golden': 'hsh_golden.bin', 'sha256': h,
             'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]

def golden_state_hsh_sig_appr():
    GOLDEN = f'{EXAMPLES}/hsh_golden.bin'
    g = _read_golden(GOLDEN)
    return [{'target': '(empty evidence)', 'golden': 'hsh_golden.bin',
             'sha256': g['sha256'] if g else None,
             'timestamp': g['timestamp'] if g else None,
             'tamper_id': 'hsh_golden'}]


def provision_dual_hashfile_sig_appr():
    FILE1, FILE2 = f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/file2.txt'
    G1,    G2    = f'{EXAMPLES}/golden_file1.bin', f'{EXAMPLES}/golden_file2.bin'
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return [
        {'target': 'file1.txt', 'golden': 'golden_file1.bin',
         'sha256': _write_golden(G1, open(FILE1, 'rb').read()), 'timestamp': ts},
        {'target': 'file2.txt', 'golden': 'golden_file2.bin',
         'sha256': _write_golden(G2, open(FILE2, 'rb').read()), 'timestamp': ts},
    ]

def golden_state_dual_hashfile_sig_appr():
    G1 = f'{EXAMPLES}/golden_file1.bin'
    G2 = f'{EXAMPLES}/golden_file2.bin'
    results = []
    for target, golden, path, tamper_id in [
        ('file1.txt', 'golden_file1.bin', G1, 'file1'),
        ('file2.txt', 'golden_file2.bin', G2, 'file2'),
    ]:
        g = _read_golden(path)
        results.append({'target': target, 'golden': golden,
                        'sha256': g['sha256'] if g else None,
                        'timestamp': g['timestamp'] if g else None,
                        'tamper_id': tamper_id})
    return results


# ── Tamper / Repair helpers ───────────────────────────────────────────────────

_BAD_FILE1  = b"[TAMPERED] file ONE - modified to fail appraisal."
_BAD_FILE2  = b"[TAMPERED] file TWO - modified to fail appraisal.\n"

_ORIG_HSH_GOLDEN = hashlib.sha256(b'').digest()
_BAD_HSH_GOLDEN  = bytes([0xff] * 32)


def _file_compliant(file_path, golden_path):
    """Return True if SHA256(current file) matches the golden (appraisal will pass)."""
    try:
        current_hash = hashlib.sha256(open(file_path, 'rb').read()).digest()
        golden       = open(golden_path, 'rb').read()
        return current_hash == golden
    except FileNotFoundError:
        return False


def _tamper_file(file_path, golden_path, bad_bytes):
    """
    Write bad_bytes to file_path, guaranteed to mismatch the current golden.
    If the golden already equals SHA256(bad_bytes) (e.g. re-provisioned from a
    prior tamper), append nonce bytes until the hash differs.
    """
    try:
        golden = open(golden_path, 'rb').read()
    except FileNotFoundError:
        golden = b''
    content, nonce = bad_bytes, 0
    while hashlib.sha256(content).digest() == golden:
        nonce += 1
        content = bad_bytes + f'\n[TAMPER-NONCE-{nonce}]'.encode()
    open(file_path, 'wb').write(content)


def tamper_file1():
    _tamper_file(f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/golden_file1.bin', _BAD_FILE1)

def repair_file1():
    src = f'{EXAMPLES}/golden_file1.bin.src'
    fallback = f'{EXAMPLES}/file1.txt.default'
    content = open(src, 'rb').read() if os.path.exists(src) else open(fallback, 'rb').read()
    open(f'{EXAMPLES}/file1.txt', 'wb').write(content)

def reset_file1():
    """Restore default file content and recompute golden — guaranteed compliant state."""
    content = open(f'{EXAMPLES}/file1.txt.default', 'rb').read()
    open(f'{EXAMPLES}/file1.txt', 'wb').write(content)
    _write_golden(f'{EXAMPLES}/golden_file1.bin', content)

def get_state_file1():
    return {'compliant': _file_compliant(f'{EXAMPLES}/file1.txt', f'{EXAMPLES}/golden_file1.bin')}


def tamper_file2():
    _tamper_file(f'{EXAMPLES}/file2.txt', f'{EXAMPLES}/golden_file2.bin', _BAD_FILE2)

def repair_file2():
    src = f'{EXAMPLES}/golden_file2.bin.src'
    fallback = f'{EXAMPLES}/file2.txt.default'
    content = open(src, 'rb').read() if os.path.exists(src) else open(fallback, 'rb').read()
    open(f'{EXAMPLES}/file2.txt', 'wb').write(content)

def reset_file2():
    """Restore default file content and recompute golden — guaranteed compliant state."""
    content = open(f'{EXAMPLES}/file2.txt.default', 'rb').read()
    open(f'{EXAMPLES}/file2.txt', 'wb').write(content)
    _write_golden(f'{EXAMPLES}/golden_file2.bin', content)

def get_state_file2():
    return {'compliant': _file_compliant(f'{EXAMPLES}/file2.txt', f'{EXAMPLES}/golden_file2.bin')}


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


def _inspect_file(file_path, golden_path, src_path):
    """Return inspection data for a file-based measurement target."""
    try:
        current = open(file_path, 'rb').read()
    except FileNotFoundError:
        return {'error': f'Target file not found: {os.path.basename(file_path)}'}
    try:
        golden = open(golden_path, 'rb').read()
    except FileNotFoundError:
        return {'error': 'Golden file not found — run Provision first'}
    compliant = hashlib.sha256(current).digest() == golden
    provisioned = open(src_path, 'rb').read() if os.path.exists(src_path) else None
    return {
        'type':              'file',
        'compliant':         compliant,
        'current':           current.decode('utf-8', errors='replace'),
        'current_sha256':    hashlib.sha256(current).hexdigest(),
        'golden_sha256':     golden.hex(),
        'provisioned':       provisioned.decode('utf-8', errors='replace') if provisioned else None,
    }


def inspect_file1():
    return _inspect_file(f'{EXAMPLES}/file1.txt',
                         f'{EXAMPLES}/golden_file1.bin',
                         f'{EXAMPLES}/golden_file1.bin.src')

def inspect_file2():
    return _inspect_file(f'{EXAMPLES}/file2.txt',
                         f'{EXAMPLES}/golden_file2.bin',
                         f'{EXAMPLES}/golden_file2.bin.src')

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


_TAMPER_TARGET_FILE1 = {
    'label':     'file1.txt',
    'tamper':    tamper_file1,
    'repair':    repair_file1,
    'reset':     reset_file1,
    'get_state': get_state_file1,
    'inspect':   inspect_file1,
}
_TAMPER_TARGET_FILE2 = {
    'label':     'file2.txt',
    'tamper':    tamper_file2,
    'repair':    repair_file2,
    'reset':     reset_file2,
    'get_state': get_state_file2,
    'inspect':   inspect_file2,
}
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
        'tamper_targets': {'file1': _TAMPER_TARGET_FILE1},
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
        'tamper_targets': {'file1': _TAMPER_TARGET_FILE1, 'file2': _TAMPER_TARGET_FILE2},
    },
}
