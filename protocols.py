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
    """Hash data with SHA-256 and write raw digest bytes to path."""
    digest = hashlib.sha256(data).digest()
    with open(path, 'wb') as f:
        f.write(digest)
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
             'timestamp': g['timestamp'] if g else None}]


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
             'timestamp': g['timestamp'] if g else None}]


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
    for target, golden, path in [('file1.txt', 'golden_file1.bin', G1),
                                  ('file2.txt', 'golden_file2.bin', G2)]:
        g = _read_golden(path)
        results.append({'target': target, 'golden': golden,
                        'sha256': g['sha256'] if g else None,
                        'timestamp': g['timestamp'] if g else None})
    return results


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
        'build':        build_single_hashfile_appr,
        'provision':    provision_single_hashfile_appr,
        'golden_state': golden_state_single_hashfile_appr,
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
        'build':        build_hsh_sig_appr,
        'provision':    provision_hsh_sig_appr,
        'golden_state': golden_state_hsh_sig_appr,
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
        'build':        build_dual_hashfile_sig_appr,
        'provision':    provision_dual_hashfile_sig_appr,
        'golden_state': golden_state_dual_hashfile_sig_appr,
    },
}
