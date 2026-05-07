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


# ── Tamper / Repair helpers ───────────────────────────────────────────────────

_ORIG_HSH_GOLDEN = hashlib.sha256(b'').digest()
_BAD_HSH_GOLDEN  = bytes([0xff] * 32)


def _simple_file_target(target_id, label, file_path):
    """File tamper target for protocols that do not support provisioning.

    Provides tamper/repair/reset operations but always returns compliant=None
    because there is no golden to compare against.
    """
    bad_bytes = f'[TAMPERED] {label} - modified to fail appraisal.'.encode()

    def tamper():
        try:
            open(file_path + '.src', 'wb').write(open(file_path, 'rb').read())
        except FileNotFoundError:
            pass
        open(file_path, 'wb').write(bad_bytes)

    def repair():
        for src in (file_path + '.src', file_path + '.default'):
            if os.path.exists(src):
                open(file_path, 'wb').write(open(src, 'rb').read())
                return

    def reset():
        for src in (file_path + '.original', file_path + '.default'):
            if os.path.exists(src):
                open(file_path, 'wb').write(open(src, 'rb').read())
                return

    def get_state():
        return {'compliant': None}

    def inspect():
        try:
            data = open(file_path, 'rb').read()
        except FileNotFoundError:
            return {'error': f'Target file not found: {label}'}
        return {
            'type':           'file',
            'current':        data.decode('utf-8', errors='replace'),
            'current_sha256': hashlib.sha256(data).hexdigest(),
            'error':          'No golden — protocol does not support provisioning',
        }

    return {'label': label, 'tamper': tamper, 'repair': repair,
            'reset': reset, 'get_state': get_state, 'inspect': inspect}


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
        'tamper_targets': {
            'file1': _simple_file_target('file1', 'file1.txt', f'{EXAMPLES}/file1.txt'),
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
        'tamper_targets': {
            'file1': _simple_file_target('file1', 'file1.txt', f'{EXAMPLES}/file1.txt'),
            'file2': _simple_file_target('file2', 'file2.txt', f'{EXAMPLES}/file2.txt'),
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
        'tamper_targets': {
            'file1': _simple_file_target('file1', 'file1.txt', f'{EXAMPLES}/file1.txt'),
            'file2': _simple_file_target('file2', 'file2.txt', f'{EXAMPLES}/file2.txt'),
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

def _make_contract_target(label, filepath, asp_id, args_fn, proto_id, extract_fn,
                          golden_lookup_fn=None):
    """
    Build a tamper target dict for a per-contract range measurement.

    args_fn:          callable() -> dict   returns current ASP args (called live
                      so line-number resolution is always up to date)
    extract_fn:       callable(filepath) -> bytes   extracts current contract content
    golden_lookup_fn: callable() -> str|None   returns golden base64 string or None
    """
    def _get_golden_bytes():
        import base64
        if golden_lookup_fn is None:
            return None
        b64 = golden_lookup_fn()
        if b64 is None:
            return None
        try:
            return base64.b64decode(b64)
        except Exception:
            return None

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
            'hashfile':         ASP_REPLACE1,
            'sig':              ASP_EXTEND1,
            'sig_appr':         ASP_REPLACE1,
            'goldenbytes_appr': ASP_REPLACE1,
        },
        'ASP_Comps': {'hashfile': 'goldenbytes_appr', 'sig': 'sig_appr'},
    }
    manifest = cvm.build_manifest(
        asps=['hashfile', 'sig', 'sig_appr', 'goldenbytes_appr'], asp_fs_map={}, policy=[])
    request = cvm.build_run_request(
        session_plc='P0', req_plc='P0', term=term, session_context=sc)
    return manifest, request


def _gumbo_l1_tamper_targets():
    return {tid: _simple_file_target(tid, label, fp)
            for fp, label, tid in _GUMBO_L1_FILES}


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


_GUMBO_L2_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             'protocol_dirs', 'gumbo_l2')
_GUMBO_GOLDEN_SKIP = frozenset(
    {'asp_id_appr', 'env_var_golden', 'filepath_golden', 'golden_b64', 'golden_ts'})


def _gumbo_l2_golden_lookup(asp_id, filepath, spec):
    """Return a callable() -> golden_b64 | None for a single gumbo_l2 contract.

    Matches by comparing cleaned ASP args (stripped of bookkeeping keys) against
    the entries in protocol_dirs/gumbo_l2/asp_args.json.  For readfile_range
    contracts the line numbers are resolved live so the lookup stays accurate as
    long as the file has not shifted since provisioning.
    """
    def _lookup():
        try:
            with open(os.path.join(_GUMBO_L2_DIR, 'asp_args.json')) as f:
                all_args = json.load(f)
            stored_targets = all_args.get(asp_id, {})
            live_args   = _resolve_args(filepath, spec)
            clean_query = {k: v for k, v in live_args.items()
                           if k not in _GUMBO_GOLDEN_SKIP}
            for _tid, tdata in stored_targets.items():
                clean_stored = {k: v for k, v in tdata.items()
                                if k not in _GUMBO_GOLDEN_SKIP}
                if clean_stored == clean_query:
                    return tdata.get('golden_b64') or None
        except Exception:
            pass
        return None
    return _lookup


def _gumbo_l2_tamper_targets():
    targets = {}
    for label, tid, fp, spec in _GUMBO_L2_CONTRACTS:
        asp_id     = _asp_id_for_spec(spec)
        extract_fn = _resolve_extract_fn(fp, spec)
        def _make_args_fn(filepath, s):
            return lambda: _resolve_args(filepath, s)
        targets[tid] = _make_contract_target(
            label, fp, asp_id, _make_args_fn(fp, spec), 'gumbo_l2', extract_fn,
            golden_lookup_fn=_gumbo_l2_golden_lookup(asp_id, fp, spec))
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


# ── Provision capabilities for protocol-dir-based built-in protocols ──────────
#
# Protocols whose golden evidence is stored in protocol_dirs/<proto_id>/ need
# provision / golden_state / prepare registered by register_protocol_dir.  We
# call it here (after REGISTRY is fully built) and then restore the richer
# inline metadata (name / description / copland / flow / build / tamper_targets)
# so the dashboard shows the correct display while also having a Provision button.

_BUILTIN_PROTOCOL_DIRS = [
    'gumbo_l2',
]

for _pid in _BUILTIN_PROTOCOL_DIRS:
    _local_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'protocol_dirs', _pid)
    if not os.path.isdir(_local_dir):
        continue
    try:
        import sys as _sys
        from protocol_loader import register_protocol_dir as _rpd
        _saved = REGISTRY.get(_pid, {}).copy()
        _rpd(_pid, local_dir=_local_dir)
        # Restore rich inline metadata that register_protocol_dir would overwrite
        for _k in ('name', 'description', 'copland', 'flow', 'build', 'tamper_targets'):
            if _k in _saved:
                REGISTRY[_pid][_k] = _saved[_k]
        # Built-in protocol dirs are not editable via the single-file spec editor;
        # remove custom_source so the Edit button does not appear.
        REGISTRY[_pid].pop('custom_source', None)
    except Exception as _e:
        import sys as _sys
        print(f'[protocols] WARNING: could not merge protocol-dir provision '
              f"for '{_pid}': {_e}", file=_sys.stderr)


# Load any protocol JSON files that were previously added via the dashboard
from protocol_loader import load_saved_protocols as _load_saved
for _path, _err in _load_saved():
    import sys
    print(f"[protocols] warning: could not load '{_path}': {_err}", file=sys.stderr)
