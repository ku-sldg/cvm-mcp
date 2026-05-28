"""
Load Copland protocol definitions from JSON files and register them in the REGISTRY.

JSON protocol file format:
{
  "id":          "my_protocol",
  "name":        "My Protocol",
  "description": "What this protocol does",
  "copland":     "lseq( hashfile(myfile), APPR )",

  "flow": [                              // optional — auto-generated if omitted
    {"type": "asp", "label": "hashfile(myfile.txt)", "style": "file"},
    {"type": "arrow"},
    {"type": "asp", "label": "APPR", "style": "appr"}
  ],

  "manifest": {                          // CVM manifest object
    "ASPS": ["hashfile", "hashfile_appr"],
    "ASP_FS_MAP": {},
    "POLICY": []
  },

  "request": {                           // CVM run request object
    "Session_Plc": "P0",
    "Req_Plc": "P0",
    "Term": { ... },
    "Session_Context": {
      "ASP_Types": { ... },
      "ASP_Comps": { ... }
    }
  },

  "targets": [                           // optional measurement targets
    {
      "id":     "myfile",
      "label":  "myfile.txt",
      "file":   "/absolute/path/to/file.txt",
      "golden": "/absolute/path/to/golden.bin"
    }
  ]
}
"""
import json
import os
import hashlib
import datetime


# ── Canonical protocol registry ───────────────────────────────────────────────
#
# Single in-memory registry of all known protocols, keyed by protocol id.
# Populated entirely from protocol_dirs/ via load_all_protocols(); there is no
# longer a code-defined registry (the former protocols.py). Both the dashboard
# and the MCP server import this object and call load_all_protocols() at startup.
REGISTRY = {}


# ── Protocol-directory helpers ────────────────────────────────────────────────

_HERE = os.path.dirname(os.path.abspath(__file__))

def _protocol_dirs_root():
    """Return the protocol_dirs root, configurable via CVM_PROTOCOL_DIRS env var."""
    return os.environ.get(
        'CVM_PROTOCOL_DIRS',
        os.path.join(_HERE, 'protocol_dirs'),
    )

def _protocol_dir(proto_id):
    return os.path.join(_protocol_dirs_root(), proto_id)

def _read_dir_json(proto_id, filename):
    with open(os.path.join(_protocol_dir(proto_id), filename)) as f:
        return json.load(f)

def has_protocol_dir(proto_id):
    """Return True if a protocol_dirs/<proto_id>/ directory exists."""
    return os.path.isdir(_protocol_dir(proto_id))

def list_protocol_dir_ids():
    """Return sorted list of protocol IDs that have a protocol_dirs entry."""
    root = _protocol_dirs_root()
    if not os.path.isdir(root):
        return []
    return sorted(
        d for d in os.listdir(root)
        if os.path.isdir(os.path.join(root, d))
    )

def get_protocol_dir_meta(proto_id):
    """Return the meta.json dict for a protocol, or {} if not found."""
    try:
        return _read_dir_json(proto_id, 'meta.json')
    except FileNotFoundError:
        return {}


# Known config files in a protocol directory, in the order they should be
# displayed on the dashboard.
PROTOCOL_DIR_FILES = (
    'term.json',
    'term_no_appr.json',
    'manifest.json',
    'session.json',
    'asp_args.json',
)


def get_protocol_dir_files(proto_id):
    """
    Return a list of (filename, raw_text) tuples for every known config file
    that exists in protocol_dirs/<proto_id>/.

    The raw file text is returned (not parsed JSON) so the dashboard preserves
    on-disk formatting and key order exactly as written by the generator.
    """
    out = []
    base = _protocol_dir(proto_id)
    if not os.path.isdir(base):
        return out
    for fn in PROTOCOL_DIR_FILES:
        path = os.path.join(base, fn)
        if os.path.isfile(path):
            try:
                with open(path) as f:
                    out.append((fn, f.read()))
            except OSError:
                pass
    return out

def inject_asp_args(term, asp_args_map):
    """
    Return a deep copy of *term* with ASP_ARGS filled in from *asp_args_map*
    for every ASPC node that carries an ASP_TARG_ID.

    *asp_args_map* has the rust-rodeo-client shape:
        { "<asp_id>": { "<targ_id>": { <args dict> }, ... }, ... }

    For each ASPC node:
      - Look up asp_args_map[ASP_ID][ASP_TARG_ID]
      - Merge those args into ASP_ARGS (node args take precedence over map)
    Nodes without ASP_TARG_ID, or whose IDs are not in the map, are unchanged.
    """
    import copy
    term = copy.deepcopy(term)

    def _walk(node):
        if not isinstance(node, dict):
            return
        ctor = node.get('TERM_CONSTRUCTOR')
        body = node.get('TERM_BODY')
        if ctor == 'asp':
            if isinstance(body, dict) and body.get('ASP_CONSTRUCTOR') == 'ASPC':
                asp_body = body.get('ASP_BODY', {})
                asp_id   = asp_body.get('ASP_ID', '')
                targ_id  = asp_body.get('ASP_TARG_ID', '')
                mapped   = None
                if asp_id and targ_id:
                    # Primary: match by explicit ASP_TARG_ID
                    mapped = asp_args_map.get(asp_id, {}).get(targ_id)
                elif asp_id:
                    # Fallback: when terms were generated without ASP_TARG_ID
                    # (e.g. gumbo_l1 uses the legacy filepath-in-args format),
                    # match the stored entry whose 'filepath' equals the node's.
                    node_fp = asp_body.get('ASP_ARGS', {}).get('filepath', '')
                    if node_fp:
                        for entry in asp_args_map.get(asp_id, {}).values():
                            if entry.get('filepath') == node_fp:
                                mapped = entry
                                break
                if mapped:
                    asp_body['ASP_ARGS'] = {**mapped, **asp_body.get('ASP_ARGS', {})}
            return
        if isinstance(body, list):
            for child in body:
                if isinstance(child, dict):
                    _walk(child)

    _walk(term)
    return term


# Dict-encoded bseq/bpar splits from older rust-rodeo-client serialization
# mapped to the string form expected by the current CVM.
_SPLIT_DICT_MAP = {
    ('ALL',  'ALL'):  'both_paths',
    ('ALL',  'NONE'): 'left_path',
    ('NONE', 'ALL'):  'right_path',
}


def normalize_term(term):
    """
    Return a deep copy of *term* with known format incompatibilities repaired
    so the current CVM can parse it.

    Currently handles:
    - bseq/bpar split encoded as {"split1": X, "split2": Y} → string form
      e.g. {"split1": "ALL", "split2": "ALL"} → "both_paths"
    - ASPC ASP_BODY extra fields (ASP_PLC, ASP_TARG_ID, …) → stripped;
      CVM's JSON decoder expects only ASP_ID and ASP_ARGS.
    """
    import copy
    term = copy.deepcopy(term)

    _ASPC_BODY_KEYS = {'ASP_ID', 'ASP_ARGS'}

    def _walk(node):
        if not isinstance(node, dict):
            return
        ctor = node.get('TERM_CONSTRUCTOR')
        body = node.get('TERM_BODY')

        if ctor == 'asp':
            if isinstance(body, dict) and body.get('ASP_CONSTRUCTOR') == 'ASPC':
                asp_body = body.get('ASP_BODY', {})
                # Strip any keys CVM doesn't understand (e.g. ASP_PLC, ASP_TARG_ID)
                extra = set(asp_body) - _ASPC_BODY_KEYS
                for k in extra:
                    del asp_body[k]
            return

        if ctor in ('bseq', 'bpar') and isinstance(body, list) and len(body) >= 3:
            split = body[0]
            if isinstance(split, dict) and 'split1' in split and 'split2' in split:
                key = (split['split1'], split['split2'])
                normalized = _SPLIT_DICT_MAP.get(key)
                if normalized:
                    body[0] = normalized
            for child in body[1:]:
                _walk(child)
            return

        if isinstance(body, list):
            for child in body:
                _walk(child)
        elif isinstance(body, dict):
            _walk(body)

    _walk(term)
    return term


def _load_asp_args(proto_id):
    """Return the asp_args.json dict for a protocol dir, or {} if absent/empty."""
    try:
        data = _read_dir_json(proto_id, 'asp_args.json')
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _load_asp_args_from_dir(local_dir):
    """Return the asp_args.json dict for an absolute protocol dir path, or {}."""
    try:
        path = os.path.join(local_dir, 'asp_args.json')
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def build_from_dir(proto_id):
    """
    Build (manifest_dict, request_dict) from protocol_dirs/<proto_id>/ files.

    Reconstructs the ProtocolRunRequest from the split term.json / session.json
    / manifest.json files written by generate_protocol_dirs.py.

    If asp_args.json is present and non-empty, its entries are injected into
    any ASPC nodes that carry a matching ASP_TARG_ID (same mechanism as
    rust-rodeo-client's term_swap_args).

    Raises FileNotFoundError if the directory or required files are missing.
    """
    manifest  = _read_dir_json(proto_id, 'manifest.json')
    term      = _read_dir_json(proto_id, 'term.json')
    session   = _read_dir_json(proto_id, 'session.json')
    asp_args  = _load_asp_args(proto_id)

    if asp_args:
        term = inject_asp_args(term, asp_args)
    term = normalize_term(term)

    request = {
        'TYPE':    'REQUEST',
        'ACTION':  'RUN',
        'REQ_PLC': session.get('Session_Plc', 'P0'),
        'TO_PLC':  session.get('Session_Plc', 'P0'),
        'TERM':    term,
        'EVIDENCE': [{'RawEv': []}, {'EvidenceT_CONSTRUCTOR': 'mt_evt'}],
        'ATTESTATION_SESSION': session,
    }
    return manifest, request


# ── Import / register protocol directories ───────────────────────────────────

def _term_to_copland(term):
    """
    Render a Copland term dict as a compact Copland expression string.
    Produces a best-effort human-readable form — not guaranteed to be
    executable, but useful as a display label.
    """
    if not isinstance(term, dict):
        return '?'
    ctor = term.get('TERM_CONSTRUCTOR', '')
    body = term.get('TERM_BODY')

    if ctor == 'asp':
        if not isinstance(body, dict):
            return 'asp(?)'
        ac = body.get('ASP_CONSTRUCTOR', '')
        if ac == 'APPR':
            return 'APPR'
        if ac == 'SIG':
            return 'SIG'
        if ac == 'HSH':
            return 'HSH'
        if ac == 'NULL':
            return 'NULL'
        if ac == 'ASPC':
            ab  = body.get('ASP_BODY', {})
            aid = ab.get('ASP_ID', 'asp')
            fp  = ab.get('ASP_ARGS', {}).get('filepath', '')
            if fp:
                return f'{aid}({os.path.basename(fp)})'
            return aid
        return ac or 'asp(?)'

    if ctor == 'lseq' and isinstance(body, list) and len(body) == 2:
        return f'lseq( {_term_to_copland(body[0])}, {_term_to_copland(body[1])} )'

    if ctor in ('bseq', 'bpar') and isinstance(body, list) and len(body) == 3:
        sp = body[0]
        label = f'{ctor}({sp})' if sp else ctor
        return f'{label}( {_term_to_copland(body[1])}, {_term_to_copland(body[2])} )'

    if ctor == 'att' and isinstance(body, list) and len(body) == 2:
        return f'att( {body[0]}, {_term_to_copland(body[1])} )'

    return ctor or '?'


def _default_meta_from_term(proto_id, term):
    """
    Build a default meta.json dict for a protocol directory that has no meta.json.

    - name:        title-cased proto_id (underscores/hyphens → spaces)
    - description: empty string
    - copland:     rendered from term
    - flow:        derived from term via protocol_builder
    """
    name = proto_id.replace('_', ' ').replace('-', ' ').title()
    copland = _term_to_copland(term) if term else ''
    try:
        from protocol_builder import derive_from_term
        flow = derive_from_term(term).get('flow', [])
    except Exception:
        flow = []
    return {
        'name':        name,
        'description': '',
        'copland':     copland,
        'flow':        flow,
    }


def import_protocol_dir(source_path, proto_id=None):
    """
    Import a protocol directory from *source_path* into the local
    protocol_dirs/<proto_id>/ tree.

    Steps:
      1. Read term.json / session.json / manifest.json from source (required).
         meta.json is optional — a default is generated from term.json when absent.
      2. Copy core JSON files to the local directory.
      3. Register the protocol in REGISTRY via register_protocol_dir().
      4. Return proto_id.

    Raises FileNotFoundError if required source files are missing.
    Raises ValueError if proto_id conflicts with a built-in protocol.
    """
    import shutil

    source_path = os.path.abspath(os.path.expanduser(source_path))

    def _read(filename):
        with open(os.path.join(source_path, filename)) as f:
            return json.load(f)

    # Required files
    term     = _read('term.json')
    session  = _read('session.json')
    manifest = _read('manifest.json')

    if proto_id is None:
        proto_id = os.path.basename(source_path.rstrip('/\\'))

    # meta.json is optional — generate a default when absent
    try:
        meta = _read('meta.json')
    except FileNotFoundError:
        meta = _default_meta_from_term(proto_id, term)


    # Create local directory
    local_dir = _protocol_dir(proto_id)
    os.makedirs(local_dir, exist_ok=True)

    def _write(filename, data):
        with open(os.path.join(local_dir, filename), 'w') as f:
            json.dump(data, f, indent=2)
            f.write('\n')

    _write('meta.json', meta)
    _write('term.json', term)
    _write('session.json', session)
    _write('manifest.json', manifest)

    asp_args_path = os.path.join(local_dir, 'asp_args.json')
    if not os.path.exists(asp_args_path):
        _write('asp_args.json', {})

    for fname in ('term_no_appr.json', 'term_no_appr_provisioned.json'):
        src = os.path.join(source_path, fname)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(local_dir, fname))

    register_protocol_dir(proto_id, local_dir=local_dir, source_path=source_path)
    return proto_id


def register_protocol_dir(proto_id, local_dir=None, source_path=None):
    """
    Build a REGISTRY entry backed by protocol_dirs/<proto_id>/ and insert it.

    Reads meta.json from *local_dir* (defaults to _protocol_dir(proto_id)).
    Creates provision / golden_state closures compatible with the rest of the
    dashboard.

    All protocols are treated identically — a protocol simply *is* its
    protocol_dirs/<id>/ directory. There is no built-in/custom distinction.

    Returns proto_id.
    """
    if local_dir is None:
        local_dir = _protocol_dir(proto_id)

    # Read meta
    try:
        with open(os.path.join(local_dir, 'meta.json')) as f:
            meta = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        meta = {}

    # Determine effective term file (prefer term_local.json when stubs exist),
    # then inject ASP_ARGS from asp_args.json for any ASP_TARG_ID nodes.
    def _effective_term():
        local_term = os.path.join(local_dir, 'term_local.json')
        if os.path.exists(local_term):
            with open(local_term) as f:
                term = json.load(f)
        else:
            with open(os.path.join(local_dir, 'term.json')) as f:
                term = json.load(f)
        asp_args = _load_asp_args(proto_id)
        if asp_args:
            term = inject_asp_args(term, asp_args)
        term = normalize_term(term)
        return term

    def build():
        manifest = json.load(open(os.path.join(local_dir, 'manifest.json')))
        session  = json.load(open(os.path.join(local_dir, 'session.json')))
        term     = _effective_term()
        request  = {
            'TYPE':    'REQUEST',
            'ACTION':  'RUN',
            'REQ_PLC': session.get('Session_Plc', 'P0'),
            'TO_PLC':  session.get('Session_Plc', 'P0'),
            'TERM':    term,
            'EVIDENCE': [{'RawEv': []}, {'EvidenceT_CONSTRUCTOR': 'mt_evt'}],
            'ATTESTATION_SESSION': session,
        }
        return json.dumps(manifest), json.dumps(request)

    # Determine which ASP_IDs use goldenbytes_appr or goldenevidence_appr in this session.
    # Only these protocols support the provision flow.
    try:
        _session_for_init = json.load(open(os.path.join(local_dir, 'session.json')))
    except Exception:
        _session_for_init = {}
    _comps_for_init = (_session_for_init
                       .get('Session_Context', {})
                       .get('ASP_Comps', {}))
    _has_goldenbytes_appr = any(
        v in ('goldenbytes_appr', 'goldenevidence_appr')
        for v in _comps_for_init.values()
    )

    def provision(golden_path=None):  # golden_path ignored in new flow
        import subprocess
        from cvm_client import run_cvm
        from protocol_builder import _make_measurement_term

        asp_bin = os.environ.get(
            'CVM_ASP_BIN',
            os.path.expanduser('~/Claude_workspace/asp-libs/target/release'),
        )
        extract_bin = os.path.join(asp_bin, 'extract_golden_slice')

        manifest_obj = json.load(open(os.path.join(local_dir, 'manifest.json')))
        session_obj  = json.load(open(os.path.join(local_dir, 'session.json')))
        term_obj     = _effective_term()
        session_ctx  = session_obj.get('Session_Context', {})
        comps        = session_ctx.get('ASP_Comps', {})

        # Fields stored in asp_args.json for dashboard bookkeeping only —
        # must NOT appear in the ASPC ASP_ARGS sent to the CVM (they would
        # vary between provision runs and break do_EvidenceSlice matching).
        # filepath_golden / env_var_golden are legacy hashfile_appr fields that
        # may appear in asp_args.json entries but are irrelevant for goldenbytes_appr;
        # they must be stripped so the evidence-tree args match what
        # extract_golden_slice reconstructs from asp_args.json.
        _PROVISION_BOOKKEEPING_KEYS = {'golden_b64', 'golden_ts',
                                       'filepath_golden', 'env_var_golden'}

        def _inject_asp_id_appr(term, goldenbytes_ids):
            """
            Walk term (in-place) for every ASPC whose ASP_ID is in
            goldenbytes_ids:
              - Strip bookkeeping keys (golden_b64, golden_ts, filepath_golden, env_var_golden) from ASP_ARGS
              - Inject asp_id_appr: <asp_id>

            This mirrors rust-am-lib::add_provisioning_args_asp so that the
            evidence tree produced by the CVM stores the same stable ASP_ARGS
            that extract_golden_slice will reconstruct for matching.
            """
            if not isinstance(term, dict):
                return
            ctor = term.get('TERM_CONSTRUCTOR')
            body = term.get('TERM_BODY')
            if ctor == 'asp' and isinstance(body, dict):
                if body.get('ASP_CONSTRUCTOR') == 'ASPC':
                    ab = body.get('ASP_BODY', {})
                    asp_id = ab.get('ASP_ID', '')
                    if asp_id in goldenbytes_ids:
                        args = {k: v for k, v in ab.get('ASP_ARGS', {}).items()
                                if k not in _PROVISION_BOOKKEEPING_KEYS}
                        args['asp_id_appr'] = asp_id
                        ab['ASP_ARGS'] = args
                return
            if isinstance(body, list):
                for child in body:
                    _inject_asp_id_appr(child, goldenbytes_ids)

        # Run CVM with measurement-only term (APPR → NULL) so it always succeeds
        meas_term = _make_measurement_term(term_obj)
        # Inject asp_id_appr into goldenbytes_appr ASPC nodes so the evidence tree
        # stores the same args that extract_golden_slice will use for matching.
        goldenbytes_ids = {k for k, v in comps.items() if v == 'goldenbytes_appr'}
        _inject_asp_id_appr(meas_term, goldenbytes_ids)
        request_obj = {
            'TYPE':    'REQUEST',
            'ACTION':  'RUN',
            'REQ_PLC': session_obj.get('Session_Plc', 'P0'),
            'TO_PLC':  session_obj.get('Session_Plc', 'P0'),
            'TERM':    meas_term,
            'EVIDENCE': [{'RawEv': []}, {'EvidenceT_CONSTRUCTOR': 'mt_evt'}],
            'ATTESTATION_SESSION': session_obj,
        }

        response = run_cvm(manifest_obj, request_obj, asp_bin)
        if not response.get('SUCCESS'):
            raise RuntimeError(
                f"CVM provision run failed: {response.get('PAYLOAD', 'unknown error')}"
            )

        payload = response['PAYLOAD']  # [rawev_dict, evidencet_dict]

        # Build GlobalContext from session (ASP_Types + ASP_Comps) for the bundle.
        # do_EvidenceSlice only uses ASP_Types (to look up EvCombSig body size),
        # so the session's ASP_Types is the authoritative source.
        global_context = {
            'ASP_Types': session_ctx.get('ASP_Types', {}),
            'ASP_Comps': comps,
        }

        # Write provision_bundle.json as [[rawev, evidencet], global_context].
        # This is the format expected by extract_golden_slice / do_EvidenceSlice.
        bundle_path = os.path.join(local_dir, 'provision_bundle.json')
        with open(bundle_path, 'w') as _bf:
            json.dump([payload, global_context], _bf)

        # Load asp_args.json and populate golden_b64 for each goldenbytes_appr target
        asp_args_path = os.path.join(local_dir, 'asp_args.json')
        try:
            with open(asp_args_path) as _f:
                asp_args = json.load(_f)
        except (FileNotFoundError, json.JSONDecodeError):
            asp_args = {}

        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        resolved = []
        changed  = False

        for asp_id, targets in asp_args.items():
            if comps.get(asp_id) != 'goldenbytes_appr':
                continue
            for targ_id in list(targets.keys()):
                result = subprocess.run(
                    [extract_bin, local_dir, asp_id, targ_id],
                    capture_output=True, text=True,
                )
                if result.returncode != 0:
                    raise RuntimeError(
                        f"extract_golden_slice failed for {asp_id}/{targ_id}: "
                        f"{result.stderr.strip()}"
                    )
                golden_b64 = result.stdout.strip()
                asp_args[asp_id][targ_id]['golden_b64'] = golden_b64
                asp_args[asp_id][targ_id]['golden_ts']  = ts
                changed = True
                resolved.append({
                    'target':    targ_id,
                    'golden':    'provision_bundle.json',
                    'timestamp': ts,
                })

        if changed:
            with open(asp_args_path, 'w') as _f:
                json.dump(asp_args, _f, indent=2)
                _f.write('\n')

        return resolved

    def golden_state():
        """Return provision state for each goldenbytes_appr / goldenevidence_appr target."""
        asp_args    = _load_asp_args(proto_id)
        session_obj = json.load(open(os.path.join(local_dir, 'session.json')))
        comps       = session_obj.get('Session_Context', {}).get('ASP_Comps', {})
        bundle_path = os.path.join(local_dir, 'provision_bundle.json')
        bundle_ts   = None
        if os.path.exists(bundle_path):
            import time
            bundle_ts = datetime.datetime.fromtimestamp(
                os.path.getmtime(bundle_path)
            ).strftime('%Y-%m-%d %H:%M:%S')
        result = []
        for asp_id, targets in asp_args.items():
            comp = comps.get(asp_id, '')
            if comp == 'goldenbytes_appr':
                for targ_id, args in targets.items():
                    golden_b64 = args.get('golden_b64', '')
                    ts         = args.get('golden_ts') if golden_b64 else None
                    result.append({
                        'target':      targ_id,
                        'golden':      'provision_bundle.json' if golden_b64 else None,
                        'golden_path': bundle_path if golden_b64 else None,
                        'sha256':      None,
                        'timestamp':   ts,
                    })
            elif comp == 'goldenevidence_appr':
                for targ_id, args in targets.items():
                    fp_golden = args.get('filepath_golden', '')
                    provisioned = bool(fp_golden and os.path.exists(fp_golden))
                    result.append({
                        'target':      targ_id,
                        'golden':      os.path.basename(fp_golden) if provisioned else None,
                        'golden_path': fp_golden if provisioned else None,
                        'sha256':      None,
                        'timestamp':   bundle_ts if provisioned else None,
                    })
        return result

    def prepare(req):
        # golden_b64 is already written to asp_args.json at provision time and
        # injected into the term via inject_asp_args() inside _effective_term()
        # (called by build()). No additional run-time injection is needed.
        return req

    # Select provision strategy and build REGISTRY entry
    if _has_goldenbytes_appr:
        _provision_fn    = provision
        _golden_state_fn = golden_state
        _prepare_fn      = prepare
    else:
        _provision_fn = _golden_state_fn = _prepare_fn = None

    entry = {
        'id':             proto_id,
        'name':           meta.get('name', proto_id),
        'description':    meta.get('description', ''),
        'copland':        meta.get('copland', ''),
        'flow':           meta.get('flow', []),
        'build':          build,
        'places':         {},
        'custom_source':  source_path or local_dir,
        'imported_dir':   local_dir,
    }
    if _provision_fn:
        entry['provision']    = _provision_fn
        entry['golden_state'] = _golden_state_fn
        entry['prepare']      = _prepare_fn
    _get_registry()[proto_id] = entry
    return proto_id


def preview_protocol_dir(source_path):
    """
    Validate and preview an external protocol directory without importing it.

    Returns a dict with:
      - proto_id, name, description, copland, flow
      - meta_generated: True when meta.json was absent and defaults were generated
      - files_found: list of filenames found
      - files_missing: list of required filenames not found
      - warnings: list of warning strings
      - error: string or None
    """
    source_path = os.path.abspath(os.path.expanduser(source_path))
    required = ('term.json', 'session.json', 'manifest.json')
    optional = ('meta.json', 'term_no_appr.json', 'asp_args.json')

    files_found   = []
    files_missing = []
    for fn in required + optional:
        p = os.path.join(source_path, fn)
        if os.path.exists(p):
            files_found.append(fn)
        elif fn in required:
            files_missing.append(fn)

    if files_missing:
        return {
            'error':          f"Missing required files: {', '.join(files_missing)}",
            'files_found':    files_found,
            'files_missing':  files_missing,
            'proto_id':       None,
            'name':           None,
            'meta_generated': False,
            'warnings':       [],
        }

    try:
        with open(os.path.join(source_path, 'term.json')) as f:
            term = json.load(f)
    except Exception as e:
        return {'error': f'Could not parse term.json: {e}', 'files_found': files_found,
                'files_missing': [], 'proto_id': None, 'name': None,
                'meta_generated': False, 'warnings': []}

    proto_id = os.path.basename(source_path.rstrip('/\\'))

    meta_generated = False
    meta_path = os.path.join(source_path, 'meta.json')
    if os.path.exists(meta_path):
        try:
            with open(meta_path) as f:
                meta = json.load(f)
        except Exception as e:
            return {'error': f'Could not parse meta.json: {e}', 'files_found': files_found,
                    'files_missing': [], 'proto_id': proto_id, 'name': None,
                    'meta_generated': False, 'warnings': []}
    else:
        meta = _default_meta_from_term(proto_id, term)
        meta_generated = True

    proto_id = os.path.basename(source_path.rstrip('/\\'))

    warnings = []
    registry = _get_registry()
    if proto_id in registry or has_protocol_dir(proto_id):
        warnings.append(f"'{proto_id}' already exists; importing will overwrite it.")

    if meta_generated:
        warnings.append(
            "meta.json not found — name, copland, and flow were inferred from term.json."
        )

    return {
        'error':          None,
        'proto_id':       proto_id,
        'name':           meta.get('name', proto_id),
        'description':    meta.get('description', ''),
        'copland':        meta.get('copland', ''),
        'flow':           meta.get('flow', []),
        'meta_generated': meta_generated,
        'files_found':    files_found,
        'files_missing':  [],
        'warnings':       warnings,
    }


def add_protocol_dir(source_path):
    """
    Import a protocol directory and return its proto_id.

    import_protocol_dir copies the source into protocol_dirs/<id>/, so the
    protocol is picked up automatically on every subsequent startup by
    load_all_protocols() scanning protocol_dirs/. No separate config is needed.
    """
    return import_protocol_dir(source_path)


def unique_protocol_id(base_id):
    """Return 'copy_of_<base_id>' if unused, else '..._2', '..._3', … — checking
    both the registry and existing protocol_dirs/ so no on-disk dir is clobbered."""
    def _used(pid):
        return pid in _get_registry() or has_protocol_dir(pid)
    candidate = f'copy_of_{base_id}'
    if not _used(candidate):
        return candidate
    n = 2
    while _used(f'{candidate}_{n}'):
        n += 1
    return f'{candidate}_{n}'


# Runtime/provisioned artifacts that must NOT be carried into a fresh copy —
# the copy starts unprovisioned and is re-provisioned from scratch.
_COPY_SKIP_FILES = {'provision_bundle.json'}
_COPY_SKIP_SUFFIXES = ('_evidence.json', '_evidence.json.ts')


def copy_protocol_dir(src_id, new_id=None, new_name=None):
    """
    Duplicate protocol_dirs/<src_id>/ into a new protocol directory and register
    it. The copy is an ordinary protocol like any other.

    The copy starts UNPROVISIONED: golden_b64 / golden_ts are cleared from
    asp_args.json and provisioning bundles/evidence sidecars are not copied, so
    the user must re-provision it before running.

    Returns the new proto_id.
    """
    import shutil

    if not has_protocol_dir(src_id):
        raise ValueError(f"'{src_id}' has no protocol directory to copy")

    if not new_id:
        new_id = unique_protocol_id(src_id)
    if new_id in _get_registry() or has_protocol_dir(new_id):
        raise ValueError(f"Protocol id '{new_id}' already exists")

    src_dir = _protocol_dir(src_id)
    dst_dir = _protocol_dir(new_id)

    # Copy the canonical config files, skipping runtime/provisioned artifacts.
    os.makedirs(dst_dir, exist_ok=True)
    for fname in os.listdir(src_dir):
        if fname in _COPY_SKIP_FILES or fname.endswith(_COPY_SKIP_SUFFIXES):
            continue
        src = os.path.join(src_dir, fname)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(dst_dir, fname))

    # Clear provisioned goldens so the copy must be re-provisioned.
    asp_args_path = os.path.join(dst_dir, 'asp_args.json')
    try:
        with open(asp_args_path) as f:
            asp_args = json.load(f)
        for targets in asp_args.values():
            if isinstance(targets, dict):
                for entry in targets.values():
                    if isinstance(entry, dict):
                        entry.pop('golden_b64', None)
                        entry.pop('golden_ts', None)
        with open(asp_args_path, 'w') as f:
            json.dump(asp_args, f, indent=2)
            f.write('\n')
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    # Update display name in meta.json (id is the directory name).
    meta_path = os.path.join(dst_dir, 'meta.json')
    try:
        with open(meta_path) as f:
            meta = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        meta = {}
    if new_name:
        meta['name'] = new_name
    elif meta.get('name'):
        meta['name'] = f"Copy of {meta['name']}"
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)
        f.write('\n')

    # Register it. The copy lives under protocol_dirs/, so it is picked up
    # automatically on every subsequent startup — no separate config needed.
    register_protocol_dir(new_id, local_dir=dst_dir)
    return new_id


def load_all_protocols():
    """
    Populate REGISTRY by scanning protocol_dirs/. This is the single startup
    entry point used by both the dashboard and the MCP server.

    A protocol simply *is* a protocol_dirs/<id>/ directory: every directory is
    registered, with no built-in/custom distinction. Copies and imports live in
    the same tree and are therefore picked up identically.

    Safe to call more than once (registration is idempotent per id).
    """
    import sys
    for proto_id in list_protocol_dir_ids():
        try:
            register_protocol_dir(proto_id)
        except Exception as exc:
            print(f"[protocol_loader] WARNING: could not auto-register "
                  f"protocol_dir {proto_id!r}: {exc}", file=sys.stderr)
    return REGISTRY


def _get_registry():
    return REGISTRY


def list_cleanup_files(proto_id):
    """
    Return the paths that would be deleted when this protocol is removed. For
    the dir-only model this is simply the protocol's directory under
    protocol_dirs/. Called by the dashboard before showing the confirm dialog.
    """
    entry = _get_registry().get(proto_id)
    if not entry:
        return []
    local_dir = entry.get('imported_dir') or entry.get('custom_source')
    return [local_dir] if local_dir and os.path.isdir(local_dir) else []


def remove_protocol(proto_id, delete_files=False):
    """
    Remove a protocol from the REGISTRY. If delete_files=True, also deletes its
    protocol_dirs/<id>/ tree. All protocols are removable — a protocol is just a
    directory. (Directories that ship in the repo are recoverable via git.)
    Returns True if removed, False if not found.
    """
    registry = _get_registry()
    entry = registry.get(proto_id)
    if not entry:
        return False
    local_dir = entry.get('imported_dir') or entry.get('custom_source')

    # Stop any running am_place subprocesses for this protocol
    try:
        import place_manager
        place_manager.stop_all_places(proto_id)
    except Exception:
        pass

    del registry[proto_id]

    # Clear all persisted state so a re-registration starts fresh
    from evidence_slice import clear_protocol_state
    clear_protocol_state(proto_id)

    # Delete the protocol directory if requested
    if delete_files and local_dir and os.path.isdir(local_dir):
        import shutil
        shutil.rmtree(local_dir, ignore_errors=True)

    return True

