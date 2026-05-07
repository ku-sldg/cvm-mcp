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

_CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'loaded_protocols.json')


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
                if asp_id and targ_id:
                    mapped = asp_args_map.get(asp_id, {}).get(targ_id)
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


def infer_tamper_config(term):
    """
    Walk a Copland term tree and return a dict of file-target metadata keyed by
    "<asp_id>::<filepath>" for every ASPC node whose ASP_ARGS include 'filepath'.

    Each entry:
      {
        "label":       "<basename(filepath)>",
        "asp_id":      "<asp_id>",
        "target_file": "<filepath>",
        "asp_args":    {<ASP_ARGS without golden_b64>}
      }
    """
    result = {}

    def _walk(node):
        if not isinstance(node, dict):
            return
        constructor = node.get('TERM_CONSTRUCTOR')
        body        = node.get('TERM_BODY')
        if constructor == 'asp':
            if isinstance(body, dict) and body.get('ASP_CONSTRUCTOR') == 'ASPC':
                asp_body = body.get('ASP_BODY', {})
                asp_id   = asp_body.get('ASP_ID', '')
                asp_args = asp_body.get('ASP_ARGS', {})
                filepath = asp_args.get('filepath', '')
                if asp_id and filepath:
                    tid = f'{asp_id}::{filepath}'
                    clean_args = {k: v for k, v in asp_args.items() if k != 'golden_b64'}
                    result[tid] = {
                        'label':       os.path.basename(filepath) or filepath,
                        'asp_id':      asp_id,
                        'target_file': filepath,
                        'asp_args':    clean_args,
                    }
            return
        if isinstance(body, list):
            for child in body:
                if isinstance(child, dict):
                    _walk(child)

    _walk(term)
    return result


def create_target_stubs(tamper_config, targets_dir):
    """
    For each target in tamper_config whose target_file doesn't exist locally,
    create a stub file in targets_dir.

    Returns a rewrite dict {original_path: stub_path}.
    """
    rewrites = {}
    for tid, cfg in tamper_config.items():
        target_file = cfg.get('target_file', '')
        if not target_file or os.path.exists(target_file):
            continue
        os.makedirs(targets_dir, exist_ok=True)
        stub_name = os.path.basename(target_file) or tid.replace('::', '_')
        base, ext = os.path.splitext(stub_name)
        stub_path = os.path.join(targets_dir, stub_name)
        n = 1
        while os.path.exists(stub_path) and stub_path not in rewrites.values():
            stub_path = os.path.join(targets_dir, f'{base}_{n}{ext}')
            n += 1
        with open(stub_path, 'wb') as f:
            f.write(b'# stub created by cvm-mcp import -- replace with the real file\n')
        rewrites[target_file] = stub_path
    return rewrites


def _rewrite_paths_in_term(term, rewrites):
    """Return a deep copy of *term* with filepath values replaced per *rewrites*."""
    import copy
    term = copy.deepcopy(term)

    def _walk(node):
        if not isinstance(node, dict):
            return
        constructor = node.get('TERM_CONSTRUCTOR')
        body        = node.get('TERM_BODY')
        if constructor == 'asp':
            if isinstance(body, dict) and body.get('ASP_CONSTRUCTOR') == 'ASPC':
                asp_body = body.get('ASP_BODY', {})
                asp_args = asp_body.get('ASP_ARGS', {})
                fp = asp_args.get('filepath', '')
                if fp in rewrites:
                    asp_args['filepath'] = rewrites[fp]
            return
        if isinstance(body, list):
            for child in body:
                if isinstance(child, dict):
                    _walk(child)

    _walk(term)
    return term


def import_protocol_dir(source_path, proto_id=None):
    """
    Import a protocol directory from *source_path* into the local
    protocol_dirs/<proto_id>/ tree.

    Steps:
      1. Read term.json / session.json / manifest.json from source (required).
         meta.json is optional — a default is generated from term.json when absent.
      2. Infer tamper_config from term (merge label overrides from source
         tamper_config.json if present).
      3. Create stub files in protocol_dirs/<proto_id>/targets/ for any
         target_file paths that do not exist locally.
      4. Write term_local.json with rewritten paths when stubs were created.
      5. Copy core JSON files to the local directory.
      6. Register the protocol in REGISTRY via register_protocol_dir().
      7. Return proto_id.

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

    # Guard against clobbering built-in protocols
    registry = _get_registry()
    if proto_id in registry and 'custom_source' not in registry[proto_id]:
        raise ValueError(
            f"'{proto_id}' is a built-in protocol and cannot be replaced by import."
        )

    # Merge tamper_config: infer from term, apply label overrides from source
    tamper_config = infer_tamper_config(term)
    try:
        source_tamper = _read('tamper_config.json')
        for tid, cfg in source_tamper.items():
            if tid in tamper_config:
                if 'label' in cfg:
                    tamper_config[tid]['label'] = cfg['label']
            else:
                tamper_config[tid] = cfg  # preserve entries we couldn't infer
    except (FileNotFoundError, KeyError):
        pass

    # Create local directory
    local_dir   = _protocol_dir(proto_id)
    targets_dir = os.path.join(local_dir, 'targets')
    os.makedirs(local_dir, exist_ok=True)

    # Create stubs for missing targets; rewrite tamper_config + term
    rewrites = create_target_stubs(tamper_config, targets_dir)
    if rewrites:
        # Update tamper_config entries with rewritten paths
        for tid, cfg in tamper_config.items():
            orig = cfg.get('target_file', '')
            if orig in rewrites:
                cfg['target_file_original'] = orig
                cfg['target_file']          = rewrites[orig]
                cfg['stub']                 = True
                if isinstance(cfg.get('asp_args'), dict) and 'filepath' in cfg['asp_args']:
                    cfg['asp_args'] = {**cfg['asp_args'], 'filepath': rewrites[orig]}
        # Write term_local.json with rewritten paths
        term_local = _rewrite_paths_in_term(term, rewrites)
        with open(os.path.join(local_dir, 'term_local.json'), 'w') as f:
            json.dump(term_local, f, indent=2)
            f.write('\n')

    def _write(filename, data):
        with open(os.path.join(local_dir, filename), 'w') as f:
            json.dump(data, f, indent=2)
            f.write('\n')

    _write('meta.json', meta)
    _write('term.json', term)
    _write('session.json', session)
    _write('manifest.json', manifest)
    _write('tamper_config.json', tamper_config)

    asp_args_path = os.path.join(local_dir, 'asp_args.json')
    if not os.path.exists(asp_args_path):
        _write('asp_args.json', {})

    for fname in ('term_no_appr.json', 'term_no_appr_provisioned.json'):
        src = os.path.join(source_path, fname)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(local_dir, fname))

    register_protocol_dir(proto_id, local_dir=local_dir, source_path=source_path)
    return proto_id


def _build_tamper_targets_from_config(proto_id, tamper_config):
    """
    Build a tamper_targets dict from a tamper_config dict
    (as loaded from tamper_config.json).
    """
    targets = {}
    for tid, cfg in tamper_config.items():
        target_file = cfg.get('target_file', '')
        if not target_file:
            continue
        label    = cfg.get('label', tid)
        asp_id   = cfg.get('asp_id') or None
        asp_args = cfg.get('asp_args') if cfg.get('asp_args') is not None else None
        targets[tid] = _make_file_tamper_target(
            tid, label, target_file, '',
            golden_evidence_path=None,
            asp_id=asp_id,
            asp_args=asp_args,
            asp_types={},
            proto_id=proto_id,
        )
    return targets


def register_protocol_dir(proto_id, local_dir=None, source_path=None):
    """
    Build a REGISTRY entry backed by protocol_dirs/<proto_id>/ and insert it.

    Reads meta.json and tamper_config.json from *local_dir*
    (defaults to _protocol_dir(proto_id)).  Creates provision / golden_state
    closures compatible with the rest of the dashboard.

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

    # Read tamper_config
    try:
        with open(os.path.join(local_dir, 'tamper_config.json')) as f:
            tamper_config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        tamper_config = {}

    tamper_targets = _build_tamper_targets_from_config(proto_id, tamper_config)

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

    # Determine which ASP_IDs use goldenbytes_appr in this session.
    # Only these protocols support the new provision flow.
    try:
        _session_for_init = json.load(open(os.path.join(local_dir, 'session.json')))
    except Exception:
        _session_for_init = {}
    _comps_for_init = (_session_for_init
                       .get('Session_Context', {})
                       .get('ASP_Comps', {}))
    _has_goldenbytes_appr = any(v == 'goldenbytes_appr' for v in _comps_for_init.values())

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

        # Save .original snapshots of any tamper target files before running
        for cfg in tamper_config.values():
            fp = cfg.get('target_file', '')
            if fp:
                orig = fp + '.original'
                if not os.path.exists(orig):
                    try:
                        open(orig, 'wb').write(open(fp, 'rb').read())
                    except FileNotFoundError:
                        pass

        # Run CVM with measurement-only term (APPR → NULL) so it always succeeds
        meas_term = _make_measurement_term(term_obj)
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
                    'tamper_id': targ_id,
                })

        if changed:
            with open(asp_args_path, 'w') as _f:
                json.dump(asp_args, _f, indent=2)
                _f.write('\n')

        return resolved

    def golden_state():
        """Return provision state for each goldenbytes_appr target from asp_args.json."""
        asp_args    = _load_asp_args(proto_id)
        session_obj = json.load(open(os.path.join(local_dir, 'session.json')))
        comps       = session_obj.get('Session_Context', {}).get('ASP_Comps', {})
        bundle_path = os.path.join(local_dir, 'provision_bundle.json')
        result = []
        for asp_id, targets in asp_args.items():
            if comps.get(asp_id) != 'goldenbytes_appr':
                continue
            for targ_id, args in targets.items():
                golden_b64 = args.get('golden_b64', '')
                ts         = args.get('golden_ts') if golden_b64 else None
                result.append({
                    'target':      targ_id,
                    'golden':      'provision_bundle.json' if golden_b64 else None,
                    'golden_path': bundle_path if golden_b64 else None,
                    'sha256':      None,
                    'timestamp':   ts,
                    'tamper_id':   targ_id,
                })
        return result

    def prepare(req):
        # golden_b64 is already written to asp_args.json at provision time and
        # injected into the term via inject_asp_args() inside _effective_term()
        # (called by build()). No additional run-time injection is needed.
        return req

    # ── Legacy (non-goldenbytes_appr) provision flow ──────────────────────────
    # Protocols whose appraiser is NOT goldenbytes_appr (e.g. goldenevidence_appr,
    # readfile_appr, etc.) keep the old tamper_config-driven flow that stores
    # golden slices in target_goldens.json via do_evidence_slice (Python).
    def _legacy_provision(golden_path=None):
        from cvm_client import run_cvm
        from evidence_slice import (
            store_golden_evidence, load_golden_evidence,
            do_evidence_slice, store_target_golden, store_provision_path,
        )
        from protocol_builder import _make_measurement_term

        asp_bin = os.environ.get(
            'CVM_ASP_BIN',
            os.path.expanduser('~/Claude_workspace/asp-libs/target/release'),
        )

        manifest_obj = json.load(open(os.path.join(local_dir, 'manifest.json')))
        session_obj  = json.load(open(os.path.join(local_dir, 'session.json')))
        term_obj     = _effective_term()
        asp_types    = session_obj.get('Session_Context', {}).get('ASP_Types', {})

        golden_evidence_path = os.path.join(local_dir, f'{proto_id}_evidence.json')
        actual_ev_path = (
            os.path.abspath(os.path.expanduser(golden_path))
            if golden_path else golden_evidence_path
        )

        _, _, _, owner = load_golden_evidence(actual_ev_path)
        if owner and owner != proto_id:
            raise RuntimeError(
                f"Bundle '{os.path.basename(actual_ev_path)}' was provisioned by "
                f"'{owner}', not '{proto_id}'. Choose a different path."
            )

        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        for cfg in tamper_config.values():
            fp = cfg.get('target_file', '')
            if fp:
                orig = fp + '.original'
                if not os.path.exists(orig):
                    try:
                        open(orig, 'wb').write(open(fp, 'rb').read())
                    except FileNotFoundError:
                        pass

        request_obj = {
            'TYPE':    'REQUEST',
            'ACTION':  'RUN',
            'REQ_PLC': session_obj.get('Session_Plc', 'P0'),
            'TO_PLC':  session_obj.get('Session_Plc', 'P0'),
            'TERM':    term_obj,
            'EVIDENCE': [{'RawEv': []}, {'EvidenceT_CONSTRUCTOR': 'mt_evt'}],
            'ATTESTATION_SESSION': session_obj,
        }
        meas_term    = _make_measurement_term(term_obj)
        meas_request = {**request_obj, 'TERM': meas_term}

        response = run_cvm(manifest_obj, meas_request, asp_bin)
        if not response.get('SUCCESS'):
            raise RuntimeError(
                f"CVM provision run failed: {response.get('PAYLOAD', 'unknown error')}"
            )

        payload = response['PAYLOAD']
        store_golden_evidence(actual_ev_path, payload, proto_id)

        raw_ev_list = payload[0].get('RawEv', [])
        et          = payload[1]
        resolved    = []

        for tid, cfg in tamper_config.items():
            asp_id   = cfg.get('asp_id')
            asp_args = cfg.get('asp_args')
            label    = cfg.get('label', tid)
            fp       = cfg.get('target_file', '')
            if asp_id and asp_args is not None:
                ev_slice = do_evidence_slice(et, raw_ev_list, asp_types, asp_id, asp_args)
                if ev_slice:
                    store_target_golden(asp_id, asp_args, ev_slice[0],
                                        proto_id, actual_ev_path, ts)
                    orig_golden = fp + f'.{proto_id}.original_golden.json' if fp else None
                    if orig_golden and not os.path.exists(orig_golden):
                        import base64
                        with open(orig_golden, 'w') as _f:
                            json.dump({
                                'golden_b64':           ev_slice[0],
                                'timestamp':            ts,
                                'asp_id':               asp_id,
                                'asp_args':             asp_args,
                                'protocol_id':          proto_id,
                                'evidence_bundle':      os.path.basename(actual_ev_path),
                                'evidence_bundle_path': actual_ev_path,
                            }, _f)
            resolved.append({'target': label, 'golden': os.path.basename(actual_ev_path),
                              'timestamp': ts, 'tamper_id': tid})

        store_provision_path(proto_id, actual_ev_path)
        return resolved

    def _legacy_golden_state():
        result = []
        for tid, cfg in tamper_config.items():
            asp_id   = cfg.get('asp_id')
            asp_args = cfg.get('asp_args')
            label    = cfg.get('label', tid)
            ts = golden = golden_path = None
            if asp_id and asp_args is not None:
                from evidence_slice import load_target_golden
                entry = load_target_golden(asp_id, asp_args, proto_id)
                if entry:
                    ts          = entry.get('timestamp', '')
                    golden      = entry.get('evidence_bundle')
                    golden_path = entry.get('evidence_bundle_path') or None
            result.append({
                'target':      label,
                'golden':      golden,
                'golden_path': golden_path,
                'sha256':      None,
                'timestamp':   ts,
                'tamper_id':   tid,
            })
        return result

    def _legacy_prepare(req):
        from protocol_builder import inject_golden_b64
        return {**req, 'TERM': inject_golden_b64(req.get('TERM', {}), proto_id)}

    # Select provision strategy and build REGISTRY entry
    if _has_goldenbytes_appr:
        _provision_fn    = provision
        _golden_state_fn = golden_state
        _prepare_fn      = prepare
    elif tamper_config:
        _provision_fn    = _legacy_provision
        _golden_state_fn = _legacy_golden_state
        _prepare_fn      = _legacy_prepare
    else:
        _provision_fn = _golden_state_fn = _prepare_fn = None

    entry = {
        'id':             proto_id,
        'name':           meta.get('name', proto_id),
        'description':    meta.get('description', ''),
        'copland':        meta.get('copland', ''),
        'flow':           meta.get('flow', []),
        'build':          build,
        'tamper_targets': tamper_targets,
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
      - inferred_targets: result of infer_tamper_config(term)
      - stubs_needed: list of target_file paths that don't exist locally
      - warnings: list of warning strings
      - error: string or None
    """
    source_path = os.path.abspath(os.path.expanduser(source_path))
    required = ('term.json', 'session.json', 'manifest.json')
    optional = ('meta.json', 'tamper_config.json', 'term_no_appr.json', 'asp_args.json')

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
            'error':            f"Missing required files: {', '.join(files_missing)}",
            'files_found':      files_found,
            'files_missing':    files_missing,
            'proto_id':         None,
            'name':             None,
            'meta_generated':   False,
            'inferred_targets': {},
            'stubs_needed':     [],
            'warnings':         [],
        }

    try:
        with open(os.path.join(source_path, 'term.json')) as f:
            term = json.load(f)
    except Exception as e:
        return {'error': f'Could not parse term.json: {e}', 'files_found': files_found,
                'files_missing': [], 'proto_id': None, 'name': None,
                'meta_generated': False, 'inferred_targets': {}, 'stubs_needed': [],
                'warnings': []}

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
                    'meta_generated': False, 'inferred_targets': {}, 'stubs_needed': [],
                    'warnings': []}
    else:
        meta = _default_meta_from_term(proto_id, term)
        meta_generated = True

    proto_id = os.path.basename(source_path.rstrip('/\\'))
    inferred = infer_tamper_config(term)
    stubs_needed = [
        cfg['target_file']
        for cfg in inferred.values()
        if cfg.get('target_file') and not os.path.exists(cfg['target_file'])
    ]

    warnings = []
    registry = _get_registry()
    if proto_id in registry and 'custom_source' not in registry[proto_id]:
        warnings.append(
            f"'{proto_id}' is a built-in protocol — import will be rejected. "
            "Rename the directory first."
        )
    elif proto_id in registry:
        warnings.append(f"'{proto_id}' is already imported; re-importing will overwrite it.")

    if meta_generated:
        warnings.append(
            "meta.json not found — name, copland, and flow were inferred from term.json."
        )

    if stubs_needed:
        warnings.append(
            f"{len(stubs_needed)} target file(s) not found locally — "
            "stub files will be created in targets/."
        )

    return {
        'error':            None,
        'proto_id':         proto_id,
        'name':             meta.get('name', proto_id),
        'description':      meta.get('description', ''),
        'copland':          meta.get('copland', ''),
        'flow':             meta.get('flow', []),
        'meta_generated':   meta_generated,
        'files_found':      files_found,
        'files_missing':    [],
        'inferred_targets': inferred,
        'stubs_needed':     stubs_needed,
        'warnings':         warnings,
    }


def add_protocol_dir(source_path):
    """Import a protocol directory, persist it to config, and return its proto_id."""
    proto_id = import_protocol_dir(source_path)
    config = _load_config()
    dirs = config.setdefault('dirs', [])
    entry = {'source': os.path.abspath(os.path.expanduser(source_path)),
             'proto_id': proto_id}
    if not any(d.get('proto_id') == proto_id for d in dirs):
        dirs.append(entry)
        _save_config(config)
    return proto_id


def load_saved_protocol_dirs():
    """
    Re-register all imported protocol directories saved in loaded_protocols.json.
    Called once at startup.
    """
    config = _load_config()
    for entry in config.get('dirs', []):
        proto_id  = entry.get('proto_id', '')
        local_dir = _protocol_dir(proto_id)
        if proto_id and os.path.isdir(local_dir):
            try:
                register_protocol_dir(proto_id, local_dir=local_dir,
                                      source_path=entry.get('source'))
            except Exception as exc:
                import sys
                print(f"[protocol_loader] WARNING: could not re-register "
                      f"imported dir '{proto_id}': {exc}", file=sys.stderr)


def _get_registry():
    from protocols import REGISTRY
    return REGISTRY


def _write_golden(path, data):
    from protocols import _write_golden as _wg
    return _wg(path, data)


def _read_golden(path):
    from protocols import _read_golden as _rg
    return _rg(path)


def _file_compliant(file_path, golden_path):
    from protocols import _file_compliant as _fc
    return _fc(file_path, golden_path)


def _tamper_file(file_path, golden_path, bad_bytes):
    from protocols import _tamper_file as _tf
    return _tf(file_path, golden_path, bad_bytes)


def _make_file_tamper_target(target_id, label, file_path, golden_path,
                              golden_evidence_path=None, asp_id=None,
                              asp_args=None, asp_types=None, proto_id=None):
    """
    Create a generic file-based tamper_targets entry for a loaded protocol.

    asp_id / asp_args: the measurement ASP and its exact args for this target,
                       used to look up the golden from the shared target store.
    golden_evidence_path / asp_types: kept for API compatibility, not used.
    """
    bad_bytes = f"[TAMPERED] {label} - modified to fail appraisal.".encode()

    def _get_golden_hash():
        if asp_id and asp_args is not None:
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
            return   # no restore point — provision first
        open(file_path, 'wb').write(content)

    def reset():
        orig    = file_path + '.original'
        default = file_path + '.default'
        if os.path.exists(orig):
            content = open(orig, 'rb').read()
        elif os.path.exists(default):
            content = open(default, 'rb').read()
        else:
            return   # no restore point — provision first
        open(file_path, 'wb').write(content)
        # Restore original golden so compliance check passes after reset
        orig_golden = file_path + (f'.{proto_id}.original_golden.json' if proto_id else '.original_golden.json')
        if os.path.exists(orig_golden) and asp_id and asp_args is not None:
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
        if asp_id and asp_args is not None:
            from evidence_slice import load_target_golden
            import base64
            entry = load_target_golden(asp_id, asp_args, proto_id)
            if entry is None:
                return {'compliant': None}   # not yet provisioned
            try:
                current  = hashlib.sha256(open(file_path, 'rb').read()).digest()
                expected = base64.b64decode(entry['golden_b64'])
                return {'compliant': current == expected}
            except Exception:
                return {'compliant': None}
        return {'compliant': _file_compliant(file_path, golden_path)}

    def inspect():
        try:
            current_bytes = open(file_path, 'rb').read()
        except FileNotFoundError:
            return {'error': f'Target file not found: {os.path.basename(file_path)}'}

        result = {
            'type':           'file',
            'current':        current_bytes.decode('utf-8', errors='replace'),
            'current_sha256': hashlib.sha256(current_bytes).hexdigest(),
        }

        src = file_path + '.src'
        if os.path.exists(src):
            result['pre_tamper'] = open(src, 'rb').read().decode('utf-8', errors='replace')
        orig = file_path + '.original'
        if os.path.exists(orig):
            result['original'] = open(orig, 'rb').read().decode('utf-8', errors='replace')

        if asp_id and asp_args is not None:
            from evidence_slice import load_target_golden
            import base64
            entry = load_target_golden(asp_id, asp_args, proto_id)
            if entry is None:
                return {**result, 'error': 'No golden evidence — run Provision first'}
            result['evidence_timestamp'] = entry.get('timestamp', '')
            result['golden_protocol']    = entry.get('protocol_id', '')
            result['evidence_bundle']    = entry.get('evidence_bundle', '')
            try:
                expected = base64.b64decode(entry['golden_b64'])
                result['golden_sha256'] = expected.hex()
                result['compliant']     = (
                    hashlib.sha256(current_bytes).digest() == expected
                )
            except Exception as e:
                result['evidence_slice_error'] = str(e)
            return result

        return {**result, 'error': 'No golden evidence — run Provision first'}

    return {
        'label':     label,
        'tamper':    tamper,
        'repair':    repair,
        'reset':     reset,
        'get_state': get_state,
        'inspect':   inspect,
    }


def load_protocol_from_file(path):
    """
    Parse a protocol JSON file and return (proto_id, registry_entry).
    Raises on missing required fields or file errors.
    """
    path = os.path.abspath(os.path.expanduser(path))
    with open(path) as f:
        spec = json.load(f)

    for required in ('id', 'manifest', 'request'):
        if required not in spec:
            raise ValueError(f"Protocol JSON missing required field: '{required}'")

    proto_id     = spec['id']
    manifest_obj = spec['manifest']
    request_obj  = spec['request']
    targets_spec = spec.get('targets', [])

    # Evidence bundle stored alongside the spec file: <proto_id>_evidence.json
    golden_evidence_path = os.path.splitext(path)[0] + '_evidence.json'

    # ASP_Types from the session context — needed by do_evidence_slice
    asp_types = (
        request_obj.get('ATTESTATION_SESSION', {})
                   .get('Session_Context', {})
                   .get('ASP_Types', {})
    )

    resolved_targets = [
        {
            'id':      t['id'],
            'label':   t['label'],
            'file':    os.path.abspath(os.path.expanduser(t['file'])),
            'golden':  os.path.abspath(os.path.expanduser(t['golden'])),
            'asp_id':  t.get('asp_id'),
            'asp_args': t.get('asp_args'),
        }
        for t in targets_spec
    ]

    def build():
        return json.dumps(manifest_obj), json.dumps(request_obj)

    def provision(golden_path=None):
        from cvm_client import run_cvm
        from evidence_slice import store_golden_evidence, load_golden_evidence
        from protocol_builder import _make_measurement_term

        actual_ev_path = (os.path.abspath(os.path.expanduser(golden_path))
                          if golden_path else golden_evidence_path)

        # Conflict check: refuse to overwrite a bundle owned by a different protocol
        _, _, _, owner = load_golden_evidence(actual_ev_path)
        if owner and owner != proto_id:
            raise RuntimeError(
                f"Bundle '{os.path.basename(actual_ev_path)}' was provisioned by "
                f"'{owner}', not '{proto_id}'. Choose a different path."
            )
        ts      = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        asp_bin = os.environ.get(
            'CVM_ASP_BIN',
            os.path.expanduser('~/Claude_workspace/asp-libs/target/release'),
        )

        # Save per-file original snapshots (for repair/reset) before running CVM
        for t in resolved_targets:
            orig = t['file'] + '.original'
            if not os.path.exists(orig):
                try:
                    open(orig, 'wb').write(open(t['file'], 'rb').read())
                except FileNotFoundError:
                    pass

        # Run CVM with a measurement-only term (APPR → NULL) so it always succeeds
        meas_term    = _make_measurement_term(request_obj.get('TERM', {}))
        meas_request = {**request_obj, 'TERM': meas_term}

        response = run_cvm(manifest_obj, meas_request, asp_bin)
        if not response.get('SUCCESS'):
            raise RuntimeError(
                f"CVM provision run failed: {response.get('PAYLOAD', 'unknown error')}"
            )

        payload = response['PAYLOAD']
        store_golden_evidence(actual_ev_path, payload, proto_id)

        # Populate shared target golden store
        from evidence_slice import do_evidence_slice, store_target_golden
        raw_ev_list = payload[0].get('RawEv', [])
        et          = payload[1]
        for t in resolved_targets:
            if t.get('asp_id') and t.get('asp_args') is not None:
                ev_slice = do_evidence_slice(et, raw_ev_list, asp_types,
                                             t['asp_id'], t['asp_args'])
                if ev_slice:
                    store_target_golden(t['asp_id'], t['asp_args'], ev_slice[0],
                                        proto_id, actual_ev_path, ts)
                    # Save original-golden sidecar for reset semantics (never overwritten)
                    orig_golden = t['file'] + f'.{proto_id}.original_golden.json'
                    if not os.path.exists(orig_golden):
                        with open(orig_golden, 'w') as _f:
                            # Always use the default bundle path in the sidecar so reset()
                            # shows the protocol's canonical bundle name, not a custom path.
                            json.dump({
                                'golden_b64':           ev_slice[0],
                                'timestamp':            ts,
                                'asp_id':               t['asp_id'],
                                'asp_args':             t['asp_args'],
                                'protocol_id':          proto_id,
                                'evidence_bundle':      os.path.basename(golden_evidence_path),
                                'evidence_bundle_path': golden_evidence_path,
                            }, _f)

        from evidence_slice import store_provision_path
        store_provision_path(proto_id, actual_ev_path)

        return [
            {
                'target':    t['label'],
                'golden':    os.path.basename(actual_ev_path),
                'timestamp': ts,
                'tamper_id': t['id'],
            }
            for t in resolved_targets
        ]

    def golden_state():
        from evidence_slice import load_target_golden, load_golden_evidence
        result = []
        for t in resolved_targets:
            ts, golden, golden_path = None, None, None
            if t.get('asp_id') and t.get('asp_args') is not None:
                # Source of truth is target_goldens.json — don't fall back to the
                # bundle file, which may exist from a prior provision/different protocol.
                entry = load_target_golden(t['asp_id'], t['asp_args'], proto_id)
                if entry:
                    ts          = entry.get('timestamp', '')
                    golden      = entry.get('evidence_bundle')
                    golden_path = entry.get('evidence_bundle_path') or None
            else:
                # No asp_id/args — fall back to bundle file timestamp
                if not ts:
                    _, _, ts, _ = load_golden_evidence(golden_evidence_path)
            result.append({
                'target':      t['label'],
                'golden':      golden,
                'golden_path': golden_path,
                'sha256':      None,
                'timestamp':   ts,
                'tamper_id':   t['id'],
            })
        return result

    tamper_targets = {
        t['id']: _make_file_tamper_target(
            t['id'], t['label'], t['file'], t['golden'],
            golden_evidence_path=golden_evidence_path,
            asp_id=t.get('asp_id'),
            asp_args=t.get('asp_args'),
            asp_types=asp_types,
            proto_id=proto_id,
        )
        for t in resolved_targets
    }

    flow = spec.get('flow') or [
        {'type': 'asp', 'label': spec.get('copland', proto_id), 'style': 'default'}
    ]

    # Reconstruct step builders from the serialized steps array (if present).
    # Each step was stored as {id, label, manifest, request} by save_and_register.
    _spec_steps = spec.get('steps', [])
    reconstructed_steps = [
        (s['id'], s['label'],
         (lambda m=s['manifest'], r=s['request']: (json.dumps(m), json.dumps(r))))
        for s in _spec_steps
    ] or None

    def prepare(req):
        """Inject golden_b64 into ASPC ASP_ARGS from the shared target golden store."""
        from protocol_builder import inject_golden_b64
        return {**req, 'TERM': inject_golden_b64(req.get('TERM', {}), proto_id)}

    entry = {
        'id':             proto_id,
        'name':           spec.get('name', proto_id),
        'description':    spec.get('description', ''),
        'copland':        spec.get('copland', ''),
        'flow':           flow,
        'build':          build,
        'provision':      provision,
        'golden_state':   golden_state,
        'prepare':        prepare,
        'tamper_targets': tamper_targets,
        'places':         spec.get('places', {}),
        'custom_source':  path,          # marks this as a dynamically-loaded protocol
    }
    if reconstructed_steps:
        entry['steps'] = reconstructed_steps
    return proto_id, entry


def register_protocol_file(path):
    """Load a protocol JSON file and insert it into the REGISTRY. Returns proto_id."""
    proto_id, entry = load_protocol_from_file(path)
    _get_registry()[proto_id] = entry
    return proto_id


# ── Config persistence ────────────────────────────────────────────────────────

def _load_config():
    try:
        cfg = json.load(open(_CONFIG_FILE))
        cfg.setdefault('files', [])
        cfg.setdefault('dirs',  [])
        return cfg
    except (FileNotFoundError, json.JSONDecodeError):
        return {'files': [], 'dirs': []}


def _save_config(config):
    with open(_CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)


def add_protocol_file(path):
    """Register a protocol file, persist it to config, and return its proto_id."""
    proto_id = register_protocol_file(path)
    path = os.path.abspath(os.path.expanduser(path))
    config = _load_config()
    if path not in config['files']:
        config['files'].append(path)
        _save_config(config)
    return proto_id


def list_cleanup_files(proto_id):
    """
    Return an ordered list of file paths that exist on disk and would be
    deleted when this protocol is removed.  Called by the dashboard before
    showing the confirmation dialog.
    """
    registry = _get_registry()
    entry = registry.get(proto_id)
    if not entry or 'custom_source' not in entry:
        return []

    source_file = entry['custom_source']
    seen = set()
    files = []

    def _add(path):
        if path and path not in seen and os.path.exists(path):
            seen.add(path)
            files.append(path)

    # Protocol JSON file
    _add(source_file)

    # Evidence bundles from provision history + the default bundle path
    from evidence_slice import load_provision_history, _EXAMPLES_DIR
    default_bundle = os.path.splitext(source_file)[0] + '_evidence.json'
    for p in list(dict.fromkeys(load_provision_history(proto_id) + [default_bundle])):
        _add(p)

    # .{proto_id}.original_golden.json sidecars
    suffix = f'.{proto_id}.original_golden.json'
    for search_dir in dict.fromkeys([_EXAMPLES_DIR, os.path.dirname(source_file)]):
        try:
            for fname in os.listdir(search_dir):
                if fname.endswith(suffix):
                    _add(os.path.join(search_dir, fname))
        except Exception:
            pass

    return files


def remove_protocol(proto_id, delete_files=False):
    """
    Remove a dynamically-loaded protocol from the REGISTRY and config.
    If delete_files=True, also deletes the protocol JSON, evidence bundles,
    and sidecar files returned by list_cleanup_files().
    Returns True if removed, False if not found or built-in.
    """
    registry = _get_registry()
    entry = registry.get(proto_id)
    if not entry or 'custom_source' not in entry:
        return False
    source_file = entry['custom_source']

    # Collect files before modifying registry (list_cleanup_files reads registry)
    files_to_delete = list_cleanup_files(proto_id) if delete_files else []

    # Stop any running am_place subprocesses for this protocol
    try:
        import place_manager
        place_manager.stop_all_places(proto_id)
    except Exception:
        pass

    del registry[proto_id]
    config = _load_config()
    config['files'] = [f for f in config['files'] if f != source_file]
    config['dirs']  = [d for d in config.get('dirs', []) if d.get('proto_id') != proto_id]
    _save_config(config)

    # Clear all persisted state so a re-registration starts fresh
    from evidence_slice import clear_protocol_state
    clear_protocol_state(proto_id)

    # Also delete sidecars in the directory where the protocol file lives,
    # in case targets point to files outside the examples/ dir
    try:
        proto_dir = os.path.dirname(source_file)
        suffix = f'.{proto_id}.original_golden.json'
        for fname in os.listdir(proto_dir):
            if fname.endswith(suffix):
                try:
                    os.remove(os.path.join(proto_dir, fname))
                except Exception:
                    pass
    except Exception:
        pass

    # Delete provisioning files if requested
    for fpath in files_to_delete:
        try:
            os.remove(fpath)
        except Exception:
            pass

    return True


def load_saved_protocols():
    """
    Load all previously-added protocol files on startup.
    Returns list of (path, error_string) for any that failed.
    """
    config = _load_config()
    errors = []
    for path in config.get('files', []):
        try:
            register_protocol_file(path)
        except Exception as e:
            errors.append((path, str(e)))
    return errors
