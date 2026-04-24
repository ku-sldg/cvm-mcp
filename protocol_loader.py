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
        return json.load(open(_CONFIG_FILE))
    except (FileNotFoundError, json.JSONDecodeError):
        return {'files': []}


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
