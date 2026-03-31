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


def _make_file_tamper_target(target_id, label, file_path, golden_path):
    """Create a generic file-based tamper_targets entry for a loaded protocol."""
    bad_bytes = f"[TAMPERED] {label} - modified to fail appraisal.".encode()

    def tamper():
        _tamper_file(file_path, golden_path, bad_bytes)

    def repair():
        src     = golden_path + '.src'
        default = golden_path + '.default'
        if os.path.exists(src):
            content = open(src, 'rb').read()
        elif os.path.exists(default):
            content = open(default, 'rb').read()
        else:
            content = open(file_path, 'rb').read()
        open(file_path, 'wb').write(content)

    def reset():
        default = golden_path + '.default'
        if os.path.exists(default):
            content = open(default, 'rb').read()
        else:
            content = open(file_path, 'rb').read()
        open(file_path, 'wb').write(content)
        _write_golden(golden_path, content)

    def get_state():
        return {'compliant': _file_compliant(file_path, golden_path)}

    def inspect():
        try:
            current_bytes = open(file_path, 'rb').read()
        except FileNotFoundError:
            return {'error': f'Target file not found: {os.path.basename(file_path)}'}
        try:
            golden_bytes = open(golden_path, 'rb').read()
        except FileNotFoundError:
            return {'error': 'Golden file not found — run Provision first'}
        compliant    = hashlib.sha256(current_bytes).digest() == golden_bytes
        src          = golden_path + '.src'
        provisioned  = None
        if os.path.exists(src):
            provisioned = open(src, 'rb').read().decode('utf-8', errors='replace')
        return {
            'type':           'file',
            'compliant':      compliant,
            'current':        current_bytes.decode('utf-8', errors='replace'),
            'current_sha256': hashlib.sha256(current_bytes).hexdigest(),
            'golden_sha256':  golden_bytes.hex(),
            'provisioned':    provisioned,
        }

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

    resolved_targets = [
        {
            'id':     t['id'],
            'label':  t['label'],
            'file':   os.path.abspath(os.path.expanduser(t['file'])),
            'golden': os.path.abspath(os.path.expanduser(t['golden'])),
        }
        for t in targets_spec
    ]

    def build():
        return json.dumps(manifest_obj), json.dumps(request_obj)

    def provision():
        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        result = []
        for t in resolved_targets:
            h = _write_golden(t['golden'], open(t['file'], 'rb').read())
            result.append({
                'target':    t['label'],
                'golden':    os.path.basename(t['golden']),
                'sha256':    h,
                'timestamp': ts,
                'tamper_id': t['id'],
            })
        return result

    def golden_state():
        result = []
        for t in resolved_targets:
            g = _read_golden(t['golden'])
            result.append({
                'target':    t['label'],
                'golden':    os.path.basename(t['golden']),
                'sha256':    g['sha256'] if g else None,
                'timestamp': g['timestamp'] if g else None,
                'tamper_id': t['id'],
            })
        return result

    tamper_targets = {
        t['id']: _make_file_tamper_target(t['id'], t['label'], t['file'], t['golden'])
        for t in resolved_targets
    }

    flow = spec.get('flow') or [
        {'type': 'asp', 'label': spec.get('copland', proto_id), 'style': 'default'}
    ]

    return proto_id, {
        'id':             proto_id,
        'name':           spec.get('name', proto_id),
        'description':    spec.get('description', ''),
        'copland':        spec.get('copland', ''),
        'flow':           flow,
        'build':          build,
        'provision':      provision,
        'golden_state':   golden_state,
        'tamper_targets': tamper_targets,
        'custom_source':  path,          # marks this as a dynamically-loaded protocol
    }


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


def remove_protocol(proto_id):
    """
    Remove a dynamically-loaded protocol from the REGISTRY and config.
    Returns True if removed, False if not found or built-in.
    """
    registry = _get_registry()
    entry = registry.get(proto_id)
    if not entry or 'custom_source' not in entry:
        return False
    source_file = entry['custom_source']
    del registry[proto_id]
    config = _load_config()
    config['files'] = [f for f in config['files'] if f != source_file]
    _save_config(config)
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
