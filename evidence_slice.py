"""
Copland evidence bundle storage and do_EvidenceSlice.

Mirrors do_EvidenceSlice / et_size from rust-am-lib/src/copland.rs.

Evidence bundle format (matches CVM PAYLOAD):
  [
    {"RawEv": ["<base64>", ...]},
    {"EvidenceT_CONSTRUCTOR": "...", "EvidenceT_BODY": ...}
  ]

ASP_Types format (from Session_Context.ASP_Types):
  {
    "hashfile": {"FWD": {"FWD": "REPLACE", "_BODY": 1}, "ATTRS": []},
    "sig":      {"FWD": {"FWD": "EXTEND",  "_BODY": 1, "EvInSig": "ALL"}, "ATTRS": []},
    ...
  }
"""

import json
import os
import datetime


# ── Evidence type size ────────────────────────────────────────────────────────

def et_size(et, asp_types):
    """
    Return the number of raw evidence items produced by an EvidenceT node.
    Mirrors et_size from copland.rs.
    """
    if not isinstance(et, dict):
        return 0
    ctor = et.get('EvidenceT_CONSTRUCTOR', '')
    body = et.get('EvidenceT_BODY')

    if ctor in ('mt_evt', 'nonce_evt'):
        return 0

    elif ctor == 'asp_evt':
        # body = [place, ASP_PARAMS, sub_EvidenceT]
        if not isinstance(body, list) or len(body) < 3:
            return 0
        params  = body[1]
        sub_et  = body[2]
        asp_id  = params.get('ASP_ID', '') if isinstance(params, dict) else ''
        evsig   = asp_types.get(asp_id, {})
        fwd     = evsig.get('FWD', {})
        kind    = fwd.get('FWD', '')
        n       = fwd.get('_BODY', 0)
        if kind == 'REPLACE':
            return n
        elif kind == 'EXTEND':
            return n + et_size(sub_et, asp_types)
        return 0

    elif ctor in ('left_evt', 'right_evt'):
        return et_size(body, asp_types) if isinstance(body, dict) else 0

    elif ctor == 'split_evt':
        if not isinstance(body, list):
            return 0
        return sum(et_size(child, asp_types) for child in body)

    return 0


# ── Evidence slicing ──────────────────────────────────────────────────────────

def do_evidence_slice(et, raw_ev, asp_types, target_id, target_args):
    """
    Extract the raw evidence slice produced by a specific ASP instance.

    Mirrors do_EvidenceSlice / do_EvidenceSlice_inner from copland.rs.

    Args:
        et:           EvidenceT dict (PAYLOAD[1])
        raw_ev:       list of base64 raw-evidence strings (PAYLOAD[0]['RawEv'])
        asp_types:    Session_Context.ASP_Types dict
        target_id:    ASP_ID to extract (e.g. 'hashfile')
        target_args:  ASP_ARGS dict to match exactly

    Returns:
        list of matching base64 strings, or None if not found
    """
    if not isinstance(et, dict):
        return None

    ctor = et.get('EvidenceT_CONSTRUCTOR', '')
    body = et.get('EvidenceT_BODY')

    if ctor in ('mt_evt', 'nonce_evt'):
        return None

    elif ctor == 'split_evt':
        if not isinstance(body, list) or len(body) < 2:
            return None
        et1, et2 = body[0], body[1]
        n1 = et_size(et1, asp_types)
        n2 = et_size(et2, asp_types)
        r1, rest = raw_ev[:n1], raw_ev[n1:]
        result = do_evidence_slice(et1, r1, asp_types, target_id, target_args)
        if result is not None:
            return result
        r2 = rest[:n2]
        return do_evidence_slice(et2, r2, asp_types, target_id, target_args)

    elif ctor in ('left_evt', 'right_evt'):
        if not isinstance(body, dict):
            return None
        return do_evidence_slice(body, raw_ev, asp_types, target_id, target_args)

    elif ctor == 'asp_evt':
        if not isinstance(body, list) or len(body) < 3:
            return None
        params   = body[1]
        sub_et   = body[2]
        asp_id   = params.get('ASP_ID', '')   if isinstance(params, dict) else ''
        asp_args = params.get('ASP_ARGS', {}) if isinstance(params, dict) else {}
        evsig    = asp_types.get(asp_id, {})
        fwd      = evsig.get('FWD', {})
        kind     = fwd.get('FWD', '')
        n        = fwd.get('_BODY', 0) if kind in ('REPLACE', 'EXTEND') else 0
        r1, rest = raw_ev[:n], raw_ev[n:]

        if asp_id == target_id and asp_args == target_args:
            return r1
        return do_evidence_slice(sub_et, rest, asp_types, target_id, target_args)

    return None


# ── Provision history ─────────────────────────────────────────────────────────

_EXAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'examples')

PROVISION_HISTORY_PATH = os.path.join(_EXAMPLES_DIR, 'provision_history.json')
PROVISION_HISTORY_MAX  = 8

def store_provision_path(proto_id, path):
    """Record an evidence bundle path in the per-protocol history (most recent first, deduped)."""
    try:
        history = json.loads(open(PROVISION_HISTORY_PATH).read())
    except Exception:
        history = {}
    paths = [p for p in history.get(proto_id, []) if p != path]
    paths.insert(0, path)
    history[proto_id] = paths[:PROVISION_HISTORY_MAX]
    with open(PROVISION_HISTORY_PATH, 'w') as f:
        json.dump(history, f, indent=2)

def load_provision_history(proto_id):
    """Return list of previously used evidence bundle paths for a protocol (most recent first)."""
    try:
        history = json.loads(open(PROVISION_HISTORY_PATH).read())
        return history.get(proto_id, [])
    except Exception:
        return []


def clear_protocol_state(proto_id):
    """
    Remove all persisted state for a protocol: provision history and
    per-file .original_golden.json sidecars.
    Called when a custom protocol is removed so the next registration starts fresh.
    """
    # Remove provision history entry
    try:
        history = json.loads(open(PROVISION_HISTORY_PATH).read())
        if proto_id in history:
            del history[proto_id]
            with open(PROVISION_HISTORY_PATH, 'w') as f:
                json.dump(history, f, indent=2)
    except Exception:
        pass

    # Delete per-file .{proto_id}.original_golden.json sidecars in examples dir
    try:
        suffix = f'.{proto_id}.original_golden.json'
        for fname in os.listdir(_EXAMPLES_DIR):
            if fname.endswith(suffix):
                try:
                    os.remove(os.path.join(_EXAMPLES_DIR, fname))
                except Exception:
                    pass
    except Exception:
        pass


# ── Bundle storage ────────────────────────────────────────────────────────────

def store_golden_evidence(path, payload, proto_id=''):
    """
    Persist a CVM PAYLOAD as a golden evidence bundle JSON file.

    Wraps the payload in an envelope that records the owning protocol and
    timestamp, so cross-protocol overwrites can be detected at provision time.

    payload: [{"RawEv": [...]}, {"EvidenceT_CONSTRUCTOR": ..., ...}]
    """
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    envelope = {'protocol_id': proto_id, 'timestamp': ts, 'payload': payload}
    with open(path, 'w') as f:
        json.dump(envelope, f, indent=2)


def load_golden_evidence(path):
    """
    Load a golden evidence bundle.

    Returns:
        (raw_ev, et, timestamp, owner_proto_id)
        (None, None, None, None)  — if file missing or malformed
    """
    try:
        data = json.load(open(path))
        payload = data['payload']
        return (
            payload[0].get('RawEv', []),
            payload[1],
            data.get('timestamp', ''),
            data.get('protocol_id', ''),
        )
    except Exception:
        return None, None, None, None
