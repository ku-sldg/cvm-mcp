"""
Derive Copland protocol metadata (flow, targets, session context, manifest)
from a Copland term JSON tree.

Public API:
    derive_from_term(term_dict) → {
        'asps':       [str, ...]           # for Manifest.ASPS
        'asp_types':  {str: dict, ...}     # for Session_Context.ASP_Types
        'asp_comps':  {str: str, ...}      # for Session_Context.ASP_Comps
        'targets':    [{'id', 'label', 'file', 'golden'}, ...]
        'flow':       [flow_item, ...]
    }

    save_and_register(proto_id, name, description, copland,
                      term_dict, manifest_obj, session_context,
                      evidence_obj, targets_spec, flow)
        → proto_id   (registers in REGISTRY + persists to a JSON file)

Term JSON structure (TERM_CONSTRUCTOR values and their TERM_BODY shapes):
    lseq  → [child1, child2]
    bseq  → [split_str, child1, child2]
    asp   → {'ASP_CONSTRUCTOR': 'APPR'|'SIG'|'HSH'|'NULL'}
    asp   → {'ASP_CONSTRUCTOR': 'ASPC',
              'ASP_BODY': {'ASP_ID': str, 'ASP_ARGS': {filepath, filepath_golden, asp_id_appr, ...}}}
    att   → [place_str, sub_term_dict]
"""

import os
import json
import datetime

# ── ASP type templates ────────────────────────────────────────────────────────
_ASP_REPLACE = {'FWD': {'FWD': 'REPLACE', '_BODY': 1}, 'ATTRS': []}
_ASP_EXTEND  = {'FWD': {'FWD': 'EXTEND',  '_BODY': 1, 'EvInSig': 'ALL'}, 'ATTRS': []}

# Directory where builder-registered protocols are persisted as JSON files
_BUILT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'built_protocols')


# ── Term walking ──────────────────────────────────────────────────────────────

def derive_from_term(term):
    """
    Walk a Copland term dict and return derived dashboard metadata.

    Args:
        term: parsed term dict (e.g. from json.loads of the term JSON)

    Returns:
        {
          'asps':      [str, ...]
          'asp_types': {str: dict}
          'asp_comps': {str: str}
          'targets':   [{'id', 'label', 'file', 'golden'}, ...]
          'flow':      [flow_item, ...]
        }
    """
    ctx = {
        'asps':      [],
        'asp_types': {},
        'asp_comps': {},
        'targets':   [],
        '_counts':   {},   # asp_id → int, for generating unique target IDs
    }
    flow = _walk(term, ctx)
    del ctx['_counts']
    ctx['flow'] = flow
    return ctx


def _flow_label(items):
    """Return a short display label from a list of flow items."""
    for item in items:
        if item.get('type') in ('asp', 'bseq'):
            return item.get('label', '?')
    return '?'


def _walk(term, ctx):
    """
    Recursively walk a term dict.
    Returns list of flow items for this subtree.
    Populates ctx (asps, asp_types, asp_comps, targets) as side-effect.
    """
    if not isinstance(term, dict):
        return []

    ctor = term.get('TERM_CONSTRUCTOR', '')
    body = term.get('TERM_BODY')

    # ── lseq: linear sequence ─────────────────────────────────────────────────
    if ctor == 'lseq':
        if not isinstance(body, list):
            return []
        items = []
        for i, child in enumerate(body):
            child_flow = _walk(child, ctx)
            if i > 0 and items and child_flow:
                items.append({'type': 'arrow'})
            items.extend(child_flow)
        return items

    # ── bseq: branching sequence ──────────────────────────────────────────────
    elif ctor == 'bseq':
        if not isinstance(body, list) or len(body) < 3:
            return [{'type': 'asp', 'label': 'bseq(?)', 'style': 'default'}]
        split, t1, t2 = body[0], body[1], body[2]
        c1 = _walk(t1, ctx)
        c2 = _walk(t2, ctx)
        return [{'type': 'bseq',
                 'label': f'bseq / {split}',
                 'children': [_flow_label(c1), _flow_label(c2)]}]

    # ── bpar: branching parallel (same structure as bseq) ────────────────────
    elif ctor == 'bpar':
        if not isinstance(body, list) or len(body) < 3:
            return [{'type': 'asp', 'label': 'bpar(?)', 'style': 'default'}]
        split, t1, t2 = body[0], body[1], body[2]
        c1 = _walk(t1, ctx)
        c2 = _walk(t2, ctx)
        return [{'type': 'bseq',
                 'label': f'bpar / {split}',
                 'children': [_flow_label(c1), _flow_label(c2)]}]

    # ── asp: single ASP node ──────────────────────────────────────────────────
    elif ctor == 'asp':
        if not isinstance(body, dict):
            return []
        asp_ctor = body.get('ASP_CONSTRUCTOR', '')

        if asp_ctor == 'APPR':
            return [{'type': 'asp', 'label': 'APPR', 'style': 'appr'}]

        elif asp_ctor == 'SIG':
            for asp_id, asp_type in [('sig', _ASP_EXTEND), ('sig_appr', _ASP_REPLACE)]:
                if asp_id not in ctx['asps']:
                    ctx['asps'].append(asp_id)
                    ctx['asp_types'][asp_id] = asp_type
            ctx['asp_comps'].setdefault('sig', 'sig_appr')
            return [{'type': 'asp', 'label': 'SIG', 'style': 'sig'}]

        elif asp_ctor == 'HSH':
            if 'hsh' not in ctx['asps']:
                ctx['asps'].append('hsh')
                ctx['asp_types']['hsh'] = _ASP_REPLACE
            return [{'type': 'asp', 'label': 'hsh', 'style': 'hsh'}]

        elif asp_ctor == 'NULL':
            return [{'type': 'asp', 'label': 'NULL', 'style': 'default'}]

        elif asp_ctor == 'ASPC':
            asp_body = body.get('ASP_BODY', {})
            asp_id   = asp_body.get('ASP_ID', 'unknown')
            asp_args = asp_body.get('ASP_ARGS', {})

            if asp_id not in ctx['asps']:
                ctx['asps'].append(asp_id)
                ctx['asp_types'][asp_id] = _ASP_REPLACE

            appr_id = asp_args.get('asp_id_appr')
            if appr_id and appr_id not in ctx['asps']:
                ctx['asps'].append(appr_id)
                ctx['asp_types'][appr_id] = _ASP_REPLACE
                ctx['asp_comps'].setdefault(asp_id, appr_id)

            filepath = asp_args.get('filepath', '')
            golden   = asp_args.get('filepath_golden', '')
            if filepath and golden:
                count = ctx['_counts'].get(asp_id, 0)
                ctx['_counts'][asp_id] = count + 1
                target_id = asp_id if count == 0 else f'{asp_id}_{count}'
                label = os.path.basename(filepath)
                ctx['targets'].append({
                    'id':     target_id,
                    'label':  label,
                    'file':   os.path.abspath(os.path.expanduser(filepath)),
                    'golden': os.path.abspath(os.path.expanduser(golden)),
                })
                return [{'type': 'asp', 'label': f'{asp_id}({label})', 'style': 'file'}]

            return [{'type': 'asp', 'label': asp_id, 'style': 'default'}]

    # ── att: remote attestation ───────────────────────────────────────────────
    elif ctor == 'att':
        if isinstance(body, list) and len(body) == 2:
            place = body[0]
            _walk(body[1], ctx)   # still collect ASPs from sub-term
            return [{'type': 'asp', 'label': f'att@{place}', 'style': 'default'}]

    return []


# ── Protocol persistence + registration ───────────────────────────────────────

def save_and_register(proto_id, name, description, copland,
                      term_dict, manifest_obj, attestation_session,
                      evidence_obj, targets_spec, flow):
    """
    Assemble a complete protocol JSON spec, write it to built_protocols/,
    then register it via protocol_loader (which also persists it to
    loaded_protocols.json so it survives restarts).

    attestation_session is the full ATTESTATION_SESSION object:
        {"Session_Plc": "P0", "Plc_Mapping": {}, "PubKey_Mapping": {},
         "Session_Context": {"ASP_Types": {...}, "ASP_Comps": {...}}}

    Returns the proto_id on success.
    """
    from protocol_loader import add_protocol_file

    spec = {
        'id':          proto_id,
        'name':        name,
        'description': description,
        'copland':     copland,
        'flow':        flow,
        'manifest':    manifest_obj,
        'request': {
            'TYPE':               'REQUEST',
            'ACTION':             'RUN',
            'ATTESTATION_SESSION': attestation_session,
            'REQ_PLC':            'P0',
            'TERM':               term_dict,
            'EVIDENCE':           evidence_obj,
        },
        'targets': targets_spec,
    }

    os.makedirs(_BUILT_DIR, exist_ok=True)
    path = os.path.join(_BUILT_DIR, f'{proto_id}.json')
    with open(path, 'w') as f:
        json.dump(spec, f, indent=2)

    return add_protocol_file(path)
