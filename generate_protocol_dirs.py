#!/usr/bin/env python3
"""
generate_protocol_dirs.py — export protocol configurations as per-protocol
JSON file trees consumable by rust-rodeo-client and cvm-mcp.

Each protocol produces:

  <output_dir>/<proto_id>/
    term.json          Copland Term as built by protocols.py  (→ rust-rodeo-client -t)
    term_no_appr.json  Same term with trailing APPR stripped  (→ rust-rodeo-client -t -a)
    session.json       Attestation_Session  (→ rust-rodeo-client -s)
    manifest.json      CVM Manifest  (→ rust-rodeo-client -m)
    asp_args.json      ASP args map  (→ rust-rodeo-client -g); empty until provisioned
    meta.json          UI / display fields (name, description, copland, flow)
    tamper_config.json Declarative tamper-target metadata

Usage:
    python generate_protocol_dirs.py                         # → ./protocol_dirs/
    python generate_protocol_dirs.py -o /some/other/path
    python generate_protocol_dirs.py -o /some/path --protocols single_hashfile_appr gumbo_l1
    python generate_protocol_dirs.py --list
"""

import argparse
import json
import os
import sys
import traceback


# ── helpers ───────────────────────────────────────────────────────────────────

def _to_dict(value):
    """Accept either a dict or a JSON string and return a dict."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        return json.loads(value)
    raise TypeError(f"Expected dict or JSON string, got {type(value).__name__}")


def _is_appr(node):
    """Return True if *node* is an asp(APPR) term node."""
    return (
        isinstance(node, dict)
        and node.get('TERM_CONSTRUCTOR') == 'asp'
        and isinstance(node.get('TERM_BODY'), dict)
        and node['TERM_BODY'].get('ASP_CONSTRUCTOR') == 'APPR'
    )


def _strip_appr(term):
    """
    Return a copy of *term* with the trailing APPR stripped, or None if the
    term is *only* APPR (nothing left after stripping).

    Handles the common pattern  lseq(..., APPR)  produced by protocols.py,
    including nested cases like  lseq(lseq(meas, SIG), APPR).
    """
    if not isinstance(term, dict):
        return term
    constructor = term.get('TERM_CONSTRUCTOR')
    body = term.get('TERM_BODY')

    if constructor == 'lseq' and isinstance(body, list) and len(body) == 2:
        left, right = body
        if _is_appr(right):
            # lseq(t1, APPR) → t1  (recurse in case t1 itself ends with APPR)
            inner = _strip_appr(left)
            return inner  # may be None if t1 was also bare APPR
        # Neither branch is APPR at this level; recurse into both
        return {**term, 'TERM_BODY': [_strip_appr(left), _strip_appr(right)]}

    if constructor in ('bseq', 'bpar') and isinstance(body, list) and len(body) == 3:
        sp, t1, t2 = body
        return {**term, 'TERM_BODY': [sp, _strip_appr(t1), _strip_appr(t2)]}

    if constructor == 'att' and isinstance(body, list) and len(body) == 2:
        plc, inner = body
        return {**term, 'TERM_BODY': [plc, _strip_appr(inner)]}

    return term


# ASPs known to fold all incoming evidence into their output.
# Everything else is assumed to produce fresh evidence (EvInSig=NONE).
_EV_IN_SIG_ALL = {
    'sig', 'sig_tpm', 'attest', 'certificate', 'appraise',
    'provision_goldenevidence', 'hsh',
}


def _normalize_session(session):
    """
    Return a copy of *session* with ASP_Types corrected for do_AppraisalSummary.

    Problems in the raw session from build():
      - Measurement ASPs use FWD=REPLACE instead of EXTEND+EvInSig
      - Appraiser ASPs (values in ASP_Comps) use REPLACE correctly but
        their EvInSig is missing

    Rules applied:
      - Appraisers (values in ASP_Comps): FWD=REPLACE, no EvInSig — unchanged
      - Measurement ASPs (keys in ASP_Comps or neither):
          * known fold-all ASPs  → EXTEND + EvInSig=ALL
          * everything else      → EXTEND + EvInSig=NONE
    """
    import copy
    session = copy.deepcopy(session)
    ctx = session.get('Session_Context', {})
    asp_types = ctx.get('ASP_Types', {})
    asp_comps = ctx.get('ASP_Comps', {})

    appraisers = set(asp_comps.values()) - {'NULL'}

    for asp_id, sig in asp_types.items():
        if asp_id in appraisers:
            # Keep REPLACE; ensure no EvInSig leaks in
            sig['FWD'] = {'FWD': 'REPLACE', '_BODY': sig['FWD'].get('_BODY', 1)}
        else:
            ev_in_sig = 'ALL' if asp_id in _EV_IN_SIG_ALL else 'NONE'
            sig['FWD'] = {
                'FWD': 'EXTEND',
                '_BODY': sig['FWD'].get('_BODY', 1),
                'EvInSig': ev_in_sig,
            }

    return session


def _load_target_goldens():
    """Load target_goldens.json from the cvm-mcp examples directory, or {} if absent."""
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, 'examples', 'target_goldens.json')
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def _inject_golden_b64(term, proto_id, target_goldens):
    """
    Return a deep copy of *term* with golden_b64 injected into every ASPC
    node whose ASP_ID+filepath has a provisioned entry in *target_goldens*.

    Keys in target_goldens follow the pattern  "<proto_id>::<asp_id>::<filepath>".
    Returns (injected_term, n_injected) where n_injected is the count of nodes
    that received a golden_b64.
    """
    import copy
    term = copy.deepcopy(term)

    def _walk(node):
        if not isinstance(node, dict):
            return 0
        constructor = node.get('TERM_CONSTRUCTOR')
        body = node.get('TERM_BODY')

        if constructor == 'asp':
            if isinstance(body, dict) and body.get('ASP_CONSTRUCTOR') == 'ASPC':
                asp_body = body.get('ASP_BODY', {})
                asp_id   = asp_body.get('ASP_ID', '')
                asp_args = asp_body.get('ASP_ARGS', {})
                filepath = asp_args.get('filepath', '')
                if asp_id and filepath:
                    key = f'{proto_id}::{asp_id}::{filepath}'
                    entry = target_goldens.get(key)
                    if entry and 'golden_b64' in entry:
                        asp_args['golden_b64'] = entry['golden_b64']
                        return 1
            return 0

        if isinstance(body, list):
            return sum(_walk(child) for child in body if isinstance(child, dict))
        return 0

    n = _walk(term)
    return term, n


def _infer_tamper_config_from_term(term):
    """
    Walk the term tree and return a dict of tamper-target metadata keyed by
    "<asp_id>::<filepath>" for every ASPC node whose ASP_ARGS contain 'filepath'.

    Returned format per entry:
      {
        "label":       "<basename of filepath>",
        "asp_id":      "<asp_id>",
        "target_file": "<filepath>",
        "asp_args":    {<ASP_ARGS dict without golden_b64>}
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


def _write_json(path, data, overwrite=True):
    """Write *data* as pretty-printed JSON to *path*. Skips if overwrite=False and file exists."""
    if not overwrite and os.path.exists(path):
        return False
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
        f.write('\n')
    return True


# ── per-protocol export ───────────────────────────────────────────────────────

def export_protocol(proto_id, proto, out_dir, overwrite_asp_args=False):
    """
    Export one REGISTRY entry to *out_dir/<proto_id>/*.

    Returns a dict with keys 'written', 'skipped', 'errors'.
    """
    proto_dir = os.path.join(out_dir, proto_id)
    os.makedirs(proto_dir, exist_ok=True)

    written  = []
    skipped  = []
    errors   = []

    def _w(filename, data, *, skip_if_exists=False):
        path = os.path.join(proto_dir, filename)
        try:
            if _write_json(path, data, overwrite=not skip_if_exists):
                written.append(filename)
            else:
                skipped.append(filename)
        except Exception as exc:
            errors.append(f"{filename}: {exc}")

    target_goldens = _load_target_goldens()

    # ── call build() to get manifest + ProtocolRunRequest ────────────────────
    try:
        raw_manifest, raw_request = proto['build']()
    except Exception as exc:
        errors.append(f"build() failed: {exc}")
        return {'written': written, 'skipped': skipped, 'errors': errors}

    try:
        manifest = _to_dict(raw_manifest)
        request  = _to_dict(raw_request)
    except Exception as exc:
        errors.append(f"build() returned unexpected types: {exc}")
        return {'written': written, 'skipped': skipped, 'errors': errors}

    # ── term.json ─────────────────────────────────────────────────────────────
    term = request.get('TERM')
    if term is None:
        errors.append("term.json: 'TERM' key missing from request")
    else:
        _w('term.json', term)

    # ── term_no_appr.json — same term with trailing APPR stripped ─────────────
    stripped = None
    if term is not None:
        s = _strip_appr(term)
        if s is not None and not _is_appr(s) and s != term:
            stripped = s
            _w('term_no_appr.json', stripped)

    # ── term_no_appr_provisioned.json — stripped term + golden_b64 injected ──
    if stripped is not None:
        provisioned, n_injected = _inject_golden_b64(stripped, proto_id, target_goldens)
        if n_injected > 0:
            _w('term_no_appr_provisioned.json', provisioned)
        # If no golden entries exist yet, skip silently — provision first

    # ── session.json ──────────────────────────────────────────────────────────
    session = request.get('ATTESTATION_SESSION')
    if session is None:
        errors.append("session.json: 'ATTESTATION_SESSION' key missing from request")
    else:
        _w('session.json', _normalize_session(session))

    # ── manifest.json ─────────────────────────────────────────────────────────
    _w('manifest.json', manifest)

    # ── asp_args.json — start empty; never overwrite existing content unless forced ──
    asp_args_path = os.path.join(proto_dir, 'asp_args.json')
    if overwrite_asp_args or not os.path.exists(asp_args_path):
        _w('asp_args.json', {})
    else:
        skipped.append('asp_args.json')

    # ── meta.json ─────────────────────────────────────────────────────────────
    meta = {k: proto[k] for k in ('name', 'description', 'copland', 'flow') if k in proto}
    # Flag dynamic protocols whose term may change when source files change
    if proto_id in ('gumbo_l2', 'gumbo_l1'):
        meta['dynamic'] = True
    _w('meta.json', meta)

    # ── tamper_config.json ────────────────────────────────────────────────────
    # Primary source: infer from term (captures asp_id, target_file, asp_args)
    tamper_cfg = _infer_tamper_config_from_term(term) if term is not None else {}
    # Apply label overrides from REGISTRY tamper_targets where labels differ from filename
    for _tid, _t in proto.get('tamper_targets', {}).items():
        _label = _t.get('label', '')
        # Try to match by label (registry uses short names like "file1.txt")
        for _inf_tid, _inf_t in tamper_cfg.items():
            if _inf_t.get('label') == _label or _inf_tid == _tid:
                _inf_t['label'] = _label
                break
        else:
            # No match from term inference; add a label-only stub for completeness
            if _label:
                tamper_cfg.setdefault(_tid, {'label': _label})
    _w('tamper_config.json', tamper_cfg)

    return {'written': written, 'skipped': skipped, 'errors': errors}


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        '-o', '--output-dir',
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'protocol_dirs'),
        metavar='DIR',
        help='Root output directory (default: ./protocol_dirs)',
    )
    parser.add_argument(
        '--protocols',
        nargs='+',
        metavar='ID',
        help='Only export these protocol IDs (default: all)',
    )
    parser.add_argument(
        '--list',
        action='store_true',
        help='Print all available protocol IDs and exit',
    )
    parser.add_argument(
        '--overwrite-asp-args',
        action='store_true',
        help='Overwrite existing asp_args.json files (default: preserve provisioned values)',
    )
    args = parser.parse_args()

    # Load REGISTRY from protocols.py (must be importable)
    mcp_dir = os.path.dirname(os.path.abspath(__file__))
    if mcp_dir not in sys.path:
        sys.path.insert(0, mcp_dir)

    try:
        from protocols import REGISTRY
    except Exception as exc:
        print(f"ERROR: could not import protocols.REGISTRY: {exc}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

    if args.list:
        for pid in sorted(REGISTRY):
            print(pid)
        return

    target_ids = args.protocols if args.protocols else list(REGISTRY.keys())
    unknown = [p for p in target_ids if p not in REGISTRY]
    if unknown:
        print(f"ERROR: unknown protocol(s): {', '.join(unknown)}", file=sys.stderr)
        sys.exit(1)

    out_dir = os.path.abspath(args.output_dir)
    os.makedirs(out_dir, exist_ok=True)
    print(f"Output directory: {out_dir}\n")

    total_written = total_skipped = total_errors = 0

    for proto_id in target_ids:
        proto = REGISTRY[proto_id]
        result = export_protocol(
            proto_id, proto, out_dir,
            overwrite_asp_args=args.overwrite_asp_args,
        )

        n_w = len(result['written'])
        n_s = len(result['skipped'])
        n_e = len(result['errors'])
        total_written  += n_w
        total_skipped  += n_s
        total_errors   += n_e

        status = 'OK' if n_e == 0 else 'PARTIAL' if n_w > 0 else 'FAILED'
        print(f"  [{status:7s}] {proto_id}")
        if result['written']:
            print(f"             wrote:   {', '.join(result['written'])}")
        if result['skipped']:
            print(f"             skipped: {', '.join(result['skipped'])}")
        for err in result['errors']:
            print(f"             ERROR:   {err}")

    print(f"\nDone.  {total_written} files written, {total_skipped} skipped, {total_errors} errors.")
    if total_errors:
        sys.exit(1)


if __name__ == '__main__':
    main()
