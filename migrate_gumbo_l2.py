#!/usr/bin/env python3
"""
migrate_gumbo_l2.py — Migrate gumbo_l2 from readfile_appr to goldenbytes_appr.

Changes:
  session.json      readfile_appr -> goldenbytes_appr in ASP_Types + ASP_Comps
  manifest.json     replace readfile_appr with goldenbytes_appr in ASPS list
  term.json         replace inline ASP_ARGS with ASP_TARG_ID on every
                    readfile_range / readfile_marker_range ASPC node
  asp_args.json     populate with measurement args for every ASPC node
  tamper_config.json  asp_id_appr: "readfile_appr" -> "goldenbytes_appr"
"""
import copy, json, os, re, sys

PROTO_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'protocol_dirs', 'gumbo_l2',
)

MEAS_ASP_IDS = {'readfile_range', 'readfile_marker_range'}

# Legacy fields stored in the old inline ASP_ARGS that must be stripped —
# they are NOT measurement args and must not appear in the evidence tree.
LEGACY_KEYS = {'env_var_golden', 'filepath_golden', 'asp_id_appr'}


# ── targ_id generation ────────────────────────────────────────────────────────

def _filestem(filepath):
    """Short stem: strip directory and extension."""
    return os.path.splitext(os.path.basename(filepath))[0]

_ABBREVS = {
    'TempControlSystem':                    'tc_sys_aadl',
    'TempSensor':                           'ts_aadl',
    'TempControlPeriodic_p_tcproc_tempControl_GumboX': 'tc_gumbox',
    'TempSensorPeriodic_p_tcproc_tempSensor_GumboX':   'ts_gumbox',
    'TempControlPeriodic_p_tcproc_tempControl':        'tc_comp',
    'TempSensorPeriodic_p_tcproc_tempSensor':          'ts_comp',
}

def _abbrev_filestem(filepath):
    stem = _filestem(filepath)
    return _ABBREVS.get(stem, stem)

_MARKER_SLUGS = {
    'BEGIN STATE VARS':                           'state_vars',
    'BEGIN COMPUTE MODIFIES timeTriggered':       'compute_mod',
    'BEGIN COMPUTE ENSURES timeTriggered':        'compute_ens',
    'BEGIN INITIALIZES MODIFIES':                 'init_mod',
    'BEGIN INITIALIZES ENSURES':                  'init_ens',
}

def _marker_slug(begin_marker):
    if begin_marker in _MARKER_SLUGS:
        return _MARKER_SLUGS[begin_marker]
    # Fallback: lowercase words, drop 'BEGIN', join with _
    words = [w.lower() for w in begin_marker.split() if w.upper() != 'BEGIN']
    return '_'.join(words[:4])

def targ_id_for(asp_id, args):
    prefix = _abbrev_filestem(args['filepath'])
    if asp_id == 'readfile_range':
        return f"{prefix}_{args['start_index']}_{args['end_index']}_targ"
    elif asp_id == 'readfile_marker_range':
        return f"{prefix}_{_marker_slug(args['begin_marker'])}_targ"
    else:
        raise ValueError(f"Unexpected asp_id: {asp_id}")


# ── term transformation ───────────────────────────────────────────────────────

def transform_term(term):
    """
    Walk term in-place.  For every ASPC node whose ASP_ID is in MEAS_ASP_IDS:
      - Derive a targ_id from its args
      - Replace ASP_BODY with {ASP_ID: ..., ASP_TARG_ID: <targ_id>}
      - Return the collected {asp_id: {targ_id: measurement_args}} dict
    """
    collected = {}  # asp_id -> {targ_id -> clean_args}

    def _walk(node):
        if not isinstance(node, dict):
            return
        ctor = node.get('TERM_CONSTRUCTOR')
        body = node.get('TERM_BODY')
        if ctor == 'asp' and isinstance(body, dict):
            if body.get('ASP_CONSTRUCTOR') == 'ASPC':
                ab = body.get('ASP_BODY', {})
                asp_id = ab.get('ASP_ID', '')
                if asp_id in MEAS_ASP_IDS:
                    raw_args = ab.get('ASP_ARGS', {})
                    # Strip legacy fields — keep only measurement args
                    clean_args = {k: v for k, v in raw_args.items()
                                  if k not in LEGACY_KEYS}
                    targ = targ_id_for(asp_id, clean_args)
                    collected.setdefault(asp_id, {})[targ] = clean_args
                    # Replace ASP_BODY in-place
                    body['ASP_BODY'] = {'ASP_ID': asp_id, 'ASP_TARG_ID': targ}
            return  # don't recurse into asp nodes
        if isinstance(body, list):
            for child in body:
                _walk(child)

    _walk(term)
    return collected


# ── session.json ──────────────────────────────────────────────────────────────

def migrate_session(session):
    session = copy.deepcopy(session)
    ctx = session.setdefault('Session_Context', {})

    # ASP_Types: rename readfile_appr -> goldenbytes_appr
    types = ctx.setdefault('ASP_Types', {})
    if 'readfile_appr' in types and 'goldenbytes_appr' not in types:
        types['goldenbytes_appr'] = types.pop('readfile_appr')
    elif 'readfile_appr' in types:
        del types['readfile_appr']

    # ASP_Comps: readfile_appr -> goldenbytes_appr for every value
    comps = ctx.setdefault('ASP_Comps', {})
    for k in list(comps.keys()):
        if comps[k] == 'readfile_appr':
            comps[k] = 'goldenbytes_appr'

    return session


# ── manifest.json ─────────────────────────────────────────────────────────────

def migrate_manifest(manifest):
    manifest = copy.deepcopy(manifest)
    asps = manifest.get('ASPS', [])
    if 'readfile_appr' in asps:
        idx = asps.index('readfile_appr')
        asps[idx] = 'goldenbytes_appr'
    elif 'goldenbytes_appr' not in asps:
        asps.append('goldenbytes_appr')
    manifest['ASPS'] = asps
    return manifest


# ── tamper_config.json ────────────────────────────────────────────────────────

def migrate_tamper_config(tc):
    tc = copy.deepcopy(tc)
    for entry in tc.values():
        if isinstance(entry, dict) and 'asp_args' in entry:
            aa = entry['asp_args']
            if aa.get('asp_id_appr') == 'readfile_appr':
                aa['asp_id_appr'] = 'goldenbytes_appr'
    return tc


# ── asp_args.json ─────────────────────────────────────────────────────────────

def build_asp_args(collected):
    """
    Build the asp_args.json content from the collected measurement args.
    Adds golden_b64: "" and golden_ts: "" bookkeeping fields to each entry.
    Merges with any existing entries (keeping existing golden_b64/golden_ts).
    """
    asp_args_path = os.path.join(PROTO_DIR, 'asp_args.json')
    try:
        existing = json.load(open(asp_args_path))
    except (FileNotFoundError, json.JSONDecodeError):
        existing = {}

    result = {}
    for asp_id, targets in collected.items():
        result[asp_id] = {}
        for targ_id, args in targets.items():
            prev = existing.get(asp_id, {}).get(targ_id, {})
            entry = dict(args)
            entry['golden_b64'] = prev.get('golden_b64', '')
            entry['golden_ts']  = prev.get('golden_ts',  '')
            result[asp_id][targ_id] = entry
    return result


# ── main ──────────────────────────────────────────────────────────────────────

def run(dry_run=False):
    print(f"{'DRY RUN — ' if dry_run else ''}Migrating gumbo_l2: {PROTO_DIR}")

    # Load files
    term        = json.load(open(os.path.join(PROTO_DIR, 'term.json')))
    session     = json.load(open(os.path.join(PROTO_DIR, 'session.json')))
    manifest    = json.load(open(os.path.join(PROTO_DIR, 'manifest.json')))
    tamper_cfg  = json.load(open(os.path.join(PROTO_DIR, 'tamper_config.json')))

    # Transform term + collect measurement args
    term_copy = copy.deepcopy(term)
    collected = transform_term(term_copy)

    total_targs = sum(len(v) for v in collected.items())
    for asp_id, targets in collected.items():
        print(f"  {asp_id}: {len(targets)} targets")
        for targ_id, args in targets.items():
            detail = (f"lines {args['start_index']}-{args['end_index']}"
                      if 'start_index' in args
                      else f"begin={args.get('begin_marker')!r}")
            print(f"    {targ_id:55s}  {detail}")

    # Build updated configs
    new_session     = migrate_session(session)
    new_manifest    = migrate_manifest(manifest)
    new_tamper_cfg  = migrate_tamper_config(tamper_cfg)
    new_asp_args    = build_asp_args(collected)

    # Verify uniqueness
    for asp_id, targets in collected.items():
        if len(targets) != sum(1 for _ in targets):
            print(f"ERROR: duplicate targ_ids for {asp_id}!")
            sys.exit(1)

    if dry_run:
        print("\n[DRY RUN] Would write:")
        print("  term.json, session.json, manifest.json, tamper_config.json, asp_args.json")
        print(f"\n  asp_args.json preview:")
        print(json.dumps(new_asp_args, indent=2)[:800])
        return

    def _write(path, data):
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
            f.write('\n')
        print(f"  Wrote {os.path.basename(path)}")

    _write(os.path.join(PROTO_DIR, 'term.json'),         term_copy)
    _write(os.path.join(PROTO_DIR, 'session.json'),      new_session)
    _write(os.path.join(PROTO_DIR, 'manifest.json'),     new_manifest)
    _write(os.path.join(PROTO_DIR, 'tamper_config.json'),new_tamper_cfg)
    _write(os.path.join(PROTO_DIR, 'asp_args.json'),     new_asp_args)
    print("Done.")


if __name__ == '__main__':
    dry_run = '--dry-run' in sys.argv
    run(dry_run=dry_run)
