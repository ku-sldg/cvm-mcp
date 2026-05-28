#!/usr/bin/env python3
"""
Phase 2 migration: update protocol_dirs for canonical goldenbytes_appr provisioning.

For each affected protocol:
  - session.json:  hashfile_appr → goldenbytes_appr in ASP_Comps
  - manifest.json: replace hashfile_appr with goldenbytes_appr in ASPS list
  - term.json:     replace inline provision/appr args with ASP_TARG_ID references;
                   keep only measurement args inline (or empty)
  - asp_args.json: create/update with measurement args + golden_b64: "" placeholder

Run from the cvm-mcp directory:
    python3 migrate_phase2.py [--dry-run]
"""

import json, os, re, sys, copy

PROTOCOL_DIRS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'protocol_dirs')

DRY_RUN = '--dry-run' in sys.argv

# Arg keys that are provision/appraisal infrastructure — not measurement args.
# These must be stripped from inline term ASP_ARGS.
PROVISION_KEYS = {'filepath_golden', 'env_var_golden', 'asp_id_appr'}

# ASP_IDs whose appraiser is being renamed hashfile_appr → goldenbytes_appr.
SCOPE_ASP_IDS = {'hashfile', 'hsh', 'hashevidence'}


def read_json(path):
    with open(path) as f:
        return json.load(f)


def write_json(path, data):
    if DRY_RUN:
        print(f'  [dry-run] would write {path}')
        return
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
        f.write('\n')


def targ_id_from_args(asp_id, args, index):
    """Derive a stable targ_id from the ASP args (filepath basename preferred)."""
    fp = args.get('filepath', '')
    if fp:
        base = os.path.splitext(os.path.basename(fp))[0]
        # Sanitize: lower, replace non-alphanum with underscore, collapse runs
        base = re.sub(r'[^a-z0-9]+', '_', base.lower()).strip('_')
        return f'{base}_targ'
    # No filepath — fall back to asp_id + index
    suffix = f'_{index}' if index > 0 else ''
    return f'{asp_id}{suffix}_targ'


def migrate_term(term, asp_id_counter, hashfile_appr_ids):
    """
    Walk term tree. For every in-scope ASPC node:
      - Assign a targ_id
      - Strip provision args from ASP_ARGS
      - Add ASP_TARG_ID
      - Return measurement args keyed by targ_id for asp_args.json

    Only ASPC nodes whose ASP_ID is in hashfile_appr_ids (i.e. mapped to
    hashfile_appr in the session's ASP_Comps) are migrated.

    Returns (new_term, {asp_id: {targ_id: {measurement_args}}})
    """
    term = copy.deepcopy(term)
    collected = {}  # asp_id → {targ_id: args}

    def _walk(node):
        if not isinstance(node, dict):
            return
        ctor = node.get('TERM_CONSTRUCTOR')
        body = node.get('TERM_BODY')
        if ctor == 'asp' and isinstance(body, dict):
            ac = body.get('ASP_CONSTRUCTOR')
            if ac == 'ASPC':
                ab = body.get('ASP_BODY', {})
                asp_id = ab.get('ASP_ID', '')
                if asp_id in hashfile_appr_ids:
                    raw_args = ab.get('ASP_ARGS', {})
                    idx = asp_id_counter.get(asp_id, 0)
                    targ_id = targ_id_from_args(asp_id, raw_args, idx)
                    asp_id_counter[asp_id] = idx + 1

                    # Measurement args = all args minus provision keys
                    meas_args = {k: v for k, v in raw_args.items()
                                 if k not in PROVISION_KEYS}

                    # Record for asp_args.json (add golden_b64 placeholder)
                    collected.setdefault(asp_id, {})[targ_id] = {
                        **meas_args,
                        'golden_b64': '',
                    }

                    # Update term node: keep only measurement args inline,
                    # add ASP_TARG_ID for substitution at load time.
                    ab['ASP_TARG_ID'] = targ_id
                    ab['ASP_ARGS'] = {}   # args live in asp_args.json now
            return

        if isinstance(body, list):
            for child in body:
                if isinstance(child, dict):
                    _walk(child)

    _walk(term)
    return term, collected


def migrate_session(session):
    """Replace hashfile_appr → goldenbytes_appr in ASP_Comps."""
    session = copy.deepcopy(session)
    comps = (session
             .setdefault('Session_Context', {})
             .setdefault('ASP_Comps', {}))
    changed = False
    for asp_id, appr in list(comps.items()):
        if appr == 'hashfile_appr' and asp_id in SCOPE_ASP_IDS:
            comps[asp_id] = 'goldenbytes_appr'
            changed = True
    asp_types = (session
                 .setdefault('Session_Context', {})
                 .setdefault('ASP_Types', {}))
    # Add goldenbytes_appr ASP_Types entry (REPLACE, body=1) if not present
    if 'goldenbytes_appr' not in asp_types and changed:
        asp_types['goldenbytes_appr'] = {
            'FWD': {'FWD': 'REPLACE', '_BODY': 1},
            'ATTRS': []
        }
    # Remove obsolete hashfile_appr entry if goldenbytes_appr is now used
    if changed and 'hashfile_appr' in asp_types:
        # Only remove if no ASP_Comps still references hashfile_appr
        still_used = any(v == 'hashfile_appr' for v in comps.values())
        if not still_used:
            del asp_types['hashfile_appr']
    return session, changed


def migrate_manifest(manifest):
    """Replace hashfile_appr with goldenbytes_appr in ASPS list."""
    manifest = copy.deepcopy(manifest)
    asps = manifest.get('ASPS', [])
    if 'hashfile_appr' in asps:
        asps = [('goldenbytes_appr' if a == 'hashfile_appr' else a) for a in asps]
        # Deduplicate while preserving order
        seen = set()
        asps = [a for a in asps if not (a in seen or seen.add(a))]
        manifest['ASPS'] = asps
        return manifest, True
    # hashfile_appr not in list but goldenbytes_appr may need adding
    # (e.g. verus_protocol manifest had no hashfile_appr but uses hashevidence→goldenbytes_appr)
    if 'goldenbytes_appr' not in asps:
        asps.append('goldenbytes_appr')
        manifest['ASPS'] = asps
        return manifest, True
    return manifest, False


def merge_asp_args(existing, new_entries):
    """
    Merge new_entries (from term migration) into existing asp_args dict.
    Existing entries take precedence for keys that already have values,
    but golden_b64 is always seeded as '' if absent.
    """
    result = copy.deepcopy(existing)
    for asp_id, targets in new_entries.items():
        for targ_id, args in targets.items():
            existing_targ = result.setdefault(asp_id, {}).setdefault(targ_id, {})
            for k, v in args.items():
                if k == 'golden_b64':
                    # Only seed if not already set (preserve existing golden)
                    existing_targ.setdefault('golden_b64', '')
                else:
                    existing_targ.setdefault(k, v)
    return result


def migrate_protocol(proto_id, proto_dir):
    print(f'\n--- {proto_id} ---')
    term_path    = os.path.join(proto_dir, 'term.json')
    session_path = os.path.join(proto_dir, 'session.json')
    manifest_path = os.path.join(proto_dir, 'manifest.json')
    asp_args_path = os.path.join(proto_dir, 'asp_args.json')

    # ── session.json ──────────────────────────────────────────────────────────
    session = read_json(session_path)
    new_session, sess_changed = migrate_session(session)
    if sess_changed:
        print(f'  session.json: updated ASP_Comps hashfile_appr → goldenbytes_appr')
        write_json(session_path, new_session)
    else:
        print(f'  session.json: no hashfile_appr entries in scope — skipped')

    # ── manifest.json ─────────────────────────────────────────────────────────
    manifest = read_json(manifest_path)
    new_manifest, man_changed = migrate_manifest(manifest)
    if man_changed:
        print(f'  manifest.json: ASPS updated → {new_manifest["ASPS"]}')
        write_json(manifest_path, new_manifest)
    else:
        print(f'  manifest.json: no change needed')

    # ── term.json ─────────────────────────────────────────────────────────────
    # Determine which ASP_IDs are configured with hashfile_appr in this session.
    # Only those nodes should be migrated (e.g. in verus_protocol, hashfile maps
    # to goldenevidence_appr and must be left alone).
    comps = (new_session if sess_changed else session) \
                .get('Session_Context', {}).get('ASP_Comps', {})
    hashfile_appr_ids = {k for k, v in comps.items()
                         if v == 'goldenbytes_appr' and k in SCOPE_ASP_IDS}

    term = read_json(term_path)
    counter = {}
    new_term, collected = migrate_term(term, counter, hashfile_appr_ids)
    if collected:
        print(f'  term.json: {sum(len(v) for v in collected.values())} '
              f'ASPC nodes updated → ASP_TARG_ID:')
        for asp_id, targets in collected.items():
            for targ_id, args in targets.items():
                meas = {k: v for k, v in args.items() if k != 'golden_b64'}
                print(f'    {asp_id}/{targ_id}: measurement args = {list(meas.keys())}')
        write_json(term_path, new_term)
    else:
        print(f'  term.json: no in-scope ASPC nodes found')

    # ── asp_args.json ─────────────────────────────────────────────────────────
    existing_asp_args = {}
    if os.path.exists(asp_args_path):
        try:
            existing_asp_args = read_json(asp_args_path)
        except Exception:
            pass
    if collected:
        new_asp_args = merge_asp_args(existing_asp_args, collected)
        print(f'  asp_args.json: written with {sum(len(v) for v in new_asp_args.values())} target(s)')
        write_json(asp_args_path, new_asp_args)
    else:
        print(f'  asp_args.json: no changes')


def main():
    if DRY_RUN:
        print('=== DRY RUN — no files will be written ===\n')

    # Protocols whose session.json has hashfile_appr for an in-scope ASP_ID
    affected = []
    for proto_id in sorted(os.listdir(PROTOCOL_DIRS)):
        d = os.path.join(PROTOCOL_DIRS, proto_id)
        if not os.path.isdir(d):
            continue
        session_path = os.path.join(d, 'session.json')
        if not os.path.exists(session_path):
            continue
        try:
            session = read_json(session_path)
            comps = (session
                     .get('Session_Context', {})
                     .get('ASP_Comps', {}))
            if any(v == 'hashfile_appr' and k in SCOPE_ASP_IDS
                   for k, v in comps.items()):
                affected.append((proto_id, d))
        except Exception:
            continue

    print(f'Found {len(affected)} protocols to migrate:')
    for pid, _ in affected:
        print(f'  {pid}')

    for proto_id, proto_dir in affected:
        migrate_protocol(proto_id, proto_dir)

    print('\nDone.')


if __name__ == '__main__':
    main()
