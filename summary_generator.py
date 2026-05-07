"""
Generate a Markdown run summary from the on-disk JSON configuration files
that are passed (directly or via build_from_dir) to the CVM.

Entry point:  generate_run_summary(protocol_id, result_data, registry_entry)

All config is read from protocol_dirs/<id>/ — the same files build_from_dir()
uses.  For protocols without a protocol_dir entry the function returns a short
note explaining where config lives.
"""

import json
import os
import datetime

# ── Low-level term-tree renderer ──────────────────────────────────────────────

def _render_term_tree(node, indent=0) -> list[str]:
    """
    Recursively render a Copland term dict as an indented tree.
    Returns a list of text lines (no trailing newlines).
    golden_b64 values are suppressed — they are runtime ephemera.
    """
    pad = '  ' * indent
    lines = []

    if not isinstance(node, dict):
        lines.append(f'{pad}?')
        return lines

    ctor = node.get('TERM_CONSTRUCTOR', '')
    body = node.get('TERM_BODY')

    if ctor == 'asp':
        if not isinstance(body, dict):
            lines.append(f'{pad}asp(?)')
            return lines
        ac = body.get('ASP_CONSTRUCTOR', '')

        if ac in ('APPR', 'SIG', 'HSH', 'NULL'):
            lines.append(f'{pad}{ac}')
            return lines

        if ac == 'ASPC':
            ab      = body.get('ASP_BODY', {})
            asp_id  = ab.get('ASP_ID', 'asp')
            args    = {k: v for k, v in ab.get('ASP_ARGS', {}).items()
                       if k != 'golden_b64'}
            if args:
                lines.append(f'{pad}{asp_id}')
                for k, v in args.items():
                    # shorten long absolute paths to basename + ... for readability
                    disp = v
                    if isinstance(v, str) and os.sep in v and len(v) > 60:
                        disp = '…/' + os.path.basename(v)
                    lines.append(f'{pad}    {k} = {disp}')
            else:
                lines.append(f'{pad}{asp_id}')
            return lines

        lines.append(f'{pad}{ac or "asp(?)"} ')
        return lines

    if ctor == 'lseq' and isinstance(body, list) and len(body) == 2:
        lines.append(f'{pad}lseq')
        lines.extend(_render_term_tree(body[0], indent + 1))
        lines.extend(_render_term_tree(body[1], indent + 1))
        return lines

    if ctor in ('bseq', 'bpar') and isinstance(body, list) and len(body) == 3:
        split = body[0]
        if isinstance(split, dict):
            s1, s2 = split.get('split1', '?'), split.get('split2', '?')
            split_str = f'{s1}/{s2}'
        else:
            split_str = str(split)
        lines.append(f'{pad}{ctor}  [{split_str}]')
        lines.extend(_render_term_tree(body[1], indent + 1))
        lines.extend(_render_term_tree(body[2], indent + 1))
        return lines

    if ctor == 'att' and isinstance(body, list) and len(body) == 2:
        lines.append(f'{pad}att @ {body[0]}')
        lines.extend(_render_term_tree(body[1], indent + 1))
        return lines

    lines.append(f'{pad}{ctor or "?"}')
    return lines


# ── asp_args.json rendering ───────────────────────────────────────────────────

def _render_asp_args(asp_args: dict) -> list[str]:
    """
    Render an asp_args.json dict as Markdown table rows.
    Format:  { asp_id: { targ_id: { key: value, ... } } }
    Returns list of '| asp_id | targ_id | key | value |' lines (no header).
    """
    rows = []
    for asp_id, targets in asp_args.items():
        if not isinstance(targets, dict):
            continue
        for targ_id, args in targets.items():
            if not isinstance(args, dict):
                continue
            for k, v in args.items():
                if k == 'golden_b64':
                    continue
                disp = str(v)
                if isinstance(v, str) and os.sep in v and len(v) > 60:
                    disp = '…/' + os.path.basename(v)
                rows.append(f'| `{asp_id}` | `{targ_id}` | `{k}` | `{disp}` |')
    return rows


# ── Session context rendering ────────────────────────────────────────────────

def _render_session(session: dict) -> str:
    """Render session.json as Markdown sections."""
    lines = []
    ctx   = session.get('Session_Context', {})

    # Place
    plc = session.get('Session_Plc', '')
    if plc:
        lines.append(f'**Session place:** `{plc}`')

    plc_map = session.get('Plc_Mapping', {})
    if plc_map:
        lines.append('')
        lines.append('**Place mapping:**')
        lines.append('')
        lines.append('| Place | Address |')
        lines.append('|-------|---------|')
        for p, addr in plc_map.items():
            lines.append(f'| `{p}` | `{addr}` |')

    # ASP Compositions
    comps = ctx.get('ASP_Comps', {})
    if comps:
        lines.append('')
        lines.append('**ASP compositions** (measurement → appraisal):')
        lines.append('')
        lines.append('| Measurement ASP | Appraisal ASP |')
        lines.append('|-----------------|---------------|')
        for meas, appr in comps.items():
            lines.append(f'| `{meas}` | `{appr}` |')

    # ASP Types (forward / body)
    asp_types = ctx.get('ASP_Types', {})
    if asp_types:
        lines.append('')
        lines.append('**ASP types** (evidence forwarding):')
        lines.append('')
        lines.append('| ASP | Forward | Body |')
        lines.append('|-----|---------|------|')
        for asp, spec in asp_types.items():
            fwd  = spec.get('FWD', {})
            fkind = fwd.get('FWD', '?') if isinstance(fwd, dict) else str(fwd)
            body  = fwd.get('_BODY', '?') if isinstance(fwd, dict) else '?'
            lines.append(f'| `{asp}` | {fkind} | {body} |')

    return '\n'.join(lines)


# ── Golden evidence cross-reference ──────────────────────────────────────────

def _golden_refs(proto_id: str, term: dict) -> list[dict]:
    """
    Walk the term tree and look up golden evidence for each ASPC node.
    Returns list of dicts with keys: asp_id, filepath, timestamp, bundle.
    """
    from evidence_slice import load_target_golden
    from protocol_loader import infer_tamper_config

    targets = infer_tamper_config(term)
    rows    = []
    seen    = set()
    for _tid, cfg in targets.items():
        asp_id   = cfg['asp_id']
        asp_args = cfg['asp_args']
        filepath = cfg['target_file']
        key      = (asp_id, filepath)
        if key in seen:
            continue
        seen.add(key)
        entry = load_target_golden(asp_id, asp_args, proto_id)
        rows.append({
            'asp_id':    asp_id,
            'filepath':  filepath,
            'timestamp': entry.get('timestamp', '—')        if entry else '—',
            'bundle':    entry.get('evidence_bundle', '—')  if entry else '—',
        })
    return rows


# ── Run results table ────────────────────────────────────────────────────────

def _render_results(results: list) -> str:
    lines = [
        '| Appraiser ASP | Target | Verdict | Message |',
        '|---------------|--------|---------|---------|',
    ]
    for row in results:
        verdict = row.get('verdict', '?')
        mark    = '✓' if verdict == 'PASS' else '✗'
        target  = row.get('target', '')
        appr    = row.get('appr',   '')
        msg     = row.get('msg',    '') or ''
        lines.append(f'| `{appr}` | `{target}` | {mark} {verdict} | {msg} |')
    return '\n'.join(lines)


# ── ASP binaries table ───────────────────────────────────────────────────────

def _render_asp_binaries(asps: list[str], asp_bin: str, asp_fs_map: dict) -> str:
    """
    Produce a Markdown table of the binary path resolved for each registered ASP.
    Resolution order mirrors what the CVM does:
      1. ASP_FS_MAP[asp_id]  — explicit override
      2. <asp_bin>/<asp_id>  — default dispatch directory
    Each row also shows whether the binary actually exists on disk.
    """
    lines = [
        '| ASP | Binary path | Exists |',
        '|-----|-------------|--------|',
    ]
    for asp in asps:
        if asp in asp_fs_map:
            path = asp_fs_map[asp]
            src  = 'FS_MAP override'
        else:
            path = os.path.join(asp_bin, asp)
            src  = ''
        exists = '✓' if os.path.isfile(path) else '✗ missing'
        note   = f' *({src})*' if src else ''
        lines.append(f'| `{asp}` | `{path}`{note} | {exists} |')
    return '\n'.join(lines)


# ── Source file table ────────────────────────────────────────────────────────

def _source_files_table(proto_dir: str, filenames: list[str]) -> str:
    lines = [
        '| File | Path |',
        '|------|------|',
    ]
    for fn in filenames:
        full = os.path.join(proto_dir, fn)
        if os.path.exists(full):
            lines.append(f'| `{fn}` | `{full}` |')
    return '\n'.join(lines)


# ── Main entry point ─────────────────────────────────────────────────────────

def generate_run_summary(protocol_id: str,
                         result_data:   dict | None,
                         registry_entry: dict) -> str:
    """
    Generate a Markdown run summary for a protocol.

    Reads configuration directly from protocol_dirs/<id>/ on disk.
    result_data may be None if the protocol has not been run yet.

    Returns a Markdown string.
    """
    import protocol_loader as pl

    proto_dir = pl._protocol_dir(protocol_id) if pl.has_protocol_dir(protocol_id) else None

    # ── helpers ──
    def _load(filename):
        if proto_dir:
            p = os.path.join(proto_dir, filename)
            if os.path.exists(p):
                with open(p) as f:
                    return json.load(f), p
        return None, None

    # ── metadata ──
    name        = registry_entry.get('name',        protocol_id)
    description = registry_entry.get('description', '')
    copland_str = registry_entry.get('copland',     '')

    ts_now  = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # ── load config files ──
    manifest_obj, manifest_path = _load('manifest.json')
    session_obj,  session_path  = _load('session.json')
    asp_args_obj, asp_args_path = _load('asp_args.json')

    # term: prefer term_local.json (substituted args baked in) over term.json
    term_obj, term_path = _load('term_local.json')
    if term_obj is None:
        term_obj, term_path = _load('term.json')

    # if asp_args exist, inject them into the term for accurate rendering
    if term_obj and asp_args_obj:
        from protocol_loader import inject_asp_args, normalize_term
        term_obj = inject_asp_args(term_obj, asp_args_obj)
        term_obj = normalize_term(term_obj)
    elif term_obj:
        from protocol_loader import normalize_term
        term_obj = normalize_term(term_obj)

    # Prefer rendering the Copland one-liner from the normalized term so that
    # split forms like {'split1':'ALL','split2':'ALL'} show as 'both_paths'.
    if term_obj:
        from protocol_loader import _term_to_copland
        copland_str = _term_to_copland(term_obj)

    # ── assemble output ──
    md = []

    # Header
    md.append(f'# CVM Attestation Run — {protocol_id}')
    md.append('')
    md.append(f'**Protocol:** {name}')
    if description:
        md.append(f'**Description:** {description}')
    if copland_str:
        md.append(f'**Copland:** `{copland_str}`')
    md.append('')

    # Run outcome (if available)
    if result_data:
        r_ts        = result_data.get('timestamp', ts_now)
        r_ok        = result_data.get('cvm_success', False)
        r_all_pass  = result_data.get('all_pass',    False)
        r_pass      = result_data.get('pass_count',  0)
        r_fail      = result_data.get('fail_count',  0)
        r_err       = result_data.get('error',       '')
        outcome_str = 'SUCCESS' if r_ok else 'FAILED'
        verdict_str = 'PASS' if r_all_pass else 'FAIL'
        md.append('---')
        md.append('')
        md.append('## Run Metadata')
        md.append('')
        md.append(f'| | |')
        md.append(f'|-|-|')
        md.append(f'| Run time       | {r_ts} |')
        md.append(f'| CVM outcome    | {outcome_str} |')
        md.append(f'| Verdict        | {verdict_str} |')
        md.append(f'| Pass / Fail    | {r_pass} passed, {r_fail} failed |')
        if r_err:
            md.append(f'| Error          | {r_err} |')
        md.append('')
    else:
        md.append('> *No run data available — run the protocol to populate results.*')
        md.append('')

    # CVM invocation
    cvm_bin = os.environ.get(
        'CVM_BINARY',
        os.path.expanduser('~/Claude_workspace/cvm/_build/default/theories/cvm'),
    )
    asp_bin = os.environ.get(
        'CVM_ASP_BIN',
        os.path.expanduser('~/Claude_workspace/asp-libs/target/release'),
    )
    md.append('---')
    md.append('')
    md.append('## CVM Invocation')
    md.append('')
    md.append('```')
    md.append(f'cvm \\')
    md.append(f'  --manifest_file  <manifest.json> \\')
    md.append(f'  --req_file       <request.json>  \\')
    md.append(f'  --asp_bin        {asp_bin} \\')
    md.append(f'  --log_level      Info \\')
    md.append(f'  --cvm_binary     {cvm_bin}')
    md.append('```')
    md.append('')

    # Manifest
    md.append('---')
    md.append('')
    md.append('## Manifest')
    if manifest_path:
        md.append(f'*Source: `{manifest_path}`*')
    md.append('')
    if manifest_obj:
        asps = manifest_obj.get('ASPS', [])
        fs   = manifest_obj.get('ASP_FS_MAP', {})
        pol  = manifest_obj.get('POLICY', [])
        if asps:
            md.append('')
            md.append('**ASP binaries** (`asp_bin` = `' + asp_bin + '`):')
            md.append('')
            md.append(_render_asp_binaries(asps, asp_bin, fs))
        if pol:
            md.append('')
            md.append(f'**Policy:** `{json.dumps(pol)}`')
    else:
        md.append('*(manifest.json not found)*')
    md.append('')

    # Term
    md.append('---')
    md.append('')
    md.append('## Copland Term')
    if term_path:
        md.append(f'*Source: `{term_path}`*')
        if asp_args_path and asp_args_obj:
            md.append(f'*Arguments applied from: `{asp_args_path}`*')
    md.append('')
    if term_obj:
        md.append('```')
        md.extend(_render_term_tree(term_obj))
        md.append('```')
    else:
        md.append('*(term.json not found)*')
    md.append('')

    # ASP Args (table form, only if the file is non-empty)
    if asp_args_obj and any(isinstance(v, dict) for v in asp_args_obj.values()):
        md.append('---')
        md.append('')
        md.append('## ASP Arguments')
        md.append(f'*Source: `{asp_args_path}`*')
        md.append('')
        md.append('| ASP | Target ID | Argument | Value |')
        md.append('|-----|-----------|----------|-------|')
        rows = _render_asp_args(asp_args_obj)
        if rows:
            md.extend(rows)
        else:
            md.append('| — | — | — | — |')
        md.append('')

    # Session
    md.append('---')
    md.append('')
    md.append('## Session Context')
    if session_path:
        md.append(f'*Source: `{session_path}`*')
    md.append('')
    if session_obj:
        md.append(_render_session(session_obj))
    else:
        md.append('*(session.json not found)*')
    md.append('')

    # Golden evidence
    if term_obj:
        golden_rows = _golden_refs(protocol_id, term_obj)
        if golden_rows:
            md.append('---')
            md.append('')
            md.append('## Golden Evidence References')
            md.append('')
            md.append('| ASP | Target file | Provisioned at | Bundle |')
            md.append('|-----|-------------|----------------|--------|')
            for r in golden_rows:
                fp_disp = '…/' + os.path.basename(r['filepath']) if os.sep in r['filepath'] else r['filepath']
                md.append(f'| `{r["asp_id"]}` | `{fp_disp}` | {r["timestamp"]} | `{r["bundle"]}` |')
            md.append('')

    # Run results
    if result_data and result_data.get('results'):
        md.append('---')
        md.append('')
        md.append('## Run Results')
        md.append('')
        md.append(_render_results(result_data['results']))
        md.append('')

    # Source files
    if proto_dir:
        src_files = [f for f in
                     ['manifest.json', 'term.json', 'asp_args.json', 'session.json', 'tamper_config.json']
                     if os.path.exists(os.path.join(proto_dir, f))]
        if src_files:
            md.append('---')
            md.append('')
            md.append('## Source Files')
            md.append('')
            md.append(_source_files_table(proto_dir, src_files))
            md.append('')

    # Footer
    md.append('---')
    md.append(f'*Generated by cvm-mcp · {ts_now}*')

    return '\n'.join(md)
