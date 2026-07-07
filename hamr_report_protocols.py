#!/usr/bin/env python3
"""
Generate dashboard protocol dirs from a HAMR attestation report.

The HAMR attestation report (aadl_attestation_report.json /
sysml_attestation_report.json, emitted by HAMR codegen) is the authoritative
statement of which contract slices matter. This tool derives two protocol
directories in the standard provisionable layout:

    <prefix>_l1  — hashfile of every unique file the report names
                   (fast whole-file integrity tier)
    <prefix>_l2  — readfile_range of every report slice
                   (per-contract attribution tier; goldens are content,
                    so these targets are also repairable)

Golden values are NOT generated here: provision the emitted dirs with the
existing dashboard flow (Provision button / /api/provision/<id>), exactly as
for the gumbo_* protocols. Re-run this tool whenever the report changes,
then re-provision — the measured regions can never drift from the model.

Usage:
    python3 hamr_report_protocols.py <attestation_report.json> \
        [--prefix isolette] [--dest protocol_dirs]
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

_ASP_TYPES = {
    'hashfile':          {'FWD': {'FWD': 'EXTEND', '_BODY': 1, 'EvInSig': 'NONE'}, 'ATTRS': []},
    'readfile_range':    {'FWD': {'FWD': 'EXTEND', '_BODY': 1, 'EvInSig': 'NONE'}, 'ATTRS': []},
    'sig':               {'FWD': {'FWD': 'EXTEND', '_BODY': 1, 'EvInSig': 'ALL'}, 'ATTRS': []},
    'sig_appr':          {'FWD': {'FWD': 'REPLACE', '_BODY': 1}, 'ATTRS': []},
    'goldenbytes_appr':  {'FWD': {'FWD': 'REPLACE', '_BODY': 1}, 'ATTRS': []},
}


def load_slices(report_path: Path):
    """Return ([{component, contract, filepath, begin, end}], [unique filepaths])."""
    report = json.loads(report_path.read_text())
    root = report_path.parent
    slices, files = [], []
    for comp_report in report['reports']:
        component = '_'.join(comp_report['idPath'])
        for contract in comp_report['reports']:
            for s in contract['slices']:
                pos = s['pos']
                fp = (root / pos['uri']).resolve()
                slices.append({
                    'component': component,
                    'contract':  contract['id'],
                    'filepath':  str(fp),
                    'begin':     pos['beginLine'],
                    'end':       pos['endLine'],
                })
                if str(fp) not in files:
                    files.append(str(fp))
    return slices, files


def _stem(filepath: str) -> str:
    return re.sub(r'[^a-z0-9]+', '_', Path(filepath).stem.lower()).strip('_')


def _aspc(asp_id: str, targ_id: str) -> dict:
    return {'TERM_CONSTRUCTOR': 'asp',
            'TERM_BODY': {'ASP_CONSTRUCTOR': 'ASPC',
                          'ASP_BODY': {'ASP_ID': asp_id, 'ASP_TARG_ID': targ_id}}}


def _sig() -> dict:
    return {'TERM_CONSTRUCTOR': 'asp', 'TERM_BODY': {'ASP_CONSTRUCTOR': 'SIG'}}


def _appr() -> dict:
    return {'TERM_CONSTRUCTOR': 'asp', 'TERM_BODY': {'ASP_CONSTRUCTOR': 'APPR'}}


def _chain(leaves: list) -> dict:
    """Left-nested bseq chain (gumbo convention), then SIG, then APPR."""
    node = leaves[0]
    for leaf in leaves[1:]:
        node = {'TERM_CONSTRUCTOR': 'bseq', 'TERM_BODY': ['both_paths', node, leaf]}
    node = {'TERM_CONSTRUCTOR': 'lseq', 'TERM_BODY': [node, _sig()]}
    return {'TERM_CONSTRUCTOR': 'lseq', 'TERM_BODY': [node, _appr()]}


def _session(measure_asp: str) -> dict:
    types = {k: _ASP_TYPES[k] for k in (measure_asp, 'sig', 'sig_appr', 'goldenbytes_appr')}
    return {
        'Session_Plc': 'P0',
        'Plc_Mapping': {},
        'PubKey_Mapping': {},
        'Session_Context': {
            'ASP_Types': types,
            'ASP_Comps': {measure_asp: 'goldenbytes_appr', 'sig': 'sig_appr'},
        },
    }


def _manifest(measure_asp: str) -> dict:
    return {'ASPS': [measure_asp, 'sig', 'sig_appr', 'goldenbytes_appr'],
            'ASP_FS_MAP': {}, 'POLICY': []}


def _flow(labels: list, chunk_label: str) -> list:
    return [
        {'type': 'bseq', 'label': 'bseq / both_paths', 'children': labels},
        {'type': 'arrow'},
        {'type': 'asp', 'label': 'SIG', 'style': 'sig'},
        {'type': 'arrow'},
        {'type': 'asp', 'label': 'APPR', 'style': 'appr'},
    ]


def generate(report_path: Path, prefix: str, dest: Path) -> list:
    slices, files = load_slices(report_path)
    written = []

    # ── <prefix>_l1: whole-file hashes ────────────────────────────────────────
    l1_targets = {}
    for fp in files:
        targ = f'{prefix}_{_stem(fp)}_targ'
        n = 1
        while targ in l1_targets:
            n += 1
            targ = f'{prefix}_{_stem(fp)}_{n}_targ'
        l1_targets[targ] = {'filepath': fp, 'env_var': ''}
    l1 = {
        'term': _chain([_aspc('hashfile', t) for t in l1_targets]),
        'session': _session('hashfile'),
        'manifest': _manifest('hashfile'),
        'asp_args': {'hashfile': l1_targets},
        'meta': {
            'name': f'{prefix} file integrity (level 1)',
            'description': (
                f'Whole-file hashes of the {len(files)} files named by the HAMR '
                f'attestation report ({report_path.name}). Fast check; run '
                f'{prefix}_l2 on failure for per-contract attribution.'
            ),
            'copland': f'lseq( lseq( bseq_chain( hashfile×{len(files)} ), SIG ), APPR )',
            'flow': _flow([f'hashfile({Path(f).name})' for f in files], 'hashfile'),
            'dynamic': True,
        },
    }

    # ── <prefix>_l2: per-slice contract ranges ────────────────────────────────
    l2_targets = {}
    for s in slices:
        targ = f"{prefix}_{_stem(s['filepath'])}_{s['begin']}_{s['end']}_targ"
        n = 1
        while targ in l2_targets:
            n += 1
            targ = f"{prefix}_{_stem(s['filepath'])}_{s['begin']}_{s['end']}_{n}_targ"
        l2_targets[targ] = {
            'filepath': s['filepath'],
            'start_index': s['begin'],
            'end_index': s['end'],
            'metadata': f"{s['component']}::{s['contract']}",
        }
    l2 = {
        'term': _chain([_aspc('readfile_range', t) for t in l2_targets]),
        'session': _session('readfile_range'),
        'manifest': _manifest('readfile_range'),
        'asp_args': {'readfile_range': l2_targets},
        'meta': {
            'name': f'{prefix} contract attribution (level 2)',
            'description': (
                f'Per-contract line-range measurements of all {len(slices)} slices '
                f'in the HAMR attestation report ({report_path.name}). Identifies '
                'which specific contract failed; goldens are content, so failing '
                'ranges are repairable by golden restore.'
            ),
            'copland': f'lseq( lseq( bseq_chain( readfile_range×{len(slices)} ), SIG ), APPR )',
            'flow': _flow(
                [f"readfile_range({Path(a['filepath']).name}:{a['start_index']}-{a['end_index']})"
                 for a in l2_targets.values()],
                'readfile_range',
            ),
            'dynamic': True,
        },
    }

    for suffix, proto in (('l1', l1), ('l2', l2)):
        proto_dir = dest / f'{prefix}_{suffix}'
        proto_dir.mkdir(parents=True, exist_ok=True)
        for name, obj in (
            ('term.json', proto['term']),
            ('session.json', proto['session']),
            ('manifest.json', proto['manifest']),
            ('asp_args.json', proto['asp_args']),
            ('meta.json', proto['meta']),
        ):
            (proto_dir / name).write_text(json.dumps(obj, indent=2) + '\n')
        written.append(str(proto_dir))
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', help='HAMR attestation report JSON')
    parser.add_argument('--prefix', default='isolette')
    parser.add_argument('--dest', default=str(Path(__file__).parent / 'protocol_dirs'))
    cli = parser.parse_args()
    written = generate(Path(cli.report), cli.prefix, Path(cli.dest))
    for d in written:
        print(f'wrote {d}')
    print('Provision the new protocols via the dashboard '
          '(Provision button or /api/provision/<id>) before attesting.')


if __name__ == '__main__':
    main()
