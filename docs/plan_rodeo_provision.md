# Plan: Replace Python Provisioning with `rust-rodeo-client -p`

## Background

**Current Python provisioning flow** (`provision()` closure in `register_protocol_dir()`, `protocol_loader.py`):
1. Calls `_make_measurement_term()` — replaces all `APPR` nodes with `NULL`
2. Calls `_inject_asp_id_appr()` — injects `asp_id_appr` into ASPC nodes and strips bookkeeping keys
3. Invokes **CVM binary** via `cvm_client.run_cvm()` subprocess
4. Takes CVM's JSON stdout and writes `provision_bundle.json` as `[payload, global_context]`
5. For each `goldenbytes_appr` target, calls **`extract_golden_slice`** to get `golden_b64` and writes it to `asp_args.json`

**`rust-rodeo-client -p` flow** (from `rust-am-clients/executables/rust-rodeo-client/src/main.rs` and `rust-am-lib/src/copland.rs`):
- Takes `-t term_no_appr.json`, `-s session.json`, `-m manifest.json`, `-g asp_args.json`, `-p <bundle_output_path>`, `-c <cvm_binary>`, `-l <asp_bin_dir>`
- Internally calls `rust_am_lib::copland::add_provisioning_args()` — injects `asp_id_appr` into all ASPC nodes
- Calls `rust_am_lib::copland::append_provisioning_term()` — appends a `provision_goldenevidence` ASP to the term
- Invokes the **CVM binary** directly (via `--manifest <contents>` and `--req_file <path>`)
- **`provision_goldenevidence`** ASP runs inside CVM and writes the evidence bundle to the `-p` path as `(Evidence, GlobalContext)` — same JSON structure as the current `provision_bundle.json`

**Key differences to account for:**
1. `add_provisioning_args` in rust-am-lib only injects `asp_id_appr` — it does NOT strip `golden_b64`/`golden_ts`/`filepath_golden`/`env_var_golden`. A cleaned `asp_args.json` must be passed to prevent stale values from polluting re-provision runs.
2. `provision_goldenevidence` must be in the manifest — current `manifest.json` doesn't include it; a `manifest_provision.json` must be generated.
3. rust-rodeo-client passes manifest contents inline via `--manifest` (the CVM supports both `--manifest` and `--manifest_file`).
4. The bundle output format from `provision_goldenevidence` matches what `extract_golden_slice` already expects — same rust-am-lib serialization.

---

## 1. Prerequisites / Setup

- `CVM_BINARY` — path to CVM binary. Already read by `cvm_client.py`. No change.
- `CVM_ASP_BIN` — directory containing ASP binaries including `provision_goldenevidence`. Already read in `protocol_loader.py`. No change.
- `ASP_BIN` — required by `rust-rodeo-client`'s `clientArgs.rs` as default for `--libs`. Must be set to same path as `CVM_ASP_BIN`. Document in README/startup notes.
- **New:** `RODEO_CLIENT_BIN` — path to `rust-rodeo-client` binary. Default: `~/Claude_workspace/rust-am-clients/target/release/rust-rodeo-client`.

At provision time, verify `rust-rodeo-client`, `provision_goldenevidence` (in `CVM_ASP_BIN`), and `CVM_BINARY` all exist. Raise `RuntimeError` with a clear message if any are missing.

---

## 2. `generate_protocol_dirs.py` Changes

Add `manifest_provision.json` generation in `export_protocol()`, immediately after the existing `manifest.json` write:

```python
provision_manifest = {
    **manifest,
    'ASPS': sorted(set(manifest.get('ASPS', [])) | {'provision_goldenevidence'}),
}
_w('manifest_provision.json', provision_manifest)
```

- Always overwritten (fully derived from `manifest.json`; no `skip_if_exists` guard).
- Update module docstring file-list comment to include `manifest_provision.json`.

---

## 3. `protocol_loader.py` Changes — `provision()` Rewrite

Replace the existing `provision()` closure body with:

1. **Resolve binary paths:** `rodeo_bin` from `RODEO_CLIENT_BIN`, `cvm_bin` from `CVM_BINARY`, `asp_bin` from `CVM_ASP_BIN`.
2. **Resolve input files:** `term_no_appr.json`, `session.json`, `manifest_provision.json` from `local_dir` — see Section 5 for fallbacks when absent.
3. **Snapshot target files** (`.original` sidecars) — keep the existing block unchanged.
4. **Write cleaned `asp_args.json` temp file** — see Section 4.
5. **Invoke `rust-rodeo-client`:**
   ```python
   cmd = [
       rodeo_bin,
       '-t', term_no_appr_path,
       '-s', session_path,
       '-m', manifest_provision_path,
       '-g', cleaned_asp_args_path,
       '-p', bundle_path,
       '-c', cvm_bin,
       '-l', asp_bin,
   ]
   result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
   if result.returncode != 0:
       raise RuntimeError(f"rust-rodeo-client provision failed: {result.stderr.strip()}")
   ```
   Flag letters per `clientArgs.rs`: `-t` = `term_filepath`, `-s` = `session_filepath`, `-m` = `manifest_filepath`, `-g` = `g_asp_args_filepath`, `-p` = `provisioned_evidence_filepath`, `-c` = `cvm_filepath`, `-l` = `libs_asp_bin`.
6. **Verify `provision_bundle.json` was written** — raise `RuntimeError` if absent.
7. **Run `extract_golden_slice` per target** — the existing inner loop is **unchanged**; it still reads `provision_bundle.json` and writes `golden_b64` to `asp_args.json`.
8. **Delete temp files** in a `finally` block.
9. **Return `resolved`** list — same shape as current return value.

Remove the `from cvm_client import run_cvm` and `from protocol_builder import _make_measurement_term` imports from inside this closure.

---

## 4. Handling the `asp_args` Stripping Problem

`add_provisioning_args_asp` injects `asp_id_appr` but does NOT strip bookkeeping keys. Stale `golden_b64` etc. from a previous provision run would be injected into ASPC nodes, causing evidence-tree mismatches on re-provision.

**Solution:** write a temporary cleaned copy of `asp_args.json` before invoking `rust-rodeo-client`.

```python
_PROVISION_BOOKKEEPING_KEYS = frozenset({
    'golden_b64', 'golden_ts', 'filepath_golden', 'env_var_golden'
})

def _clean_asp_args_for_provision(asp_args: dict) -> dict:
    return {
        asp_id: {
            targ_id: {k: v for k, v in args.items()
                      if k not in _PROVISION_BOOKKEEPING_KEYS}
            for targ_id, args in targets.items()
        }
        for asp_id, targets in asp_args.items()
    }
```

Write the cleaned dict to a `tempfile.NamedTemporaryFile` (suffix `_asp_args_clean.json`), unlink in `finally`. If `asp_args.json` is empty or absent, write `{}`.

---

## 5. Fallback Strategy for Absent Files

Both `term_no_appr.json` and `manifest_provision.json` may be absent in older imported protocol directories.

**`term_no_appr.json` absent:**
- Compute on-the-fly using `_strip_appr()` from `generate_protocol_dirs.py`.
- Write to a temp file, pass as `-t`, delete in `finally`.
- If `_strip_appr(term)` returns `None` / the unmodified term (no APPR present), raise `RuntimeError`.
- Log a warning recommending re-running `generate_protocol_dirs.py`.

**`manifest_provision.json` absent:**
- Generate in-memory from `manifest.json`: add `"provision_goldenevidence"` to `ASPS`.
- Write to a temp file, pass as `-m`, delete in `finally`.
- Log a warning recommending re-generation.

Consider extracting both fallbacks into a helper `_resolve_provision_inputs(local_dir) -> (term_path, manifest_path, cleanup_fn)`.

---

## 6. What Can Be Removed After the Change

**In `protocol_loader.py`:**
- `_inject_asp_id_appr()` inner function — replaced by `add_provisioning_args` inside `rust-rodeo-client`
- `_PROVISION_BOOKKEEPING_KEYS` inline definition inside `provision()` — replaced by module-level constant in `_clean_asp_args_for_provision`
- `from cvm_client import run_cvm` inside `register_protocol_dir`'s `provision()` closure
- `from protocol_builder import _make_measurement_term` inside that same closure
- The `manifest_obj` / `request_obj` / CVM invocation block inside `provision()`

**Do NOT remove yet:**
- `extract_golden_slice` subprocess loop — still needed to populate `golden_b64` into `asp_args.json`
- `_make_measurement_term` in `protocol_builder.py` — still used by `load_protocol_from_file`'s own `provision()`

---

## 7. Testing Steps

1. **Compile check:** confirm `provision_goldenevidence` and `rust-rodeo-client` exist in their respective `target/release/` directories. Build if absent (`cargo build --release`).

2. **Regenerate protocol dirs:** run `python generate_protocol_dirs.py` and confirm each `protocol_dirs/<id>/manifest_provision.json` is written with `provision_goldenevidence` in `ASPS`.

3. **Manual CLI smoke test** (before Python integration) for a simple protocol such as `single_hashfile_appr`:
   ```sh
   rust-rodeo-client \
     -t protocol_dirs/single_hashfile_appr/term_no_appr.json \
     -s protocol_dirs/single_hashfile_appr/session.json \
     -m protocol_dirs/single_hashfile_appr/manifest_provision.json \
     -g /tmp/empty_asp_args.json \
     -p /tmp/test_bundle.json \
     -c $CVM_BINARY \
     -l $CVM_ASP_BIN
   ```
   Confirm `/tmp/test_bundle.json` is valid JSON with two top-level elements matching `(Evidence, GlobalContext)`.

4. **Python `provision()` integration test:** call `provision()` for a protocol from a REPL or unit test. Confirm `provision_bundle.json` is written, `asp_args.json` is updated with `golden_b64` and `golden_ts`, and `resolved` is non-empty.

5. **Re-provision idempotency:** call `provision()` a second time. Confirm `golden_b64` is updated (same value if file unchanged) and no error is raised.

6. **Tamper/appraise cycle via dashboard:** tamper target → run (expect FAIL) → repair → provision → run (expect PASS).

7. **Fallback path test:** rename `term_no_appr.json` and `manifest_provision.json` in one protocol dir, call `provision()`, confirm fallback succeeds with warnings.

8. **Multi-target test:** provision a protocol with multiple `goldenbytes_appr` targets. Confirm all `targ_id` entries in `asp_args.json` are populated.
