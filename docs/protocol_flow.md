# Protocol Provisioning and Run Flow

---

## Startup

- Flask dashboard server starts; `loaded_protocols.json` is read to re-register previously imported protocols.
- Each `protocol_dirs/<id>/` entry is loaded into the shared `REGISTRY` (`meta.json`, `manifest.json`, `session.json`, `term.json`, `asp_args.json`).
- Built-in protocols are registered directly from `protocols.py`.

---

## Provisioning

1. User clicks **Provision** → browser calls `GET /api/provision/<id>`.
2. Target files are snapshotted (`.original` sidecar) for later repair/reset.
3. The full Copland term is transformed into a measurement-only term (`APPR` → `NULL`) so the CVM always succeeds.
4. **CVM binary** is invoked via `cvm_client.run_cvm()` with the measurement-only term.
   - CVM fork/execs each measurement ASP (e.g. `hashfile`) from `asp-libs/target/release/`.
   - Returns a JSON evidence payload (`RawEv` + `EvidenceT` tree).
5. Evidence payload is written to `provision_bundle.json`.
6. **`extract_golden_slice`** (Rust binary) is invoked once per target.
   - Reads `provision_bundle.json` + `asp_args.json`, locates the matching ASP event, and returns base64-encoded golden bytes.
7. `golden_b64` and `golden_ts` are written back into `asp_args.json`.

---

## Running

1. User clicks **Run** → browser calls `GET /api/run/<id>`; dashboard spawns a background thread.
2. Provision guard: checks `asp_args.json` for a `golden_ts`; returns an error if not provisioned.
3. Manifest and request are assembled:
   - `protocol_loader.build_from_dir()` loads `term.json`, `session.json`, `manifest.json`.
   - `inject_asp_args()` merges `golden_b64` and other stored args from `asp_args.json` into matching ASPC nodes in the term.
4. For multi-place protocols, place reachability is checked via `place_manager`.
5. **CVM binary** is invoked via `cvm_server.run_attestation()` → `cvm_client.run_cvm()` with the full term.
   - CVM fork/execs measurement ASPs, then appraisal ASPs (e.g. `goldenbytes_appr`), then `sig`/`sig_appr`.
   - Returns `{ SUCCESS, PAYLOAD: [RawEv, EvidenceT] }`.
6. `walk_et()` parses the `EvidenceT` tree; each `_appr` ASP event is decoded to a PASS/FAIL verdict.
7. Results are stored in `results_store` and rendered in the UI via a polling loop.

---

## Stepped Protocols

Some protocols (e.g. `gumbo_validation`) split attestation into sub-steps:

- **Sequential** (`_run_stepped`): each step invokes the **CVM binary** separately; partial results are pushed to the UI after each step.
- **Parallel** (`_run_check`): all steps invoke the **CVM binary** concurrently via `ThreadPoolExecutor`.

---

## Key Binaries

| Binary | Role |
|---|---|
| `cvm` | Executes Copland terms; fork/execs ASPs; produces the evidence tree |
| `hashfile` | Measurement ASP — reads a file and produces raw measurement bytes |
| `goldenbytes_appr` | Appraisal ASP — compares measured bytes to the provisioned `golden_b64` |
| `sig` / `sig_appr` | Signs and verifies the evidence chain |
| `extract_golden_slice` | Extracts per-target golden bytes from the provision bundle |
