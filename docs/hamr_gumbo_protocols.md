# HAMR / GUMBO Protocols

The dashboard includes five protocols built around the **TempControl** HAMR/GUMBO case study — a model-based avionics component with formally specified contracts. The source artifacts are:

| Artifact | Role |
|---|---|
| `TempControlSystem.aadl` | AADL model with GUMBO `assume`/`guarantee` clauses and data invariants |
| `TempSensor.aadl` | AADL model with GUMBO `guarantee` clauses |
| `TempControlPeriodic_..._GumboX.scala` | Generated Slang oracle (`@strictpure` predicates) for TempControl |
| `TempSensorPeriodic_..._GumboX.scala` | Generated Slang oracle for TempSensor |
| `TempControlPeriodic_..._tempControl.scala` | HAMR-generated component implementation |
| `TempSensorPeriodic_..._tempSensor.scala` | HAMR-generated component implementation |

---

## GUMBO File Integrity (Level 1)

**Copland:** `lseq( lseq( bseq_chain( hashfile×4 ), SIG ), APPR )`

A fast whole-file integrity check over the four "do not edit" contract artifacts. Detects any change but cannot identify which contract was modified. Intended as a quick first-pass; run Level 2 on failure for attribution.

**ASPs invoked:**
- `hashfile` — hashes each file in its entirety (×4, run sequentially via `bseq_chain`)
- `sig` — signs the accumulated evidence chain
- `goldenbytes_appr` — compares each hash against provisioned `golden_b64` values
- `sig_appr` — verifies the signature

**Provisioning:** Required. CVM runs with `hashfile` only (APPR replaced with NULL); `golden_b64` captured per file via `extract_golden_slice`.

---

## GUMBO Contract Attribution (Level 2)

**Copland:** `lseq( lseq( bseq_chain( readfile_range×22 + readfile_marker_range×6 ), SIG ), APPR )`

Per-contract measurements that identify exactly which GUMBO clause or oracle predicate failed attestation. Contracts are extracted as byte ranges rather than whole files, so a single targeted edit triggers exactly one failing measurement.

**28 measurement targets across three artifact types:**
- **AADL clauses** (`readfile_range`) — `assume`/`guarantee` statements and data invariants extracted by scanning for the clause name and reading to the `;` terminator. Line numbers are resolved live at provision/build time.
- **GumboX `@strictpure` predicates** (`readfile_range`) — oracle predicate function bodies extracted by scanning for the `@strictpure def NAME` signature. Line numbers tracked live.
- **Component BEGIN/END blocks** (`readfile_marker_range`) — implementation contract blocks bounded by stable `// BEGIN …` / `// END …` comment markers, immune to line number drift as implementation code grows.

**ASPs invoked:**
- `readfile_range` — reads a file slice by 1-based start/end line indices (×22)
- `readfile_marker_range` — reads a file slice bounded by exact comment-line markers (×6)
- `sig` — signs the full evidence chain
- `goldenbytes_appr` — compares each slice against its provisioned golden bytes
- `sig_appr` — verifies the signature

**Provisioning:** Required. Each target's golden bytes are captured independently and stored under their `targ_id` in `asp_args.json`.

---

## GUMBO Behavioral Validation

**Copland:** `lseq( bseq_chain( run_command_hamr×5 ), APPR )`

Runs live HAMR/Sireum validation tools rather than comparing against golden bytes. Pass means the tools themselves exit cleanly — no provisioning needed.

**Steps (sequential via `bseq_chain`):**
1. `proyek tipe` — Slang type check over all project modules
2. `proyek logika` — Logika formal verification of TempControl GumboX predicates (z3 solver)
3. `proyek logika` — Logika formal verification of TempSensor GumboX predicates (z3 solver)
4. `proyek test` — Randomised GumboX unit tests for TempControl
5. `proyek test` — Randomised GumboX unit tests for TempSensor

**ASPs invoked:**
- `run_command_hamr` — invokes a `sireum proyek` subcommand; exit code captured as evidence (×5)
- `run_command_hamr_appr` — checks `exit_code == 0` for each invocation

**Tools leveraged:** Sireum CLI (`sireum proyek tipe / logika / test`), resolved from `PATH`; `SIREUM_HOME` inherited from the CVM process environment. Logika and test steps require cvc5/z3 solver dependencies.

**Provisioning:** None required.

---

## GUMBO Behavioral Validation (bpar)

**Copland:** `lseq( bpar/both_paths( bseq_chain(tipe, logika_tc, test_tc), bseq_chain(logika_ts, test_ts) ), APPR )`

Parallel variant of Behavioral Validation. The five steps are split into two independent tracks that run concurrently via `bpar`:

- **Left branch** (main process): `tipe` → `logika_tc` → `test_tc`
- **Right branch** (CVM subprocess): `logika_ts` → `test_ts`

Expected speedup ≈ 2× over sequential. ASPs and tools are identical to the sequential variant.

---

## GUMBO Behavioral Validation (full parallel)

**Copland:** `lseq( bpar(tipe, bpar(logika_tc, bpar(logika_ts, bpar(test_tc, test_ts)))), APPR )`

Fully-parallel variant. All five steps run simultaneously as individual `bpar` branches — each `sireum` invocation reads source files without shared write state. Expected wall time ≈ max of any single step (~28s vs ~66s sequential, ≈2.4× speedup). ASPs and tools are identical to the sequential variant.
