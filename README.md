# cvm-mcp

An MCP server and web dashboard for the [Copland Virtual Machine (CVM)](https://github.com/ku-sldg/cvm) attestation framework. Lets AI agents (and humans) configure, run, and appraise Copland attestation protocols without writing JSON by hand.

## What's here

| File | Purpose |
|------|---------|
| `server.py` | FastMCP server — exposes CVM tools to AI agents |
| `cvm_client.py` | Low-level subprocess wrapper around the `cvm` binary |
| `protocols.py` | Named protocol registry with build + provisioning functions |
| `dashboard.py` | Flask web dashboard (port 5050) for human-readable results |
| `examples/` | Sample target files (`file1.txt`, `file2.txt`) |

## Prerequisites

1. **CVM binary** — build from [ku-sldg/cvm](https://github.com/ku-sldg/cvm) and ensure `cvm` is on your `PATH`.

2. **ASP binaries** — build from [ku-sldg/asp-libs](https://github.com/ku-sldg/asp-libs):
   ```sh
   cd asp-libs
   cargo build --release
   ```

3. **Python dependencies**:
   ```sh
   pip install -r requirements.txt
   # Also needed for the dashboard:
   pip install flask
   ```

## Configuration

By default the server looks for ASP binaries at `~/asp-libs/target/release`.
Override with an environment variable:

```sh
export CVM_ASP_BIN=/path/to/asp-libs/target/release
```

## Running the MCP server

```sh
python server.py
```

Connect any MCP-compatible client (Claude Desktop, etc.) to use the tools.

## Running the dashboard

```sh
python dashboard.py
# Open http://localhost:5050
```

The dashboard shows all registered protocols. For each protocol you can:
- **Provision** — compute golden hashes from the current target files and write them to disk
- **Run** — execute the full attestation protocol and display appraisal results

## Using the MCP tools

Key tools exposed by `server.py`:

| Tool | Description |
|------|-------------|
| `list_protocols` | List all registered named protocols |
| `run_protocol` | Run a named protocol and push results to the dashboard |
| `run_attestation` | Low-level: run a CVM manifest + request directly |
| `build_manifest` | Construct a CVM manifest JSON |
| `build_run_request` | Construct a CVM run request JSON |
| `term_lseq` | Build a sequential Copland term |
| `term_bseq` | Build a branching/parallel Copland term |
| `term_sig_asp` | Build a SIG (signature) term |
| `term_appr_asp` | Build an APPR (appraisal) term |
| `term_custom_asp` | Build an arbitrary ASP term with custom args |
| `list_available_asps` | List ASP binaries found in the configured asp_bin directory |

## Registered protocols

| ID | Copland term | Description |
|----|-------------|-------------|
| `single_hashfile_appr` | `lseq(hashfile(file1), APPR)` | Hash one file and appraise against a golden value |
| `hsh_sig_appr` | `lseq(lseq(hsh, SIG), APPR)` | Hash evidence, sign it, then appraise both layers |
| `dual_hashfile_sig_appr` | `lseq(lseq(bseq/both_paths(hashfile×2), SIG), APPR)` | Hash two files in parallel, sign, appraise all layers |

## Adding a new protocol

Add a `build_*` function, a `provision_*` function, a `golden_state_*` function, and a registry entry in `protocols.py`. The `build` function returns `(manifest_json, request_json)`; the `provision` function writes golden evidence files and returns a list of `{target, golden, sha256, timestamp}` dicts.
