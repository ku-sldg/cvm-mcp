# cvm-mcp

A Python server that wraps the **Copland Virtual Machine (CVM)** — a verified CakeML binary (verified and extracted from Rocq) that executes Copland attestation protocols. It exposes the CVM as an **MCP tool server**, letting AI agents build and run attestation workflows via structured tool calls.

## Features

- **Protocol registry** — a protocol *is* a `protocol_dirs/<id>/` directory (`meta.json`, `term.json`, `session.json`, `manifest.json`, `asp_args.json`). Every directory is auto-registered at startup; there is no built-in/custom distinction. New protocols are created by copying an existing one and editing its directory, or by importing an external directory.
- **Attestation execution** — invokes the CVM binary with Copland terms, sessions, and manifests; returns structured pass/fail evidence
- **Provisioning** — runs measurement-only CVM passes to capture golden reference values (`golden_b64`) per target, written back into `asp_args.json`
- **MCP tool surface** — `term_*` builders, `build_manifest`, `run_attestation`, `run_protocol`, `appraisal_summary`, etc.
