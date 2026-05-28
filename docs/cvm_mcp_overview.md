# cvm-mcp

A Python server that wraps the **Copland Virtual Machine (CVM)** — a verified CakeML binary (verified and extracted from Rocq) that executes Copland attestation protocols. It exposes the CVM as an **MCP tool server**, letting AI agents build and run attestation workflows via structured tool calls.

## Features

- **Protocol registry** — built-in protocols defined in `protocols.py`; custom ones importable from directories
- **Attestation execution** — invokes the CVM binary with Copland terms, sessions, and manifests; returns structured pass/fail evidence
- **Provisioning** — runs measurement-only CVM passes to capture golden reference values (`golden_b64`) per target file
- **MCP tool surface** — `term_*` builders, `build_manifest`, `run_attestation`, `run_protocol`, `appraisal_summary`, etc.
