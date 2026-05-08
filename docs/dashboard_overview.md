# Dashboard

A Flask web UI for interacting with the protocol registry without writing code.

## Features

- **Protocol cards** — one card per protocol showing last run verdict (pass/fail counts), Copland expression, and action buttons
- **Provision** — captures golden reference bytes for each measurement target; stores them in `asp_args.json`
- **Run / Check** — executes the full attestation term through the CVM; displays per-target PASS/FAIL verdicts
- **Tamper / Repair** — modifies target files to simulate attacks; restores them from `.original` snapshots
- **Multi-place support** — start/stop remote attestation endpoints; monitor place connectivity
- **Protocol builder** — UI for composing new Copland terms and importing external protocol directories
