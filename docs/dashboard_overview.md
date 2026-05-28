# Dashboard

A Flask web UI for interacting with the protocol registry without writing code.

## Features

- **Protocol cards** — one card per protocol showing last run verdict (pass/fail counts), Copland expression, and action buttons (Provision / Run / Copy / Remove)
- **Provision** — captures golden reference bytes for each measurement target; stores them in the protocol's `asp_args.json`
- **Run / Check** — executes the full attestation term through the CVM; displays per-target PASS/FAIL verdicts
- **Copy & edit** — every protocol is a `protocol_dirs/<id>/` directory. **Copy** duplicates one into a new (unprovisioned) directory; the detail page then lets you edit its **Metadata** (name/description) and **ASP Arguments** (per-target `filepath`, etc.) in place. Changing a target's filepath clears its golden so it must be re-provisioned.
- **Import** — register an external protocol directory by path (copied into `protocol_dirs/`)
