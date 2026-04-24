#!/usr/local/bin/python3
"""
am_place.py — Lightweight ZMQ-REP wrapper around the CVM binary.

Simulates a remote Copland place by listening on a TCP port and dispatching
incoming att requests to a local CVM instance.  The CVM binary makes outbound
ZMQ REQ connections when it encounters att(P, t) terms; this service is the
REP end of that exchange.

Wire protocol (set by CVM's socket_ffi.c / IO_Axioms.cml):
  - Transport: ZMQ REQ/REP over TCP
  - Framing:   raw string messages (no envelope)
  - Request:   PRReq JSON string  { ATTESTATION_SESSION, REQ_PLC, TERM, EVIDENCE, ... }
  - Response:  PRResp JSON string { SUCCESS, PAYLOAD }

Usage:
    python am_place.py --port 8081 --manifest path/to/manifest.json \\
                       --asp_bin path/to/asp/binaries [--place P1] [--log_level Info]

    # Multiple places for a multi-place protocol:
    python am_place.py --port 8081 --manifest place_b.json --asp_bin .../asps --place P1 &
    python am_place.py --port 8082 --manifest place_c.json --asp_bin .../asps --place P2 &
"""

import argparse
import json
import logging
import os
import sys

import zmq

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cvm_client import run_cvm


# ---------------------------------------------------------------------------
# Core request handler
# ---------------------------------------------------------------------------

def handle_request(req_str: str, manifest: dict, asp_bin: str, log_level: str) -> str:
    """
    Parse an incoming PRReq JSON string, invoke CVM, and return a PRResp
    JSON string.

    Returns a well-formed error PRResp on any failure so the calling CVM
    instance receives a parseable response rather than a broken socket.
    """
    try:
        request = json.loads(req_str)
    except json.JSONDecodeError as e:
        return json.dumps({"SUCCESS": False, "ERROR": f"Malformed request JSON: {e}"})

    try:
        response = run_cvm(manifest, request, asp_bin, log_level)
        return json.dumps(response)
    except Exception as e:
        return json.dumps({"SUCCESS": False, "ERROR": str(e)})


# ---------------------------------------------------------------------------
# Server loop
# ---------------------------------------------------------------------------

def serve(port: int, manifest: dict, asp_bin: str, place: str, log_level: str) -> None:
    log = logging.getLogger(f"am_place[{place}]")
    ctx = zmq.Context()
    sock = ctx.socket(zmq.REP)
    sock.bind(f"tcp://*:{port}")
    log.info(f"Listening on tcp://*:{port}  (place={place})")

    try:
        while True:
            req_str = sock.recv_string()
            log.info(f"← request  {len(req_str):,} bytes")
            resp_str = handle_request(req_str, manifest, asp_bin, log_level)
            sock.send_string(resp_str)
            log.info(f"→ response {len(resp_str):,} bytes")
    except KeyboardInterrupt:
        log.info("Shutting down")
    finally:
        sock.close()
        ctx.term()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CVM AM place wrapper — listens for att requests over ZMQ and dispatches to CVM"
    )
    parser.add_argument("--port",      type=int, required=True,
                        help="TCP port to listen on (e.g. 8081)")
    parser.add_argument("--manifest",  required=True,
                        help="Path to the manifest JSON file for this place")
    parser.add_argument("--asp_bin",   required=True,
                        help="Directory containing ASP binaries for this place")
    parser.add_argument("--place",     default=None,
                        help="Place identifier string (used in log output only)")
    parser.add_argument("--log_level", default="Info",
                        choices=["Debug", "Info", "Warning", "Error", "Critical"],
                        help="CVM log level passed to each CVM invocation (default: Info)")
    args = parser.parse_args()

    place = args.place or f"port-{args.port}"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    if not os.path.isfile(args.manifest):
        sys.exit(f"Manifest not found: {args.manifest}")
    if not os.path.isdir(args.asp_bin):
        sys.exit(f"asp_bin directory not found: {args.asp_bin}")

    with open(args.manifest) as f:
        manifest = json.load(f)

    serve(args.port, manifest, args.asp_bin, place, args.log_level)


if __name__ == "__main__":
    main()
