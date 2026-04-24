"""
Low-level client for invoking the CVM binary as a subprocess.
"""

import json
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Any

CVM_BINARY = os.environ.get(
    'CVM_BINARY',
    '/Users/adampetz/Claude_workspace/cvm/_build/default/theories/cvm',
)


def _write_temp_json(data: Any, suffix: str) -> str:
    """Write a JSON-serializable value to a temp file and return the path."""
    if isinstance(data, str):
        # Already a JSON string — validate it parses, then write as-is
        json.loads(data)
        content = data
    else:
        content = json.dumps(data)

    fd, path = tempfile.mkstemp(suffix=suffix, prefix="cvm_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
    except Exception:
        os.unlink(path)
        raise
    return path


def run_cvm(
    manifest: "str | dict",
    request: "str | dict",
    asp_bin: str,
    log_level: str = "Debug",
) -> dict:
    """
    Invoke the CVM binary and return the parsed JSON response.

    Args:
        manifest:  Manifest JSON — either a JSON string or a Python dict.
        request:   Request JSON — either a JSON string or a Python dict.
        asp_bin:   Directory containing ASP binaries. CVM resolves each ASP as
                   <asp_bin>/<asp_id>. With asp-libs use target/release/.
        log_level: CVM log level (Debug, Info, Warning, Error, Critical).

    Returns:
        Parsed JSON response as a Python dict.

    Raises:
        ValueError:  If the manifest or request JSON is invalid.
        RuntimeError: If the CVM process fails unexpectedly.
    """
    manifest_path = _write_temp_json(manifest, "_manifest.json")
    request_path = _write_temp_json(request, "_request.json")

    try:
        cmd = [
            CVM_BINARY,
            "--manifest_file", manifest_path,
            "--req_file", request_path,
            "--asp_bin", asp_bin,
            "--log_level", log_level,
            "--cvm_binary", CVM_BINARY,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1200,  # 20 min — sequential gumbo_validation runs 5 Sireum tools
        )

        # CVM writes the JSON response to stdout
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if not stdout:
            raise RuntimeError(
                f"CVM produced no output (exit {result.returncode}).\n"
                f"stderr: {stderr}"
            )

        try:
            return json.loads(stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"CVM output was not valid JSON: {e}\nraw output: {stdout}"
            )
    finally:
        os.unlink(manifest_path)
        os.unlink(request_path)


# ---------------------------------------------------------------------------
# Manifest helpers
# ---------------------------------------------------------------------------

def build_manifest(
    asps: list[str],
    asp_fs_map: dict[str, str] | None = None,
    policy: list | None = None,
) -> dict:
    """
    Construct a CVM manifest dict.

    Args:
        asps:       List of ASP identifier strings.
        asp_fs_map: Mapping of ASP ID → filesystem path to the ASP binary.
        policy:     Policy list (list of [place, asp_id] pairs). Defaults to [].

    Returns:
        Manifest as a Python dict ready for json.dumps.
    """
    return {
        "ASPS": asps,
        "ASP_FS_MAP": asp_fs_map or {},
        "POLICY": policy or [],
    }


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------

def build_run_request(
    session_plc: str,
    req_plc: str,
    term: dict,
    plc_mapping: dict[str, str] | None = None,
    pubkey_mapping: dict[str, str] | None = None,
    session_context: dict | None = None,
    evidence: list | None = None,
) -> dict:
    """
    Construct a CVM RUN request dict.

    Args:
        session_plc:     Place identifier for the attestation session (e.g. "P0").
        req_plc:         Place identifier of the requester.
        term:            Copland term dict (use term_* helpers below).
        plc_mapping:     Map of place → "ip:port" for remote places. Defaults to {}.
        pubkey_mapping:  Map of place → public key string. Defaults to {}.
        session_context: GlobalContext dict. Defaults to empty context.
        evidence:        Initial evidence. Defaults to empty (mt_evt).

    Returns:
        Request as a Python dict ready for json.dumps.
    """
    return {
        "TYPE": "REQUEST",
        "ACTION": "RUN",
        "ATTESTATION_SESSION": {
            "Session_Plc": session_plc,
            "Plc_Mapping": plc_mapping or {},
            "PubKey_Mapping": pubkey_mapping or {},
            "Session_Context": session_context or {"ASP_Types": {}, "ASP_Comps": {}},
        },
        "REQ_PLC": req_plc,
        "TERM": term,
        "EVIDENCE": evidence or [{"RawEv": []}, {"EvidenceT_CONSTRUCTOR": "mt_evt"}],
    }


# ---------------------------------------------------------------------------
# Copland term constructors
# ---------------------------------------------------------------------------

def term_appr_asp() -> dict:
    """APPR — built-in recursive appraisal of the current evidence tree."""
    return {"TERM_CONSTRUCTOR": "asp", "TERM_BODY": {"ASP_CONSTRUCTOR": "APPR"}}


def term_null_asp() -> dict:
    """NULL ASP — no-op, useful for testing."""
    return {"TERM_CONSTRUCTOR": "asp", "TERM_BODY": {"ASP_CONSTRUCTOR": "NULL"}}


def term_sig_asp() -> dict:
    """SIG ASP — sign the current evidence."""
    return {"TERM_CONSTRUCTOR": "asp", "TERM_BODY": {"ASP_CONSTRUCTOR": "SIG"}}


def term_hsh_asp() -> dict:
    """HSH ASP — hash the current evidence."""
    return {"TERM_CONSTRUCTOR": "asp", "TERM_BODY": {"ASP_CONSTRUCTOR": "HSH"}}


def term_custom_asp(asp_id: str, asp_args: dict | None = None) -> dict:
    """Custom (ASPC) ASP with an ID and optional args dict."""
    return {
        "TERM_CONSTRUCTOR": "asp",
        "TERM_BODY": {
            "ASP_CONSTRUCTOR": "ASPC",
            "ASP_BODY": {
                "ASP_ID": asp_id,
                "ASP_ARGS": asp_args or {},
            },
        },
    }


def term_att(place: str, sub_term: dict) -> dict:
    """Remote attestation at a given place."""
    return {
        "TERM_CONSTRUCTOR": "att",
        "TERM_BODY": [place, sub_term],
    }


def term_lseq(t1: dict, t2: dict) -> dict:
    """Linear sequence of two terms."""
    return {
        "TERM_CONSTRUCTOR": "lseq",
        "TERM_BODY": [t1, t2],
    }


def term_bseq(split: str, t1: dict, t2: dict) -> dict:
    """
    Branching sequence.

    Args:
        split: One of "left_path", "right_path", "both_paths".
    """
    return {
        "TERM_CONSTRUCTOR": "bseq",
        "TERM_BODY": [split, t1, t2],
    }


def term_bpar(split: str, t1: dict, t2: dict) -> dict:
    """
    Branching parallel.

    Args:
        split: One of "left_path", "right_path", "both_paths".
    """
    return {
        "TERM_CONSTRUCTOR": "bpar",
        "TERM_BODY": [split, t1, t2],
    }
