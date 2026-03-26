"""
CVM MCP Server

Exposes the Copland Virtual Machine (CVM) attestation tool to AI agents
via the Model Context Protocol (MCP).

Run with:
    python server.py

ASP binary layout
-----------------
The CVM --asp_bin argument is a *directory*.  When CVM invokes an ASP it
constructs the path: <asp_bin>/<asp_id> and fork/execs that binary.

With the asp-libs build the correct value is the release directory, e.g.:
    ~/asp-libs/target/release

Set the CVM_ASP_BIN environment variable to override the default, or pass
asp_bin explicitly to run_attestation().
"""

import base64
import json
import os
import urllib.request
from pathlib import Path
from mcp.server.fastmcp import FastMCP
import cvm_client as cvm

DASHBOARD_URL = "http://localhost:5050"

ASP_BIN_DEFAULT = os.environ.get(
    "CVM_ASP_BIN",
    str(Path.home() / "asp-libs/target/release"),
)

mcp = FastMCP(
    "cvm",
    instructions=(
        "Tools for configuring and invoking the Copland Virtual Machine (CVM) "
        "attestation framework. Use build_manifest and build_run_request to "
        "construct the required JSON inputs, then call run_attestation to "
        "execute them. Use the term_* tools to build Copland attestation terms."
    ),
)


# ---------------------------------------------------------------------------
# Core tool: invoke the CVM
# ---------------------------------------------------------------------------

@mcp.tool()
def run_attestation(
    manifest: str,
    request: str,
    asp_bin: str = ASP_BIN_DEFAULT,
    log_level: str = "Info",
) -> str:
    """
    Execute a CVM attestation request and return the result.

    Args:
        manifest:  Manifest JSON string. Describes which ASPs are available and
                   their filesystem locations. Build one with build_manifest().
        request:   Request JSON string. Describes the attestation session,
                   Copland term, and initial evidence. Build one with
                   build_run_request().
        asp_bin:   Path to the directory containing ASP binaries. CVM locates
                   each ASP by joining this directory with the ASP ID:
                   <asp_bin>/<asp_id>. Defaults to the asp-libs release build
                   at ~/Claude_workspace/asp-libs/target/release.
                   Use list_available_asps() to see what is built there.
        log_level: CVM log verbosity: "Debug", "Info", "Warning", "Error",
                   or "Critical". Defaults to "Info".

    Returns:
        JSON string with the attestation result. On success the response
        contains {"TYPE": "RESPONSE", "ACTION": "RUN", "SUCCESS": true,
        "PAYLOAD": <evidence>}. On failure it contains {"SUCCESS": false,
        "PAYLOAD": "<error message>"}.
    """
    try:
        manifest_dict = json.loads(manifest)
        request_dict = json.loads(request)
    except json.JSONDecodeError as e:
        return json.dumps({"SUCCESS": False, "PAYLOAD": f"Invalid JSON input: {e}"})

    try:
        result = cvm.run_cvm(manifest_dict, request_dict, asp_bin, log_level)
        return json.dumps(result, indent=2)
    except (ValueError, RuntimeError) as e:
        return json.dumps({"SUCCESS": False, "PAYLOAD": str(e)})


# ---------------------------------------------------------------------------
# Manifest tools
# ---------------------------------------------------------------------------

@mcp.tool()
def build_manifest(
    asps: list[str],
    asp_fs_map: dict | None = None,
    policy: list | None = None,
) -> str:
    """
    Construct a CVM manifest JSON string.

    The manifest tells CVM which ASPs (Attestation Service Providers) are
    available and where their binaries live on the filesystem.

    Args:
        asps:       List of ASP identifier strings that this place supports.
                    Example: ["hashfile", "sig", "attest"]
        asp_fs_map: Mapping of ASP ID → absolute path to the ASP binary.
                    Example: {"hashfile": "/usr/local/bin/asp_hashfile"}
                    Leave empty ({}) if the asp_bin dispatcher handles routing.
        policy:     Policy list — list of [place, asp_id] pairs that define
                    which ASPs are permitted at which places.
                    Example: [["P0", "hashfile"], ["P0", "sig"]]
                    Defaults to [] (no policy restrictions).

    Returns:
        Manifest as a JSON string, ready to pass to run_attestation().
    """
    manifest = cvm.build_manifest(
        asps=asps,
        asp_fs_map=asp_fs_map,
        policy=policy,
    )
    return json.dumps(manifest, indent=2)


@mcp.tool()
def validate_manifest(manifest: str) -> str:
    """
    Check a manifest JSON string for required fields and basic structure.

    Args:
        manifest: Manifest JSON string to validate.

    Returns:
        "OK" if valid, or a string describing what is missing or malformed.
    """
    try:
        m = json.loads(manifest)
    except json.JSONDecodeError as e:
        return f"Invalid JSON: {e}"

    issues = []
    if "ASPS" not in m:
        issues.append("Missing required field: ASPS (list of ASP IDs)")
    elif not isinstance(m["ASPS"], list):
        issues.append("ASPS must be a list of strings")

    if "ASP_FS_MAP" not in m:
        issues.append("Missing required field: ASP_FS_MAP (object mapping ASP ID -> path)")
    elif not isinstance(m["ASP_FS_MAP"], dict):
        issues.append("ASP_FS_MAP must be an object")

    if "POLICY" not in m:
        issues.append("Missing required field: POLICY (list of [place, asp_id] pairs)")
    elif not isinstance(m["POLICY"], list):
        issues.append("POLICY must be a list")

    return "OK" if not issues else "\n".join(issues)


# ---------------------------------------------------------------------------
# Request tools
# ---------------------------------------------------------------------------

@mcp.tool()
def build_run_request(
    session_plc: str,
    req_plc: str,
    term: str,
    plc_mapping: dict | None = None,
    pubkey_mapping: dict | None = None,
    session_context: dict | None = None,
    evidence: list | None = None,
) -> str:
    """
    Construct a CVM RUN request JSON string.

    Args:
        session_plc:     Place identifier for this attestation session.
                         Typically matches the local place, e.g. "P0".
        req_plc:         Place identifier of the entity making the request.
                         Often the same as session_plc for local requests.
        term:            Copland term as a JSON string. Build one using the
                         term_* tools (term_custom_asp, term_lseq, etc.).
        plc_mapping:     Map of place ID → "ip:port" for remote places involved
                         in the attestation. Example: {"P1": "10.0.0.2:8080"}.
                         Omit or leave empty for local-only attestation.
        pubkey_mapping:  Map of place ID → public key string. Used for
                         cryptographic operations. Example: {"P0": "-----BEGIN..."}.
        session_context: GlobalContext dict with ASP type and composition info.
                         Defaults to {"ASP_Types": {}, "ASP_Comps": {}}.
        evidence:        Initial evidence to feed into the attestation.
                         Defaults to empty evidence (mt_evt).

    Returns:
        RUN request as a JSON string, ready to pass to run_attestation().
    """
    try:
        term_dict = json.loads(term)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid term JSON: {e}"})

    request = cvm.build_run_request(
        session_plc=session_plc,
        req_plc=req_plc,
        term=term_dict,
        plc_mapping=plc_mapping,
        pubkey_mapping=pubkey_mapping,
        session_context=session_context,
        evidence=evidence,
    )
    return json.dumps(request, indent=2)


# ---------------------------------------------------------------------------
# Copland term tools
# ---------------------------------------------------------------------------

@mcp.tool()
def term_appr_asp() -> str:
    """
    Build an APPR Copland term (built-in recursive appraisal).

    APPR walks the current evidence tree and automatically invokes the dual
    appraisal ASP for each measurement ASP encountered, using ASP_Comps from
    the Session_Context to resolve which appraiser to call.

    Requirements:
      - Every measurement ASP in the evidence tree must have an entry in
        Session_Context.ASP_Comps mapping it to its appraisal counterpart.
      - Every appraisal ASP must be listed in the manifest ASPS and have an
        entry in Session_Context.ASP_Types.

    Returns:
        Copland term JSON string.
    """
    return json.dumps({"TERM_CONSTRUCTOR": "asp", "TERM_BODY": {"ASP_CONSTRUCTOR": "APPR"}})


@mcp.tool()
def term_null_asp() -> str:
    """
    Build a NULL ASP Copland term (no-op).

    Useful for testing the CVM pipeline without invoking a real ASP.

    Returns:
        Copland term JSON string.
    """
    return json.dumps(cvm.term_null_asp())


@mcp.tool()
def term_sig_asp() -> str:
    """
    Build a SIG ASP Copland term (sign the current evidence).

    Returns:
        Copland term JSON string.
    """
    return json.dumps(cvm.term_sig_asp())


@mcp.tool()
def term_hsh_asp() -> str:
    """
    Build a HSH ASP Copland term (hash the current evidence).

    Returns:
        Copland term JSON string.
    """
    return json.dumps(cvm.term_hsh_asp())


@mcp.tool()
def term_custom_asp(asp_id: str, asp_args: dict | None = None) -> str:
    """
    Build a custom ASP Copland term.

    Use this to invoke any named ASP that is registered in the manifest.

    Args:
        asp_id:   The ASP identifier string, e.g. "hashfile" or "attest".
                  Must match an entry in the manifest's ASPS list.
        asp_args: Optional JSON object of arguments to pass to the ASP.
                  The structure is ASP-specific. Defaults to {}.

    Returns:
        Copland term JSON string.
    """
    return json.dumps(cvm.term_custom_asp(asp_id, asp_args))


@mcp.tool()
def term_att(place: str, sub_term: str) -> str:
    """
    Build a remote attestation Copland term.

    Wraps a sub-term to be executed at a remote place.

    Args:
        place:    Remote place identifier, e.g. "P1". Must have an entry in
                  the request's Plc_Mapping.
        sub_term: Copland term JSON string to execute at the remote place.

    Returns:
        Copland term JSON string.
    """
    try:
        sub_dict = json.loads(sub_term)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid sub_term JSON: {e}"})
    return json.dumps(cvm.term_att(place, sub_dict))


@mcp.tool()
def term_lseq(t1: str, t2: str) -> str:
    """
    Build a linear sequence Copland term (t1 then t2).

    Evidence flows from t1 into t2.

    Args:
        t1: First Copland term JSON string.
        t2: Second Copland term JSON string.

    Returns:
        Copland term JSON string.
    """
    try:
        d1 = json.loads(t1)
        d2 = json.loads(t2)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid term JSON: {e}"})
    return json.dumps(cvm.term_lseq(d1, d2))


@mcp.tool()
def term_bseq(split: str, t1: str, t2: str) -> str:
    """
    Build a branching sequence Copland term.

    Evidence is split, each branch processed independently, then merged.

    Args:
        split: Evidence split strategy — one of:
               "left_path"  — send only left branch to both terms
               "right_path" — send only right branch to both terms
               "both_paths" — send both branches
        t1: First branch Copland term JSON string.
        t2: Second branch Copland term JSON string.

    Returns:
        Copland term JSON string.
    """
    valid_splits = {"left_path", "right_path", "both_paths"}
    if split not in valid_splits:
        return json.dumps({"error": f"split must be one of {sorted(valid_splits)}"})
    try:
        d1 = json.loads(t1)
        d2 = json.loads(t2)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid term JSON: {e}"})
    return json.dumps(cvm.term_bseq(split, d1, d2))


@mcp.tool()
def term_bpar(split: str, t1: str, t2: str) -> str:
    """
    Build a branching parallel Copland term.

    Like bseq but t2 executes in a parallel thread.

    Args:
        split: Evidence split strategy — one of:
               "left_path", "right_path", "both_paths"
        t1: First branch Copland term JSON string.
        t2: Second branch Copland term JSON string (runs in parallel).

    Returns:
        Copland term JSON string.
    """
    valid_splits = {"left_path", "right_path", "both_paths"}
    if split not in valid_splits:
        return json.dumps({"error": f"split must be one of {sorted(valid_splits)}"})
    try:
        d1 = json.loads(t1)
        d2 = json.loads(t2)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid term JSON: {e}"})
    return json.dumps(cvm.term_bpar(split, d1, d2))


# ---------------------------------------------------------------------------
# ASP discovery tool
# ---------------------------------------------------------------------------

@mcp.tool()
def list_available_asps(asp_bin: str = ASP_BIN_DEFAULT) -> str:
    """
    List the ASP binaries available in an asp_bin directory.

    Use this before building a manifest to see which ASP IDs are usable.
    The returned names are the exact strings to put in the manifest ASPS list.

    Args:
        asp_bin: Directory to inspect. Defaults to the asp-libs release build.

    Returns:
        JSON string with {"asp_bin": "<path>", "asps": ["name", ...]} on
        success, or {"error": "<message>"} if the directory is not found.
    """
    d = Path(asp_bin)
    if not d.is_dir():
        return json.dumps({"error": f"Directory not found: {asp_bin}"})
    asps = sorted(
        p.name for p in d.iterdir()
        if p.is_file() and os.access(p, os.X_OK)
    )
    return json.dumps({"asp_bin": str(d.resolve()), "asps": asps}, indent=2)


# ---------------------------------------------------------------------------
# Protocol registry tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_protocols() -> str:
    """
    List all named protocols in the CVM protocol registry.

    Returns:
        JSON string with a list of protocol objects, each containing:
        id, name, description, and copland (the Copland term expression).
    """
    from protocols import REGISTRY
    return json.dumps([
        {'id': p['id'], 'name': p['name'],
         'description': p['description'], 'copland': p['copland']}
        for p in REGISTRY.values()
    ], indent=2)


@mcp.tool()
def run_protocol(
    protocol_id: str,
    push_to_dashboard: bool = True,
) -> str:
    """
    Run a named protocol from the registry and return appraisal results.

    Builds the manifest and request automatically from the registry, runs the
    CVM attestation, parses the evidence tree into human-readable appraisal
    results, and optionally pushes the results to the live dashboard.

    Args:
        protocol_id:        ID of the protocol to run (use list_protocols to see options).
        push_to_dashboard:  If True (default), POST results to the dashboard at
                            http://localhost:5050/api/push so the UI updates live.

    Returns:
        JSON string with:
        {
          "protocol_id":  str,
          "cvm_success":  bool,
          "all_pass":     bool,
          "pass_count":   int,
          "fail_count":   int,
          "results": [
            {"appr": str, "target": str, "filepath": str, "verdict": "PASS"|"FAIL", "msg": str},
            ...
          ],
          "error":        str | null,
          "timestamp":    str,
          "dashboard_pushed": bool
        }
    """
    from protocols import REGISTRY
    import base64, datetime

    if protocol_id not in REGISTRY:
        ids = list(REGISTRY.keys())
        return json.dumps({"error": f"Unknown protocol '{protocol_id}'. Available: {ids}"})

    proto = REGISTRY[protocol_id]
    manifest, req = proto['build']()

    raw = run_attestation(manifest, req)
    response = json.loads(raw) if isinstance(raw, str) else raw

    cvm_success = response.get('SUCCESS', False)
    error = None
    results = []

    if cvm_success:
        try:
            raw_ev = response['PAYLOAD'][0]['RawEv']
            et     = response['PAYLOAD'][1]

            def _decode(b):
                try:    s = base64.b64decode(b).decode()
                except: s = b
                return ('PASS', '') if s == '' else ('FAIL', s.strip("'"))

            def _walk(node, idx):
                out = []
                if not node: return out
                ctor = node.get('EvidenceT_CONSTRUCTOR', '')
                body = node.get('EvidenceT_BODY', [])
                if ctor == 'mt_evt': return out
                if ctor == 'split_evt':
                    for child in body: out += _walk(child, idx)
                elif ctor in ('left_evt', 'right_evt'):
                    out += _walk(body, idx)
                elif ctor == 'asp_evt':
                    place, params, sub = body
                    asp_id   = params['ASP_ID']
                    asp_args = params.get('ASP_ARGS', {})
                    if asp_id.endswith('_appr'):
                        v, msg = _decode(raw_ev[idx[0]] if idx[0] < len(raw_ev) else '')
                        idx[0] += 1
                        target = asp_id[:-5]
                        fp = asp_args.get('filepath') or asp_args.get('filepath_golden', '')
                        fp = fp.split('/')[-1] if fp else ''
                        out.append({'appr': asp_id, 'target': target,
                                    'filepath': fp, 'verdict': v, 'msg': msg})
                    out += _walk(sub, idx)
                return out

            results = _walk(et, [0])
        except Exception as e:
            error = str(e)
    else:
        error = str(response.get('PAYLOAD', 'CVM execution failed'))

    data = {
        'protocol_id': protocol_id,
        'cvm_success': cvm_success,
        'results':     results,
        'all_pass':    cvm_success and all(r['verdict'] == 'PASS' for r in results),
        'pass_count':  sum(1 for r in results if r['verdict'] == 'PASS'),
        'fail_count':  sum(1 for r in results if r['verdict'] != 'PASS'),
        'error':       error,
        'timestamp':   datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'dashboard_pushed': False,
    }

    if push_to_dashboard:
        try:
            payload = json.dumps(data).encode()
            req_obj = urllib.request.Request(
                f"{DASHBOARD_URL}/api/push",
                data=payload,
                headers={'Content-Type': 'application/json'},
                method='POST',
            )
            urllib.request.urlopen(req_obj, timeout=3)
            data['dashboard_pushed'] = True
        except Exception:
            pass  # dashboard not running — results still returned

    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Schema reference tool
# ---------------------------------------------------------------------------

@mcp.tool()
def get_schema_reference() -> str:
    """
    Return a reference describing the CVM manifest and request JSON schemas.

    Use this to understand the structure of inputs before building them,
    or to verify that a manually constructed JSON is correct.

    Returns:
        A JSON string containing annotated schema examples for the manifest,
        RUN request, Copland terms, and response format.
    """
    reference = {
        "manifest": {
            "description": "Describes available ASPs and their locations.",
            "fields": {
                "ASPS": "Array of ASP ID strings available at this place.",
                "ASP_FS_MAP": "Object mapping ASP ID -> absolute filesystem path.",
                "POLICY": "Array of [place, asp_id] pairs (access policy). May be empty.",
            },
            "example": {
                "ASPS": ["hashfile", "sig", "attest"],
                "ASP_FS_MAP": {"hashfile": "/usr/local/bin/asp_hashfile"},
                "POLICY": [["P0", "hashfile"], ["P0", "sig"]],
            },
        },
        "run_request": {
            "description": "Drives a CVM attestation execution.",
            "fields": {
                "TYPE": "Always 'REQUEST'.",
                "ACTION": "Always 'RUN' for attestation execution.",
                "ATTESTATION_SESSION": {
                    "Session_Plc": "Local place identifier string, e.g. 'P0'.",
                    "Plc_Mapping": "Object: place -> 'ip:port' for remote places.",
                    "PubKey_Mapping": "Object: place -> public key string.",
                    "Session_Context": "Object: {ASP_Types: {}, ASP_Comps: {}}.",
                },
                "REQ_PLC": "Requesting place identifier.",
                "TERM": "Copland term object (see term schema below).",
                "EVIDENCE": "Array: [{RawEv: []}, {EvidenceT_CONSTRUCTOR: 'mt_evt'}] for empty.",
            },
        },
        "term_constructors": {
            "NULL": {"TERM_CONSTRUCTOR": "asp", "TERM_BODY": {"ASP_CONSTRUCTOR": "NULL"}},
            "SIG":  {"TERM_CONSTRUCTOR": "asp", "TERM_BODY": {"ASP_CONSTRUCTOR": "SIG"}},
            "HSH":  {"TERM_CONSTRUCTOR": "asp", "TERM_BODY": {"ASP_CONSTRUCTOR": "HSH"}},
            "ASPC": {
                "TERM_CONSTRUCTOR": "asp",
                "TERM_BODY": {
                    "ASP_CONSTRUCTOR": "ASPC",
                    "ASP_BODY": {"ASP_ID": "<id>", "ASP_ARGS": {}},
                },
            },
            "att":  {"TERM_CONSTRUCTOR": "att",  "TERM_BODY": ["<place>", "<sub_term>"]},
            "lseq": {"TERM_CONSTRUCTOR": "lseq", "TERM_BODY": ["<term1>", "<term2>"]},
            "bseq": {"TERM_CONSTRUCTOR": "bseq", "TERM_BODY": ["<left|right|both_paths>", "<t1>", "<t2>"]},
            "bpar": {"TERM_CONSTRUCTOR": "bpar", "TERM_BODY": ["<left|right|both_paths>", "<t1>", "<t2>"]},
        },
        "response": {
            "success": {"TYPE": "RESPONSE", "ACTION": "RUN", "SUCCESS": True, "PAYLOAD": "<evidence>"},
            "failure": {"SUCCESS": False, "PAYLOAD": "<error message string>"},
        },
    }
    return json.dumps(reference, indent=2)


# ---------------------------------------------------------------------------
# Appraisal summary tools
# ---------------------------------------------------------------------------

# Human-readable labels for well-known ASP IDs
_ASP_LABELS = {
    "hashfile":      "File hash",
    "hashfile_appr": "File integrity",
    "hsh":           "Evidence hash",
    "sig":           "RSA signature",
    "sig_appr":      "Signature verification",
    "sig_appr_bad":  "Signature verification (bad key)",
    "hashevidence":  "Evidence hash",
    "readfile":      "File read",
    "readfile_appr": "File read integrity",
    "uptime":        "System uptime",
}


def _describe_target(target_asp: str, target_args: dict, appr_args: dict) -> str:
    """Return a short human-readable description of the measurement target."""
    label = _ASP_LABELS.get(target_asp, target_asp)
    # Pull the most meaningful identifier from the args
    filepath = (
        target_args.get("filepath")
        or appr_args.get("filepath")
        or target_args.get("filepath_golden")
        or appr_args.get("filepath_golden")
        or ""
    )
    if filepath:
        return f"{label}: {Path(filepath).name}"
    return label


def _find_target_asp_id(et_node: dict, prefer_right: bool = False) -> str:
    """
    Recursively descend an EvidenceT subtree and return the ASP_ID of the
    measurement target.  prefer_right is set when descending into right_evt
    so that bseq right-branch targets are correctly identified.
    """
    if et_node is None:
        return "unknown"
    ctor = et_node.get("EvidenceT_CONSTRUCTOR", "")
    body = et_node.get("EvidenceT_BODY", [])

    if ctor == "asp_evt":
        _, params, _ = body
        return params.get("ASP_ID", "unknown")
    elif ctor == "split_evt":
        # Choose left or right child based on direction hint
        child = body[1] if prefer_right else body[0]
        return _find_target_asp_id(child, prefer_right=False)
    elif ctor == "left_evt":
        inner = body if isinstance(body, dict) else (body[0] if body else None)
        return _find_target_asp_id(inner, prefer_right=False)
    elif ctor == "right_evt":
        inner = body if isinstance(body, dict) else (body[0] if body else None)
        return _find_target_asp_id(inner, prefer_right=True)
    return "unknown"


def _parse_appraisal_tree(et: dict, raw_ev: list[str]) -> list[dict]:
    """
    Walk an EvidenceT tree produced by an APPR invocation and correlate
    each appraisal-ASP node with its verdict from the flat RawEv list.

    The RawEv list is consumed left-to-right in the same DFS order that
    invoke_APPR' builds the evidence tree.

    Returns a list of result dicts:
        appr_asp    — ID of the appraisal ASP (e.g. "hashfile_appr")
        target_asp  — ID of the measurement ASP being appraised
        target_args — args from the measurement ASP params
        appr_args   — args forwarded to the appraisal ASP (same as target_args)
        verdict     — "PASS" or "FAIL: <reason>"
        description — short human-readable target label
    """
    results: list[dict] = []
    idx = [0]  # mutable cursor shared across recursion

    def _verdict(raw: str) -> str:
        """Decode one RawEv entry to a verdict string."""
        try:
            decoded = base64.b64decode(raw).decode()
        except Exception:
            decoded = raw  # already a plain string (e.g. error message)
        return "PASS" if decoded == "" else f"FAIL: {decoded}"

    def _walk(et_node: dict) -> None:
        if et_node is None:
            return
        ctor = et_node.get("EvidenceT_CONSTRUCTOR", "")
        body = et_node.get("EvidenceT_BODY", [])

        if ctor == "mt_evt":
            return

        elif ctor == "split_evt":
            # Two branches — recurse in order; ordering mirrors invoke_APPR'
            _walk(body[0])
            _walk(body[1])

        elif ctor == "asp_evt":
            place, asp_params, sub_et = body
            asp_id   = asp_params.get("ASP_ID", "")
            asp_args = asp_params.get("ASP_ARGS", {})

            # Appraisal-ASP nodes contain "appr" in their ID (e.g. hashfile_appr,
            # sig_appr, sig_appr_bad) or are known checkers like check_nonce.
            is_appraiser = "appr" in asp_id or asp_id in ("check_nonce",)

            if is_appraiser:
                # Consume one verdict from RawEv
                raw = raw_ev[idx[0]] if idx[0] < len(raw_ev) else ""
                idx[0] += 1

                # Find the measurement target by descending into sub_et.
                # sub_et may be a direct asp_evt (lseq protocols) or wrapped in
                # left_evt / right_evt / split_evt (bseq protocols).
                # Use appr_args for filepath — they are the measurement args
                # forwarded by invoke_APPR' and are always per-instance correct.
                target_asp = _find_target_asp_id(sub_et)

                results.append({
                    "appr_asp":    asp_id,
                    "target_asp":  target_asp,
                    "target_args": asp_args,   # appr_args == measurement args
                    "appr_args":   asp_args,
                    "verdict":     _verdict(raw),
                    "description": _describe_target(target_asp, asp_args, asp_args),
                })
                # Do NOT recurse into sub_et — it is original measurement evidence,
                # not further appraisal output.
            else:
                # Not an appraisal node; recurse into its sub-evidence
                _walk(sub_et)

        elif ctor in ("left_evt", "right_evt"):
            inner = body if isinstance(body, dict) else (body[0] if body else None)
            _walk(inner)

    _walk(et)
    return results


@mcp.tool()
def appraisal_summary(response: str) -> str:
    """
    Parse a CVM attestation response and return a human-readable appraisal
    summary for display in a terminal.

    The response must contain an APPR step; measurements without appraisal
    produce an empty summary.

    Args:
        response: CVM response JSON string as returned by run_attestation().

    Returns:
        A formatted text block listing each appraisal target, its verdict
        (PASS / FAIL), and a final tally. Returns an error string if the
        response JSON is malformed or does not contain appraisal evidence.
    """
    try:
        resp = json.loads(response)
    except json.JSONDecodeError as e:
        return f"ERROR: Invalid JSON — {e}"

    if not resp.get("SUCCESS"):
        payload = resp.get("PAYLOAD", "(no payload)")
        return f"ATTESTATION FAILED — no appraisal results available\nPayload: {payload}"

    payload = resp.get("PAYLOAD", [])
    if not isinstance(payload, list) or len(payload) < 2:
        return "No appraisal evidence found in response (PAYLOAD has fewer than 2 elements)."

    raw_ev = payload[0].get("RawEv", [])
    et     = payload[1]

    results = _parse_appraisal_tree(et, raw_ev)

    if not results:
        return "No appraisal ASPs found in evidence tree. Was an APPR term used?"

    # ── Format ──────────────────────────────────────────────────────────────
    W = 64
    lines = [
        "=" * W,
        " APPRAISAL SUMMARY",
        "=" * W,
    ]

    pass_count = fail_count = 0
    for r in results:
        verdict = r["verdict"]
        if verdict == "PASS":
            marker = "[PASS]"
            pass_count += 1
        else:
            marker = "[FAIL]"
            fail_count += 1

        desc  = r["description"]
        appr  = r["appr_asp"]
        lines.append(f"  {marker:<8} {desc}")
        lines.append(f"           appraiser : {appr}")
        if verdict != "PASS":
            reason = verdict[len("FAIL: "):]
            lines.append(f"           reason    : {reason}")
        lines.append("")

    lines.append("-" * W)
    overall = "PASS" if fail_count == 0 else "FAIL"
    lines.append(
        f"  Overall: {overall}   "
        f"({pass_count} passed, {fail_count} failed, {len(results)} total)"
    )
    lines.append("=" * W)

    return "\n".join(lines)


@mcp.tool()
def appraisal_dashboard(response: str, title: str = "Attestation Appraisal") -> str:
    """
    Parse a CVM attestation response and return a self-contained HTML
    dashboard with colour-coded pass/fail cards for each appraisal target.

    Save the returned string to a .html file and open it in a browser.

    Args:
        response: CVM response JSON string as returned by run_attestation().
        title:    Page title shown in the dashboard header. Defaults to
                  "Attestation Appraisal".

    Returns:
        A self-contained HTML string (no external dependencies) or an error
        string if the response is malformed.
    """
    try:
        resp = json.loads(response)
    except json.JSONDecodeError as e:
        return f"ERROR: Invalid JSON — {e}"

    payload = resp.get("PAYLOAD", [])
    success = resp.get("SUCCESS", False)

    if not success or not isinstance(payload, list) or len(payload) < 2:
        msg = payload if isinstance(payload, str) else "No appraisal evidence found."
        return _dashboard_error_html(title, str(msg))

    raw_ev  = payload[0].get("RawEv", [])
    et      = payload[1]
    results = _parse_appraisal_tree(et, raw_ev)

    if not results:
        return _dashboard_error_html(title, "No appraisal ASPs found in evidence tree.")

    pass_count = sum(1 for r in results if r["verdict"] == "PASS")
    fail_count = len(results) - pass_count
    overall    = "PASS" if fail_count == 0 else "FAIL"

    cards_html = ""
    for r in results:
        is_pass = r["verdict"] == "PASS"
        cls     = "pass" if is_pass else "fail"
        badge   = "PASS" if is_pass else "FAIL"
        reason  = "" if is_pass else (
            f'<div class="reason">{r["verdict"][len("FAIL: "):]}</div>'
        )
        # Show relevant args (filepath preferred)
        args = r["target_args"] or r["appr_args"]
        filepath = (
            args.get("filepath") or args.get("filepath_golden") or ""
        )
        detail = f'<div class="filepath">{filepath}</div>' if filepath else ""
        cards_html += f"""
        <div class="card {cls}">
          <div class="badge">{badge}</div>
          <div class="card-body">
            <div class="desc">{r["description"]}</div>
            {detail}
            <div class="appr-asp">appraiser: {r["appr_asp"]}</div>
            {reason}
          </div>
        </div>"""

    overall_cls = "overall-pass" if overall == "PASS" else "overall-fail"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; padding: 2rem; }}
  h1 {{ font-size: 1.6rem; font-weight: 700; margin-bottom: 0.25rem; }}
  .subtitle {{ color: #94a3b8; font-size: 0.9rem; margin-bottom: 2rem; }}
  .overall {{ display: inline-block; padding: 0.5rem 1.5rem; border-radius: 999px; font-weight: 700; font-size: 1rem; margin-bottom: 2rem; }}
  .overall-pass {{ background: #166534; color: #bbf7d0; }}
  .overall-fail {{ background: #7f1d1d; color: #fecaca; }}
  .tally {{ color: #94a3b8; font-size: 0.85rem; margin-left: 1rem; vertical-align: middle; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1rem; }}
  .card {{ border-radius: 0.75rem; padding: 1.25rem; display: flex; align-items: flex-start; gap: 1rem; }}
  .card.pass {{ background: #052e16; border: 1px solid #166534; }}
  .card.fail {{ background: #2d0a0a; border: 1px solid #7f1d1d; }}
  .badge {{ font-size: 0.7rem; font-weight: 800; padding: 0.25rem 0.6rem; border-radius: 0.4rem; white-space: nowrap; flex-shrink: 0; }}
  .card.pass .badge {{ background: #166534; color: #bbf7d0; }}
  .card.fail .badge {{ background: #7f1d1d; color: #fecaca; }}
  .card-body {{ flex: 1; min-width: 0; }}
  .desc {{ font-weight: 600; font-size: 0.95rem; margin-bottom: 0.25rem; }}
  .filepath {{ font-family: monospace; font-size: 0.78rem; color: #94a3b8; word-break: break-all; margin-bottom: 0.25rem; }}
  .appr-asp {{ font-size: 0.75rem; color: #64748b; }}
  .reason {{ font-size: 0.8rem; color: #fca5a5; margin-top: 0.4rem; font-style: italic; }}
  .error {{ color: #fca5a5; padding: 2rem; background: #2d0a0a; border-radius: 0.75rem; }}
</style>
</head>
<body>
  <h1>{title}</h1>
  <div class="subtitle">CVM Attestation Appraisal Results</div>
  <div>
    <span class="overall {overall_cls}">{overall}</span>
    <span class="tally">{pass_count} passed · {fail_count} failed · {len(results)} total</span>
  </div>
  <div class="grid">{cards_html}
  </div>
</body>
</html>"""

    return html


def _dashboard_error_html(title: str, message: str) -> str:
    return (
        f'<!DOCTYPE html><html><head><title>{title}</title></head>'
        f'<body style="font-family:sans-serif;background:#0f172a;color:#fca5a5;padding:2rem">'
        f'<h2>{title}</h2><pre>{message}</pre></body></html>'
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
