"""
place_manager.py — Lifecycle manager for am_place.py subprocesses.

Maps (proto_id, place_id) pairs to running am_place.py processes.
Thread-safe; probes run concurrently so multi-place health checks are fast.
"""
import os
import sys
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

import zmq

_lock      = threading.Lock()
_processes = {}   # { (proto_id, place_id): {'process': Popen, 'pid': int, 'config': dict} }

_AM_PLACE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'am_place.py')


# ---------------------------------------------------------------------------
# Process lifecycle
# ---------------------------------------------------------------------------

def start_place(proto_id: str, place_id: str, config: dict) -> dict:
    """
    Spawn am_place.py for (proto_id, place_id).

    Returns {'started': bool, 'already_running': bool, 'pid': int}.
    Raises FileNotFoundError if manifest or asp_bin path does not exist.
    """
    manifest = config.get('manifest', '')
    asp_bin  = config.get('asp_bin', '')
    port     = int(config.get('port', 0))

    if not manifest or not os.path.isfile(manifest):
        raise FileNotFoundError(f'Manifest not found: {manifest!r}')
    if not asp_bin or not os.path.isdir(asp_bin):
        raise FileNotFoundError(f'asp_bin directory not found: {asp_bin!r}')

    key = (proto_id, place_id)
    with _lock:
        existing = _processes.get(key)
        if existing:
            proc = existing['process']
            if proc.poll() is None:   # still running
                return {'started': False, 'already_running': True, 'pid': proc.pid}
            del _processes[key]       # process died — clean up stale entry

        cmd = [
            sys.executable, _AM_PLACE,
            '--port',     str(port),
            '--manifest', manifest,
            '--asp_bin',  asp_bin,
            '--place',    place_id,
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _processes[key] = {'process': proc, 'pid': proc.pid, 'config': dict(config)}
        return {'started': True, 'already_running': False, 'pid': proc.pid}


def stop_place(proto_id: str, place_id: str) -> dict:
    """
    Terminate the am_place.py subprocess for (proto_id, place_id).
    Idempotent — returns was_running=False if not found.
    """
    key = (proto_id, place_id)
    with _lock:
        entry = _processes.pop(key, None)
    if not entry:
        return {'stopped': False, 'was_running': False}
    proc = entry['process']
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    return {'stopped': True, 'was_running': True}


def stop_all_places(proto_id: str) -> list:
    """Stop all running am_place.py subprocesses for proto_id."""
    with _lock:
        place_ids = [pid for (p, pid) in list(_processes.keys()) if p == proto_id]
    stopped = []
    for place_id in place_ids:
        result = stop_place(proto_id, place_id)
        if result['was_running']:
            stopped.append(place_id)
    return stopped


# ---------------------------------------------------------------------------
# Health checking
# ---------------------------------------------------------------------------

def is_place_reachable(host: str, port: int, timeout_ms: int = 1000) -> bool:
    """
    Probe the ZMQ REP socket at tcp://host:port.

    Sends a minimal JSON probe; any response (including an error PRResp)
    confirms the place is reachable.  Creates and destroys its own ZMQ
    context so the caller's environment is not polluted.
    """
    ctx = zmq.Context()
    sock = ctx.socket(zmq.REQ)
    sock.setsockopt(zmq.SNDTIMEO, timeout_ms)
    sock.setsockopt(zmq.RCVTIMEO, timeout_ms)
    sock.setsockopt(zmq.LINGER, 0)
    try:
        sock.connect(f'tcp://{host}:{port}')
        sock.send_string('{"ACTION":"ping"}')
        sock.recv_string()
        return True
    except zmq.error.ZMQError:
        return False
    finally:
        sock.close()
        ctx.term()


def _probe_one(proto_id: str, place_id: str, config: dict) -> tuple:
    """Helper called in a thread pool — returns (place_id, status_dict)."""
    host = config.get('host', 'localhost')
    port = int(config.get('port', 0))
    key  = (proto_id, place_id)
    with _lock:
        entry = _processes.get(key)
    pid     = entry['process'].pid if entry else None
    running = bool(entry and entry['process'].poll() is None)
    reachable = is_place_reachable(host, port)
    return place_id, {
        'reachable': reachable,
        'pid':       pid,
        'running':   running,
        'host':      host,
        'port':      port,
        'manifest':  config.get('manifest', ''),
        'asp_bin':   config.get('asp_bin', ''),
    }


def get_place_status(proto_id: str, places_config: dict) -> dict:
    """
    Return liveness dict for all declared places.  Probes run concurrently.

    places_config: the 'places' dict from the protocol registry entry,
                   e.g. {'P1': {'host': 'localhost', 'port': 8081, ...}}.
    """
    if not places_config:
        return {}
    n = len(places_config)
    with ThreadPoolExecutor(max_workers=n) as ex:
        futures = {
            ex.submit(_probe_one, proto_id, pid, cfg): pid
            for pid, cfg in places_config.items()
        }
        results = {}
        for fut, pid_key in futures.items():
            try:
                _, info = fut.result()
                results[pid_key] = info
            except Exception:
                cfg = places_config[pid_key]
                results[pid_key] = {
                    'reachable': False, 'pid': None, 'running': False,
                    'host': cfg.get('host', 'localhost'),
                    'port': int(cfg.get('port', 0)),
                    'manifest': cfg.get('manifest', ''),
                    'asp_bin':  cfg.get('asp_bin', ''),
                }
    return results
