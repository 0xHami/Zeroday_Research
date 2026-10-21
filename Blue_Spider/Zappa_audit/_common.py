"""Shared helpers for Zappa stage-10 dynamic-validation exploits.

This is NOT an exploit — it is imported by each finding's ``automation.py`` to
avoid duplicating boilerplate 30 times. It provides four things:

  * ``log`` / ``banner`` / ``verdict`` — status tags that are ANSI-coloured for a
    human at a terminal but plain when captured to a file (gated on isatty()
    and NO_COLOR), so ``run.log`` stays free of escape codes.
  * ``raw_request`` — send a byte-exact HTTP/1.1 request over a socket. Used
    where precise control matters: duplicate ``Set-Cookie`` counting, ``%0a`` in
    the path, arbitrary ``Host``/forwarding headers (Surface A).
  * ``raw_event`` — POST a raw Lambda event JSON to the harness
    ``/_sim/raw-event`` endpoint. This models a *direct Lambda invocation*
    (an AWS-authenticated caller), i.e. Surface B — NOT internet-facing.
  * ``lab_python`` / ``lab_exec`` / ``ensure_lab_dep`` — run Zappa's real
    deploy-time / parsing code (cli.py, core.py, wsgi.py, handler.py helpers)
    inside the running lab container, in a FRESH python process each call
    (isolated from the long-running gateway). PYTHONPATH=/app there resolves
    ``import zappa`` to the exact bind-mounted target checkout.

Config comes from the environment, defaulting to the manifest's Runtime block:
  BASE_URL       default http://localhost:22571   (the API-Gateway simulator)
  LAB_CONTAINER  default cvehunterlab_Zappa_app    (the running lab container)
"""
import os
import socket
import subprocess
import sys

BASE_URL = os.environ.get("BASE_URL", "http://localhost:22571").rstrip("/")
LAB_CONTAINER = os.environ.get("LAB_CONTAINER", "cvehunterlab_Zappa_app")


def _base_host_port():
    hostport = BASE_URL.split("://", 1)[-1]
    host, _, port = hostport.partition(":")
    return host or "127.0.0.1", int(port or "80")


BASE_HOST, BASE_PORT = _base_host_port()

# --- coloured, report-grade output ------------------------------------------
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag, msg):
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}", flush=True)
    else:
        print(f"[{tag}] {msg}", flush=True)


def banner(vuln_id, title, code_path=""):
    line = "=" * 74
    print(line, flush=True)
    print(f"{vuln_id}: {title}", flush=True)
    print(f"target : {BASE_URL}", flush=True)
    if code_path:
        print(f"[INFO] exercising: {code_path}", flush=True)
    print(line, flush=True)


def verdict(status, msg):
    """Print the final one-line verdict (green CONFIRMED / red FAILED / yellow NEEDS_MANUAL)."""
    color = {"CONFIRMED": "32", "FAILED": "31", "NEEDS_MANUAL": "33"}.get(status, "0")
    text = f"==> {msg}"
    if _USE_COLOR:
        print(f"\033[1;{color}m{text}\033[0m", flush=True)
    else:
        print(text, flush=True)


# --- Surface A: byte-exact HTTP over a socket -------------------------------
def raw_request(request_bytes, host=None, port=None, timeout=10):
    """Send an exact HTTP/1.1 request and return the raw response bytes.

    ``request_bytes`` must be the full request incl. request-line, headers and
    the trailing blank line. Use ``Connection: close`` so the recv loop ends.
    """
    host = host or BASE_HOST
    port = port or BASE_PORT
    if isinstance(request_bytes, str):
        request_bytes = request_bytes.encode("latin-1")
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(request_bytes)
        chunks = []
        while True:
            try:
                b = s.recv(65536)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks)
    finally:
        s.close()


def build_request(method, path, headers, body=b"", host_header=None):
    """Assemble a raw HTTP/1.1 request. ``path`` is written verbatim (so %0a etc. survive)."""
    if isinstance(body, str):
        body = body.encode("utf-8")
    host_header = host_header or f"{BASE_HOST}:{BASE_PORT}"
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host_header}"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + body


def split_response(raw):
    """Return (status_line, header_lines[list], body_bytes) from raw response bytes."""
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = lines[0].decode("latin-1", "replace") if lines else ""
    headers = [ln.decode("latin-1", "replace") for ln in lines[1:]]
    return status, headers, body


# --- Surface B: raw Lambda event via the harness ----------------------------
def raw_event(event, timeout=60):
    """POST a raw Lambda event to /_sim/raw-event (direct-invoke / Surface B).

    Returns the parsed harness JSON: {"result": <handler return value>}.
    Uses stdlib urllib so the only third-party dep stays 'requests'-free-capable.
    """
    import json
    import urllib.request

    data = json.dumps(event).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/_sim/raw-event", data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# --- run Zappa's REAL code inside the lab container -------------------------
def lab_python(script, args=None, timeout=180):
    """Run `script` (Python source) in a fresh process inside the lab container.

    A new `python` process is spawned per call, so it never disturbs the
    long-running gateway process; PYTHONPATH=/app makes `import zappa` resolve
    to the exact bind-mounted target checkout. Returns CompletedProcess.
    """
    cmd = ["docker", "exec", "-i", "-e", "PYTHONPATH=/app", LAB_CONTAINER, "python", "-"]
    if args:
        cmd += [str(a) for a in args]
    return subprocess.run(cmd, input=script.encode("utf-8"), capture_output=True, timeout=timeout)


def lab_exec(argv, timeout=120):
    """Run an arbitrary command inside the lab container (e.g. cat/ls/stat)."""
    return subprocess.run(["docker", "exec", LAB_CONTAINER, *argv], capture_output=True, timeout=timeout)


def ensure_lab_dep(module, pip_name=None):
    """Idempotently ensure `module` is importable in the lab container.

    cli.py/core.py need `setuptools`, which the slim base image omits; pip runs
    INSIDE the container (hook-allowed) and the lab is disposable.
    """
    pip_name = pip_name or module
    check = subprocess.run(
        ["docker", "exec", LAB_CONTAINER, "python", "-c", f"import {module}"], capture_output=True
    )
    if check.returncode != 0:
        log("SETUP", f"installing '{pip_name}' into the lab container (in-container pip)")
        subprocess.run(["docker", "exec", LAB_CONTAINER, "pip", "install", "-q", pip_name], check=True, timeout=300)


def lab_up():
    """Best-effort check that the lab container is running; returns bool."""
    r = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", LAB_CONTAINER], capture_output=True, text=True
    )
    return r.returncode == 0 and r.stdout.strip() == "true"
