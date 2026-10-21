"""
Shared helpers for the gin (github.com/gin-gonic/gin) stage-10 exploit scripts.

Every finding's ``automation.py`` imports from this module so the exploits share
one colored/plain logger, one banner/verdict format, one HTTP session factory and
a couple of protocol helpers (raw BSON docs, raw HTTP-over-socket). Keeping this
common code in one place means each ``automation.py`` stays focused on the *one*
vulnerability it proves, while every run.log comes out in the same report-grade
format.

Target under test: gin v1.12.0, commit 1bd0ecf2d3e08da37efa270bb7be20c1eddb0d68.
The live surface is the harness in claude_audit/gin/setup/harness (default engine,
:36274) plus, for the conditional/primitive findings, an *extended* harness that
enables the relevant Engine toggle or adds the app pattern a real consumer would
use (:36275-36281).  Both harnesses link the SAME local gin source, so every
exploit exercises gin's own code — the target — not third-party code.
"""
import os
import socket
import sys
import time

# ----------------------------------------------------------------------------
# Colored, report-grade logging.  Color only when attached to a TTY and NO_COLOR
# is unset, so a captured run.log stays free of ANSI escape codes.
# ----------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag: str, msg: str) -> None:
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}", flush=True)
    else:
        print(f"[{tag}] {msg}", flush=True)


def banner(vuln_id: str, title: str, base_url: str, code_path: str) -> None:
    line = "=" * 78
    print(line, flush=True)
    print(f"{vuln_id}: {title}", flush=True)
    print(f"target: {base_url}", flush=True)
    log("INFO", f"exercising gin code path: {code_path}")
    print(line, flush=True)


def verdict(vuln_id: str, status: str, msg: str) -> int:
    """Print the final one-line verdict (colored) and return the process exit code."""
    color = {"CONFIRMED": "32", "FAILED": "31", "NEEDS_MANUAL": "33"}.get(status, "0")
    text = f"==> {vuln_id}: {status} — {msg}"
    if _USE_COLOR:
        print(f"\033[1;{color}m{text}\033[0m", flush=True)
    else:
        print(text, flush=True)
    return 0 if status == "CONFIRMED" else 1


# ----------------------------------------------------------------------------
# HTTP helpers.
# ----------------------------------------------------------------------------
def base_url(default_port: int = 36274) -> str:
    return os.environ.get("BASE_URL", f"http://localhost:{default_port}")


def session(timeout: float = 10.0):
    """A requests.Session that never auto-follows redirects (we assert on Location)
    and carries a browser-like User-Agent."""
    import requests

    s = requests.Session()
    s.max_redirects = 3
    s.headers.update({"User-Agent": "gin-st10/1.0"})
    # Bake a default timeout in and FORCE allow_redirects off: these are security
    # exploits, we always want to inspect the raw Location / status ourselves rather
    # than let requests silently follow a redirect into an external host. (requests'
    # get()/post() helpers pre-set allow_redirects=True, so we override, not setdefault.)
    orig = s.request

    def _req(method, url, **kw):
        kw.setdefault("timeout", timeout)
        kw["allow_redirects"] = kw.get("allow_redirects_override", False)
        kw.pop("allow_redirects_override", None)
        return orig(method, url, **kw)

    s.request = _req  # type: ignore
    return s


def wait_ready(url: str, tries: int = 60, delay: float = 1.0) -> bool:
    """Poll a health URL until it answers or we run out of tries."""
    import requests

    for _ in range(tries):
        try:
            requests.get(url, timeout=3)
            return True
        except Exception:
            time.sleep(delay)
    return False


# ----------------------------------------------------------------------------
# Protocol helpers.
# ----------------------------------------------------------------------------
# The smallest possible valid BSON document: int32 length (5) little-endian,
# then the closing 0x00.  An empty document => the destination struct is left at
# its zero value => any `binding:"required"` constraint MUST fire if validate()
# is called.  gin's binding/bson.go never calls validate(), so it does not.
BSON_EMPTY_DOC = b"\x05\x00\x00\x00\x00"


def raw_http_over_socket(host: str, port: int, raw: bytes, read_bytes: int = 4096,
                         timeout: float = 8.0) -> bytes:
    """Send raw bytes on a TCP socket and read the response. Used where requests
    cannot express the exact wire form (e.g. h2c upgrade, header ordering)."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(raw)
        s.settimeout(timeout)
        chunks = []
        got = 0
        try:
            while got < read_bytes:
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b)
                got += len(b)
        except socket.timeout:
            pass
        return b"".join(chunks)


def hostport(url: str):
    """Split a http://host:port base URL into (host, port)."""
    from urllib.parse import urlparse

    u = urlparse(url)
    return u.hostname or "localhost", u.port or 80


def save(path: str, data) -> None:
    """Write request.http / response.txt style evidence next to the script."""
    mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
    with open(path, mode) as fh:
        fh.write(data)
