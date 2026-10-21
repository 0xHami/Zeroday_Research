"""
railslab.py — shared helpers for the Rails 8.2.0.alpha CVE-hunter lab exploits.

Every finding's automation.py imports this module. It centralises the three
things that are awkward about driving *this* lab, so each exploit can stay
focused on its own vulnerability:

  1. Colored, file-safe logging (`log`) — ANSI only on a TTY, honours NO_COLOR,
     so a captured run.log is free of escape codes (CLAUDE.md evidence rule).
  2. The HTTP state-changing recipe for this lab. The app runs the documented
     secure baseline (`assume_ssl` + `force_ssl`), so Rails issues `Secure`
     cookies and enforces the CSRF token **and** the Sec-Fetch-Site check.
     Over plain HTTP an HTTP client will NOT resend a `Secure` cookie, so we
     extract the `_harness_session` value from Set-Cookie and send it back as an
     explicit `Cookie:` header, alongside a reused `authenticity_token` and
     `Sec-Fetch-Site: same-origin`. (`grab_token`, `post_form`, `post_json`.)
  3. Running real framework code (the target is a *library*). `run_ruby` pipes a
     Ruby script to `bin/rails runner -` over stdin inside the app container —
     this exercises the actual source under targets/rails/ (mounted at
     /rails-src) with no source edits, which is exactly what the library harness
     is for. stdin piping avoids shell/heredoc quoting entirely.

Config is read from the environment with defaults matching the manifest
(claude_audit/rails/rails_summary.md).
"""
import os
import re
import subprocess
import sys

# ---- configuration (defaults match the manifest ## Runtime section) --------
BASE_URL      = os.environ.get("BASE_URL", "http://localhost:27966")
APP_CONTAINER = os.environ.get("APP_CONTAINER", "cvehunterlab_rails_app")
ADMIN_EMAIL   = os.environ.get("ADMIN_EMAIL", "admin@example.com")
ADMIN_PASS    = os.environ.get("ADMIN_PASS", "Passw0rd!cvehunter")

# ---- colored, file-safe logging -------------------------------------------
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag: str, msg: str) -> None:
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}", flush=True)
    else:
        print(f"[{tag}] {msg}", flush=True)


def banner(vuln_id: str, title: str, code_path: str) -> None:
    line = "=" * 72
    print(line, flush=True)
    print(f"{vuln_id}: {title}", flush=True)
    print(f"target : {BASE_URL}", flush=True)
    print(line, flush=True)
    log("INFO", f"exercising vulnerable code path: {code_path}")


def verdict(vuln_id: str, status: str, msg: str) -> None:
    """Final one-line verdict; colored green/red/yellow for CONFIRMED/FAILED/else."""
    color = {"CONFIRMED": "32", "FAILED": "31"}.get(status, "33")
    text = f"==> {vuln_id}: {status} — {msg}"
    if _USE_COLOR:
        print(f"\033[1;{color}m{text}\033[0m", flush=True)
    else:
        print(text, flush=True)


# ---- HTTP helpers ----------------------------------------------------------
import requests  # noqa: E402  (imported after config so a missing dep errors clearly)

_CSRF_META = re.compile(r'name="csrf-token"\s+content="([^"]*)"')
_AUTH_FIELD = re.compile(r'name="authenticity_token"[^>]*value="([^"]*)"')
_COOKIE = re.compile(r'(_harness_session=[^;]*)')


def grab_token(path: str = "/"):
    """GET `path`; return (cookie_header_value, csrf_token).

    The csrf-token meta (and the form authenticity_token) are both valid
    authenticity tokens for the issued session and are reusable within it.
    """
    r = requests.get(BASE_URL + path, timeout=15, allow_redirects=False)
    sc = r.headers.get("set-cookie", "")
    m = _COOKIE.search(sc)
    cookie = m.group(1) if m else ""
    tok = ""
    mt = _CSRF_META.search(r.text)
    if mt:
        tok = mt.group(1)
    else:
        ma = _AUTH_FIELD.search(r.text)
        tok = ma.group(1) if ma else ""
    return cookie, tok


def _state_headers(cookie: str, extra=None):
    h = {"Cookie": cookie, "Sec-Fetch-Site": "same-origin"}
    if extra:
        h.update(extra)
    return h


def post_form(path: str, cookie: str, token: str, data: dict, allow_redirects=False):
    """POST an urlencoded form with the lab's CSRF recipe. Returns the Response."""
    body = dict(data)
    body["authenticity_token"] = token
    return requests.post(
        BASE_URL + path, data=body, headers=_state_headers(cookie),
        timeout=20, allow_redirects=allow_redirects,
    )


def patch_form(path: str, cookie: str, token: str, data: dict, allow_redirects=False):
    body = dict(data)
    body["authenticity_token"] = token
    return requests.patch(
        BASE_URL + path, data=body, headers=_state_headers(cookie),
        timeout=20, allow_redirects=allow_redirects,
    )


def post_json(path: str, cookie: str, token: str, payload: str):
    """POST a raw JSON body with the CSRF token in the X-CSRF-Token header."""
    return requests.post(
        BASE_URL + path, data=payload,
        headers=_state_headers(cookie, {"X-CSRF-Token": token,
                                        "Content-Type": "application/json"}),
        timeout=20, allow_redirects=False,
    )


def require_up():
    """Pre-flight: the target must answer /up with 200."""
    try:
        r = requests.get(BASE_URL + "/up", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


# ---- run real framework code inside the container --------------------------
def run_ruby(code: str, timeout: int = 180):
    """Pipe `code` to `bin/rails runner -` in the app container.

    Returns (returncode, stdout, stderr). This drives the real source under
    /rails-src (== targets/rails/) with no modification — the library harness.
    """
    proc = subprocess.run(
        ["docker", "exec", "-i", APP_CONTAINER, "bash", "-lc",
         "cd /harness && RAILS_ENV=production bin/rails runner -"],
        input=code.encode(), capture_output=True, timeout=timeout,
    )
    return proc.returncode, proc.stdout.decode(errors="replace"), proc.stderr.decode(errors="replace")


def ruby_markers(stdout: str, prefix: str):
    """Extract lines beginning with `prefix` (our marker convention) from runner output."""
    return [ln for ln in stdout.splitlines() if ln.startswith(prefix)]
