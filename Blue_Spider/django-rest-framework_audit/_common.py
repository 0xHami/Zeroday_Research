"""
Shared helpers for django-rest-framework Stage-10 dynamic-validation exploits.

Every per-finding automation.py imports from here so the individual exploits stay
short and consistent. Nothing security-relevant lives here — it is plumbing:
colored logging, the lab's base URL / seeded credentials, a couple of request
helpers, and lab-reset utilities (re-seed / redis-flush / container restart).

The lab is the Stage-00 harness (a minimal Django project that imports the
audited DRF source read-only from /opt/drf-src). Base URL, tokens and creds are
copied from claude_audit/django-rest-framework/django-rest-framework_summary.md.
"""
import os
import subprocess
import sys
import time

import requests

# ---- Lab configuration (from the Stage-00 manifest §Runtime) --------------
BASE_URL = os.environ.get("BASE_URL", "http://localhost:21514").rstrip("/")

# Seeded users + FIXED token keys (stable across restarts — seed_lab.py).
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "Admin!Pass123")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "0000000000adminadminadmintoken0000000001")

ALICE_USER = os.environ.get("ALICE_USER", "alice")
ALICE_PASS = os.environ.get("ALICE_PASS", "Alice!Pass123")
ALICE_TOKEN = os.environ.get("ALICE_TOKEN", "1111111111alicealicealicetoken1111111112")

BOB_USER = os.environ.get("BOB_USER", "bob")
BOB_PASS = os.environ.get("BOB_PASS", "Bob!Pass123")
BOB_TOKEN = os.environ.get("BOB_TOKEN", "2222222222bobbobbobbobbobtoken2222222223")

# Compose invocation used by the reset helpers (namespaced per manifest).
COMPOSE = [
    "docker", "compose",
    "-p", "cvehunterlab_django-rest-framework",
    "-f", os.environ.get(
        "COMPOSE_FILE",
        "/opt/cvehunter/claude_audit/django-rest-framework/setup/docker-compose.yml",
    ),
]
APP_SVC = "app"
REDIS_CONTAINER = "cvehunterlab_django-rest-framework_redis"

# ---- Colored, file-safe logging (gate ANSI on a real TTY + honor NO_COLOR) --
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag: str, msg: str) -> None:
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}", flush=True)
    else:
        print(f"[{tag}] {msg}", flush=True)


def banner(vuln_id: str, title: str) -> None:
    line = "=" * 78
    print(line, flush=True)
    print(f"{vuln_id}: {title}", flush=True)
    print(f"target: {BASE_URL}", flush=True)
    print(line, flush=True)


def verdict(ok, vuln_id, msg, status=None):
    """Print the final one-line verdict and exit (0 = confirmed, 1 = not)."""
    status = status or ("CONFIRMED" if ok else "FAILED")
    color = {"CONFIRMED": "32", "FAILED": "31", "NEEDS_MANUAL": "33"}.get(status, "32")
    text = f"==> {vuln_id}: {status} — {msg}"
    if _USE_COLOR:
        print(f"\033[1;{color}m{text}\033[0m", flush=True)
    else:
        print(text, flush=True)
    sys.exit(0 if ok else 1)


# ---- HTTP helpers ----------------------------------------------------------
def tok(token: str) -> dict:
    """Authorization header for DRF TokenAuthentication."""
    return {"Authorization": f"Token {token}"}


def s() -> requests.Session:
    return requests.Session()


# ---- Lab-state helpers -----------------------------------------------------
def reseed():
    """Re-run the idempotent seed command (resets user flags + base data)."""
    log("SETUP", "re-seeding lab (manage.py seed_lab) to restore a clean state")
    subprocess.run(COMPOSE + ["exec", "-T", APP_SVC, "python", "manage.py", "seed_lab"],
                   check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def flush_redis():
    """Flush the shared throttle cache so throttle counters start empty."""
    log("SETUP", "flushing redis throttle cache")
    subprocess.run(["docker", "exec", REDIS_CONTAINER, "redis-cli", "flushall"],
                   check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def app_shell(pycode: str) -> str:
    """Run python in the app container's Django shell; return combined output."""
    r = subprocess.run(
        COMPOSE + ["exec", "-T", APP_SVC, "python", "manage.py", "shell", "-c", pycode],
        capture_output=True, text=True,
    )
    return (r.stdout or "") + (r.stderr or "")


def artifact(name: str, text: str):
    """Write an evidence file (request.http / response.txt / ...) into the CWD.
    run.sh cd's into the finding's own dir, so a relative name lands there."""
    with open(name, "w") as f:
        f.write(text if text.endswith("\n") else text + "\n")


def wait_up(timeout=60):
    """Block until the app answers 200 on / (used after a restart)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(BASE_URL + "/", timeout=4).status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(2)
    return False
