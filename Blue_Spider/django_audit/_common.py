"""
Shared helpers for the django (6.2.0a0 @9e06baf) Stage-10 exploit suite.

Two families of exploit use this module:

* HTTP exploits — drive the *running lab* over HTTP (:20796 WSGI, :20797 ASGI)
  with ``requests``.  This is the gold-standard proof: the framework code runs
  exactly as a deployed Django app would run it.

* Library-footgun exploits — drive the *real bind-mounted target source*
  (``/opt/django_src/django`` inside ``cvehunterlab_django_app``) by feeding a
  small Python driver to ``docker exec -i … python -``.  Django is on the
  container's ``PYTHONPATH`` (NOT pip-installed), so ``import django`` there is
  the audited commit, and the driver exercises the vulnerable API precisely the
  way a *consuming application* would.  This is how we validate the LATENT
  "framework footgun" findings without shipping a bespoke vulnerable app.

Everything is config-driven from the manifest (claude_audit/django/django_summary.md).
"""

from __future__ import annotations

import os
import subprocess
import sys

# --------------------------------------------------------------------------
# Runtime configuration (defaults mirror django_summary.md → ## Runtime)
# --------------------------------------------------------------------------
BASE_URL = os.environ.get("BASE_URL", "http://localhost:20796")      # WSGI / gunicorn
ASGI_URL = os.environ.get("ASGI_URL", "http://localhost:20797")      # ASGI / uvicorn

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "AdminLabPass123!")
STAFF_USER = os.environ.get("STAFF_USER", "staff")
STAFF_PASS = os.environ.get("STAFF_PASS", "StaffLabPass123!")
USER_USER = os.environ.get("USER_USER", "alice")
USER_PASS = os.environ.get("USER_PASS", "AliceLabPass123!")

APP_CONTAINER = os.environ.get("APP_CONTAINER", "cvehunterlab_django_app")
ASGI_CONTAINER = os.environ.get("ASGI_CONTAINER", "cvehunterlab_django_asgi")
REDIS_CONTAINER = os.environ.get("REDIS_CONTAINER", "cvehunterlab_django_redis")
DB_CONTAINER = os.environ.get("DB_CONTAINER", "cvehunterlab_django_db")

TARGET_COMMIT = "9e06baf2e4dd17834b5deaf3a3e6ae3bff2fcf26"

# --------------------------------------------------------------------------
# Colored, report-grade logging (plain when captured to a file / NO_COLOR)
# --------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag: str, msg: str) -> None:
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}", flush=True)
    else:
        print(f"[{tag}] {msg}", flush=True)


def banner(vuln_id: str, title: str, code_path: str, base_url: str = BASE_URL) -> None:
    line = "=" * 74
    print(line, flush=True)
    print(f"{vuln_id}: {title}", flush=True)
    print(f"target : {base_url}  (commit {TARGET_COMMIT[:12]})", flush=True)
    print(line, flush=True)
    log("INFO", f"exercising vulnerable code path: {code_path}")


def verdict(vuln_id: str, status: str, msg: str) -> int:
    """Print the final one-line verdict; return the process exit code."""
    tag = {"CONFIRMED": "OK", "FAILED": "FAIL", "NEEDS_MANUAL": "STEP"}.get(status, "INFO")
    color = {"CONFIRMED": "32", "FAILED": "31", "NEEDS_MANUAL": "33"}.get(status, "36")
    text = f"==> {vuln_id}: {status} — {msg}"
    if _USE_COLOR:
        print(f"\033[1;{color}m{text}\033[0m", flush=True)
    else:
        print(text, flush=True)
    return 0 if status in ("CONFIRMED", "NEEDS_MANUAL") else 1


def rand_suffix(n: int = 4) -> str:
    import secrets

    return secrets.token_hex(n)


# --------------------------------------------------------------------------
# In-container driver: run Python against the real bind-mounted target source
# --------------------------------------------------------------------------
def dexec(pycode: str, container: str = APP_CONTAINER, env: dict | None = None,
          timeout: int = 120) -> subprocess.CompletedProcess:
    """Run *pycode* with the container's python (Django target on PYTHONPATH).

    Returns the CompletedProcess (stdout/stderr captured, text mode).  The
    driver is fed on stdin to ``python -`` so there is no file to stage.
    """
    cmd = ["docker", "exec", "-i"]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [container, "python", "-"]
    return subprocess.run(cmd, input=pycode, capture_output=True, text=True, timeout=timeout)


def dexec_sh(shcode: str, container: str = APP_CONTAINER,
             timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a shell snippet inside *container*."""
    return subprocess.run(
        ["docker", "exec", "-i", container, "sh", "-c", shcode],
        capture_output=True, text=True, timeout=timeout,
    )


# Boilerplate prepended to Django drivers so they bootstrap the framework the
# same way the WSGI/ASGI handlers do.
DJANGO_BOOTSTRAP = (
    "import warnings; warnings.filterwarnings('ignore')\n"
    "import os, django\n"
    "os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'labsite.settings')\n"
    "django.setup()\n"
)


def django_driver(body: str) -> str:
    return DJANGO_BOOTSTRAP + body


# --------------------------------------------------------------------------
# HTTP session helpers (CSRF-aware login against the running lab)
# --------------------------------------------------------------------------
def new_session():
    import requests

    s = requests.Session()
    # A browser-like UA avoids any spider/bot special-casing.
    s.headers.update({"User-Agent": "cvehunter-stage10/1.0"})
    return s


def _csrf_from_html(html: str) -> str | None:
    import re

    m = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', html)
    return m.group(1) if m else None


def admin_login(session, base_url: str = BASE_URL, user: str = ADMIN_USER,
                password: str = ADMIN_PASS):
    """Log into the Django admin; returns the session (raises on failure)."""
    login_url = f"{base_url}/admin/login/"
    r = session.get(login_url, timeout=15)
    token = _csrf_from_html(r.text) or session.cookies.get("csrftoken")
    r = session.post(
        login_url,
        data={
            "csrfmiddlewaretoken": token,
            "username": user,
            "password": password,
            "next": "/admin/",
        },
        headers={"Referer": login_url},
        allow_redirects=False,
        timeout=15,
    )
    if r.status_code != 302:
        raise RuntimeError(f"admin login failed for {user}: HTTP {r.status_code}")
    return session


def get_form_csrf(session, url: str) -> str | None:
    """GET a page and return its embedded csrfmiddlewaretoken (or cookie)."""
    r = session.get(url, timeout=15)
    return _csrf_from_html(r.text) or session.cookies.get("csrftoken")


def save_http(dirpath: str, request_text: str, response_text: str) -> None:
    """Persist request.http / response.txt evidence next to the exploit."""
    with open(os.path.join(dirpath, "request.http"), "w") as f:
        f.write(request_text)
    with open(os.path.join(dirpath, "response.txt"), "w") as f:
        f.write(response_text)


def here(automation_file: str) -> str:
    return os.path.dirname(os.path.abspath(automation_file))
