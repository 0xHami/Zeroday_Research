"""
lwlib — a tiny shared toolkit for driving the Academico (Laravel 12 + Filament 5 +
Livewire v3) target during Stage-10 dynamic validation.

Every exploit in this target talks to the same handful of surfaces:

  * the Filament login form / student login,
  * the public registration wizard,
  * the authenticated Filament pages (checkout, grade-edit, skill-evaluation, …),
  * and the single Livewire action endpoint ``POST /livewire-<hash>/update`` that
    every Livewire component (form, table, page action) dispatches through.

Livewire v3 works like this: the server renders a component into HTML with a
``wire:snapshot="<json>"`` attribute (the component's serialized state, carrying an
HMAC ``checksum`` the server will re-verify) and a ``<meta name="csrf-token">``.
To invoke a method or change a property, the browser POSTs the *exact* snapshot it
was given back to ``/livewire-<hash>/update`` together with an ``updates`` diff
(property overwrites) and ``calls`` (method invocations). Because the snapshot is
echoed verbatim, its checksum stays valid — and the ``updates`` diff is applied to
**any** public, non-``#[Locked]`` property before the method runs. That last fact
is the root cause of several findings here (client-controlled ``isReadOnly``,
``currentStep``, ``courseId`` …); this helper just makes that request easy to send.

Nothing here is target-specific beyond defaults; everything is overridable via env.
"""
import html
import json
import os
import re
import shlex
import subprocess
import sys

import requests

# docker compose project (manifest: cvehunt_academico). Used for seeding legitimate
# state that is impractical to build through the multi-step Filament UI (courses,
# enrollments, reference data). Seeding via `artisan tinker` stands in for an admin
# performing those actions; the *attack* itself always goes over real HTTP.
COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT", "cvehunt_academico")
TARGET_DIR = os.environ.get("TARGET_DIR",
                            "/opt/cvehunter/targets/academico")

BASE_URL = os.environ.get("BASE_URL", "http://localhost:20000")
# Livewire URL prefix is a per-build hash (manifest Known-issues #4). Override if it changed.
LW_HASH = os.environ.get("LW_HASH", "5f244c96")

# ---- colored, report-grade logging (plain when captured to a file) -----------
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
    print(f"target: {BASE_URL}", flush=True)
    log("INFO", f"exercising vulnerable code path: {code_path}")
    print(line, flush=True)


def verdict(vuln_id: str, status: str, msg: str) -> None:
    """Print the final one-line verdict (colored by status)."""
    color = {"CONFIRMED": "32", "FAILED": "31", "NEEDS_MANUAL": "33"}.get(status, "0")
    text = f"==> {vuln_id}: {status} — {msg}"
    if _USE_COLOR:
        print(f"\033[1;{color}m{text}\033[0m", flush=True)
    else:
        print(text, flush=True)


# ---- Livewire plumbing -------------------------------------------------------
_META_CSRF = re.compile(r'<meta name="csrf-token" content="([^"]+)"')
# wire:snapshot="{...html-escaped json...}" wire:id="..." ; capture snapshot + id
_SNAP = re.compile(r'wire:snapshot="((?:[^"\\]|\\.)*)"')


def csrf_of(page_html: str) -> str:
    m = _META_CSRF.search(page_html)
    if not m:
        raise RuntimeError("no csrf-token meta on page")
    return m.group(1)


def snapshots(page_html: str):
    """Return list of (snapshot_json_str, parsed_dict) for every Livewire component on the page."""
    out = []
    for m in _SNAP.finditer(page_html):
        raw = html.unescape(m.group(1))
        try:
            out.append((raw, json.loads(raw)))
        except json.JSONDecodeError:
            continue
    return out


def find_snapshot(page_html: str, name: str):
    """Return the (raw_json_str, parsed) snapshot whose memo.name matches `name`
    (or whose memo.path contains it, for Filament pages keyed by route)."""
    for raw, snap in snapshots(page_html):
        memo = snap.get("memo", {})
        if memo.get("name") == name or name in (memo.get("path") or ""):
            return raw, snap
    # Filament page components are named like "app.filament.pages.checkout-page"
    for raw, snap in snapshots(page_html):
        memo = snap.get("memo", {})
        if name.replace("-", "").lower() in (memo.get("name") or "").replace(".", "").replace("-", "").lower():
            return raw, snap
    raise RuntimeError(f"no Livewire snapshot matching {name!r} on page (found: "
                       f"{[s[1].get('memo', {}).get('name') for s in snapshots(page_html)]})")


def lw_update(session: requests.Session, snapshot_raw: str, updates: dict, calls: list,
              csrf: str, extra_headers: dict = None):
    """Send one Livewire component update. `snapshot_raw` must be the exact snapshot
    string echoed from the page (its checksum is re-verified server-side)."""
    payload = {
        "_token": csrf,
        "components": [{
            "snapshot": snapshot_raw,
            "updates": updates or {},
            "calls": calls or [],
        }],
    }
    headers = {
        "X-CSRF-TOKEN": csrf,
        "X-Livewire": "",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Referer": BASE_URL + "/",
    }
    if extra_headers:
        headers.update(extra_headers)
    return session.post(f"{BASE_URL}/livewire-{LW_HASH}/update", data=json.dumps(payload),
                        headers=headers, timeout=30)


def tinker(php_code: str) -> str:
    """Run a PHP snippet inside the app container via `artisan tinker --execute`.
    Used only for SEEDING legitimate state / verifying side effects — never to
    perform the exploit itself. Returns combined stdout+stderr (minus the harmless
    'Restricted Mode' banner)."""
    cmd = ["docker", "compose", "-p", COMPOSE_PROJECT, "exec", "-T", "app",
           "php", "artisan", "tinker", "--execute", php_code]
    out = subprocess.run(cmd, cwd=TARGET_DIR, capture_output=True, text=True, timeout=120)
    text = (out.stdout or "") + (out.stderr or "")
    return "\n".join(l for l in text.splitlines() if "restricted mode" not in l.lower())


def container_exec(*args: str) -> str:
    """Run an arbitrary command inside the app container (e.g. read a file, ls)."""
    cmd = ["docker", "compose", "-p", COMPOSE_PROJECT, "exec", "-T", "app", *args]
    out = subprocess.run(cmd, cwd=TARGET_DIR, capture_output=True, text=True, timeout=120)
    return (out.stdout or "") + (out.stderr or "")


def queue_work_once() -> str:
    """Process one queued job (queue=database). The password-reset notification is
    ShouldQueue, so its email is only rendered into storage/logs/laravel.log after a
    worker runs it."""
    return container_exec("php", "artisan", "queue:work", "--once", "--stop-when-empty")


def strip_secure_cookies(session: "requests.Session") -> None:
    """Re-issue the session's cookies without the Secure flag. Needed when a request
    was made with X-Forwarded-Proto: https (which makes Laravel mark the session
    cookie Secure); requests would otherwise refuse to send it back over plain http."""
    jar = requests.cookies.RequestsCookieJar()
    for c in session.cookies:
        jar.set(c.name, c.value, domain=c.domain, path=c.path)
    session.cookies = jar


def read_laravel_log_tail(nbytes: int = 20000) -> str:
    """Return the tail of storage/logs/laravel.log from inside the container.
    MAIL_MAILER=log in this build, so password-reset / notification URLs land here."""
    return container_exec("sh", "-c", f"tail -c {int(nbytes)} storage/logs/laravel.log")


def new_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "cvehunt-stage10/1.0"})
    return s


def response_snapshot(resp) -> str:
    """Extract the updated component snapshot string from a Livewire update response,
    so a multi-step interaction (mount action -> fill form -> call) can chain state."""
    return resp.json()["components"][0]["snapshot"]


def filament_login(session: requests.Session, email: str, password: str) -> bool:
    """Log into the Filament admin panel (/admin/login) via its Livewire form.
    Returns True on success (session cookie now authenticated)."""
    r = session.get(f"{BASE_URL}/admin/login", timeout=30)
    csrf = csrf_of(r.text)
    snap_raw, _ = find_snapshot(r.text, "login")
    resp = lw_update(
        session, snap_raw,
        updates={"data.email": email, "data.password": password, "data.remember": True},
        calls=[{"path": "", "method": "authenticate", "params": []}],
        csrf=csrf,
    )
    # On success Filament returns a redirect directive in the JSON effects.
    ok = resp.status_code == 200 and ("redirect" in resp.text or "\"effects\"" in resp.text)
    # Confirm by hitting an authed page.
    chk = session.get(f"{BASE_URL}/admin", timeout=30, allow_redirects=False)
    return ok and chk.status_code == 200


def student_login(session: requests.Session, email: str, password: str) -> bool:
    """Log in through the generic /login (student) Livewire form if present."""
    r = session.get(f"{BASE_URL}/login", timeout=30, allow_redirects=True)
    csrf = csrf_of(r.text)
    try:
        snap_raw, _ = find_snapshot(r.text, "login")
    except RuntimeError:
        return False
    resp = lw_update(
        session, snap_raw,
        updates={"data.email": email, "data.password": password},
        calls=[{"path": "", "method": "authenticate", "params": []}],
        csrf=csrf,
    )
    return resp.status_code == 200 and "redirect" in resp.text
