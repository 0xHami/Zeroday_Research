"""
Shared helpers for SuiteCRM 7.15.2 stage-10 dynamic-validation exploits.

Every exploit imports from this module so the login / user-provisioning /
legacy-API primitives are written once and reused. Import it by adding the
exploits dir to sys.path at the top of each automation.py:

    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from _common import (BASE_URL, ADMIN_USER, ADMIN_PASS, log, rand,
                         web_login, create_user, rest_login, rest_call)

Target facts (from claude_audit/SuiteCRM/SuiteCRM_summary.md):
  BASE_URL       http://localhost:33116
  admin creds    admin / Admin@2026!
  legacy REST    POST /service/v4_1/rest.php   (method/input_type/response_type/rest_data)
  V8 API         /Api/access_token  +  /Api/V8/...
"""
import os
import sys
import json
import time
import secrets
import hashlib

import requests

BASE_URL = os.environ.get("BASE_URL", "http://localhost:33116").rstrip("/")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "Admin@2026!")

# A real browser UA — SuiteCRM's referer/CSRF handling and some UA sniffing
# behave differently for non-browser agents; use a browser UA everywhere.
BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 "
              "Firefox/123.0 cvehunter-stage10")

# ---------------------------------------------------------------------------
# Colored, report-grade logging (plain when captured to a file / NO_COLOR set)
# ---------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag, msg):
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}", flush=True)
    else:
        print(f"[{tag}] {msg}", flush=True)


def banner(vuln_id, title):
    line = "=" * 72
    print(line, flush=True)
    print(f"{vuln_id}: {title}", flush=True)
    print(f"target: {BASE_URL}", flush=True)
    print(line, flush=True)


def rand(prefix="x"):
    """Random suffix so every run is independent (mandatory per stage rules)."""
    return f"{prefix}_{secrets.token_hex(4)}"


def verdict(vuln_id, status, msg):
    """Print the final one-line verdict; color it by status."""
    color = {"CONFIRMED": "32", "FAILED": "31", "NEEDS_MANUAL": "33"}.get(status, "0")
    text = f"==> {vuln_id}: {status} — {msg}"
    if _USE_COLOR:
        print(f"\033[1;{color}m{text}\033[0m", flush=True)
    else:
        print(text, flush=True)


# ---------------------------------------------------------------------------
# Web (session-cookie) authentication
# ---------------------------------------------------------------------------
def new_session():
    s = requests.Session()
    s.headers.update({"User-Agent": BROWSER_UA})
    return s


def web_login(user, password, base=BASE_URL, session=None):
    """Log in through the SuiteCRM web form; return an authenticated Session.

    Raises RuntimeError on failure (no 302 -> Home / bounced back to Login).
    """
    s = session or new_session()
    s.get(f"{base}/index.php?module=Users&action=Login", timeout=30)
    r = s.post(
        f"{base}/index.php",
        data={
            "module": "Users",
            "action": "Authenticate",
            "user_name": user,
            "username_password": password,
        },
        headers={"Referer": f"{base}/index.php?module=Users&action=Login"},
        allow_redirects=False,
        timeout=30,
    )
    loc = r.headers.get("Location", "")
    if r.status_code != 302 or "action=Login" in loc:
        raise RuntimeError(f"web login failed for {user!r}: status={r.status_code} loc={loc!r}")
    return s


def admin_session(base=BASE_URL):
    return web_login(ADMIN_USER, ADMIN_PASS, base=base)


# ---------------------------------------------------------------------------
# Provision a low-privileged regular user (as admin)
# ---------------------------------------------------------------------------
def create_user(admin_s, password, base=BASE_URL, is_admin="0", extra=None):
    """Create a fresh regular user via the Users EditView Save flow.

    As admin editing *another* user, User::change_password() skips the
    old-password check (User.php:1368), so new_password+password_change='true'
    sets the account password. Returns dict: {user_name, id, password}.
    """
    uname = rand("mod")
    fields = {
        "module": "Users",
        "action": "Save",
        "record": "",
        "page": "EditView",
        "user_name": uname,
        "last_name": f"Stage10{secrets.token_hex(2)}",
        "first_name": "Low",
        "status": "Active",
        "is_admin": is_admin,
        "employee_status": "Active",
        "UserType": "RegularUser",
        # password: admin-editing-other path skips old-password verification
        "new_password": password,
        "password_change": "true",
        "old_password": "",
        # email widget (SuiteCRM requires a primary email on user save)
        "useremail0": f"{uname}@example.invalid",
        "useremailaddress0": f"{uname}@example.invalid",
        "email0": f"{uname}@example.invalid",
        "Users0emailAddress0": f"{uname}@example.invalid",
        "Users0emailAddressPrimaryFlag": "Users0emailAddress0",
        "Users_email_widget_id": "0",
        "emailAddressWidget": "1",
    }
    if extra:
        fields.update(extra)
    r = admin_s.post(
        f"{base}/index.php",
        data=fields,
        headers={"Referer": f"{base}/index.php?module=Users&action=EditView"},
        allow_redirects=False,
        timeout=60,
    )
    # A successful save redirects to the new record's DetailView; the GUID is in
    # the Location header (record=<guid>).
    import re
    loc = r.headers.get("Location", "")
    m = re.search(r"record=([0-9a-fA-F-]{36})", loc)
    if not m:
        raise RuntimeError(
            f"create_user: no record id in redirect for {uname} "
            f"(status={r.status_code} loc={loc!r})")
    return {"user_name": uname, "id": m.group(1), "password": password}


# ---------------------------------------------------------------------------
# Legacy REST API (service/v4_1/rest.php) — JSON in/out
# ---------------------------------------------------------------------------
def rest_login(user, password, base=BASE_URL, app_name="cvehunter"):
    """Return a session_id from the legacy REST login (password is md5-hashed)."""
    res = rest_call("login", [
        {"user_name": user, "password": hashlib.md5(password.encode()).hexdigest(),
         "version": "1"},
        app_name, [],
    ], base=base)
    sid = res.get("id")
    if not sid:
        raise RuntimeError(f"rest_login failed for {user!r}: {res}")
    return sid


def rest_call(method, rest_data, base=BASE_URL, version="v4_1", timeout=60):
    """Call a legacy REST method; rest_data is the python list of args."""
    r = requests.post(
        f"{base}/service/{version}/rest.php",
        data={
            "method": method,
            "input_type": "JSON",
            "response_type": "JSON",
            "rest_data": json.dumps(rest_data),
        },
        headers={"User-Agent": BROWSER_UA},
        timeout=timeout,
    )
    try:
        return r.json()
    except Exception:  # noqa: BLE001
        return {"_raw": r.text, "_status": r.status_code}


# ---------------------------------------------------------------------------
# V8 REST API (OAuth2 password grant)
# ---------------------------------------------------------------------------
def v8_token(user, password, base=BASE_URL, client_id=None, client_secret=None):
    """Get a V8 OAuth2 access token (password grant). Requires an OAuth2 client
    to exist; returns None if not configured (caller decides)."""
    payload = {
        "grant_type": "password",
        "client_id": client_id or os.environ.get("V8_CLIENT_ID", ""),
        "client_secret": client_secret or os.environ.get("V8_CLIENT_SECRET", ""),
        "username": user,
        "password": password,
    }
    r = requests.post(f"{base}/Api/access_token", data=payload,
                      headers={"User-Agent": BROWSER_UA}, timeout=30)
    try:
        return r.json().get("access_token")
    except Exception:  # noqa: BLE001
        return None


if __name__ == "__main__":
    # Smoke-test the primitives when run directly.
    banner("SELFTEST", "common helper primitives")
    log("STEP", "admin web login")
    a = admin_session()
    log("OK", "admin web session established")
    log("STEP", "admin legacy REST login")
    sid = rest_login(ADMIN_USER, ADMIN_PASS)
    log("OK", f"REST session id = {sid[:8]}...")
    log("STEP", "create low-priv user")
    u = create_user(a, "LowPriv@2026x!")
    log("OK", f"created user {u['user_name']} id={u['id']}")
    log("STEP", "low-priv web login")
    web_login(u["user_name"], u["password"])
    log("OK", "low-priv web session established")
    log("STEP", "low-priv legacy REST login")
    lsid = rest_login(u["user_name"], u["password"])
    log("OK", f"low-priv REST session id = {lsid[:8]}...")
    verdict("SELFTEST", "CONFIRMED", "all primitives work")
