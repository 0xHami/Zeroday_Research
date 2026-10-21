# VULN-004 — vCard.php cross-user PII export via ACL-less loadContact() (IDOR)

**ID**: VULN-004
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1: 6.5** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**Status**: CONFIRMED (dynamic)
**Auth required**: any authenticated user (`PR:L`) — the `vCard` entry point is registered `auth => true`, no module-specific grant needed.
**What an attacker gains**: full PII export (name, phone numbers, email, postal address, birthdate) of any Contact/Lead/Prospect in the instance, as a downloadable vCard, bypassing Security-Group and assignment-based confidentiality.

## Summary
SuiteCRM's `vCard` legacy entry point exports a Contact (or Lead/Prospect) as a vCard file. It reads the target record's id straight from the request and retrieves the bean with no access-control check at all, then serializes the record's full PII into the response. Any authenticated user can export any other user's Contact/Lead/Prospect records this way.

## How it works (mechanism & code trace)

**Entry point** — `vCard.php:54-60` (registered `auth => true`, `include/MVC/Controller/entry_point_registry.php:52`):
```php
54: $vcard = new vCard();
    $module = 'Contacts';
    if (isset($_REQUEST['module'])) {
57:     $module = clean_string($_REQUEST['module']);
    }
60: $vcard->loadContact($_REQUEST['contact_id'], $module);
    $vcard->saveVCard();
```

**Sink** — `include/vCard.php:60-66`:
```php
60: public function loadContact($contactid, $module = 'Contacts')
    {
        global $app_list_strings;
        require_once($GLOBALS['beanFiles'][$GLOBALS['beanList'][$module]]);
        $contact = new $GLOBALS['beanList'][$module]();
66:     $contact->retrieve($contactid);          // <-- no ACLAccess call
```
followed immediately (`include/vCard.php:76-89`) by `setName`/`setBirthDate`/`setPhoneNumber` (fax/home/cell/work)/`setEmail`/`setAddress`/`setORG` — the record's complete PII, unconditionally.

**The exact defect**: `clean_string($_REQUEST['module'])` (line 57) is the *only* validation on the request. It constrains `$module` to a legitimate `$beanList` key (blocking arbitrary-class instantiation) and, incidentally, means `retrieve()`'s internal id-quoting blocks SQL injection — but it performs **zero** authorization. `SugarBean::retrieve()` loads strictly by primary key; it does not itself apply `ACLAccess`, Security-Group visibility, or `assigned_user_id` scoping (those are applied by *callers*, typically the MVC controller's `processView()` — which this legacy top-level script never goes through).

## Why it is a vulnerability (reasoning)
SuiteCRM's authorization model enforces list/detail visibility at the MVC view layer (`processView()`'s `ACLAccess` call) — that's the mechanism that makes "only see your team's Contacts" actually work in the normal UI. `vCard.php` is a legacy top-level script that constructs a bean and calls `retrieve()` directly, entirely outside that layer. Nothing about "exporting a vCard" is inherently exempt from the same visibility rules that apply to viewing the same record in the browser — quite the opposite, an export is arguably *more* sensitive (it's a portable file containing PII, explicitly designed to leave the system). The missing invariant is simple: "before serializing a bean's PII into a vCard, verify `bean->ACLAccess('view')` for the current user, exactly as the DetailView would."

## Reproduction
From a clean state (`./run.sh`):
1. **Preconditions** — admin creates **V** and **A** (unrelated). As **V**, create a Contact with a unique last name and a unique work-phone value.
2. **Attack request**, as **A**:
   ```
   GET /index.php?entryPoint=vCard&module=Contacts&contact_id=<victim_contact_id>
   Cookie: PHPSESSID=<attacker session>
   ```
   (full request in `request.http`)
3. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected tail:
   ```
   [PROOF] victim last_name '...' present in vCard: True
   [PROOF] victim phone_work marker '...' present in vCard: True
   ==> VULN-004: CONFIRMED — attacker exported V's Contact PII (...) via vCard, no ACL check
   ```
4. **Observable proof** — `response.txt` is a `200 OK`, `Content-Type: text/x-vcard; charset=UTF-8`, whose body is a complete `BEGIN:VCARD ... END:VCARD` record containing the victim's `N`/`FN`/`TEL;WORK` fields with the exact values seeded by the harness — see `evidence/leaked_vcard.txt`.

## Impact
- **Confidentiality (broad, high)**: full PII (name, salutation, birthdate, all phone numbers, email, postal address, organization) of any Contact/Lead/Prospect, for any authenticated user, regardless of Security-Group or assignment restrictions.
- The export is a clean, unauthenticated-beyond-session single GET with no CSRF token, so it's trivially scriptable for bulk exfiltration: an attacker can enumerate GUIDs (via [VULN-001]'s broader enumeration or [VULN-024]'s subpanel leak) and script a sweep of the entire Contacts/Leads/Prospects table into vCard files.
- Regulatory exposure: a GDPR/PII-class confidentiality breach; also a force-multiplier for phishing/social-engineering (real names, direct phone numbers, and org affiliations make convincing pretexting material).
- No integrity/availability impact; chains with [VULN-001]/[VULN-002]/[VULN-003] (same "retrieve-by-id, ACL only at view render" root-cause family).

## Suggested fix
```php
$vcard->loadContact($_REQUEST['contact_id'], $module);
// inside loadContact(), immediately after retrieve():
if (empty($contact->id) || !$contact->ACLAccess('view')) {
    sugar_die($GLOBALS['app_strings']['LBL_NO_ACCESS'] ?? 'No access');
}
```
Enforce `ACLAccess('view')` (and Security-Group row-level visibility) right after `retrieve()` in `loadContact()`, or — preferably — route the vCard export through the standard module controller so the normal view ACL is inherited automatically rather than re-implemented in every legacy entry point.

## References
- CWE-639 — Authorization Bypass Through User-Controlled Key.
- OWASP Top 10 2021 — A01:2021 Broken Access Control; OWASP WSTG-ATHZ-04 (IDOR).
- Same read-IDOR family as CVE-2026-63217 / CVE-2026-69144 (no advisory names this specific `vCard`/`loadContact` sink — tracked as possibly novel per stage-07 known-issue cross-check).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory DB text search `SuiteCRM vCard` — 0 results.
2. GitHub issue search `vCard contact_id OR vCard ACL OR vCard security` — only a vcard library dependency bump (#7376); no access-control report.
3. All 77 SuiteCRM GHSA titles reviewed — none mention the vCard entry point.
4. NVD API keywordSearch=SuiteCRM (107 CVEs) and keywordSearch=SugarCRM (66 CVEs) — no description mentions vCard.
5. (Web search `SuiteCRM vCard entryPoint contact_id IDOR vulnerability` could not be run — per-turn search budget exhausted; primary sources above were fetched directly instead.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-63217 / GHSA-m5xj-rrwv-g3q3 — IDOR in the generatePdf entry point; different entry point.
- CVE-2026-32697 — missing view ACL in SuiteCRM 8 RecordHandler::getRecord(); different codebase.
- CVE-2026-29189 — V8 REST API ACL gaps; different API.

**Reasoning:** No CVE, GHSA, release note or issue describes the vCard entry point loading a record without an ACL check. The class (retrieve-by-id without ACL) is common in SuiteCRM, so a private report could exist, but the component itself has no public history.
