# VULN-033 — Users signatures: read + overwrite any user's e-mail signature (IDOR)

**ID**: VULN-033
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1: 5.4** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`
**Status**: CONFIRMED (dynamic)
**Auth required**: any authenticated user (`PR:L`) — no special role.
**What an attacker gains**: read any other user's stored e-mail signature, and overwrite it in place with attacker-controlled HTML that the victim will then unknowingly append to every outbound e-mail sent through SuiteCRM.

## Summary
E-mail signatures (`UserSignature` beans) are addressed by a request-supplied `record` GUID in two legacy scripts, neither of which checks that the loaded signature belongs to the caller. Any authenticated user can read another user's signature, and — more seriously — overwrite its content in place while the row keeps its original owner, meaning the victim's own outgoing mail starts carrying attacker-controlled content without the victim ever touching the Signatures screen.

## How it works (mechanism & code trace)

**Write sink** — `modules/Users/SaveSignature.php:44-58`:
```php
44: $us = new UserSignature();
    if (isset($_REQUEST['record']) && !empty($_REQUEST['record'])) {
46:     $us->retrieve($_REQUEST['record']);       // <-- no owner check
    } else {
        $us->id = create_guid();
        $us->new_with_id = true;
    }
    $us->name = $_REQUEST['name'];
    $us->signature = strip_tags(br2nl(from_html($_REQUEST['description'])));
    $us->signature_html = $_REQUEST['description'];  // <-- raw HTML from the request, unsanitized here
    if (empty($us->user_id) && isset($_REQUEST['the_user_id'])) {
        $us->user_id = $_REQUEST['the_user_id'];
    }
58: $us->save();
```
When `record` is supplied, `retrieve()` loads *whatever row that GUID points to* — including a signature that already has `user_id` set to someone else — and then unconditionally overwrites `name`/`signature`/`signature_html` from the request and saves. Because `user_id` is already non-empty on an existing row, the `the_user_id` branch is skipped and ownership is silently preserved — the attacker doesn't even need to know or guess the victim's user id to hijack their signature, only the signature's own GUID.

**Read sink** — `modules/Users/PopupSignature.php:56-96`:
```php
56: if (isset($_REQUEST['record']) && !empty($_REQUEST['record'])) {
        $focus->retrieve($_REQUEST['record']);     // <-- no owner check
    }
    ...
96: $xtpl->assign('SIGNATURE_TEXT', !empty($focus->signature_html) ? $focus->signature_html : $focus->signature);
```
Same pattern: `retrieve()` by bare id, rendered back to whoever asked.

**The exact defect**: neither file ever compares `$focus->user_id` (or `$us->user_id`) to `current_user->id`. `UserSignature::retrieve()` is a plain primary-key fetch; the `Users` module's normal per-record save/delete/password guards (`hasSaveAccess`, `setIsAdmin`, etc.) live on the *user record* edit flow and are never invoked by these two standalone scripts.

## Why it is a vulnerability (reasoning)
A signature is, by definition, a *personal* artifact — it's appended to a specific user's outgoing mail and is never intended to be shared or edited by anyone else, unlike (say) a shared Document. The correct invariant is trivial to state: "an authenticated user may read or write a `UserSignature` row only if `row.user_id == current_user.id`, or the caller is an admin." Both entry points implement half of the feature (create/edit *a* signature) while omitting the one check that makes "a signature" become "*your* signature." Because the write path preserves the original `user_id` on overwrite, the resulting bug is worse than a generic IDOR: the attacker doesn't gain a copy of the data, they gain silent, persistent write access to a channel the victim will use and trust (their own outgoing mail) without any indication anything changed.

## Reproduction
From a clean state (`./run.sh`):
1. **Preconditions** — admin creates **V** and **A** (unrelated). As **V**, create her own signature (`SaveSignature` with `the_user_id=<V>`, no prior `record`) with a unique name and body marker; extract the new signature's GUID from the `refresh_signature_list("<guid>", ...)` JS snippet in V's own save response.
2. **Attack requests**, as **A**:
   ```
   GET  /index.php?module=Users&action=PopupSignature&record=<victim_signature_id>
   POST /index.php?module=Users&action=SaveSignature
        record=<victim_signature_id>&name=pwned-by-attacker&description=<p>PWNEDSIG033_...</p>
   ```
   (full requests in `request.http`)
3. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected tail:
   ```
   [PROOF] read status=200 ... V's body marker present in A's response: True
   [PROOF] row user_id still == victim's id (ownership unchanged): True
   [PROOF] row signature_html now contains attacker payload: True
   ==> VULN-033: CONFIRMED — read leaked '...'; overwrite planted '...' on V's row (user_id unchanged)
   ```
4. **Observable proof** — `docker compose exec db mysql` before/after dump (`evidence/db_before_after.txt`) shows the **same** `users_signatures.id`, an **unchanged** `user_id` (still V's), and `name`/`signature_html` replaced with the attacker's payload — i.e. victim V's own signature now silently carries attacker content, with no action taken by V.

## Impact
- **Confidentiality (horizontal)**: read any user's signature HTML/text — useful for cloning branding/formatting to make a forged version convincing elsewhere.
- **Integrity (horizontal, persistent)**: overwrite any user's signature in place. The next time the victim sends mail through SuiteCRM using that signature, it silently carries attacker-controlled HTML — a spoofed "updated wire/bank details" block, a phishing link, or a tracking pixel — a high-trust Business-Email-Compromise (BEC) primitive, since the mail genuinely originates from the victim's account.
- The write path also lets an attacker **plant** a brand-new signature on an arbitrary `user_id` (via `the_user_id` when `record` is empty or points at a not-yet-owned row), not just hijack an existing one.
- No availability impact; confined to the signature subsystem, but with an outsized trust impact given where the tampered content ends up (outbound mail).

## Suggested fix
Owner-scope both endpoints immediately after `retrieve()`:
```php
if (empty($focus->id) || $focus->user_id !== $current_user->id) {
    if (!$current_user->isAdmin()) {
        sugar_die($mod_strings['LBL_NO_ACCESS'] ?? 'No access');
    }
}
```
For `SaveSignature.php`, additionally stop trusting `$_REQUEST['the_user_id']` to assign ownership on new rows — bind new signatures to `current_user->id` unconditionally; only an admin-only "manage other users' signatures" path (if one is truly needed) should be allowed to target a different `user_id`, and even then via an explicit capability check, not an unauthenticated request field.

## References
- CWE-639 — Authorization Bypass Through User-Controlled Key.
- OWASP Top 10 2021 — A01:2021 Broken Access Control; OWASP WSTG-ATHZ-04 (IDOR).
- General BEC pattern reference: FBI IC3 guidance on business e-mail compromise via trusted-channel content tampering (forged signature/footer content used to redirect payments).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM SaveSignature IDOR CVE signature overwrite` — only unrelated CVE-2026-32697 (RecordHandler::getRecord, v8) and third-party "Signature Field Widget" plugin support tickets; nothing on SaveSignature
2. `SuiteCRM PopupSignature vulnerability user signature access control` — generic access-control CVEs (CVE-2020-8802 action_saveHTMLField, CVE-2023-5353, CVE-2026-29108); no signature component
3. `SuiteCRM "signature" IDOR advisory Users module 2025` — CVE-2026-29189 (REST API V8 user preferences/relationships), CVE-2026-32697; none mention signatures
4. `github advisories SuiteCRM UserSignature broken access control` — CVE-2025-64490 (Resource Calendar), CVE-2026-29189, CVE-2025-54786 (iCal); no UserSignature match
5. `"SaveSignature" OR "PopupSignature" SuiteCRM security` (extended) — only the GitHub source tree listing and plugin docs; no advisory names either file
6. Fetched CVE-2020-8787 (invalid Bean ID submission, fixed 7.10.23/7.11.11) — no component named, no signature reference, and pre-dates the audited 7.15.2 where this bug is confirmed present

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-29189 / GHSA-m6x8-3hxp-qxwv — missing ACL on REST API V8 user-preference/relationship endpoints (fixed 7.15.1), not the legacy Users/SaveSignature or PopupSignature scripts
- CVE-2026-32697 — `RecordHandler::getRecord()` IDOR in SuiteCRM 8 core, different component
- CVE-2020-8787 — generic "invalid Bean ID submission" in <=7.11.11, no signature code path, already fixed long before 7.15.2
- CVE-2020-8802 — `action_saveHTMLField` bean manipulation, different endpoint

**Reasoning:** No CVE, GHSA, or vendor advisory references `modules/Users/SaveSignature.php`, `modules/Users/PopupSignature.php`, or the `UserSignature` bean; the only signature-related hits are a third-party store plugin. IDOR/ACL issues are a very common class in SuiteCRM and the vendor has shipped many ACL fixes, so a private or unindexed report could exist, but nothing public matches this component and root cause on 7.15.2.
