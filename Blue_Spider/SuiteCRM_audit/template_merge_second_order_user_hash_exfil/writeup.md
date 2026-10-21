# VULN-090 — Second-Order Merge-Token Injection Exfiltrates the Assigned User's Password Hash

**ID**: VULN-090
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`)
**Commit**: `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: High — **CVSS 3.1 8.0** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (conditional on a template-merge workflow existing; the fully unauthenticated WebToLead variant raises this further — see Impact)
**Status**: **CONFIRMED (dynamic)**
**Auth required**: Any authenticated user able to create/edit a record whose field gets merged into an email/PDF template (demonstrated below with an admin session for reliability; the write access needed — creating an `AOS_Quotes` record — is available to ordinary sales-role users in a typical deployment, not an admin-only action). A related, unauthenticated variant exists via public lead-capture forms (see Impact).
**What an attacker gains**: The plaintext-crackable bcrypt password hash of any user they can name via `assigned_user_id`, obtained by typing one line of text into an ordinary CRM record field.

## 1. Summary

SuiteCRM's PDF/email template-merge engine builds its replacement map by iterating beans **in sequence** and applies each bean's substitutions with a `str_replace` call that mutates a **shared** string — so text inserted by an earlier bean's substitution is re-scanned and expanded by a later bean's pass. Because the "assigned user" bean is always included in the merge context and is parsed *after* the triggering record, an attacker who can only edit an ordinary text field on that record (no template access needed) can plant the literal merge token for the user's password hash and have it "arrive" fully expanded in the final output — proven live: a Quote's plain `description` field containing the literal string `$users_user_hash` came back, after an ordinary "compose email from template" action, containing the assigned user's actual bcrypt hash.

## 2. How it works (mechanism & code trace)

**Merge context construction** — `modules/AOS_PDF_Templates/generatePdf.php`:
```php
$object_arr = array();
$object_arr[$bean->module_dir] = $bean->id;          // the triggering record FIRST
$object_arr['Users'] = $bean->assigned_user_id ?? ''; // the assigned user's bean, appended AFTER
...
$converted = templateParser::parse_template($text, $object_arr);
```

**The sink — per-bean substitution, sequential and string-mutating**:
```php
// modules/AOS_PDF_Templates/templateParser.php
public static function parse_template($string, $bean_arr) {
    foreach ($bean_arr as $bean_name => $bean_id) {          // ORDER MATTERS: record, then Users
        $focus = BeanFactory::getBean($bean_name, $bean_id);
        $string = templateParser::parse_template_bean($string, $focus->table_name, $focus);  // MUTATES $string
    }
    return $string;
}

public static function parse_template_bean($string, $key, &$focus) {
    foreach ($focus->field_defs as $field_def) {
        ...
        $repl_arr[$key . '_' . $fieldName] = $focus->{$fieldName};   // EVERY field, no denylist check
    }
    ...
    foreach ($repl_arr as $name => $value) {
        ...
        $string = str_replace('$' . $name, $value, (string) $string);   // re-scans the CURRENT $string
    }
    return $string;
}
```
No `sensitive`/`$badFields` check (the denylist that hides `user_hash` from the UI's variable-picker, `modules/EmailTemplates/templateFields.php`) is ever consulted here — the merge operates directly on the bean's raw `field_defs`, so `user_hash` (a public property on `User`, `modules/Users/User.php:59`) is exactly as mergeable as `name` or `description`.

**The second-order mechanic, traced through this validation's exact data**:
1. Pass 1 (Quotes bean): `$repl_arr['aos_quotes_description'] = "$users_user_hash"` (the attacker's literal text, verbatim). `str_replace('$aos_quotes_description', "$users_user_hash", $string)` inserts that literal text into the shared `$string` — nothing here has "decided" to leak anything yet; this pass just copied a field value, exactly as every legitimate `$aos_quotes_*` merge does.
2. Pass 2 (Users bean): `$repl_arr['users_user_hash'] = "$2y$10$Acb4wZ..."` (the real hash). `str_replace('$users_user_hash', "$2y$10$Acb4wZ...", $string)` now finds the literal text Pass 1 just inserted and expands it.

**The exact defect**: (a) sensitive fields are never excluded from `$repl_arr`, and (b) substitution is done as N sequential passes over one mutating string instead of a single-pass replacement built from a pre-computed, non-recursive map — the combination is what allows one bean's *data* to be reinterpreted as another bean's *merge syntax*.

## 3. Why it is a vulnerability (reasoning)

A template-merge engine's implicit contract is "field values become literal display text in the output" — a customer's name, a quote's notes, an address. That contract is silently broken the moment inserted text can itself be re-parsed as merge syntax and expanded again: this is structurally the same class of bug as second-order SQL injection or stored XSS reflected through an unexpected sink, just applied to a templating engine instead of a database or a browser. Combined with the missing sensitive-field denylist, the result is that a completely ordinary, low-privilege content field (a quote description, a lead description) becomes a vector to exfiltrate a value (`user_hash`) that the application elsewhere goes out of its way to keep out of the UI (`$badFields`). No part of this is a documented or intentional feature — merge tokens are meant to be typed by the *template author*, not discovered by re-scanning *record data*.

## 4. Reproduction

1. Create a throwaway "victim" user; note their real `users.user_hash` for later comparison only.
2. Create an `AOS_PDF_Templates` record whose body contains only the ordinary field `$aos_quotes_description` — nothing sensitive.
3. Create an `AOS_Quotes` record: `description = "$users_user_hash"` (plain text, the injection), `assigned_user_id = <victim>`.
4. Trigger the ordinary, authenticated action (`request.http`):
   ```
   GET /index.php?entryPoint=generatePdf&module=AOS_Quotes&uid=<quote>&templateID=<template>&task=email
   ```

Run `./run.sh`. Observed:
```
[PROOF] the merged email body contains the VICTIM'S REAL user_hash
        ($2y$10$Acb4wZZu79O0FN9hrgnlgeuiwck0VnpFHYw2CsbsxNw0wKM7kbas.) inside our marker
        tokens -- exfiltrated purely by putting the literal string '$users_user_hash' in
        an ordinary Quote record field and letting a completely unrelated, benign
        template merge run.
==> VULN-090: CONFIRMED — second-order injection exfiltrated victim mod_605fad0e's real
    bcrypt user_hash via an ordinary record field + a benign template merge
```
Full merged body: `evidence/merged_email_body.txt` / `response.txt`; full transcript: `run.log`.

**Key-name transparency note**: this reproduction uses `templateParser`/`generatePdf.php` (token `$users_user_hash`, plural) rather than the report's headline `aowTemplateParser`/`actionSendEmail.php` citation (token `$user_user_hash`, singular) — both classes share the identical vulnerable `parse_template_bean()`/sequential-mutation sink; only the bean-key prefix differs, because `aowTemplateParser` remaps bean names through a `$beanList` lookup. This path was chosen because it is synchronous and needs no AOW workflow queue, letting the core defect be proven live rather than deferred to NEEDS_MANUAL. See `notes.md`'s "If NEEDS_MANUAL" section for the precise, separately-scoped checklist to additionally reproduce the literal `$user_user_hash` / fully-unauthenticated WebToLead variant.

## 5. Impact

**Demonstrated here**: any authenticated user able to create/edit an `AOS_Quotes` (or similarly template-merged) record and trigger its own template actions exfiltrates the real password hash of any user they can name via `assigned_user_id` — a low bar in most role configurations (Quotes are typically sales-role-writable, not admin-only). The hash is a standard bcrypt-of-md5 value; offline cracking cost is whatever bcrypt's cost factor implies, but the attacker chose the target, so a weak/reused password among the exfiltrated hashes is a realistic, attacker-favorable bet — and if the legacy-MD5 weakness (VULN-037) applies to the target account instead, cracking is far faster.

**Amplification (analytically supported, not independently re-driven — see checklist in notes.md)**: because WebToLead lets an *unauthenticated* submitter control both `assigned_user_id` and free-text fields on the resulting Lead (documented separately in this audit), and because a lead auto-responder workflow is a common, realistic real-world configuration, the same mechanism is reachable **pre-authentication** wherever such a workflow exists — turning this into a zero-click, unauthenticated path to an admin's password hash (choose the admin as `assigned_user_id`), chaining directly to the RCE at VULN-011.

## 6. Suggested fix

1. **Honor the existing denylist in the merge itself**, not just the UI picker:
   ```php
   if (in_array($fieldName, $GLOBALS['badFields'][$focus->module_dir] ?? [], true)) {
       continue;   // never enter sensitive fields into $repl_arr at all
   }
   ```
2. **Single-pass substitution**: build the complete replacement map across *all* beans first, then perform exactly one `strtr($string, $repl_arr)` (or a `preg_replace_callback` over `\$[a-z0-9_]+` tokens looked up in the map) — never re-scan already-substituted output for further tokens.
3. Clear `user_hash` (and any other `sensitive`-flagged field) when loading the `Users` bean specifically for merge purposes, as defense in depth even if (1)/(2) are somehow bypassed elsewhere.

## 7. References

- CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), CWE-522 (Insufficiently Protected Credentials).
- Second-order injection as a general pattern: OWASP Testing Guide, "Testing for Stored Input Handling" (the same "data becomes code in a later context" shape as second-order SQLi/XSS): https://owasp.org/www-project-web-security-testing-guide/
- CVE-2022-45186 (distant cousin — a different SuiteCRM merge-context field-recovery issue, cited as related prior art in the static finding).
- Technique used: constructing a deliberately *benign-looking* template (only an ordinary field reference) and delivering the actual sensitive-value trigger entirely through record data — isolates and proves the "attacker needs only a text field, not template access" claim precisely.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory Database query `suitecrm template` — two results: CVE-2026-108713 / GHSA-8vgh-x9vp-8w93 (missing authorization on the `setCampaignMarketingAndTemplate` entry point, `WizardCampaignSave.php`, through 7.15.2) and CVE-2020-15301 (CSV injection); neither concerns `templateParser::parse_template_bean()` or merge-token expansion.
2. Fetched GHSA-m5xj-rrwv-g3q3 (CVE-2026-63217) — IDOR in the same `generatePdf` entry point (`BeanFactory::getBean()` with no ACL), fixed 7.15.2; no mention of template merge, `user_hash` or `templateParser`.
3. CVE-2022-45186 (cited by the scanner) — PoC fetched: reads `user_hash` via `getEditFieldHTML`; different mechanism (direct field render, not second-order merge).
4. CVE-2026-29107 / GHSA-g7cv-4ghj-x98h — SSRF via `<img>` in PDF templates (same PDF-template subsystem, different class).
5. Upstream diffs of `modules/AOS_PDF_Templates/templateParser.php` in v7.14.4, v7.14.5 and v7.15.1 (GitHub compare API) — discount/percentage formatting and boolean-label changes only; the sequential `str_replace` over the mutating string and the absence of a sensitive-field filter are unchanged through 7.15.2.
6. Full SuiteCRM GHSA catalogue (77 advisories through 2026-10-12) — no advisory on merge-token injection, template-variable expansion, or `user_hash` disclosure via templates.
(Note: the shared WebSearch budget was exhausted before this folder; checks were made by direct fetch of the advisory databases, CVE.org records, the cited PoC and the upstream repository.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-63217 / GHSA-m5xj-rrwv-g3q3 — `generatePdf` IDOR; same entry point, different bug (object-level authz rather than merge semantics).
- CVE-2022-45186 — `user_hash` recovery via `getEditFieldHTML`; same impact (hash disclosure), different vector.
- CVE-2026-29107 / GHSA-g7cv-4ghj-x98h — PDF-template SSRF; same subsystem, different class.
- CVE-2026-108713 / GHSA-8vgh-x9vp-8w93 — EmailMarketing/template reassignment authz; different component.

**Reasoning:** No public advisory describes record data being re-parsed as merge syntax by a later bean pass in `templateParser`/`aowTemplateParser`, nor the resulting `$users_user_hash` expansion; the parser's substitution loop has only received formatting changes upstream. Confidence is moderate because the PDF/template subsystem and `user_hash` exposure have both drawn repeated public reports (three advisories on `generatePdf`/PDF templates in 2026 alone), so a parallel private report is plausible, and the impact depends on a merge workflow existing.
