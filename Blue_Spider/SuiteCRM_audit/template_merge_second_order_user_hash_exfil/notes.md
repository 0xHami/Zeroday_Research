# VULN-090 — Second-order merge-token injection → exfiltration of the assigned user's `user_hash`

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: High (CVSS 8.0)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T23:32Z

## Preconditions
- A throwaway "victim" user (`_common.create_user()`) — any account whose password hash is the target; its real bcrypt `user_hash` is read from the DB *only* for comparison/verification, never used as an input.
- An `AOS_PDF_Templates` record whose body contains **only** the ordinary, legitimate merge field `$aos_quotes_description` — nothing sensitive typed into the template itself.
- An `AOS_Quotes` record whose own `description` field (plain user-editable text) is set to the literal string `$users_user_hash`, with `assigned_user_id` set to the victim.

## Request
See `request.http`:
```
GET /index.php?entryPoint=generatePdf&module=AOS_Quotes&uid=<quote>&templateID=<template>&task=email HTTP/1.1
Cookie: PHPSESSID=<admin-session>
```
An ordinary, authenticated "compose an email from this quote's template" action — not a special/crafted endpoint.

## Response
See `response.txt` / `evidence/merged_email_body.txt`. The resulting `Emails` draft's stored body (`emails_text.description_html`):
```
SECOND-ORDER-LEAK-START[$2y$10$Acb4wZZu79O0FN9hrgnlgeuiwck0VnpFHYw2CsbsxNw0wKM7kbas.]SECOND-ORDER-LEAK-END
```
The bracketed value is byte-for-byte identical to the victim's real `users.user_hash`, independently read from the DB before the merge ran.

## Observation
Matches the static finding's mechanism precisely: `parse_template($string, $object_arr)` (`modules/AOS_PDF_Templates/templateParser.php`) calls `parse_template_bean()` once per bean, **in the order beans appear in `$object_arr`** — the base `AOS_Quotes` record first, the assigned `Users` bean appended after (`generatePdf.php`: `$object_arr[$bean->module_dir]=$bean->id;` then later `$object_arr['Users']=$bean->assigned_user_id;`). During the FIRST (Quotes) pass, `$aos_quotes_description` is substituted with the record's raw field value — which is the literal string `$users_user_hash` — inserting that literal text into the shared, mutated `$string`. During the SECOND (Users) pass, a fresh `str_replace("$users_user_hash", <real hash>, $string)` call re-scans the now-mutated string and expands the literal text left behind by the first pass into the real secret. Neither pass is aware of the other; the vulnerability is exactly this sequential-mutation "second-order" interaction, reproduced deterministically.

## Key-name note (full transparency)
The report's headline citation is `modules/AOW_Actions/actions/actionSendEmail.php` (an AOW workflow "Send Email" action), which merges via `aowTemplateParser` — a sibling class that remaps the Users bean's key through a `$beanList` lookup to the **singular** `user`, producing the literal token `$user_user_hash`. This validation instead exercises `modules/AOS_PDF_Templates/templateParser.php` directly (the exact file/lines the report cites for the `repl_arr`-build and sequential-`str_replace` defects — `aowTemplateParser` inherits `parse_template_bean()` from this same class) via the synchronous, authenticated-only `generatePdf.php` caller, which keys the Users bean off `$focus->table_name = "users"` (plural), producing `$users_user_hash` instead. Both call sites share the **identical vulnerable sink**; only the bean-name prefix differs. This path was chosen because it requires no AOW workflow/scheduler queue to reach — letting the core defect be proven live end-to-end in this validation window rather than deferred.

## Side effects
- One throwaway victim user (`mod_605fad0e`).
- One `AOS_PDF_Templates` record and one `AOS_Quotes` record (both clearly named with the `tmpl_`/random-suffix convention).
- One `Emails` draft record containing the victim's real password hash in its body — left in place as evidence (harmless in this throwaway lab; in a real remediation this draft itself would need clearing).

## Research & references
- CWE-200 (Exposure of Sensitive Information), CWE-522 (Insufficiently Protected Credentials); the injection mechanic itself is a template/merge-engine analog of second-order injection (cf. CWE-77 family "downstream re-interpretation of stored data").
- Distant cousin CVE-2022-45186 ("recover arbitrary field" via a different SuiteCRM merge context) — cited in the static finding as related prior art; the sequential-`str_replace`-over-a-mutating-string mechanic exploited here is a distinct, more specific mechanism.
- Technique used: construct a completely ordinary, benign-looking template (referencing only a normal merge field) and let the actual sensitive-value substitution arrive entirely through record data — directly demonstrates "you don't need control of the template, only a text field on a record wired to any template."

## If NEEDS_MANUAL (scope of what was NOT additionally re-driven)
The fully unauthenticated **WebToLead** amplification described in the static finding (attacker submits a public lead-capture form, setting their own `description` field to the merge token and choosing `assigned_user_id`, then a pre-existing lead auto-responder workflow fires the merge with no login at all) was not separately re-driven end-to-end in this validation — it requires standing up a real `AOW_WorkFlow`/`AOW_Action` "Send Email" auto-responder wired to `Leads`, which in turn depends on this codebase's workflow scheduler/queue rather than a synchronous action. The sink and mechanism proven above are identical to what that chain would exercise; what remains for a human to additionally confirm the fully-unauthenticated variant:
1. Create an `AOW_WorkFlow` on `Leads`, flow type "On Save", with a condition that always matches new leads.
2. Attach an `AOW_Action` of type "Send Email" using a template whose body includes `$leads_description` (or any Lead field the WebToLead form exposes) and confirm it is addressed using the Lead's own submitted email.
3. Ensure `assigned_user_id` is attacker-settable via the public WebToLead form (already documented separately as VULN-059 in this audit).
4. Submit the public `entryPoint=WebToLeadCapture` (or equivalent) form, unauthenticated, with `description=$user_user_hash` (note: literal singular form, matching the AOW path's key) and `assigned_user_id=<target>`.
5. Wait for / trigger the scheduler to process the AOW queue, then inspect the resulting sent email for the target's real `user_hash`.
Observation that would confirm: the delivered/archived email body contains the target user's real bcrypt hash, reached with zero authentication at any step.
