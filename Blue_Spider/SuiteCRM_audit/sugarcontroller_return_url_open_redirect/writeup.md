# VULN-054 — SugarController Post-Save/Delete Redirect to Raw `return_url` (Framework-Wide Open Redirect)

**ID**: VULN-054
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`), commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1 6.1** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**Status**: **CONFIRMED (dynamic)**
**Auth required**: Any authenticated user — the redirect fires in the victim's own session; no elevated privilege needed, and it is reachable via *any* `SugarController`-routed save/delete across the classic-MVC surface, not just one module.
**What an attacker gains**: A link to a legitimate, everyday CRM action (e.g. "delete this note") that, after completing normally, 301-redirects the victim's browser off the trusted CRM origin to any URL the attacker names.

## Summary

Every classic-MVC module that extends `SugarController` funnels its post-save and post-delete redirect through one shared base-controller code path. When the request carries a `return_url` parameter, that value is used **as the redirect target with no validation whatsoever** — no same-origin check, no scheme allow-list, nothing. Because this is the *common* return path shared by essentially every save/delete action in the application, a single missing check turns the entire classic-MVC action surface into an open-redirect delivery mechanism.

## How it works (mechanism & code trace)

**Entry point** — any `module=<X>&action=Delete` (or `Save`) request reaches `SugarController::process()` (`include/MVC/Controller/SugarController.php:452-479`), which after `loadBean()`/`handle_action()` calls `$this->redirect()` (`:475`) — a generic step, not specific to any one module.

**Sink hop 1** — `post_delete()` (`include/MVC/Controller/SugarController.php:732-755`):
```php
protected function post_delete()
{
    if (empty($_REQUEST['return_url'])) {
        $return_module = isset($_REQUEST['return_module']) ? $_REQUEST['return_module'] : $GLOBALS['sugar_config']['default_module'];
        $return_action = isset($_REQUEST['return_action']) ? $_REQUEST['return_action'] : $GLOBALS['sugar_config']['default_action'];
        $return_id     = isset($_REQUEST['return_id']) ? $_REQUEST['return_id'] : '';
        $url = "index.php?module=" . $return_module . "&action=" . $return_action . "&record=" . $return_id;
    } else {
        $url = $_REQUEST['return_url'];          // :746 — attacker-controlled, unvalidated
    }
    ...
    $this->set_redirect($url);                    // :754
}
```
Note the asymmetry that makes this a real defect and not a design choice: when `return_url` is **absent**, the framework deliberately builds a safe, relative `index.php?module=...` URL (`:744`). The *only* unguarded branch is the one an attacker controls.

**Sink hop 2** — `set_redirect()` stores `$url`; `SugarApplication::redirect()` (`include/MVC/SugarApplication.php:639-671`) emits it:
```php
header('HTTP/1.1 301 Moved Permanently');
header("Location: " . $url);                      // :664-665
```
No `parse_url()`, no host comparison, no encoding — `$url` reaches the `Location` header byte-for-byte.

**The defect, pinpointed**: `include/MVC/Controller/SugarController.php:746` — `$url = $_REQUEST['return_url'];` — is the one line that needs a same-origin check and doesn't have one, despite the file's own author already knowing how to build a safe fallback three lines earlier.

## Why it is a vulnerability (reasoning)

`return_url` exists so that, e.g., a subpanel's "delete and come back to where I was" UX works — its *intended* range of values is internal SuiteCRM URLs (list views, detail views), which is exactly what the empty-`return_url` fallback branch constructs. Accepting an **externally supplied absolute URL** for that same parameter, with no check that it stays inside the app, breaks the implicit contract that "the app decides where you land after an action, not the query string." Because save/delete are routine, frequent actions that any authenticated user performs constantly, and because `checkHTTPReferer()` already exists and *is* enforced on the delete action itself (proving the framework has anti-CSRF infrastructure and applies it here) — the redirect target is simply never run through the equivalent check. This is not an intentional "trust the caller" design: the safe-fallback branch three lines above proves the framework's own default behavior is to construct a same-origin URL; the vulnerability is that the escape hatch (`return_url`) has no boundary at all.

## Reproduction

From a clean state (verified 2026-09-28):

1. **Setup**: a fresh low-privileged user (`mod_bf71d83d`, provisioned via the standard admin-editing-another-user flow) creates a Note they own (`ec1267f4-c9c1-4d0f-855c-998323c4ea6c`) via legacy REST `set_entry`.
2. **Attack** (`request.http`), sent in that user's own authenticated web session:
   ```
   GET /index.php?module=Notes&action=Delete&record=ec1267f4-c9c1-4d0f-855c-998323c4ea6c&return_url=https://evil-cvehunter-c054_505001ad.example/pwn HTTP/1.1
   Host: localhost:33116
   Referer: http://localhost:33116/index.php?module=Notes&action=DetailView&record=ec1267f4-c9c1-4d0f-855c-998323c4ea6c
   ```
   (The same-origin `Referer` is only there to satisfy the unrelated, working `checkHTTPReferer()` CSRF gate on the *delete* action itself — see notes.md. It does not touch the redirect-validation defect being demonstrated.)
3. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log` — observed output ends:
   ```
   [PROOF] HTTP 301 Moved Permanently
   [PROOF] Location: 'https://evil-cvehunter-c054_505001ad.example/pwn'
   [PROOF] notes.deleted for ec1267f4-c9c1-4d0f-855c-998323c4ea6c = '1' ...
   [OK] Delete executed for real (deleted=1) AND the trusted CRM origin redirected the user's browser off-site, verbatim, via return_url.
   ==> VULN-054: CONFIRMED — module=Notes&action=Delete&return_url redirected (HTTP 301) to https://evil-cvehunter-c054_505001ad.example/pwn; notes.deleted=1
   ```
   Exit code `0`.
4. Observable proof: `response.txt` shows `HTTP/1.1 301 Moved Permanently` / `Location:` exactly equal to the attacker URL; a direct DB query (`docker compose exec db mysql ...`) confirms `notes.deleted=1` for the acted-on record, proving this was genuine `post_delete()` traffic and not a short-circuited error page.

## Impact

Because the vulnerable code path is the **shared base-controller redirect handler**, it is reachable from essentially every classic-MVC module's save/delete action (Notes, Accounts, Contacts, Cases, …) — an attacker only needs a link to *any* legitimate action the victim is willing to click (or that fires automatically, e.g. from an auto-submitting form/image on a hostile page, subject to the CSRF Referer gate already covering the action itself). After the action completes normally — the victim sees nothing wrong, their delete/save really happened — their browser is bounced off the trusted CRM domain to a phishing page, OAuth-relay endpoint, or malware landing page. No direct data disclosure from SuiteCRM itself; the damage is entirely on the phished/redirected user, and — because this is the framework-wide default handler — the blast radius spans the whole classic-MVC module surface rather than one form. Same open-redirect family as VULN-005, VULN-020, VULN-055, VULN-056.

## Suggested fix

Before `set_redirect($url)` at `include/MVC/Controller/SugarController.php:746`, validate `return_url` as same-origin or relative, falling back to the already-present safe builder:
```php
} else {
    $candidate = $_REQUEST['return_url'];
    $host = parse_url($candidate, PHP_URL_HOST);
    $siteHost = parse_url($GLOBALS['sugar_config']['site_url'] ?? '', PHP_URL_HOST);
    $url = ($host === null || $host === $siteHost)
        ? $candidate
        : "index.php?module=" . $GLOBALS['sugar_config']['default_module']
          . "&action=" . $GLOBALS['sugar_config']['default_action'];
}
```
Principle: allow-list same-origin/relative destinations; since a safe fallback already exists in this exact function, route untrusted values through it instead of trusting them verbatim.

## References

- CWE-601: URL Redirection to Untrusted Site ('Open Redirect') — https://cwe.mitre.org/data/definitions/601.html
- OWASP Unvalidated Redirects and Forwards Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- PortSwigger Web Security Academy, "Open redirection" — https://portswigger.net/web-security/dom-based/open-redirection
- GHSA-hcw8-p37h-8hrv / CVE-2026-29105 — open-redirect advisory class cited across this report's redirect cluster (this is the framework-wide base-controller instance, distinct from the WebToLead/formbase-specific advisories).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 68 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM CVE-2026-29105 open redirect` — CVE-2026-29105 / GHSA-9crg-83cg-wv74 is the *unauthenticated WebToLead capture* POST-parameter redirect (fixed 7.15.1); not the SugarController path.
2. `SuiteCRM "return_url" open redirect SugarController post_delete post_save` — no result mentions `return_url`, `SugarController`, `post_save` or `post_delete`.
3. `SuiteCRM open redirect CVE return_url vulnerability` — only CVE-2026-29105, CVE-2024-36406, CVE-2020-15300 (Documents SVG); none reference `return_url`.
4. `GHSA-hcw8-p37h-8hrv SuiteCRM` + fetched advisory — CVE-2024-36406 "Open redirects" (fixed 7.14.4) names no component; the v7.14.3..v7.14.4 diff (GitHub compare API) shows the fix added `check_trusted_hosts()` (Host-header allow-list) and `isWebToLeadAllowedRedirectHost()` (WebToLead), and did not touch `include/MVC/Controller/SugarController.php` or `SugarApplication::redirect()`.
5. `SuiteCRM open redirect "action=Delete" OR "action=Save" "return_url" phishing` (extended) — no relevant results.
6. `huntr SuiteCRM open redirect return_url` — no huntr report; same three CVEs only.
7. GitHub commit history of `include/MVC/Controller/SugarController.php` (API) — no security-related change since 2021 (only PHP 8.x compatibility and entry-point commits through 2025-07).
8. Full SuiteCRM GHSA catalogue (77 published advisories, through 2026-10-12) reviewed — only two open-redirect advisories (GHSA-hcw8-p37h-8hrv, GHSA-9crg-83cg-wv74), neither in this component.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2024-36406 / GHSA-hcw8-p37h-8hrv — "Open redirects", fixed 7.14.4; the shipped fix is a trusted-Host-header check plus a WebToLead redirect allow-list, not the `return_url` branch of `SugarController::post_delete()/post_save()`, which is unchanged in 7.15.2.
- CVE-2026-29105 / GHSA-9crg-83cg-wv74 — unauthenticated open redirect in `modules/Campaigns/WebToLeadCapture.php` (fixed 7.15.1); different component.
- CVE-2020-15300 — open redirect via crafted SVG in the Documents module; different component and vector.

**Reasoning:** Both public SuiteCRM open-redirect advisories are vague in text, but their shipped patches (verified from the upstream diffs) target the WebToLead capture flow and Host-header trust, not the framework-wide `return_url` branch in the base controller, which is still raw in 7.15.2 (the latest release) and has no fixing commit upstream. Caveat: open redirect is a recurring class in this project and GHSA-hcw8-p37h-8hrv is titled in the plural with no detail, so a private report naming `return_url` could exist; the same code is inherited from SugarCRM CE and a very old SugarCRM-era report could not be fully excluded (WebSearch budget was exhausted before a SugarCRM-specific query could run).
