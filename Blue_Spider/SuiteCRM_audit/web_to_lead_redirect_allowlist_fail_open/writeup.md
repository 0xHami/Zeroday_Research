# VULN-005 — Unauthenticated Open Redirect in Web-to-Lead Capture (default config)

**ID**: VULN-005
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`), commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb` (untagged `forkedSuite`/hotfix snapshot self-identifying as 7.15.2)
**Severity**: Medium — **CVSS 3.1 6.1** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**Status**: **CONFIRMED (dynamic)**
**Auth required**: None. Fully unauthenticated — no account, session, or valid campaign is needed.
**What an attacker gains**: A link on the trusted `suitecrm.example` (CRM) origin that silently 301-redirects any visitor to an attacker-chosen external site — the standard building block for credential phishing, OAuth/SSO return-flow abuse, and malware delivery "from a trusted sender."

## Summary

SuiteCRM's public Web-to-Lead capture form (`modules/Campaigns/WebToLeadCapture.php`), an unauthenticated entry point meant to receive lead-generation form submissions from external websites, honors a client-supplied `redirect` POST parameter and 301-redirects the visitor to it — **with no same-origin validation** — whenever the app's redirect allow-list is unconfigured. That allow-list ships **empty by default** (confirmed live in this lab's `config.php`), and the check function treats an empty allow-list as "allow everything." Any unauthenticated visitor who is lured to POST (or auto-submits via a hostile page) to this endpoint is bounced off the CRM's own domain to any URL the attacker chooses.

## How it works (mechanism & code trace)

**Entry point** — registered unauthenticated in `include/MVC/Controller/entry_point_registry.php:61`:
```php
'WebToLeadCapture' => array('file' => 'modules/Campaigns/WebToLeadCapture.php', 'auth' => false),
```
`SugarController::checkEntryPointRequiresAuth()` (`include/MVC/Controller/SugarController.php:1037-1048`) returns `false` for any registry entry with `'auth' => false`, so `index.php?entryPoint=WebToLeadCapture` is dispatched to the file with **no login check at all** (`handleEntryPoint()`, `SugarController.php:1013-1029`).

**Sink** — `modules/Campaigns/WebToLeadCapture.php:262-272`:
```php
if (!empty($_POST['redirect']) && isWebToLeadAllowedRedirectHost($_POST['redirect'] ?? '')) {
    if (headers_sent()) {
        ...
    } else {
        $header_URL = "Location: {$_POST['redirect']}";
        SugarApplication::headerRedirect($header_URL);
        die();
    }
}
```
`SugarApplication::headerRedirect()` (`include/MVC/SugarApplication.php:677-685`) strips the literal `Location:` prefix and calls `SugarApplication::redirect($href)` (`:639-671`), which emits `header("Location: " . $url)` **verbatim**, with a `301 Moved Permanently` status (`:664-665`) — no scheme/host check, no encoding.

**The gate that should stop this** — `isWebToLeadAllowedRedirectHost()` (`include/utils.php:6439-6469`):
```php
function isWebToLeadAllowedRedirectHost(string $url): bool {
    global $sugar_config;
    $redirectHost = getHostFromUrl($url);
    $allowedRedirectHosts = $sugar_config['web_to_lead_allowed_redirect_hosts'] ?? [];
    if (empty($allowedRedirectHosts)) {
        return true;                      // <-- fail-OPEN
    }
    foreach ($allowedRedirectHosts as $allowedRedirectHost) {
        ...
        if ($redirectHost === $allowedHost) {
            return true;
        }
    }
    return false;
}
```
The defect is the `if (empty($allowedRedirectHosts)) { return true; }` branch: an *unconfigured* allow-list is treated as "no restriction" instead of "restrict to same-origin" or "deny all." This lab's live `config.php` has the key present but empty (`'web_to_lead_allowed_redirect_hosts' => array()`), which is also SuiteCRM's shipped default — so this is not a lab misconfiguration, it is the out-of-the-box behavior.

**Reachability is even wider than the static finding assumed.** The redirect check at `:262` sits *outside* the `if (isset($_POST['campaign_id']) && !empty($_POST['campaign_id']))` block that spans `:66-260`. When `campaign_id` is omitted, that entire block is skipped (no `die()`/`exit()` on that path) and execution falls straight through to the vulnerable check — so **no valid `campaign_id` is required at all**, contrary to the original reproduce steps. The bug fires on the bare minimum: one POST parameter, zero setup.

## Why it is a vulnerability (reasoning)

The Web-to-Lead capture endpoint is *designed* to be embedded in third-party web pages and to run unauthenticated (that is its entire purpose — capturing leads from public marketing sites). That makes it a **public,零-privilege pivot point**: everything it emits is implicitly trusted by the visitor's browser as coming from the CRM vendor's domain. A `Location` header is a navigation primitive with no user-visible warning — the browser just goes. The code *has* a same-origin control (the allow-list check) sitting exactly where you'd expect it, which is what makes the fail-open default a real defect and not a documented feature: the control exists, is invoked, and is unconditionally bypassed by the common "I haven't configured this yet" state. A secure design would fail closed — treat an empty allow-list as "same-origin only," not "any origin." There is no compensating control elsewhere (no CSP `form-action`/`navigate-to`, no interstitial warning page for cross-origin targets).

## Reproduction

From a clean, unauthenticated state (verified 2026-09-28):

1. No setup. Confirmed the running lab's config carries the vulnerable default:
   ```
   docker compose -p cvehunterlab_suitecrm exec -T app grep -n web_to_lead config.php
   464:  'web_to_lead_allowed_redirect_hosts' =>
         array (
         ),
   ```
2. Single unauthenticated request (`request.http`):
   ```
   POST /index.php?entryPoint=WebToLeadCapture HTTP/1.1
   Host: localhost:33116
   Content-Type: application/x-www-form-urlencoded

   redirect=https://evil-cvehunter-w2l_4aac3760.example/phish
   ```
3. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log` — expected/observed output ends:
   ```
   [PROOF] HTTP 301 Moved Permanently
   [PROOF] Location: 'https://evil-cvehunter-w2l_4aac3760.example/phish'
   [OK] Unauthenticated request redirected the browser off-origin to the attacker URL, verbatim -- fail-open allow-list confirmed live.
   ==> VULN-005: CONFIRMED — unauth POST redirected (HTTP 301) to attacker origin https://evil-cvehunter-w2l_4aac3760.example/phish
   ```
   Exit code `0`.
4. Observable proof: `response.txt` shows `HTTP/1.1 301 Moved Permanently` with `Location:` equal, byte-for-byte, to the attacker URL supplied in the request body. See also `evidence/location_header.txt`.

## Impact

An attacker distributes a link such as `https://<real-suitecrm-host>/index.php?entryPoint=WebToLeadCapture` with a `redirect` (via a self-submitting HTML form, since the field is POST-only, or any auto-submit page) pointing at a look-alike login page. Because the initial hop is the victim's actual, trusted CRM vendor domain, this defeats casual URL inspection and is effective against:
- Credential phishing (look-alike SuiteCRM/SSO login).
- Abuse in any OAuth/SSO flow that trusts a redirect through this host as a "return" step.
- Bulk spam/malware campaigns that want a reputable sender domain in the first hop of a redirect chain.

No direct confidentiality/integrity/availability loss against SuiteCRM itself (hence Medium, not High) — the damage lands on the phished victim, not the CRM's data. Same open-redirect family as VULN-020, VULN-054, VULN-055, VULN-056 — several of these share the "fail-open/unchecked `return_url`" pattern across different entry points, which is worth fixing as one class rather than four separate patches.

## Suggested fix

In `isWebToLeadAllowedRedirectHost()` (`include/utils.php:6439-6469`), fail **closed**:
```php
$allowedRedirectHosts = $sugar_config['web_to_lead_allowed_redirect_hosts'] ?? [];
if (empty($allowedRedirectHosts)) {
    // No admin-configured allow-list: restrict to the app's own origin.
    $siteHost = getHostFromUrl($sugar_config['site_url'] ?? '');
    return $siteHost !== '' && $redirectHost === $siteHost;
}
```
Principle: an **allow-list**, not a **deny-list**, and an *unconfigured* allow-list must mean "nothing extra is allowed," not "everything is allowed."

## References

- CWE-601: URL Redirection to Untrusted Site ('Open Redirect') — https://cwe.mitre.org/data/definitions/601.html
- OWASP Unvalidated Redirects and Forwards Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- PortSwigger Web Security Academy, "Open redirection (reflected)" — https://portswigger.net/web-security/dom-based/open-redirection
- GHSA-9crg-83cg-wv74 / CVE-2026-29105 — "Unauthenticated Open Redirect in Leads WebToLead Capture" (fixed upstream 7.15.1; this commit-pinned checkout still carries the empty-allow-list default and was reproduced live above).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 35 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Fetched GHSA-9crg-83cg-wv74 / CVE-2026-29105 (the CVE cited above): "Unauthenticated Open Redirect in Leads WebToLead Capture", patched 7.15.1. The 7.15.1 release commit (7f2b384) changed `modules/Leads/Capture.php` (which at v7.15.0 redirected to a POST parameter with no validation; the file no longer exists at v7.15.1) and did not touch `modules/Campaigns/WebToLeadCapture.php`, `isWebToLeadAllowedRedirectHost()` or `SugarApplication.php`. That CVE therefore concerns the sibling Leads capture script, not this endpoint.
2. Fetched GHSA-hcw8-p37h-8hrv / CVE-2024-36406 "Open redirects" (patched 7.14.4): `WebToLeadCapture.php` at v7.14.3 has no host validation; from 7.14.4 onward it calls `isWebToLeadAllowedRedirectHost()`. The function is byte-identical at v7.15.0, v7.15.1 and the audited commit (empty allow-list returns true), and `web_to_lead_allowed_redirect_hosts` defaults to an empty array in `get_sugar_config_defaults()`.
3. SuiteCRM release notes 7.14.x and 7.15.x — no mention of the config key or of a fail-open default; the lab installs through the stock silent installer, so the empty list is the shipped default.
4. Commit history of `WebToLeadCapture.php` and `include/utils.php` on hotfix — nothing on this path after Nov 2025.
5. NVD SuiteCRM (107) / SugarCRM (66) descriptions — CVE-2017-14510 (SugarCRM WebToLeadCapture unvalidated redirect value) plus the two advisories above; nothing describes the fail-open default.
6. (Web search for `web_to_lead_allowed_redirect_hosts` could not be run — per-turn search budget exhausted.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2024-36406 / GHSA-hcw8-p37h-8hrv — the open redirect on this exact endpoint, "fixed" in 7.14.4 by introducing the allow-list whose empty-list fail-open behaviour is this finding.
- CVE-2026-29105 / GHSA-9crg-83cg-wv74 — the sibling `modules/Leads/Capture.php` redirect, fixed by removal in 7.15.1.
- CVE-2017-14510 — SugarCRM-era unvalidated redirect value in WebToLeadCapture (XSS).

**Reasoning:** The open redirect on this endpoint has been publicly reported and patched before (CVE-2024-36406), so the vulnerability itself is not novel; what no public source describes is that the patch's allow-list fails open when unconfigured, which is the shipped default, so a stock 7.15.2 install still redirects off-origin. This should be disclosed as an incomplete fix / insecure default of CVE-2024-36406 rather than a new issue, and the vendor may regard it as a configuration matter; confidence is accordingly low.
