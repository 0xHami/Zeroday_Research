# VULN-005 — Unauthenticated open redirect in Web-to-Lead / Web-to-Person capture

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 3.1 6.1 — `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:39:02Z

## Preconditions
- None. Fully unauthenticated. No campaign, lead, or account is created or required.
- Confirmed the lab's live `config.php` (inside the app container) carries the
  fail-open default: `web_to_lead_allowed_redirect_hosts => array()` (empty array),
  via `docker compose -p cvehunterlab_suitecrm exec -T app grep -n web_to_lead config.php`
  → `464:  'web_to_lead_allowed_redirect_hosts' =>` followed by an empty `array()`.

## Request
See `request.http`. Single unauthenticated POST:
```
POST /index.php?entryPoint=WebToLeadCapture HTTP/1.1
Host: localhost:33116
Content-Type: application/x-www-form-urlencoded

redirect=https://evil-cvehunter-w2l_4aac3760.example/phish
```
Note `campaign_id` is deliberately omitted (see Observation below — this is a
stronger/simpler trigger than the report's original reproduce steps, which assumed
a valid `campaign_id` was required).

## Response
See `response.txt`:
```
HTTP/1.1 301 Moved Permanently
Location: https://evil-cvehunter-w2l_4aac3760.example/phish
```
No `Set-Cookie` for an authenticated session is consumed or required; the
`PHPSESSID` cookie set here is just PHP's default anonymous session.

## Observation
Static finding predicted the redirect requires a `campaign_id` matching a real
campaign (per the report's reproduce steps and `WebToLeadCapture.php:66`
`if (isset($_POST['campaign_id']) && !empty($_POST['campaign_id']))`). Reading the
full control flow (`modules/Campaigns/WebToLeadCapture.php:66-276`) shows the
entire lead-capture block (lines 66-260) is skipped whenever `campaign_id` is
absent/empty, and execution falls straight through — with no intervening `die()`
or `exit()` on that path — to the unconditional, unauthenticated redirect check
at line 262:
```php
// modules/Campaigns/WebToLeadCapture.php:262-272
if (!empty($_POST['redirect']) && isWebToLeadAllowedRedirectHost($_POST['redirect'] ?? '')) {
    ...
    $header_URL = "Location: {$_POST['redirect']}";
    SugarApplication::headerRedirect($header_URL);
    die();
}
```
So the bug is reachable with **zero preconditions** — not even a valid
`campaign_id` is needed, which makes this slightly more severe/easier to weaponize
than the report's reproduce steps suggested (mass-spam a redirect link with no
setup at all). `isWebToLeadAllowedRedirectHost()` (`include/utils.php:6439-6469`)
returns `true` (fail-open) because `$sugar_config['web_to_lead_allowed_redirect_hosts']`
is an empty array in this lab's config — `empty([])` is `true` in PHP, so the
allow-list is a no-op. Confirmed dynamically: HTTP 301 with `Location:` set
verbatim to the attacker-supplied absolute URL.

## Side effects
None beyond the HTTP response — no DB rows created, no session established
(pure reflected redirect, no stored state).

## Research & references
- OWASP Unvalidated Redirects and Forwards Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- PortSwigger Web Security Academy — "DOM-based open redirection" / "Open redirection":
  https://portswigger.net/web-security/dom-based/open-redirection
- CWE-601: https://cwe.mitre.org/data/definitions/601.html
- GHSA-9crg-83cg-wv74 / CVE-2026-29105 (cited by the report as the known-issue match).

## If FAILED
N/A — confirmed.
