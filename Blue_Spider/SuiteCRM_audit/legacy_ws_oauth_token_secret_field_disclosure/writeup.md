# VULN-082 — Legacy Web Service Leaks OAuth Token & Client-Secret Material

**ID**: VULN-082
**Software / Repository**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2, commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: High (conditional on OAuth1/OAuth2/EAPM being in use) — **CVSS 3.1 6.5** —
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (escalates further via the refresh-grant/ATO chain
noted in Impact)
**Status**: `CONFIRMED (dynamic)`
**Auth required**: Any authenticated web-service user (lowest privilege) — no special ACL/Role needed
**What an attacker gains**: Any other user's live OAuth2 access/refresh-token identifiers and any
OAuth2 client's `secret`, read straight out of modules that are supposed to be invisible/internal.

## Summary

`OAuth2Tokens`, `OAuth2Clients`, and `OAuthKeys` are "invisible" modules (`$modInvisList`) — they
have no navigation entry, no admin-facing ACL configuration UI, and their sensitive columns
(`access_token`, `refresh_token`, `state`, `secret`, `c_secret`) are all marked `api-visible=false`
in their vardefs specifically to keep them out of general-purpose read APIs. The legacy web-service
read gate, however, force-grants every caller `read_only` on every `$modInvisList` module
unconditionally, and the legacy serializer (`clean_sensitive_data()`) only ever blanks fields
flagged `sensitive` — it has never heard of `api-visible`. The result: any authenticated user, with
zero special privilege, can `get_entry`/`get_entry_list` these modules and read another user's live
OAuth token material and any client's secret. Live testing confirms this exactly: a freshly created,
completely unprivileged user read admin's real, just-minted OAuth2 access/refresh-token identifiers
and an OAuth2 client's secret hash, byte-for-byte.

## How it works (mechanism & code trace)

**Entry point**: `POST /service/v4_1/rest.php` with `method=get_entry` or `get_entry_list`,
`module_name=OAuth2Tokens` (or `OAuth2Clients`), any valid low-priv `session_id`.

**Gap 1 — the read gate force-allows these modules for everyone.**
`OAuth2Tokens`/`OAuth2Clients` are registered invisible — `include/modules.php:530-537`:
```php
$beanList['OAuth2Tokens'] = 'OAuth2Tokens'; ... $modInvisList[] = 'OAuth2Tokens';
$beanList['OAuth2Clients'] = 'OAuth2Clients'; ... $modInvisList[] = 'OAuth2Clients';
```
Every legacy-service caller's module-access list is built by
`get_user_module_list()`/`SoapHelperWebService::get_user_module_list()`
(`soap/SoapHelperFunctions.php:327-338`):
```php
$modules = query_module_access_list($user);
ACLController:: filterModuleList($modules, false);
global $modInvisList;
foreach ($modInvisList as $invis) {
    $modules[$invis] = 'read_only';                 // unconditional -- runs for EVERY caller
}
```
This loop runs **after** the normal role-derived list is computed and unconditionally sets these
modules to `read_only`, regardless of any Role/ACL configuration — there is no acl_actions
category for these modules to restrict in the first place, since they were never meant to be
reachable through the ACL-configurable UI at all.

**Gap 2 — the serializer only understands `sensitive`, never `api-visible`.**
`include/utils.php:5757-5771` (`clean_sensitive_data`):
```php
function clean_sensitive_data($defs, $data)
{
    foreach ($defs as $field => $def) {
        if (!empty($def['sensitive'])) {            // :5760  ONLY checks 'sensitive'
            if (is_array($data)) { $data[$field] = ''; }
            if ($data instanceof SugarBean) { $data->$field = ''; }
        }
    }
    return $data;
}
```
But the actual token/secret fields are flagged the *other* way — `modules/OAuth2Tokens/vardefs.php`:
```php
'access_token' => [ ... 'api-visible' => false, ... ],   // :85-91  no 'sensitive' key at all
'refresh_token' => [ ... 'api-visible' => false, ... ],  // :95-101
'state' => [ ... 'api-visible' => false, ... ],          // :125-131
```
and `modules/OAuth2Clients/vardefs.php:67-73` (`secret`) the same way. The V8 API team clearly knew
these fields needed hiding (that's what `api-visible=false` is *for*), but the legacy serializer's
denylist checks a different flag entirely, so it never blanks them.

**Live confirmation** (full transcript in `run.log`): admin minted a real OAuth2 token pair via
`/Api/access_token` (`assigned_user_id='1'`, i.e. admin). A brand-new, otherwise-unprivileged user
then called:
```
method=get_entry&rest_data=["<low-priv session>","OAuth2Tokens","<admin's token row id>",
  ["id","access_token","refresh_token","assigned_user_id","state","client"],[]]
```
and received the full row, including
`access_token=5c44d555e138c322baf5446a12f5fc5aad561a3b826cd5cf53cac8fa3bdf1c7102066b7e16fead29`
and `refresh_token=189edb6420e84b4c2b7039b692e1b03e25dd5d0e0f163501edc79e073eaef34fcfba8f3f89c0fbb8`
— an exact match for the values independently confirmed in the live `oauth2tokens` DB row.
`OAuth2Clients.secret` came back the same way, matching the sha256 the test set.

(One implementation nuance confirmed only by running it: `get_entry_list` on `OAuth2Tokens` applies
an application-level "my tokens" row-scope to `assigned_user_id`, unrelated to ACL — so a bare
listing call alone shows nothing. That scope does not apply to a direct by-id `get_entry`, which
is what actually demonstrates the BOLA — see Reproduction.)

## Why it is a vulnerability (reasoning)

The trust boundary here is explicit in the vardefs themselves: `api-visible=false` is the flag the
codebase's own API layer (V8) uses to keep a field out of general-purpose reads. The legacy
service's `clean_sensitive_data()` denylist checks a *different, narrower* flag (`sensitive`),
so fields the framework's authors clearly intended to hide from APIs sail through untouched on the
legacy channel. This is not an intentional "any authenticated user may read all OAuth tokens"
design — the V8 API for the same data goes out of its way to exclude these modules from
`$moduleList` entirely and to strip both `sensitive` **and** `api-visible=false`
(per the static finding's code comparison). The legacy channel doing neither is a gap between two
enforcement points for the same trust boundary, not a deliberate choice.

## Reproduction

1. **Preconditions**: admin creates an `OAuth2Clients` record and mints a real token pair via
   `/Api/access_token` for any user (here, admin). A brand-new, unprivileged user account exists —
   no ACL/Role setup needed. *(Lab note: this required generating a missing
   `Api/V8/OAuth2/{private,public}.key` RSA keypair first — a one-time environment gap unrelated to
   the vulnerability; see `notes.md`.)*
2. **Decisive request** (`request.http`):
   ```
   POST /service/v4_1/rest.php
   method=get_entry&input_type=JSON&response_type=JSON&rest_data=
     ["<low-priv session>","OAuth2Tokens","<victim token row id>",
      ["id","access_token","refresh_token","assigned_user_id","state","client"],[]]
   ```
3. Run `./run.sh` (`run.log` has the full transcript). Expected:
   ```
   ==> VULN-082: CONFIRMED — low-priv user (no special ACL) read admin's OAuth2Tokens row:
   access_token=5c44d555e138c322baf5446a... refresh_token=189edb6420e84b4c2b7039b6...
   (exact match to DB-verified minted values); OAuth2Clients.secret=771a62257fa398d39ada886a...
   (exact match)
   ```
4. **Observable proof**: `response.txt` / `evidence/low_priv_oauth2tokens_get_entry_response.json`
   contain the full unredacted row; `evidence/low_priv_oauth2clients_response.json` shows the
   leaked `secret`; `evidence/minted_v8_token_response.json` records the genuinely minted token
   pair used as ground truth.

## Impact

Any authenticated user — the lowest privilege level, with no special configuration required —
reads every other user's OAuth2 access/refresh-token identifiers and every OAuth2 client's secret,
plus (by the same mechanism, per the static finding) OAuth1 `c_secret`/`c_key` in `OAuthKeys`,
which has neither protective flag at all. Chained with the token-identifier material captured
here, and the latent `oauth2_encryption_key` default (`SCRM-DEFK`, when unset — see
[stage-05/07 notes cross-referenced in the report]), an attacker holding these identifiers and a
client secret is positioned to attempt refresh-grant token reconstruction for the victim,
escalating a confidentiality leak toward account takeover in deployments that never set a custom
encryption key. Even without that chain, exposing another user's OAuth session material and a
client's authentication secret to any low-privilege account is a direct violation of OAuth2's
credential-confidentiality model (see reference below). It also compounds
[VULN-001](../../vulns/VULN-001.md): the same `modInvis`/serializer gap is reachable via JSON-RPC
`retrieve` for non-`Users` modules too.

## Suggested fix

1. Remove `OAuth2Tokens`/`OAuth2Clients`/`OAuthKeys`/`OAuth2AuthCodes` from the legacy
   `modInvisList`-implies-`read_only` rule (`soap/SoapHelperFunctions.php:336-338` and
   `service/core/SoapHelperWebService.php:420-422`) — or require `is_admin` for read access.
2. Make `clean_sensitive_data()` (`include/utils.php:5757`) also blank any field with
   `api-visible === false`, not only `sensitive`:
   ```php
   if (!empty($def['sensitive']) || (isset($def['api-visible']) && $def['api-visible'] === false)) {
       ...
   }
   ```
3. Ensure `oauth2_encryption_key` is always a randomly generated per-install value, never the
   `SCRM-DEFK` fallback, closing the downstream refresh-grant chain even if the read gap above is
   later reintroduced elsewhere.

## References

- CWE-213 — Exposure of Sensitive Information Due to Incompatible Policies
- CWE-359 — Exposure of Private Personal Information to an Unauthorized Actor
- OWASP OAuth2 Cheat Sheet — token/secret confidentiality requirements: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
- League OAuth2 Server documentation (token identifier vs. issued-token encoding, used to explain why the DB value differs from the client-visible JWT/refresh blob): https://oauth2.thephpleague.com/
- Adjacent public issue class: CVE-2022-45186 ("recover arbitrary field" excessive-exposure class) — this finding is the concrete `modInvis`+`api-visible` instance of that same excessive-data-exposure pattern.
- Technique used: mint a real, independently DB-verified secret via the legitimate OAuth2 flow, then prove an unrelated low-privilege account can read it back unredacted through the legacy API (BOLA by-id read, same shape as VULN-001).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory Database query `suitecrm oauth` — 0 advisories.
2. Full SuiteCRM GHSA catalogue (77 advisories through 2026-10-12) reviewed — OAuth-related entries are GHSA-rc46-hjjp-4jv5 (V8 OAuth2 username enumeration, fixed 7.15.2) and GHSA-m6x8-3hxp-qxwv (V8 IDOR on user preferences / relationships, fixed 7.15.1); none concerns legacy `get_entry`/`get_entry_list` reads of `OAuth2Tokens`, `OAuth2Clients` or `OAuthKeys`.
3. CVE-2022-45186 (cited by the scanner) — the Orange Cyberdefense PoC fetched: it reads `user_hash` via `?action=getEditFieldHTML&module=Home&field=user_hash&id=1&current_module=Users`; a different endpoint, field and mechanism from the `modInvisList → read_only` + `clean_sensitive_data()` gap.
4. Full Disclosure Feb-2020 post (CVE-2020-8802 `action_saveHTMLField` bean manipulation) — different component.
5. v7.15.1..v7.15.2 compare (GitHub API) — the only OAuth2 module changes are cosmetic `listviewdefs.php` edits and a V8 `UserRepository` timing-equalisation fix; `include/utils.php::clean_sensitive_data()` and `service/core/SoapHelperWebService.php`'s `modInvisList` loop are unchanged.
6. GitHub commit history of `service/core/SugarWebServiceImpl.php` — no change to the legacy read path.
(Note: the shared WebSearch budget was exhausted before this folder; checks were made by direct fetch of the advisory databases, CVE.org records, the cited PoC and the upstream repository.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2022-45186 — authenticated recovery of an arbitrary field (incl. `user_hash`) via `getEditFieldHTML`; same "excessive field exposure" class, different endpoint and fields.
- GHSA-rc46-hjjp-4jv5 — V8 OAuth2 username enumeration; same OAuth2 subsystem, different bug.
- CVE-2026-29189 / GHSA-m6x8-3hxp-qxwv — V8 IDOR on user preferences/relationships; different API layer.

**Reasoning:** No advisory, CVE or fix addresses the legacy web service force-granting `read_only` on every `$modInvisList` module (including the OAuth token/client modules) combined with `clean_sensitive_data()` ignoring `api-visible=false`; the token/secret fields remain readable in the latest release. Confidence is moderate because SuiteCRM's legacy API has a dense history of field-exposure reports (CVE-2022-45186 and the `user_hash` guard show prior attention to this exact serializer) and a private report on OAuth modules specifically cannot be excluded without a general web search.
