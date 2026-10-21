# VULN-082 — Legacy web service leaks OAuth token & client-secret material

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: High (conditional — OAuth1/OAuth2/EAPM in use) (CVSS 3.1 6.5 — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: see `run.log`

## Environment note (precondition the lab was missing, not part of the vulnerability)
`Api/V8/OAuth2/{private,public}.key` did not exist in this lab build (`league/oauth2-server`'s
`CryptKey` threw `LogicException: Invalid key supplied` on every `/Api/access_token` call — visible
in `docker logs cvehunterlab_SuiteCRM_app`). This is a one-time missing install step (SuiteCRM's V8
API requires an RSA keypair at that path; stage 00 did not generate one), unrelated to this finding.
Generated it the standard way so V8 OAuth2 works at all in this lab:
```
docker exec cvehunterlab_SuiteCRM_app sh -c "
  openssl genrsa -out /var/www/html/Api/V8/OAuth2/private.key 2048
  openssl rsa -in /var/www/html/Api/V8/OAuth2/private.key -pubout -out /var/www/html/Api/V8/OAuth2/public.key
  chown www-data:www-data /var/www/html/Api/V8/OAuth2/private.key /var/www/html/Api/V8/OAuth2/public.key
  chmod 600 /var/www/html/Api/V8/OAuth2/private.key; chmod 644 /var/www/html/Api/V8/OAuth2/public.key"
```
After this, `/Api/access_token` mints real signed JWTs as expected. This is a lab-environment fix,
not a step an attacker would need (the vulnerability itself needs only that *some* OAuth2 tokens
exist, which is true of any real deployment that uses OAuth1/OAuth2/EAPM).

## Preconditions
- OAuth2Clients record `44f11778-3f51-4f96-bbea-16f4a6d0879b` created by admin via legacy
  `set_entry`, with `secret` set to a locally-computed `sha256(plaintext)` hex digest (mirrors what
  `OAuth2Clients::save()`'s `$_REQUEST['new_secret']` hook would do — see
  `modules/OAuth2Clients/OAuth2Clients.php:100-104`), `allowed_grant_type=password`.
- A REAL V8 OAuth2 token pair minted for **admin** (`assigned_user_id='1'`) via
  `POST /Api/access_token` (`grant_type=password`) using that client — genuine, unpredictable
  secret material, not fabricated.
- Ordinary low-priv user `mod_2752acc0` — **no ACL/Role restriction was set up for this finding**;
  the leak is unconditional (see Observation).
- Ground truth captured directly from the `oauth2tokens` DB row (admin/db access, for verification
  only): `access_token='5c44d555...bdf1c7102066b7e16fead29'`,
  `refresh_token='189edb64...073eaef34fcfba8f3f89c0fbb8'`. Note: the client-visible `access_token`
  is a signed JWT and the client-visible `refresh_token` is a Defuse-encrypted blob — **neither**
  is what's stored verbatim; the DB stores only League's internal identifier
  (`AccessTokenRepository::persistNewAccessToken`/`RefreshTokenRepository::persistNewRefreshToken`,
  both call `->getIdentifier()`). Decoding the minted JWT's `jti` claim independently confirms it
  equals the DB `access_token` value.

## Request
```
POST /service/v4_1/rest.php
method=get_entry&input_type=JSON&response_type=JSON&rest_data=
  ["<low-priv session>","OAuth2Tokens","587e1eab-f82e-4086-9e08-1919046f1d45",
   ["id","access_token","refresh_token","assigned_user_id","state","client"],[]]
```
(`request.http`; also probed `get_entry_list` on both `OAuth2Tokens` and `OAuth2Clients`, saved
under `evidence/`)

## Response
```json
{"entry_list":[{"id":"587e1eab-...","module_name":"OAuth2Tokens","name_value_list":{
  "access_token":{"value":"5c44d555e138c322baf5446a12f5fc5aad561a3b826cd5cf53cac8fa3bdf1c7102066b7e16fead29"},
  "refresh_token":{"value":"189edb6420e84b4c2b7039b692e1b03e25dd5d0e0f163501edc79e073eaef34fcfba8f3f89c0fbb8"},
  "assigned_user_id":{"value":"1"},
  "client":{"value":"44f11778-3f51-4f96-bbea-16f4a6d0879b"}
}}]}
```
`OAuth2Clients` (`get_entry_list`, `response.txt`-adjacent evidence): `secret` field returned as
`771a62257fa398d39ada886ac06a24284af726292162c925dd917284608922ee` — exact match to the sha256 we set.

## Observation
Matches the static finding: `OAuth2Tokens`/`OAuth2Clients` are in `$modInvisList`
(`include/modules.php:530/534`), forced to `read_only` for **every** caller unconditionally
(`SoapHelperWebService.php:420-422` / `soap/SoapHelperFunctions.php:336-338`), and
`clean_sensitive_data()` (`include/utils.php:5757-5771`) only blanks fields flagged `sensitive`,
never `api-visible=false` — which is what `access_token`/`refresh_token`/`state`
(`modules/OAuth2Tokens/vardefs.php`) and `secret` (`modules/OAuth2Clients/vardefs.php:73`) are
actually flagged with. Live: a low-priv user with **no** special ACL/Role read another user's
(admin's) live token material and the client secret hash, unredacted. One nuance found only by
running it: `get_entry_list` on `OAuth2Tokens` row-scopes results to the caller's own
`assigned_user_id` (an application-level "my tokens" filter, not an ACL control) — so a plain
listing call alone shows nothing. The BOLA is still complete: a direct by-id `get_entry` call
(exactly VULN-001's `retrieve`-by-id shape) bypasses that row-scope entirely and returns the full
row for a target id the low-priv caller has no relationship to.

## Side effects
1 throwaway OAuth2Clients record, 1 real OAuth2Tokens row (admin's), 1 throwaway low-priv user.
No destructive changes. (Plus the one-time key-generation environment fix noted above.)

## Research & references
CWE-213 (Exposure of Sensitive Information Due to Incompatible Policies) / CWE-359. OWASP Cheat
Sheet — OAuth2: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html (secrets/tokens
must never be exposed via a general-purpose read API). League OAuth2 Server docs on token storage
(identifier vs. issued token) explain the JWT/encrypted-blob-vs-stored-identifier distinction used
above: https://oauth2.thephpleague.com/
