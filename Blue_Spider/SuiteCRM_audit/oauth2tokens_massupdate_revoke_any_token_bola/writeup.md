# VULN-025 — `OAuth2Tokens massupdate` (mass[] branch) revokes/deletes any user's token by id (BOLA)

## 1. Header
- **Title:** Low-privilege user revokes/deletes any principal's OAuth2 token by id via `massupdate` `mass[]`
- **ID:** VULN-025 · **Software:** SuiteCRM · **Repository:** https://github.com/SuiteCRM/SuiteCRM
- **Affected version:** 7.15.2 (`suitecrm_version.php`) — commit-pinned `forkedSuite` snapshot · **Commit:** `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
- **Severity:** High · **CVSS 3.1:** 6.5 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H`
- **Status:** CONFIRMED (dynamic) · **Auth required:** any authenticated user
- **What an attacker gains:** targeted revocation/deletion of another user's (incl. admin's) OAuth2 access/refresh tokens → API denial-of-service / session lockout across the OAuth boundary.

## 2. Summary
`OAuth2TokensController::action_massupdate` has two branches. The `select_entire_list` branch is safely owner-scoped, but the `mass[]` branch loads each token **by request-supplied id** and revokes (or with `Delete=true`, deletes) it with **no ACL or ownership check**. Any authenticated user who knows a token's row id — leaked to low-priv users by VULN-082, or found via IDOR — can therefore knock out another principal's API access. Validated by minting a victim (admin) token, confirming it works (V8 → 200), then having a non-admin revoke it by id (V8 → 401).

## 3. How it works (mechanism & code trace)
```php
// modules/OAuth2Tokens/controller.php:48-73
public function action_massupdate()
{
    if (!empty($_REQUEST['select_entire_list'])) {
        $tokens = $this->bean->get_full_list();          // OWNER-SCOPED for non-admins (see below)
        ...
    } elseif (!empty($_REQUEST['mass'])) {
        foreach ($_REQUEST['mass'] as $id) {
            $token = BeanFactory::getBean('OAuth2Tokens', $id);   // :65  by id, ANY owner
            if (isTrue($_REQUEST['Delete'] ?? false)) { $token->mark_deleted($token->id); continue; }
            $token->token_is_revoked = true;                      // :70  no ACL / owner check
            $token->save();                                       // :71
        }
    }
}
```
The `mass[]` branch never checks `is_admin`, never compares `assigned_user_id` to the current user, and never calls `ACLAccess`. It simply trusts the caller-supplied id.

The token's effect on API access is enforced here:
```php
// Api/V8/OAuth2/Repository/AccessTokenRepository.php:125-133  isAccessTokenRevoked($tokenId)
return $token->id === null || $token->token_is_revoked === '1' || new DateTime() > new DateTime($token->access_token_expires);
```
so setting `token_is_revoked=1` makes the next V8 request with that token return 401.

**Correcting the static claim.** The finding stated `select_entire_list → get_full_list()` revokes *every* user's tokens. That is false here: `OAuth2Tokens::create_new_list_query` (`OAuth2Tokens.php:151-163`) returns unscoped only for admins and otherwise appends `AND assigned_user_id = '<currentUserId>'`, so a non-admin's `select_entire_list` massupdate only touches their own tokens (verified: it left all other tokens unrevoked). The real, confirmed authorization break is the `mass[]` by-id branch.

**Confirmed live** (`response.txt`): victim admin token → `GET /Api/V8/module/Accounts` = 200; low-priv attacker `POST massupdate mass[]=<victim row id>` = 301; victim token afterward = **401**.

## 4. Why it is a vulnerability (reasoning)
OAuth tokens are per-principal credentials; revoking or deleting one is an operation on *that principal's* security state. The trust boundary "a user may manage only their own tokens" is exactly what the owner-scoping in the `select_entire_list` branch enforces — and exactly what the `mass[]` branch omits. That asymmetry (one branch scoped, the sibling not) shows the missing check is an oversight, not intent. The demonstrated cross-owner revocation (non-admin → admin's token) is a direct object-level authorization break with a concrete availability impact.

## 5. Reproduction
1. Precondition (scripted): admin creates a RegularUser (attacker); admin creates an OAuth2 password-grant client and mints a victim token (assigned to admin); resolve the victim token's row id via `get_entry_list where access_token=<jti>` (the id an attacker obtains via VULN-082).
2. Confirm the victim token works: `GET /Api/V8/module/Accounts` with `Authorization: Bearer <victim token>` → 200.
3. Attack (as the low-priv attacker, valid same-origin Referer): `POST /index.php module=OAuth2Tokens&action=massupdate&mass[]=<victim_row_id>`.
4. Re-check the victim token → 401 (revoked).
5. `./run.sh` → expected tail:
```
[PROOF] victim token works BEFORE attack: ... HTTP 200
[PROOF] attacker massupdate: HTTP 301, csrf-blocked=False
[PROOF] victim token works AFTER attack: HTTP 401
==> VULN-025: CONFIRMED — low-priv mass[]=<id> revokes any user's OAuth token (BOLA -> API DoS)
```
Full capture in `run.log`/`request.http`/`response.txt`.

## 6. Impact
A low-privilege user can revoke or (with `Delete=true`) delete any other user's OAuth access/refresh tokens by id — breaking that user's or integration's API access on demand (denial of service, forced re-authentication, disruption of automations/mobile clients). Iterating over ids obtained from VULN-082 lets an attacker knock out API access broadly. Chains: **VULN-082** leaks the token ids that make this a practical, un-guessing attack. Blast radius: every OAuth-authenticated user/integration whose token id the attacker learns.

## 7. Suggested fix
Enforce ownership/admin in the `mass[]` branch (mirror the owner-scoping the list branch already has):
```php
foreach ($_REQUEST['mass'] as $id) {
    $token = BeanFactory::getBean('OAuth2Tokens', $id);
    if (empty($token->id)) continue;
    if (!is_admin($GLOBALS['current_user']) && $token->assigned_user_id !== $GLOBALS['current_user']->id) {
        continue;   // a non-admin may only manage their own tokens
    }
    ...
}
```
Principle: object-level authorization on every by-id operation; a non-admin may act only on tokens they own (the same rule the `select_entire_list` branch already applies via `create_new_list_query`).

## 8. References
- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization; OWASP WSTG-ATHZ-04 (IDOR).
- CWE-639 (Authorization Bypass Through User-Controlled Key); CWE-862 (Missing Authorization).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM OAuth2Tokens massupdate revoke token any user authorization vulnerability` — nothing on the module's massupdate; returned CVE-2025-64489 (sessions not invalidated on deactivation), CVE-2019-18785, CVE-2021-25961.
2. `SuiteCRM "OAuth2Tokens" module controller massupdate OR "mark_deleted" OR revoke vulnerability` — no advisory names `OAuth2Tokens`; only a community thread on deleting tokens and CVE-2025-64489 / CVE-2026-32697.
3. `SuiteCRM CVE-2019-18785 OAuth2 tokens 7.11.9 security release details` — CVE-2019-18785 is CWE-522 "mishandles API access tokens and credentials", unauthenticated (PR:N); not a by-id revocation BOLA.
4. SuiteCRM 7.15.x release-notes security list + GitHub repo advisory titles (7.15.1, 7.15.2, 20 most recent) — the only OAuth2 entry is GHSA-rc46-hjjp-4jv5 / CVE-2026-100362 (V8 OAuth2 username enumeration); no OAuth2Tokens module advisory.
5. GitHub issue search `repo:SuiteCRM/SuiteCRM OAuth2Tokens massupdate` — only unrelated #7241 (DB global usage).
6. Upstream `hotfix` branch `modules/OAuth2Tokens/controller.php` (2026-10-21): `mass[]` branch at :63-:71 still loads tokens by request id with no owner/admin check. NVD keyword query for SuiteCRM CVEs 2026-04-01..2026-10-21 — no match.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2025-64489 — OAuth2 access tokens/sessions remained valid after account deactivation (token lifecycle, different root cause and direction).
- CVE-2019-18785 — unauthenticated mishandling of API tokens/credentials in 7.10.x/7.11.x (CWE-522).
- GHSA-rc46-hjjp-4jv5 / CVE-2026-100362 — V8 OAuth2 username enumeration.
- GHSA-m6x8-3hxp-qxwv / CVE-2026-29189 — V8 REST missing ACL on user preferences/relationships (same BOLA class, different component).

**Reasoning:** No CVE, GHSA, vendor note, issue, or write-up describes the `OAuth2Tokens` module's `action_massupdate` `mass[]` branch revoking or deleting tokens by arbitrary id, and the code is unchanged upstream today. Published OAuth-related SuiteCRM issues concern token lifecycle on deactivation, credential exposure, and V8 enumeration, none of which is this object-level authorization gap. Confidence is 80 given the noisy BOLA class in this project and the possibility of an unindexed private report.
