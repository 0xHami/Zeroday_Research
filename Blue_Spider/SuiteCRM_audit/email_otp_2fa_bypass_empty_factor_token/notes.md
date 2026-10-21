# VULN-091 — Two-factor (email OTP) bypass: empty `factor_token` loose-compares equal to the unset session token

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: High (CVSS 8.1)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T22:57Z

## Preconditions
- `automation.py` creates a fresh regular (non-admin) user via `_common.create_user()`.
- 2FA (`factor_auth`) is **off by default** per account. `modules/Users/User.php::save()` additionally hard-blocks *any* `factor_auth` change (even by admin) while `Administration::checkSmtpError()` is true (`modules/Administration/Administration.php:97-101`), i.e. while the system outbound mailer is unconfigured — true by default in this lab (empty `outbound_email.mail_smtpserver`).
- To lift both gates as admin: `_smtp_common.configure_system_outbound_smtp()` POSTs to `module=Administration&action=PasswordManager` (`saveConfig=1`) with `mail_smtpserver=172.18.0.1`, `mail_smtpport=33121` pointed at a throwaway SMTP-stub we run ourselves (`_smtp_common.SmtpCatcher`, same OOB-listener technique already validated for VULN-045, just aimed at the *system* mail config instead of a one-shot AJAX test). Verified this persists to the real `outbound_email` system row (`docker compose exec db mysql ... 'SELECT mail_smtpserver FROM outbound_email'`).
- `_smtp_common.enable_2fa_for_user()` then POSTs `factor_auth=1` via the normal Users EditView Save (the same primitive `_common.create_user()` uses). DB-verified: `users.factor_auth = '1'` for the test account after this call (see run.log `[INFO] DB check users.factor_auth ... = '1'`).

## Request
See `request.http`. Decisive pair, **same account, same password**, only the query string differs:
```
# Negative control (no factor_token at all)
GET /index.php?module=Home&action=index HTTP/1.1
Cookie: PHPSESSID=<session-1>

# Attack (FRESH session; first post-login touch carries an EMPTY factor_token)
GET /index.php?module=Home&action=index&factor_token= HTTP/1.1
Cookie: PHPSESSID=<session-2>
```

## Response
See `response.txt` and `evidence/resp1_no_token_challenge.html` / `evidence/resp2_empty_token_bypass.html`.
- Negative control: **200, 2460 bytes**, contains `name="factor_token"` (the OTP-entry form) — confirmed by `run.log`: a real "Two Factor Authentication Code" email WAS generated and captured by our catcher for this request. 2FA is genuinely active for this account.
- Attack: **200, 98945 bytes**, no `factor_token` input field, contains `action=Logout` and `Dashboard` (real authenticated app chrome) — reached with **zero** OTP emails generated in session #2.

## Observation
Matches the static finding exactly. `modules/Users/authentication/SugarAuthenticate/SugarAuthenticateUser.php:183` `isUserFactorTokenReceived()` returns true for `isset($_REQUEST['factor_token'])`, which is true even for `factor_token=''`. `:191` `factorAuthenticateCheck()`: `$_REQUEST['factor_token'] == $_SESSION['factor_token']` — on the very first post-login request, `$_SESSION['factor_token']` was never initialized (no prior call to `sendFactorTokenToUser()`), so PHP evaluates `'' == null` as **true**, and `$_SESSION['user_factor_authenticated']` flips to `true` for the rest of the session. The orchestrator (`SugarAuthenticate.php:278`) only calls `sendFactorTokenToUser()` in the branch taken when **no** `factor_token` param is present at all (`:303`), so supplying `factor_token=` short-circuits straight past OTP generation.

## Side effects
- One new `users` row (`mod_85c76ff2`, random suffix) with `factor_auth=1` — harmless throwaway fixture, left in place like other stage-10 fixtures.
- `outbound_email` system row repointed at our own OOB catcher (172.18.0.1:33121) and `passwordsetting_SystemGeneratedPasswordON`/`forgotpasswordON` flipped on in `config_override.php` — both are shared prerequisites also used by VULN-038/VULN-040 in this cluster; they only make previously-inert flows live, they do not disable or weaken anything else in the lab.
- Session #1's request genuinely emailed a 5-digit OTP (captured by our own catcher, never used) — see `run.log`.

## Research & references
- OWASP Authentication Cheat Sheet (MFA implementation pitfalls, "fail open" comparisons): https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- CWE-697 (Incorrect Comparison) / CWE-1284 (Improper Validation of Specified Quantity in Input) / CWE-303 (Incorrect Implementation of Authentication Algorithm).
- Technique used: PHP loose-comparison (`==`) type-juggling against an uninitialized/NULL session value — classic `'' == null` / `"0" == false`-class PHP footgun, well documented (PHP manual "Comparison Operators" type-juggling table; PortSwigger "Authentication" topic, "flawed multi-factor verification logic").

## If NEEDS_MANUAL
N/A — fully reproduced live end-to-end.
