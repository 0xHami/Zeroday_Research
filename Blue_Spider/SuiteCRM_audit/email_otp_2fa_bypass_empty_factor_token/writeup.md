# VULN-091 — Two-Factor (Email OTP) Bypass via Empty `factor_token`

**ID**: VULN-091
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`)
**Commit**: `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: High — **CVSS 3.1 8.1** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
**Status**: **CONFIRMED (dynamic)**
**Auth required**: The attacker must already hold the account's username + password (the exact scenario 2FA exists to defend against). No further privilege or role is needed — the bug defeats the *second* factor, not the first.
**What an attacker gains**: Full authenticated session as the target user — including an admin, if the admin account has 2FA enabled — without ever seeing, guessing, or intercepting a one-time code.

## 1. Summary

SuiteCRM's email-based two-factor authentication can be satisfied by simply appending an **empty** `factor_token` parameter to the first request after a normal username/password login. The server-side check treats "a `factor_token` parameter is present" (even empty) as "the user submitted their OTP," then compares it against the session's stored OTP with a loose `==`. Because no OTP has been generated yet at that point in the flow, the session-side value is `NULL`, and PHP evaluates `'' == null` as `true`. The result: the second factor is marked satisfied, no OTP is ever generated or emailed, and the attacker is fully logged in with nothing beyond the primary password.

## 2. How it works (mechanism & code trace)

**Entry point** — the ordinary login/session-continuation flow, gated by a factor-auth check the framework runs on every authenticated request:

```php
// modules/Users/authentication/SugarAuthenticate/SugarAuthenticate.php:278-303 (orchestration)
if ($this->userAuthenticate->isUserNeedFactorAuthentication()) {          // :278  true iff user.factor_auth
    if (!$this->userAuthenticate->isUserFactorAuthenticated()) {
        if ($this->userAuthenticate->isUserFactorTokenReceived()) {       // :281  <-- our hook
            if (!$this->userAuthenticate->factorAuthenticateCheck()) {    // reject branch
                ... showFactorTokenInput();
            } else {
                // "User factor auth success!" -- silently continues
            }
        } else {
            // :303  ONLY reached when NO factor_token param exists at all
            ... $this->userAuthenticate->sendFactorTokenToUser(); ...
        }
    }
}
```

**Hop 1 — the "was a token submitted" check treats empty as present:**

```php
// modules/Users/authentication/SugarAuthenticate/SugarAuthenticateUser.php:183
public function isUserFactorTokenReceived(){ return isset($_REQUEST['factor_token']); }
```
`isset()` on `factor_token=''` is `true` — PHP's `isset()` only returns `false` for a genuinely absent key or an explicit `null`, not for an empty string. Sending `factor_token=` (or `&factor_token=` in a query string, or an empty POST field) therefore routes the request into the `factorAuthenticateCheck()` branch (`:281`), which — critically — is the branch that **never calls `sendFactorTokenToUser()`**. No OTP is generated for this session.

**Hop 2 — the comparison itself, against an uninitialized session value:**

```php
// modules/Users/authentication/SugarAuthenticate/SugarAuthenticateUser.php:189-197
public function factorAuthenticateCheck()
{
    if ($_SESSION['user_factor_authenticated'] || $_REQUEST['factor_token'] == $_SESSION['factor_token']) {  // :191
        $_SESSION['user_factor_authenticated'] = true;
    } else {
        $_SESSION['user_factor_authenticated'] = false;
    }
    return $_SESSION['user_factor_authenticated'];
}
```
`$_SESSION['factor_token']` is set **only** inside `sendFactorTokenToUser()` (`SugarAuthenticateUser.php:277`, `$_SESSION['factor_token'] = $token;`), which — per Hop 1 — never ran in this session. Reading an unset array key yields `NULL` (with a notice, silenced by default error reporting). So the comparison PHP actually evaluates is:

```php
'' == null   // => true  (PHP 7 and PHP 8 both; loose comparison / type juggling)
```

`$_SESSION['user_factor_authenticated']` becomes `true` for the remainder of the session. Every subsequent request in that session is now treated as fully 2FA-verified.

**The exact defect**: line 183 should require a *non-empty* token before treating one as "received," and line 191 should `hash_equals()`-compare against a token that is verified to have actually been generated (fail closed if `$_SESSION['factor_token']` was never set), not loose-`==` against whatever happens to be there — including nothing.

**Why the framework doesn't catch this**: the "did we already send a token" and "does the submitted token match" checks are conflated into a single `==`. There is no separate "a token exists to be checked against" guard, so an absent server-side value silently participates in the comparison instead of causing an unconditional reject.

## 3. Why it is a vulnerability (reasoning)

Two-factor authentication is a trust boundary: possession of the password alone must **not** be sufficient to reach an authenticated session when 2FA is enabled — a second, independently-delivered secret is supposed to be required. Here, an attacker who already has the password (via phishing, credential stuffing, a leak, or any of this audit's other credential-disclosure findings, e.g. VULN-090's hash exfiltration) can skip the second factor entirely by adding one empty parameter. This is not a rate-limiting or brute-force weakness (contrast VULN-040, which is about guessing a real OTP) — no code is ever generated, requested, or guessed. It is a straightforward logic bug: "empty" and "absent" are conflated, and an uninitialized value is allowed to participate in a security-critical equality check. No legitimate design intends 2FA to be optional based on whether the client happens to include a blank query parameter; this is unambiguously unintended behavior, not a documented bypass/testing hook.

## 4. Reproduction

Preconditions (created by `automation.py`, all via legitimate admin actions, no source modification):
1. A fresh regular user is created (`_common.create_user()`).
2. The system outbound mailer is pointed at a throwaway SMTP stub we run ourselves, because `User::save()` refuses to change `factor_auth` (even for admin) while the system mailer is unconfigured — a real precondition of the *feature*, not of the bug.
3. `factor_auth=1` is set for the test user via the normal Users EditView Save (same POST shape any admin's browser would send from Employee Management).

Exact requests (also in `request.http`):
```
POST /index.php   (module=Users&action=Authenticate&user_name=<user>&username_password=<pass>)
GET  /index.php?module=Home&action=index                    <- negative control, session #1
GET  /index.php?module=Home&action=index&factor_token=      <- attack, FRESH session #2
```

Run `./run.sh`. Expected and observed `[OK]`-equivalent output (this script's final line):
```
==> VULN-091: CONFIRMED — empty factor_token bypassed 2FA for mod_85c76ff2; challenge page 2460B vs bypass page 98945B
```

Observable proof (`response.txt`, `evidence/resp1_no_token_challenge.html`, `evidence/resp2_empty_token_bypass.html`, `run.log`):
- Session #1 (no `factor_token` param): 2,460-byte response containing a `factor_token` `<input>` field — the OTP challenge. `run.log` additionally shows a real "Two Factor Authentication Code" email was generated and captured by our test SMTP stub for this request.
- Session #2 (`factor_token=` on the first touch): 98,945-byte response — the full authenticated Home page (`action=Logout`, `Dashboard` present, no challenge form) — with **no OTP ever generated** in that session.

Same account, same password, only the empty parameter differs — isolating the defect precisely.

## 5. Impact

An attacker holding a victim's password defeats email-based 2FA in a single extra request parameter, with no OTP interception, no brute force, and no timing dependency. If the victim is an administrator, this chains directly to full admin capability, including the authenticated RCE at VULN-011. It also nullifies 2FA as a mitigating control for every *other* credential-disclosure finding in this audit (e.g. VULN-090's `user_hash` exfiltration, VULN-036's reversible-secret-storage chain, VULN-037's legacy-MD5 rows) — anywhere the write-up for those findings says "2FA would still need to be defeated," this bug removes that caveat for free.

## 6. Suggested fix

```php
// SugarAuthenticateUser.php:183
public function isUserFactorTokenReceived(){
    return isset($_REQUEST['factor_token']) && $_REQUEST['factor_token'] !== '';
}

// SugarAuthenticateUser.php:191
if ($_SESSION['user_factor_authenticated']
    || (isset($_SESSION['factor_token'])
        && hash_equals((string) $_SESSION['factor_token'], (string) $_REQUEST['factor_token']))) {
    ...
```
Fail closed when `$_SESSION['factor_token']` was never generated (i.e. treat "no token was ever sent" as an automatic reject, never as a pass). Combine with VULN-040's fix (attempt limiting / regeneration) so the OTP channel is both mandatory and non-guessable.

## 7. References

- OWASP Authentication Cheat Sheet — Multi-Factor Authentication: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- CWE-697 (Incorrect Comparison), CWE-1284 (Improper Validation of Specified Quantity in Input), CWE-303 (Incorrect Implementation of Authentication Algorithm)
- PortSwigger Web Security Academy — "Authentication" topic, flawed 2FA verification logic patterns: https://portswigger.net/web-security/authentication
- Technique used: PHP loose-comparison / type-juggling against an uninitialized session value (`'' == null`), combined with an `isset()`-on-empty-string mishandling — both are catalogued PHP-specific logic-bug patterns, not guesswork specific to this codebase.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory Database query `suitecrm two-factor` — 0 advisories.
2. GitHub Advisory Database query `suitecrm authentication bypass` — 0 advisories.
3. Fetched GHSA-j6jg-9jj3-q2ph (CVE-2025-64489, "Privilege Escalation via Improper Session Invalidation and Inactive User Bypass", fixed 7.14.8) — no mention of two-factor, `factor_token` or OTP; the 7.14.8 diff adds an `isEnabled()` check in `SugarAuthenticateUser::loadUserOnSession()`, a different function in the same file.
4. Fetched GHSA-7g39-m4fg-vrq7 (CVE-2026-33288, SQL injection in the authentication module with directory support, fixed 7.15.1) — no mention of 2FA.
5. Upstream v7.15.0..v7.15.1 diff of `FactorAuthEmailCode.php`/`.tpl` — only assigns the Referer URL for a `history.replaceState()` call; `isUserFactorTokenReceived()` / `factorAuthenticateCheck()` are unchanged.
6. GitHub commit history of `SugarAuthenticateUser.php` — the factor-token logic has not been modified since 2018 (`isset`-based "resend token" change); nothing in 7.15.1 or 7.15.2 touches it.
7. Full SuiteCRM GHSA catalogue (77 advisories through 2026-10-12) — authentication entries are session invalidation (GHSA-j6jg-9jj3-q2ph), LDAP filter injection (GHSA-26vx-rj47-x599), auth-module SQLi (GHSA-7g39-m4fg-vrq7), login XSS/HTML injection (GHSA-prfm-6667-x3mv, GHSA-g7hf-3j93-rwm5), unauthenticated password reset (GHSA-6p2f-wwx9-952r); no 2FA bypass.
(Note: the shared WebSearch budget was exhausted before this folder; checks were made by direct fetch of the advisory databases and the upstream repository.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2025-64489 / GHSA-j6jg-9jj3-q2ph — deactivated-user session persistence in `SugarAuthenticateUser.php`; same file, different function and root cause.
- CVE-2026-33288 / GHSA-7g39-m4fg-vrq7 and GHSA-26vx-rj47-x599 — injection bugs in the authentication module; different class.
- Scanner's own VULN-040 (5-digit OTP brute-forceability) — same 2FA feature, different weakness (guessing vs. no code required).

**Reasoning:** No public advisory, CVE or upstream change describes the empty-`factor_token` / `'' == null` loose-comparison bypass of SuiteCRM's email OTP second factor; the relevant code has been static since 2018 and is untouched by the 2025–2026 authentication fixes. Caveat: the 2FA feature is non-default and the bug is a simple PHP type-juggling pattern, so an unindexed pentest write-up could exist; confidence is held below 80 for that reason and because the WebSearch budget prevented a general-web query.
