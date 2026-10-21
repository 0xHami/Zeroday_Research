# VULN-038 — Unauthenticated System-Generated Password Uses Predictable `mt_rand`

**ID**: VULN-038
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`)
**Commit**: `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: High (conditional) — **CVSS 3.1 7.4** — `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
**Status**: **CONFIRMED (dynamic)**
**Auth required**: None — the vulnerable endpoint is explicitly unauthenticated (`entry_point_registry.php:51`, `'auth' => false`).
**What an attacker gains**: The ability to force a real, live password onto an account (their own, or — with the mt_rand state-recovery caveat below — potentially a victim's), where that password is drawn from a small, non-cryptographic PRNG output space.

## 1. Summary

When an admin enables "System-Generated Passwords" (a documented, legitimate SuiteCRM feature) and outbound mail is functioning, an **unauthenticated** request to `entryPoint=GeneratePassword` with just a username and matching primary email causes the server to mint a brand-new 6-character password using PHP's `mt_rand()` — a non-cryptographic, statistically-predictable PRNG — email it, and **actually set it as the account's live password**. This was dynamically proven end-to-end: the emitted string was captured from a real outbound email and then used, unmodified, to log in over HTTP.

## 2. How it works (mechanism & code trace)

**Entry point**:
```php
// include/MVC/Controller/entry_point_registry.php:51
'GeneratePassword' => array('file' => 'modules/Users/GeneratePassword.php', 'auth' => false),
```
`modules/Users/GeneratePassword.php`'s username+email branch performs no `current_user` check at all — it only verifies the supplied email matches the account's primary address (`$usr->isPrimaryEmail($useremail)`), which an attacker satisfies trivially for any account whose email they know (including one they registered themselves).

**Generation** (the weak PRNG):
```php
// modules/Users/User.php:2298-2320  generatePassword()
$length = '6';                                                        // :2312
for ($i = 0; $i < $length - $condition; $i++) {
    $password = $password . substr($charBKT, mt_rand() % strlen($charBKT), 1);   // :2316
}
```
`mt_rand()` is the Mersenne Twister generator — fast, statistically excellent for simulation, and **explicitly documented by PHP itself as unsuitable for security purposes**. Six characters from a ~62-symbol alphabet is also short (≈35.7 bits) independent of the RNG choice.

**The step that makes it a real credential, not just an email body** — the part the static analysis flagged as needing dynamic confirmation:
```php
// modules/Users/User.php:2415-2434  sendEmailForPassword()
...
if ($hasRecipients) {
    $result['status'] = $mail->Send();                 // must succeed
}
if ($result['status'] == true) {
    ... // archive a copy of the email
    if (!isset($additionalData['link']) || $additionalData['link'] == false) {
        $this->setNewPassword($additionalData['password'], '1');   // :2434 -- THE REAL PASSWORD CHANGE
    }
}
```
`setNewPassword()` runs `getPasswordHash()` (bcrypt-of-md5, the same primary hashing path used everywhere else in the app) and issues `UPDATE users SET user_hash=... WHERE id=...`. This is not a side channel — it is the account's actual authentication credential from that point forward.

**The exact defect**: `mt_rand()` at `:2316` should be `random_int()`/`random_bytes()` (already used correctly elsewhere in this very codebase, e.g. the 2FA OTP generator), and the emitted length/alphabet should honor the admin-configured password-complexity policy instead of a hardcoded 6-character shortcut.

## 3. Why it is a vulnerability (reasoning)

A password-reset credential is exactly as security-critical as the password it replaces — it must come from a CSPRNG, because anything that predicts it defeats authentication as completely as knowing the password outright. SuiteCRM gets this right elsewhere (the 2FA OTP uses `random_int()`); this one code path uses the legacy PRNG instead, almost certainly because `generatePassword()` predates the app's later CSPRNG adoption and was never revisited. There is no plausible legitimate reason a *security credential* needs Mersenne Twister's speed or reproducibility properties — this is squarely an oversight, not a design trade-off, and the surrounding code (bcrypt hashing, forced first-login-change flag) shows the rest of the flow *does* take credential handling seriously.

## 4. Reproduction

Preconditions (`automation.py`): admin enables `SystemGeneratedPasswordON` and points the system mailer at a throwaway SMTP stub (one POST to the real Admin > Password Management screen); a throwaway account is created to serve as the "attacker-controlled" target.

Exact unauthenticated request (`request.http`, no `Cookie` header):
```
POST /index.php?entryPoint=GeneratePassword HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user_name=mod_2f797c8d&Users0emailAddress0=mod_2f797c8d%40example.invalid
```

Run `./run.sh`. Observed:
```
[PROOF] unauthenticated request caused a real email to be sent containing a 6-character
        mt_rand-derived password: 'pLh4gt' ...
[PROOF] HTTP login with the mt_rand-derived password SUCCEEDED -- ... not merely display text.
==> VULN-038: CONFIRMED — unauth GeneratePassword emitted 6-char mt_rand password 'pLh4gt' ...
```
Full email in `evidence/captured_email_raw.txt`; post-login page in `evidence/post_login_page.html`; full transcript in `run.log`.

## 5. Impact

Any unauthenticated party who knows (or guesses, or phishes) a username+matching-email pair can force that account's password to a new, attacker-visible-in-principle value drawn from a weak generator — for an account they themselves control, this is trivially and fully demonstrated live above. For a **different** (victim) account, the same mechanism applies, but predicting *that* specific output requires reconstructing the PHP process's Mersenne-Twister state from previously observed outputs (see the Honest Scope Note in `notes.md` and Impact caveat below) — a real, published, but non-trivial technique, reflected in the CVSS `AC:H`. Either way, this endpoint is also an unauthenticated **forced-password-reset** primitive in its own right: it silently invalidates whatever password an account holder was using, whenever `SystemGeneratedPasswordON` is enabled, which is itself worth remediating independent of the RNG question.

## 6. Suggested fix

```php
// modules/Users/User.php — generatePassword()
$length = max(8, (int) ($sugar_config['passwordsetting']['minpwdlength'] ?? 8));
for ($i = 0; $i < $length; $i++) {
    $password .= $charBKT[random_int(0, strlen($charBKT) - 1)];
}
```
Honor the configured complexity policy; use `random_int()` (already the codebase's own standard elsewhere, e.g. the 2FA token). Prefer the CSPRNG reset-**link** path (already sound — a `create_guid()`-based URL) over emailing a standalone password wherever possible, and invalidate any prior active reset material when a new one is issued.

## 7. References

- GHSA-6p2f-wwx9-952r — "Unauthenticated user password reset on php7" (same weak-PRNG-for-a-security-token class).
- CWE-338 (Use of Cryptographically Weak PRNG), CWE-330 (Use of Insufficiently Random Values).
- PHP manual, `mt_rand()`: explicitly documents it as not cryptographically secure.
- Openwall `php_mt_seed` (Mersenne-Twister seed-recovery tooling, background reference for the impact caveat): https://www.openwall.com/php_mt_seed/
- Technique used: live email interception via a self-hosted SMTP stub (server-speaks-first OOB capture, the same class of technique already used for VULN-045 in this audit) plus an end-to-end HTTP-login proof that the captured value is the real, active credential.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM mt_rand generatePassword weak random password CVE` — only generic PHP CVE-2008-4107 and other products (Joomla, Mautic); SuiteCRM hit was CVE-2024-36407 (CWE-640, not PRNG)
2. `SuiteCRM entryPoint GeneratePassword unauthenticated password reset system generated password vulnerability` — CVE-2024-36407 / GHSA-6p2f-wwx9-952r only; no mention of mt_rand or predictable passwords
3. `CVE-2020-8784 SuiteCRM weak password reset token` — CVE-2020-8784 is SQL injection, not a reset-token issue; CVE-2021-25961 is reset-link reuse after user deletion
4. `SuiteCRM "generatePassword" OR "GeneratePassword.php" predictable password mt_rand github issue security` (extended) — SuiteCRM issue #6982 / PR #7718 is a functional "password not generated" bug; mt_rand hits are MODX/WBCE, not SuiteCRM
5. `SuiteCRM CVE-2020-8785 CVE-2020-8786 description` — both SQL injection (3 of 4, 4 of 4), unrelated
6. `SuiteCRM insufficiently random values CWE-338 OR CWE-330 password generation advisory` — no SuiteCRM entries; closest is EspoCRM rand() token advisory
7. Fetched tenable.com/cve/CVE-2024-36407 — description: unauthenticated attacker can trigger a reset but "does not get access to the new password"; requires PHP 7; fixed 7.14.4/8.6.1; no mt_rand/generatePassword reference. github.com/advisories/GHSA-6p2f-wwx9-952r returned 404 (repo-scoped advisory)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2024-36407 / GHSA-6p2f-wwx9-952r — same `GeneratePassword` flow, but root cause is an unauthenticated reset trigger specific to PHP 7 (CWE-640), fixed in 7.14.4; it explicitly states the attacker does not learn the password. This finding is about the non-CSPRNG `mt_rand()` used in `User::generatePassword()` (CWE-338) and is confirmed on 7.15.2
- CVE-2021-25961 — reset links not invalidated for deleted user ids (CWE-640), different mechanism
- CVE-2008-4107 — generic PHP `mt_rand` not cryptographically strong; not SuiteCRM-specific

**Reasoning:** No CVE, GHSA, vendor advisory or GitHub issue reports that SuiteCRM's system-generated password is produced with `mt_rand()` or is predictable. The entry point itself has prior public history (CVE-2024-36407), and "unauthenticated forced reset when System-Generated Passwords is enabled" is close to designed forgot-password behaviour, so the novel part is specifically the weak-PRNG root cause; confidence is moderated because mt_rand-for-secrets is an extremely common class and the vendor publishes few technical details in its advisories.
