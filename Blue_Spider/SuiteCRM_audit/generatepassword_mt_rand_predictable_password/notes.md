# VULN-038 — System-generated / forgot-password temp password = 6 chars from `mt_rand`

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: High (CVSS 7.4)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T23:07Z

## Preconditions
- As admin: `passwordsetting_SystemGeneratedPasswordON` flipped on and the system outbound mailer pointed at our own SMTP stub, both via one legitimate POST to `module=Administration&action=PasswordManager` (`_smtp_common.configure_system_outbound_smtp()`). Verified to persist: `outbound_email.mail_smtpserver` (DB) and `config_override.php`'s `passwordsetting_SystemGeneratedPasswordON` (container file), both read back live.
- A throwaway "attacker-controlled" account (`_common.create_user()`), representing any account the attacker legitimately owns.
- **Both gates are load-bearing and independent**: the `SystemGeneratedPasswordON` toggle alone is not enough — `User::sendEmailForPassword()` only calls `setNewPassword()` if `SugarPHPMailer->Send()` actually succeeds (`modules/Users/User.php:2434`), which requires a working mail transport. This lab ships no MTA by default, so without our SMTP stub the endpoint would echo an error and the account's password would be left unchanged (verified: an earlier run against a stopped catcher produced a mail-send failure and no DB change).

## Request
See `request.http`. Decisive property: **no `Cookie` header at all** — this is a fully unauthenticated POST:
```
POST /index.php?entryPoint=GeneratePassword HTTP/1.1
user_name=mod_2f797c8d&Users0emailAddress0=mod_2f797c8d%40example.invalid
```

## Response
See `response.txt` / `evidence/captured_email_raw.txt`. HTTP 200, body `1` (success). The real outbound email (captured by our SMTP stub, addressed to the account's own primary email) contains: `Password : pLh4gt` — a 6-character string from the alphabet `[A-Za-z0-9]`, matching `generatePassword()`'s `$charBKT`/`$length='6'` exactly.

## Observation
Matches the static finding precisely: `modules/Users/User.php:2312` (`$length = '6'`) and `:2316` (`mt_rand() % strlen($charBKT)`) produce the emitted value; `GeneratePassword.php`'s unauthenticated username+email branch (no `current_user` check) reaches it. Beyond the static prediction, dynamic validation also proved the value is **not just an email artifact**: `sendEmailForPassword()` calls `$this->setNewPassword($additionalData['password'], '1')` (`User.php:2434`) only after a successful send, and a follow-up HTTP login (`module=Users&action=Authenticate`) with *only* the captured 6-character string succeeded — confirming the mt_rand output truly became the account's live `user_hash`.

## Side effects
- One throwaway account (`mod_2f797c8d`) with its password reset to the mt_rand-derived value — harmless fixture.
- Same outbound-mailer/PasswordManager config changes shared with VULN-040/VULN-091 in this cluster (system-wide, not per-finding, and additive-only — they turn previously-inert flows on, nothing is disabled).

## Research & references
- GHSA-6p2f-wwx9-952r ("Unauthenticated user password reset on php7") — same predictable-`mt_rand`-for-a-security-token class, cited in the static finding as a known-issue analog.
- CWE-338 (Use of Cryptographically Weak PRNG), CWE-330 (Use of Insufficiently Random Values).
- `php_mt_seed` / Mersenne-Twister state-recovery tooling (background reading, not executed here): https://www.openwall.com/php_mt_seed/

## Honest scope note (not glossed over)
This run proves, live: (1) unauthenticated reachability, (2) the emitted secret is exactly the short mt_rand-derived value the static finding describes, and (3) that value is the account's real, live password (closed the loop with an actual HTTP login using only the captured value). It does **not** additionally perform Mersenne-Twister *state recovery* to predict a **different** (victim) account's password from the attacker account's observed output — reconstructing PHP's MT19937 state from a handful of `mt_rand() % 62`-reduced samples (far fewer bits than the classical 624-raw-32-bit-output recovery technique needs) is a genuine, published-but-nontrivial research problem, not a copy-paste step, and was intentionally not fabricated here. The severity/CVSS already reflects this via `AC:H`. A human wanting to close that specific gap would need to either capture many more samples from the SAME PHP-FPM worker process (which recycles across requests, so the RNG stream can be shared across "different" HTTP requests) and run a partial-output MT-state-recovery attack, or brute-force the 32-bit auto-seed space with a tool such as `php_mt_seed` if the PHP version's seeding is seed-recoverable.
