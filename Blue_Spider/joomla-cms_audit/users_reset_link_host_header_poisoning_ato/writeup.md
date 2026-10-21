# VULN-004 — Host-header password-reset-link poisoning → account takeover

| | |
|---|---|
| **ID** | VULN-004 |
| **Software** | Joomla! CMS |
| **Repository** | https://github.com/joomla/joomla-cms |
| **Affected version** | 5.4.9-rc2-dev (commit-pinned, no tagged release) |
| **Commit** | a8bd3564ef52e830069aeb91286c2fd67bb3872d |
| **Severity** | Medium (potential High) |
| **CVSS 3.1** | 6.8 — `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N` |
| **Status** | CONFIRMED (dynamic — full ATO) |
| **Confidence** | 8/10 |
| **Confidence reasoning** | End-to-end proven incl. password change + login as victim; a real attack also needs the deployment to forward an arbitrary Host and the victim to click. |
| **Auth required** | None (unauthenticated). |
| **Attacker gain** | The victim's real reset token → set a new password → full account takeover. |

## Summary
The password-reset email's absolute link is built from the incoming request's `Host` header, not from the configured `live_site` — and `Route::link(absolute=true)` ignores `live_site` entirely. An unauthenticated attacker who submits a reset for a victim's email while sending `Host: attacker.example` causes Joomla to email the **victim** a link pointing at the **attacker's** host but carrying the victim's **real** single-use reset token. When the victim clicks, the attacker captures the token and replays it to set a new password. Proven end-to-end: the poisoned email was captured, the token replayed, the victim's password changed, and the attacker logged in as the victim.

## How it works (mechanism & code trace)
1. The request URI is built from the Host header — `libraries/src/Uri/Uri.php:89`:
   `$theURI = 'http' . $https . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];` (cleanup at `:107` only strips `' " < >` — no host allow-list).
2. The absolute-link branch copies scheme/host/port from `Uri::getInstance()` and never references `live_site` — `libraries/src/Router/Route.php:171-179`:
   ```php
   171: $uri2 = Uri::getInstance();
   179: $uri->setHost($scheme_host_port[1]);   // host = HTTP_HOST
   ```
   So configuring `live_site` does **not** protect this sink.
3. The reset model emits the real token inside that host-derived absolute link to the victim's stored address — `components/com_users/src/Model/ResetModel.php`:
   ```php
   470: $link = 'index.php?option=com_users&view=reset&layout=confirm&token=' . $token;  // plaintext token
   475: $data['link_text'] = Route::link('site', $link, false, $mode, true);             // absolute = true
   481: $mailer->addRecipient($user->email, $user->name);                                // to the VICTIM
   ```
Observed captured email link: `http://attacker.evil.example/index.php/component/users/reset?layout=confirm&token=534f855468bfc7c891aa54328bbeea00`.

The attacker then replays on the real host: `reset.confirm(username, token)` validates the token against the user's stored `activation` hash, and `reset.complete(password1/2)` sets a new password.

**Consistent-Host nuance (found dynamically):** the attacker must use the spoofed Host for *both* the form GET and the reset.request POST, so the per-host session and its CSRF form token are coherent. (Fetching the form on the real host but POSTing under a spoofed Host makes `checkToken` fail — a test artifact, not a mitigation.) The reset form is reachable under a spoofed Host via the canonical SEF URL `/index.php/component/users/reset`, which does not redirect. This is exactly how a real attacker's browser behaves.

## Why it is a vulnerability
Security-sensitive, email-bound absolute URLs are derived from an attacker-controllable request header. The trust boundary — "the link we email a user points at *our* site" — is violated: the server emails the victim a link to the attacker's host carrying a valid credential (the reset token). Because the token is the sole proof of identity for the reset, delivering it to the attacker is equivalent to handing over the account. The documented mitigation (`live_site`) does not apply because `Route::link` never consults it, so even a correctly-configured operator is exposed.

## Reproduction
1. Lab up at `http://localhost:34931`.
2. `./run.sh` (optionally `ATTACKER_HOST=...`). It creates a Manager victim, runs the attacker's consistent spoofed-Host reset (`Host: attacker.evil.example`), captures the poisoned email, replays the token (`reset.confirm` → `reset.complete`), and verifies the victim's password hash changed and that it can log in as the victim.
3. Expected: `[OK] exploit confirmed …`, `==> VULN-004: CONFIRMED`. Evidence: `evidence/poisoned_reset_mail.eml`, `response.txt`, `run.log`.

## Impact
Account takeover of any user whose email the attacker knows/enumerates (chains with VULN-017's registration oracle to target Administrators/Managers), bounded only by the victim clicking the poisoned link and the deployment forwarding an arbitrary Host (common on default/catch-all vhosts). The same Host primitive also poisons any reflected `Uri::base()`/`root()` (cache poisoning, malicious absolute asset URLs).

## Suggested fix
Build security-email links from the configured `live_site` and fail/omit rather than fall back to `Host` if it is unset; make `Route::link(absolute=true)` consult `live_site` for email-bound links; and/or validate the request `Host` against an operator allow-list in `Uri::getInstance('SERVER')`. Operators: set `$live_site` **and** reject unexpected Host headers at the web server (note `live_site` alone is insufficient because `Route::link` ignores it).

## References
- PortSwigger Web Security Academy — Password reset poisoning via the Host header.
- OWASP WSTG-ATHN-09; CWE-644 (Host-header injection), CWE-640 (weak password recovery).
- CVE-2026-48902 (scheme half, fixed 5.4.6); the host sink remains open.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 45 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Fetched osv.dev record for CVE-2026-48902 — covers only the scheme (http vs https) of reset/remind links, fixed in 5.4.6 / 6.1.1; nothing about the host component
2. Fetched github.com/advisories?query=joomla+host+header — only CVE-2012-3829 (installation-path disclosure via Host) and CVE-2012-3828; no reset-link item
3. Fetched github.com/advisories?query=joomla+password+reset — 13 results (CVE-2026-48902, CVE-2016-9081, CVE-2011-4321, CVE-2008-3681, extension CVEs); none concerns the request host being used in emailed links
4. Fetched joomla-cms issue searches `password reset host header` and `live_site HTTP_HOST` — only PHP-notice fixes (#7757, #17655) and functional bugs; no security report
5. Fetched the 5.4.9 security-release commit 955d7d3 plus raw `components/com_users/src/Model/ResetModel.php` (5.4.8 and 5.4.9) and `libraries/src/Uri/Uri.php` (5.4.9) — link construction unchanged (`Route::link(..., absolute)`), `Uri::getInstance()` still derives the host from `HTTP_HOST` with no allow-list; all 5.4.9 CVEs (2026-90913..90918, 92222..92226) checked on OSV, none matches
6. developer.joomla.org security centre returned HTTP 521 on three attempts, so it could not be read directly during this check

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-48902 / Joomla [20260518] — scheme downgrade of the same reset/remind links; host handling untouched
- CVE-2012-3829 — Host header used for path disclosure in Joomla 2.5.3; different sink
- `libraries/src/Uri/Uri.php` comment "prevent injections through the Host header" — vendor is aware of Host injection generally but only strips quote/angle-bracket characters

**Reasoning:** No Joomla-specific CVE, advisory or issue describes the request host flowing into emailed reset links; the only related 2026 fix addressed the scheme. The attack class itself is generic and widely documented, and Joomla has historically positioned Host validation as a hosting/configuration responsibility, so a report may be declined as by-design. Confidence is moderate-low for those reasons and because the vendor security centre could not be consulted directly.
