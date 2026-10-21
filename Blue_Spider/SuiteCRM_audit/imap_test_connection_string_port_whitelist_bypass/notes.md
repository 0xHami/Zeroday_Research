# VULN-046 — IMAP "Test Settings" SSRF + `valid_imap_ports` whitelist bypass

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 6.5; static finding notes it "escalates toward High on an imap-enabled host with the connection_string bypass" — see correction below, that escalation applies to *this* lab too)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:4x Z (see run.log)

## *** Correction to the static finding and to TARGET_FACTS.md — read first ***
Both `VULN-046.md` and `TARGET_FACTS.md`'s "known environment gates" state this sink is dead here because the PHP `imap` C extension is absent (`php -m` confirms no `imap` module). **That gate does not apply to this code path.** `InboundEmail::getImapHandlerType()` (`InboundEmail.php:8741`) is hardcoded to return `'imap2'`, and `ImapHandlerFactory::getHandlers()` (`include/Imap/ImapHandlerFactory.php:262`) maps `'imap2'` to `Imap2Handler`, which wraps the Composer package `javanile/php-imap2` (confirmed installed: `composer show` inside the app container → `javanile/php-imap2  0.1.10  PHP IMAP with OAUTH2`) — a **pure-PHP, socket-based** re-implementation of the IMAP client with **no dependency on the `imap` C extension at all**. `Imap2Handler::isAvailable()` checks `function_exists('imap2_open')`, a function the Composer package itself defines in PHP. So the "no imap ext" gate blocks only the legacy `ImapHandler`/`imap_open()` path, which this fork never actually calls. This is proven live below by a genuine IMAP protocol exchange (the app's IMAP client sends a real `A0001 CAPABILITY` command to our listener after reading its banner) — not merely a TCP connection.

## Preconditions
- Fresh non-admin user via `_common.create_user()`.
- Raw TCP listener on `0.0.0.0:33119` (app reaches it at `172.18.0.1:33119`) that sends an IMAP-style greeting (`* OK IMAP4rev1 BANNER-LEAK-<random> ready\r\n`) on accept and logs whatever the client sends next.

## Request
`POST /index.php?module=InboundEmail&action=Popup&target=Popup` (`request.http`):
```
port=143&connection_string=172.18.0.1:33119/imap/notls&server_url=172.18.0.1&protocol=imap&ssl=false&...
```
`port=143` is a member of the default `valid_imap_ports` allow-list (checked at `InboundEmail.php:6465`); `connection_string` is a **separate** field that `getConnectString()` (`:6407-6408`) uses verbatim and never cross-checks against that allow-list.

## Response
`HTTP 500`, empty body (`response.txt`) — the popup's downstream handling of an unexpected/aborted IMAP session throws, which is irrelevant to the vulnerability: the outbound connection and protocol exchange already happened by the time that occurs (see Observation).

## Observation
`evidence/oob_listener.log`:
```
listener bound 0.0.0.0:33119, banner='* OK IMAP4rev1 BANNER-LEAK-imap_2ea5a07c ready\r\n'
HIT from 172.18.0.3:55430: client sent b''
HIT from 172.18.0.3:55438: client sent b''
HIT from 172.18.0.3:55450: client sent b'A0001 CAPABILITY\r\n'
```
The third hit — occurring immediately after and only during the POST request itself — carries `A0001 CAPABILITY\r\n`, a genuine IMAP client command (the tagged-command syntax `javanile/php-imap2`'s client uses), issued in direct response to our banner. That is the decisive, protocol-level proof: this is not a bare port-scan hit, the target's IMAP client completed a real protocol round-trip with our internal-only listener.

**Anomaly, noted honestly**: an earlier, empty-payload connection is also observed in every run, occurring around/just after user provisioning (i.e. *before* this finding's own POST request is sent). Its cause was not conclusively identified — a plausible explanation is a scheduler/cron-style "check due mail accounts" pass running inline on an admin page load inside this shared, long-lived lab container, possibly re-polling state left by an earlier manual probe during analysis of this same finding. It is called out here for transparency but is **not** relied upon for the CONFIRMED verdict — the verdict rests solely on the third, request-correlated hit with real IMAP command content.

## Side effects
- New throwaway `users` row (random suffix).
- Several inbound TCP connections to the OOB listener, logged.

## Research & references
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger, "Server-side request forgery (SSRF)": https://portswigger.net/web-security/ssrf
- `javanile/php-imap2` package (pure-PHP IMAP client, no ext-imap dependency): https://github.com/javanile/php-imap2 — confirms the "imap ext absent" environment gate does not apply to `Imap2Handler`.
- Technique: server-speaks-first OOB banner + protocol-content assertion (stronger than a bare connection: the response includes an application-layer command only a real IMAP client would send), same family as [VULN-045](../VULN-045/notes.md)'s SMTP banner-reflection proof.
