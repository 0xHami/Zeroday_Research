# VULN-028 — SSRF via unguarded WebUserAgent (admin config URLs)

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (5.8)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- Admin session. `AdminPackageManager` requires `SecureMode=1` (the lab has it). OOB listener on
  the docker host gateway (172.18.0.1), reachable from the app container.

## Request / Response
`POST AdminPackageManager;Subaction=ChangeRepository;Source=http://172.18.0.1:<port>/repo` then
`GET AdminPackageManager` → the app container (172.18.0.3) issued `GET /repo/otrs.xml` to the OOB
listener (2 hits). See `response.txt`.

## Observation
Confirms `WebUserAgent.pm:225` `get($Param{URL})` with no SSRF filtering; the package-manager
online-repository fetch (`Package.pm`) forwards the admin-set `Source` to it. The app made a
server-side request to an attacker-chosen host/port.

## Side effects
Sets the admin's repository preference (revertible). Idempotent.

## Research & references
- OWASP WSTG-INPV-19 / SSRF Prevention Cheat Sheet; PortSwigger SSRF. CWE-918. Other callers:
  OAuth2Token, RSS dashboard, AdminMailAccount. VULN-040 extends reachability to customers (host
  admin-set there).

## Scope / note
Admin-gated; OTRS historically treats admin config as trusted (may be judged by-design), but the
`WebUserAgent` has no internal-range/scheme allowlist, so it reaches internal services / cloud
metadata. On this libxml2 build the XSLT-mapping network vector (VULN-025) is blocked; this
package/OAuth path is not.
