# VULN-094 — validate_external_host() SSRF guard bypassable via an HTTP redirect chain

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 6.5)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:3x Z (see run.log timestamp)

## Preconditions
- Fresh non-admin user via `_common.create_user()`.
- HTTP listener on `0.0.0.0:33119` (app reaches it at `172.18.0.1:33119`).
- **Fixture**: the low-priv user's `dashlets` Home preference is seeded with one `RSSDashlet` instance whose `url` is a public-redirector chain, via `docker compose -p cvehunterlab_suitecrm exec -T app php` calling `User::setPreference()`/`savePreferencesToDB()` directly (the same persistence the real "Add Dashlet" UI performs — see [VULN-014](../VULN-014/writeup.md), whose exploit *does* drive that add-flow end-to-end over plain HTTP for its own, unguarded sink). This fixture step was needed here specifically because this freshly-created low-priv account's dashboard/`activeTab` layout state made the *add*-flow's own HTTP response unreliable to parse (HTTP 500 after the identical, already-unguarded fetch that VULN-014 targets — a dashboard-layout side effect unrelated to this guard). The actual code path under test in this finding — the **guarded** `RSSDashlet::getRSSOutput()` — is only reached by the second, independent HTTP call below, made for real over the network as the low-priv user.
- **Redirector**: `https://httpbin.org/redirect-to?url=<urlencoded inner>&status_code=302`. httpbin.org resolves to genuine public IPs (confirmed: the app container has real internet egress — `curl https://1.1.1.1` → `301` from inside the container).

## Request
`POST /index.php` (low-priv session): `to_pdf=1&module=Home&action=CallMethodDashlet&method=display&id=<dashlet_id>` — see `request.http` (also documents the pre-seeded dashlet URL and the redirect chain it encodes).

## Response
HTTP 200:
```
<div id='rss_dash_1f4b2bb5' ...>
<table class='edit view'><tr>
<td>
    <h3><a href="" target="_child">hit</a></h3>
</td>
</tr></table>
</div><br />
```
The rendered `<h3>` title **"hit"** is the `<title>` of the synthetic RSS payload our OOB listener served — i.e. not only did the fetch reach the internal-only listener, its response was parsed as the feed and rendered back into the authenticated page (semi-blind full read, matching the finding's "internal RSS/Atom-parseable XML renders back into the page" note).

## Observation
`evidence/oob_listener.log`:
```
GET /canary-rss094_ab9c346b
  Host: 172.18.0.1:33119
  ...
```
Exactly matches the static finding: `validate_external_host()` (`RSSDashlet.php:161`) is called **once**, against the *original* configured URL (`https://httpbin.org/redirect-to?...`), which resolves to a genuine public IP and passes. `file_get_contents($url)` (`:165`) then follows the `302 Location:` PHP's http stream wrapper receives from httpbin.org straight to `172.18.0.1:33119` — an address that, when tested directly against `validate_external_host()` in isolation (`docker compose exec app php` one-liner during analysis), is **rejected** (`FILTER_FLAG_NO_PRIV_RANGE` catches the 172.16.0.0/12 range). The guard is real and correctly rejects the internal address when given directly; it is simply never re-applied to the redirect hop.

## Side effects
- New throwaway `users` row + one `dashlets` preference entry (random-suffixed ids).
- One inbound HTTP GET on the OOB listener (the httpbin.org hop itself is not directly observed by us, but is implied — see Research note).

## Research & references
- OWASP SSRF Prevention Cheat Sheet (redirect-following as a named bypass class): https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy, "SSRF with blacklist-based input filters" / bypassing via open redirection: https://portswigger.net/web-security/ssrf
- Technique: a real, public redirector service (`httpbin.org/redirect-to`) stands in for an attacker-controlled public server — this is a faithful reproduction of the real-world exploitation shape (attacker registers a domain, its server 302s to the internal target) using a well-known, publicly documented test endpoint instead of standing up new attacker infrastructure, since the app container has genuine internet egress.
- Fixture-setup note: seeding the preference directly via the app's own `User::setPreference()` API (rather than only through the HTTP add-dashlet flow) is standard "known-good state" setup, consistent with how earlier stages used direct DB/API access to create precondition records; the vulnerability's own trigger (the render/`CallMethodDashlet` request) was executed for real, over HTTP, by the low-priv account.
