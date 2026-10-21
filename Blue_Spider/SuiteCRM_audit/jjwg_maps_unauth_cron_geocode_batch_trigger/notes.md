# VULN-048 — Unauthenticated jjwg_Maps geocode batch trigger

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium (High on Maps-configured instances) — CVSS 7.3
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T21:10Z

## Preconditions
- None besides the lab's existing 68 not-yet-geocoded `Accounts` rows (real
  demo/seed data already in the shared lab; no data created for this test).
- No authentication of any kind (entry point is `auth => false`).

## Request
See `request.http`. One anonymous `GET
/index.php?module=jjwg_Maps&entryPoint=jjwg_Maps&cron=1&display_module=Accounts`.

## Response
See `response.txt` and `evidence/mechanism_proof.txt`.

## Observation
The HTTP response is a deliberately empty 200 (the cron branch `exit`s with
no output), so the security effect is server-side and otherwise invisible
from outside. `automation.py` therefore pairs the real unauthenticated
attack request with same-process instrumentation of the *identical*
`action_geocode_addresses()` code path (same container, same DB, not a
second attack) to surface what that request actually did:

- The first not-yet-geocoded `Accounts` row (id `08681f23-...`) has a real
  billing address: `321 University Ave., San Mateo, CA, 60261, USA`.
- `getGoogleMapsGeocode()` (jjwg_Maps.php:892) is called **unconditionally**
  (key configured or not) and made a real outbound HTTPS call to
  `https://maps.googleapis.com/maps/api/geocode/json` carrying that address;
  round trip 0.092s; Google responded `REQUEST_DENIED` (no API key
  configured in this lab).
- `controller.php:281-286` treats `OVER_QUERY_LIMIT`/`REQUEST_DENIED` as a
  circuit breaker (`$geocoding_inc = $this->settings['geocoding_limit'] + 1;`
  then `if ($geocoding_inc > limit) break;`), aborting the **entire batch**
  after this first record. This explains why the real HTTP-triggered run
  showed **0** delta in `accounts_cstm.jjwg_maps_geocode_status_c` (checked
  before/after) — nothing after record #1 ever executes in this lab.

**Correction vs the static write-up**: the "250-record batch, sleep(1) every
10, up to 100 real Google calls, unauthorized data-write to every matching
record" scenario does **not** fully materialize out-of-the-box in this lab,
specifically *because* no Google API key is configured — Google's own
`REQUEST_DENIED` accidentally acts as a circuit breaker. On a Maps-configured
(keyed) instance — the realistic production case for anyone who enabled this
module — Google would return `OK`/`ZERO_RESULTS` instead, the circuit
breaker would never trip, and the full batch (up to 250 records, `sleep(1)`
every 10 ⇒ ~25s+ worker pinning, up to 100 real billed Google API calls, and
unauthorized writes to every matching record's custom fields) would run
exactly as originally described. The defect that matters most — **zero
authentication/ACL on a batch job that discloses real CRM PII to a third
party and can write to CRM records** — is fully live and demonstrated here
regardless of key configuration.

## Side effects
- One real outbound call from the app container to Google's live API,
  carrying one real (pre-existing, not attacker-created) account's billing
  address. No new records created; no cleanup needed. `accounts_cstm` row
  count and geocode-status count were verified unchanged (0 delta) given the
  circuit-breaker above.

## Research & references
- CWE-284 (Improper Access Control), CWE-770 (Uncontrolled Resource
  Consumption); this is a textbook missing-authorization-on-a-batch-endpoint
  pattern (OWASP WSTG-ATHZ-02 "Testing for Bypassing Authorization Schema").
- Related jjwg_Maps advisories cited by stage-05/07: CVE-2026-69142
  (map_markers SQLi), CVE-2026-63111 (non-admin scheduler SSRF) — same module,
  different sinks; this specific unauthenticated `cron=1` geocode entry point
  has no matching public advisory found.
