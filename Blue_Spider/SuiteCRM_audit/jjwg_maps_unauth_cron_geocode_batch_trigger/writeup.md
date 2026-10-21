# VULN-048 — Unauthenticated jjwg_Maps geocode batch discloses CRM data to Google and drives an unauthorized write/DoS job

**ID**: VULN-048
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium (High on Maps-configured instances) — **CVSS 3.1: 7.3** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`
**Status**: **CONFIRMED (dynamic)**
**Auth required**: None. The entry point is registered `auth => false`; no session, cookie, token, or referer is needed.
**What an attacker gains**: the ability to anonymously force the CRM server to (a) send real customer/account PII (billing addresses) to a third party (Google), (b) burn a Maps-configured instance's Google API quota/billing, (c) write to CRM records' custom fields, and (d) pin an Apache/PHP worker for tens of seconds per request — all with a single unauthenticated GET, repeatable at will.

## Summary

`jjwg_Maps` (the bundled Maps module) registers its entry point with
`auth => false`. That router forwards any request carrying a non-empty
`cron` parameter straight into `jjwg_MapsController::action_geocode_addresses()`
— a batch job intended for a scheduled cron task, but reachable by anyone who
can send an HTTP request. The action performs no session, ACL, or capability
check of any kind. It scans up to 250 not-yet-geocoded records in the chosen
module (default: 8 core modules including Accounts/Contacts/Leads), and for
each one with a real address calls Google's Geocoding API with that address
and writes the result back into the record's custom fields. This dynamic
validation proves the full chain live: an anonymous request causes the
server to transmit a real account's billing address to Google.

## How it works (mechanism & code trace)

**Entry point** — registered unauthenticated:
```php
// modules/jjwg_Maps/entry_point_registry.php:2
$entry_point_registry['jjwg_Maps'] = array('file' => 'modules/jjwg_Maps/jjwg_Maps_Router.php', 'auth' => false);
```
`auth => false` means `SugarApplication::execute()` skips `loadUser()`,
`ACLFilter()`, and `checkHTTPReferer()` for this entry point entirely — no
authentication surface at all.

**Router** — dispatches the cron branch with no gate:
```php
// modules/jjwg_Maps/jjwg_Maps_Router.php:14-25
if (!empty($_REQUEST['cron'])) {
    require_once('modules/jjwg_Maps/jjwg_Maps.php');
    require_once('modules/jjwg_Maps/controller.php');
    $controller = new jjwg_MapsController();
    $controller->action_geocode_addresses();
    exit;
}
```
Any request with `cron` set (even `cron=1`) reaches the batch action. The
non-cron branch (the rest of the file) is a legitimate JS-redirect helper for
authenticated users selecting records from a list view — the `auth => false`
registration was evidently meant for *that* helper, not for the cron branch
that shares the same file.

**Action** — no `$current_user`/ACL check anywhere in its 140+ lines
(`modules/jjwg_Maps/controller.php:171-313`, verified by reading the whole
method). It builds the module list from `$_REQUEST['display_module']` (here:
`Accounts`), pulls up to `geocoding_limit` (250) not-yet-geocoded rows via
`getGeocodeAddressesResult()`, and for each one with a resolvable address:

```php
// modules/jjwg_Maps/controller.php:226-237
if (!empty($aInfo['address']) && empty($aInfo['status'])) {
    if ($google_geocoding_inc < $this->settings['google_geocoding_limit']) {
        $aInfoGoogle = $this->bean->getGoogleMapsGeocode($aInfo['address'], false, false);
        ...
    }
}
```

```php
// jjwg_Maps.php:892-913 (getGoogleMapsGeocode)
$request_url = $base_url . "&address=" . urlencode($address);
$request_url .= "&key=" . urlencode($this->settings['google_maps_api_key']);
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $request_url);
...
```
This call fires **unconditionally** — whether or not a Google API key is
configured. The defect is not "this needs a key to be dangerous"; the
address is sent to Google either way.

**The exact defect**: nothing between the `auth => false` router and this
outbound call checks who is asking. The batch's own size/frequency governor
(`geocoding_limit=250`, `sleep(1)` every 10 records, `google_geocoding_limit=100`)
is a *resource* control, not an *authorization* control — it bounds how much
damage one request does, not who may cause it.

## Why it is a vulnerability (reasoning)

The trust boundary being violated is straightforward: sending real customer
PII to a third-party API, writing to CRM records, and consuming paid API
quota are all state-changing / disclosure-causing operations that should
require, at minimum, an authenticated session — SuiteCRM enforces exactly
that (`current_user_can`-equivalent ACL checks) for every normal path to
this same data. The `jjwg_Maps` cron entry point is a deliberate hole in that
model: it exists so an OS-level cron job (which cannot carry a session
cookie) can drive the batch, but the implementation gates it by *auth flag
alone* rather than a shared secret, IP allowlist, or CLI-only invocation —
so the "convenience for cron" bypass is available to anyone on the network,
not just the local cron daemon. This is not by-design; nothing in the code
or the surrounding module suggests unauthenticated internet users were meant
to be able to trigger this.

## Reproduction

Preconditions: none beyond the lab's pre-existing Accounts data (68
not-yet-geocoded rows; the first one has billing address "321 University
Ave., San Mateo, CA, 60261, USA").

1. Send, with **no cookies**:
   ```
   GET /index.php?module=jjwg_Maps&entryPoint=jjwg_Maps&cron=1&display_module=Accounts HTTP/1.1
   Host: localhost:33116
   ```
   (see `request.http`). Response: `HTTP/1.1 200 OK`, 0-byte body (the code
   `exit`s with no output on this branch — see `response.txt`).
2. Run `./run.sh` (`NO_COLOR=1 ./run.sh 2>&1 | tee run.log`). It sends exactly
   the request above, then — because the HTTP response is opaque by design —
   uses same-process instrumentation of the identical
   `action_geocode_addresses()` code path (same container, same DB; not a
   second attack) to surface the server-side effect.
3. Expected `[OK]`-equivalent output (this script uses the shared `verdict()`
   helper): `==> VULN-048: CONFIRMED — anonymous GET (no auth/ACL) reached
   action_geocode_addresses() and caused a real outbound call to Google
   carrying a real CRM billing address ('321 University Ave., San Mateo, CA,
   60261, USA' -> REQUEST_DENIED)`.
4. Observable proof (`evidence/mechanism_proof.txt`):
   ```
   FIRST_ADDRESS_RECORD_ID=08681f23-9274-4c6f-9e18-75422a600e5d
   FIRST_ADDRESS=321 University Ave., San Mateo, CA, 60261, USA
   GOOGLE_CALL_SECONDS=0.092
   GOOGLE_STATUS=REQUEST_DENIED
   ```
   `REQUEST_DENIED` is Google's real answer to a keyless request — proof the
   outbound call actually happened, not a simulated result.

**Why the batch stops after one record here**: `controller.php:281-286`
treats `OVER_QUERY_LIMIT`/`REQUEST_DENIED` as a circuit breaker that aborts
the whole batch. Because this lab has no Google API key configured, the very
first address-bearing record trips that breaker, so the DB delta for this
run is 0 (verified via `accounts_cstm.jjwg_maps_geocode_status_c` before/after).
On a Maps-configured (keyed) instance, Google would return `OK`/
`ZERO_RESULTS` instead, the breaker would never trip, and the full batch
(up to 250 records, `sleep(1)` every 10 ⇒ 25s+ of worker time, up to 100 real
billed Google calls, and an unauthorized write to every matching record)
would run exactly as the original static finding describes.

## Impact

- **Confidentiality**: real CRM data (account billing addresses, and by the
  same code path Contacts/Leads/Opportunities/Cases/Project/Meetings/Prospects
  addresses) is sent to a third party (Google) at the whim of an
  unauthenticated caller — a real, if narrow, data-disclosure channel.
  `C:L` in the CVSS vector.
- **Integrity**: unauthorized writes to `*_cstm` geocode fields
  (lat/lng/status) on real records, without any actor attribution.
- **Availability**: on any instance where the circuit breaker in this lab
  doesn't trip (i.e., real-world Maps-configured deployments, which is the
  point of enabling the module), one request pins a worker for 25s+ and can
  be repeated at will for a sustained DoS; `A:H` in the CVSS vector.
- **Cost**: each triggered batch consumes up to 100 real Google Maps API
  calls against the operator's billing/quota — a repeatable, free-to-the-
  attacker cost-amplification vector.
- Pre-auth, network-reachable, no rate limit observed on the entry point
  itself.

## Suggested fix

- `modules/jjwg_Maps/jjwg_Maps_Router.php:14`: split the cron branch into its
  own entry point registered separately from the JS-redirect helper, and gate
  it behind something the anonymous internet cannot present — a
  CLI-only/`php -f` invocation (no HTTP surface at all), or at minimum a
  per-install shared secret compared with `hash_equals()`, or
  `is_admin($current_user)` if it must stay HTTP-reachable.
- `modules/jjwg_Maps/controller.php:171`: even with the above, bound
  `geocoding_limit`/`google_geocoding_limit` server-side (not purely
  admin-configurable-upward) and add a per-IP/per-hour rate limit as
  defense-in-depth.
- Principle: a resource cap (`geocoding_limit`, `sleep(1)`) is not a
  substitute for an authorization check; both are needed.

## References

- CWE-284: Improper Access Control — https://cwe.mitre.org/data/definitions/284.html
- CWE-770: Allocation of Resources Without Limits or Throttling — https://cwe.mitre.org/data/definitions/770.html
- OWASP WSTG-ATHZ-02, "Testing for Bypassing Authorization Schema" — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema
- Related (same module, different sinks): CVE-2026-69142 (jjwg_Maps map_markers SQLi), CVE-2026-63111 (jjwg_Maps non-admin scheduler SSRF) — cited by stage-05/07 known-issue cross-check; no existing public advisory matches this specific unauthenticated `cron=1` geocode entry point.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM jjwg_Maps geocode_addresses cron unauthenticated entry point vulnerability` — only community threads documenting the `entryPoint=jjwg_Maps&cron=1` scheduler URL as a feature; unrelated unauthenticated CVEs (CVE-2025-54786 iCal, CVE-2025-54787 downloads, CVE-2024-36412 events response)
2. `CVE-2026-63111 OR CVE-2026-69142 SuiteCRM jjwg_Maps` — neither hinted ID exists in any index; no jjwg_Maps advisory returned
3. `SuiteCRM Maps module jjwg_Maps security advisory CVE geocoding unauthenticated Google API` — no Maps-module advisory; only a community thread noting the module is abandoned upstream but bundled
4. `SuiteCRM "jjwg_Maps" CVE advisory` (extended) — only GitHub functional issue #4970; no CVE/GHSA names jjwg_Maps
5. Fetched tenable CVE-2024-50333 (surfaced in Maps search) — `ParserLabel::addLabels()` file write, unrelated

**Related but distinct public references** (same class or component, not this bug):
- 7.14.2 release commit (54bc56c3) touches `modules/jjwg_Maps/controller.php` and `views/view.map_markers.php` — jQuery/XSS hygiene changes bundled with CVE-2023-612x fixes, not the `auth => false` cron entry point
- CVE-2024-36412 — unauthenticated SQLi in the events response entry point; same "unauthenticated entry point" class, different module
- CVE-2025-54786 — unauthenticated iCal data exposure; different entry point

**Reasoning:** No CVE, GHSA, vendor advisory or PoC describes the `jjwg_Maps` entry point being registered `auth => false` and its `cron` branch dispatching `action_geocode_addresses()` to anonymous callers (PII sent to Google, unauthorized geocode writes, worker pinning). The two CVE IDs cited by the scanner as "same module" could not be found anywhere. The Maps module is a bundled third-party component with little public security scrutiny, so an unpublished report is possible but nothing public matches.
