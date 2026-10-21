# VULN-063 — Unauthenticated `ReflectionClass` Dump of the Legacy Web-Service Implementation

**ID**: VULN-063
**Software / Repository**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2, commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1 5.3** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**Status**: `CONFIRMED (dynamic)`
**Auth required**: None
**What an attacker gains**: A complete, unauthenticated map of the legacy web-service API surface
— every method name, parameter list, and visibility modifier of `SugarWebServiceImplv4_1` — handed
over before a single login attempt.

## Summary

The legacy REST dispatcher's base `serve()` method runs before any authentication check. When the
`method` request parameter is empty, instead of failing closed it treats that as a request for an
API listing and echoes `(string) new ReflectionClass(get_class($this->implementation))` — PHP's
full class reflection, including private/protected members and doc comments. A single
unauthenticated `GET /service/v4_1/rest.php` (no parameters) returns a 41 KB HTML dump naming
every one of 39 public methods, including internal/undocumented ones (`job_queue_next`,
`job_queue_cycle`, `job_queue_run`, `oauth_request_token`, `oauth_access_token`, `oauth_access`)
that are not part of any published API reference.

## How it works (mechanism & code trace)

**Entry point**: `GET /service/v4_1/rest.php` with no query string (also `v2`/`v3`/`v4`). The
front controller instantiates `SugarRest` and calls `serve()`.

**The defect** — `service/core/REST/SugarRest.php:78-86`:
```php
public function serve()
{
    if (empty($_REQUEST['method']) || !method_exists($this->implementation, $_REQUEST['method'])) {
        if (empty($_REQUEST['method'])) {
            echo '<pre>';
            $reflect = new ReflectionClass(get_class($this->implementation));   // :83
            $restWSDL = (string)$reflect;                                       // :84  full class dump
            $restWSDL = preg_replace('/@@.*/', "", $restWSDL);
            echo $restWSDL;                                                     // :86
        } else {
            $er = new SoapError(); $er->set_error('invalid_call'); $this->fault($er);
        }
    } else {
        $method = $_REQUEST['method'];
        return $this->implementation->$method();
    }
}
```
No call to `validate_authenticated()` or `checkSessionAndModuleAccess()` precedes this branch —
`serve()` itself is the very first thing invoked, before any per-method auth logic in
`SugarWebServiceImpl*` even has a chance to run. The defect is the `if (empty($_REQUEST['method']))`
branch at line 79: it should reject with the same `invalid_call` fault used for an *unknown*
method (the `else` branch just below), but instead treats "no method" as "please reflect
yourself to me."

**Live confirmation**: an anonymous client (no cookies, no `rest_data` session id) sent a bare GET
and received (excerpt, full text in `evidence/v4_1_reflection_dump.html`):
```
Class [ <user> class SugarWebServiceImplv4_1 extends SugarWebServiceImplv4 ] {
  ...
  - Methods [90] {
    Method [ <user, inherits SugarWebServiceImplv4> public method job_queue_next ] { ... }
    Method [ <user, inherits SugarWebServiceImplv4> public method job_queue_cycle ] { ... }
    Method [ <user, inherits SugarWebServiceImplv4> public method job_queue_run ] { ... }
    Method [ <user, inherits SugarWebServiceImplv4> public method oauth_request_token ] { ... }
    ...
```
39 distinct method names were parsed out of the live response (see `notes.md`), and the same
reflection-dump shape reproduces on all four legacy endpoints (`v2`, `v3`, `v4`, `v4_1`).

## Why it is a vulnerability (reasoning)

The trust boundary here is "no session ⇒ no internal implementation detail," which every other
method in the same class enforces via `checkSessionAndModuleAccess()`. `ReflectionClass::__toString()`
is explicitly documented by PHP as a debugging/introspection tool — it is not a WSDL generator and
intentionally surfaces private/protected members, which is far more than any legitimate
API-discovery client needs. Feeding it attacker-controlled request state (`empty($_REQUEST['method'])`)
with no gate is a fail-open design: an error path (`invalid_call`) already exists one branch away
and is clearly the intended behavior for a bad/missing method — the empty case should hit exactly
that fault, not a richer disclosure path. This is not an intentional public API: the reflected
methods include internal machinery (`job_queue_*`) that has no WSDL/registry entry and is never
meant to be called externally (see VULN-080).

## Reproduction

1. **Preconditions**: none. Lab up at `http://localhost:33116`.
2. **Request**:
   ```
   GET /service/v4_1/rest.php HTTP/1.1
   Host: localhost:33116
   ```
   (see `request.http`)
3. Run `./run.sh` (`run.log` has the full transcript). Expected:
   ```
   ==> VULN-063: CONFIRMED — anonymous GET with empty method= returned a full ReflectionClass dump
   of SugarWebServiceImplv4_1 (39 methods disclosed, incl. ['job_queue_cycle', 'job_queue_next',
   'job_queue_run', 'oauth_access', 'oauth_access_token', 'oauth_request_token']) -- zero authentication
   ```
4. **Observable proof**: `response.txt` / `evidence/v4_1_reflection_dump.html` — HTTP 200, body
   opens with `<pre>` then `Class [ <user> class SugarWebServiceImplv4_1 ... ] { ... - Methods [90] { ...`.
   `evidence/v2_reflection_dump.html`, `v3_reflection_dump.html`, `v4_reflection_dump.html` show
   the same shape on the sibling endpoints.

## Impact

Confidentiality-only: no data is read or modified, but the attacker now has the complete,
authoritative method surface of the legacy service — including methods with no public
documentation — before spending a single authentication attempt. This directly cuts the discovery
cost for every other finding in the legacy-API cluster (VULN-001/003/077/078/079/080/082): an
attacker no longer has to guess method names or signatures, they read them straight from the
reflection dump. Combined with the unauthenticated version leak (VULN-009), an attacker builds a
complete pre-auth fingerprint (exact release + exact method surface) from two anonymous requests.

## Suggested fix

Make `SugarRest::serve()` fail closed: route the `empty($_REQUEST['method'])` case to the same
`invalid_call` fault used for an unrecognized method, and delete the `ReflectionClass` branch
entirely (or, if an API listing is genuinely wanted, gate it behind authentication and hand-write
an allow-listed, public-only method/parameter manifest instead of reflecting the live
implementation object).

```php
// service/core/REST/SugarRest.php:78 -- suggested
public function serve()
{
    if (empty($_REQUEST['method']) || !method_exists($this->implementation, $_REQUEST['method'])) {
        $er = new SoapError();
        $er->set_error('invalid_call');
        $this->fault($er);
        return;
    }
    $method = $_REQUEST['method'];
    return $this->implementation->$method();
}
```

## References

- CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- CWE-215 — Insertion of Sensitive Information Into Debugging Code
- PHP manual, `ReflectionClass::__toString()` (documented as a debug/introspection facility): https://www.php.net/manual/en/reflectionclass.tostring.php
- OWASP WSTG-INFO-02 — Fingerprint Web Application Framework
- Technique used: direct unauthenticated API probing across all four legacy REST endpoint versions.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 55 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory Database query `suitecrm reflection` — 0 advisories.
2. GitHub Advisory Database query `suitecrm information disclosure` — only CVE-2021-41595 / CVE-2021-41596 (directory-traversal information disclosure, fixed 7.10.33/7.11.22); nothing about `rest.php`, `SugarRest::serve()` or ReflectionClass.
3. NVD keyword query `suitecrm rest.php` — no results returned.
4. Full SuiteCRM GHSA catalogue (77 published advisories, 2024-06 through 2026-10-12) reviewed — no advisory describes an unauthenticated API-surface/reflection disclosure on the legacy `service/v*/rest.php` endpoints.
5. GitHub commit history of `service/core/REST/SugarRest.php` (API) — no functional change since the 2013 initial import (only style/rector commits); the reflection branch has never been patched or gated.
6. Scanner's own prior query `SuiteCRM SugarRest ReflectionClass dump` — recorded as no exact public match.
(Note: the shared WebSearch budget was exhausted before this folder; checks 1–5 were made by direct fetch of the advisory databases and the upstream repository rather than a general web search.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2021-41595 / CVE-2021-41596 — information disclosure via directory traversal in SuiteCRM < 7.10.33 / 7.11.22; different component and vector.
- CVE-2026-63215 / GHSA-pmhw-r27f-w92m and CVE-2026-69134 / GHSA-3phg-q9w9-4pqw — SQL injection reachable through the same legacy `service/v4_1/rest.php` dispatcher; different class and sink.

**Reasoning:** No advisory, CVE or upstream fix addresses the fail-open `empty($_REQUEST['method'])` branch of `SugarRest::serve()` that echoes a `ReflectionClass` dump before any authentication. Caveat (why confidence is moderate): this behaviour is inherited unchanged from SugarCRM CE and has been observable on every install for over a decade, so it is plausibly documented in SugarCRM-era forum posts or pentest blogs as "visit rest.php to list the API methods" without ever being filed as a vulnerability; a general web search (not possible within this run's budget) would be needed to rule that out, and the impact is reconnaissance-only, which lowers the chance anyone bothered to report it.
