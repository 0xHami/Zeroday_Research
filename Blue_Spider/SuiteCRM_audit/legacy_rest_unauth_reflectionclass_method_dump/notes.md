# VULN-063 — Unauthenticated `ReflectionClass` dump of the SOAP/REST implementation

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 3.1 5.3 — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:xx (see run.log timestamp)

## Preconditions
None. Fresh anonymous `requests.Session()`, no cookies, no `method=` parameter.

## Request
```
GET /service/v4_1/rest.php HTTP/1.1
Host: localhost:33116
```
(full headers in `request.http`; also probed `v2`, `v3`, `v4` siblings, dumps saved under `evidence/`)

## Response
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8

<pre>/**
 * SugarWebServiceImplv4_1.php
 * ...
 */
Class [ <user> class SugarWebServiceImplv4_1 extends SugarWebServiceImplv4 ] {
  ...
  - Methods [90] {
    Method [ <user, overwrites SugarWebServiceImplv4, ctor> public method __construct ] { ... }
    ...
    Method [ <user, inherits SugarWebServiceImplv4> public method job_queue_next ] { ... }
    Method [ <user, inherits SugarWebServiceImplv4> public method job_queue_cycle ] { ... }
    Method [ <user, inherits SugarWebServiceImplv4> public method job_queue_run ] { ... }
    ...
```
(full body in `response.txt` / `evidence/v4_1_reflection_dump.html`, 41825 bytes)

## Observation
Exactly matches the static finding: an unauthenticated GET with no `method` parameter hits
`SugarRest::serve()`'s empty-method branch (`service/core/REST/SugarRest.php:78-86`) and gets a
full `(string) ReflectionClass` dump instead of an auth error. Parsed out of the live response:
**39 public method signatures** of `SugarWebServiceImplv4_1`, including the undocumented/internal
`job_queue_next`, `job_queue_cycle`, `job_queue_run` (the exact methods behind VULN-080) and
`oauth_request_token`/`oauth_access_token`/`oauth_access`. All four legacy endpoints (`v2`, `v3`,
`v4`, `v4_1`) reproduce the same reflection-dump shape.

## Side effects
None — read-only unauthenticated GET, no state change on app/db containers.

## Research & references
CWE-200 / CWE-215 (Information Exposure Through Debug Information). PHP `ReflectionClass::__toString()`
intentionally dumps full signatures including non-public members — using it on unauthenticated
input is the root cause. No public CVE found for this exact sink (novel per static analysis).
