# VULN-060 — QuickSearch attacker-controlled `limit` bypasses the list cap -> memory/DB exhaustion

**ID**: VULN-060
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1: 6.5** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`
**Status**: **CONFIRMED (dynamic)**
**Auth required**: Any authenticated user (low-privileged; QuickSearch is wired into every EditView, not admin-gated).
**What an attacker gains**: the ability to defeat the server's own row-count safety ceiling with a single request, driving an arbitrarily large list query and SugarBean-hydration pass — a single-request memory-exhaustion (worker-kill) primitive.

## Summary

QuickSearch is the autocomplete backing every relate-field lookup in the UI.
Its JSON request body includes a `limit`. Instead of clamping that value to
the server's configured `list_max_entries_per_page` safety ceiling, the code
*raises* the ceiling to match whatever the client sent — with no maximum.
Any logged-in user (no special privilege required) can therefore force a
single QuickSearch request to return, and have the server hydrate, far more
rows than the application is normally configured to allow — up to and
including a value large enough to exhaust PHP's memory limit.

## How it works (mechanism & code trace)

**Entry point**: `POST index.php?module=Home&action=quicksearchQuery&to_pdf=true`
(any authenticated session) → `modules/Home/quicksearchQuery.php`:
```php
// modules/Home/quicksearchQuery.php:56-57
$json = getJSONobj();
$data = $json::decode(html_entity_decode((string) $_REQUEST['data']));   // attacker-controlled array, no schema check
```

**The defect** — the safety ceiling is raised FROM the value it should be
capping:
```php
// modules/Home/QuickSearch.php:514-517  (prepareArguments)
// override query limits
if (isset($args['limit']) && $sugar_config['list_max_entries_per_page'] < ($args['limit'] + 1)) {
    $sugar_config['list_max_entries_per_page'] = ($args['limit'] + 1);   // <-- no upper clamp
}
```

**Sink** — the same attacker value flows straight into the DB query:
```php
// modules/Home/QuickSearch.php:374, 459
$limit = !empty($args['limit']) ? (int)$args['limit'] : '';
...
$result = $focus->get_list($orderBy, $where, 0, $limit, -1, 0, $singleSelect);
```
The exact defect is the direction of the comparison at `:515-517`: a
correct implementation would take `min($args['limit'], $sugar_config['list_max_entries_per_page'])`
(client input never widens the ceiling); instead it takes the client value
whenever it is *larger*, which is backwards — it only ever loosens the cap,
never tightens it.

## Why it is a vulnerability (reasoning)

`list_max_entries_per_page` exists precisely so that no single list query —
regardless of who issues it or with what filter — can force the server to
materialize an unbounded result set. Every other list view in the
application (search results, related-list subpanels, reports) is built to
respect this ceiling as an *application-enforced* invariant, independent of
what any individual request asks for. QuickSearch's `prepareArguments()`
inverts that invariant for its own request only: the requester's own
`limit` becomes the new ceiling. There is no legitimate reason an
autocomplete widget — whose entire purpose is returning a handful of
best-matching suggestions — needs to request more rows than the global
default; a value here above single digits is already anomalous. Nothing
about the code suggests this was an intentional "power user" override (no
capability check, no config toggle) — it reads as the classic bug of testing
`if (input > current) { current = input; }` where the intent was almost
certainly `min()`.

## Reproduction

Preconditions: any authenticated session (a freshly created, non-admin user
was used here to show privilege is irrelevant).

1. `POST /index.php?module=Home&action=quicksearchQuery&to_pdf=true` with
   `data={"method":"query","modules":["Accounts"],"field_list":["name","id"],
   "group":"or","conditions":[{"name":"name","op":"like_custom","end":"%","value":""}],
   "limit":45}` (see `request.http`).
2. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. It sends this at `limit=15`,
   `limit=45`, and with no `limit` key (control), non-destructively.
3. Expected: `==> VULN-060: CONFIRMED — authenticated (non-admin) QuickSearch
   request with limit=45 returned totalCount=45 > configured default cap 20`.
4. Observable proof (`evidence/results.txt`):
   ```
   limit=15 (below cap)  -> totalCount=15
   limit=45 (above cap)   -> totalCount=45
   no limit key (baseline)   -> totalCount=20
   ```
   The control alone (`totalCount=20` with no `limit` key) proves 20 is the
   real, enforced ceiling in every other case; `limit=45` breaking past it to
   exactly 45 proves the override is live and unbounded.

**What was not sent, and why the conclusion still holds**: the finding's own
reproduce steps use `limit=100000000`. This script never sends that —
consistent with stage-10's bounded-DoS rule, a value that large would ask
MySQL for up to 100,000,000 rows and PHP for that many `SugarBean` objects,
reliably exhausting `memory_limit`. The 15→15, (no-limit)→20, 45→45 sequence
already proves the mechanism (uncapped, request-controlled ceiling) with
certainty; only the scale of the eventual OOM crash is extrapolated rather
than reproduced.

## Impact

Any authenticated user — including the lowest-privileged account in the
system — can single-handedly crash or badly degrade the PHP worker pool
serving *all* users, by sending one crafted autocomplete request. Because
PHP-FPM/Apache workers are typically shared across all concurrent users,
this is an application-wide availability impact from a single low-privilege
session, and it is trivially repeatable. No confidentiality or integrity
impact.

## Suggested fix

- `modules/Home/QuickSearch.php:515-517`: replace the "raise if larger" logic
  with a hard clamp: `$limit = min((int)$args['limit'], $sugar_config['list_max_entries_per_page']);`
  and never write back into `$sugar_config['list_max_entries_per_page']` from
  request input at all — that global should only ever be set from the admin
  configuration.
- Principle: a client-supplied value may narrow a result set; it must never
  be allowed to widen a server-enforced safety ceiling.

## References

- CWE-770: Allocation of Resources Without Limits or Throttling — https://cwe.mitre.org/data/definitions/770.html
- OWASP Denial of Service Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM QuickSearch "limit" denial of service list_max_entries_per_page` — only forum threads on pagination bugs and `resource_management` query limits; no advisory or CVE.
2. `SuiteCRM quicksearchQuery vulnerability CVE` — no CVE names `quicksearchQuery`/`QuickSearch`; results are unrelated SQLi CVEs (CVE-2024-49773 export `current_post`, CVE-2024-50332 DeleteRelationShip, CVE-2022-50589 export `uid`).
3. `SuiteCRM denial of service CVE memory exhaustion authenticated 2025 2026` — CVE-2026-29101 (GHSA-24pf-9cvh-ppcg, fetched: "Directory Traversal to DoS in Modules", CWE-23, PR:H) and CVE-2024-36416 (v4 API example log-flood DoS); neither is the QuickSearch limit override.
4. Full SuiteCRM GHSA catalogue (77 published advisories through 2026-10-12) reviewed — DoS-related entries are GHSA-24pf-9cvh-ppcg (path traversal), GHSA-jrpp-22g3-2j77 (v4 API log DoS), GHSA-x3p2-qcqh-qx2m (RSS dashlet SSRF/DoS); none concern `modules/Home/QuickSearch.php`.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-29101 / GHSA-24pf-9cvh-ppcg — DoS via relative path traversal in modules (admin-level), fixed 7.15.1; different component and root cause.
- CVE-2024-36416 / GHSA-jrpp-22g3-2j77 — unauthenticated DoS by flooding the deprecated v4 API example log; different component.
- GHSA-x3p2-qcqh-qx2m — SSRF/DoS via RSS Feed Dashlet; different component.

**Reasoning:** No public advisory, CVE, issue or forum post describes `QuickSearch::prepareArguments()` raising `list_max_entries_per_page` from the client-supplied `limit` with no clamp. SuiteCRM's DoS advisories to date are path-traversal and log-flood issues in other modules. Caveat: resource-exhaustion bugs are a low-prestige class that often go unreported, and the WebSearch budget was exhausted before a SugarCRM-heritage query could be run against the same (inherited) code.
