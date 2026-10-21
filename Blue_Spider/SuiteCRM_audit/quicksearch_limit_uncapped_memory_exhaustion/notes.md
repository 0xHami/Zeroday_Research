# VULN-060 — QuickSearch attacker-controlled `limit` bypasses the list cap

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium — CVSS 6.5
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T21:45Z

## Preconditions
- One fresh, non-admin, low-privileged user (created via the shared
  `create_user()` helper) — the finding's premise is that *any* authenticated
  session suffices, not just admin, so a low-priv account is the stronger
  demonstration.
- Discovered during validation: the real client always adds `to_pdf=true` to
  this request (`include/javascript/quicksearch.js`) — without it, `index.php`
  renders the full Home page HTML instead of invoking
  `modules/Home/quicksearchQuery.php`'s raw JSON output. Added once this was
  found; noted here since it is not mentioned in the static finding.

## Request
See `request.http`. Three POSTs to `module=Home&action=quicksearchQuery&to_pdf=true`,
differing only in the JSON `data.limit` field: 15, 45, and omitted (control).

## Response
See `response.txt` and `evidence/results.txt`.

## Observation
Exact match to the static prediction, and unusually clean:
- No `limit` key → `totalCount=20` — confirms 20 is genuinely the enforced
  `list_max_entries_per_page` default under normal use.
- `limit=15` → `totalCount=15`.
- `limit=45` → `totalCount=45` — more than double the configured cap, from a
  non-admin session, with a single request.

This directly demonstrates `QuickSearch.php:515-517`'s defect: the same
per-request value that is supposed to be *constrained by*
`list_max_entries_per_page` is instead allowed to *raise* it, with no upper
bound. The script deliberately never sent the attacker's real payload
(`limit=100000000`, per the static finding's own reproduce steps) — bounded
per stage-10 safety rules — but the linear relationship observed at 15/45
rows leaves no ambiguity about what a larger value would do: MySQL would be
asked for that many rows via `get_list($orderBy, $where, 0, $limit, -1, 0, ...)`
(`QuickSearch.php:459`), and PHP would attempt to hydrate one `SugarBean`
object per returned row.

## Side effects
None persisted — QuickSearch is read-only (a search query). The one
low-privileged test user created remains (harmless, random-suffixed,
consistent with other findings' test users in this lab).

## Research & references
- CWE-770 (Uncontrolled Resource Consumption). OWASP: "Denial of Service
  Cheat Sheet", unbounded-query-result pattern —
  https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
