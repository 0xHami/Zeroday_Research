# VULN-007 — Lucene NativeQuery injection + cross-index content disclosure via the searcher endpoint

**Software**: Umbraco CMS
**Repository**: https://github.com/umbraco/Umbraco-CMS
**Affected version**: 18.3.0-rc (version.json; commit-pinned, no tagged release)
**Commit**: `cee7d8981ab0fd18b4dc96449ae071edf1aaf21e`
**Status**: CONFIRMED
**Severity (static)**: Medium (borderline — Settings-tier) — CVSS 3.1 `5.5` `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:L`
**Validated at**: 2026-09-29

## Preconditions
- Admin creates a document type (1 text property) and one **unpublished** document whose `body`
  property holds a random `topsecretval…` value (random each run → we assert this run's value).
- Admin creates a user group with **only** the Settings section (`Umb.Section.Settings`),
  `documentRootAccess=false`, no start node; creates a user in it and sets a password.
- Exploit logs in as that Settings-only user. All names/emails/secrets carry a random suffix.
- One admin token is reused for provisioning + indexing wait (backoffice tokens live ~20 min); the
  exploit does **not** re-authenticate in a loop (that trips Umbraco's rapid-login lockout).
- Examine indexes on save asynchronously; the exploit polls the targeted `nodeName:` query until the
  value is indexed (observed ~3 s idle, but can lag under load).

## Request
See `request.http`. All requests are sent as the **Settings-only** user:
- contrast: `GET /umbraco/management/api/v1/document/{docId}` → 403.
- disclosure: `GET /umbraco/management/api/v1/searcher/InternalIndex/query?term=nodeName:{name}&take=10`.
- injection: `GET …/searcher/InternalIndex/query?term=nodeName:{name} AND __IndexType:content`.
- malformed: `GET …/searcher/InternalIndex/query?term=*abc`.

## Response
See `response.txt` / `run.log` (this run's values):
- `GET /document/{docId}` (normal, content-authorized endpoint) → **403 Forbidden**.
- `GET /searcher/InternalIndex/query?term=nodeName:secretdoca6449e` → **200**, and the hit's
  `AllValues` contained `body = ["topsecretvald5bb729847a6"]` plus `__Key`, `nodeName`, `path`,
  `creatorName`, `writerName`, etc. — the full indexed field set of a document the user is 403-forbidden
  to read.
- `GET /searcher/ExternalIndex/query` (same node) → **200, total=0** → the leaked document is
  **unpublished/draft** (only the Internal index holds it) yet it still leaked.
- `GET /searcher/InternalIndex/query?term=nodeName:… AND __IndexType:content` → **200, total=1** →
  raw boolean/fielded Lucene syntax reaches `NativeQuery` unescaped.
- `GET /searcher/InternalIndex/query?term=*abc` → **HTTP 400** "Could not parse the query" (the
  ProblemDetails object carries `status:404` but the controller returns `BadRequest`) → the raw term is
  fed to Lucene's classic `QueryParser` (leading-wildcard `ParseException` path).

## Observation
Exactly matches the static finding. The searcher family is guarded only by the Settings **section**
policy (`SearcherControllerBase.cs:13`) with a single carve-out for the member index
(`QuerySearcherController.cs:78-82`). The Internal/External indexes are not additionally gated, the
endpoint returns `x.AllValues` (`:135`), and `term` is passed to `NativeQuery` after only `Trim()`
(`:84,110-113`). So a Settings-only user with no Content/Media section, no start-node scope and no
per-item `ContentPermission` reads the full property values of any content/media node (including
unpublished content) and injects arbitrary Lucene query syntax.

## Side effects
- Created 1 document type, 1 unpublished document, 1 user group, 1 user per run (all random-suffixed).
- Read-only against the target's data otherwise; no records modified.

## Research & references
- OWASP WSTG-ATHZ-04 (IDOR) / OWASP API1:2023 (Broken Object Level Authorization): identity A
  (Settings-only) reads object B's content it is not authorized for. https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP WSTG-INPV-05 family / query-language injection: attacker controls the query grammar
  (`NativeQuery` = Lucene classic `QueryParser`), contrast the safe `BackOfficeExamineSearcher` which
  escapes free text via `QueryParserBase.Escape`.
- GHSA-w5q3-9wf8-43gg (Management-API search-endpoint authz, fixed 17.6.2/18.1.1) — same
  cross-index-disclosure class; that fix did not gate this Settings-scoped searcher endpoint (source-
  confirmed present at 18.3.0-rc).

## If FAILED
n/a — CONFIRMED. (If content indexing does not complete within the poll budget under heavy load, the
exploit exits NEEDS_MANUAL rather than asserting falsely; re-run when the Examine queue has drained.)
