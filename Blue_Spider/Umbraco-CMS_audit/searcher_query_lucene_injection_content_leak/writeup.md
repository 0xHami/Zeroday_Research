# VULN-007 — Lucene `NativeQuery` injection + cross-index content disclosure in the backoffice searcher

| | |
|---|---|
| **ID** | VULN-007 |
| **Software** | Umbraco CMS |
| **Repository** | https://github.com/umbraco/Umbraco-CMS |
| **Affected version** | 18.3.0-rc (commit-pinned; no tagged release) |
| **Commit** | `cee7d8981ab0fd18b4dc96449ae071edf1aaf21e` |
| **Severity** | Medium (borderline) — CVSS 3.1 `5.5` (`AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:L`) |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | A backoffice user holding the **Settings** section — *including one explicitly denied the Content and Media sections*, with no start-node scope. Obtained here by the admin creating a Settings-only group + user (the normal invite flow). |
| **Attacker gains** | Full read of every content/media node's property values site-wide — including **unpublished/draft** content — bypassing section access, start-node isolation and per-item `ContentPermission`; plus arbitrary Lucene query injection (wildcard/fuzzy scans = index-DoS lever). |

## Summary

The backoffice searcher endpoint `GET /umbraco/management/api/v1/searcher/{searcherName}/query?term=` is guarded **only** by the Settings *section* policy, with a single carve-out for the member index. The Internal/External Examine indexes — which hold every content and media node's property values, and (Internal) **unpublished/draft** content — are not additionally authorized. The action returns each hit's `x.AllValues` (all indexed field values), and it passes the caller's `term` to Examine's `NativeQuery` (Lucene's classic `QueryParser`) after only a `Trim()`. Consequently a user who holds the Settings section but is **denied Content and Media** (and has no start-node scope and no per-item `ContentPermission`) can (a) read the full property values of any node through the searcher, and (b) inject arbitrary Lucene query syntax.

Dynamically confirmed: a **Settings-only** user (allowedSections `['Umb.Section.Settings']`) received **403 Forbidden** on `GET /document/{docId}` (the normal, content-authorized endpoint) yet **200 OK** on `GET /searcher/InternalIndex/query?term=nodeName:{doc}`, whose response leaked the document's secret `body` value `["topsecretvald5bb729847a6"]` together with `__Key`, `nodeName`, `path`, `creatorName`, `writerName`, … . The same document returned **total=0** from the External index, proving the leaked content is unpublished. A raw boolean/fielded query (`nodeName:… AND __IndexType:content`) parsed and matched, and a malformed leading-wildcard term (`*abc`) produced the Lucene `ParseException` path — both proving the raw term reaches the classic `QueryParser` unescaped.

## How it works (mechanism & code trace)

**Entry point / section floor.** The whole searcher family derives from a base that sets only the Settings *section* policy:

```csharp
// src/Umbraco.Cms.Api.Management/Controllers/Searcher/SearcherControllerBase.cs:11-14
[VersionedApiBackOfficeRoute("searcher")]
[Authorize(Policy = AuthorizationPolicies.SectionAccessSettings)]
public class SearcherControllerBase : ManagementApiControllerBase
```

`SectionAccessSettings` maps to the **Settings** application (`BackOfficeAuthPolicyBuilderExtensions.cs:100`). It is a floor, not a per-object check, and — crucially — it is **not** the Content or Media section. There is no start-node or `ContentPermission` check anywhere in the searcher pipeline.

**The only per-index carve-out is the member index.** The query action gates *only* member indexes:

```csharp
// Controllers/Searcher/QuerySearcherController.cs:78-82
if (_memberIndexAuthorizer.IsMemberIndex(searcherName)
    && await _memberIndexAuthorizer.HasAccessAsync(User) is false)
{
    return StatusCode(StatusCodes.Status403Forbidden);
}
```

`MemberIndexAuthorizer.IsMemberIndex` returns true only for `IUmbracoMemberIndex` (`MemberIndexAuthorizer.cs:28`). The **InternalIndex** and **ExternalIndex** are content/media indexes, so they fall through with no additional authorization.

**The injection sink.** The caller's `term` is passed to `NativeQuery` after only `Trim()`:

```csharp
// Controllers/Searcher/QuerySearcherController.cs:84,110-113
term = term?.Trim();
...
results = searcher
    .CreateQuery()
    .NativeQuery(term)                                   // raw term -> Lucene classic QueryParser
    .Execute(new LuceneQueryOptions(skip, take, skipTakeMaxResults: skip + take));
```

`NativeQuery` hands the string to Lucene's classic `QueryParser` — the user controls fields, boolean operators, wildcards, fuzzy terms, ranges. Confirmed live: `nodeName:… AND __IndexType:content` parsed and matched, and `*abc` (leading wildcard) threw `ParseException` (`:115-126` → the "Could not parse the query … starts with a wildcard" branch). The **safe** contrast is `Umbraco.Examine.Lucene/BackOfficeExamineSearcher.cs`, which escapes free text via `QueryParserBase.Escape` before searching — this endpoint does not.

**The full-field disclosure.** Every hit returns *all* of its indexed field values:

```csharp
// Controllers/Searcher/QuerySearcherController.cs:131-136
Items = results.Select(x => new SearchResultResponseModel
{
    Id = x.Id,
    Score = x.Score,
    Fields = x.AllValues.OrderBy(y => y.Key).Select(y => new FieldPresentationModel { Name = y.Key, Values = y.Value }),
}),
```

The content indexer (`Umbraco.Infrastructure/Examine/ContentValueSetBuilder.cs`) stores every property value plus metadata (`__Key`, `__NodeId`, `nodeName`, `path`, `creatorName`, …), so `AllValues` = the document's full content. The **InternalIndex** indexes unpublished/draft content (the ExternalIndex only published), so draft data leaks too — verified by the External-index `total=0` for the same node.

## Why it is a vulnerability (reasoning)

Umbraco's authorization model confines editors by **section** and, within Content/Media, by **start node** and per-item **ContentPermission**. A delegated "site-builder"/developer group is a real deployment pattern: give it Settings so it can manage data types/templates/languages, but deliberately withhold the Content section so it cannot read editorial content. This endpoint defeats that: the same identity, **403-forbidden** to read a document through `GET /document/{id}`, reads the document's complete property values (including unpublished drafts) through the searcher — no Content section, no start node, no per-item permission consulted. That is Broken Object/Function Level Authorization (OWASP API1/ API5:2023): authorization is enforced at the section floor of *other* endpoints but not on the searcher's object-returning path. Independently, feeding raw `term` to the classic `QueryParser` is query-language injection (OWASP WSTG injection); the sibling `BackOfficeExamineSearcher` escaping free text shows the intended-safe contract that this endpoint omits.

**Honest severity bound (why Medium, not High).** The gate is `PR:H`: the actor must already hold the **Settings** section, which on this product is a developer/administrator-tier capability that is independently powerful (e.g. template RCE, VULN-001). So the marginal risk is real only for installs that deliberately grant a group **Settings but not Content/Media** — a genuine but narrower configuration. Hence Medium/borderline. The injection half's realistic ceiling is expensive wildcard/fuzzy scans (`*a*~`) = an index-CPU DoS lever (`A:L`), not code execution — the query runs inside Lucene's search engine.

## Reproduction

From the running lab (`http://localhost:29184`), the exploit does everything end-to-end:

1. **Preconditions (as admin):** create a document type with a text property; create an **unpublished** document whose `body` = a random `topsecretval…`; create a user group with **only** `Umb.Section.Settings` (`documentRootAccess=false`, no start node); create a user in it and set its password. Poll the InternalIndex (targeted `nodeName:` query) until the value is indexed.
2. **Run:** `cd exploits/VULN-007 && ./run.sh`
3. **Boundary (as the Settings-only user):**
   ```
   GET /umbraco/management/api/v1/document/{docId}  ->  403 Forbidden
   ```
4. **Disclosure (same user):**
   ```
   GET /umbraco/management/api/v1/searcher/InternalIndex/query?term=nodeName:{doc}&take=10  ->  200
   fields: [ ... "alias":"body","values":["topsecretvald5bb729847a6"] ... __Key, nodeName, path, creatorName ... ]
   ```
5. **Unpublished proof:** `GET /searcher/ExternalIndex/query?term=nodeName:{doc}` → 200, **total=0**.
6. **Injection:** `GET /searcher/InternalIndex/query?term=nodeName:{doc} AND __IndexType:content` → 200, total=1; `…?term=*abc` → HTTP 400 "Could not parse the query".

Expected output ends with `[OK]`/`==> VULN-007: CONFIRMED`. Full capture: `run.log`, `request.http`, `response.txt`.

## Impact

- **Confidentiality (C:H):** complete read of every content and media node's property values site-wide — including unpublished/trashed/draft content via the Internal index — for a user with **no** Content/Media section, **no** start-node scope and **no** per-item permission. Collapses section- and start-node-based content isolation.
- **Availability (A:L):** the unescaped `NativeQuery` accepts expensive Lucene constructs (leading-wildcard/fuzzy term expansion), a lever for index-CPU DoS.
- **Attack cost:** one authenticated request per query; standard index field names (`__IndexType`, `nodeName`, `__Key`) enumerate all content.
- **Systemic siblings** (same class, same Settings floor): `DetailsIndexerController.cs:78-82` (field/count metadata) and `RebuildIndexerController.cs:95-99` (a Settings user triggering expensive rebuilds — another DoS lever).

## Suggested fix

Two independent defects, fix both:
1. **Escape / structure the query.** Escape `term` with `QueryParserBase.Escape` (as `BackOfficeExamineSearcher` does), or accept only a structured query model — do not hand raw input to the classic `QueryParser`.
2. **Scope reachable indexes to the caller's authorization.** Mirror the member-index authorizer for the content/media indexes: a Settings-only user with no Content/Media section (or a start-node-restricted user) must not read internal/external index values. Trim `AllValues` to fields the caller is entitled to, and apply the same to `DetailsIndexerController`/`RebuildIndexerController`.

## References
- OWASP API Security Top 10 — **API1:2023 Broken Object Level Authorization** & **API5:2023 Broken Function Level Authorization**: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP WSTG **WSTG-ATHZ-04** (Insecure Direct Object References) and the injection test family (attacker-controlled query grammar).
- PortSwigger Web Security Academy — server-side query/DSL injection concepts (untrusted input compiled into a query rather than treated as data).
- **GHSA-w5q3-9wf8-43gg** — "Insufficient authorization on Management API search endpoints" (fixed 17.6.2 / 18.1.1); same cross-index disclosure class, not applied to this Settings-scoped searcher route in 18.3.0-rc (source-confirmed).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 30 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `Umbraco searcher query endpoint "NativeQuery" Lucene injection Examine dashboard unpublished content disclosure Settings section` (WebSearch) — search budget exhausted before this query ran; no result returned.
2. WebFetch `github.com/umbraco/Umbraco-CMS/security/advisories/GHSA-w5q3-9wf8-43gg` — "Insufficient authorization on Management API search endpoints" (fixed 17.6.2 / 18.1.1): endpoints lacked the section check and "do not filter results against the calling user's permissions"; no mention of Lucene query injection or of Settings-only users.
3. `gh api repos/umbraco/Umbraco-CMS/commits/4558b7e4` (the GHSA-w5q3 fix, 2026-08-18) — adds `SectionAccessSettings` to `SearcherControllerBase`/`IndexerControllerBase` and a `MemberIndexAuthorizer` for member indexes only; no content/media result filtering, no escaping of `term`. Current `main` still passes `term.Trim()` to `NativeQuery`.
4. `gh api search/issues q='repo:umbraco/Umbraco-CMS QuerySearcherController OR NativeQuery searcher'` — only functional search issues (stop words, parse errors); nothing on authorization or injection.
5. GitHub advisory DB full listing for NuGet `Umbraco.Cms` — no other searcher/indexer advisory.

**Related but distinct public references** (same class or component, not this bug):
- GHSA-w5q3-9wf8-43gg — same endpoint family and the same "results not filtered against caller permissions" root cause, but scoped to the missing section gate; the vendor's fix deliberately chose the Settings section as the boundary, so the residual Settings-only disclosure may be regarded as by-design.
- CVE-2024-43377 / GHSA-hrww-x3fq-xcvh — generic "endpoints protected only by authentication" (14.1.2); different endpoints.

**Reasoning:** The cross-index disclosure half is a residual of a public advisory whose fix defined Settings-section access as sufficient, so a vendor is likely to classify it as accepted behaviour of the Examine developer dashboard; the raw-Lucene `NativeQuery` sink is not described anywhere public but is plausibly an intended feature of that dashboard. Nothing public matches the specific "Settings-without-Content user reads unpublished property values + query-language injection" combination, hence NOT KNOWN but with low confidence.
