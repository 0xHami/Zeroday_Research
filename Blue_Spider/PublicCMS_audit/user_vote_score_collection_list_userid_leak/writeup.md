# VULN-011 — Unauthenticated deanonymization of any user's votes / scores / collections

## Header

- **Title:** Unauthenticated enumeration / deanonymization of any user's votes, scores and collections by `userId`
- **ID:** VULN-011
- **Severity:** **Medium** — CVSS 3.1 **5.3** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Status:** CONFIRMED (dynamic) — scores + collections proven; votes are the same code path (need an existing poll).
- **Affected version / commit:** PublicCMS `V5.202608.a`, commit `e85ab023a22b19bff5b5b0c944440ab614df467f`
- **Auth required:** **None** (unauthenticated over `/api/*`)
- **Known-issue status:** sibling of **CVE-2026-8737**; the deanonymization angle is possibly novel.

## Summary

`CmsUserVoteListDirective` / `CmsUserScoreListDirective` / `CmsUserCollectionListDirective` take the subject `userId` from the request and pass it straight to a service `getPage` overload with no token and no site filter. An anonymous caller names any `userId` and receives that person's complete on-site activity — including non-anonymous vote choices and, for scores, the recording client IP. Unlike the blind id-iteration of [VULN-005](../VULN-005/writeup.md), the harm here is *targeted*: pick a person, read their behaviour.

## Technical details

### Root cause

`targets/PublicCMS/publiccms-parent/publiccms-core/src/main/java/com/publiccms/views/directive/cms/CmsUserVoteListDirective.java:52-53`:

```java
PageHandler page = service.getPage(handler.getLong("userId"), handler.getLong("voteId"),
        handler.getBoolean("anonymous"), handler.getString("orderType"),
        handler.getInteger("pageIndex", 1), handler.getInteger("pageSize", 30));
```

The `userId` is request-supplied and flows into a `getPage` overload that does not even filter by site. The same pattern is present in `CmsUserScoreListDirective`, `CmsUserCollectionListDirective`, and the single-entity `CmsUserVoteDirective`/`CmsUserScoreDirective`. None of these override `needAppToken()`/`needUserToken()` (re-verified live), so they run for anonymous callers.

### Data flow

Anonymous caller → `GET /api/directive/cms/userScoreList?userId=<victim>&pageSize=100` → `service.getPage(userId, …)` returns every score row for that user → serialized to JSON, including `score`, `itemType`/`itemId`, `createDate` **and the recording `ip`**. The intended template usage fixes the subject to the current viewer (`userId=${user.id}`); over HTTP the attacker names anyone.

### Why existing mitigations don't apply

There is no auth on these directives and no derivation of the subject from a session — the `userId` filter is entirely attacker-chosen. The score record additionally leaks the client IP, an extra deanonymization signal not called out statically.

## Reproduction

1. **Bring up the target** (see the manifest `## Runtime`):
   ```bash
   cd targets/PublicCMS
   DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker compose -p cvehunt_publiccms up -d --build
   bash ../../claude_audit/PublicCMS/setup/install.sh   # first run only
   ```
2. **Run the exploit** from this directory:
   ```bash
   cd claude_audit/PublicCMS/exploits/VULN-011 && ./automation.sh
   ```
   The script seeds a victim (via admin) who collects and scores an existing content item, then makes anonymous `GET`s to `userCollectionList?userId=<victim>` and `userScoreList?userId=<victim>` and asserts the victim's activity is returned.
3. **Expected output:** `[OK] exploit confirmed — anonymous caller read victim userId=<n> activity (collection + score, incl. client IP)`.
4. **Confirm exploitation:** `evidence/collections.json` and `evidence/scores.json` contain the victim's records, e.g. `{"id":{"userId":"9","itemType":"content","itemId":"1"},"score":5,"ip":"172.19.0.1",…}`. `userVoteList?userId=<n>` behaves identically (exposes non-anonymous poll choices) where a poll exists.

- See `request.http` / `response.txt` for the requests, `evidence/` for the leaked activity, and `run.log` for the full run.

## Impact

Anonymous profiling/deanonymization of any named user: how they voted (including choices marked non-anonymous), what they rated, what they collected, and the IP they used. Supports targeted harassment or coercion, and with [VULN-002](../VULN-002/writeup.md) links a real identity (name/phone/address) to that activity. Violates the anonymity users reasonably expect for poll participation.

## Suggested fix

Require an authenticated user token and derive the subject from it (identical to the [VULN-002](../VULN-002/writeup.md) / [VULN-005](../VULN-005/writeup.md) class fix):

```java
@Override
public boolean needUserToken() { return true; }

@Override
public void execute(RenderHandler handler) throws ... {
    SysUser user = getUserFromToken(handler);          // authenticated caller
    PageHandler page = service.getPage(user.getId(),   // subject = the token owner, NOT a request param
            handler.getLong("voteId"), ...);
    ...
}
```

If staff need to read another user's activity, gate that on an admin capability rather than exposing it on the anonymous directive API. For vote lists specifically, also honour the poll's `anonymous` flag server-side so non-anonymous choices are never disclosed to third parties. Apply the same fix to the score/collection list directives and the single-entity `CmsUserVote`/`CmsUserScore` directives.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `PublicCMS CVE 2025 2026 security advisory sanluan` + full PublicCMS CVE listing (releasealert.dev, 49 CVEs) — no entry for `CmsUserVoteListDirective`, `CmsUserScoreListDirective`, `CmsUserCollectionListDirective`, `userVoteList` / `userScoreList` / `userCollectionList`, or user-activity disclosure; the only vote-related CVE is CVE-2024-11175 (admin XSS in `/admin/cmsVote/save`)
2. GitHub Advisory Database search `publiccms`, pages 1–3 (58 advisories) — the only directive leaks are CVE-2026-8737 (`TradeAddressListDirective`), CVE-2026-8740 (`TemplateResultDirective`) and CVE-2022-29784 (`SysConfigDataDirective`)
3. GitHub issue search `register OR emailChecked OR contentCreate OR refund OR directive OR vote OR race OR draft OR userId` — 4 results, none about user vote / score / collection directives
4. GitHub issue search `xss OR vulnerability OR security OR CVE OR 漏洞` (43 issues) — nothing on activity deanonymization
5. CVE-2026-8737 (Tenable) — `TradeAddressListDirective.execute`, `userId` / `id` manipulation without authentication; trade addresses only
6. (Planned WebSearch `PublicCMS userScoreList userId directive disclosure` could not be executed — shared search budget exhausted; replaced by direct fetches 2–5)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-8737 — identical pattern (request-supplied `userId` into an anonymous list directive) on `TradeAddressListDirective`; different directives and data (vote choices, scores incl. client IP, collections)
- CVE-2022-29784 — `SysConfigDataDirective` information leak; different directive
- CVE-2024-11175 — XSS in the admin vote editor; unrelated sink

**Reasoning:** No public reference covers the user vote / score / collection list directives or the deanonymization of a named user's activity and recording IP. The exact same code pattern was published for the trade-address directive (CVE-2026-8737) in May 2026, so a reporter who audited the sibling directives may hold an undisclosed report; confidence is reduced for that reason, but nothing public names these components.
