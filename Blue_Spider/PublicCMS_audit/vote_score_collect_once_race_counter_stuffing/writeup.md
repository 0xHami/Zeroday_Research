# VULN-012 — Redemption race in "vote/score/collect once" → counter / ballot stuffing

## Header

- **Title:** Redemption race in "vote once / score once / collect once" → counter / ballot stuffing (TOCTOU)
- **ID:** VULN-012
- **Severity:** **Medium** — CVSS 3.1 **5.3** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` (`PR:N` for anonymous-vote polls)
- **Status:** CONFIRMED (dynamic)
- **Affected version / commit:** PublicCMS `V5.202608.a`, commit `e85ab023a22b19bff5b5b0c944440ab614df467f`
- **Auth required:** **Authenticated web user** for score/collect and logged-in vote; anonymous for `allowAnonymous` votes.
- **Known-issue status:** no matching public advisory — possibly novel.

## Summary

Each "use-once" action (vote/score/collect) reads the per-user marker, then increments a counter and inserts the marker in **separate, independently-committed transactions**, with no row lock, no atomic conditional, and no per-user throttle on the logged-in path. K concurrent requests from one user all read a null marker and all commit their increment; the unique marker PK prevents duplicate marker *rows* but does not roll back the already-committed counter increments. Confirmed: 40 parallel collects from one user inflated the counter by 7 while only 1 marker row exists.

## Technical details

### Root cause

`targets/PublicCMS/publiccms-parent/publiccms-core/src/main/java/com/publiccms/controller/web/cms/VoteController.java:94-106` (score/collect are analogous):

```java
CmsUserVote entity = userVoteService.getEntity(id);   // (txn) "have I voted?" -> null
if (vote && null == entity) {
    entity = new CmsUserVote(); entity.setId(id); ...
    userVoteService.save(entity);              // (txn) INSERT marker
    voteItemService.updateVotes(itemId, 1);   // (txn) item.votes += 1 (non-atomic RMW) -> COMMITS
    service.updateVotes(siteId, cmsVote.getId(), 1);   // (txn) vote.votes += 1 -> COMMITS
}
```

The services are class-level `@Transactional`; the controllers are not, so the check and the record are distinct transactions. Counters are non-atomic read-modify-write via Hibernate dirty-checking, not SQL `SET x = x + 1`.

### Data flow

One user fires K concurrent `POST /collection/collect?contentId=<id>` (or `/vote/vote`, `/score/score`) → each request's "have I already?" read sees `null` (the marker isn't committed yet) → each proceeds to `updateCollections(+1)` which commits → the marker INSERTs race: one wins, the rest hit a duplicate-key rollback **that only reverts the marker transaction** — the counter increments have already committed. Net effect: 1 marker row, but the counter over-counts by up to K.

### Why existing mitigations don't apply

The unique marker PK is the intended "once per user" guard, but it protects only the marker table, not the separately-committed counter. `VoteController` locks only the *anonymous* branch (`LockComponent`), not the logged-in path, so an authenticated user has no per-user throttle. The window is wide (multiple sequential service calls), so contention is easy to win.

## Reproduction

1. **Bring up the target** (see the manifest `## Runtime`):
   ```bash
   cd targets/PublicCMS
   DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker compose -p cvehunt_publiccms up -d --build
   bash ../../claude_audit/PublicCMS/setup/install.sh   # first run only
   ```
2. **Run the exploit** from this directory:
   ```bash
   cd claude_audit/PublicCMS/exploits/VULN-012 && ./automation.sh
   ```
   The script creates one web user, records the item's `collections` counter, fires 40 parallel `POST /collection/collect?contentId=1` from that single user, then compares the counter delta against the number of marker rows.
3. **Expected output:** `[OK] exploit confirmed — one user inflated the counter by 7 while owning 1 marker (should be +1)`. (Magnitude varies with contention; any delta > 1 proves the bug. Re-run or raise `K` if a run happens to win no races.)
4. **Confirm exploitation:** `content.collections` increased by >1 (e.g. 9→16) while `cms_user_collection` markers for the user = 1. The same pattern applies to `/vote/vote` and `/score/score`.

- See `request.http` / `response.txt` for the parallel requests, and `run.log` for the counter delta vs marker count.

## Impact

Defeats the "one per user" integrity guarantee: ballot/counter stuffing that skews poll tallies, star ratings, and popularity/collection metrics from a single account. Compounds [VULN-025](../VULN-025/writeup.md) when `static_after_*` is enabled (each raced increment also triggers a regeneration).

## Suggested fix

Make the check-and-record atomic and the counter update a conditional SQL statement:

1. **Insert the marker first and let the unique PK gate the whole operation** — only increment the counter if the marker INSERT actually created a row:
   ```java
   // one transaction: succeed only if this user had no marker yet
   if (userVoteService.saveIfAbsent(entity)) {          // INSERT ... ; returns false on duplicate-key
       voteItemService.updateVotes(itemId, 1);          // only runs when the marker was newly created
       service.updateVotes(siteId, voteId, 1);
   }
   ```
2. **Make counter updates atomic in SQL** (`UPDATE cms_vote_item SET votes = votes + 1 WHERE id = ?`) instead of Hibernate read-modify-write, so concurrent increments cannot lose updates.
3. Wrap the marker-check + counter-update in a single service-level transaction (move the logic out of the non-transactional controller), and/or add a per-user lock on the logged-in path as already exists for the anonymous branch.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `PublicCMS CVE 2025 2026 security advisory sanluan` + full PublicCMS CVE listing (releasealert.dev, 49 CVEs) — no race-condition, TOCTOU, counter-manipulation, or vote / score / collect integrity entry; the only vote-related CVE is CVE-2024-11175 (admin XSS in `/admin/cmsVote/save`)
2. GitHub Advisory Database search `publiccms`, pages 1–3 (58 advisories) — no CWE-362 / business-logic race entry
3. GitHub issue search `register OR emailChecked OR contentCreate OR refund OR directive OR vote OR race OR draft OR userId` — 4 results (#125, #113, #108, #107), none about voting, scoring or collections
4. GitHub issue search `xss OR vulnerability OR security OR CVE OR 漏洞` (43 issues) — nothing on concurrency or ballot stuffing
5. (Planned WebSearch `PublicCMS vote race condition counter` could not be executed — shared search budget exhausted; replaced by direct fetches 2–4)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2024-11175 — stored XSS in the admin vote management form; same feature area, unrelated vulnerability class
- None found for race conditions in PublicCMS

**Reasoning:** Nothing public describes the non-atomic check-then-increment in `VoteController` / score / collect or counter inflation from concurrent requests. Race-condition findings are rarely filed against this project (none in its 49-CVE history), which makes a prior public report unlikely; the residual uncertainty is only that the search budget limited keyword coverage.
