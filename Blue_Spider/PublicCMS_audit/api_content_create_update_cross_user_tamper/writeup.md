# VULN-007 — Cross-user content tampering / unpublish via `/api/contentCreate` update branch

## Header

- **Title:** Cross-user content tampering and unpublish via the `/api/contentCreate` update branch (missing author check)
- **ID:** VULN-007
- **Severity:** **Medium** — CVSS 3.1 **6.5** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L`
- **Status:** CONFIRMED (dynamic)
- **Affected version / commit:** PublicCMS `V5.202608.a`, commit `e85ab023a22b19bff5b5b0c944440ab614df467f`
- **Auth required:** **App token + user token** — an app authorized for `contentCreate` and any valid user token for that site (not anonymous, but low-privilege).
- **Known-issue status:** no matching public advisory — possibly novel.

## Summary

On create, `ContentCreateDirective` correctly pins the content owner to the calling user; on **update** it authorizes on tenancy (`siteId`) only, omitting the object-level ownership check that the web content-edit path enforces. Any token holder can therefore overwrite content authored by anyone — including admins. Worse, because `status` is not in the update's ignore-list, each API update also resets the target to `STATUS_PEND`, silently unpublishing a currently-live article. Confirmed: a non-owner (id=12) overwrote an admin-owned (id=2), published article and dropped its status 1→2.

## Technical details

### Root cause

`targets/PublicCMS/publiccms-parent/publiccms-core/src/main/java/com/publiccms/views/directive/api/ContentCreateDirective.java:216-222`:

```java
if (null != entity.getId()) {
    CmsContent oldEntity = service.getEntity(entity.getId());
    if (null != oldEntity && site.getId() == oldEntity.getSiteId()) {   // <-- no oldEntity.getUserId()==user.getId()
        entity = service.update(entity.getId(), entity,
                entity.isOnlyUrl() ? CmsContentService.ignoreProperties : CmsContentService.ignorePropertiesWithUrl);
    }
} else {
    ...
    entity.setSiteId(site.getId());
    entity.setUserId(user.getId());   // create pins the owner
    service.save(entity);
}
```

The web edit path shows the intended check — `ContentController.java:135` verifies owner-or-superuser before update.

### Data flow

Attacker (holding a valid app token + user token for a *different* account) → `GET /api/contentCreate?id=<victim-content>&categoryId=…&modelId=…&title=…&text=…` → the update branch loads `oldEntity`, checks only `site.getId() == oldEntity.getSiteId()` → `service.update(...)` overwrites the body. Because `status` is not in `CmsContentService.ignoreProperties`, the update rewrites the target's status to `STATUS_PEND (2)`, removing a published article from public listings. The owner field is left unchanged, so the victim still "owns" the defaced/unpublished item.

### Why existing mitigations don't apply

The create branch pins the owner (`entity.setUserId(user.getId())`), which proves ownership is a known concept here — the update branch just omits the check. Tenancy scoping (`siteId`) is necessary but not sufficient: it stops cross-tenant edits, not cross-user edits within a tenant.

## Reproduction

1. **Bring up the target** (see the manifest `## Runtime`):
   ```bash
   cd targets/PublicCMS
   DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker compose -p cvehunt_publiccms up -d --build
   bash ../../claude_audit/PublicCMS/setup/install.sh   # first run only
   ```
2. **Run the exploit** from this directory:
   ```bash
   cd claude_audit/PublicCMS/exploits/VULN-007 && ./automation.sh
   ```
   The script provisions an app (authorized for `contentCreate`) + token, creates and publishes a VICTIM article owned by the admin (id=2), creates a low-priv ATTACKER user (id=12), then has the attacker `POST` an update to the victim's content id and asserts the body was overwritten and status reset 1→2.
3. **Expected output:** `[OK] exploit confirmed — non-owner (id=12) overwrote content owned by id=2 and unpublished it (status 1->2)`.
4. **Confirm exploitation:** the API returns `{"result":"success","contentId":"<victim>"}`; the DB after shows `title=PWNED_BY_ATTACKER_<S>`, `status=2`, `user_id=2` (owner unchanged) — see `evidence/content_after.txt`.

- See `request.http` / `response.txt` for the update request and response, `evidence/content_after.txt` for the mutated row, and `run.log` for the full run.

## Impact

Cross-author content tampering, defacement, and censorship (unpublish) of arbitrary articles — including admin-authored ones — by any provisioned principal. Combined with [VULN-004](../VULN-004/writeup.md) it plants stored XSS into a *victim's* article (so the payload appears to come from a trusted author). Enumerated ids from [VULN-005](../VULN-005/writeup.md) select the targets.

## Suggested fix

Add the object-level ownership check to the update branch, matching the web path:

```java
if (null != entity.getId()) {
    CmsContent oldEntity = service.getEntity(entity.getId());
    if (null != oldEntity
            && site.getId() == oldEntity.getSiteId()
            && oldEntity.getUserId() == user.getId()) {     // <-- owner check (or allow site admins explicitly)
        entity = service.update(entity.getId(), entity, ...);
    } else {
        handler.put("result", "error").render();            // reject cross-user edits
    }
}
```

Separately, **add `status` to `CmsContentService.ignoreProperties`** (and `ignorePropertiesWithUrl`) so an update cannot silently change publication state; status transitions should go through the explicit review/approve API, not a content overwrite.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `PublicCMS CVE 2025 2026 security advisory sanluan` + full PublicCMS CVE listing (releasealert.dev, 49 CVEs) — no entry for `ContentCreateDirective`, `/api/contentCreate`, or cross-user content update / unpublish
2. GitHub Advisory Database search `publiccms`, pages 1–3 (58 advisories) — closest is CVE-2026-110113 (`tradeAddress/save` cross-user overwrite), a different controller
3. GitHub issue search `register OR emailChecked OR contentCreate OR refund OR directive OR vote OR race OR draft OR userId` — 4 results, none about the content API
4. GitHub issue search `xss OR vulnerability OR security OR CVE OR 漏洞` (43 issues) — #107 (`/tradeAddress/save.html` update IDOR) is the same class in the trade module; nothing on content
5. Fix commit 7329437 (CVE-2026-2010) — hardened the `CmsContentSourceAdminController.save` and `TradeAddressController.save` update branches (`siteId` / `userId` added to `ignoreProperties`); `ContentCreateDirective` not touched
6. (Planned WebSearch `PublicCMS contentCreate update IDOR` could not be executed — shared search budget exhausted; replaced by direct fetches 2–5)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-110113 / sanluan/PublicCMS#107 — IDOR in `TradeAddressController` `tradeAddress/save` (members overwrite others' addresses); same class, different component
- CVE-2026-1112 — `TradeAddressController.delete` `ids` authorization bypass; different component
- commit 7329437 — update-branch hardening in `CmsContentSourceAdminController`; different controller, and does not add an owner check

**Reasoning:** No public reference covers the `/api/contentCreate` update branch, its missing owner check, or the status reset to pending. Public IDOR reports for PublicCMS in 2026 concentrate on the trade module; the content API path appears undisclosed, though the class is active enough that a private report is plausible.
