# VULN-004 — Stored XSS: rich-text sanitizer skipped on the web & API content-save channels

## Header

- **Title:** Stored XSS — `cleanUnsafeHtml` sanitizer skipped on web/API content-save via an inverted `base64` gate
- **ID:** VULN-004
- **Severity:** **High** — CVSS 3.1 **8.0** `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N`
- **Status:** CONFIRMED (dynamic) — payload **executed in a real headless browser**
- **Affected version / commit:** PublicCMS `V5.202608.a`, commit `e85ab023a22b19bff5b5b0c944440ab614df467f`
- **Auth required:** **User (low-privilege)** — a registered contributor (web channel) or an app-token + user-token holder (API channel). No admin rights.
- **Known-issue status:** known class for PublicCMS (CVE-2020-21333 / CVE-2025-65837); the base64-gate mechanism is possibly novel.

## Summary

The rich-text sanitizer is gated on a `base64` boolean, and the three content-save channels pass it with the trust relationship **inverted**: the most-trusted admin channel passes `true` (sanitized), while the least-trusted web and API channels pass `false` and store attacker HTML verbatim. A low-privilege user can store `<script>`/`<img onerror>` that is emitted un-escaped (the template renders the body with `?no_esc`) — confirmed executing in a real browser both on the public content page and, critically, in the admin-review UI, giving a low-priv → admin escalation.

## Technical details

### Root cause

The sanitizer runs **only when `base64 == true`** (`targets/PublicCMS/publiccms-parent/publiccms-core/src/main/java/com/publiccms/logic/service/cms/CmsContentService.java:248-251`):

```java
if (null != attribute.getText() && base64) {
    attribute.setText(HtmlUtils.cleanUnsafeHtml(
        new String(VerificationUtils.base64Decode(attribute.getText()), StandardCharsets.UTF_8), site.getSitePath()));
}
```

The three callers pass different flags:

```java
// ContentController.java:130 (web)         -> initContent(..., attribute, false, ...)  base64=false  -> NOT sanitized
// ContentCreateDirective.java:200 (API)    -> initContent(..., attribute, false, ...)  base64=false  -> NOT sanitized
// CmsContentAdminController.java:174 (admin)-> initContent(..., attribute, true,  now)  base64=true   -> sanitized
```

### Data flow

Low-priv user → `POST /content/save` (or `GET /api/contentCreate`) with `text=<img src=x onerror=…>` → `initContent(..., base64=false)` → the `cleanUnsafeHtml` branch is skipped → `cms_content_attribute.text` stores the payload **verbatim**. On render, the deployed template `content.html:46` emits `${(arrtibute.text?no_esc)!}` — `?no_esc` explicitly disables FreeMarker auto-escaping — so the raw HTML reaches the DOM inside `<div class="content">`. The only transform on the raw path is `HtmlUtils.removeHtmlTag`, which builds the description/search excerpt, **not** the stored body (`ContentCreateDirective.java:202`).

### Why existing mitigations don't apply

- **Approval does not repair it:** `check`/`checkInProcess` only `setStatus(STATUS_NORMAL)`, so a raw body survives moderation onto the public site.
- **Template auto-escaping is bypassed by design** for this field (`?no_esc`), because the field is *meant* to hold sanitized HTML — but the web/API channels never sanitize it.
- The `/content/<id>` page is reachable **without auth**, so the payload fires for any public visitor, and it also fires in the admin-review UI when a moderator opens the pending item (execution in the admin origin).

## Reproduction

1. **Bring up the target** (see the manifest `## Runtime`):
   ```bash
   cd targets/PublicCMS
   DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker compose -p cvehunt_publiccms up -d --build
   bash ../../claude_audit/PublicCMS/setup/install.sh   # first run only
   ```
2. **Run the exploit** from this directory (needs Docker for the containerized Playwright step):
   ```bash
   cd claude_audit/PublicCMS/exploits/VULN-004 && ./automation.sh
   ```
   The script provisions an app (authorized for `contentCreate`) + token and a low-priv contributor (random suffix), stores a marker payload (`<img src=x onerror=window.__xss_<S>=1> <script>window.__xss2_<S>=1</script>`) via `/api/contentCreate` with `base64=false`, verifies the DB stored it verbatim and the page emits it un-escaped, then loads `/content/<id>` in a real headless browser (`mcr.microsoft.com/playwright:latest`, pinned `playwright@1.46.1`) and checks both marker globals were set.
3. **Expected output:** `[OK] stored XSS EXECUTED in a real browser` and `[OK] exploit confirmed — low-priv-authored stored XSS executed in a real browser`.
4. **Confirm exploitation:** `evidence/stored_text.txt` shows the raw payload as stored; `evidence/rendered_page.html` shows it un-escaped in the HTML; `evidence/browser_run.log` shows `img.onerror executed … = 1` and `<script> executed … = 1`; `evidence/xss_fired.png` is the browser screenshot.

- See `request.http` / `response.txt` for the save request, `evidence/` for the stored/rendered/executed proof, and `run.log` for the full run.

## Impact

Script authored by a low-privilege submitter executes in the **moderator/admin browser origin** when content is reviewed — enabling admin session/cookie theft or admin-authenticated actions (low-priv → super-admin escalation) — and in every visitor's origin after approval (public-site XSS).

- **Chains to [VULN-001](../VULN-001/writeup.md) / [VULN-003](../VULN-003/writeup.md)** via the admin foothold obtained from stolen admin session.
- **Chains with [VULN-007](../VULN-007/writeup.md)** — a token holder can plant this payload into *another* user's (e.g. an admin's) article.

## Suggested fix

Bind sanitization to the save operation, not to an unrelated encoding flag:

1. **Always sanitize the stored body**, regardless of `base64`. In `CmsContentService.initContent`, decode when `base64` is set but run `cleanUnsafeHtml` unconditionally on the resulting HTML:
   ```java
   if (null != attribute.getText()) {
       String html = base64
           ? new String(VerificationUtils.base64Decode(attribute.getText()), StandardCharsets.UTF_8)
           : attribute.getText();
       attribute.setText(HtmlUtils.cleanUnsafeHtml(html, site.getSitePath()));   // sanitize on every channel
   }
   ```
2. This makes the web (`ContentController`), API (`ContentCreateDirective`) and admin (`CmsContentAdminController`) channels converge on one choke point, so no future caller can opt out of sanitization by passing `base64=false`.
3. Keep the `?no_esc` render only if step 1 guarantees the field is always sanitized before storage; otherwise switch the template to contextual auto-escaping for that field.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 45 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `PublicCMS CVE 2025 2026 security advisory sanluan` + full PublicCMS CVE listing (releasealert.dev, 49 CVEs) — XSS entries are CVE-2020-21333 (front-end case submission → admin review), CVE-2025-65837 (Content Search), CVE-2026-36521 (site configuration), CVE-2025-69437 / CVE-2023-51252 (uploaded PDF/HTML), CVE-2024-46410 / CVE-2024-11070 / CVE-2024-11175 (admin forms); none names `/content/save`, `/api/contentCreate`, `CmsContentService.initContent` or `cleanUnsafeHtml`
2. GitHub Advisory Database search `publiccms`, pages 1–3 (58 advisories) — same set; no advisory on the content-save sanitizer
3. GitHub issue search `is:issue xss OR vulnerability OR security OR CVE OR 漏洞` (43 issues, both pages) — XSS issues #22 / #25 / #60 / #64 / #66 / #104 are admin-side (logo, categoryType, file management, template management); #27 and #37 examined below
4. Issue #27 (CVE-2020-21333) — stored XSS submitted through the public case-contribution form, executing when an admin reviews it; fixed Dec 2019 by flagging contributed articles and escaping unreviewed submissions by default
5. Issue #37 (Apr 2020) — "insert the xss payload into the background database", no endpoint named; fixed by commit a1f1a21; nothing about the contribution channels
6. Issue #104 (Dec 2025, V5.202506.d) — admin template-file management; maintainer: "online development feature", not a bug
7. (Planned WebSearch queries `PublicCMS stored XSS contentCreate API content save sanitizer bypass CVE` and `PublicCMS cross-site scripting content text HtmlUtils sanitize vulnerability 2025 2026` could not be executed — the shared search budget was exhausted; items 2–6 were fetched directly instead)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2020-21333 / sanluan/PublicCMS#27 — same entry channel (front-end content contribution) and same admin-review sink in PublicCMS 4.0 (2019), fixed by escaping unreviewed submissions; does not describe the `base64`-gated `cleanUnsafeHtml` skip in `CmsContentService.initContent`, the `/api/contentCreate` channel, or the `?no_esc` public render. Strongest near-miss.
- CVE-2025-65837 — XSS in the Content Search module (different component)
- CVE-2026-36521 — XSS in the site configuration module (admin side)
- CVE-2025-69437 / CVE-2023-51252 — stored XSS via uploaded PDF/HTML files (different sink)

**Reasoning:** No public CVE, advisory or issue describes the specific defect (the rich-text sanitizer is only applied when `base64=true`, so the web and API save channels store raw HTML). CVE-2020-21333 covered the same contribution channel and admin-review sink six years earlier and was fixed then, so this is judged a distinct (regressed or new-code-path) bug rather than a re-report, but the overlap is substantial and a triager could reasonably treat it as a variant of that CVE; confidence is lowered accordingly. PublicCMS has a long public XSS history, so a private report of this exact path may exist.
