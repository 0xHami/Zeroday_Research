# VULN-004 — Stored XSS: sanitizer skipped on web/API content-save (base64 gate)

**Target name:** PublicCMS
**Target URL:** https://github.com/sanluan/PublicCMS
**Software version:** V5.202608.a
**Status**: CONFIRMED (executes in a real browser)
**Severity (static)**: High
**Target commit**: e85ab023a22b19bff5b5b0c944440ab614df467f
**Validated at**: 2026-09-19

## Preconditions
- A low-privilege contributor (web user) + app token for the API channel (both provisioned via
  admin here). No admin rights needed to author the payload.

## Request / Response
See `request.http`, `response.txt`, `evidence/stored_text.txt`, `evidence/rendered_page.html`,
`evidence/browser_run.log`, `evidence/xss_fired.png`.
- Store: `GET /api/contentCreate?...&text=<img src=x onerror=window.__xss_<S>=1> <script>window.__xss2_<S>=1</script>`
  (headers appToken/authToken/authUserId) → `{"result":"success",...}`.
- `cms_content_attribute.text` stores the payload **verbatim** (no sanitization).
- `GET /content/<id>` emits it **unescaped** inside `<div class="content">`.
- Playwright: `window.__xss_<S>=1` and `window.__xss2_<S>=1` both set → JS executed.

## Observation
The report's "LIKELY" is now CONFIRMED. Three facts line up: (1) the API/web save passes
`base64=false`, so `initContent`'s `cleanUnsafeHtml` gate is skipped and text is stored raw
(code + DB verified); (2) the deployed `content.html:46` renders `${(arrtibute.text?no_esc)!}` —
`?no_esc` explicitly disables FreeMarker auto-escaping; (3) a real headless browser executed both
the `<img onerror>` and the `<script>`. The content page is reachable at `/content/<id>` without
auth, so the payload fires for any viewer (public visitor) and for admins reviewing pending
content (low-priv → admin origin). The admin save channel (`base64=true`) sanitizes, confirming the
inverted-trust gate.

## Side effects
Creates app+token+contributor+one content item per run (random suffix). The content is a PoC
article containing the payload. Cleanup hint in script footer.

## Research & references
- CWE-79 (Stored XSS). PublicCMS prior class CVE-2020-21333 / CVE-2025-65837.
- OWASP WSTG-INPV-02 (Stored XSS) + XSS Prevention / DOM XSS Cheat Sheets — technique: inject an
  HTML/JS payload via a persistence channel, confirm it is emitted into an HTML context without
  contextual output encoding, and observe execution in a rendered DOM (done via Playwright markers).

## If FAILED
n/a — CONFIRMED. (Browser step needs docker + network to fetch playwright@1.46.1 matching the image.)
