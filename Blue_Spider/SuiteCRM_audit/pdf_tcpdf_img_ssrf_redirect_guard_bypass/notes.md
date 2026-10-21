# VULN-047 — TCPDF remote `<img>` SSRF on PDF generation (guard exists; redirect-bypass confirmed)

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 6.5 — see correction note; scored consistent with VULN-094, the sibling bypass)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:3x Z (see run.log)

## *** Correction to the static finding — read first ***
`VULN-047.md` states "No `validate_external_host()` anywhere in the PDF path." **This is incorrect for this commit.** `lib/PDF/TCPDF/SuiteTCPDF.php:92-99` overrides TCPDF's `Image()` method and explicitly calls `validate_external_host($file)` before fetching, returning `false` (skipping the image) if it fails. **TEST 1** below proves this guard is live: pointing `product_image` directly at the internal OOB listener produced **zero** hits. The sink is nonetheless exploitable — **TEST 2** proves TCPDF's own underlying fetch (inside the vendored library, called via `parent::Image()`) follows HTTP redirects with no re-validation, exactly the pattern already confirmed for the RSS dashlet in [VULN-094](../VULN-094/notes.md), and explicitly flagged there as a "sibling candidate" at this exact file:line. This finding is CONFIRMED as a **redirect-bypass of a real guard**, not as the "zero guard" bug the static write-up describes — treat this file, not the original VULN-047.md text, as authoritative on the mechanism.

## Preconditions
- Fresh non-admin user via `_common.create_user()`.
- Fixture seeded directly via `docker compose exec db mysql` (random-suffixed ids each run): one `AOS_Products` row (`product_image` set per-test below), one `AOS_Quotes` row assigned to the low-priv user, one `AOS_Products_Quotes` line item linking them, and one `AOS_PDF_Templates` row whose `description` is `&lt;tr&gt;$aos_products_product_image&lt;/tr&gt;` (HTML-entity-encoded).
  - **Why entity-encoded**: `generatePdf.php`'s `$search`/`$replace` pass (`:89-119`) strips **all** literal `<...>` tags from the template body *before* the product-image merge runs; only entities (`&lt;`/`&gt;`) that later steps in the *same* `preg_replace` array decode back into real tags survive to become the `<tr>` wrapper `populate_product_lines()` (`:273-320`) needs to find and repeat per line item. Verified directly during analysis via a standalone PHP probe replaying `generatePdf.php`'s merge logic against the real stored template/quote and printing each intermediate stage; final output for our fixture was exactly `<tr><img src="http://172.18.0.1:33119/canary-..." class="img-responsive"/></tr>`, confirming the merge mechanics before ever touching TCPDF.
- HTTP listener on `0.0.0.0:33119` (app reaches it at `172.18.0.1:33119`).

## Request
`POST /index.php?entryPoint=generatePdf` with `module=AOS_Quotes&uid=<quote_id>&templateID=<template_id>&task=pdf`, run twice (`request.http`) — once with `product_image` set directly to the internal listener, once set to a public `httpbin.org` redirector that 302s to the same listener (updated via `UPDATE aos_products SET product_image=... WHERE id=...` between the two calls).

## Response
Both calls return `HTTP 200`, `Content-Type: application/pdf`, a valid `%PDF-1.7` document (`response.txt`) — TCPDF completes normally either way; the difference is entirely in the OOB listener log.

## Observation
`evidence/oob_listener.log`:
```
GET /canary-pdfredir_2e6e7b4f
  User-Agent: tcpdf
GET /canary-pdfredir_2e6e7b4f
  User-Agent:
GET /canary-pdfredir_2e6e7b4f
  User-Agent:
```
Three hits, all for the **TEST 2 (redirect)** canary, **zero** for the TEST 1 (direct) canary — TCPDF fetches an image more than once internally (size probe + render), but only ever for the run where the guard was satisfied by the *original* URL. `User-Agent: tcpdf` on the first hit is TCPDF's own default HTTP client signature, independent confirmation this is the PDF engine's own fetch, not the exploit script (which never itself talks to port 33119).

## Side effects
- New throwaway `users` row; one `aos_products`/`aos_quotes`/`aos_products_quotes`/`aos_pdf_templates` row each (all random-suffixed, all owned by/assigned to the throwaway user).
- Six inbound HTTP GETs on the OOB listener across the two tests (0 + 3, plus TCPDF's typical double-fetch pattern).

## Research & references
- OWASP SSRF Prevention Cheat Sheet ("Disable HTTP redirections"): https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger, "Server-side request forgery (SSRF)" — bypassing filters via redirection: https://portswigger.net/web-security/ssrf
- Same technique and same public redirector (`httpbin.org/redirect-to`) as [VULN-094](../VULN-094/notes.md), applied to a second, independent sink (TCPDF `Image()` vs. `RSSDashlet::getRSSOutput()`) to demonstrate the gap is systemic to how this codebase uses `validate_external_host()` (once, pre-fetch, never on redirect hops) rather than a one-off.
