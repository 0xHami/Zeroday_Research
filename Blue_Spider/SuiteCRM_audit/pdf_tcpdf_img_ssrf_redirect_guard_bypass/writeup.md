# VULN-047 — TCPDF remote `<img>` SSRF on PDF generation (redirect-bypass of a real guard)

**ID**: VULN-047
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`suitecrm_version.php`), commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1 6.5** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N` (rescored consistent with the sibling redirect-bypass, [VULN-094](../VULN-094/writeup.md); see correction note below on why this differs from the original static score's premise)
**Status**: CONFIRMED (dynamic) — **mechanism corrected from the static finding; see §3**
**Auth required**: Any authenticated user with access to Quotes/Invoices and their Products line items (standard, unrestricted CRM modules) plus the ability to author an `AOS_PDF_Template` (also unrestricted by default) — a freshly-created, non-admin regular user is used throughout.
**What an attacker gains**: server-side SSRF triggered by the ordinary "Generate PDF" action on a quote, bypassing a real allow-list check via a one-hop HTTP redirect.

## 1. Summary

Rendering a Quote/Invoice to PDF embeds each line item's product image as an `<img src="...">` that TCPDF fetches server-side. Unlike some other sinks in this codebase's SSRF cluster, this one **is** guarded by `validate_external_host()` — confirmed live, pointing the image URL directly at an internal address produces no request at all. But the guard only inspects the URL the template author supplied; TCPDF's own image-loading code, entirely inside the vendored `tecnickcom/tcpdf` library, follows HTTP redirects on its own with no further validation. A URL that resolves to a genuine public server and 302-redirects to an internal address sails straight through.

## 2. How it works (mechanism & code trace)

**The guard** — `lib/PDF/TCPDF/SuiteTCPDF.php:92-99`, SuiteCRM's own override of TCPDF's `Image()`:
```php
public function Image($file, ...) {
    if (validate_external_host($file) === false) {
        return false;
    }
    return parent::Image($file, ...);   // :99 -- the real fetch, inside vendored TCPDF
}
```
This is real: pointing `product_image` directly at `172.18.0.1:33119` (the docker-internal address our OOB listener uses) and generating a PDF produces **zero** hits on the listener — TCPDF's `Image()` returns `false` before any network I/O happens, exactly as the guard is supposed to behave. **The static finding's claim that no such guard exists is wrong for this sink at this commit.**

**The gap** — `parent::Image()`, i.e. TCPDF's own image-loading path (`TCPDF_IMAGES`/`TCPDF_STATIC::fileGetContents()` inside `vendor/tecnickcom/tcpdf`), performs the actual HTTP fetch using PHP's `http://` stream wrapper or curl with default redirect-following behavior — and `validate_external_host()` is never consulted again for whatever URL a `Location:` header points to. So: author a template's merge data (or, as here, the underlying product) with an image URL on a real public host, and have that host respond with a redirect to the internal target.

**The merge chain that gets the `<img>` there at all** — `modules/AOS_PDF_Templates/templateParser.php:152`:
```php
if ($name === 'aos_products_product_image' && !empty($value)) {
    $value = '<img src="' . $value . '" class="img-responsive"/>';
}
```
`$value` is the product's raw `product_image` field (`varchar(255)`), attacker/user-controlled, surviving `cleanBean`/`purify_html` because it's a bare string field, not rich HTML.

## 3. Why it is a vulnerability (reasoning)

Structurally this is the same defect as [VULN-094](../VULN-094/writeup.md), applied to a different fetch client: a real, purpose-built allow-list is checked exactly once, against the URL as originally supplied, and the follow-up network operation is delegated to a library (TCPDF) that was never told about that allow-list and does its own thing with redirects by default. The guard's *presence* here (unlike the RSS dashlet's title-fetch sink, [VULN-014](../VULN-014/writeup.md), which has no guard at all) shows the developers understood this exact class of user-controlled-URL risk for this sink specifically — which makes the gap more concerning, not less: a reviewer skimming `SuiteTCPDF.php:95` would reasonably conclude this path is safe, when it is not. A defense that silently stops covering the request the moment a redirect is involved is not a defense a security reviewer — or the code's own author — can rely on.

## 4. Reproduction

From a clean state:

1. **Preconditions**: `automation.py` creates a throwaway non-admin user, seeds a minimal Quote + Product + line item + PDF template fixture directly via `docker compose exec db mysql` (the template body uses `&lt;tr&gt;$aos_products_product_image&lt;/tr&gt;`, HTML-entity-encoded so it survives `generatePdf.php`'s tag-stripping pass before decoding back into a real `<tr>` — verified independently by replaying the merge logic and inspecting each intermediate string), and starts an OOB HTTP listener on `172.18.0.1:33119`.
2. **TEST 1 — guard sanity check**: sets `product_image` directly to `http://172.18.0.1:33119/canary-<c1>`, calls `POST /index.php?entryPoint=generatePdf` with `module=AOS_Quotes&uid=<quote>&templateID=<template>&task=pdf` as the low-priv user. Result: `200`, valid PDF, **zero** OOB hits — the guard blocked it.
3. **TEST 2 — bypass**: sets `product_image` to `https://httpbin.org/redirect-to?url=<urlencoded http://172.18.0.1:33119/canary-<c2>>&status_code=302` (a genuinely public redirector — the app container has real internet egress, confirmed live), calls the same `generatePdf` request again.
4. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected/observed: exit 0, `==> VULN-047: CONFIRMED`.
5. **Observable proof** — `evidence/oob_listener.log`:
   ```
   GET /canary-pdfredir_2e6e7b4f
     User-Agent: tcpdf
   GET /canary-pdfredir_2e6e7b4f
     User-Agent:
   GET /canary-pdfredir_2e6e7b4f
     User-Agent:
   ```
   Three hits, all for the TEST 2 canary, none for TEST 1's — `User-Agent: tcpdf` is TCPDF's own client signature, confirming the PDF engine itself made the request.

## 5. Impact

- **Confidentiality**: blind SSRF from the app server's network position — internal service reachability/port-scanning; the fetched bytes are embedded as an image in the resulting PDF (limited direct exfiltration, but content-type/size/error timing all leak).
- **Guard-bypass, not guard-absence**: demonstrates that `validate_external_host()`, while real and effective against naive direct targeting, is insufficient wherever the actual network I/O is delegated to code that isn't aware of it — a pattern likely to recur in any future sink unless fixed centrally.
- **Pre/post-auth**: post-auth, ordinary user privilege (standard Quotes/Products/PDF-template access, unrestricted by default).
- **Chaining**: same redirect-bypass technique and same SSRF cluster as [VULN-094](../VULN-094/writeup.md), [VULN-045](../VULN-045/writeup.md), [VULN-014](../VULN-014/writeup.md), [VULN-085](../VULN-085/writeup.md).

## 6. Suggested fix

- In `SuiteTCPDF.php`'s `Image()` override, don't rely on `parent::Image()`'s own network layer at all: pre-fetch the resource with a redirect-disabled HTTP client that re-validates every hop (or resolves once and pins the IP), and hand TCPDF the already-downloaded local bytes/temp file instead of a remote URL.
- Globally: disable redirect-following in every outbound-fetch code path in this codebase (or re-validate on every hop) — see the identical recommendation for [VULN-094](../VULN-094/writeup.md).
- Principle: an SSRF allow-list must be enforced at the point of the actual network connection (or via IP pinning), not only at the point where a URL string is first accepted — checking once "before handing off to a library" is not equivalent to checking the connection itself.

## 7. References

- CWE-918 (SSRF) / CWE-441 (redirect-following as unintended proxy) — https://cwe.mitre.org/data/definitions/918.html
- OWASP SSRF Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy, "Server-side request forgery (SSRF)" — bypassing SSRF filters via open redirection: https://portswigger.net/web-security/ssrf
- Originally tracked as CVE-2026-29107 / GHSA-g7cv-4ghj-x98h ("Authenticated SSRF via PDF export", fixed 7.15.1); this fork's `SuiteTCPDF.php:95` guard appears to be that fix, and this finding shows the fix is incomplete against redirects — see [VULN-094](../VULN-094/writeup.md) for the identical gap in the RSS dashlet's independently-fixed (CVE-2026-29097) sink.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 50 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Fetched osv.dev CVE-2026-29107 — GHSA-g7cv-4ghj-x98h "Authenticated SSRF via PDF export", `<img>` in PDF templates, fixed 7.15.1 / 8.9.3 (fix commit 7f2b384d); no mention of redirects
2. Fetched github.com/SuiteCRM/SuiteCRM/security/advisories/GHSA-g7cv-4ghj-x98h — affected <= 7.14.5 / <= 8.7.0, patched 7.15.1 / 8.9.3, CVSS 5.0, reporter Parnuski; describes the TCPDF (tc-lib-file) fetch; nothing about redirect-following or guard bypass
3. `SuiteCRM validate_external_host bypass redirect SSRF PDF TCPDF 7.15.1 7.15.2` — only CVE-2026-29107 itself and the unrelated SonarSource 2019 post; no bypass disclosure
4. `CVE-2026-61649 SuiteCRM` — hinted "guard-bypass" ID does not exist in any index; results were CVE-2026-29096/29098/29104/29105
5. `SuiteCRM SSRF CVE outbound email test settings internal port scan 2024 2025 2026` and `SuiteCRM "Test Settings" ... SSRF exploit` (extended) — enumerated all public SuiteCRM SSRFs (CVE-2019-13335, CVE-2023-6124, CVE-2023-6388, CVE-2024-36414, CVE-2026-29097, CVE-2026-29107, CVE-2026-69137); none is a redirect bypass of `validate_external_host()`

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-29107 / GHSA-g7cv-4ghj-x98h — SAME sink (`<img>` in AOS PDF templates rendered by TCPDF). The public bug was the absence of any host check; it was fixed in 7.15.1 by the `validate_external_host()` guard in `SuiteTCPDF::Image()`. This finding is that the guard is applied once to the supplied URL while TCPDF follows HTTP redirects unvalidated, which is not described publicly
- CVE-2026-29097 — RSS dashlet SSRF fixed 7.15.1 by the same guard function; the same redirect gap is tracked separately as VULN-094
- PortSwigger SSRF filter-bypass-via-open-redirect — generic technique, not SuiteCRM-specific

**Reasoning:** The component and original SSRF are publicly known and were patched before the audited version; the specific defect here is that the 7.15.1 patch is incomplete because redirect-following inside vendored TCPDF is never re-validated, which no CVE, GHSA, advisory or PoC describes. Because this is an incomplete-fix variant of a very recent (March 2026) advisory, the reporter or vendor may already be aware; confidence that it is unknown is therefore moderate, and it should be reported as a bypass of the CVE-2026-29107 fix.
