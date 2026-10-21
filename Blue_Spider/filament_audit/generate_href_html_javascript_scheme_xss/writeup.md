# VULN-009 — `generate_href_html()` does not scheme-sanitize `->url()` → `javascript:` href XSS

| | |
|---|---|
| **ID** | VULN-009 |
| **Software** | Filament |
| **Repository** | https://github.com/filamentphp/filament |
| **Affected version** | v4.14.0 |
| **Commit** | `154a22c52498a5400ae53fe64e772f8eb09946aa` |
| **Severity** | Medium (High real-world ceiling) |
| **CVSS 3.1** | 5.4 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` |
| **Status** | CONFIRMED (dynamic) — stored XSS fires on click |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Full stored XSS proven in a real browser (href emitted + executed on click); needs a ->url() binding to user data + a victim click. |
| **Auth required** | Low-priv author to store the value; fires in any viewer's session (often an admin) |
| **Attacker gains** | One-click script execution in another user's authenticated session (→ admin-session takeover) |

## Summary

Filament renders every clickable surface (table column links, record URLs, infolist links,
action/button/badge hrefs) through one helper, `generate_href_html()`. It calls `e()`, which
HTML-entity-encodes `"`/`<`/`>`/`&`/`'` — preventing attribute breakout — but leaves a
`javascript:` **scheme** intact as the attribute *value*. The library already has a
scheme-allowlisting helper (`Str::sanitizeUrl()`) and applies it to file URLs, but **not** to
developer `->url()`/`->recordUrl()` values. So when a developer binds user-controlled data to
`->url()` (the standard column pattern — the shipped `LinksRelationManager` does exactly
`TextColumn::make('url')->url(fn ($state) => $state)`), an attacker who stores a `javascript:`
URL gets a live `<a href="javascript:…">` that runs in the viewer's session on click.

## How it works (mechanism & code trace)

**The helper, escaping but not sanitizing** —
`packages/support/src/helpers.php:154-176`:

```php
function generate_href_html(?string $url, bool $shouldOpenInNewTab = false, ...): Htmlable
{
    if (blank($url)) { return new HtmlString(''); }
    $html = 'href="' . e($url) . '"';                    // :161 — e() blocks breakout, NOT a dangerous scheme
    // ... target/_blank, wire:navigate handling ...
    return new HtmlString($html);
}
```

`e()` = `htmlspecialchars(..., ENT_QUOTES)`: it turns `'`→`&#039;`, `"`→`&quot;`, etc., so the
attacker cannot add new attributes — but `javascript:void(...)` contains none of those as a
*prefix*, so the scheme passes through. When the browser parses `href="javascript:void(…)"` it
decodes the entities and gets a working `javascript:` URL.

**The inconsistency (the actual defect)** — the scheme allowlist exists and is used elsewhere:
`Str::sanitizeUrl()` (http/https allowlist, `SupportServiceProvider.php:330`) is applied to file
URLs (`BaseFileUpload.php:210`, `:953`) but **not** in `generate_href_html()`. Note `is_app_url()`
(`helpers.php:135-151`) *does* check the scheme — but only for SPA-navigation detection, not for
href safety.

**Reached from every `->url()` surface** — `tables/.../Column.php:185`, `TextColumn.php:221,338`,
`ImageColumn.php:533`, `IconColumn.php:362`, infolist `*Entry.php`, `actions/.../Action.php:894,978`,
and the support button/link/badge/dropdown concerns.

## Why it is a vulnerability

The boundary crossed is script execution in another user's authenticated origin. The broken
assumption is that Filament renders safe hrefs by default (as it does for file URLs); instead
developer-bound URLs are escaped but not scheme-restricted, so stored attacker data becomes an
executable `javascript:` link. HTML-entity-encoding a URL is not the same as sanitizing its
scheme (CWE-79). A one-click stored XSS against whoever views the record — frequently a
higher-privileged admin — results.

## Reproduction

`./run.sh` (self-contained; drives a real browser in the Playwright container):

1. **Harness precondition:** add the documented `->url(fn ($state) => $state)` to the posts
   'title' column (the shipped LinksRelationManager pattern), reverted afterwards.
2. **Store** attacker value: set post 1's title to `javascript:void(document.title='PWNED-<suffix>')`
   (`void()` so execution doesn't replace the page).
3. **View + click** as the authenticated viewer: load `/admin/posts`, locate the
   `a[href^="javascript:"]`, read its href, click it.

Observed (`run.log`, `response.txt`, `evidence/after_click.png`):

```
HREF=javascript:void(document.title='PWNED-<suffix>')      # server emitted it unsanitized
TITLE_BEFORE=Posts - Filament
TITLE_AFTER=PWNED-<suffix>                                 # the JS executed in the viewer's session
RESULT=PASS
```

## Impact

One-click stored XSS in the viewer's authenticated session (UI:R, S:C). Base 5.4, but the
**real-world ceiling is High**: if the poisoned link appears in an admin panel, one admin click
runs attacker JS that can drive any `/livewire/update` action as the admin (the CSRF token is in
the page) — effective admin-session takeover (C:H/I:H). PR drops toward N where an unauthenticated
surface feeds the `->url()` value. VULN-002's stored-XSS variant and VULN-010 escalate the same
way.

## Suggested fix

Apply the existing scheme allowlist inside the one helper (one line, library-wide):

```php
function generate_href_html(?string $url, ...): Htmlable
{
    if (blank($url)) { return new HtmlString(''); }
    $html = 'href="' . e(Str::sanitizeUrl($url)) . '"';   // allowlist http/https/mailto/tel, drop javascript:/data:
    ...
}
```

`Str::sanitizeUrl()` already exists and is already trusted for file URLs. Principle: allowlist URL
schemes at the render boundary; never rely on HTML-entity-encoding alone to neutralise a dangerous
scheme.

## References

- PortSwigger Web Security Academy — XSS into a `javascript:` URL; `void()` to keep the page.
- OWASP XSS Prevention Cheat Sheet — Rule #5 (URL attributes must be scheme-validated).
- CWE-79 Improper Neutralization of Input During Web Page Generation.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 60 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Vendor advisory list `github.com/filamentphp/filament/security/advisories` (pages 1–2, 19 advisories) — XSS advisories exist for ColorColumn, ImageColumn, summarizers, RichEditor and tenant tooltips; none concerns `generate_href_html()` or a `javascript:` URL scheme in `->url()` hrefs.
2. GitHub Advisory Database, Composer ecosystem, query `filament` — same set; no href/scheme advisory.
3. Project issue tracker query `is:issue "javascript:" url xss` — 0 results. (Web-search quota exhausted; checks via direct fetch of primary sources.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2024-47186 / GHSA-9h9q-qhxg-89xr (ColorColumn/ColorEntry XSS), CVE-2026-48167 / GHSA-3fc8-8hp6-6jr4 (ImageColumn/ImageEntry XSS), CVE-2026-33080 / GHSA-vv3x-j2x5-36jc (summarizer XSS), GHSA-9f9v-vm6w-3wx6 (tenant tooltip XSS) — all value-escaping defects in specific renderers, not scheme sanitization of hrefs.
- `Str::sanitizeUrl()` — vendor helper already applied to file URLs, showing the scheme allowlist exists but is not applied in the generic href helper.

**Reasoning:** No public advisory or issue reports that developer-bound `->url()` values are entity-escaped but not scheme-restricted. Confidence is moderate because the vendor may consider `->url()` values the developer's responsibility (the helper exists and is documented), XSS reports against Filament are frequent in 2026 so a private report could exist, and the finding needs a developer to bind user data to `->url()`.
