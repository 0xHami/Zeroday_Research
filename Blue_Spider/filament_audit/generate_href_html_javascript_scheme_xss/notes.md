# VULN-009 — generate_href_html() does not scheme-sanitize ->url() → javascript: href XSS

**Software**: Filament
**Repository**: https://github.com/filamentphp/filament
**Affected version**: v4.14.0 (git tag; `composer.json` has no `version`, tag authoritative)
**Status**: CONFIRMED
**Severity (static)**: Medium (High real-world ceiling: admin-session takeover)
**Confidence**: 7/10
**Confidence reasoning**: Full stored XSS proven in a real browser — the server-emitted `<a href="javascript:...">` executed on click (document.title → sentinel) in the authenticated session. Needs a developer ->url() binding to user data (common; the shipped LinksRelationManager does it) + a victim click, hence 7.
**Target commit**: 154a22c52498a5400ae53fe64e772f8eb09946aa
**Validated at**: 2026-10-01

## Preconditions
- Lab up; viewer `ryan@filamentphp.com` / `password` (the victim who views+clicks).
- HARNESS: the demo posts table has no ->url() column over a free-text field, so the exploit adds
  the documented `->url(fn ($state) => $state)` to the posts 'title' column — the exact pattern the
  SHIPPED `LinksRelationManager` uses (`TextColumn::make('url')->url(fn($s)=>$s)`), placed on the
  list page so it renders without the relation-group tab. Reverted after (touch for opcache). No
  library code changed.
- Attacker value: post 1 title set to `javascript:void(document.title='PWNED-<suffix>')`
  (`void()` so the expression returns undefined and the page isn't replaced).

## Request
See `request.http`. Viewer loads `GET /admin/posts`; the title cell renders
`<a href="javascript:void(document.title='PWNED-<suffix>')">`; clicking executes it.

## Response
`response.txt` (browser markers): `HREF=javascript:void(document.title='PWNED-<suffix>')`;
`TITLE_AFTER=PWNED-<suffix>`; `RESULT=PASS`. Screenshots in `evidence/` (rendered_link.png,
after_click.png).

## Observation
Matches the finding exactly. `generate_href_html()` (support/helpers.php:161) builds
`href="<e($url)>"` — `e()` encodes `"`/`<`/`>`/`&`/`'` (preventing attribute breakout) but leaves
the `javascript:` SCHEME intact. The library *has* `Str::sanitizeUrl()` (http/https allowlist) and
already applies it to file URLs (BaseFileUpload.php:210), but NOT to developer `->url()` values.
So a stored `javascript:` value renders as a live `href="javascript:..."` and executes in the
viewer's authenticated session on click — proven by the document.title change in a real browser.

## Side effects
- Post 1's title left as the payload (cosmetic); harness reverted. Reseed to restore:
  `docker exec cvehunterlab_filament_app php artisan migrate:fresh --seed --force`.
- Evidence PNGs owned by the container user (root) — read-only artifacts.

## Research & references
- PortSwigger Web Security Academy — "Reflected/stored XSS into a JavaScript scheme URL"; the
  `javascript:` URI technique and `void()` to avoid page replacement.
- OWASP XSS Prevention Cheat Sheet — URL attributes must be scheme-allowlisted (http/https/mailto),
  not merely HTML-entity-encoded. CWE-79.

## If FAILED
n/a — CONFIRMED (both the emitted href and click-execution).

## If NEEDS_MANUAL
n/a. (Real-world admin-session-takeover chaining — using the XSS to drive /livewire/update as an
admin — is the documented ceiling; the one-click script execution is proven here.)

## If INTENDED
Not INTENDED. The inconsistency is the tell: the library scheme-sanitizes file URLs but not
developer `->url()` values, and `is_app_url()` (helpers.php:135-151) checks the scheme only for SPA
detection, not for href safety. A safe-by-default href helper is expected.
