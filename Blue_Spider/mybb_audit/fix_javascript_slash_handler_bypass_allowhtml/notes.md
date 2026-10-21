# VULN-006 — Stored XSS via bypassable `fix_javascript` when "Allow HTML" is enabled

**Software**: MyBB
**Repository**: https://github.com/mybb/mybb
**Affected version**: 1.9.0-alpha.1 (`inc/src/Application.php:28`; branch `dev-1.9`, commit-pinned — no tagged release)
**Status**: CONFIRMED (conditional) — the `fix_javascript` bypass is proven by running MyBB's own parser; reachable as live stored XSS only when an operator enables an Allow HTML flag (all four default OFF)
**Severity (static)**: High (conditional)
**Confidence**: 7/10
**Confidence reasoning**: The sanitiser bypass is definitively proven (MyBB's own `postParser` leaves `/`-separated handlers + `<iframe>` intact while neutralising the space form). Gated behind a default-off flag, so not reachable on the documented baseline — hence conditional.
**Target commit**: f8bf4e840cd42f5d61bfb789eb3975674081d69e
**Validated at**: 2026-10-02T01:14Z

## Preconditions
- An operator has enabled one of the Allow HTML flags (all default OFF; the Security Guide says keep them off): per-forum `forums.allowhtml`, `sightml` (signatures), `pmsallowhtml` (PMs), or `announcementshtml`.
- A registered user (posts/signatures/PMs) or moderator (announcements) supplies the payload.

## Request
See `request.http`. The authoritative validation runs MyBB's own
`postParser::parse_message($payload, ['allow_html'=>1])` inside the app container
(`parse_probe.php` via `docker exec`), which is exactly the code path a post /
signature / PM / announcement body takes once an Allow HTML flag is on.

## Response
See `response.txt` — per-payload parser output:
```
img_space_onerror  neutralised=1 intact=0   <img src=x on‌error=alert(1)>      (U+200C inserted)
svg_slash_onload   neutralised=0 intact=1   <svg/onload=alert(1)>
img_slash_onerror  neutralised=0 intact=1   <img src=x/onerror=alert(1)>
iframe_data        neutralised=0 intact=1   <iframe src=data:text/html,alert(1)></iframe>
```

## Observation
Exactly as predicted. `fix_javascript()`'s regex `#([\s"']on)([a-z]+\s*=)#i` only
matches `on…=` after whitespace/`"`/`'`; the control `<img src=x onerror=>` is
neutralised (a U+200C is inserted → `on‌error`), but a `/` separator
(`<svg/onload=>`, `<img src=x/onerror=>`) bypasses it, and `<iframe src=data:>`
survives because only `base|meta|script|style` are stripped (parser `:190`). The
allow_html branch also skips `parse_html` and the output XML-validation (`:2027`),
and the result renders raw — so the surviving markup is live XSS.

## Side effects
None persistent from the probe. (The earlier forum-post attempt set and restored
`forums.allowhtml`; the probe itself only parses in-memory.)

## Research & references
- PortSwigger XSS cheat sheet / "event handlers" and "bypassing filters" — the
  `/` separator and `data:` iframe vectors used.
- MyBB Security Guide — documents keeping the Allow HTML features off; this is the
  "documented footgun" the finding concerns.
- OWASP XSS Prevention Cheat Sheet — blocklist sanitisers are inherently
  bypassable; use an allow-list DOM sanitiser.

## If FAILED
n/a — the bypass is confirmed.

## If NEEDS_MANUAL
End-to-end firing in a *rendered forum page* could not be captured: in this
1.9-alpha, `showthread.php` returns HTTP 503 for ANY thread in a forum with
`allowhtml=1` (even a plain-text post) — a separate rendering fault in the
allow_html render path, independent of the payload. To see the alert fire in a
browser, a human can: (a) fix/avoid that 503 (e.g. test the `pmsallowhtml` /
`sightml` render paths instead of a forum post), enable the relevant flag, submit
`<svg/onload=alert(document.domain)>`, and view the rendered content; or (b) once
the 503 is resolved, re-run against `showthread.php`. The sanitiser bypass that
makes all of these dangerous is already CONFIRMED above.

## If INTENDED
No — MyBB presents `fix_javascript()` as the sanitiser that makes allow_html
content safe from untrusted authors; the vendor does not document that enabling
Allow HTML permits arbitrary script. The bypass is a real defect (the Security
Guide's advice to keep the flags off is risk-reduction, not a statement that the
sanitiser is intended to be bypassable).
