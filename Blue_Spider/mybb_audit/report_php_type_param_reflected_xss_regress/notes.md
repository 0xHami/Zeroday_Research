# VULN-002 — Reflected XSS in `report.php` via the `type` parameter

**Software**: MyBB
**Repository**: https://github.com/mybb/mybb
**Affected version**: 1.9.0-alpha.1 (`inc/src/Application.php:28`; branch `dev-1.9`, commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: High
**Confidence**: 9/10
**Confidence reasoning**: Proven end-to-end — payload reflected unescaped into the `|raw` sink AND executed in a real browser (alert fired). No attacker account; single GET; admin victim → ACP/RCE chain.
**Target commit**: f8bf4e840cd42f5d61bfb789eb3975674081d69e
**Validated at**: 2026-10-01T23:54Z

## Preconditions
- The victim is any logged-in forum user (`report.php:19` `error_no_permission()` for guests). The script provisions one ordinary Registered-group user to play the victim and logs it in over the real web login form.
- The attacker needs **no account** and no CSRF token — delivery is a single crafted GET link.

## Request
See `request.http`. Essence:
```
GET /report.php?type=<img src=x onerror=alert('xss…')> HTTP/1.1
Cookie: mybbuser=<victim uid_loginkey>
```

## Response
See `response.txt`. The rendered report page contains, inside the error row, the **verbatim** payload:
```html
<div class="row row--form">This <img src=x onerror=alert('xss…')> either does not exist or is not allowed to be reported.</div>
```
`<` / `>` are **not** entity-encoded (no `&lt;`), so the `<img>` tag is parsed as live HTML.

## Observation
Matches the static prediction exactly. The unknown `type` value hits no handler branch, falls through to `$error = $lang->sprintf($lang->error_invalid_report, $type)` (report.php:128/:253), and `report.twig:15` renders `{{ report.error|raw }}`. The HTTP check confirmed `raw payload present=True, html-escaped=False`. The real-browser probe reported `DIALOG_FIRED msg="localhost"` and `window.__xss=<marker>`, i.e. `alert(document.domain)` executed in the victim's authenticated session (screenshot: `evidence/xss_fired.png`).

## Side effects
None persistent — purely reflected. A throwaway victim account remains in `mybb_users` (random username, usergroup 2); harmless.

## Research & references
- OWASP WSTG-INPV-01 (Reflected XSS) — test procedure: inject a context-breaking payload into each reflected parameter and confirm it renders unescaped in the response; verified the element-content context here.
- PortSwigger "Reflected XSS into HTML context with nothing encoded" — the `<img src=x onerror=…>` auto-firing vector used.
- Exploit-DB 35224 (MyBB 1.8.1 `report.php?type=` XSS) — confirms this is a regression of a previously-fixed bug reintroduced by the 1.9 rewrite.

## If FAILED
n/a — confirmed.

## If NEEDS_MANUAL
n/a.

## If INTENDED
n/a — reflected unsanitised user input in an HTML context is not documented/by-design; MyBB escapes this value elsewhere and previously fixed this exact parameter in 1.8.1.
