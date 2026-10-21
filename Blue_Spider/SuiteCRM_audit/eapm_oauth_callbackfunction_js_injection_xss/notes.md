# VULN-043 — Reflected XSS via JS-context injection in EAPM::action_oauth

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 3.1 6.1 — AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T21:02:47.845551+00:00

## Preconditions
- Created a fresh low-privileged victim user via admin (`_common.create_user`):
  `mod_12ae4340` (id `2cf8bfe9-8dc2-42c4-b90d-efb1ff6ad6c3`); logged in as that user (web session).
- As the victim, created an EAPM record via legacy REST `set_entry`
  (id `8b3660e9-1541-4c0f-93b6-6e15436b7dfd`) — `EAPM::$disable_row_level_security = true`
  (`modules/EAPM/EAPM.php:78`) means `ACLAccess('save')` only checks
  module-level access, not record ownership, so any valid EAPM id
  (attacker-supplied or the victim's own) satisfies `action_oauth`'s check.

## Request
GET `http://localhost:33116/index.php?module=EAPM&action=oauth&record=8b3660e9-1541-4c0f-93b6-6e15436b7dfd&oauth_error=1&closeWhenDone=1&callbackFunction=eval&application=top.__vuln043_fired%3Dtrue`
Key params: `callbackFunction=eval`, `application=top.__vuln043_fired=true`,
`oauth_error=1` (skips the `checkLogin()` branch), `closeWhenDone=1`
(reaches the vulnerable branch at `controller.php:159-171`).

## Response
See response.txt — the emitted `<script>` contains, byte-for-byte:
`window.opener.eval("top.__vuln043_fired=true"); window.close();`

## Observation
- **Correction to the static finding's PoC**: the finding's own example
  payload (`callbackFunction=alert(document.cookie);window.close;//`)
  does NOT survive `securexss()` — verified directly against this lab's
  PHP 8.2 engine: `securexss('alert(document.cookie);window.close;//')`
  returns `'alert&#40;&#41;;window.close;//'` — `(`/`)` ARE HTML-entity
  encoded by the `AntiXSS` component `securexss()` invokes (not just the
  bare `<>"'`` table the finding cites), AND the `document.cookie`
  argument is deleted outright. Since the payload sits inside a
  `<script>` element (whose content is HTML "raw text" — the parser does
  **not** decode entities there), `&#40;` etc. renders as inert literal
  text, not `(` — the finding's exact PoC would be a JS syntax error, not
  working XSS.
- **The sink is still exploitable**: the vulnerable line's own template
  already supplies the call parens — `window.opener.<CB>("<APP>")` — so a
  payload never needs its own `(`/`)`. `callbackFunction=eval` +
  `application=top.__vuln043_fired=true` are both plain identifiers/operators
  with no parens/quotes/angle-brackets, confirmed to survive `securexss()`
  byte-for-byte, turning the sink into `window.opener.eval("top.__vuln043_fired=true")`
  — an **indirect eval call**, which per the ECMAScript spec runs in the
  *global scope of `window.opener`* — i.e. in the victim's real,
  already-authenticated SuiteCRM window, not the disposable popup.
- Real-browser proof (Playwright/Chromium): an "opener" window navigated
  to the victim's authenticated SuiteCRM origin opens the crafted URL as a
  genuine popup (`window.open`, so `window.opener` is set); the popup's
  emitted script runs `window.opener.eval(...)`. DOM sentinel
  `window.top.__vuln043_fired` observed as `True` **in the opener
  window** (the victim's real session, confirmed by checking it there, not
  in the popup). Screenshot: evidence/fired.png.

## Side effects
- One new Users record (victim) and one EAPM record (`8b3660e9-1541-4c0f-93b6-6e15436b7dfd`),
  cosmetic test fixtures.

## Research & references
- MDN, "eval() — Direct and indirect eval" (indirect eval executes in the
  global scope of the object it is called through):
  https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#direct_and_indirect_eval
- WHATWG HTML Standard, "13.2.5 — script raw text elements" (script
  element content is not subject to character-reference/entity decoding
  the way normal HTML body text is):
  https://html.spec.whatwg.org/multipage/parsing.html#cdata-rcdata-restrictions
- PortSwigger, "Cross-site scripting contexts": https://portswigger.net/web-security/cross-site-scripting/contexts
- Technique used: parens-free `window.opener.eval("<expr>")` bypass of a
  content-aware sanitizer that specifically HTML-entity-encodes `(`/`)`
  and strips `document.*` accessor patterns, by never emitting those
  characters ourselves and instead relying on the sink template's own
  literal parens.
