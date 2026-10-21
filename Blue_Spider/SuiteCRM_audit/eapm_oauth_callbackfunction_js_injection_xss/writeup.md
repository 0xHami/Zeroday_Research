# VULN-043 — Reflected XSS via JS-context injection in EAPM::action_oauth (executes in window.opener)

**ID**: VULN-043
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`), commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb` (untagged `forkedSuite` hotfix snapshot self-identifying as 7.15.2)
**Severity**: Medium — **CVSS 3.1 6.1** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
**Status**: CONFIRMED (dynamic)
**Auth required**: Victim must be an authenticated user with (module-level) EAPM access, lured to click a crafted link (reflected, `UI:R`). Attacker needs no privileges of their own.
**What an attacker gains**: arbitrary JavaScript execution in the victim's real, already-authenticated SuiteCRM window (not a sandboxed popup) — session-riding, CSRF-token theft, and (against an admin victim) a path to full takeover.

## Summary
`EAPM::action_oauth` (the handler behind SuiteCRM's "connect an external
account" OAuth popup flow) builds a `<script>` block by string-concatenating
two request parameters, `callbackFunction` and `application`, directly into
a `window.opener.<callbackFunction>("<application>")` call with no
JSON-encoding or allow-listing. SuiteCRM's global request sanitizer,
`securexss()`, HTML-encodes angle brackets/quotes and (via its `AntiXSS`
component) also neutralizes parenthesized `word(...)` patterns — enough to
break the *literal* proof-of-concept some analyses assume
(`alert(document.cookie)`), but not enough to stop a payload built purely
from bare identifiers and operators. Setting `callbackFunction=eval` and
`application=<arbitrary JS with no parens/quotes>` turns the sink into an
**indirect `eval()` call on `window.opener`**, which the ECMAScript spec
defines as running in the *opener's own global scope* — i.e. directly in
the victim's real browsing session, not the disposable OAuth popup.

## How it works (mechanism & code trace)
1. **Entry point**: `GET /index.php?module=EAPM&action=oauth&record=<id>&oauth_error=1&closeWhenDone=1&callbackFunction=eval&application=top.__vuln043_fired=true`
   dispatches to `EAPMController::action_oauth()`
   (`modules/EAPM/controller.php:138-175`).
2. **Guards that don't stop it**:
   - `empty($this->bean->id)` — false, `record` points at a real EAPM row.
   - `$this->bean->ACLAccess('save')` — `EAPM::$disable_row_level_security = true`
     (`modules/EAPM/EAPM.php:78`) reduces this to a module-level check, so
     any authenticated user with default EAPM access passes regardless of
     who owns the record.
   - `oauth_error=1` skips the `checkLogin()` branch (:148-156) that would
     otherwise try to contact a real OAuth provider.
3. **The sink**, `controller.php:159-171`:
   ```php
   if (isset($_REQUEST['closeWhenDone']) && $_REQUEST['closeWhenDone'] == 1) {
       if (!empty($_REQUEST['callbackFunction']) && !empty($_REQUEST['application'])) {
           $js = '<script type="text/javascript">window.opener.' . $_REQUEST['callbackFunction']
               . '("' . $_REQUEST['application'] . '"); window.close();</script>';
       } ...
       echo($js);
       return;
   }
   ```
   Both `$_REQUEST` values are concatenated directly into a JS expression
   with **no `json_encode()`, no allow-list, no output encoding** of any
   kind at this point.
4. **Why `securexss()` doesn't save it, precisely**: `clean_incoming_data()`
   (`include/utils.php:2503-2590`, run for every request via
   `include/entryPoint.php:93`) maps `securexss()`
   (`include/utils.php:2608-2637`) over `$_REQUEST`, so both
   `callbackFunction` and `application` ARE filtered — but the filter's
   actual behavior is narrower than a full JS-aware encoder: it
   HTML-entity-encodes `< > " ' `` `` and (via its bundled `AntiXSS`
   library) additionally mangles parenthesized call-like patterns and
   strips some dotted-accessor arguments — verified empirically:
   `securexss('alert(document.cookie);window.close;//')` →
   `'alert&#40;&#41;;window.close;//'` (parens encoded, argument deleted),
   while `securexss('top.__vuln043_fired=true')` →
   `'top.__vuln043_fired=true'` (byte-for-byte unchanged — no parens, quotes, or
   angle brackets to act on). The sink is inside a `<script>` element,
   whose content the HTML parser treats as raw text — entities like
   `&#40;` are **not** decoded back to `(` there, so the "obvious" PoC
   payload is inert, but a parens-free one is not.
5. **The bypass**: the vulnerable line's own fixed template already
   supplies the call parens: `window.opener.` + `<callbackFunction>` +
   `("` + `<application>` + `");`. Neither injected value needs to
   contribute its own `(`/`)`. With `callbackFunction=eval` and
   `application=top.__vuln043_fired=true`, the emitted script is exactly:
   ```html
   <script type="text/javascript">window.opener.eval("top.__vuln043_fired=true"); window.close();</script>
   ```
   `window.opener.eval(...)` is an **indirect eval call**. Per the
   ECMAScript specification, indirect eval always executes in the global
   scope of the realm the `eval` function belongs to — here,
   `window.opener`'s global scope — so `top.__vuln043_fired=true` runs as if
   typed directly into the victim's own, already-authenticated SuiteCRM
   window.

## Why it is a vulnerability (reasoning)
The trust boundary violated is "request parameters never become executable
code without explicit, deliberate serialization." `callbackFunction` and
`application` are user input placed directly into a JavaScript execution
context; the correct fix (`json_encode()`, or an allow-list regex on
`callbackFunction` such as `^[A-Za-z0-9_.]+$`) was never applied here. That
SuiteCRM's *general-purpose* HTML sanitizer happens to mangle the single
most obvious payload shape is incidental hardening, not a deliberate,
sufficient defense for a JS-string/JS-expression sink — `securexss()` is
documented and used throughout the codebase as an *HTML* output guard, and
this is a *JavaScript* output context, a fundamentally different escaping
domain (OWASP XSS Prevention Cheat Sheet Rule #3). The fact that a
parens-free bypass exists at all demonstrates the mismatch concretely.

## Reproduction
1. Preconditions: any authenticated user with default EAPM module access
   (`used` here: freshly created regular user `mod_12ae4340`), and
   any valid EAPM record id (`8b3660e9-1541-4c0f-93b6-6e15436b7dfd`, created by the same user in this
   run — module-level ACL only, ownership irrelevant).
2. Victim (or attacker driving the victim's browser via a lured link) opens:
   ```
   http://localhost:33116/index.php?module=EAPM&action=oauth&record=8b3660e9-1541-4c0f-93b6-6e15436b7dfd&oauth_error=1&closeWhenDone=1&callbackFunction=eval&application=top.__vuln043_fired%3Dtrue
   ```
3. Run `./run.sh` (venv auto-provisioned). Expected terminal output ends
   with `[OK]` / `==> VULN-043: CONFIRMED — ...`.
4. Observable proof: response.txt contains the raw, unescaped
   `window.opener.eval("top.__vuln043_fired=true"); window.close();`; a real
   headless Chromium "opener" window that opens this URL as a genuine
   popup (`evidence/fired.png`) shows `window.top.__vuln043_fired` become `true`
   **in the opener window itself** (see run.log for the full transcript
   proving the check was made on the opener, not the popup).

## Impact
Any authenticated user with EAPM access who can be lured to a crafted link
gets arbitrary attacker JavaScript executed directly in their real,
authenticated SuiteCRM session (not a throwaway popup) — full session
compromise: cookie/token theft, silent actions as the victim, and (chained
against an admin victim) a path to [VULN-011](../../vulns/VULN-011.md)
(authenticated RCE) for full server compromise. EAPM record ids are
enumerable per [VULN-001](../../vulns/VULN-001.md), removing the need for
the attacker to guess one.

## Suggested fix
- `json_encode()` both values before embedding: `window.opener[<?php echo
  json_encode($_REQUEST['callbackFunction']); ?>](<?php echo
  json_encode($_REQUEST['application']); ?>);` — this alone defeats the
  bypass shown here, since `eval`/`top.X=true` would be emitted as inert
  JSON string literals, not bare code.
- Additionally allow-list `callbackFunction` to `^[A-Za-z0-9_]+$` (a
  property name, never a dotted path or reserved global like `eval`) and
  drop the dynamic-callback pattern in favor of a fixed `postMessage`
  handler, which needs no string-building at all.

## References
- MDN, "eval() — Direct and indirect eval":
  https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#direct_and_indirect_eval
- OWASP XSS Prevention Cheat Sheet, Rule #3 (JavaScript escaping is not
  HTML escaping): https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- PortSwigger, "Cross-site scripting contexts": https://portswigger.net/web-security/cross-site-scripting/contexts
- CWE-79

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM EAPM oauth callbackFunction XSS window.opener` — only unrelated SuiteCRM XSS CVEs (CVE-2025-54784 email viewer, CVE-2025-64491 login page, CVE-2024-50335 Publish Key); nothing on EAPM/OAuth/window.opener
2. `SuiteCRM EAPM module reflected cross-site scripting CVE action=oauth` — CVE-2025-41384/CVE-2025-54783 (Referer header), CVE-2024-36413 (import error view); no EAPM match
3. `SugarCRM EAPM controller action_oauth "callbackFunction" "closeWhenDone" XSS advisory` — SugarCRM SA-2024-015 (Administration stored XSS), SA-2024-038 (ForecastsWorksheets), CVE-2005-0266; nothing on the inherited EAPM OAuth popup code
4. `SuiteCRM EAPM "External Accounts" XSS OR "cross-site scripting" advisory CVE` (extended) — CVE-2021-31792 (client account page), CVE-2024-36413, CVE-2024-50335, CVE-2025-54783, CVE-2025-64491, CVE-2019-14752, CVE-2023-3293; none involve the EAPM module

**Related but distinct public references** (same class or component, not this bug):
- CVE-2024-50335 — reflected XSS in Edit Profile "Publish Key" (Users module), fixed 7.14.6; different module and HTML context
- CVE-2025-54783 / CVE-2025-41384 — reflected XSS via Referer header in redirect/navigation responses, fixed 7.14.7; different sink
- CVE-2025-64491 — unauthenticated reflected XSS on login page, fixed 7.14.8; different component
- CVE-2021-31792 (GHSA-whq7-fhx8-mxr9) — XSS in client account page before 7.11.19; different component

**Reasoning:** No public CVE, GHSA, SugarCRM or SuiteCRM advisory describes the `modules/EAPM/controller.php` `action_oauth` sink where `callbackFunction`/`application` are concatenated into a `window.opener.<fn>("<arg>")` script, nor the indirect-eval bypass of `securexss()`. Reflected XSS is a very common class in SuiteCRM and vendor advisories are often terse, so an unpublished report is possible, but the EAPM OAuth popup path does not appear in any indexed disclosure.
