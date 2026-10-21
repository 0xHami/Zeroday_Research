# VULN-002 — Reflected XSS in `report.php` via the `type` parameter

| | |
|---|---|
| **Software** | MyBB |
| **Repository** | https://github.com/mybb/mybb |
| **Affected version** | 1.9.0-alpha.1 (`inc/src/Application.php:28`) |
| **Commit** | `f8bf4e840cd42f5d61bfb789eb3975674081d69e` (branch `dev-1.9`) |
| **Severity** | High — CVSS 3.1 **8.2** (`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`) |
| **Status** | CONFIRMED (dynamic) |
| **Confidence** | 9/10 — proven unescaped reflection **and** real-browser execution |
| **Auth required** | None for the attacker; the victim must be logged in (any user; admin for the RCE leg) |
| **Attacker gains** | Arbitrary JS in the victim's forum session; against an admin victim, a same-origin pivot into the ACP → template `eval()` RCE |

## Summary

`report.php` reflects the raw `type` request parameter into an error message that
is rendered with Twig's `|raw` filter. A `type` value outside the three valid
report kinds (`post`, `profile`, `reputation`) falls through to an "invalid
report" error built by MyBB's non-escaping i18n primitive and printed raw, so an
attacker-controlled string lands verbatim in HTML element-content context and
executes as JavaScript. Delivery is a single GET link; the only precondition is
that the lured victim is logged in (guests are rejected at `report.php:19`).
Because the forum front-end shares an origin with `/admin/`, luring an
administrator turns this into the XSS→ACP→`eval()`-template-RCE chain
(SECURITY.md #3689).

## How it works (mechanism & code trace)

**Entry point / source.** `report.php` is reachable by any authenticated user.
The guest gate is the only access control:

```php
// targets/mybb/report.php:19
if(!$mybb->user['uid'])
{
    error_no_permission();
}
```

The `type` parameter is then copied in **raw**, with no validation against the
set of real report types:

```php
// targets/mybb/report.php:31-34
$report_info['type'] = 'post';
if(!empty($mybb->input['type']))
{
    $report_info['type'] = $mybb->get_input('type');   // raw INPUT_STRING
}
```

**Branch miss.** The handler only has branches for `post` (`:45`), `profile`
(`:85`) and `reputation` (`:102`); there is no validating `else`. An unknown
`type` leaves `$verified = false` and, because `user_permissions($checkid)` on
the unresolved id yields no `canbereported`, reaches the error construction:

```php
// targets/mybb/report.php:126-129
$permissions = user_permissions($checkid);
if(empty($permissions['canbereported']))
{
    $error = $lang->sprintf($lang->error_invalid_report, $report_info['type']);
}
```

A guaranteed fallback builds the same error even if that branch is skipped:

```php
// targets/mybb/report.php:252-255
if($verified == false && empty($error))
{
    $error = $lang->sprintf($lang->error_invalid_report, $report_info['type']);
}
```

**The exact defect — no-escape substitution into an HTML sink.** `sprintf()`
here is `MyLanguage::sprintf()`, which substitutes placeholders with a plain
`str_replace` and performs **no HTML escaping**:

```php
// targets/mybb/inc/class_language.php:192
$string = str_replace('{'.$i.'}', $arg_list[$i], $string);
```

and the language string **contains** the `{1}` placeholder, so the argument is
actually emitted (contrast strings with no placeholder, which silently drop their
argument and are therefore safe):

```php
// targets/mybb/inc/languages/english/report.lang.php:28
$l['error_invalid_report'] = "This {1} either does not exist or is not allowed to be reported.";
```

**Sink.** The error is assigned to the template model (`report.php:266`) and the
template prints it with the `|raw` filter, defeating Twig autoescaping:

```twig
{# targets/mybb/inc/themes/core.base/frontend/templates/report/report.twig:15 #}
<div class="row row--form">{{ report.error|raw }}</div>
```

(The `no_modal=1` fragment `report/report_error_nomodal.twig:5` has the identical
`{{ report.error|raw }}`.)

**Why the framework doesn't save it.** Twig's `html` autoescaping would normally
neutralise this, but `|raw` explicitly opts out, and the value never passes
through `htmlspecialchars_uni()` on the controller side — unlike the many sibling
controllers that pre-escape subjects/strings before templating. The combination
"non-escaping `sprintf` + `|raw`" leaves zero defence on the path.

## Why it is a vulnerability (reasoning)

The security invariant for any web template is that untrusted request data is
rendered as **text**, not markup. Here a value taken verbatim from the query
string is rendered as raw HTML in the victim's authenticated document, so the
attacker crosses the boundary between "data the server echoes" and "code that runs
in the victim's session". This is not an intended feature: `type` is an
enumerated selector with exactly three legal values, the message is a plain
English sentence with no need for HTML, and MyBB *did* fix this exact parameter in
1.8.1 (Exploit-DB 35224) — the 1.9 rewrite reintroduced it via a new sink
(`sprintf` + `|raw`). The attacker's capability (run JS as the victim, and against
an admin drive the same-origin ACP) vastly exceeds what the report feature grants
(submit a report form).

## Reproduction

From a clean lab (`docker compose -p cvehunterlab_mybb up -d`, base URL
`http://localhost:25850`):

1. The exploit provisions one ordinary user (random name, usergroup 2) and logs
   it in over the real `member.php?action=do_login` form to obtain a `mybbuser`
   session cookie — this stands in for "any lured, logged-in victim".
2. It issues, as that victim, the crafted GET (see `request.http`):
   ```
   GET /report.php?type=<img src=x onerror=alert('xss…')>
   Cookie: mybbuser=<victim uid_loginkey>
   ```
3. **HTTP proof:** the response (`response.txt`) contains the payload verbatim —
   `This <img src=x onerror=alert('xss…')> either does not exist …` — with `<`/`>`
   un-encoded inside the `report.twig:15` `|raw` div.
4. **Browser proof:** `./run.sh` then opens the same URL in a real Chromium
   (Playwright container) carrying the victim cookie. The run prints
   `DIALOG_FIRED msg="localhost"` — `alert(document.domain)` executed — and saves
   `evidence/xss_fired.png`.

Run it:
```bash
cd claude_audit/mybb/exploits/VULN-002 && ./run.sh
# expect: [OK] exploit confirmed … ==> VULN-002: CONFIRMED
```
Observable proof: the `DIALOG_FIRED` line, `window.__xss` set to the run marker,
and the screenshot of the fired alert.

## Impact

Against an ordinary logged-in victim: full control of that user's forum session
(act as them, read/modify their data, steal CSRF tokens for their actions).
Against a **moderator/administrator** victim — the high-value target — the script
runs in a session that shares an origin with the Admin Control Panel, so it can
fetch an ACP page to read the admin post-key and submit a privileged ACP action
(create an administrator, or write/modify a template or plugin), reaching the
vendor-accepted **template `eval()` RCE** (SECURITY.md #3689). That converts a
no-privilege attacker (who only needs to lure an admin into clicking a link) into
full board and host compromise. `HttpOnly` on `mybbuser` blocks raw cookie theft
but not this same-origin ACP-driving payload. Chains with **VULN-001** (stored
variant of the same sink family) and **VULN-020** (the systemic root cause).

## Suggested fix

In `report.php`, validate `type` against its whitelist before use, and do not
print user input with `|raw`:

```php
// report.php — normalise/validate first
$valid = array('post', 'profile', 'reputation');
$report_info['type'] = in_array($mybb->get_input('type'), $valid, true)
                     ? $mybb->get_input('type') : 'post';
```
and/or escape before substitution:
```php
$error = $lang->sprintf($lang->error_invalid_report,
                        htmlspecialchars_uni($report_info['type']));
```
and drop `|raw` in `report/report.twig:15` and `report/report_error_nomodal.twig:5`
(the message is plain text, so `{{ report.error }}` autoescaped is sufficient).
Principle: validate against an allow-list and keep untrusted data out of `|raw`
sinks. Systemic remediation: VULN-020 — stop declaring the i18n helpers
`is_safe=html` / escape data arguments at the `sprintf`/`trans` boundary.

## References

- Exploit-DB **35224** — MyBB 1.8.1 `report.php?type=` reflected XSS (the bug this
  regresses).
- OWASP **WSTG-INPV-01** (Testing for Reflected XSS) and the OWASP XSS Prevention
  Cheat Sheet (output encoding by context; allow-list input validation).
- PortSwigger Web Security Academy — "Reflected XSS into HTML context with nothing
  encoded" (the `<img onerror>` vector).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 25 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Fetched exploit-db.com/exploits/35224 — confirms a 2014 reflected XSS in `report.php` via the `type` parameter in MyBB 1.8.1 (CVE-2014-9241), fixed in the 1.8 line
2. Fetched github.com/mybb/mybb/security/advisories pages 1-7 and mybb.com/versions/1.8.41/ — no `report.php` XSS in any 2020-2026 advisory
3. Fetched github.com/advisories?query=mybb+xss+2026 — 0 results
4. Fetched github.com/mybb/mybb/security/policy — not listed as a known issue

**Related but distinct public references** (same class or component, not this bug):
- Exploit-DB 35224 / CVE-2014-9241 — same endpoint and parameter in MyBB 1.8.1, publicly disclosed and fixed in 2014; the 1.9 rewrite reintroduces it through a different sink (`MyLanguage::sprintf` + Twig `|raw`)

**Reasoning:** This is a partial match: the endpoint and parameter were publicly disclosed twelve years ago and fixed, so the vulnerability "shape" is known, but the 1.9 instance is an unreported regression via a new code path. It should be reported as a regression rather than a new discovery; confidence that it is "not previously known" is correspondingly low.
