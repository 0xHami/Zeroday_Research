# VULN-006 — Stored XSS via bypassable `fix_javascript` when "Allow HTML" is enabled

| | |
|---|---|
| **Software** | MyBB |
| **Repository** | https://github.com/mybb/mybb |
| **Affected version** | 1.9.0-alpha.1 (`inc/src/Application.php:28`) |
| **Commit** | `f8bf4e840cd42f5d61bfb789eb3975674081d69e` (branch `dev-1.9`) |
| **Severity** | High (conditional) — CVSS 3.1 **8.7** *when enabled* (`AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N`) |
| **Status** | CONFIRMED (conditional) — bypass proven; reachable only with an Allow HTML flag on |
| **Confidence** | 7/10 — sanitiser bypass definitively proven; gated behind a default-off flag |
| **Auth required** | A registered user / moderator **plus** an operator-enabled Allow HTML flag (default off) |
| **Attacker gains** | Stored XSS reaching admins (→ ACP → template `eval()` RCE) when the flag is enabled |

## Summary

When any "Allow HTML" feature is turned on, MyBB relies on `fix_javascript()` to
keep attacker-supplied HTML safe. That sanitiser is a blocklist whose event-handler
regex only fires when an `on…=` handler is preceded by whitespace or a quote, so a
`/` separator (`<svg/onload=>`, `<img src=x/onerror=>`) slips past it, and non-event
tags like `<iframe src=data:>` are never stripped. The surviving markup is rendered
raw (allow_html also skips the output XML-validation), giving stored XSS. On the
documented secure baseline all four Allow HTML flags are off and this branch is
unreachable; the moment an operator enables one — trusting MyBB's promise that the
content is sanitised — they are exposed to the user→admin→RCE chain.

## How it works (mechanism & code trace)

In allow_html mode the parser strips only four tags and then calls `fix_javascript`:

```php
// targets/mybb/inc/class_parser.php:188-202 (allow_html branch)
else {
    // Replace base, meta, script and style tags - these are > dangerous <
    $message = preg_replace('#<(/?)(base|meta|script|style)([^>]*)>#i', '&lt;$1$2$3&gt;', $message);
    $message = $this->fix_javascript($message);     // the ONLY remaining defence
    ...
}
```

`fix_javascript()` neutralises handlers with this regex:

```php
// targets/mybb/inc/class_parser.php:799-810
$js_array = array(
    "#(&\#(0*)106;? ... j)...(script)...(\:))#i",       // javascript: scheme
    "#([\s\"']on)([a-z]+\s*=)#i",                        // event handlers — ONLY after \s " '
);
$message = preg_replace($js_array, "$1\xE2\x80\x8C$2$6", $message);  // insert U+200C
```

The second pattern requires `on…=` to be preceded by whitespace, `"` or `'`. So:

- `<img src=x onerror=…>` → matched → `on` + U+200C + `error=` (neutralised). ✔ defended
- `<svg/onload=…>` → the char before `onload` is `/`, **not** `[\s"']` → **no match** → handler intact. ✘ bypass
- `<img src=x/onerror=…>` → same `/` bypass. ✘
- `<iframe src=data:text/html,…>` → `iframe` is not in the stripped tag set and has no `on…=` → survives entirely. ✘

allow_html also skips the output XML-validation (parser `:2027`), and the parsed
message renders raw, so these survive to the DOM.

**Authoritative dynamic proof.** Rather than infer, the exploit runs MyBB's own
`postParser::parse_message($payload, ['allow_html'=>1])` inside the live app
container (`parse_probe.php`). The observed output:

```
img_space_onerror  neutralised=1  ->  <img src=x on‌error=alert(1)>      (U+200C inserted)
svg_slash_onload   neutralised=0  ->  <svg/onload=alert(1)>
img_slash_onerror  neutralised=0  ->  <img src=x/onerror=alert(1)>
iframe_data        neutralised=0  ->  <iframe src=data:text/html,alert(1)></iframe>
```

i.e. the sanitiser demonstrably runs (it neutralises the space form) yet lets the
`/`-separated handlers and the `<iframe>` through unchanged — live XSS HTML.

## Why it is a vulnerability (reasoning)

The Allow HTML features exist specifically to let untrusted authors submit HTML
that MyBB then *sanitises* — `fix_javascript()` is that sanitiser. A sanitiser that
can be bypassed with a one-character change (`/`) does not provide the property the
feature advertises, so an operator who enables Allow HTML believing content is made
safe is in fact exposed to arbitrary script in every viewer's session, including
administrators. This is not "HTML is allowed, so script is expected": MyBB actively
tries to strip script and claims to, and fails. The Security Guide's advice to keep
the flags off is risk-reduction, not a statement that the sanitiser is meant to be
porous. Conditional, because the vulnerable branch is only reached when a default-off
flag is enabled — hence High *when enabled*, informational on the baseline.

## Reproduction

From a clean lab (`http://localhost:25850`):

1. `./run.sh` copies `parse_probe.php` into the app container and runs MyBB's own
   parser in allow_html mode on the four payloads, asserting the control is
   neutralised and the three bypasses survive (`response.txt`).
2. To reach it over HTTP, an operator enables an Allow HTML flag (e.g.
   `forums.allowhtml=1`, or `sightml`/`pmsallowhtml`/`announcementshtml`); a user
   then submits `<svg/onload=alert(document.domain)>` in the corresponding field;
   any viewer (including an admin) executes it.

```bash
cd claude_audit/mybb/exploits/VULN-006 && ./run.sh   # ==> VULN-006: CONFIRMED (conditional)
```

**On end-to-end browser firing:** in this 1.9-alpha, `showthread.php` returns HTTP
503 for *any* thread in a forum with `allowhtml=1` (even plain text) — a separate
rendering fault in the allow_html render path — so the alert could not be captured
via a forum post here. The bypass (the actual vulnerability) is confirmed by the
parser output; firing it in a browser via the signature/PM/announcement render paths
or after that 503 is fixed is the NEEDS_MANUAL remainder (see `notes.md`).

## Impact

When an Allow HTML flag is enabled, any author of the corresponding content type
(ordinary user for posts/signatures/PMs; moderator for announcements) can store
JavaScript that executes in every viewer's session. Against an administrator viewer
the same-origin ACP pivot reaches the template `eval()` RCE (SECURITY.md #3689) — a
user→admin→host-compromise chain identical in terminal to VULN-001. On the documented
secure baseline (all flags off) it is not reachable.

## Suggested fix

Replace the blocklist with an allow-list DOM/HTML sanitiser (e.g. HTML Purifier) for
all allow_html content, or at minimum fix the separator handling and stop skipping
output validation:

```php
// fix_javascript(): match handlers regardless of the preceding separator, e.g.
"#([\s\"'/\\\\(]on)([a-z]+\s*=)#i"   // still a blocklist — prefer an allow-list sanitiser
```
and do not skip the XML-validation pass for allow_html. Principle: never rely on a
regex blocklist to make untrusted HTML safe.

## References

- MyBB SECURITY.md (Allow HTML / template `eval()` #3689); MyBB Security Guide
  (keep Allow HTML off).
- OWASP XSS Prevention & "XSS Filter Evasion" Cheat Sheets; PortSwigger XSS cheat
  sheet (event-handler and `data:`-iframe vectors).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 45 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Fetched github.com/advisories?query=mybb+fix_javascript — 0 results
2. Fetched github.com/mybb/mybb/security/advisories pages 1-7 — no sanitiser-bypass advisory for the Allow HTML mode (nearest: GHSA-3qqj-j98h-49x6 disabled video MyCode XSS, GHSA-8wjw-mmj9-f5xg attachment header suppression XSS, visual-editor XSS entries)
3. Fetched github.com/mybb/mybb/security/policy — "partial HTML sanitization" is listed only as a generic anticipated weakness class; no specific item
4. Fetched mybb.com/versions/1.8.41/ — nothing related

**Related but distinct public references** (same class or component, not this bug):
- MyBB security policy (SECURITY.md) — generic acknowledgement of partial HTML sanitisation as a weakness area
- MyBB Security Guide — advises keeping every Allow HTML setting disabled (generic guidance, not a disclosure of this bypass)

**Reasoning:** No advisory or database entry describes a specific bypass of the `fix_javascript` sanitiser. However, the vendor publicly documents Allow HTML as unsafe and lists partial sanitisation as a known weakness class, so the maintainers may treat the sanitiser as best-effort and decline a report; the feature is also off by default. Confidence is therefore moderate-low.
