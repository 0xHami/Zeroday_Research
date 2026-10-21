# VULN-001 — Stored XSS in the Moderator Report Center via thread subject

| | |
|---|---|
| **Software** | MyBB |
| **Repository** | https://github.com/mybb/mybb |
| **Affected version** | 1.9.0-alpha.1 (`inc/src/Application.php:28`) |
| **Commit** | `f8bf4e840cd42f5d61bfb789eb3975674081d69e` (branch `dev-1.9`) |
| **Severity** | High — CVSS 3.1 **8.7** (`AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N`) |
| **Status** | CONFIRMED (dynamic) |
| **Confidence** | 9/10 — stored, served unescaped to staff, and executed in the admin's browser |
| **Auth required** | Any registered user (open registration) to inject; a moderator/admin to trigger |
| **Attacker gains** | JS execution in a moderator/administrator session → same-origin ACP pivot → template `eval()` RCE |

## Summary

Any ordinary forum member can store a cross-site-scripting payload that fires in
a **moderator or administrator** session simply by creating a thread with a
malicious subject and then reporting its first post. The front-end Moderator
Report Center renders the reported post's thread subject through MyBB's Twig
`trans()` helper, which is declared `is_safe=html` and so skips autoescaping; the
subject is stored raw and never `htmlspecialchars_uni()`'d at the controller, so
attacker markup reaches the staff browser verbatim. Because the forum front-end
shares an origin with `/admin/`, an administrator viewing the routine report queue
hands the attacker a scriptable foothold in the ACP, which reaches the
vendor-accepted template `eval()` RCE (SECURITY.md #3689). This is a
low-privilege-user → full-server-compromise chain, and the entry point is proven
firing in a real admin browser.

## How it works (mechanism & code trace)

**Source — the subject is stored raw.** `PostDataHandler::verify_subject()` only
trims blank characters and length-checks; it applies no HTML escaping:

```php
// targets/mybb/inc/datahandlers/post.php:180-186 (verify_subject)
function verify_subject()
{
    $post = &$this->data;
    $subject = &$post['subject'];
    $subject = trim_blank_chrs($subject);
    ...
```

Dynamic confirmation: a subject of
`<img src=x onerror="alert(document.domain);window.__xss='xss…'">` was stored
byte-for-byte in `mybb_threads.subject` (the exploit asserts this against the DB).

**Entry point — the Report Center controller.** When a moderator opens
`modcp.php?action=reports`, each reported post's thread subject is copied into the
template model with only a bad-word filter — **no HTML escaping**:

```php
// targets/mybb/modcp.php:471
$report_data['thread_subject'] = $parser->parse_badwords($postcache[$report['id']]['subject']);
```

`parse_badwords()` is a `str_replace` of configured bad words; it does not encode
HTML. (The `action=allreports` path has the identical sink at `modcp.php:657`.)
Contrast sibling controllers — `moderation.php:98`, `newreply.php:75`,
`editpost.php:58`, `sendthread.php:44` — which all call `htmlspecialchars_uni()`
on the subject before templating. This controller is the odd one out.

**Sink — a translation helper that opts out of autoescaping.** The template emits
the subject as the link text of the "reported post in thread" line:

```twig
{# targets/mybb/inc/themes/core.base/frontend/templates/modcp/reports/item.twig:11 #}
{{ trans('report_info_post_thread', report.thread_link, report.thread_subject) }}
```

`trans()` is registered **`is_safe => ['html']`**, so Twig does not autoescape its
return value:

```php
// targets/mybb/inc/src/Twig/Extensions/LangExtension.php:34-36
new TwigFunction('trans', [$this, 'trans'], [
    'is_safe' => ['html']
]),
```

`trans()` delegates to `MyLanguage::sprintf()`, which substitutes placeholders
with a plain `str_replace` and **no escaping**:

```php
// targets/mybb/inc/class_language.php:192
$string = str_replace('{'.$i.'}', $arg_list[$i], $string);
```

and the language string places the subject (`{2}`) directly as anchor link text:

```php
// targets/mybb/inc/languages/english/modcp.lang.php:61
$l['report_info_post_thread'] = "in <a href=\"{1}\">{2}</a>";
```

So the taint path is: `threads.subject` (attacker) → `modcp.php:471` (no escape)
→ `item.twig:11` `trans()` (`is_safe=html`, autoescape off) →
`MyLanguage::sprintf()` (no escape) → rendered as `<a>` link text in the staff
document. Every hop is unescaped.

**Why the framework doesn't save it.** Twig autoescaping is MyBB 1.9's primary XSS
defence, but `is_safe=html` is an explicit promise that `trans()`'s output is
already-safe HTML — a promise that is false the moment any argument is attacker
data. There is no `htmlspecialchars_uni()` on the controller side to make it true.

## Why it is a vulnerability (reasoning)

The trust boundary crossed is **member → staff**. A thread subject is content any
registered user controls; the Report Center is a privileged staff surface. The
invariant that should hold — "staff UI renders member-supplied strings as inert
text" — is broken: the subject renders as live HTML in the moderator/admin DOM.
This is not by design: MyBB escapes the very same subject on every other surface
(the mod-logs template renders it as `{{ logitem.tsubject }}`, autoescaped and
safe; `printthread.php:44` calls `htmlspecialchars_uni()`), and the report
template's use of `trans()` for a data argument is an oversight, not a feature.
The attacker's capability — run arbitrary JS in an administrator's session — is
categorically beyond what "post a thread / file a report" is meant to grant.

## Reproduction

From a clean lab (`docker compose -p cvehunterlab_mybb up -d`,
`http://localhost:25850`):

1. The exploit provisions one ordinary user (random name, usergroup 2) and logs
   it in (real web login) — this is "any registered member", no mod rights.
2. As that user it posts a thread in forum 2 whose **subject** is
   `<img src=x onerror="alert(document.domain);window.__xss='xss…'">`
   (`POST /newthread.php action=do_newthread`), and asserts the subject is stored
   verbatim in `mybb_threads.subject`.
3. It self-reports the thread's first post
   (`POST /report.php action=do_report&type=post&pid=<pid>&reason=3`) — MyBB
   allows self-reports (`report.php` only requires a logged-in uid), so the post
   enters the report queue.
4. **HTTP proof:** it logs in as the administrator and GETs
   `/modcp.php?action=reports`; the response contains the payload verbatim,
   un-encoded (`raw payload present=True, escaped=False`) — see `response.txt`.
5. **Browser proof:** it opens the same Report Center URL in a real Chromium
   carrying the admin's `mybbuser` cookie; the run prints `DIALOG_FIRED
   msg="localhost"` (i.e. `alert(document.domain)` executed in the admin session)
   and saves `evidence/xss_fired.png`.

Run it:
```bash
cd claude_audit/mybb/exploits/VULN-001 && ./run.sh
# expect: [OK] … ==> VULN-001: CONFIRMED
```

## Impact

Arbitrary JavaScript in a moderator/administrator forum session, delivered by a
brand-new low-privilege account and triggered by the victim's routine act of
opening the report queue. `mybbuser`/`adminsid` are `HttpOnly`, so raw cookie
theft is blocked — but the payload runs **same-origin with `/admin/`**, so it can
fetch an ACP page, read the admin post-key, and drive privileged ACP actions
(create an administrator, write/modify a template or plugin). A written template
reaches MyBB's documented `eval()`-based template execution (SECURITY.md #3689),
i.e. PHP code execution on the host. Net effect: **any registered user →
administrator → RCE**. This is the canonical sink of the XSS→ACP→RCE chain shared
with VULN-002/-004/-006; VULN-003's `multiapprovethreads` can additionally
force-publish a payload-bearing thread a moderator had held in the queue, widening
delivery.

## Suggested fix

Escape the subject at the controller before it reaches `trans()`, matching every
sibling controller:

```php
// modcp.php:471 and :657
$report_data['thread_subject'] = htmlspecialchars_uni($parser->parse_badwords($subject));
```

Systemically (VULN-020): stop declaring `trans()` `is_safe=html` for data
arguments, or escape data arguments inside `MyLanguage::sprintf()` / at each
`trans(…, <data>)` call site, and prefer autoescaped `{{ var }}` for user data.
Principle: the escape belongs at the output boundary, by default, not opt-in.

## References

- MyBB **SECURITY.md** issues #3126 (ACP XSS) and #3689 (template `eval()` RCE) —
  the documented terminal of this chain.
- **CVE-2015-2149** / Sonar "MyBB stored XSS to RCE" — the class (stored XSS →
  ACP → template RCE); this 1.9 `trans()`/`is_safe` sink is a new instance.
- OWASP **WSTG-INPV-02** (Stored XSS) and the OWASP XSS Prevention Cheat Sheet
  (contextual output encoding; never trust an "is_safe" wrapper over user data).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Fetched github.com/mybb/mybb/security/advisories pages 1-7 (67 advisories, 2020-2026-09-16) — no Report Center / thread-subject XSS; the only report-center entry is GHSA-47mm-6v2r-2rr6 (authorization, not output encoding)
2. Fetched mybb.com/versions/1.8.41/ — 24 security fixes listed; none is a Mod CP report XSS
3. Fetched github.com/advisories?query=mybb+xss+2026 — 0 results
4. Fetched github.com/mybb/mybb/security/policy — lists #3126 (ACP XSS) and #3689 (template system) as known classes; this sink is not listed

**Related but distinct public references** (same class or component, not this bug):
- GHSA-47mm-6v2r-2rr6 — insufficient authorization in the same `modcp.php` reports view (1.8.41); different weakness
- CVE-2015-2149 / Sonar "MyBB stored XSS to RCE" — the general stored-XSS-to-ACP chain; different sink
- MyBB SECURITY.md #3126 / #3689 — acknowledged ACP XSS class and template execution terminal

**Reasoning:** No advisory, release note or advisory-database entry covers the 1.9 Twig `trans()`/`is_safe` sink for the reported thread subject; the sink is new in the 1.9 rewrite. Caveats: 1.9 is alpha and the vendor may not yet publish advisories for it, stored XSS is a crowded class in MyBB, and a private report could exist.
