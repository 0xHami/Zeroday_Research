# VULN-004 — Stored XSS in moderator "user notes" (moderator → staff/admin → RCE)

| | |
|---|---|
| **Software** | MyBB |
| **Repository** | https://github.com/mybb/mybb |
| **Affected version** | 1.9.0-alpha.1 (`inc/src/Application.php:28`) |
| **Commit** | `f8bf4e840cd42f5d61bfb789eb3975674081d69e` (branch `dev-1.9`) |
| **Severity** | Medium — CVSS 3.1 **6.8** (`AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N`) |
| **Status** | CONFIRMED (dynamic) |
| **Confidence** | 8/10 — stored unescaped and executed in a real admin browser |
| **Auth required** | Moderator with `caneditprofiles`; victim is a `canmodcp` staff member |
| **Attacker gains** | JS execution in a staff/admin session → same-origin ACP → template `eval()` RCE |

## Summary

A moderator can store a cross-site-scripting payload in a user's "notes" field
that executes in the session of any staff member who later views that user's
notes. The notes field is HTML-escaped on the *insert* path but only SQL-escaped
on the *update* path (`inc/datahandlers/user.php:1452`), and the viewnotes page
renders it with Twig's `|raw` filter — so a moderator-supplied `<img onerror>`
runs in an administrator's browser, giving the moderator a path to escalate to
administrator and, via the same-origin ACP, to the template `eval()` RCE.

## How it works (mechanism & code trace)

**Entry point.** A moderator submits the ModCP profile editor. The handler
requires only `caneditprofiles` and that the mod may manage the target:

```php
// targets/mybb/modcp.php:2202-2222 (abridged)
if($mybb->input['action'] == "do_editprofile")
{
    verify_post_check($mybb->get_input('my_post_key'));
    if($mybb->usergroup['caneditprofiles'] == 0) { error_no_permission(); }
    $user = get_user($mybb->input['uid']);
    if(!modcp_can_manage_user($user['uid'])) { error_no_permission(); }
```

The note is taken from input verbatim into the update handler:

```php
// targets/mybb/modcp.php:2287
"usernotes" => $mybb->get_input('usernotes'),
```

**The exact defect — update path SQL-escapes only.** `UserDataHandler('update')`
stores it with `$db->escape_string()` and **no** `htmlspecialchars_uni()`:

```php
// targets/mybb/inc/datahandlers/user.php:1450-1452
if(isset($user['usernotes'])) {
    $this->user_update_data['usernotes'] = $db->escape_string($user['usernotes']);
}
```

`escape_string()` neutralises SQL metacharacters only; the HTML (`<img …>`)
survives into the column intact. Dynamically confirmed: the DB row held the
payload byte-for-byte. Note the asymmetry — the *insert* path (~`user.php:1185`)
and the edit-form prefill (`modcp.php` editprofile) both `htmlspecialchars_uni`
the value, which is why the attacker never sees the payload fire in their own
editor; only the update→viewnotes path is unescaped.

**Sink.** The note is read, `nl2br`'d (no sanitising), and rendered `|raw`:

```php
// targets/mybb/member.php:1984-1992 (abridged)
if($mybb->user['uid'] == 0 || $mybb->usergroup['canmodcp'] != 1) { error_no_permission(); }
...
$user['usernotes'] = nl2br($user['usernotes']);     // nl2br does not sanitise
```
```twig
{# targets/mybb/inc/themes/core.base/frontend/templates/member/viewnotes.twig:5 #}
<div class="block__content">{{ user.usernotes|raw }}</div>
```

So: `usernotes` (moderator input) → `modcp.php:2287` (no escape) →
`user.php:1452` (SQL-escape only) → `member.php:1992` (`nl2br`) →
`viewnotes.twig:5` (`|raw`). No HTML escaping anywhere; the payload reaches the
staff DOM.

## Why it is a vulnerability (reasoning)

The trust boundary is **moderator → administrator/other staff**. User notes are a
staff coordination field a moderator writes; viewnotes is a staff surface.
MyBB clearly intends the field to be inert text — it escapes it on insert and in
the edit form — so the update-path omission is a bug, not design. The attacker
(a moderator) obtains JS execution in a higher-privileged session (administrator),
crossing a privilege boundary the moderator role is not meant to cross. Hence a
real stored XSS, scored Medium because injection requires the attacker to already
hold moderator rights and the victim must open that specific user's notes.

## Reproduction

From a clean lab (`http://localhost:25850`):

1. Provision a moderator (Super Moderators, gid 3 → `canmodcp=1, caneditprofiles=1`)
   and an ordinary target user; log the moderator in (real web login).
2. As the moderator, `POST /modcp.php` `action=do_editprofile&uid=<T>&usernotes=<img
   src=x onerror="alert(document.domain);window.__xss='xss…'">&my_post_key=…`; the
   exploit asserts the payload is stored verbatim in `mybb_users.usernotes`.
3. **HTTP proof:** as the administrator, `GET /member.php?action=viewnotes&uid=<T>`
   returns the note un-encoded in the `|raw` div (`response.txt`).
4. **Browser proof:** opening that URL in Chromium with the admin cookie prints
   `DIALOG_FIRED msg="localhost"` and saves `evidence/xss_fired.png`.

```bash
cd claude_audit/mybb/exploits/VULN-004 && ./run.sh   # ==> VULN-004: CONFIRMED
```

## Impact

A moderator escalates to arbitrary JavaScript in an administrator's session. Since
the forum front-end shares an origin with `/admin/`, the payload reads the ACP
post-key and drives privileged ACP actions, reaching the vendor-accepted template
`eval()` RCE (SECURITY.md #3689) — i.e. moderator → administrator → host RCE. It
can also laterally compromise other staff sessions that view the note. Same
terminal chain as VULN-001/-002/-006.

## Suggested fix

Escape on the update path exactly as the insert path does:

```php
// inc/datahandlers/user.php:1452
$this->user_update_data['usernotes'] = $db->escape_string(htmlspecialchars_uni($user['usernotes']));
```

or render autoescaped in `member/viewnotes.twig` (`{{ user.usernotes }}` with a
newline-preserving CSS/filter that keeps escaping). Audit every
`UserDataHandler('update')` text field for the same insert-vs-update asymmetry.

## References

- CVE-2015-2149 / curesec "MyBB <= 1.8.6 signature & profile XSS" — the ModCP
  stored-XSS class.
- OWASP WSTG-INPV-02 (Stored XSS); OWASP XSS Prevention Cheat Sheet.
- MyBB SECURITY.md #3689 (template `eval()` RCE) — chain terminal.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Fetched github.com/mybb/mybb/security/advisories pages 1-7 — no user-notes XSS; nearest are GHSA-22wp-jxm2-5w7m (ACP Users View Manager XSS), GHSA-4p6g-p3qh-559v (profile field type confusion XSS), GHSA-p766-qqxv-rfc2 (buddy/ignore list username XSS), all different fields
2. Fetched mybb.com/versions/1.8.41/ — none of the 24 fixes concerns user notes
3. Fetched github.com/advisories?query=mybb+xss+2026 — 0 results
4. Fetched github.com/mybb/mybb/security/policy — not listed

**Related but distinct public references** (same class or component, not this bug):
- CVE-2015-2149 / curesec 1.8.x profile-field XSS — same ModCP profile-editor class, different field
- GHSA-22wp-jxm2-5w7m, GHSA-4p6g-p3qh-559v — 2026 stored XSS fixes in other user-profile fields

**Reasoning:** No advisory or release note covers the insert-vs-update escaping asymmetry for the moderator notes field or its raw rendering in the viewnotes page. Caveats: stored XSS is a crowded class in MyBB, the 1.8 line was not checked for the same asymmetry, and the attacker must already hold moderator rights.
