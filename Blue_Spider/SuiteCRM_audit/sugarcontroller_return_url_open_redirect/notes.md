# VULN-054 — SugarController post-delete redirect to raw return_url

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 3.1 6.1 — `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:44Z

## Preconditions
- A fresh low-privileged user, provisioned by admin via `create_user()` (standard
  stage-10 primitive) — represents *any* authenticated SuiteCRM user, not a
  privileged one.
- That user creates a Note they own (legacy REST `set_entry`, module `Notes`).
- Per the assignment: "Use a record you create/own; the redirect is the
  finding, not the delete" — the delete is the legitimate vehicle into
  `post_delete()`, not itself the bug.

## Request
See `request.http`:
```
GET /index.php?module=Notes&action=Delete&record=<own note id>&return_url=https://evil-cvehunter-c054_505001ad.example/pwn HTTP/1.1
Host: localhost:33116
Referer: http://localhost:33116/index.php?module=Notes&action=DetailView&record=<own note id>
Cookie: (authenticated session of mod_bf71d83d)
```
A same-origin `Referer` is included because `action=Delete` is a *modify
action* (`SugarApplication::isModifyAction()`, `include/MVC/SugarApplication.php:502-523`,
matches the `delete` prefix) and `checkHTTPReferer()` (`:535-591`) would
otherwise reject the request outright with the `xsrf.tpl` page. This referer
requirement is orthogonal to the vulnerability under test — it is the *normal*
CSRF gate on the delete action working as intended; the bug is that the
resulting **redirect target** is never validated at all.

## Response
See `response.txt`:
```
HTTP/1.1 301 Moved Permanently
Location: https://evil-cvehunter-c054_505001ad.example/pwn
```

## Observation
Matches the static finding exactly. `post_delete()`
(`include/MVC/Controller/SugarController.php:732-755`):
```php
protected function post_delete()
{
    if (empty($_REQUEST['return_url'])) {
        ...
        $url = "index.php?module=" . $return_module . "&action=" . $return_action . "&record=" . $return_id;
    } else {
        $url = $_REQUEST['return_url'];      // :746 — attacker-controlled, unvalidated
    }
    ...
    $this->set_redirect($url);               // :754
}
```
`set_redirect()` feeds `SugarApplication::redirect()`
(`include/MVC/SugarApplication.php:639-671`), which emits `header("HTTP/1.1 301
Moved Permanently")` + `header("Location: " . $url)` (`:664-665`) verbatim —
confirmed by the observed `301` + exact `Location` echo.

Independently confirmed the delete genuinely executed — `notes.deleted = 1`
for the note id in the DB (queried via the `db` container) — proving this is
real `SugarController` save/delete traffic reaching `post_delete()`, not a
short-circuited or erroring request.

## Side effects
- `notes` table: the created Note's `deleted` flag flips `0 → 1` (expected,
  legitimate side effect of the user deleting their own record — not itself a
  security issue, included only to prove the request path taken).
- No other state change; the open redirect itself is stateless.

## Research & references
- OWASP Unvalidated Redirects and Forwards Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- PortSwigger Web Security Academy — "Open redirection":
  https://portswigger.net/web-security/dom-based/open-redirection
- CWE-601: https://cwe.mitre.org/data/definitions/601.html

## If FAILED
N/A — confirmed.
