# VULN-055 — Alerts `action_redirect`: cross-user stored open redirect

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 3.1 6.1 — `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:46Z

## Preconditions
- Two independent, unrelated, low-privileged users provisioned via admin
  (`create_user()`): **attacker** and **victim**. Neither is an admin; they
  share no relationship or ACL scope.
- Attacker plants an Alert (`module=Alerts&action=add`, their own,
  legitimately owned record) with a malicious `url_redirect`.
- The alert's id is read back by matching on a random `reminder_id` the
  attacker chose (via the `db` container — `action_add`'s JSON response only
  echoes `{"result":1}`, not the new id, so this is "find what I just
  created," equivalent to what a real attacker would see in their own Alerts
  list/DB).

## Request
Plant (attacker's own session):
```
POST /index.php?module=Alerts&action=add
reminder_id=rem_<rand>&url_redirect=<attacker URL>&name=malicious-reminder&description=planted by attacker
```
Attack (see `request.http`, **victim's** session — a completely different
user who never interacted with the attacker's alert):
```
GET /index.php?module=Alerts&action=redirect&record=<attacker's alert id> HTTP/1.1
Host: localhost:33116
Cookie: (authenticated session of VICTIM, NOT the attacker)
```

## Response
See `response.txt`:
```
HTTP/1.1 301 Moved Permanently
Location: https://evil-cvehunter-c055_7edd5dd5.example/redir
```

## Observation
Matches the static finding exactly. `action_redirect`
(`modules/Alerts/controller.php:140-155`):
```php
public function action_redirect()
{
    $bean = BeanFactory::getBean('Alerts', $_GET['record']);   // :142 — no owner check
    $redirect_url = $bean->url_redirect;
    $bean->is_read = 1;
    $bean->save();
    if ($redirect_url) {
        SugarApplication::redirect($redirect_url);              // :148 — stored, unvalidated
    }
    ...
}
```
The victim account — created fresh, with no shared team/role/relationship to
the attacker account, and never having called `action=add` — was able to
fetch and be redirected by an alert it does not own, purely by supplying that
alert's id. This confirms the load at `:142` performs **no**
`assigned_user_id`/ACL scoping (unlike, e.g., a properly scoped
`get_full_list("alerts.assigned_user_id = '\$current_user->id'")` as seen in
`action_get()` at `:50` of the same file, which shows the codebase *does* know
how to scope this bean and simply omits it here).

## Side effects
- `alerts` table: the target alert's `is_read` flag flips to `1` as a side
  effect of `action_redirect()` calling `$bean->save()` (`:144-145`) —
  confirms the request reached and executed the real handler, not a cached or
  short-circuited response.
- No other state change.

## Research & references
- CWE-639: Authorization Bypass Through User-Controlled Key (IDOR):
  https://cwe.mitre.org/data/definitions/639.html
- CWE-601: URL Redirection to Untrusted Site: https://cwe.mitre.org/data/definitions/601.html
- OWASP Unvalidated Redirects and Forwards Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- PortSwigger Web Security Academy — "Open redirection" / "Insecure direct
  object references": https://portswigger.net/web-security/dom-based/open-redirection

## Note on the Referer-XSS lead (from the static finding)
The static finding also flags a **NEEDS_MANUAL** lead: `SugarApplication::redirect()`
echoes `$url` into an inline `<script>` when `ajax_load` is set or headers are
already sent (`include/MVC/SugarApplication.php:650`/`:660`), and that `$url`
can come from an **unfiltered `HTTP_REFERER`** fallback
(`modules/Alerts/controller.php:151-152`) rather than the stored
`url_redirect`. This dynamic pass did not attempt that path (it requires
forcing the `ajax_load`/headers-sent branch and controlling `Referer` in a way
a normal HTTP client can, but confirming actual script execution needs a real
browser context) — left as NEEDS_MANUAL per the original finding, not
re-scored here since this exploit's scope was the redirect (already
CONFIRMED via the primary sink).

## If FAILED
N/A — confirmed.
