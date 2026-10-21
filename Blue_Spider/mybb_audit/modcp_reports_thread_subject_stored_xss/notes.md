# VULN-001 — Stored XSS in the Moderator Report Center via thread subject

**Software**: MyBB
**Repository**: https://github.com/mybb/mybb
**Affected version**: 1.9.0-alpha.1 (`inc/src/Application.php:28`; branch `dev-1.9`, commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: High
**Confidence**: 9/10
**Confidence reasoning**: Proven end-to-end against the running lab — payload stored verbatim, served unescaped to the admin Report Center, AND executed in a real browser in the admin's session (alert fired). Low-priv → admin, chains to ACP eval() RCE.
**Target commit**: f8bf4e840cd42f5d61bfb789eb3975674081d69e
**Validated at**: 2026-10-01T23:58Z

## Preconditions
- Any registered user (open registration is on). The script provisions one ordinary Registered-group user with no moderator rights and logs it in over the real web login.
- A moderator/administrator later opens the Report Center (routine). The admin (uid 1, super admin; gid 4 has `canmodcp=1, canmanagereportedcontent=1, issupermod=1`) sees all reports.

## Request
See `request.http`. Three HTTP steps, all as the low-priv attacker except the last:
1. `POST /newthread.php` `action=do_newthread&fid=2&subject=<img src=x onerror=...>&message=...&my_post_key=…`
2. `POST /report.php` `action=do_report&type=post&pid=<first post>&reason=3&my_post_key=…`
3. `GET /modcp.php?action=reports` as the moderator/admin → payload fires.

## Response
See `response.txt` — the admin's Report Center HTML contains the subject verbatim inside the report line
(`in <a href="…"><img src=x onerror="alert(document.domain);window.__xss='xss…'"></a>`), with `<`/`>` **not** entity-encoded.

## Observation
Exactly as predicted statically:
- The subject persisted unchanged in `mybb_threads.subject` (verify_subject does not HTML-escape).
- The Report Center (`modcp.php:471` → `modcp/reports/item.twig:11` `{{ trans('report_info_post_thread', …, report.thread_subject) }}`, `trans` is `is_safe=html`) rendered it unescaped — HTTP check: `raw payload present=True, escaped=False`.
- The real-browser probe with the ADMIN cookie reported `DIALOG_FIRED msg="localhost"` and `window.__xss=<marker>`: `alert(document.domain)` executed in the administrator's authenticated session. Screenshot: `evidence/xss_fired.png`.

## Side effects
Persistent lab state created (random-named): one attacker user, one thread (tid shown in log) with the payload subject, one reportedcontent row. All benign and clearly marked; a moderator can delete the thread/clear the report. Re-runs use fresh random markers so they do not collide.

## Research & references
- OWASP WSTG-INPV-02 (Stored XSS) — store the payload, then confirm execution in the privileged view that renders it.
- PortSwigger "Stored XSS" + the i18n/`is_safe` footgun class (cf. CVE-2026-46637 phpMyAdmin twig-i18n) — translation helpers declared HTML-safe while substituting unescaped data.
- MyBB SECURITY.md #3689 (template `eval()` RCE reachable from ACP write access) — the terminal of the chain this XSS enters once it runs in an admin session.

## If FAILED
n/a — confirmed.

## If NEEDS_MANUAL
The *admin→ACP→eval() RCE* continuation is a documented vendor-accepted class (SECURITY.md #3689) and was not re-weaponised here (per scope, the ACP-template RCE is cited as the amplifier, not re-filed). The XSS entry point that makes it reachable from a low-priv user is fully CONFIRMED above.

## If INTENDED
n/a — rendering a user-controlled subject unescaped in staff UI is not documented/by-design; sibling controllers escape it.
