# VULN-004 — Stored XSS in moderator "user notes" (moderator → staff/admin → RCE)

**Software**: MyBB
**Repository**: https://github.com/mybb/mybb
**Affected version**: 1.9.0-alpha.1 (`inc/src/Application.php:28`; branch `dev-1.9`, commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium
**Confidence**: 8/10
**Confidence reasoning**: Proven end-to-end (stored unescaped, executed in a real admin browser). Gated behind the attacker already holding moderator rights and a staff member opening that user's notes, hence Medium.
**Target commit**: f8bf4e840cd42f5d61bfb789eb3975674081d69e
**Validated at**: 2026-10-02T00:12Z

## Preconditions
- Attacker is a moderator with `caneditprofiles` (provisioned as a Super Moderator, gid 3: `canmodcp=1, caneditprofiles=1`).
- A target user whose notes the moderator edits (any ordinary user).
- Victim is any `canmodcp` staff member who opens the target's notes (admin for the RCE leg).

## Request
See `request.http`:
1. `POST /modcp.php` `action=do_editprofile&uid=<T>&usernotes=<img src=x onerror=...>&my_post_key=…`
2. `GET /member.php?action=viewnotes&uid=<T>` as a `canmodcp` staff member → fires.

## Response
See `response.txt` — the admin's viewnotes modal contains `<div class="block__content"><img src=x onerror="alert(document.domain);window.__xss='xss…'"></div>` with `<`/`>` un-encoded.

## Observation
Exactly as predicted. `modcp.php:2287` passes `usernotes` raw into `UserDataHandler('update')`; `inc/datahandlers/user.php:1452` applies `$db->escape_string()` only (SQL-escape, no HTML-escape), so the stored column holds the literal HTML. `member.php:1992` runs `nl2br()` (no sanitise) and `member/viewnotes.twig:5` renders `{{ user.usernotes|raw }}`. HTTP check: stored verbatim; served unescaped (`raw present=True, escaped=False`). Real-browser probe with the ADMIN cookie: `DIALOG_FIRED msg="localhost"`, `window.__xss=<marker>` — executed in the admin session. Screenshot: `evidence/xss_fired.png`.

## Side effects
Two throwaway users (a super-mod and a target). The target's `usernotes` holds the benign-marker payload; harmless. Random names → re-runs independent.

## Research & references
- CVE-2015-2149 / curesec — MyBB ModCP profile-editor stored XSS class (this is the 1.9 `usernotes` update-path instance rendered `|raw`).
- OWASP WSTG-INPV-02 (Stored XSS); OWASP XSS Prevention Cheat Sheet — encode on output; beware insert-vs-update encoding asymmetry.
- MyBB SECURITY.md #3689 — template `eval()` RCE reachable once the payload runs in an admin session.

## If FAILED
n/a — confirmed.

## If NEEDS_MANUAL
The admin→ACP→eval() continuation is the documented vendor-accepted class (#3689), cited as amplifier, not re-weaponised here.

## If INTENDED
n/a — the insert path escapes the same field; the update-path omission is a bug, not documented behaviour.
