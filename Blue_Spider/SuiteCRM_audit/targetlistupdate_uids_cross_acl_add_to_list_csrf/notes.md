# VULN-050 — `targetlistupdate`: add arbitrary records (any module) to any target list with no ACL, CSRF-able

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28

## Preconditions
- Admin creates a low-privilege RegularUser `L` (`_common.create_user`).
- `L` is given a throwaway ACL Role (`_c1_common.restrict_role`) that sets `Contacts` `view` and
  `list` to `ACL_ALLOW_NONE` — this is the realistic precondition ("this user cannot see these
  records at all") that makes the bypass meaningful; the helper's own doc notes a fresh install
  with zero roles defaults every module to `ACL_ALLOW_ALL`, so without this step the "bypass"
  would be indistinguishable from L's normal (wide-open) access.
- Admin creates two Contacts `C1`/`C2`, `assigned_user_id=admin` — outside L's ACL.
- `L` creates its own `ProspectList PL`.

## Request
See `request.http`. Two `POST /index.php?module=Contacts&action=targetlistupdate` calls as `L`:
(a) `uids=<C1>&prospect_list=<PL>` with a normal same-host `Referer`;
(b) `uids=<C2>&prospect_list=<PL>` with **no `Referer` header at all** (CSRF proof).

## Response
See `response.txt`. Both return `HTTP 302` to a `DetailView` redirect (`handleRedirect()` at
`TargetListUpdate.php:109`) — indistinguishable from a legitimate, authorized add; no error, no
ACL-denial page for either request, including the no-Referer one.

## Observation
Exactly matches the static finding.
1. **Baseline ACL is real**: `L`'s own `GET Contacts&action=DetailView&record=<C1>` returns HTTP 200
   but the response does **not** contain the Contact's name (`Ctgt1_...`) — SuiteCRM's normal ACL
   correctly hides `C1` from `L` everywhere else in the app.
2. **The bypass**: despite that, both `targetlistupdate` calls succeed and create
   `prospect_lists_prospects` rows linking `C1`/`C2` into `L`'s own list `PL` — confirming the
   `uids` branch (`TargetListUpdate.php:79`) truly skips the `buildAccessWhere('list')` filter that
   guards the `select_entire_list` branch (`:67`), and `retrieve()`/`add()` (`:95`,`:104`) apply no
   ACL of their own.
3. **CSRF**: the second add (`C2`) was sent with zero `Referer` header using a plain `requests.post`
   (not the `Session` that performed the login POST, so no stale Referer could linger) and still
   succeeded — confirming `isModifyAction()` is false for `targetlistupdate` on the `Contacts`
   module (`include/MVC/SugarApplication.php:502-523`), so `checkHTTPReferer()`'s empty-Referer
   guard (`:553`) never fires.

## Side effects
- Creates one throwaway RegularUser, one throwaway ACL Role (+ 2 `acl_roles_actions` overrides + 1
  `acl_roles_users` link — all random-suffixed, scoped only to that user), two Contacts, and one
  ProspectList. No demo data touched.
- DB verification (as the auditor):
  ```
  SELECT related_id, related_type, prospect_list_id, deleted FROM prospect_lists_prospects
  WHERE prospect_list_id='<PL>' AND related_id IN ('<C1>','<C2>') AND deleted=0;
  ```
  → returns both rows, `related_type='Contacts'`, `deleted=0` — the literal decisive evidence.

## Research & references
- OWASP WSTG-ATHZ-04 (Testing for Insecure Direct Object References) — the `uids` path is a
  classic id-list-with-no-ownership-check IDOR.
- OWASP CSRF Cheat Sheet / PortSwigger "CSRF where referer validation is missing" — the same
  no-Referer bypass technique used here (a hand-maintained allowlist of "modify actions" gates the
  referer check; anything outside it, like `targetlistupdate`, evades the check entirely — the
  same root cause SuiteCRM's own CVE-2023-3627/GHSA-qg9r-8vq4-2gp4 CSRF class documents).

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a.
