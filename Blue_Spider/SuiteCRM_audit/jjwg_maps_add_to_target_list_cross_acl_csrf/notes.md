# VULN-051 — jjwg_Maps `add_to_target_list`: no-ACL add-to-list, CSRF-able

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28

## Preconditions
- Low-priv RegularUser `L`, with a throwaway ACL Role denying `Contacts` `view`/`list`
  (`ACL_ALLOW_NONE`) — same rationale as VULN-050: a fresh install defaults every module to
  ACL_ALLOW_ALL, so a meaningful bypass proof needs something actually denied first.
- Admin creates two Contacts `C1`/`C2` (`assigned_user_id=admin`) — outside `L`'s ACL.
- `L` creates its own `ProspectList PL`.

## Request
See `request.http`: three `POST /index.php?module=jjwg_Maps&action=add_to_target_list` calls as
`L` — (a) `display_module=Contacts&selected_ids=<C1>` with Referer, (b) same for `C2` with **no
Referer header**, (c) `display_module=Users&selected_ids=<admin id>` (see correction below).

## Response
See `response.txt`.
- (a) and (b): `{"message":"Target List Updated","list":{"name":"Contact"}}`.
- (c): `{"message":"Target List NOT Updated","list":{"name":null}}`.

## Observation
(a)/(b) exactly match the static finding: `action_add_to_target_list()` validates only
`is_guid()` on `list_id`/`selected_ids` (`controller.php:328,338`) and performs no
`ACLAccess`/owner/SecurityGroup check before `$list->contacts->add($sel_id)`
(`:363-367`) — both admin-owned Contacts, which `L` cannot even `view`, were linked into `L`'s
own list. (b) used a bare `requests.post()` with **no** `Referer` header key at all (not the
Session that performed the login, so nothing could leak in) and still succeeded, confirming
`isModifyAction()` is false for `jjwg_Maps`/`add_to_target_list`.

**Source-verified correction to the "including Users" sub-claim**: request (c) —
`display_module=Users` — returned `"Target List NOT Updated"`, and the DB confirms **no**
`related_type='Users'` row was created. Tracing why: `$this->display_object` is only populated at
`controller.php:346-351` when
`in_array($_POST['display_module'], $this->settings['valid_geocode_modules'])`, and
`jjwg_Maps.php:62-64`'s default is
`['Accounts','Contacts','Leads','Opportunities','Cases','Project','Meetings','Prospects']` —
**'Users' is not in it**. `SELECT * FROM config WHERE category LIKE '%jjwg%'` returned zero rows,
confirming this lab has no admin override. So with `display_module=Users`, `$this->display_object`
stays unset and the big guard at `:353` (`!empty($this->display_object) && ...`) is false before
the code ever reaches the `elseif ($object_name == 'User')` branch at `:378-382`. **The Users-add
branch genuinely exists in the code and remains a real latent bug** (it still has zero ACL check,
and would fire the moment an admin adds `'Users'` to Maps' configured module list, or via any
other caller that populates `$this->display_object` with the Users module before this check) —
but it is **not reachable via this action with the shipped default configuration**, so the overall
finding is scored/reported as CONFIRMED for the core Accounts/Contacts/Leads/Prospects bypass,
with the Users angle downgraded to a documented, code-verified but config-gated sub-claim (not an
independently exploitable default-config path).

## Side effects
- Creates one throwaway RegularUser, one throwaway ACL Role (random-suffixed, scoped to that user
  only), two Contacts, one ProspectList. No demo data touched.
- DB verification:
  ```
  SELECT related_id, related_type FROM prospect_lists_prospects
  WHERE prospect_list_id='<PL>' AND related_id IN ('<C1>','<C2>') AND deleted=0;
  ```
  → both rows present, `related_type='Contacts'`. The parallel query for `related_type='Users'`
  under the same `PL` returns empty, corroborating the correction above.

## Research & references
- OWASP WSTG-ATHZ-04 (IDOR) and the OWASP CSRF Cheat Sheet — same technique family as VULN-050.
- Same `jjwg_Maps` module as the advisoried CVE-2026-69142/GHSA-pjc8-2w2x-xcgf; this specific
  `add_to_target_list` no-ACL sink is the concrete instance validated here.

## If FAILED
n/a — CONFIRMED (core Contacts bypass). See "Observation" above for the honest, source-verified
scope correction on the Users sub-claim (config-gated, not a mitigation of the core bug).

## If NEEDS_MANUAL
n/a.
