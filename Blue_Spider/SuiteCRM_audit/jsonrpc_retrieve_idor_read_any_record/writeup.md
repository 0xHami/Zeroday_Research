# VULN-001 — JSON-RPC `retrieve`: Authenticated IDOR, Read Any Record of Any Module

**ID**: VULN-001
**Software / Repository**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2, commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: High — **CVSS 3.1 6.5** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**Status**: `CONFIRMED (dynamic)`
**Auth required**: Any authenticated user (lowest privilege) — obtained here via a normal web login
of a freshly created, unprivileged "Regular User" account
**What an attacker gains**: Full-field read of any record in any module (Opportunities, Contacts,
Leads, Documents, …), regardless of the caller's own ACL/Role/Security-Group restrictions —
total defeat of SuiteCRM's horizontal access-control model from the lowest privilege level.

## Summary

SuiteCRM's JSON-RPC endpoint (`index.php?entryPoint=json_server`) exposes a `retrieve` method
that fetches any bean by module+id and serializes every column — without ever calling
`ACLAccess()` or applying Security-Group row filtering. Its own sibling method, `query`, gets this
right. Any authenticated user — including one an admin has explicitly locked out of a module via
a Role — can read that module's records in full through `retrieve`, while the same user's `query`
call against the identical record correctly returns nothing. This is confirmed live: a low-priv
test user configured with `Opportunities` `view`/`list` = **NONE** still read an admin-owned
Opportunity's full field set, including a planted secret string, through `retrieve`.

## How it works (mechanism & code trace)

**Entry point**: `POST /index.php?entryPoint=json_server` (registered
`include/MVC/Controller/entry_point_registry.php:55`, `auth => true` meaning "PHP session must
exist", not "per-record ACL enforced"). `json_server.php` instantiates `JsonRPCServer` and calls
`run()`.

**Auth gate** — `service/JsonRPCServer/JsonRPCServer.php:125-137` (`processRequest`):
```php
$current_user = $this->jsonServerUtils->authenticate();
if ($current_user === null) {
    $response['error'] = array('error_msg' => 'user not logged in');
    return $response;
}
```
`JsonRPCServerUtils::authenticate()` (`service/JsonRPCServer/JsonRPCServerUtils.php:113-152`) only
checks `$_SESSION['unique_key']` and `$_SESSION['authenticated_user_id']` — i.e. **any** logged-in
user, admin or not, restricted or not, passes this gate. Dispatch is then
`method_exists($this->jsonServerCalls, $request['method'])` (`JsonRPCServer.php:161-163`) — no
allow-list beyond "is it a public method on this class."

**The defect** — `service/JsonRPCServer/JsonRPCServerCalls.php:62-83` (`retrieve`):
```php
public function retrieve($request_id, $params)
{
    $jsonConfig = new json_config();
    $module = $params[0]['module'];
    $record = $params[0]['record'];

    $focus = BeanFactory::getBean($module, $record);
    $focus->retrieve($record);                              // :70  NO ACLAccess() call anywhere

    $module_arr = $jsonConfig->populateBean($focus);          // serializes every column_fields entry
    ...
    return array('id' => $request_id, 'result' => array('status' => 'success', 'record' => $module_arr));
}
```
`populateBean()` (`include/json_config.php:240-265`) serializes `$focus->column_fields` (every
DB-backed field) through `listFilter()`, which only strips a hardcoded list of `Users`-module
fields (`:282-298`) — for every other module, every field is returned as-is. There is no
`ACLAccess()` call and no Security-Group row filter anywhere in this path.

**The correctly-gated sibling**, for direct contrast — `JsonRPCServerCalls.php:148`:
```php
if ($focus->ACLAccess('ListView', true)) {
    $curlist = $focus->get_list(...);
    $list_return = array_merge($list_return, $curlist['list']);
}
```
`query()` checks `ACLAccess('ListView', true)` before returning any row. This is the exact same
endpoint family, exact same session, exact same underlying bean — proving the omission in
`retrieve()` is a specific defect, not a broader authentication gap.

**Live confirmation** (full transcript in `run.log`): a low-priv user was assigned a fresh Role
restricting `Opportunities` `view` and `list` to `ACL_ALLOW_NONE` (`-99`). Over one authenticated
session:
- `method=query` for the victim Opportunity → `{"id":"1","result":{"list":[]}}` (correctly blocked).
- `method=retrieve` for the **same id** → full record, including
  `"description":"CVEHUNTER-SECRET-opp_eeb3c181"` — a value independently confirmed present in the
  live `opportunities` table via `SELECT description FROM opportunities WHERE id=...`.

## Why it is a vulnerability (reasoning)

The trust boundary SuiteCRM's ACL/Role/Security-Group system exists to enforce is: *a user's
access to a record is governed by their assigned Role and Security-Group membership, evaluated
per module/action*. `query()` demonstrates the framework's own intended contract —
`ACLAccess('ListView', true)` — applied correctly one method away. `retrieve()` simply never
calls it. This cannot be by-design: the method's entire purpose (per its own doc comment, "Prints
out a SugarBean") is to hand back a specific record by id, which is precisely the operation ACL
exists to gate; omitting the check does not narrow the method's usefulness for any legitimate
caller, it only removes the one control a skeptic would expect to be there. The live evidence
removes any doubt that this is a real, exploitable authorization bypass rather than a
theoretical code-review nit: an administrator explicitly configured "this user may not view or
list Opportunities," and `retrieve` handed the data over anyway.

## Reproduction

1. **Preconditions** (all built by `automation.py`, see `notes.md` for exact IDs):
   - Create a low-privilege user via the admin panel.
   - Give that user a Role denying `Opportunities` view+list (`acl_roles`/`acl_roles_actions`/
     `acl_roles_users` rows, `access_override = -99`).
   - As admin, create an Opportunity with a random secret in `description`.
2. Log the low-priv user in (fresh web session, so the Role applies).
3. **Decisive request** (`request.http`):
   ```
   POST /index.php?entryPoint=json_server HTTP/1.1
   Content-Type: application/json
   Cookie: PHPSESSID=<low-priv session>

   {"method":"retrieve","id":"2","params":[{"module":"Opportunities","record":"<victim-guid>"}]}
   ```
4. Run `./run.sh` (`run.log` has the full transcript). Expected terminal line:
   ```
   ==> VULN-001: CONFIRMED — low-priv user w/ Opportunities view=list=NONE read admin-owned
   Opportunity <id> via JSON-RPC retrieve(); leaked description == planted secret
   'CVEHUNTER-SECRET-opp_eeb3c181'; query() on the same record via the same session returned nothing
   ```
5. **Observable proof**: `response.txt` / `evidence/retrieve_vulnerable_response.json` contain the
   full leaked record; `evidence/query_control_response.json` shows the same session's `query()`
   call for the identical record returning `{"list":[]}`.

## Impact

Any authenticated user — including the lowest-privilege account an admin can create — can read
the complete field set of any record in any module system-wide, by iterating ids (harvested from
list views, related-record panels, exports, or the ACL-limited `query` itself where partially
visible). This defeats SuiteCRM's Security-Groups/Role isolation model instance-wide for read
access. It chains directly into other findings in this cluster: harvested GUIDs feed
[VULN-003](../../vulns/VULN-003.md) (download any document's file bytes) and expose
`assigned_user_id`/relationship ids consumed by the write-side IDORs
([VULN-078](../../vulns/VULN-078.md), [VULN-079](../../vulns/VULN-079.md)). Pre-auth is not
required — but post-auth, it is total: every module except the handful of hardcoded `Users`
fields is affected.

## Suggested fix

Add an ACL check to `retrieve()` mirroring its own sibling:
```php
// service/JsonRPCServer/JsonRPCServerCalls.php:69 -- suggested
$focus = BeanFactory::getBean($module, $record);
$focus->retrieve($record);
if (!$focus->ACLAccess('DetailView')) {
    return array('id' => $request_id, 'error' => array('error_msg' => 'no_access'));
}
```
and extend `json_config::listFilter()` to honor per-module `sensitive`/ACL-sensitive field flags
for **every** module, not only the hardcoded `Users` list — an allow-list approach (only return
fields the caller's ACL/field-level security permits) is preferable to the current denylist that
happens to cover exactly one module.

## References

- CWE-639 — Authorization Bypass Through User-Controlled Key
- CWE-284 — Improper Access Control
- OWASP WSTG-ATHZ-04 — Testing for Insecure Direct Object References: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- PortSwigger — Access control vulnerabilities (IDOR): https://portswigger.net/web-security/access-control/idor
- Technique used: differential authorization testing — same session, same record, ACL'd sibling method (`query`) vs. the unguarded target method (`retrieve`), with a Role-based precondition to make the ACL boundary concrete and a DB-side cross-check on the leaked value.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM json_server JsonRPCServer retrieve IDOR CVE` — only unrelated IDORs (CVE-2026-32697 SuiteCRM 8 RecordHandler::getRecord, CVE-2026-29189 V8 API); nothing on the JSON-RPC service.
2. `SuiteCRM "json_server" entryPoint vulnerability advisory` — only 2024 SQLi advisories for other entry points (events, TreeData, export).
3. GitHub Advisory DB text search `SuiteCRM json` and `SugarCRM json_server` — 0 results.
4. All 77 advisories on github.com/SuiteCRM/SuiteCRM/security/advisories (8 pages) reviewed by title — none reference JSON-RPC / json_server / JsonRPCServerCalls.
5. NVD API keywordSearch=SuiteCRM (107 CVEs, all descriptions reviewed) and keywordSearch=SugarCRM (66 CVEs) — no description mentions json_server or JSON-RPC.
6. GitHub issue search `json_server OR JsonRPCServer` — only a functional JSON parse bug (#1044).

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-32697 — missing view ACL in SuiteCRM 8 `RecordHandler::getRecord()`; different codebase/handler.
- CVE-2026-29189 / GHSA-m6x8-3hxp-qxwv — V8 REST API ACL gaps (user preferences, relationships); different API.
- CVE-2026-63217 / GHSA-m5xj-rrwv-g3q3 — IDOR in the generatePdf entry point; different entry point.
- CVE-2022-45186 — field disclosure via the `getEditFieldHTML` action (7.12.7); different action.

**Reasoning:** No public CVE, GHSA, vendor release note or issue names the legacy JSON-RPC `retrieve` method or its missing ACL check; the adjacent IDOR disclosures are all in other handlers (V8 API, SuiteCRM 8 record handler, generatePdf). Record-level IDOR is a very common class in SuiteCRM with many 2026 reports, so a private or pending report cannot be excluded.
