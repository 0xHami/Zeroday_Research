# VULN-024 — SubPanelViewer parent-ACL bypass (IDOR)

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: High
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:18Z

## Preconditions
- `automation.py` creates two fresh, unrelated low-priv users via admin (`create_user`): victim **V** and attacker **A**.
- As **V**: creates an Account (`module=Accounts&action=Save`) and a Contact related to it via `account_id`/`account_name` (`module=Contacts&action=Save`). Both records are owned by V; A has no ACL grant, Security-Group membership, or relationship to either record. (Note: passing `dup_checked=1` on the Contact save changes `ContactFormBase::handleSave()`'s field prefix and silently drops the `account_id`/`account_name` relate — first run hit this and produced an empty subpanel (0 results); removed `dup_checked` and the relate succeeded.)

## Request
See `request.http`. In short, as **A**:
```
GET /index.php?module=Accounts&action=SubPanelViewer&record=<victim_account_id>&subpanel=contacts&inline=1&ajaxSubpanel=true
Cookie: PHPSESSID=<attacker session>
```

## Response
See `response.txt` (HTTP 200, `Content-Length: 2409` after gzip; ~9.9 KB decompressed). The listview HTML embeds a row for the victim's Contact, including its `last_name` marker.

## Observation
Matches the static finding exactly: `include/SubPanel/SubPanelViewer.php:48-90` reads `module`/`record`/`subpanel` straight from `$_REQUEST`, builds `BeanFactory::getBean($module)` + `new SubPanel($module, $record, $subpanel, ...)`, and calls `->display()` — at no point is `ACLAccess('DetailView')` (or any other authorization check) invoked on the **parent** record identified by `record`. The routing itself is also confirmed: `include/MVC/Controller/action_file_map.php:41` maps `action=SubPanelViewer` directly to this file, bypassing `AccountsController` entirely, so no module-specific `pre_action`/ACL hook ever runs either.

Dynamic proof: attacker A, who never viewed, was never assigned, and has no Security-Group overlap with victim V's Account or Contact, received the related Contact's `last_name` value in a raw AJAX-style GET with no denial page, no redirect to login, and no "no access" string anywhere in the response.

**Environmental caveat (honesty note, applies to the whole IDOR/broken-access-control cluster in this lab):** this instance has **zero ACL Roles configured** (`SELECT COUNT(*) FROM acl_roles` → 0), so SuiteCRM's generic per-module ACL is maximally permissive for every authenticated user by default — a separate control run confirmed attacker A can also open victim V's Account **directly** via `module=Accounts&action=DetailView&record=<id>` (200, full page, no denial) even without SubPanelViewer. This lab's permissive default doesn't provide a *contrasting* control (i.e. "SubPanelViewer succeeds where DetailView would fail") in this specific environment. That does **not** refute the finding: the code-level defect is real and independent of role configuration — `SubPanelViewer.php` never calls `ACLAccess('DetailView')` on the parent under any configuration, so in any deployment that *does* restrict Accounts/Contacts visibility via Roles or Security Groups (the normal case for an organization actually using SuiteCRM's authorization model), this exact code path bypasses that restriction. The dynamic run here proves the mechanism (no-ACL-check code path, reachable, returns real cross-user data); it does not by itself prove a delta against this lab's wide-open baseline.

## Side effects
None destructive. Two new Users, one Account, one Contact created (random-suffixed, harmless).

## Research & references
- CWE-639 (Authorization Bypass Through User-Controlled Key) / OWASP A01:2021-Broken Access Control.
- Root-cause pattern matches PortSwigger's "Insecure direct object references" topic (id-based access to a subordinate resource without checking the parent's authorization).
