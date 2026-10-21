# VULN-051 — UserGroup create mass-assignment → Users-delegate self-escalates to whole-tree/all-verb/all-language

**Software**: Umbraco CMS
**Repository**: https://github.com/umbraco/Umbraco-CMS
**Affected version**: 18.3.0-rc (version.json; commit-pinned, no tagged release)
**Commit**: `cee7d8981ab0fd18b4dc96449ae071edf1aaf21e`
**Status**: CONFIRMED
**Severity (static)**: Medium–High — CVSS 3.1 `8.0` (`AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N`)
**Validated at**: 2026-09-29

## Preconditions
- Admin creates: a document type + two root documents D1 (in-scope) and D2 (out-of-scope sibling).
- Admin creates a **delegate group** holding the **Users** + **Content** sections, confined to
  `documentStartNode = D1`, `documentRootAccess = false`, `hasAccessToAllLanguages = false`,
  `fallbackPermissions = ["Umb.Document.Read"]` — a realistic "user administrator" delegation that is
  otherwise tightly scoped.
- Admin creates a user in that group, sets its password; the exploit then acts **as that non-admin delegate**.
- All names/emails/aliases/passwords carry a random suffix.

## Request
See `request.http`. Two decisive requests, both sent with the **non-admin Users-delegate** bearer:
- CONTRAST: `POST /umbraco/management/api/v1/user-group` with `documentStartNode = {id: D2}` (a specific
  out-of-scope node) → rejected.
- ATTACK: `POST /umbraco/management/api/v1/user-group` with `documentRootAccess:true`,
  `mediaRootAccess:true`, `elementRootAccess:true`, `hasAccessToAllLanguages:true`, all 14 document verbs
  (sections restricted to the two the delegate already holds) → accepted.

## Response
See `response.txt` / `run.log`:
- Grant an **unheld section** (Settings) → **401** (blocked — `AllowedSections ⊆ caller` works).
- Grant a **specific out-of-scope node** D2 → **401** (blocked — `HasAccessToContentStartNode` works).
- Grant **whole-tree root access** (a *superset* of D2) → **201 Created**, group id returned.
- `GET /user-group/{id}` → `documentRootAccess=true`, `mediaRootAccess=true`, `hasAccessToAllLanguages=true`, 14 fallback verbs — the group **persisted** the escalated grant.
- Admin `GET /user/{delegateId}` → the delegate is **auto-joined** to the new group (the create endpoint
  has no members parameter).
- Effective `GET /user/current` as the delegate flipped `hasDocumentRootAccess` **false → true** (plus
  media-root, all-languages, and the full verb set).

## Observation
Matches the static finding exactly. `ValidateAccess` (`UserGroupPermissionService.cs:77-106`) enforces
section-subset and *specific* start-node scoping but never validates root access, languages, granular
verbs or element-root. `documentRootAccess:true` maps to `StartContentId = -1`
(`UserGroupPresentationFactory.cs:264-272`), and `HasAccessToContentStartNode` returns `true` for it
because `GetById(-1)` is null (`:146-151`). `EnsureNonAdminUserIsInSavedUserGroup`
(`UserGroupService.cs:747-758`) auto-joins the creator. The delegate was refused a single foreign node
yet handed the whole tree that contains it, and became a member of the group granting it.

## Side effects
- Per run creates: 1 document type, 2 documents, 1 delegate user group, 1 delegate user, and up to 3
  user groups created *as the delegate* (2 rejected attempts leave nothing; the accepted escalation
  group persists). All random-suffixed. No existing entity modified.

## Research & references
- **CVE-2026-31834 / GHSA-rhcg-3h8r-v6vp** (CVSS 7.2, fixed 16.5.1 / 17.2.2): closed the *membership*
  path ("add yourself to the Administrator group"). This finding is the distinct **group-definition
  mass-assignment** path (languages / verbs / root / element-root unvalidated), source-confirmed and
  dynamically confirmed still open at 18.3.0-rc.
- OWASP: Privilege Escalation / WSTG-ATHZ (functional access-control). CWE-915 (mass assignment),
  CWE-269 / CWE-266 (privilege management).

## If FAILED
n/a — CONFIRMED. (Note: `/user/current` is served from a 5-minute user cache; the decisive proof is the
cache-independent trio — specific node refused, root access accepted+persisted, creator auto-joined.)
