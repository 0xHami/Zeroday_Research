# VULN-051 — UserGroup create/update mass-assignment → a delegated Users-administrator self-escalates to whole-tree, all-verb, all-language access

| | |
|---|---|
| **ID** | VULN-051 |
| **Software** | Umbraco CMS |
| **Repository** | https://github.com/umbraco/Umbraco-CMS |
| **Affected version** | 18.3.0-rc (commit-pinned; no tagged release) |
| **Commit** | `cee7d8981ab0fd18b4dc96449ae071edf1aaf21e` |
| **Severity** | Medium–High — CVSS 3.1 `8.0` (`AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N`) |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | A **non-admin** backoffice user whose group holds the **Users** section — a common enterprise "user administrator" delegation (not a default group). |
| **Attacker gains** | The delegate grants *itself* whole content **and** media tree access, all languages, and every document verb — escaping the start-node / language / verb scope it was provisioned with. |

## Summary

Umbraco lets an administrator delegate user management by giving a non-admin group the **Users**
section. Such a user may create and edit user groups. The authorization gate for that,
`UserGroupPermissionService.ValidateAccess`, checks only four things: the caller has the Users section,
the group's **sections** are a subset of the caller's, and the group's **specific** content/media
start-nodes are within the caller's path. It does **not** validate the group's **languages**, its
**granular permission verbs**, its **element** start-node, or **root** content/media access. Because a
request with `documentRootAccess:true` is mapped to the sentinel start-node `-1` and `GetById(-1)` is
null, whole-tree access passes the *specific-node* check that a real foreign node would fail. On top of
this, `UserGroupService.CreateAsync` auto-joins the non-admin creator to the group it just made. The net
effect: a Users-delegate crafts a group granting the whole tree / all languages / all verbs (within the
sections it already holds) and is silently made a member of it — vertical privilege escalation.

Dynamically confirmed: a delegate confined to start-node **D1** was returned **401** when it asked for a
group scoped to the out-of-scope sibling **D2**, yet **201** when it asked for `documentRootAccess:true`
(a superset of D2), was **auto-joined**, and its effective `hasDocumentRootAccess` flipped **false → true**
(with media-root, all-languages and 14 document verbs).

## How it works (mechanism & code trace)

**The gate — only four checks.** Group create/update authorize through `ValidateAccess`:

```csharp
// src/Umbraco.Core/Services/UserGroupPermissionService.cs:77-106
private UserGroupAuthorizationStatus ValidateAccess(IUser user, IUserGroup userGroup)
{
    if (HasAccessToUsersSection(user) is false)             return ...MissingUsersSectionAccess;   // :79-83
    if (HasAccessToAllUserGroupSections(user, userGroup) is false) return ...MissingAllowedSectionAccess; // :86-90
    if (HasAccessToContentStartNode(user, userGroup) is false)    return ...MissingContentStartNodeAccess; // :93-97
    if (HasAccessToMediaStartNode(user, userGroup) is false)      return ...MissingMediaStartNodeAccess;   // :99-103
    return UserGroupAuthorizationStatus.Success;
}
```

A grep of the method body for `Language | Permission | FallbackPermission | StartElement` returns
**nothing** — `HasAccessToAllLanguages`, `AllowedLanguages`, `Permissions`/`FallbackPermissions`
(granular verbs) and `StartElementId`/element-root are never compared against the caller.

**The root-node bypass.** The start-node check treats an unresolvable node as allowed:

```csharp
// UserGroupPermissionService.cs:139-154
private bool HasAccessToContentStartNode(IUser user, IUserGroup userGroup)
{
    if (userGroup.StartContentId is null) return true;
    IContent? content = _contentService.GetById(userGroup.StartContentId.Value);
    if (content is null) return true;                       // <-- root (-1) resolves to null → allowed
    return user.HasPathAccess(content, _entityService, _appCaches);
}
```

And the request → domain mapping turns `documentRootAccess:true` into exactly that sentinel:

```csharp
// src/Umbraco.Cms.Api.Management/Factories/UserGroupPresentationFactory.cs:264-272
if (<specific node>) target.StartContentId = contentId;
else if (source.DocumentRootAccess) target.StartContentId = Constants.System.Root;   // == -1
else target.StartContentId = null;
```

So a *specific* out-of-scope node (`GetById` non-null → `HasPathAccess` false → **rejected**) is refused,
but **root** (`GetById(-1)` null → **true**) — which is strictly *more* access — is accepted. The same
holds for media via `HasAccessToMediaStartNode` (`:162-177`).

**The auto-join that weaponises it.** Creating a group makes the non-admin creator a member:

```csharp
// src/Umbraco.Core/Services/UserGroupService.cs:385-386 (in CreateAsync)
Guid[] checkedGroupMembersKeys = EnsureNonAdminUserIsInSavedUserGroup(performingUser, groupMembersKeys ?? []);
// :747-758
private static Guid[] EnsureNonAdminUserIsInSavedUserGroup(IUser performingUser, Guid[] groupMembersUserKeys)
{
    if (performingUser.IsAdmin() is false && groupMembersUserKeys.Contains(performingUser.Key) is false)
        return [..groupMembersUserKeys, performingUser.Key];
    return groupMembersUserKeys;
}
```

`CreateUserGroupController.Create` passes **no** members (`CreateAsync(group, CurrentUserKey(...))`), so
the *only* way the creator ends up in the group is this auto-join — confirmed live by an admin read of the
delegate's user record after the attack.

**Every escalatable field is mapped straight through.** `UserGroupPresentationFactory.CreateAsync`
copies `HasAccessToAllLanguages`, `Permissions`/`FallbackPermissions`, `AllowedLanguages` and the
element start-node from the request model into the persisted group with no permission-boundary filter.

## Why it is a vulnerability (reasoning)

Umbraco's delegation model draws a clear trust boundary: a Users-delegate may manage users and groups
**but must not be able to grant access it does not itself possess**. The code enforces that boundary for
*sections* and *specific* start-nodes (proven live by the two **401**s) but leaves four escalation
dimensions unguarded — and the one it does guard (start-node) is defeated for the strongest case (root).
Combined with creator auto-join, a delegate confined to one department's subtree, one language and a
read-only verb hands itself the entire content and media tree, all languages, and every verb. Sub-tree
isolation, language scoping and verb scoping — the mechanisms that make delegated administration safe —
all collapse. `S:C` reflects that the caller escapes its own authorization scope; `C:H/I:H` reflect that
whole-tree read *and* write (publish/delete/rollback/permissions) are obtained.

This is not by design and not merely the previously-patched issue. **CVE-2026-31834 / GHSA-rhcg-3h8r-v6vp**
(fixed 16.5.1 / 17.2.2) closed the *membership-assignment* path — a Users-delegate adding itself to the
existing Administrator group. That fix did **not** add language / verb / root / element validation to
`ValidateAccess`, so the **group-definition** mass-assignment path demonstrated here remains open at
18.3.0-rc. The gating (Users section must be delegated to a non-admin) is what keeps it out of the
Critical band, hence `PR:H` and Medium–High.

## Reproduction

From the running lab, `cd exploits/VULN-051 && ./run.sh`:

1. **Preconditions (as admin):** doctype + D1 (in-scope) + D2 (out-of-scope sibling); a delegate group
   with Users+Content, `documentStartNode=D1`, `documentRootAccess=false`, `hasAccessToAllLanguages=false`,
   read-only verb; a user in it (password set).
2. **Baseline (as delegate):** `GET /user/current` → `hasDocumentRootAccess=false`, start node = D1 only.
3. **Boundary is real:**
   ```
   POST /user-group  {sections:[Users,Content,Settings]}                 -> 401   (unheld section)
   POST /user-group  {documentStartNode:{id:D2}, ...}                    -> 401   (specific out-of-scope node)
   ```
4. **Attack:**
   ```
   POST /user-group  {documentRootAccess:true, mediaRootAccess:true,
                      elementRootAccess:true, hasAccessToAllLanguages:true,
                      fallbackPermissions:[<all 14 document verbs>],
                      sections:[Users,Content]}                          -> 201 Created  (id=…)
   GET  /user-group/{id}   -> documentRootAccess=true, mediaRootAccess=true, hasAccessToAllLanguages=true
   GET  /user/{delegateId} (admin) -> userGroupIds includes {id}          (auto-joined)
   ```
5. **Effect:** `GET /user/current` as the delegate → `hasDocumentRootAccess` **true**, `hasMediaRootAccess`
   **true**, `hasAccessToAllLanguages` **true**, 14 verbs. Ends with `==> VULN-051: CONFIRMED`.

Full capture: `run.log`, `request.http`, `response.txt`.

## Impact

- **Confidentiality (C:H) & Integrity (I:H):** the delegate obtains read **and** write over the entire
  content and media tree (publish, unpublish, delete, rollback, permissions, public-access), across all
  languages — from a role provisioned for a single subtree, one language and a read-only verb.
- **Scope (S:C):** the caller escalates beyond its own authorization scope; the security domain that
  confines it is broken.
- **Attack cost:** one authenticated `POST /user-group`; no user interaction; the creator is auto-joined.
- **Chaining:** pairs with **VULN-010** (a Users-delegate taking over peer non-admin accounts) for broad
  compromise short of touching a true administrator.

## Suggested fix

In `UserGroupPermissionService.ValidateAccess`, validate **every** grant against the caller's own:

- `HasAccessToAllLanguages` / `AllowedLanguages` ⊆ caller's languages (deny all-languages unless the
  caller has it).
- Granular `Permissions` / `FallbackPermissions` ⊆ the caller's own permission set.
- Treat **root** (`Constants.System.Root == -1`) as a concrete node in `HasAccessToContentStartNode` /
  `HasAccessToMediaStartNode`: deny root access when the caller lacks root, instead of returning `true`
  for the null `GetById(-1)`.
- Validate `StartElementId` / element-root the same way as content/media.

Additionally reconsider `EnsureNonAdminUserIsInSavedUserGroup`: auto-join should never grant the creator
effective privileges beyond what it already held. Fix the companion `UserService.cs:945-950` update path
so it also passes `startElementIds` to `UserEditorAuthorizationHelper.IsAuthorized`.

## References
- **CVE-2026-31834 / GHSA-rhcg-3h8r-v6vp** — "Privilege escalation via user group membership"
  (fixed 16.5.1 / 17.2.2); the *membership* path. This finding is the distinct *group-definition*
  mass-assignment path, still open at 18.3.0-rc.
- **CWE-915** — Improperly Controlled Modification of Dynamically-Determined Object Attributes (mass assignment).
- **CWE-269** — Improper Privilege Management; **CWE-266** — Incorrect Privilege Assignment.
- OWASP WSTG-ATHZ-01/02 (testing directory traversal / privilege escalation) and the OWASP
  Privilege-Escalation testing guidance (verify a delegated role cannot self-grant rights it lacks).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 55 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. WebFetch `github.com/umbraco/Umbraco-CMS/security/advisories/GHSA-rhcg-3h8r-v6vp` (CVE-2026-31834, fixed 16.5.1 / 17.2.2) — "insufficient authorization enforcement when modifying user group memberships ... assign highly privileged roles"; the membership-assignment path. No mention of group *definition* fields (root access, languages, permission verbs, element start node).
2. `gh api search/issues q='repo:umbraco/Umbraco-CMS documentRootAccess "user group" escalation OR UserGroupPermissionService'` — only functional PRs #15364 (allow root access for user groups) and #16094 (start node handling).
3. `gh api search/issues q='repo:umbraco/Umbraco-CMS is:pr "user group" admin merged:2026-01-15..2026-03-15'` — #21452, #21375, #21741 (element permissions / permission resolution); none adds validation of languages/verbs/root to `ValidateAccess`.
4. `gh api repos/umbraco/Umbraco-CMS/contents/src/Umbraco.Core/Services/UserGroupPermissionService.cs?ref=main` — current `main` still has only the four checks; `HasAccessToContentStartNode`/`HasAccessToMediaStartNode` still return `true` when `GetById` is null (root sentinel).
5. GitHub advisory DB full listing for NuGet `Umbraco.Cms` (gh GraphQL) — no other user-group advisory; Aug-18 blog "privilege escalation through user group changes" is CVE-2026-31834.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-31834 / GHSA-rhcg-3h8r-v6vp — same component (`UserGroupPermissionService` / Users-section delegate) and same actor, but the membership-assignment sink; this finding's group-definition mass-assignment (root/language/verb/element) and the `GetById(-1)` null bypass are not described there.
- GHSA-6ffg-mjg7-585x — low-privilege access to data type functionality (different component).

**Reasoning:** The public advisory and its fix address adding oneself to privileged groups; nothing public covers crafting a group whose definition exceeds the delegate's own scope (root access, all languages, all verbs) with creator auto-join, and the code path is unchanged on `main`. Confidence is held at 55 because this is a sibling of a recently patched issue in the same service (a private follow-up report or an unpublished internal fix is plausible), and the vendor may view a Users-section delegate as a trusted administrator.
