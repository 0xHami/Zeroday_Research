# VULN-019 — `item/member[/search]` omits the Members-section check → cross-section member PII enumeration

| | |
|---|---|
| **ID** | VULN-019 |
| **Software** | Umbraco CMS |
| **Repository** | https://github.com/umbraco/Umbraco-CMS |
| **Affected version** | 18.3.0-rc (commit-pinned; no tagged release) |
| **Commit** | `cee7d8981ab0fd18b4dc96449ae071edf1aaf21e` |
| **Severity** | Medium — CVSS 3.1 `4.3` (`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`) |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Any authenticated backoffice user with **no** Members section — the default **Writer**/**Editor**/**Translator** groups. Obtained here by the admin creating a default Writer (the normal invite flow). |
| **Attacker gains** | Enumerate every front-end member's display name + member type + kind, and the total count, from a token the Members section is meant to exclude. |

## Summary

Umbraco gates the front-end **member** surface behind the Members section: every controller under `MemberControllerBase` carries `[Authorize(Policy = SectionAccessMembers)]`. The member **item** endpoints — meant only to hydrate backoffice pickers — derive instead from `MemberItemControllerBase`, which inherits only the `ManagementApiControllerBase` floor (`BackOfficeAccess`) and **forgets to re-apply `SectionAccessMembers`**. Any authenticated backoffice user can therefore read a member's display name + member type by GUID (`GET /item/member?id=`) and **bulk-enumerate the whole membership** (`GET /item/member/search?query=&take=…`), crossing the Members-section boundary.

Dynamically confirmed: a default **Writer** (Content + Library only) receives **403 Forbidden** on `GET /member/{key}` yet **200 OK** with the member's display name on `GET /item/member?id={key}`, and enumerates the membership (`total=3`) via `item/member/search`.

## How it works (mechanism & code trace)

**The floor.** All member item controllers derive from a base with no section policy:

```csharp
// src/Umbraco.Cms.Api.Management/Controllers/Member/Item/MemberItemControllerBase.cs:12-16
[VersionedApiBackOfficeRoute($"{Constants.Web.RoutePath.Item}/{Constants.UdiEntityType.Member}")]
[ApiExplorerSettings(GroupName = nameof(Constants.UdiEntityType.Member))]
public class MemberItemControllerBase : ManagementApiControllerBase   // <-- no [Authorize(SectionAccessMembers)]
{
}
```

`ManagementApiControllerBase` only requires `BackOfficeAccess` (any authenticated backoffice user).

**The sinks — no section check.** Both actions map member entities straight to the response model:

```csharp
// Controllers/Member/Item/ItemMemberItemController.cs  — GET item/member?id=
IEnumerable<MemberItemResponseModel> responseModels =
    await _memberPresentationService.CreateItemResponseModelsAsync(ids);   // by GUID, no section/per-node check
return Ok(responseModels);

// Controllers/Member/Item/SearchMemberItemController.cs — GET item/member/search?query=&take=
PagedModel<IEntitySlim> searchResult = await _indexedEntitySearchService.SearchAsync(
    UmbracoObjectTypes.Member, query, null, allowedMemberTypes, false, "*", skip, take);
```

The response model carries member identity fields:

```csharp
// ViewModels/Member/Item/MemberItemResponseModel.cs
public MemberTypeReferenceResponseModel MemberType { get; set; }
public IEnumerable<VariantItemResponseModel> Variants { get; set; }   // -> Name (display name)
public MemberKind Kind { get; set; }
```

**The exact defect — contrast with the real member surface,** which *does* gate the section:

```csharp
// Controllers/Member/MemberControllerBase.cs:21
[Authorize(Policy = AuthorizationPolicies.SectionAccessMembers)]
public class MemberControllerBase : ContentControllerBase
```

`GET /member/{key}` (under this base) returns 403 for a non-Members user — proven live. `item/member[/search]` simply omits the same attribute, so it runs at the floor.

**Why the framework doesn't save it.** Section authorization here is attribute-driven per controller; nothing enforces it globally on item bases, so an omission is silently insecure.

## Why it is a vulnerability (reasoning)

The Members section is Umbraco's boundary for front-end member data — an install may hold thousands of customer/member records, and a Content editor or Translator is not meant to see them. The member item endpoints hand any logged-in backoffice user the members' names, types, and count, and the search variant turns it into full enumeration. This is **Broken Object Property Level Authorization / excessive data exposure** (OWASP API3:2023): the data is minimal (no email/password), but member *existence + identity* is precisely what the Members section is designed to withhold, and it is exposed across that boundary.

It is not by-design: the item-endpoint contract (below) forbids exactly this, and the real member controllers apply `SectionAccessMembers` — the item base just fails to.

**The documented contract it violates** (`src/Umbraco.Cms.Api.Management/CLAUDE.md` §1 rule 2, *"Do not add data to item endpoints"*):

> Item endpoints … sit on `ManagementApiControllerBase` with only `BackOfficeAccess` — deliberately looser authorization … **Never widen an item response model with fields that require stricter authorization to see (state, permissions, sensitive/computed data) — that leaks information past the resource's real authorization boundary.**

Member names/types are exactly such data — the Members section is their real authorization boundary.

## Reproduction

From a clean lab, the exploit does everything end-to-end (`cd exploits/VULN-019 && ./run.sh`):

1. **Preconditions (as admin):** create a member with a random display name (`POST /member`, built-in Member type); create a default Writer (Content + Library only) and set its password.
2. **Baseline (boundary is real):** as the Writer,
   ```
   GET /umbraco/management/api/v1/member/{memberKey}   ->  403 Forbidden
   ```
3. **Attack (by-GUID leak):**
   ```
   GET /umbraco/management/api/v1/item/member?id={memberKey}   ->  200
   [{ "memberType": {...}, "variants": [{ "name": "SecretMember_2f0affc4" }], "kind": "Default", ... }]
   ```
4. **Attack (bulk enumeration, uncapped take):**
   ```
   GET /umbraco/management/api/v1/item/member/search?query=Secret&take=100000   ->  200
   total = 3   names: ["SecretMember_6fec41cc", "SecretMember_9a70b886", "SecretMember_2f0affc4"]
   ```

Output ends with `==> VULN-019: CONFIRMED`. Full capture: `run.log`, `request.http`, `response.txt`.

## Impact

- **Confidentiality (C:L):** enumerate all members' display names, member types and count from a default low-privilege role that holds no Members access. Front-end member PII disclosed across the section boundary.
- **Chaining:** a known member roster + **VULN-026** (no member/backoffice login rate-limit) enables targeted credential attacks against the member login. It also sharpens social-engineering and account-takeover targeting.
- **Bounded:** no email, password, or account-state leak (those remain on the section-gated member endpoints and the `IMemberIndexAuthorizer`-gated Lucene fields).

## Suggested fix

Add `[Authorize(Policy = AuthorizationPolicies.SectionAccessMembers)]` to `MemberItemControllerBase` (or a dedicated, minimal member-picker policy if pickers must remain reachable by adjacent roles). Keep member identity on the section-gated `MemberResponseModel` / batch endpoint that already enforces the Members section.

## References
- OWASP API Security Top 10 — **API3:2023 Broken Object Property Level Authorization** (excessive data exposure): https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- **GHSA-w5q3-9wf8-43gg** — "Insufficient authorization on Management API search endpoints" (fixed 17.6.2 / 18.1.1); same authorization-omission class, confirmed **not** applied to `item/member[/search]` at 18.3.0-rc.
- **CVE-2024-43377 / GHSA-hrww-x3fq-xcvh** — "few endpoints … not protected by a specific section, just authentication" (fixed 14.1.2); the actively-patched class this belongs to.
- Intended contract: `src/Umbraco.Cms.Api.Management/CLAUDE.md` §1 rule 2 ("Do not add data to item endpoints").

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. WebFetch `github.com/umbraco/Umbraco-CMS/security/advisories/GHSA-w5q3-9wf8-43gg` — covers Management API *search/index* (Examine searcher/indexer) routes only; `item/member` not named; fix commit `4558b7e4` touches only Searcher/Indexer/PublishedCache controllers.
2. WebFetch `github.com/umbraco/Umbraco-CMS/security/advisories/GHSA-hrww-x3fq-xcvh` (CVE-2024-43377) — "few endpoints not protected by a specific section" (14.1.2); endpoints unnamed, reporter concern was member tokens reaching backoffice endpoints, not cross-section member PII.
3. `gh api search/issues q='repo:umbraco/Umbraco-CMS MemberItemControllerBase OR "item/member"'` — only functional items; #23979 "Memberpicker returns 403 when user has no access to Member section" (17.7, open) shows the vendor currently *expects* non-Members editors to use the member picker, i.e. the opposite direction of this finding.
4. `gh api search/issues q='repo:umbraco/Umbraco-CMS is:pr SectionAccessMembers'` — only PR #9902 (2021, password change); nothing adding the policy to item controllers.
5. `gh api repos/umbraco/Umbraco-CMS/contents/.../Member/Item/MemberItemControllerBase.cs?ref=main` — still `: ManagementApiControllerBase` with no `[Authorize]` on current `main`.
6. GitHub advisory DB full listing for NuGet `Umbraco.Cms` — Oct-6-2026 and Aug-18-2026 advisories reviewed; none names member item endpoints.

**Related but distinct public references** (same class or component, not this bug):
- GHSA-w5q3-9wf8-43gg — same "missing section check → member data" class, but for the Examine searcher/indexer routes.
- CVE-2024-43377 / GHSA-hrww-x3fq-xcvh — same class (section-less endpoints), different endpoints and version.
- Issue #23979 — functional report that implies the member picker is intended to work for non-Members users (a likely vendor by-design response).

**Reasoning:** No public advisory or issue names `item/member` / `item/member/search` or the missing `SectionAccessMembers` on `MemberItemControllerBase`, and the code is unchanged upstream. The class (Management API endpoints lacking a section check) is heavily patched and noisy, and the vendor may argue picker hydration is intended for all backoffice users, which lowers confidence; the uncapped enumeration of the whole membership is the strongest angle.
