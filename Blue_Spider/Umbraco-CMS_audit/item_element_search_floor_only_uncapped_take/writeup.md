# VULN-048 — `item/element[/search]` is floor-only with an uncapped `take` → cross-section element disclosure + full enumeration

| | |
|---|---|
| **ID** | VULN-048 |
| **Software** | Umbraco CMS |
| **Repository** | https://github.com/umbraco/Umbraco-CMS |
| **Affected version** | 18.3.0-rc (commit-pinned; no tagged release) |
| **Commit** | `cee7d8981ab0fd18b4dc96449ae071edf1aaf21e` |
| **Severity** | Medium — CVSS 3.1 `5.3` (`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`) |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Any authenticated backoffice user — including one with **no** Library section (a default **Translator**). |
| **Attacker gains** | Read any element's publish `State` / `IsTrashed` / tree metadata by GUID, and dump the entire element set in a single request — bypassing the per-node `ElementPermissionByResource` check the real element API enforces. |

## Summary

Umbraco's real element read (`ByKeyElementController`) sits behind **two** tiers: the class-level section policy `[Authorize(TreeAccessElements)]` (= the **Library** application) **and** an in-action per-node check `AuthorizeResourceAsync(ElementPermissionResource.WithKeys(ActionElementBrowse, id), ElementPermissionByResource)`. The element **item** endpoints derive from `ElementItemControllerBase`, which inherits only the `BackOfficeAccess` floor and applies **neither**. On top of that, `SearchElementItemController.Search(query, skip = 0, take = 100)` never clamps `take`. So any authenticated backoffice user — including one with no Library section at all — reads an element's publish state / trashed flag / tree position by GUID (`GET /item/element?id=`) and enumerates the whole element set in one request (`GET /item/element/search?query=&take=1000000`).

Dynamically confirmed: a default **Translator** (Translation section only) receives **403 Forbidden** on `GET /element/{key}` yet **200 OK** with `state="Draft"` / `isTrashed` / tree metadata on `GET /item/element?id={key}`, and enumerates elements (`total=3`) with `take=1000000` accepted uncapped.

## How it works (mechanism & code trace)

**The floor.** The element item base has no section policy:

```csharp
// src/Umbraco.Cms.Api.Management/Controllers/Element/Item/ElementItemControllerBase.cs:12
[VersionedApiBackOfficeRoute($"{Constants.Web.RoutePath.Item}/{Constants.UdiEntityType.Element}")]
public class ElementItemControllerBase : ManagementApiControllerBase;   // <-- BackOfficeAccess floor only
```

**The sinks.** By-GUID read and the uncapped search:

```csharp
// Controllers/Element/Item/ItemElementItemController.cs  — GET item/element?id=
IEnumerable<IElementEntitySlim> elements = _entityService
    .GetAll(UmbracoObjectTypes.Element, ids.ToArray()).OfType<IElementEntitySlim>();
// -> _elementPresentationFactory.CreateItemResponseModelAsync (no section / per-node check)

// Controllers/Element/Item/SearchElementItemController.cs:51
public async Task<IActionResult> Search(CancellationToken ct, string query, int skip = 0, int take = 100)
{
    PagedModel<IEntitySlim> searchResult =
        _entitySearchService.Search(UmbracoObjectTypes.Element, query, skip, take);   // take is NEVER clamped
    ...
}
```

The response model was widened with authorization-sensitive fields:

```csharp
// ViewModels/Element/Item/ElementItemResponseModel.cs
public bool IsTrashed { get; set; }
public ReferenceByIdModel? Parent { get; set; }
public bool HasChildren { get; set; }
public DocumentTypeReferenceResponseModel DocumentType { get; set; }
public IEnumerable<ElementVariantItemResponseModel> Variants { get; set; }   // -> per-variant State + Name
```

**The exact defect — contrast with the sibling that does it right.** The real read enforces both tiers:

```csharp
// Controllers/Element/ElementControllerBase.cs:18-21
[VersionedApiBackOfficeRoute(Constants.UdiEntityType.Element)]
[Authorize(Policy = AuthorizationPolicies.TreeAccessElements)]     // section = Library
public class ElementControllerBase : ContentControllerBase

// Controllers/Element/ByKeyElementController.cs:60
AuthorizationResult authorizationResult = await _authorizationService.AuthorizeResourceAsync(
    User,
    ElementPermissionResource.WithKeys(ActionElementBrowse.ActionLetter, id),   // per-node
    AuthorizationPolicies.ElementPermissionByResource);
if (!authorizationResult.Succeeded) { return Forbidden(); }
```

`TreeAccessElements` maps to the **Library** application (`DependencyInjection/BackOfficeAuthPolicyBuilderExtensions.cs:108` → `AddAllowedApplicationsPolicy(TreeAccessElements, Constants.Applications.Library)`). The item base omits both the section attribute and the per-node call — the whole bug.

## Why it is a vulnerability (reasoning)

This is the strongest item-endpoint leak in the batch because it bypasses the **per-node** `ElementPermissionByResource` check, not merely a section: even a Library-section user confined to a subtree would read out-of-scope elements, and a Translator with no Library section at all reads them anyway. The uncapped `take` turns the read into a one-request dump of the entire element set (a resource/enumeration amplifier). Classic **Broken Object Property Level Authorization** (OWASP API3:2023): the section floor is enforced, the object/property authorization is not.

Not by-design: the sibling `ByKeyElementController` in the same domain shows the intended contract (section + per-node), and the item base fails to apply it. It also violates the documented item-endpoint rule:

> **Never widen an item response model with fields that require stricter authorization to see (state, permissions, sensitive/computed data) — that leaks information past the resource's real authorization boundary.** — `src/Umbraco.Cms.Api.Management/CLAUDE.md` §1 rule 2

`IsTrashed` and publish `State` are exactly such fields.

## Reproduction

From a clean lab (`cd exploits/VULN-048 && ./run.sh`):

1. **Preconditions (as admin):** create an element-type with `isElement=true` **and `allowedInLibrary=true`** (required by `ElementEditingService.cs:111`), then an element at the library root with a random name (`POST /element`); create a default Translator and set its password.
2. **Baseline (boundary is real):** as the Translator,
   ```
   GET /umbraco/management/api/v1/element/{elementKey}   ->  403 Forbidden
   ```
3. **Attack (by-GUID leak):**
   ```
   GET /umbraco/management/api/v1/item/element?id={elementKey}   ->  200
   [{ "isTrashed": false, "parent": null, "hasChildren": false, "documentType": {...},
      "variants": [{ "state": "Draft", "name": "SecretElement_03a0368b" }] }]
   ```
4. **Attack (bulk enumeration, uncapped take):**
   ```
   GET /umbraco/management/api/v1/item/element/search?query=Secret&take=1000000   ->  200   (take NOT clamped)
   total = 3   names: ["SecretElement_01386693", "SecretElement_03a0368b", "SecretElement_6fec41cc"]
   ```

Output ends with `==> VULN-048: CONFIRMED`. Full capture: `run.log`, `request.http`, `response.txt`.

## Impact

- **Confidentiality (C:L):** any backoffice user reads every element's publish/trash state, document type and tree position, and enumerates the full element set — regardless of section or start-node scope. Defeats both the Library-section boundary and the per-node element isolation.
- **Availability angle:** the uncapped `take` lets a single request request an arbitrarily large page (resource pressure on large installs); scored conservatively as `A:N` since the primary demonstrated impact is disclosure.
- **Bounded:** metadata/state only — no element **property values** are returned by the item model (those need the section+per-node `ByKey` read).

## Suggested fix

Two changes: (1) gate `ElementItemControllerBase` behind `TreeAccessElements` (Library) and, for parity with the real read, resolve each element and apply the per-node `ElementPermissionByResource` check (or drop `IsTrashed`/`State`/tree fields from the item model and move them to the section+per-node detail/batch endpoint); (2) **clamp `take`** on `SearchElementItemController.Search` to a sane maximum. Apply the same to any other `item/*` search action lacking a cap.

## References
- OWASP API Security Top 10 — **API3:2023 Broken Object Property Level Authorization** (excessive data exposure): https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- OWASP WSTG **WSTG-ATHZ-04** (IDOR/BOLA).
- **GHSA-w5q3-9wf8-43gg** — "Insufficient authorization on Management API search endpoints" (fixed 18.1.1); the closest batch match. Source-confirmed the `item/element` base is still floor-only and its search `take` uncapped at 18.3.0-rc.
- Intended contract: `src/Umbraco.Cms.Api.Management/CLAUDE.md` §1 rule 2 ("Do not add data to item endpoints").

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. WebFetch `github.com/umbraco/Umbraco-CMS/security/advisories/GHSA-w5q3-9wf8-43gg` and fix commit `4558b7e4` — scoped to Examine searcher/indexer routes; `item/element` not touched.
2. `gh api search/issues q='repo:umbraco/Umbraco-CMS ElementItemControllerBase OR "item/element"'` — 306 hits, all functional (pickers, trees, Elements feature work); none about authorization of element item endpoints or an uncapped `take`.
3. `gh api repos/umbraco/Umbraco-CMS/contents/.../Element/Item/ElementItemControllerBase.cs?ref=main` and `.../SearchElementItemController.cs?ref=main` — still `: ManagementApiControllerBase;` with no `[Authorize]`, and `take` still unclamped on current `main`.
4. GitHub advisory DB full listing for NuGet `Umbraco.Cms` (gh GraphQL) — Oct-6-2026 advisories (document versions, media delete, SignalR, upload) and Aug-18-2026 advisories reviewed; none names element item endpoints.
5. `gh api search/issues q='repo:umbraco/Umbraco-CMS "document-version" OR DocumentVersion authorization start node'` — found PR #23555 (SignalR events filtered by start node) and #21375 (element start-node permissions), confirming the vendor treats element start-node scoping as a boundary, but nothing on item endpoints.

**Related but distinct public references** (same class or component, not this bug):
- GHSA-w5jr-cmfx-544x — document-version endpoints skipping the per-node check (Oct 2026); same "section floor without per-node check" class, different component.
- GHSA-w5q3-9wf8-43gg — search/index routes without section check; different component.
- CVE-2024-43377 / GHSA-hrww-x3fq-xcvh — generic section-less endpoints (14.1.2).

**Reasoning:** Elements/Library are a new (v18) feature and no public reference names `item/element[/search]`, the missing `TreeAccessElements`/`ElementPermissionByResource` checks, or the unclamped `take`; upstream `main` is unchanged. Confidence is moderate because item endpoints are documented as deliberately looser and the vendor may deem state/trash metadata acceptable to expose, and the class is being patched frequently (a parallel private report is plausible).
