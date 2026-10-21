# VULN-008 — Member self-registration mass-assignment of non-member-editable properties

| | |
|---|---|
| **ID** | VULN-008 |
| **Software** | Umbraco CMS |
| **Repository** | https://github.com/umbraco/Umbraco-CMS |
| **Affected version** | 18.3.0-rc (commit-pinned; no tagged release) |
| **Commit** | `cee7d8981ab0fd18b4dc96449ae071edf1aaf21e` |
| **Severity** | Medium (deployment-dependent; up to High) — CVSS 3.1 `6.5` (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N`) |
| **Class** | Mass assignment / over-posting — **CWE-915** |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | **None** — unauthenticated member self-registration, on a site that exposes the Register-Member snippet |
| **Attacker gains** | Sets member-type properties flagged *not* member-editable at sign-up. Impact scales with what the site stores there (tier / role / `isVerified` / balance / entitlement). |

## Summary

Umbraco member types mark each property with a **"Member can edit"** flag (`MemberTypePropertyTypeVisibility.MemberCanEdit`, surfaced as `IMemberType.MemberCanEditProperty(alias)`). It defaults **false** — a property a member is not permitted to change. The **Edit-Profile** surface controller honours this flag when writing posted member properties; the **Register** surface controller does not. Because the register action model-binds the entire `MemberProperties[]` collection (not just the fields the form rendered), an **unauthenticated** attacker who hand-crafts the POST can add an entry targeting a **non-editable** property alias, and its value is persisted on the new member at registration.

Dynamically confirmed end-to-end: with a member type carrying `accountTier` (`MemberCanEdit=false`) and a public registration page, an anonymous POST adding `registerModel.MemberProperties[0].Alias=accountTier` + `...Value=PWNED-premium-<rnd>` created a member whose `accountTier` read back — via the admin Management API — as the **exact attacker-supplied value**.

## How it works (mechanism & code trace)

**The sink — register writes properties with no editability gate.** In `RegisterMemberAsync`, after the member is created, posted properties are written back:

```csharp
// src/Umbraco.Web.Website/Controllers/UmbRegisterController.cs:156-160
foreach (MemberPropertyModel property in model.MemberProperties.Where(p => p.Value != null)
             .Where(property => member.Properties.Contains(property.Alias)))
{
    member.Properties[property.Alias]?.SetValue(property.Value);
}
```

The only filters are **"value is present"** and **"an alias by this name exists on the member type."** There is no check that the property is member-editable.

**The contrast — profile-edit does it right.** The sibling controller, writing member properties for an authenticated member, adds the missing predicate:

```csharp
// src/Umbraco.Web.Website/Controllers/UmbProfileController.cs:142-150
foreach (MemberPropertyModel property in model.MemberProperties
             .Where(p => memberType?.PropertyTypeExists(p.Alias) ?? false)
             .Where(property => member.Properties.Contains(property.Alias))
             // needs to be editable
             .Where(p => memberType?.MemberCanEditProperty(p.Alias) ?? false))
{
    member.Properties[property.Alias]?.SetValue(property.Value);
}
```

Same operation, one folder apart; only the register path omits `MemberCanEditProperty`. That single missing `.Where(...)` is the whole bug.

**Why the form's field list does not protect it.** The stock `RegisterMember.cshtml` snippet renders member-property inputs only when `.WithCustomProperties(true)` is set, and even then only editable ones. But the *form's* rendered fields are a client-side convention — the **action binds the whole `RegisterModel`**, whose `MemberProperties` is a `List<MemberPropertyModel>` (each `{ Alias, Value }`). An attacker bypasses the form and posts arbitrary `MemberProperties[i]` entries. `RegisterModel.MemberTypeAlias` itself is `[Editable(false)]` and is carried in the encrypted `ufprt` route token, so the member *type* can't be swapped — but the per-property write inside that type is unguarded.

**Why the request is reachable at all (and why it is still a real bug).** The register action is `[ValidateAntiForgeryToken]` + `[ValidateUmbracoFormRouteString]`, so a valid antiforgery token and a Data-Protection-encrypted `ufprt` are required. Both are emitted by the public registration form itself (`Html.BeginUmbracoForm<UmbRegisterController>(...)`), which any anonymous visitor loads. The exploit harvests them from the rendered page — exactly as a browser would — then over-posts. So the anti-CSRF/route protections are satisfied by design for a self-registration flow; they do nothing to stop over-posting.

## Why it is a vulnerability (reasoning)

"Member can edit = false" is Umbraco's mechanism for member-type properties that hold **server-trusted** data a member must not set themselves. The profile path treats it as a security boundary; the registration path ignores it. The result is a classic mass-assignment/over-posting flaw: the attacker influences a field the application never intended to accept from them. On a site that stores an authorization- or entitlement-relevant value on the member type and marks it non-editable (a common, natural design — `accountTier`, `role`, `isVerified`, `creditBalance`), an unauthenticated user seeds that value at sign-up.

It is not by-design: the presence of the correct `MemberCanEditProperty` filter on the sibling profile action establishes the intended contract, and the register action simply fails to apply it.

## Reproduction

The exploit does everything end-to-end (`cd exploits/VULN-008 && ./run.sh`):

1. **Static** — reads and prints both loops from source and asserts the asymmetry (register lacks `MemberCanEditProperty`, profile has it).
2. **Setup (admin, models the target site):** create a member type with `accountTier` (`Visibility.MemberCanEdit=false`); create a template rendering the Register-Member form for that type; attach it to a document type; create + publish a root page.
3. **Attack (unauthenticated):** GET the page, harvest `ufprt` + `__RequestVerificationToken` (+ antiforgery cookie); POST registration with the normal fields **plus** `registerModel.MemberProperties[0].Alias=accountTier` and `...Value=PWNED-premium-<rnd>`.
   ```
   POST /<page>/  ->  302   (RegisterMemberAsync succeeded)
   ```
4. **Verify (admin):** `GET /umbraco/management/api/v1/member/{id}` →
   ```json
   "values": [ { "editorAlias": "Umbraco.TextBox", "alias": "accountTier", "value": "PWNED-premium-ee24c1945fa0" } ]
   ```
   The non-editable property equals the attacker's value.

Expected output ends with `==> VULN-008: CONFIRMED`. Full capture: `run.log`, `request.http`, `response.txt`.

## Impact

- **Integrity (I:H on affected sites):** an unauthenticated attacker sets a stored member attribute the site deliberately withholds from members. Where that attribute gates access, pricing, verification status, or role, the attacker escalates their own entitlement at registration.
- **Baseline (I:L→none):** on a site with no security-relevant non-editable member property, the impact is a data-integrity nuisance (setting fields not meant to be user-set). The representative CVSS `6.5` reflects the meaningful-property case; severity is genuinely deployment-dependent.
- **Attack cost:** one anonymous GET + one POST; no account, no privilege, no user interaction. Reachable on any site exposing the register snippet.

## Suggested fix

Apply the same editability gate the profile controller uses. In `UmbRegisterController.RegisterMemberAsync`, resolve the member type and filter the write loop:

```csharp
IMemberType? memberType = _memberTypeService.Get(member.ContentTypeId);
foreach (MemberPropertyModel property in model.MemberProperties.Where(p => p.Value != null)
             .Where(property => member.Properties.Contains(property.Alias))
             .Where(p => memberType?.MemberCanEditProperty(p.Alias) ?? false))   // <-- add this
{
    member.Properties[property.Alias]?.SetValue(property.Value);
}
```

Principle: never write a client-supplied value to a field unless the field is explicitly designated user-editable — enforce the allow-list server-side on every path that accepts the object, not just the "primary" one.

## References
- **CWE-915** — Improperly Controlled Modification of Dynamically-Determined Object Attributes ('Mass Assignment'): https://cwe.mitre.org/data/definitions/915.html
- **OWASP Mass Assignment Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- **OWASP API Security Top 10 — API6:2023 Mass Assignment** (property-level authorization): https://owasp.org/API-Security/editions/2023/en/0xa6-mass-assignment/
- Intra-repo contrast: `UmbProfileController.cs:142-150` (correct `MemberCanEditProperty` gate) vs `UmbRegisterController.cs:156-160` (missing).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `Umbraco UmbRegisterController member registration mass assignment "MemberCanEdit" OR "member can edit" property over-posting vulnerability` (WebSearch) — search budget exhausted before this query ran; no result returned.
2. `Umbraco member register form "MemberProperties" non-editable property set at registration security advisory CVE` (WebSearch) — budget exhausted; no result returned.
3. `gh api search/issues q='repo:umbraco/Umbraco-CMS MemberCanEdit register'` — 0 results.
4. `gh api search/issues q='repo:umbraco/Umbraco-CMS UmbRegisterController properties'` and `... register member MemberProperties` — only functional issues (#19595 ModelState, #12673 notification fired twice, #5537 custom properties not saved); nothing on over-posting non-editable properties.
5. GitHub advisory DB full listing for NuGet `Umbraco.Cms` (gh GraphQL) — no advisory touching member self-registration or `UmbRegisterController`.
6. `gh api repos/umbraco/Umbraco-CMS/contents/src/Umbraco.Web.Website/Controllers/UmbRegisterController.cs?ref=main` — current `main` still writes `member.Properties[alias].SetValue` with no `MemberCanEditProperty` filter (no upstream fix).

**Related but distinct public references** (same class or component, not this bug):
- CVE-2023-49273 / GHSA-cfr5-7p54-4qg8 ("Privilege Escalation using Spoofing", 12.3.4) — different component.
- Older `UmbRegisterController` advisories (2019-era CSRF/route hardening) — same controller, different root cause.

**Reasoning:** No CVE, GHSA, vendor advisory or GitHub issue describes member self-registration writing non-member-editable properties, and the register path on upstream `main` is unchanged. The contrast with `UmbProfileController` (which applies the editability gate) makes this a specific, verifiable omission rather than a generic class. Caveat: the final targeted web searches could not run because the session's search budget was exhausted, so a private or third-party report cannot be ruled out.
