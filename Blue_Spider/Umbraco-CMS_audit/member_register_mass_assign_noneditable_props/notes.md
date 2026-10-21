# VULN-008 — Member self-registration mass-assignment (MemberCanEditProperty not enforced)

**Software**: Umbraco CMS
**Repository**: https://github.com/umbraco/Umbraco-CMS
**Affected version**: 18.3.0-rc (version.json; commit-pinned, no tagged release)
**Commit**: cee7d8981ab0fd18b4dc96449ae071edf1aaf21e
**Status**: CONFIRMED
**Severity (static)**: Medium (site-dependent; up to High) — CWE-915 mass assignment
**Validated at**: 2026-09-29

## Preconditions
- Admin (setup only — models a real site's config, not part of the attack):
  - creates a **member type** with a property `accountTier` whose `Visibility.MemberCanEdit = false`
    (a value the member is *not* allowed to edit — the class of field this bug lets you set);
  - creates a **template** that renders the stock *Register Member* form bound to that member type,
    attaches it to a **document type**, and creates + **publishes** a root page — i.e. exposes the
    public registration surface exactly as a real membership site does (the register snippet).
- The **attack itself is fully unauthenticated** (no backoffice session, no member session).
- All member-type / template / doctype / page / member names + the injected value carry a random suffix.

## Request
See `request.http`. The decisive request is an **unauthenticated** `POST` to the published page URL
carrying a harvested `ufprt` (Data-Protection route token) + antiforgery token, with the standard
register fields **plus an over-posted member property the form never rendered**:

```
registerModel.MemberProperties[0].Alias = accountTier          # MemberCanEdit=false
registerModel.MemberProperties[0].Value = PWNED-premium-<rnd>  # attacker-controlled
```

## Response
See `response.txt` / `run.log`:
- unauthenticated `GET /<page>` → **200** (registration form containing `ufprt`).
- unauthenticated `POST` registration → **302** (redirect to current page = `RegisterMemberAsync` succeeded).
- admin read-back `GET /umbraco/management/api/v1/member/{id}` → `values[]` contains
  `{ "alias": "accountTier", "value": "PWNED-premium-<rnd>" }` — the exact attacker value.

## Observation
Exactly matches the static finding. `UmbRegisterController.cs:156-160` writes any posted member
property whose alias merely *exists* on the type; it never calls `MemberCanEditProperty(alias)`, which
`UmbProfileController.cs:142-150` *does* apply on the profile-edit path. The register form's own field
list is irrelevant — the action model-binds the full `MemberProperties[]` list, so an over-posted entry
for a non-editable alias is persisted at sign-up. Public member registration **is reachable on this lab**
(via a published page rendering the Register-Member snippet).

## Side effects
- Per run creates (all random-suffixed, left in place for inspection): 1 member type, 1 template,
  1 document type, 1 published root document, 1 member.
- No modification of existing content or config.

## Research & references
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes (mass assignment).
- OWASP Mass Assignment Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- Contrast is intra-repo: the *profile* path already applies the correct `MemberCanEditProperty` gate,
  proving the intended contract and that the register path's omission is a defect, not a design choice.

## If FAILED
n/a — CONFIRMED. If a future lab has no front-end (no published page renders), the exploit still
confirms the source asymmetry statically and falls back to NEEDS_MANUAL with this checklist:
1. Expose the Register-Member snippet on a published template (as the setup here does).
2. Unauthenticated, GET the page; harvest `ufprt` + `__RequestVerificationToken` + antiforgery cookie.
3. POST the register form adding `registerModel.MemberProperties[0].Alias=<non-editable alias>` and
   `...Value=<x>`.
4. As admin, `GET /umbraco/management/api/v1/member/{id}` and confirm the non-editable property == `<x>`.
