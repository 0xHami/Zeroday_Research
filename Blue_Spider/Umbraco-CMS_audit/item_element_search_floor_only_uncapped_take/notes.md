# VULN-048 — item/element[/search] floor-only + uncapped take → cross-section element leak/enumeration

**Software**: Umbraco CMS
**Repository**: https://github.com/umbraco/Umbraco-CMS
**Affected version**: 18.3.0-rc (version.json; commit-pinned, no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium — CVSS 3.1 `5.3` (`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`)
**Target commit**: cee7d8981ab0fd18b4dc96449ae071edf1aaf21e
**Validated at**: 2026-09-29

## Preconditions
- Admin creates an element-type (`isElement=true`, `allowedInLibrary=true`) and an element instance at the library root with a random name, via the Library-gated `POST /element`.
- Admin creates a default **Translator** (groups = Translation section only — no Library) and sets its password; the exploit logs in as that Translator.
- All names/emails carry a random suffix.

## Request
See `request.http`. Sent as the Translator:
- ATTACK by-GUID: `GET /umbraco/management/api/v1/item/element?id={elementKey}`
- ATTACK enumeration (uncapped take): `GET /umbraco/management/api/v1/item/element/search?query=Secret&take=1000000`
- CONTRAST: `GET /umbraco/management/api/v1/element/{elementKey}` → 403.

## Response
See `response.txt` / `run.log`:
- `GET /element/{key}` (real, `[Authorize(TreeAccessElements)]` = Library + per-node `ElementPermissionByResource`) → **403 Forbidden**.
- `GET /item/element?id={key}` → **200** with `isTrashed=false`, `parent`, `hasChildren`, `documentType`, `variants[].state = "Draft"`, `variants[].name = "SecretElement_…"`.
- `GET /item/element/search?query=Secret&take=1000000` → **200** (take **not** clamped), `total=3`, element names enumerated.

## Observation
Matches the static finding. `ElementItemControllerBase` is floor-only and `SearchElementItemController.Search(query, skip=0, take=100)` never clamps `take`. A Translator the element API 403s reads any element's publish `State`/`IsTrashed`/tree metadata by GUID and dumps the element set in one request. This is the strongest item-endpoint leak in the batch because it bypasses the per-node `ElementPermissionByResource` check, not just a section.

## Side effects
- Created 1 element-type + 1 element + 1 Translator user per run (random-suffixed). Elements persist and accumulate in search across reruns; harmless.
- Elements are only creatable when the element-type has `AllowedInLibrary=true` (ElementEditingService.cs:111) — the exploit sets it.

## Research & references
- OWASP API Security Top 10 — **API3:2023 Broken Object Property Level Authorization** (excessive data exposure): https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- **GHSA-w5q3-9wf8-43gg** — "Insufficient authorization on Management API search endpoints" (fixed 18.1.1); this is the closest batch match. Source-confirmed the `item/element` base is still floor-only and its search `take` uncapped at 18.3.0-rc — the 18.1.1 fix did not cover it.

## If FAILED
n/a — CONFIRMED.
