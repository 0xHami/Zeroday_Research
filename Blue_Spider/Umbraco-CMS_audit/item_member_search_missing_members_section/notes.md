# VULN-019 — item/member[/search] floor-only → cross-section member PII enumeration

**Software**: Umbraco CMS
**Repository**: https://github.com/umbraco/Umbraco-CMS
**Affected version**: 18.3.0-rc (version.json; commit-pinned, no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium — CVSS 3.1 `4.3` (`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`)
**Target commit**: cee7d8981ab0fd18b4dc96449ae071edf1aaf21e
**Validated at**: 2026-09-29

## Preconditions
- Admin creates a front-end member (built-in "Member" type `d59be02f-1df9-4228-aa1e-01917d806cda`) with a random display name via the Members-gated `POST /member`.
- Admin creates a default **Writer** (groups = Content + Library only — no Members section) and sets its password; the exploit logs in as that Writer.
- All names/emails carry a random suffix.

## Request
See `request.http`. Sent as the Writer:
- ATTACK by-GUID: `GET /umbraco/management/api/v1/item/member?id={memberKey}`
- ATTACK enumeration: `GET /umbraco/management/api/v1/item/member/search?query=Secret&take=100000`
- CONTRAST: `GET /umbraco/management/api/v1/member/{memberKey}` → 403.

## Response
See `response.txt` / `run.log`:
- `GET /member/{key}` (real, `SectionAccessMembers`) → **403 Forbidden**.
- `GET /item/member?id={key}` → **200** with `variants[].name = "SecretMember_…"`, `memberType`, `kind`.
- `GET /item/member/search?query=Secret&take=100000` → **200**, `total=3`, member display names enumerated.

## Observation
Matches the static finding. `MemberItemControllerBase` omits `[Authorize(SectionAccessMembers)]`, so a Writer with no Members access reads member display names + types by GUID and bulk-enumerates the membership — data the Members section is designed to gate. No email/password is exposed (those stay on the section-gated endpoints).

## Side effects
- Created 1 member + 1 Writer user per run (random-suffixed). The Lucene `MembersIndex` accumulates the created members across runs (this is why enumeration `total` grows over reruns); harmless.

## Research & references
- OWASP API Security Top 10 — **API3:2023 Broken Object Property Level Authorization** (excessive data exposure): https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- **GHSA-w5q3-9wf8-43gg** — "Insufficient authorization on Management API search endpoints" (fixed 17.6.2 / 18.1.1); same authorization-omission class; the fix did not cover `item/member[/search]`, source-confirmed floor-only at 18.3.0-rc.
- Adjacent: **CVE-2024-43377 / GHSA-hrww-x3fq-xcvh** ("few endpoints … not protected by a specific section, just authentication", fixed 14.1.2).

## If FAILED
n/a — CONFIRMED. (The by-GUID leak is deterministic; the search enumeration retries to accommodate async Lucene indexing but was observed populated here.)
