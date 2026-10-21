# VULN-008 — API authorization structurally coarser than the UI

**Software**: Joomla! CMS
**Repository**: https://github.com/joomla/joomla-cms
**Affected version**: 5.4.9-rc2-dev (libraries/src/Version.php; commit-pinned, no tagged release)
**Status**: CONFIRMED (widened-config BFLA — non-SU group reads every component via the API, no per-component gate); baseline INTENDED (Super-User-only)
**Severity (static)**: Medium (conditional)
**Confidence**: 5/10
**Confidence reasoning**: The structural coarseness is real and demonstrated, but it requires an operator to widen two non-default gates; at the documented baseline the API is Super-User-only (no impact).
**Target commit**: a8bd3564ef52e830069aeb91286c2fd67bb3872d
**Validated at**: 2026-10-02

## Preconditions
- A valid API token. Tokens were minted directly: `base64("sha256:<uid>:HMAC_sha256(seed, site_secret)")`, with `seed = base64_decode(#__user_profiles 'joomlatoken.token')` and `site_secret` from `configuration.php` (plus `joomlatoken.enabled=1`).
- Widened-config leg: the exploit grants API access to group 7 via **two** gates, then reverts both (see Side effects).

## Request / Response
See `request.http` / `response.txt` / `run.log`.
- Baseline: group-7 token → `GET /api/index.php/v1/users` = **401**.
- Widened: same group-7 token → `/users` 200 (7 accounts), `/plugins` 200 (20), `/content/articles?filter[state]=-2` 200.

## Observation
Baseline is **Super-User-only (INTENDED)** — confirmed by the group-7 token being rejected (401). Importantly, this is enforced by **two** independent gates, not one: (1) the `plg_user_token` plugin's `allowedUserGroups` which defaults to `[8]` when absent (`getAllowedUserGroups()` fallback), and (2) the root `core.login.api` grant (`{"8":1}`). The report's F-27d note ("empty allowedUserGroups ⇒ allow all") applies only if an operator explicitly clears it to an empty array; at the shipped default (param absent) it resolves to `[8]`.

Once an operator performs the documented widening (adds group 7 to `allowedUserGroups` **and** grants `core.login.api` to group 7), the **same** group-7 token reads `/users` (every account incl. email/block/lastvisit), `/plugins` (every plugin + state), and content in any publication state (`filter[state]=-2` accepted) — with **no per-component `core.manage` gate**, because `ApiDispatcher::dispatch()` never calls `checkAccess()` and `ComponentDispatcher`'s gate is admin-client-only. That is strictly more than the group can see in any UI channel = broken function-level authorization / excessive data exposure. Writes remain gated (the divergence is read-side), matching the finding.

## Side effects
- Per run: creates a group-7 user `apiadm_<rand>`, sets its `joomlatoken.*` profile rows, and *temporarily* sets `plg_user_token` `allowedUserGroups=["7","8"]` + root `core.login.api` `{"8":1,"7":1}`. Both config changes are reverted in a `finally` block (verified: "core.login.api still grants group 7: False"). The created user + token seed remain (random suffix). Cleanup hint: remove `apiadm_*` users and their `jos_user_profiles` rows.

## Research & references
- OWASP API Security Top 10 — API5:2023 Broken Function Level Authorization; API3 Excessive Data Exposure. Technique: obtain a low-privilege identity's API credential and enumerate endpoints that the UI would gate per-component.
- Upstream 5.4.9/6.1.4 API-ACL point-fixes CVE-2026-90913/90917/92226/90916; ancestor CVE-2023-23752.

## If NEEDS_MANUAL
The *structural root* question — whether the 5.4.9 point-fixes close `ApiDispatcher`'s missing `checkAccess()` generally, vs only specific endpoints — is for a human comparing this tree against the 5.4.9 diff. The exposure itself is CONFIRMED here under the documented widening.

## If INTENDED
At the pure documented baseline the API is Super-User-only (two gates), and a Super User may legitimately read everything — so with no operator widening there is no exposure. The reportable issue is the *coarseness that surfaces when an operator grants API access to a non-SU group*, which the finding and this validation both scope as conditional.
