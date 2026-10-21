# VULN-001 — Select::editOptionForm() IDOR: read + write of arbitrary related-model records

**Software**: Filament
**Repository**: https://github.com/filamentphp/filament
**Affected version**: v4.14.0 (git tag; `composer.json` has no `version`, tag authoritative)
**Status**: CONFIRMED
**Severity (static)**: High
**Confidence**: 8/10
**Confidence reasoning**: Both legs proven live — low-priv ryan READ a victim user's email and WROTE (overwrote name+email) its row via the Select editOption action, no authorization. +1 over static 7 because the write (account-takeover primitive) is now demonstrated. Gated on the opt-in editOptionForm feature.
**Target commit**: 154a22c52498a5400ae53fe64e772f8eb09946aa
**Validated at**: 2026-10-01

## Preconditions
- Lab up; low-priv `ryan@filamentphp.com` / `password`.
- HARNESS: the demo PostResource already has `Select::make('author_id')->relationship('author','name')`.
  `automation.py` adds the documented `->editOptionForm([TextInput name, email])` to it
  (opt-in library feature, the exact pattern the finding describes) and reverts it (touch after
  mv for opcache). No library code changed; no `modifyQueryUsing` added (the natural pattern).
- A victim User is created (random suffix) to represent another owner's record.

## Request
See `request.http`. (2) `mountAction("editOption", {}, {recordKey:"1", schemaComponent:"form.author_id"})`
with `updates={"data.author_id": <victim_id>}`; (3) `callMountedAction` with
`mountedActions.0.data.name/email`.

## Response
`response.txt` (mounted-action snapshot) contains the victim's email in the editOption fill
(READ). After submit, `User::find(<victim>)` → `PWNED <suffix>|pwned_<suffix>@attacker.invalid`
(WRITE). See run.log.

## Observation
Matches the static finding exactly. `data.author_id` is public, non-#[Locked] Livewire state.
`getSelectedRecordUsing` (Select.php:831-868) resolves the record via `Relation::noConstraints`
(:855) filtered by the client PK alone (:859); `modifyQueryUsing` is absent so no parent/tenant
scope is applied. The editOption action carries no `->authorize()` (:424 only `visible(filled($state))`).
`fillEditOptionActionFormData` returns `getSelectedRecord()->attributesToArray()` → the victim's
non-hidden attributes are leaked into the modal (READ), and `updateOptionUsing` runs
`$record->update($data)` on the victim row (WRITE). A low-priv user whose only right is editing a
Post thus reads and overwrites arbitrary User records — e.g. change another user's email
(account-takeover primitive).

## Side effects
- Creates one victim User and overwrites it; harness reverted. Reseed to clean:
  `docker exec cvehunterlab_filament_app php artisan migrate:fresh --seed --force`.

## Research & references
- OWASP WSTG-ATHZ-04 (IDOR) + WSTG-ATHZ-02 (bypassing authorization) — substitute a related-object
  PK the subject doesn't own and observe read+write. CWE-639, CWE-862.

## If FAILED
n/a — CONFIRMED (both read and write).

## If NEEDS_MANUAL
n/a. (Cross-tenant impact would need a multi-tenant resource; the within-instance cross-owner
read+write is proven here.)

## If INTENDED
Not INTENDED. Unlike the vendor-documented authz family (F2/F7), the editOption action carries
no `// Security:` comment and no policy check; community guidance explicitly tells developers to
add `->authorize()` — i.e. the default is acknowledged to lack authorization. Insecure default on
an opt-in feature.
