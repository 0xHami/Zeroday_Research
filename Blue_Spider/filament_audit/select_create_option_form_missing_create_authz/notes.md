# VULN-003 — Select::createOptionForm() creates related-model records with no create authorization

**Software**: Filament
**Repository**: https://github.com/filamentphp/filament
**Affected version**: v4.14.0 (git tag; `composer.json` has no `version`, tag authoritative)
**Status**: CONFIRMED
**Severity (static)**: Medium (High where the related model is privilege-bearing, e.g. User)
**Confidence**: 7/10
**Confidence reasoning**: Proven — low-priv ryan created a new User row via createOption (count 7→8, injected account exists) with no create policy. Gated on the opt-in createOptionForm feature; impact rises when the related model is privilege-bearing (as here, User).
**Target commit**: 154a22c52498a5400ae53fe64e772f8eb09946aa
**Validated at**: 2026-10-01

## Preconditions
- Lab up; low-priv `ryan@filamentphp.com` / `password`.
- HARNESS: `automation.py` adds the documented `->createOptionForm([TextInput name, email, password])`
  to PostResource's existing `Select::make('author_id')->relationship('author','name')` (opt-in
  library feature, the exact pattern the finding describes) and reverts it. No library code changed.

## Request
See `request.http`. (2) `mountAction("createOption", {}, {recordKey:"1", schemaComponent:"form.author_id"})`;
(3) `callMountedAction` with `mountedActions.0.data.name/email/password`.

## Response
`response.txt` (post-submit snapshot). `User::count()` 7→8; `User::where('email', injected)->exists()` = YES.

## Observation
Matches the static finding. `getCreateOptionAction()` (Select.php:234-307) is gated only by
`isDisabled()` (:236) and the presence of the create form schema (:240) — there is no
`->authorize()` and no related-model `create` policy call. The default create closure
(`newModelInstance()->fill($data)->save()`) persists a new User unconditionally. The acting user
(ryan) is authorized only to edit a Post, yet created a new User account — the related model's
`create` ability is never evaluated.

## Side effects
- Creates one injected User (random suffix). Harness reverted. Reseed to clean:
  `docker exec cvehunterlab_filament_app php artisan migrate:fresh --seed --force`.

## Research & references
- OWASP WSTG-ATHZ-02 (bypassing authorization) / Access Control Cheat Sheet — a sub-action must
  enforce the target model's own create policy. CWE-862.
- Community guidance explicitly recommends adding `->authorize()`/`visible()` to the create-option
  action — i.e. the default is acknowledged to lack authorization.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a.

## If INTENDED
Not INTENDED. Unlike the documented authz family (F2/F7), the create-option surface has no
`// Security:` comment and performs no create-policy check; it silently grants create on an
arbitrary related model. Insecure default on an opt-in feature.
