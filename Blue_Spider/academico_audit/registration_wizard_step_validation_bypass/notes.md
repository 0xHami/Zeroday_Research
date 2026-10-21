# VULN-007 — Public registration: server-side validation is bypassable

**Target name:** academico
**Target URL:** https://github.com/academico-sis/academico
**Software version:** untagged, commit a6518355 (2026-05-31)
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 5.3)
**Target commit**: a6518355c3a30818044c46a9fc7fd53da34ab7f7
**Validated at**: 2026-09-25

## Preconditions
- None. Unauthenticated. `GET /register` is public and returns 200.
- The exploit fetches a fresh RegistrationWizard Livewire snapshot each run and uses a random email suffix, so runs are independent.

## Request
See `request.http`. One `POST /livewire-5f244c96/update` echoing the wizard
snapshot with `updates = {currentStep:4, contacts:[], password:"1", gender:9,
idnumber:<25 chars>, address:""}` and `calls=[register]`.

## Response
See `response.txt` — HTTP 200, no validation-error effects. The record is then
read back over `artisan tinker`.

## Observation
- **The report's stated vector (`currentStep=review`, step 5) does NOT work.** With
  `registration.terms_url`/`rules_url` both null, the review step's rule array is
  empty, and Livewire's `validate([])` throws `MissingRulesException`
  (`vendor/livewire/livewire/src/Features/SupportValidation/HandlesValidation.php:493`,
  `throw_if(empty($allRules), ...)`) → HTTP 500, no record created. (First run of this
  exploit reproduced exactly that 500 — see the vulnerability class research below.)
- **The actually-reachable bypass is the `contacts` step (currentStep=4).** Its rule
  set is non-empty (`contacts => array`, `contacts.*.firstname => required|string|max:255`,
  …) so `validate()` does not error, but with `contacts = []` every one of those rules is
  vacuously satisfied (zero array items to validate). None of the user_data /
  personal_info / picture rules run.
- Result read back from the DB: `User id=2` created with `Hash::check("1", password) == true`
  (violates `Password::min(6)`), `students.gender_id = 9` (violates `gender in:0,1,2`),
  `strlen(idnumber) = 25` (violates `idnumber max:12`), `address = ""` (violates
  `address required`). Every step-expressed constraint was skipped.

## Side effects
- Created `users` row id=2 and `students` row id=2 (email `bypass_<suffix>@example.invalid`).
  Harmless test account; delete with
  `docker compose -p cvehunt_academico exec app php artisan tinker --execute '\App\Models\User::where("email","like","bypass_%@example.invalid")->delete();'`

## Research & references
- OWASP WSTG v4.2 — 4.7.x Input Validation Testing / "Testing for Bypassing Business
  Logic" (WSTG-BUSL): server must re-validate the *entire* form on final submit, not
  only the client-claimed step. https://owasp.org/www-project-web-security-testing-guide/
- Livewire validation internals: `HandlesValidation::providedOrGlobalRulesMessagesAndAttributes`
  throws `MissingRulesException` when the merged rule set is empty — this is what breaks the
  report's review-step vector and is why the contacts-step (non-empty-but-vacuous rules)
  vector is required. Verified directly in the container's vendored Livewire source.

## If FAILED
n/a — CONFIRMED.
