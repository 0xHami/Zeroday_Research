# VULN-007 — Public registration: server-side validation is bypassable (only the client-claimed wizard step is validated)

| | |
|---|---|
| **ID** | VULN-007 |
| **Severity** | Medium |
| **CVSS 3.1** | 5.3 — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Affected commit** | `a6518355c3a30818044c46a9fc7fd53da34ab7f7` |
| **Auth required** | None (unauthenticated, public `/register`) |
| **Attacker gains** | Creates `User`+`Student` records with none of the registration constraints enforced (weak password, out-of-range gender, oversized/empty identity fields) |

## Summary

The public self-registration wizard (`App\Livewire\RegistrationWizard`) validates
input **per step**, and its final submit handler `register()` re-validates only the
rules for whatever step the client currently claims to be on. Because the step
marker (`currentStep`) and every field are client-controlled Livewire properties, an
unauthenticated attacker can issue a single `POST /livewire-<hash>/update` that
declares a step whose rules are trivially satisfiable while supplying arbitrary,
rule-violating values for all the other fields. The `User` and `Student` rows are
then created straight from the raw properties. This was proven live: one request
created a user whose password is the single character `1`, whose `gender_id` is `9`,
and whose `idnumber` is 25 characters long — each of which the wizard's own rules
forbid.

## How it works (mechanism & code trace)

**Entry point.** `register()` is a public Livewire method, reachable unauthenticated
because the whole `RegistrationWizard` component is served on the public `/register`
route (`targets/academico/app/Livewire/RegistrationWizard.php:161`):

```php
public function register(): void
{
    $key = 'registration:'.request()->ip();
    if (RateLimiter::tooManyAttempts($key, 5)) { ...; return; }
    RateLimiter::hit($key, 300);

    $this->validateCurrentStep();          // :171 — the ONLY validation on submit
    ...
    $user = DB::transaction(function () {
        $user = User::create([ 'firstname' => $this->firstname, ... 'password' => Hash::make($this->password) ]);   // :182
        $student = Student::create([ 'id' => $user->id, 'idnumber' => $this->idnumber, 'gender_id' => $this->gender, ... ]); // :193
        ...
    });
}
```

**The defect.** `validateCurrentStep()` selects its rule set from the *current* step
(`targets/academico/app/Livewire/RegistrationWizard.php:281`):

```php
protected function validateCurrentStep(): void
{
    $rules = match ($this->getActualStep()) {
        'user_data'     => [ 'password' => ['required','confirmed', Password::min(6)],
                             'gender' => 'required|in:0,1,2', 'idnumber' => 'required|max:12', ... ],
        'personal_info' => [ 'birthdate' => 'required|date', 'address' => 'required|max:255', ... ],
        'picture'       => [ 'photo' => ...'nullable|image|max:5120' ],
        'contacts'      => [ 'contacts' => 'array',
                             'contacts.*.firstname' => 'required|string|max:255', ... ],
        'review'        => array_filter([ 'accept_terms' => $this->termsUrl ? 'accepted' : null,
                                          'accept_rules' => $this->rulesUrl ? 'accepted' : null ]),
        default         => [],
    };
    $this->validate(array_filter($rules));                                      // :320
}
```

`getActualStep()` maps the client-set integer `public int $currentStep`
(`:27`) to a step name (`:323`). Since `currentStep` is a **public, non-`#[Locked]`
Livewire property**, the attacker sets it to any value in the same request's
`updates` diff. `register()` never re-runs the *other* steps' rules, so every
constraint the app expresses only as a step rule — `Password::min(6)`,
`gender in:0,1,2`, `idnumber max:12`, required `address`, the `photo image|max:5120`
check — is skippable.

**Which step to claim (a correction to the report).** The report suggested claiming
the `review` step. That path is a dead end here: with `registration.terms_url` and
`rules_url` both `null` (defaults), the review rule array is empty and
`$this->validate([])` throws `MissingRulesException` — Livewire refuses an empty rule
set (`vendor/livewire/livewire/src/Features/SupportValidation/HandlesValidation.php:493`,
`throw_if(empty($allRules), new MissingRulesException($this))`). That produces a 500,
not a bypass (and, notably, means legitimate registration is itself broken whenever
no terms/rules URLs are configured — a separate functional bug).

The actually-reachable bypass is the **`contacts` step (`currentStep = 4`)**. Its
rule set is *non-empty* (so no `MissingRulesException`) but every rule is anchored to
items of the `contacts` array: `contacts => array`, `contacts.*.firstname =>
required|...`, etc. With `contacts = []` (the default and what we send), the
`contacts` value is a valid array and the per-item rules match zero items — the whole
set passes vacuously, while none of the user_data/personal_info/picture rules run.

**Why the framework doesn't save it.** Laravel/Livewire validate exactly the rules
you hand `validate()`. There is no framework-level "validate the whole component"
behavior; the aggregate-validation responsibility is the developer's, and this code
delegates it to a single client-chosen step.

## Why it is a vulnerability (reasoning)

The trust boundary being crossed is input validation itself. The server *appears* to
enforce a password policy, a gender enum, an identity-number length, and required
contact details — a reviewer reading the `user_data`/`personal_info` rules would
reasonably conclude those are enforced on account creation. In reality the only rule
set that runs on `register()` is the one named by an attacker-controlled property,
and the attacker names one that is trivially satisfiable. The security invariant
"a persisted account satisfies the registration policy" is therefore false. The
feature is meant to grant an anonymous user the ability to create *a compliant*
student account; the actual capability is to create an *arbitrary* account row,
which is materially more than intended.

This matters beyond hygiene because it is the enabler for other findings: it removes
the `image|max:5120` gate that is the only type/size check on profile-picture upload
([VULN-009]), it lets the CSV-injection payloads of [VULN-006] be planted without any
name-format constraint, and it compounds the duplicate-account abuse of [VULN-010].

## Reproduction

From a clean state (only the seeded admin need exist):

1. Bring the target up (`docker compose -p cvehunt_academico up -d`), base URL
   `http://localhost:20000`.
2. Run `./run.sh`. It:
   - `GET /register` and extracts the `RegistrationWizard` `wire:snapshot` + CSRF token;
   - POSTs one Livewire update — the decisive request (see `request.http`):
     ```
     POST /livewire-5f244c96/update
     {"components":[{"snapshot":"<RegistrationWizard snapshot>",
       "updates":{"currentStep":4,"contacts":[],"email":"bypass_<rnd>@example.invalid",
                  "password":"1","gender":9,"idnumber":"XXXXXXXXXXXXXXXXXXXXXXXXX","address":""},
       "calls":[{"path":"","method":"register","params":[]}]}]}
     ```
   - reads the created rows back via `artisan tinker`.
3. Expected output: `[OK] exploit confirmed …` and verdict `CONFIRMED`. The proof line
   from the captured `run.log`:
   ```
   USER_ID=2
   PW_IS_1=yes          # Hash::check("1", password) == true  -> Password::min(6) skipped
   GENDER=9             # gender in:0,1,2 skipped
   IDNUM_LEN=25         # idnumber max:12 skipped
   ADDRESS=[]           # address required skipped
   ```

Full capture: `request.http`, `response.txt`, `run.log`.

## Impact

An unauthenticated attacker mints `User`+`Student` records that bypass every
registration constraint: weak-password accounts (auth-brute-force fodder),
out-of-range enum values that can break downstream code assuming `gender ∈ {0,1,2}`,
and oversized/empty identity fields that pollute staff-facing lists and exports.
Blast radius is the whole `users`/`students` table (anyone can create rows), pre-auth.
Combined with [VULN-006] (the unescaped export columns) and [VULN-009] (the skipped
`image` rule) it is the delivery mechanism for those higher-impact issues; combined
with [VULN-008] (IP-based registration limiter bypass) the planting is unbounded.

## Suggested fix

`targets/academico/app/Livewire/RegistrationWizard.php:171` — on final submit,
validate the **union of all steps' rules**, not just the current step; and lock the
step marker so it cannot be used to steer validation:

```php
use Livewire\Attributes\Locked;

#[Locked]
public int $currentStep = 1;

public function register(): void
{
    ...
    $this->validate($this->allStepRules());   // aggregate of user_data + personal_info + picture + contacts + review
    ...
}
```

where `allStepRules()` returns `array_merge(...)` of every step's rule array (guarding
the empty-review case so `validate()` never receives `[]`). Principle: never let
client-controlled state select which validations run; re-validate the entire payload
server-side at the trust boundary.

## References

- OWASP WSTG v4.2 — **WSTG-BUSL** (Business Logic) and Input Validation Testing:
  validate the full form server-side on submit, independent of client-driven wizard
  state. <https://owasp.org/www-project-web-security-testing-guide/>
- OWASP Cheat Sheet Series — *Mass Assignment* / *Input Validation*: treat every
  client-sent field (including UI-state markers) as attacker-controlled.
- Livewire security model: public properties are client-writable unless `#[Locked]`.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory Database query `academico`, NVD API `keywordSearch=academico`, OSV query `academico`, huntr repo page — only CVE-2025-10763 (`/edit-photo` upload); nothing on registration validation.
2. academico-sis/academico published advisories + issue/PR search `security` + `main` commit log through 2026-10-21 — no registration-validation fix.
3. `app/Livewire/RegistrationWizard.php` history examined in full: `efcd183` "improve security (#370)" (Apr 2026) added only the IP-keyed rate limiter and is already in the audited commit; `7b7a01f` "allow empty rules or terms url" (2026-10-19) only early-returns on an empty rule set inside `validateCurrentStep()`. Neither validates all steps nor locks `currentStep`. Current `main`: `$currentStep` is a plain public property and `register()` still calls only `validateCurrentStep()`.
4. GitHub Advisory Database query `livewire` (38 advisories by title) — no academico entry; only Livewire property-tampering issues in other products.

**Related but distinct public references** (same class or component, not this bug):
- academico commit 7b7a01f (2026-10-19) — touches `validateCurrentStep()` but only fixes the empty-rules `MissingRulesException` noted in this writeup, not the step-selection bypass.
- CVE-2025-10763 / GHSA-52xw-7w25-5w5q — academico `/edit-photo` unrestricted upload; adjacent (profile picture) but a different component.
- shopper/framework GHSA-g3f9-g5vj-p62f and similar — client-writable Livewire property abuse in other products; same class only.

**Reasoning:** Nothing public describes the client-chosen-step validation bypass in academico's public registration, and the logic is unchanged in substance on `main`. The class (unlocked Livewire properties steering server behaviour) is common, and the project has active external reporters, but no match exists for this component. All academico checks were direct GHSA/NVD/OSV/repository queries because the web-search quota was exhausted earlier in this triage.
