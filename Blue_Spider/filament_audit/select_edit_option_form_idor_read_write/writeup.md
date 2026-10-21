# VULN-001 — `Select::editOptionForm()` IDOR: read + write of arbitrary related-model records

| | |
|---|---|
| **ID** | VULN-001 |
| **Software** | Filament |
| **Repository** | https://github.com/filamentphp/filament |
| **Affected version** | v4.14.0 |
| **Commit** | `154a22c52498a5400ae53fe64e772f8eb09946aa` |
| **Severity** | High |
| **CVSS 3.1** | 8.1 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | CONFIRMED (dynamic) — read + write |
| **Confidence** | 8/10 |
| **Confidence reasoning** | Both legs proven: low-priv user read a victim's email and overwrote its row; gated on the opt-in editOptionForm. |
| **Auth required** | Any authenticated panel user (here: a user who may edit a Post) |
| **Attacker gains** | Reads and overwrites arbitrary related-model records (e.g. change another user's email → account takeover) |

## Summary

Filament's `Select` offers an opt-in inline edit affordance: `->editOptionForm([...])` adds a
pencil action that edits the currently-selected related record in a modal. The record is
resolved from the Select's `$state` — a **public, client-controlled Livewire property** — via a
query that **strips the relationship/tenant constraint** (`Relation::noConstraints`) and filters
by the client-supplied PK alone, unless the developer added `modifyQueryUsing` (the common
documented pattern does not). The edit-option action also carries **no authorization** — its
only gate is `visible(filled($state))`. Together these give an authenticated low-privilege user
a full IDOR: the modal fills with any related record's attributes (read) and submitting it runs
`->update()` on that record (write). Proven here: low-priv `ryan` read and overwrote another
user's `name`+`email` by editing a Post.

## How it works (mechanism & code trace)

**Resolve from client state, constraint stripped** —
`packages/forms/src/Components/Select.php:831-868`:

```php
$this->getSelectedRecordUsing(static function (Select $component, $state) use ($modifyQueryUsing): ?Model {
    // ... BelongsTo fast-path only when $state == already-loaded key ...
    $relationship = Relation::noConstraints(fn () => $component->getRelationship());                 // :855 strips parent/tenant scope
    $relationshipQuery = app(RelationshipJoiner::class)->prepareQueryForNoConstraints($relationship);
    $relationshipQuery->where($component->getQualifiedRelatedKeyNameForRelationship($relationship), $state);  // :859 filter by CLIENT PK only
    if ($modifyQueryUsing) {                                                                          // :861 scope ONLY if developer added it
        $relationshipQuery = $component->evaluate($modifyQueryUsing, ['query' => $relationshipQuery, 'search' => null]) ?? $relationshipQuery;
    }
    return $relationshipQuery->first();                                                               // :868
});
```

**No authorization on the action** (`:398-424`):

```php
$action = Action::make($this->getEditOptionActionName())
    ->schema(fn (Select $component, Schema $schema) => $component->getEditOptionActionForm($schema->model($component->getSelectedRecord())))
    ->fillForm(fn (Select $component): ?array => $component->getEditOptionActionFormData())           // READ sink
    ->action(function (..., Select $component, array $data, Schema $schema): void {
        $component->evaluate($component->getUpdateOptionUsing(), ['data' => $data, ...]);             // WRITE sink
    })
    ->visible(fn (): bool => filled($this->getState()));                                              // :424 — the ONLY gate; no ->authorize()
```

**Default read/write closures** (`:978-984`): read = `getSelectedRecord()?->attributesToArray()`
(all non-hidden attributes); write = `$schema->getRecord()?->update($data)`.

**Taint source** — `data.author_id` is a public Livewire property; the attacker sets it to any
PK. The `in:`/options rule only runs on full-form submit, not on action mount, so an arbitrary
PK resolves.

## Why it is a vulnerability

The invariant is horizontal/tenant authorization: a user restricted to editing their own parent
record must not read or modify other owners'/tenants' related records. Here the acted-on record
is whatever PK the client places in public state, resolved through a query that deliberately
strips the relationship constraint, and the action consults no policy. So "edit this Post" is
silently widened to "read and overwrite any `User` row." That is IDOR (CWE-639) plus missing
authorization (CWE-862), not intended behaviour — the record should be scoped to what the user
may edit, or the action should be policy-gated.

## Reproduction

`./run.sh` (self-contained):

1. **Harness precondition:** add the documented `->editOptionForm([TextInput name, email])` to
   PostResource's existing `Select::make('author_id')->relationship('author','name')` (no
   `modifyQueryUsing`); reverted afterwards. Create a victim `User` (random suffix).
2. **Auth:** log in as low-priv `ryan@filamentphp.com`.
3. **READ:** on `/admin/posts/1/edit`, set `data.author_id=<victim_id>` and
   `mountAction("editOption", {}, {recordKey:"1", schemaComponent:"form.author_id"})`.
4. **WRITE:** `callMountedAction` with `mountedActions.0.data.name/email` set to attacker values.

Observed (`run.log`, `response.txt`):

```
editOption fill leaked the victim's attributes into the modal (READ): victim email present = True
victim row after submit: PWNED <suffix>|pwned_<suffix>@attacker.invalid  (WRITE succeeded = True)
```

A low-priv user read another user's email and overwrote that user's name+email — all through a
Post edit form.

## Impact

Cross-owner/cross-tenant **read** (all non-hidden attributes) and **write** (`$fillable`/declared
columns) of arbitrary related-model records, no victim interaction, from any authenticated
session. Overwriting another user's email is an account-takeover primitive (reset flows key on
email). C:H/I:H → 8.1; a multi-tenant deployment arguably warrants S:C (→ ~9.x). Chains with the
AssociateAction FK-reassignment family (report F7) to move/steal records across owners.

## Suggested fix

1. Scope the resolve through the relationship unless `modifyQueryUsing` is set (don't strip the
   constraint by default):
   ```php
   // prefer the constrained relationship query; noConstraints only when the dev opts in
   $relationshipQuery = $component->getRelationship()->getQuery();
   $relationshipQuery->where($component->getQualifiedRelatedKeyNameForRelationship(...), $state);
   ```
2. Add a default model-policy check to the edit-option action:
   ```php
   ->authorize(fn (Select $c) => $c->getSelectedRecord() && auth()->user()->can('update', $c->getSelectedRecord()))
   ```

Principle: resolve the acted-on record within the user's authorized scope, and gate the action on
the related model's policy by default.

## References

- OWASP WSTG-ATHZ-04 (IDOR), WSTG-ATHZ-02 (bypassing authorization schema).
- CWE-639 Authorization Bypass Through User-Controlled Key; CWE-862 Missing Authorization.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Vendor advisory list `github.com/filamentphp/filament/security/advisories` (pages 1–2, 19 advisories through 2026-10-14) — no advisory names `Select::editOptionForm`, the `editOption` action, `getSelectedRecordUsing`, or `Relation::noConstraints`.
2. GitHub Advisory Database, Composer ecosystem, query `filament` — 14 `filament/*` advisories; the only Select-related one is CVE-2026-48067 (Attach/Associate Select scope), compared below.
3. Advisory GHSA-7q3w-xqjw-g3cr / CVE-2026-48067 fetched in full — scope covers only `recordSelectOptionsQuery()` validation for `AttachAction`/`AssociateAction` Select fields; it does not mention `editOptionForm` or the selected-record resolver.
4. Advisory GHSA-6p72-cx74-63f5 (2026-10-08, "resource pages may retain access after scope changes") fetched — concerns re-validation of resource-page records/parents on later Livewire requests, explicitly "does not let users ... choose arbitrary out-of-scope records"; different mechanism.
5. Vendor docs `filamentphp.com/docs/4.x/forms/select` — the `editOptionForm()` section contains no authorization, policy, or scoping guidance.
6. Project issue tracker query `is:issue editOptionForm authorize` — 0 results. (General web-search quota for this session was exhausted before the Filament set; checks were made by direct fetch of the primary sources above.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-48067 / GHSA-7q3w-xqjw-g3cr — Select-field scope bypass, but in Attach/Associate actions' validation rule, patched 4.11.4; the `editOption` resolve path is a different code path.
- GHSA-6p72-cx74-63f5 — scope re-validation of resource-page records, not Select sub-actions.
- Vendor "ModalTableSelect is presentational — scope the relationship query" danger notice — shows awareness of client-tamperable Select state, but for a different component.

**Reasoning:** No advisory, CVE, or issue describes the edit-option action resolving the acted-on record from client Select state through a constraint-stripped query with no policy check. The vendor has been actively patching adjacent Select-scope bugs in 2026 (CVE-2026-48067, GHSA-6p72-cx74-63f5), so a private report on this specific path could be in flight, and the feature is opt-in (`editOptionForm` with the documented pattern), which is why confidence is not higher.
