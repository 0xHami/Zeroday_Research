# VULN-003 — `Select::createOptionForm()` creates related-model records with no create authorization

| | |
|---|---|
| **ID** | VULN-003 |
| **Software** | Filament |
| **Repository** | https://github.com/filamentphp/filament |
| **Affected version** | v4.14.0 |
| **Commit** | `154a22c52498a5400ae53fe64e772f8eb09946aa` |
| **Severity** | Medium (High when the related model is privilege-bearing, e.g. `User`/`Role`) |
| **CVSS 3.1** | 6.5 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` |
| **Status** | CONFIRMED (dynamic) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Proven — low-priv user created a new `User` row via createOption with no create policy; gated on the opt-in createOptionForm. |
| **Auth required** | Any authenticated panel user (here: a user who may edit a Post) |
| **Attacker gains** | Creates arbitrary related-model records (e.g. new `User` accounts) with no create right |

## Summary

`Select::createOptionForm()` is the opt-in inline "+" create affordance: it lets a user create a
new related record and immediately select it. When enabled on a `relationship()` Select, the
create-option action **never consults the related model's `create` policy** — its only gates are
`isDisabled()` and the presence of the create form schema. The parent page authorized only the
**parent** record; the related model's `create` ability is never checked. So a user authorized
only to edit a Post can create rows in whatever model the Select relates to. Proven here: low-priv
`ryan` created a new `User` account.

## How it works (mechanism & code trace)

`packages/forms/src/Components/Select.php:234-307`:

```php
public function getCreateOptionAction(): ?Action
{
    if ($this->isDisabled()) { return null; }                         // :236 — only disabled-state gate
    if (! $this->hasCreateOptionActionFormSchema()) { return null; }  // :240 — only "is the feature configured" gate

    $action = Action::make($this->getCreateOptionActionName())
        ->schema(fn (Select $component, Schema $schema) => $component->getCreateOptionActionForm($schema->model(
            $component->hasRelationship() ? $component->getRelationship()->getModel()::class : $component->getActionSchemaModel())))
        ->action(function (..., Select $component, array $data, Schema $schema): void {
            $createdOptionKey = $component->evaluate($component->getCreateOptionUsing(), ['data' => $data, ...]);
        });
    // ... modal labels, extra footer actions ...
    return $action;                                                   // no ->authorize() anywhere
}
```

The default create closure (`:968-976`) persists unconditionally:
`newModelInstance()->fill($data)->save()` + `saveRelationships()`. There is no
`$user->can('create', RelatedModel::class)` anywhere in this path.

**Taint / reachability** — any authenticated user who can open the hosting form can mount the
action (`mountAction("createOption", ...)`) and submit the declared fields; mass assignment is
bounded to `$fillable` + the `createOptionForm` fields, but record *creation itself* is
unauthorized.

## Why it is a vulnerability

The invariant is that opening a parent form grants only the parent's create/edit rights. Here it
silently grants `create` on an arbitrary related model. The related model's own authorization
(`create` policy) is never evaluated, so a Post editor can inject rows into `User` — spam/garbage
at minimum, privilege-bearing records (`User`/`Account`/`Role`) at worst. That is missing
authorization (CWE-862), not intended behaviour.

## Reproduction

`./run.sh` (self-contained):

1. **Harness precondition:** add the documented `->createOptionForm([TextInput name, email,
   password])` to PostResource's existing author relationship Select; reverted afterwards.
2. **Auth:** log in as low-priv `ryan@filamentphp.com`.
3. **Attack:** on `/admin/posts/1/edit`, `mountAction("createOption", {}, {recordKey:"1",
   schemaComponent:"form.author_id"})`, then `callMountedAction` with
   `mountedActions.0.data.name/email/password`.

Observed (`run.log`, `response.txt`):

```
User rows before: 7
User rows after:  8   (injected account exists: YES)
```

A low-priv Post editor created a brand-new `User` account.

## Impact

Unauthorized creation of arbitrary related-model records. Medium in general (I:H, no read
primitive); **High** when the related model is privilege-bearing — a new `User`/`Account`/`Role`
row is privilege seeding (e.g. create an account the attacker controls, or with elevated
defaults). Pairs with VULN-001 (the edit-option IDOR) as the create/update halves of the same
unauthorized-related-model surface.

## Suggested fix

Gate the create-option action on the related model's create policy by default:

```php
$action = Action::make($this->getCreateOptionActionName())
    ->authorize(fn (Select $c) => auth()->user()->can(
        'create',
        $c->hasRelationship() ? $c->getRelationship()->getModel()::class : $c->getActionSchemaModel(),
    ))
    ->schema(...)
    ->action(...);
```

Principle: a sub-action that creates a record in another model must enforce that model's own
`create` authorization, not inherit the parent form's rights.

## References

- OWASP WSTG-ATHZ-02 (bypassing authorization schema); Access Control Cheat Sheet.
- CWE-862 Missing Authorization.
- Related: VULN-001 (edit-option IDOR on the same surface).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 60 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Vendor advisory list `github.com/filamentphp/filament/security/advisories` (pages 1–2, 19 advisories) — nothing on `createOptionForm` / the `createOption` action / related-model `create` authorization.
2. GitHub Advisory Database, Composer ecosystem, query `filament` — 14 `filament/*` advisories; none concerns inline option creation.
3. Advisory GHSA-7q3w-xqjw-g3cr / CVE-2026-48067 fetched — Attach/Associate Select key scoping only; not create authorization.
4. Vendor docs `filamentphp.com/docs/4.x/forms/select` — the `createOptionForm()` section shows only form fields and `createOptionUsing()`; no mention of policies, `authorize()`, or permissions.
5. Project issue tracker query `is:issue createOptionForm policy` — two unrelated closed issues (#15648, #13510). (Web-search quota exhausted; checks via direct fetch of primary sources.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-48067 — Select scope enforcement in Attach/Associate actions (integrity via out-of-scope key), not missing create authorization.
- VULN-001 in this audit (edit-option IDOR) — same opt-in Select surface, different sub-action.

**Reasoning:** Nothing public ties the create-option action to a missing related-model `create` policy check. Confidence is moderate rather than high because the vendor's general stance is that developers authorize actions themselves, the feature is opt-in, and the absence of any docs note means the vendor may classify this as expected behaviour (developer must add `->authorize()`), i.e. a hardening request rather than a vulnerability.
