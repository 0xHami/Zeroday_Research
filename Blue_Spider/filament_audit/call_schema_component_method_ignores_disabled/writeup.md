# VULN-012 — `callSchemaComponentMethod` enforces `hidden()` but not `disabled()`

| | |
|---|---|
| **ID** | VULN-012 |
| **Software** | Filament |
| **Repository** | https://github.com/filamentphp/filament |
| **Affected version** | v4.14.0 |
| **Commit** | `154a22c52498a5400ae53fe64e772f8eb09946aa` |
| **Severity** | Medium (low end) |
| **CVSS 3.1** | 4.3 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED (dynamic) |
| **Confidence** | 5/10 |
| **Confidence reasoning** | Mechanism proven (exposed method fired on a `disabled="disabled"` field); low incremental impact — widens the VULN-004 oracle only. |
| **Auth required** | Inherits the host page's auth (none on the lab demo page) |
| **Attacker gains** | Reaches the VULN-004 metadata/URL oracle on fields the UI presents as non-interactive (`->disabled()`) |

## Summary

Filament's host exposes a generic dispatcher, `callSchemaComponentMethod`, letting the
browser invoke any schema-component method annotated `#[ExposedLivewireMethod]`. It
excludes **hidden** components but applies **no `isDisabled()` guard**, so an exposed
method on a field rendered `->disabled()` (e.g. disabled for non-owners) remains
invokable over `/livewire/update`. The sibling **table** dispatcher performs exactly the
`isDisabled()` check, making this an inconsistency rather than a deliberate design. The
not-self-guarded reachable sink is `getUploadedFiles()` — the VULN-004 read primitive —
so this widens VULN-004's metadata/URL oracle to disabled fields.

## How it works (mechanism & code trace)

**The dispatcher, missing the guard** —
`packages/schemas/src/Concerns/InteractsWithSchemas.php`:

```php
public function callSchemaComponentMethod(string $componentKey, string $method, array $arguments = []): mixed
{
    $component = $this->getSchemaComponent($componentKey);   // :89 — filters HIDDEN; ignores disabled
    if (! $component) { return null; }
    if (! method_exists($component, $method)) { return null; }
    $methodReflection = new ReflectionMethod($component, $method);
    if (! $methodReflection->getAttributes(ExposedLivewireMethod::class)) { return null; }  // only gate: the attribute
    ...
    return $component->{$method}(...$arguments);             // :126 — invoked; NO isDisabled() check
}
```

**The sibling that gets it right** — `packages/tables/src/Concerns/HasColumns.php:63`:

```php
if ($column->isDisabled()) { return null; }   // the table dispatcher DOES guard
```

**The reachable sink** — `BaseFileUpload::getUploadedFiles()` (the VULN-004 oracle)
checks `shouldPreventFilePathTampering()` but never `isDisabled()`. The *mutating*
FileUpload methods self-guard (`BaseFileUpload.php:817,892` begin
`if ($this->isDisabled()) return;`), which is why the impact is the read oracle, not a
write.

## Why it is a vulnerability

A state-gate applied in one channel (the UI, and the table dispatcher) is not applied in
another (the schema dispatcher). A developer who disables a field for non-owners
reasonably assumes its server-side methods are unreachable too — and the table dispatcher
enforces precisely that. Here the exposed method is still callable, so `->disabled()` is
not a server-side control for schema-component methods. The attacker gains the VULN-004
read primitive on fields presented as non-interactive (CWE-862, incomplete authorization
on one channel).

## Reproduction

`./run.sh` (self-contained):

1. **Harness precondition:** the demo has no disabled FileUpload, so the exploit adds a
   standard `FileUpload::make('fileUploadDisabled')->disk('public')->disabled()` to the
   demo component in-container (the documented way to disable a field), waits for opcache,
   and **reverts it afterwards** (verified pristine). This does not touch library code.
2. **Plant** a victim object on the shared `public` disk.
3. **Confirm** the page renders the field with `disabled="disabled"`.
4. **Attack:** `callSchemaComponentMethod("form.fileUploadDisabled","getUploadedFiles")`
   with `updates={"data.fileUploadDisabled":{"inj":"<victim path>"}}` (see `request.http`).

Observed (`run.log`, `response.txt`):

```
field 'fileUploadDisabled' rendered with disabled attribute: True
returns: [{"inj":{"name":"secret-<suffix>.txt","size":70,"type":"text/plain",
          "url":"http://localhost:21890/storage/disabled-victim-<suffix>/secret-<suffix>.txt"}}]
fetched the URL → HTTP 200; victim content read: True
```

The exposed read method fired on a field the UI renders disabled, and the returned URL
yielded the victim file.

## Impact

Widens VULN-004: the metadata/URL oracle (and, on a shared public disk, full content
read) becomes reachable on fields rendered `->disabled()` — e.g. a file field disabled
for non-owners. C:L incremental (no persisted write — disabled fields don't dehydrate and
mutators self-guard). Genuine but low-impact channel-divergence; its value is as an
amplifier of VULN-004's reachability.

## Suggested fix

Mirror the table dispatcher's guard in the schema dispatcher:

```php
$component = $this->getSchemaComponent($componentKey);
if (! $component) { return null; }
if ($component instanceof CanBeDisabled && $component->isDisabled()) {
    return null;                       // match HasColumns.php:63
}
...
```

Principle: a server-side state control (`disabled`) must be enforced on every channel that
can reach the component's methods, not only the UI and the table path.

## References

- CWE-862 Missing Authorization; defense-in-depth channel divergence.
- OWASP WSTG-ATHZ — verify server-side enforcement of UI state controls.
- Related: VULN-004 (the reachable read sink).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 60 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Vendor advisory list `github.com/filamentphp/filament/security/advisories` (pages 1–2, 19 advisories) — nothing on `callSchemaComponentMethod` or `disabled()` enforcement for schema-component methods.
2. GitHub Advisory Database, Composer ecosystem, query `filament` — closest items are CVE-2026-55409 (disabled RichEditor state XSS, v3) and CVE-2026-48500 (unauthenticated temp upload on auth pages); neither is the schema dispatcher's missing `isDisabled()` gate.
3. Project issue tracker query `is:issue callSchemaComponentMethod disabled` — 0 results. (Web-search quota exhausted; checks via direct fetch of primary sources.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-55409 / GHSA-m9cv-24rx-8mv7 — a disabled field's state rendered raw (XSS), v3 only; not method dispatch.
- CVE-2026-48500 / GHSA-44wp-g8f4-f4v5 — reachability of upload handling on unauthenticated auth pages; different dispatcher/surface.

**Reasoning:** No public reference describes the schema-component dispatcher skipping the `isDisabled()` check that the table-column dispatcher applies. Confidence is moderate because the vendor documents that `disabled()` is a UI affordance and not a security boundary (so the inconsistency may be classed as hardening), and the incremental impact depends on VULN-004's read primitive.
