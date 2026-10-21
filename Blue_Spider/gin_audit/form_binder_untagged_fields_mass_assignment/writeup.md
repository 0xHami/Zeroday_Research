# VULN-004 — Reflection binder maps **all exported fields** (untagged ⇒ by field name) ⇒ mass assignment

| | |
|---|---|
| **Software** | Gin (Gin Web Framework) |
| **Repository** | https://github.com/gin-gonic/gin |
| **Affected version** | v1.12.0 (`version.go:8`), untagged master checkout |
| **Commit** | `1bd0ecf2d3e08da37efa270bb7be20c1eddb0d68` |
| **Severity** | **Medium** base CVSS 3.1 **6.5** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`; **High 8.8** `…/C:H/I:H/A:N` when bound into a persistence/domain model with a privileged untagged field |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None (unauthenticated) |
| **Attacker gains** | Set any exported field of the destination struct the developer did not explicitly tag out — e.g. `IsAdmin`, `Role`, `OwnerID` — from request input, i.e. privilege escalation / over-posting. |

## Summary

gin's form/query reflection binder maps the **entire exported field set** of the destination
struct from attacker input, binding fields that have no struct tag by their Go field name, with
**no allowlist**. Only an explicit `form:"-"` opts a field out. So any field a developer did not
think to tag — the classic `IsAdmin`, `Role`, `OwnerID` on a model bound directly from a request
— is attacker-assignable. This is the mass-assignment / over-posting class (Rails CVE-2012-5664
lineage). Base Medium; High when the struct is a real persistence model with a privileged field.

## How it works (mechanism & code trace)

**Entry point.** `POST /account` binds the request into a model with `c.ShouldBind(&u)`
(→ Form binder for a form POST), where:

```go
type userModel struct {
	Email   string `form:"email" json:"email" binding:"required,email"`
	IsAdmin bool   // NO tag
	Role    string // NO tag
}
```

**The binder iterates every field.** `mapping` walks the struct:

```go
// targets/gin/binding/form_mapping.go:84-134 (abridged)
func mapping(value reflect.Value, field reflect.StructField, setter setter, tag string) (bool, error) {
	if field.Tag.Get(tag) == "-" { return false, nil }         // :85  only "-" opts out
	...
	if vKind == reflect.Struct {
		for i := range value.NumField() {                      // :122  EVERY exported field
			sf := tValue.Field(i)
			if sf.PkgPath != "" && !sf.Anonymous { continue }  // skip unexported only
			ok, err := mapping(value.Field(i), sf, setter, tag)
			...
		}
	}
}
```

**Untagged ⇒ bind by Go field name.** For each field, `tryToSetValue` computes the key:

```go
// targets/gin/binding/form_mapping.go:149-154
tagValue = field.Tag.Get(tag)          // "" for IsAdmin / Role (no form tag)
tagValue, opts := head(tagValue, ",")
if tagValue == "" {                    // default the key to the FIELD NAME
	tagValue = field.Name              // "IsAdmin", "Role"
}
```

So a request field literally named `IsAdmin` binds to the `IsAdmin` bool; `Role` to `Role`. There
is **no allowlist** of permitted inputs — every exported field is a sink. (For JSON bodies,
`binding/json.go:25` leaves `DisallowUnknownFields=false`, so an over-post raises no error either.)

**The exact defect.** The binder's contract is "populate the destination from input," implemented
as "for every exported field, pull a value keyed on its tag-or-name." There is no notion of which
fields are *intended* to be client-settable — that distinction exists only in the developer's head
(and in whichever tags they remembered to write).

## Why it is a vulnerability (reasoning)

The invariant a developer assumes is "only the fields I put on the form are settable by the
client." gin silently widens the settable set to *all exported fields*, so a model that contains
both user-editable fields (`Email`) and privileged/internal fields (`IsAdmin`, `Role`, `OwnerID`)
is fully attacker-writable when bound directly — the extremely common "bind into the DB struct"
pattern. This is a real security flaw, not a style issue: it is the exact mechanism of
CVE-2012-5664 (Rails) and the OWASP "Mass Assignment" class, and gin provides no built-in
allowlist/DTO enforcement and no error on over-post. The dynamic proof shows `IsAdmin` flipping
to `true` and `Role` to `superadmin` purely from request body keys the endpoint never advertised,
while the same fields stay `false`/`""` when omitted — unambiguous over-posting.

## Reproduction

1. App precondition (modeled by `/account`): bind a request into a struct that has a privileged
   untagged field (`IsAdmin`, `Role`).
2. `cd claude_audit/gin/exploits/VULN-004 && ./run.sh`.

Decisive request:
```
POST /account HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=attacker@example.com&IsAdmin=true&Role=superadmin
```
Response (`run.log`): `{"IsAdmin":true,"Role":"superadmin","email":"attacker@example.com"}` — vs
the legit `email`-only request returning `IsAdmin:false, Role:""`.

## Impact

- **Privilege escalation / over-posting:** flip `IsAdmin`, escalate `Role`, reassign `OwnerID`,
  `AccountID`, `Price`, `Verified`, or any field present on a model that is bound directly —
  Confidentiality/Integrity High when the field is security-relevant (CVSS 8.8).
- **Blast radius:** any endpoint that binds request input into a struct containing a
  non-user-editable exported field without tagging it out.
- **Chains:** **VULN-013** delivers the injected field via the URL query too (even on a
  body-oriented endpoint); **VULN-005** lets the attacker also skip the validator that might
  have rejected the shape — all three ride the same `c.ShouldBind`.

## Suggested fix

This is a documented design choice (gin binds by tag/name), so the durable fix is application
discipline plus a safer default option:

- **App side:** bind into a dedicated input DTO containing *only* client-settable fields, then
  copy to the model — never bind straight into a persistence struct. Tag every non-input field
  `form:"-" json:"-"`.
- **Library side:** offer/encourage an allowlist binding mode and set `DisallowUnknownFields=true`
  by default for JSON so over-posts are at least surfaced as errors.

Principle: input binding must be an explicit allowlist (DTO), not "every exported field."

## References

- **CWE-915**; **Rails CVE-2012-5664** (the canonical mass-assignment precedent).
- **OWASP** Mass Assignment Cheat Sheet; API Security Top 10 (API6:2019 Mass Assignment).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 60 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory Database search `gin-gonic`, OSV listing for `github.com/gin-gonic/gin`, Snyk package page, gin repo security advisories — no advisory on form / query binding, untagged fields, or mass assignment
2. gin issue / PR search `mass assignment OR untagged OR "without tag" OR "field name" OR DisallowUnknownFields` (47 results, page 1) — no item describes binding untagged struct fields by Go field name as a security issue; #4875 (StrictJSON) and #4335 concern rejecting unknown JSON keys per call
3. gin issue #4683 (May 2026, "AI code audit report") — generic "ShouldBind / mass assignment, use DTO structs" remark with no mechanism; dismissed by contributors as advertising
4. gin `docs/doc.md` — "you need to set the corresponding binding tag on all fields you want to bind"; does not document that untagged exported fields are bound by field name
5. gin releases v1.10.0 – v1.12.0 — no binding allowlist / untagged-field change
6. (gin-specific WebSearch queries could not be executed — the shared search budget was exhausted before this folder; all checks above were direct fetches)

**Related but distinct public references** (same class or component, not this bug):
- gin issue #4683 — generic mass-assignment caution about `ShouldBind`; no component detail, not a bug report
- gin PR #4875 / issue #4335 — `StrictJSON` to reject unknown JSON keys; JSON-only and a different mechanism (unknown keys vs. untagged fields bound by name)
- CVE-2012-5664 (Rails) — class precedent in another project

**Reasoning:** No CVE, advisory or upstream issue reports that gin's reflection binder maps untagged exported fields by Go field name with no allowlist. The behaviour is likely to be treated as by-design (Go's own `encoding/json` binds the same way) and the class is extremely generic, so confidence that it is "unknown" as a vulnerability is moderate rather than high; the specific mechanism is nevertheless undocumented in gin's security history and even contradicted by the docs' wording.
