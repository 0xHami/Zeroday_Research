# VULN-004 — Reflection binder maps all exported fields ⇒ mass assignment

**Software**: Gin (Gin Web Framework)
**Repository**: https://github.com/gin-gonic/gin
**Affected version**: v1.12.0 (`version.go:8`) — untagged master checkout, commit-pinned
**Status**: CONFIRMED
**Severity (static)**: Medium (base 6.5) / High (8.8) when bound into a persistence/domain model
**Target commit**: 1bd0ecf2d3e08da37efa270bb7be20c1eddb0d68
**Validated at**: 2026-09-30T16:30Z

## Preconditions
- Extended harness `demo` engine (:36275), route `POST /account` binds into
  `userModel{ Email `form:"email"`; IsAdmin (untagged); Role (untagged) }` via `c.ShouldBind`
  — the common "bind straight into the model" pattern. The HTML form only offers `email`.
- Unauthenticated.

## Request
See `request.http`. `POST /account` body `email=attacker@example.com&IsAdmin=true&Role=superadmin`.

## Response
See `response.txt` / `run.log`:
```
legit  (email only):         {"IsAdmin":false,"Role":"","email":"user@example.com"}
attack (email+IsAdmin+Role): {"IsAdmin":true,"Role":"superadmin","email":"attacker@example.com"}
```

## Observation
Exactly as predicted. gin's reflection binder iterates every exported struct field
(`form_mapping.go:118-134`) and, for a field with no `form` tag, binds it by its Go field name
(`form_mapping.go:149-154`, `tagValue=="" ⇒ tagValue = field.Name`). Only `form:"-"` opts a field
out (`:85`). So `IsAdmin=true` and `Role=superadmin` — fields the form never exposed — are bound
from attacker input. When omitted (legit request) they stay at the zero value, confirming the
attack values came from the request.

## Side effects
None (the harness only echoes the struct; no persistence). In a real app these are DB columns.

## Research & references
- CWE-915 (mass assignment); lineage Rails CVE-2012-5664 / the general "over-posting" class.
- OWASP "Mass Assignment" Cheat Sheet — bind to an explicit allowlist / DTO, never to the model.
- gin `binding/json.go:25` — `DisallowUnknownFields` defaults false, so unknown JSON keys are
  silently ignored (no error surfaces the over-post) — compounds the footgun for JSON bodies.

## If FAILED
n/a — CONFIRMED.
