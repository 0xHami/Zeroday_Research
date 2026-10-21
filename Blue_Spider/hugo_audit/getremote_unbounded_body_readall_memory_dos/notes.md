# VULN-018 — GetRemote unbounded response body (io.ReadAll) → build-time memory DoS

**Software**: Hugo
**Repository**: https://github.com/gohugoio/hugo
**Affected version**: 0.167.0-DEV (common/hugo/version_current.go:19-24) — commit-pinned: no tagged release
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: c7f9999309a2e7a12d24c03fe639008ddc4565f8
**Validated at**: 2026-09-30

## Preconditions
- A `resources.GetRemote` call to a responder the attacker controls (in the wild any
  public host — the default allowlist permits them). Here a loopback responder reached
  via customized `urls` (loopback is otherwise blocked by the VULN-001 dial guard).

## Request / build input
`layouts/index.html`: `{{ $r := try (resources.GetRemote "http://bombhost.local:PORT/stream") }}`.
Responder streams N bytes. Control N=64 KiB (2 GB cap); attack N≈2.2 GB (`--memory=1g`).

## Response
See `response.txt`:
```
[control 64KB] rc=0 out=LEN=65536 hits=1
[attack ~2.2GB] rc=137 hits=1   -> OOM-kill
```

## Observation
Static prediction (remote.go:296): `io.ReadAll(res.Body)` buffers the whole body with
no `io.LimitReader`/`MaxBytesReader`; `httpClient.Timeout` bounds only time. Confirmed:
a small body builds fine, a ~2.2 GB streamed body OOM-kills the 1 GB build (rc 137). The
responder — untrusted — dictates the allocation.

## Side effects
None persistent — throwaway builds; loopback responder inside the exploit process.

## Research & references
- CWE-770 Allocation Without Limits. OWASP "Denial of Service" cheat sheet — cap
  response sizes with `io.LimitReader`/`MaxBytesReader`. Applied a streaming responder
  (server-sized allocation) rather than a Content-Length lie, since `io.ReadAll` reads
  to EOF.
- Amplifies VULN-001 (once the dial guard is off, the unbounded read targets internal
  endpoints).

## If FAILED
n/a — CONFIRMED.
