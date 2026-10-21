# VULN-003 — Unauthenticated full-read SSRF via dashboard `/proxy//host`

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned, no tagged release
**Status**: CONFIRMED
**Severity (static)**: High
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Validated at**: 2026-09-27

## Preconditions
- None. Fully unauthenticated — no cookie, no account. The exploit sends plain
  `GET` requests to the dashboard port (21526).

## Request
See `request.http`. Decisive request:
```
GET http://localhost:21526/proxy//api:3081/ HTTP/1.1
Host: localhost:21526
(no Cookie / Authorization)
```
Also validated: `GET http://localhost:21526/proxy//minio:9000/minio/health/live`.

## Response
See `response.txt` / `run.log`. `GET /proxy//api:3081/` returned **HTTP 200** with
the body `{"message":"\"Welcome to Classroomio.com API - docs are at http://localhost:21527/docs\""}`
— byte-for-byte the internal API's welcome JSON. `//minio:9000/minio/health/live`
returned HTTP 200 (MinIO's liveness endpoint).

## Observation
The static finding predicted that a protocol-relative reference (`//host`) passed
as the first arg of `new URL(ref, apiBase)` overrides the base authority, and that
`/proxy/*` forwards before auth. Both confirmed dynamically: with **no cookie**, the
dashboard's Node server fetched two hosts that are only resolvable from *inside* the
compose network (`api:3081`, `minio:9000`) and returned their bodies to us. This is
a non-blind, unauthenticated SSRF / credentialed open proxy. `api:3081` is the
internal API port (the attacker's own position can only reach the published `:21527`),
and `minio:9000` is entirely internal — reaching it proves server-side fetch.

## Side effects
None persistent (read-only GET). No state created.

## Research & references
- OWASP WSTG-INPV-19 (Server-Side Request Forgery) and the OWASP SSRF Prevention
  Cheat Sheet — used the "reach internal-only service" test procedure: a URL that
  resolves only from the server proves the request originates server-side.
- PortSwigger Web Security Academy — "SSRF against the local server / back-end
  systems": the internal-hostname read (`http://<internal>/`) is the canonical
  non-blind SSRF proof; the IMDS `169.254.169.254` escalation is documented there
  and applies unchanged on a cloud VM.
- WHATWG URL Standard §"URL parsing": a reference beginning with `//` is a
  "protocol-relative" special-scheme authority that replaces the base authority —
  the exact primitive abused here (confirmed live, matching the static Node repro).

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a. (The IMDS-credential-theft escalation needs a real cloud VM with a link-local
metadata service; the internal-service read proven here is the same primitive and
is sufficient to confirm the SSRF.)
