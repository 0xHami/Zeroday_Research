# VULN-008 — ASGI unbounded body-spool DoS (read_body has no size/time cap)

**Software**: Django
**Repository**: https://github.com/django/django
**Affected version**: 6.2.0a0 (targets/django/django/__init__.py) — commit-pinned: no tagged release
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS band High for the network-DoS vector)
**Target commit**: 9e06baf2e4dd17834b5deaf3a3e6ae3bff2fcf26
**Validated at**: 2026-09-30T08:18Z

## Preconditions
- None (unauthenticated). ASGI handler (:20797) only; WSGI is immune.

## Request
See `request.http`. Bounded validation:
- In-container: the real `ASGIHandler.read_body` coroutine driven with a mock
  `receive()` yielding 8 MB in 1 MB chunks.
- HTTP: a 4 MB chunked `POST /` with **no Content-Length** to :20797.

## Response / Observation
See `response.txt` (in-container JSON + HTTP status). Decisive facts:
- `read_body` buffered **8,388,608 bytes** (the entire body) with **no exception**,
  though `DATA_UPLOAD_MAX_MEMORY_SIZE = 2,621,440` — i.e. **no running byte total**;
  the size limit is not applied inside `read_body`.
- The `SpooledTemporaryFile` **rolled over to disk** (`rolled_to_disk=True`). The
  rolled file is an anonymous on-disk tempfile (its `.name` is the numeric fd, `6`,
  because `TemporaryFile` is unlinked-on-Linux) — the point is it is no longer in
  memory: past 2.5 MB the body lives on `/tmp`.
- WSGI `LimitedStream` with no Content-Length read **0 bytes** — the guard ASGI lacks.
- `body_receive_timeout` occurs **exactly once** in the whole tree
  (`asgi.py:47`, the definition) → **dead code**; the receive loop has no timeout.
- ASGI accepted the 4 MB chunked (no Content-Length) HTTP body → HTTP 403 (CSRF,
  since POST `/` triggers the CSRF check after the body is read) — confirming there
  is **no Content-Length gate** and the body is fully consumed by `read_body`.

The transient on-disk spool file was not caught by the best-effort /tmp poller
(timing; the rolled TemporaryFile is unlinked), but the in-container proof that the
spool rolls to disk is decisive.

## Side effects
None persistent. All buffers are bounded (≤8 MB) and freed at end of request/driver.
No host disk pressure (checked: asgi /tmp clean, overlay 16% used).

## Research & references
- OWASP WSTG-BUSL-09 / "Testing for the Circumvention of Work Flows" is not it;
  the relevant class is OWASP "Denial of Service" / Uncontrolled Resource
  Consumption (CWE-400/770) and the Application DoS cheat sheet — enforce request
  body size limits before buffering.
- Django tickets on ASGI body ingestion: #33699, #33738, #33754 (tracked, no
  security fix). The dead `body_receive_timeout` + missing running-total vs WSGI
  `LimitedStream` is the sharper, not-separately-filed edge.

## If FAILED
n/a — CONFIRMED.
