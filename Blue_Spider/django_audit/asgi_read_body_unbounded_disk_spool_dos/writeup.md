# VULN-008 — ASGI handler spools the entire request body to disk before any size check; `body_receive_timeout` is dead code → unauthenticated disk/worker DoS

| | |
|---|---|
| **Vulnerability ID** | VULN-008 (origin DJ-002) |
| **Software** | Django |
| **Repository** | https://github.com/django/django |
| **Affected version** | 6.2.0a0 (dev/`main`; commit-pinned, no tagged release) |
| **Commit** | `9e06baf2e4dd17834b5deaf3a3e6ae3bff2fcf26` |
| **Severity** | Medium — **CVSS 3.1 7.5** `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (Medium overall: front proxies commonly cap body size; ASGI-only) |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None. ASGI port only (:20797); WSGI (:20796) is immune. |
| **Attacker gains** | Force the ASGI worker to buffer an unbounded request body to `/tmp` (disk exhaustion) and/or hold a worker coroutine open with a slow body → denial of service. |

## Summary

On ASGI, Django reads the request body with `ASGIHandler.read_body`, which streams
every chunk into a `SpooledTemporaryFile` that rolls over to a real file in `/tmp`
once it passes `FILE_UPLOAD_MAX_MEMORY_SIZE` (2.5 MB). The loop keeps writing with
**no running byte total, no `Content-Length` consultation, and no timeout** — the
`DATA_UPLOAD_MAX_MEMORY_SIZE` limit is enforced only *later*, when `request.body`
/`POST` is first accessed, by which point the whole body is already on disk.
Furthermore `read_body` runs for **every** request before the view is even chosen,
so the body is buffered whether or not any view reads it. WSGI is immune: with no
`Content-Length` (chunked) it wraps the input in `LimitedStream(0)` and reads
nothing. An unauthenticated attacker can therefore stream a multi-GB (or slow,
trickle-fed) chunked body and exhaust the ASGI worker's disk or tie it up
indefinitely. Proven by driving the real `read_body` coroutine with an 8 MB body
(fully buffered, rolled to disk, no exception, no size check) and confirming the
dead timeout and the WSGI contrast.

## How it works (mechanism & code trace)

**Sink.** `ASGIHandler.read_body` (`targets/django/django/core/handlers/asgi.py:249-267`):

```python
async def read_body(self, receive):
    body_file = tempfile.SpooledTemporaryFile(
        max_size=settings.FILE_UPLOAD_MAX_MEMORY_SIZE, mode="w+b"     # 2.5 MB, then -> /tmp
    )
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            body_file.close(); raise RequestAborted()
        if "body" in message:
            ...
            body_file.write(message["body"])          # no running total, no CL check
        if not message.get("more_body", False):
            break
    body_file.seek(0)
    return body_file
```

There is no accumulator compared against a limit, no read of `Content-Length`, and
`await receive()` has no timeout. Past 2.5 MB the `SpooledTemporaryFile` rolls to a
real on-disk file and the loop keeps going.

**The late check.** `DATA_UPLOAD_MAX_MEMORY_SIZE` is only applied when the body is
*consumed* (`http/request.py`, in `body`/`_load_post_and_files`) — i.e. *after*
`read_body` has already written the entire payload to disk. And because
`ASGIHandler.handle` calls `read_body` up front for every request, a view that
never touches the body (like the lab's index view) still triggers the full spool.

**Dead timeout.** The class declares
`body_receive_timeout = 60` (`asgi.py:47`) "Number of seconds until a Request gives
up on trying to read a request body and aborts" — but a tree-wide grep finds it
**exactly once** (its own definition). It is never passed to `asyncio.wait_for` or
consulted anywhere, so a slow/trickle-fed body is never aborted.

**WSGI immunity.** `targets/django/django/core/handlers/wsgi.py:74-78`:

```python
try:
    content_length = int(environ.get("CONTENT_LENGTH"))
except (ValueError, TypeError):
    content_length = 0
self._stream = LimitedStream(self.environ["wsgi.input"], content_length)
```

With no `Content-Length` (the chunked case), `content_length = 0`, so
`LimitedStream` reads **nothing**. ASGI has no equivalent guard.

**Dynamic confirmation (bounded).** Driving the real `read_body` with a mock
`receive()` yielding 8 MB in 1 MB chunks:
- `buffered_bytes = 8,388,608` = the full body, with **no exception** raised, though
  `DATA_UPLOAD_MAX_MEMORY_SIZE = 2,621,440` → no running total;
- `rolled_to_disk = True` → the spool rolled to an on-disk file (anonymous
  `TemporaryFile`, unlinked on Linux);
- WSGI `LimitedStream(BytesIO, 0).read()` → `0` bytes;
- `body_receive_timeout` reference count in the tree = 1 (definition only);
- over HTTP, a 4 MB chunked POST with no `Content-Length` was accepted by ASGI
  (HTTP 403 = later CSRF check, *after* the body was read) — proving there is no
  `Content-Length` gate.

## Why it is a vulnerability (reasoning)

The invariant is bounded resource consumption per request: a server must not let an
unauthenticated client dictate unbounded disk/memory/time usage. Django *has* this
limit (`DATA_UPLOAD_MAX_MEMORY_SIZE`) and *does* enforce it on WSGI at ingest, but
on ASGI the enforcement is (a) absent from the buffering loop and (b) deferred until
after the whole body is on disk — so the limit cannot prevent the exhaustion it
exists to prevent. The dead `body_receive_timeout` compounds it: the code's own
stated intent (abort a slow body after 60 s) is unimplemented, leaving the slow-body
vector fully open. This is not by-design — the WSGI path and the declared-but-unused
timeout both demonstrate the intended behavior that the ASGI path fails to deliver.

## Reproduction

Unauthenticated, ASGI only. From a clean lab:

1. Run `./run.sh`. It:
   - drives the real `ASGIHandler.read_body` in-container with an 8 MB mock body and
     prints the buffered size, rollover flag, and the WSGI `LimitedStream(0)` contrast;
   - greps the tree for `body_receive_timeout` (expect 1 = dead);
   - sends a bounded 4 MB chunked HTTP POST (no Content-Length) to :20797.
2. Real-world (do **not** run unbounded against a shared host) — the DoS form:
   ```python
   import http.client
   c = http.client.HTTPConnection("localhost", 20797)
   c.putrequest("POST", "/"); c.putheader("Transfer-Encoding", "chunked"); c.endheaders()
   chunk = b"A"*65536; hdr = ("%x\r\n" % len(chunk)).encode()
   for _ in range(100000):            # ~6 GB, NO Content-Length
       c.send(hdr + chunk + b"\r\n")  # ASGI spools all of it to /tmp
   ```
   or a slow trickle (one byte every few seconds with `more_body=True`) to hold a
   worker open (no timeout fires).
3. **Observable proof:** the transcript's `[PROOF]` lines (8 MB buffered with no
   exception past the 2.5 MB limit; rolled to disk; WSGI reads 0; timeout dead), then
   `[OK] exploit confirmed …`, exit 0. See `response.txt` / `run.log`.

## Impact

Availability DoS, unauthenticated, ASGI-only:
- **Disk exhaustion:** a few concurrent multi-GB chunked bodies fill the ASGI
  worker's `/tmp`.
- **Worker starvation:** trickle-fed bodies hold worker coroutines open indefinitely
  (dead timeout) → all workers busy.
- **Blast radius:** the ASGI tier of the deployment; the worker does not crash but
  the host degrades. Practical severity is tempered where a front proxy caps request
  body size (hence Medium, not the raw 7.5 High band).
- **Chaining:** compounds VULN-011 (malformed Content-Type → 500 + unpaired
  `request_started` + ASGI traceback) — both degrade the ASGI worker under sustained
  malformed traffic.

## Suggested fix

1. Enforce a running byte total inside `read_body` against `DATA_UPLOAD_MAX_MEMORY_SIZE`
   (or a dedicated max-body setting) and abort with `RequestDataTooBig` once exceeded,
   mirroring the WSGI `LimitedStream` behavior:

   ```python
   total = 0
   while True:
       message = await receive()
       ...
       chunk = message.get("body", b"")
       total += len(chunk)
       if total > settings.DATA_UPLOAD_MAX_MEMORY_SIZE and <no per-view override>:
           body_file.close(); raise RequestDataTooBig()
       body_file.write(chunk)
   ```

2. Actually wire `body_receive_timeout` into the receive await, e.g.
   `message = await asyncio.wait_for(receive(), self.body_receive_timeout)`, so a
   slow body is aborted. Principle: apply size/time limits at ingest, before
   buffering, on every handler.

## References

- OWASP "Denial of Service" cheat sheet & WSTG input/DoS test cases — enforce
  request body size limits *before* buffering; technique applied by measuring that
  `read_body` buffers past the limit.
- CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation Without Limits).
- Django ASGI body-ingestion tickets #33699 / #33738 / #33754 (tracked, no security
  fix). The dead `body_receive_timeout` + missing running-total is the sharper edge.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 30 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Django official security-release archive (docs.djangoproject.com/en/dev/releases/security/) — two near matches: CVE-2026-33034 (2026-04-07, "Potential denial-of-service vulnerability in ASGI requests via memory upload limit bypass": missing/understated `Content-Length` bypassed `DATA_UPLOAD_MAX_MEMORY_SIZE` when reading `HttpRequest.body`; fixed 6.0.4/5.2.13/4.2.30) and CVE-2026-5766 (2026-05-05, same for `FILE_UPLOAD_MAX_MEMORY_SIZE`; fixed 6.0.5/5.2.14; advisory additionally recommends a web-server-level body limit).
2. Fix commit for CVE-2026-33034 on main (django/django@953c238058c0) fetched and read — it changes only `django/http/request.py` (`HttpRequest.body` → new `_check_data_too_big()` measuring the seekable stream at consumption time); `django/core/handlers/asgi.py` / `read_body` is untouched, and the new `DataUploadMaxMemorySizeASGITests` assert that `read_body` still consumes all chunks before the limit is applied.
3. Trac #33699 (read ASGI body on demand; closed wontfix because the ASGI spec requires receiving the full body), #33738 (`http.disconnect` handling, fixed), #33754 (body closed prematurely, fixed) — fetched; none mention a size cap, disk exhaustion, or `body_receive_timeout`.
4. Trac search for `body_receive_timeout` — endpoint returned HTTP 403; web-search quota for this session was exhausted before the query could run.
5. Audited commit 9e06baf2 dated 2026-04-25 (fetched patch header) — i.e. it already contains the CVE-2026-33034 fix and predates the CVE-2026-5766 fix.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-33034 — same component and same trigger (ASGI body without trustworthy `Content-Length`), but addresses the in-memory `request.body` limit at consumption time; it does not add ingest-time enforcement, so the unbounded spool to disk inside `read_body` remains.
- CVE-2026-5766 — same component, `FILE_UPLOAD_MAX_MEMORY_SIZE` variant; advisory delegates body-size capping to the web server.
- Trac #33699 — publicly records that Django deliberately receives the entire ASGI body up front (wontfix), i.e. the buffering design is known, but not framed as a disk/slow-body DoS.

**Reasoning:** The memory-limit bypass half of this finding is publicly known and already fixed in the audited commit (CVE-2026-33034), so the memory DoS framing is not novel. What no public advisory, ticket, or fix explicitly describes is the residual: the whole body is still written to a `SpooledTemporaryFile` on disk before any size check, and the declared `body_receive_timeout` is never consulted, leaving disk-exhaustion and trickle-body worker-hold vectors. Confidence is low because these are a near-corollary of the publicly documented design, the vendor has already said web-server limits are the expected mitigation, and a Trac ticket on the timeout could exist behind the blocked search.
