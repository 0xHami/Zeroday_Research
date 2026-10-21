# VULN-002 — Node code execution via `css.PostCSS` `--use` module injection

| | |
|---|---|
| **ID** | VULN-002 |
| **Software** | Hugo — https://github.com/gohugoio/hugo |
| **Affected version** | 0.167.0-DEV (`common/hugo/version_current.go:19-24`); commit-pinned, no tagged release |
| **Commit** | `c7f9999309a2e7a12d24c03fe639008ddc4565f8` |
| **Severity** | Medium — CVSS 3.1 **5.9** `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N` (→ High with `node.permissions.disable=true`) |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None. Actor is a malicious/compromised theme or module (T2) that ships a `.js` plugin and calls `css.PostCSS`. Not T1-reachable. |
| **Attacker gains** | Arbitrary Node code execution during the build — read the project tree and exfiltrate over the network (fs-write blocked by `--permission`; full RCE if `--permission` is disabled). |

## Summary

`security.exec.allow` is Hugo's containment boundary against untrusted themes, but it vets
only the **binary name** (`postcss`, `node` are default-allowed). `css.PostCSS` forwards a
theme-controlled `use` value to `postcss --use <value>`, and postcss-cli `require()`s and
**executes** it as a Node module. So a theme that ships a `.js` plugin and calls
`css.PostCSS (dict "use" "…")` runs arbitrary Node during the build. Confirmed dynamically: an
injected plugin, named only via the `use` option, executed and made a network callout to a
listener — **under Hugo's default `node --permission`**, proving the permission model does not
restrict network egress.

## How it works (mechanism & code trace)

**Source — free-form module designators into `postcss`.**
`targets/hugo/resources/resource_transformers/cssjs/postcss.go:112-131`:

```go
if opts.Use != "" {
    args = append(args, "--use")
    args = append(args, strings.Fields(opts.Use)...)   // :117-119 — split into tokens, passed verbatim
}
// then --parser (:122), --stringifier (:125), --syntax (:128)
```

postcss-cli `require()`s each `--use`/`--parser`/`--stringifier`/`--syntax` value as a Node
module — running its top-level code. (`strings.Fields` also permits injecting extra flags.)

**The allowlist only checks the binary name.**
`targets/hugo/config/security/securityConfig.go:181-190` (`CheckAllowedExec` →
`Exec.Allow.Accept(name)`); `postcss`/`node` are in the default allow. The policy never
inspects what the tool is then told to `require()` and run — the essence of the escape.

**Mitigation present (why residual, not immediate full RCE).** Node `--permission` is on by
default (`securityConfig.go` node permissions; applied in `common/hexec/exec.go`) with
`AllowRead:["."]`, `AllowWrite:[]`, and child-process/worker/addons limited. This blocks
fs-writes and out-of-tree reads — **but Node's permission model does not restrict network
egress**, so an in-tree plugin still runs arbitrary JS that reads the project tree and phones
home. With `security.node.permissions.disable=true` this becomes unrestricted RCE.

**The exact defect.** The `use` value is attacker-influenced (theme-controlled) and reaches
`postcss --use` unvalidated (`postcss.go:117-119`); postcss-cli executes it as code; the exec
allowlist that is supposed to contain untrusted themes checks only the binary name and is blind
to this.

**Dynamic confirmation** (`response.txt` / `run.log`): build rc=0 and the OOB listener recorded
**1** callout to `/postcss-rce-<marker>` — the plugin executed and reached the network. This ran
**under** the default `node --permission` (the exploit uses Node 24 because the lab's Node 18
rejects the `--permission` flag Hugo applies, which otherwise makes PostCSS unusable there).

## Why it is a vulnerability

The invariant `security.exec.allow` is meant to give is "an untrusted theme cannot run arbitrary
code" — it allowlists tool *names*. But allowing `postcss`/`node` while forwarding a
theme-controlled module designator to a tool that `require()`s it defeats that invariant: the
theme runs arbitrary Node. The demonstrated network callout under the default `--permission`
proves the *residual* capability (read project + network exfil, `C:H`), and the code path to full
RCE (`--permission` disabled) is one operator setting away. The proof isolates the cause: the
plugin is named only through the `use` option and nothing else, yet its code ran.

## Reproduction

1. `cd claude_audit/hugo/exploits/VULN-002 && ./run.sh`
2. The script writes `evil.js` (a valid postcss8 plugin whose top-level code does
   `http.get('http://127.0.0.1:PORT/<marker>')`), `assets/css/x.css`, and a template
   `{{ resources.Get "css/x.css" | css.PostCSS (dict "use" "/site/evil.js") }}`. It `npm install`s
   postcss + postcss-cli into the site, starts an OOB listener, and builds with
   `cvehunterlab_hugo_st10node:latest` (target hugo binary + Node 24) under `--network host`.
3. Expected: `[OK] exploit confirmed …`, exit 0. The listener records one callout to
   `/postcss-rce-<marker>` (`response.txt`).

## Impact

Arbitrary Node code execution during the build from an untrusted theme, past the exec-allowlist
boundary — exfiltrate build secrets/source over the network and tamper with emitted CSS/JS
(`C:H`, `I:L` under `--permission`). With `security.node.permissions.disable=true` → full RCE on
the build host (`C:H/I:H/A:H`). **Chains** with supply-chain module-fetch findings (HUGO-011/012)
that deliver the malicious theme, and with the SSRF findings for exfiltration.

## Suggested fix

- Validate `--use`/`--parser`/`--stringifier`/`--syntax` values: reject leading `-` (flag
  injection) and require resolvable in-tree module names; do not `strings.Fields`-split into
  arbitrary tokens (`postcss.go:112-131`).
- Resolve `Config`/`--config-file` through the assets/work FS even when absolute
  (`postcss.go:175`, `babel.go`) — reject out-of-tree.
- Document that PostCSS/Babel run arbitrary Node and that containment relies on `--permission`
  (and that disabling it removes all confinement). Principle: allowlisting a tool name is not
  sufficient when the tool executes caller-named modules.

## References

- CWE-94 (code injection). Node Permission Model (restricts fs/child-process, not network):
  https://nodejs.org/api/permissions.html
- postcss-cli `--use`: https://github.com/postcss/postcss-cli
- Related Hugo Node-tool advisories: CVE-2026-44301 (`--permission` added 0.161.0),
  CVE-2026-89259, CVE-2026-100690.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 35 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `Hugo css.PostCSS "use" option arbitrary Node module execution theme advisory GHSA` — only Hugo docs and forum posts; no advisory
2. `gohugoio hugo postcss --use plugin code execution security.exec.allow CVE` — CVE-2026-44301 (Node tools ran without FS restrictions, fixed 0.161.0) and CVE-2026-75926 (Tailwind child-process bypass, fixed 0.165.0); nothing about `--use`/`--parser`/`--syntax`
3. `hugo postcss babel config file absolute path outside project Node permission --use --parser --syntax injection advisory 2026` — same two CVEs; no match for option/flag injection
4. Fetched GHSA-x597-9fr4-5857 (CVE-2026-44301) — does not mention PostCSS plugin options or theme-named modules
5. Fetched github.com/gohugoio/hugo/security/advisories pages 1-3 — GHSA-x3mx-cm49-8m9c (symlink bypass in Node tools), GHSA-vrm6-x8vp-mv2r (Tailwind permissions), GHSA-r73q-gwx2-fpxm (module.replacements widen Node read sandbox) are different vectors

**Related but distinct public references** (same class or component, not this bug):
- GHSA-x597-9fr4-5857 / CVE-2026-44301 — Node tools (PostCSS/Babel/Tailwind) had unrestricted FS access; fixed by the `--permission` model that this finding runs under.
- CVE-2026-75926 — Tailwind config spawning a shell via `--allow-child-process`; different tool and primitive.
- GHSA-x3mx-cm49-8m9c / CVE-2026-100690, GHSA-vrm6-x8vp-mv2r / CVE-2026-89259, GHSA-r73q-gwx2-fpxm — permission-model escapes via symlinks / Tailwind / module mounts, not module-designator injection.

**Reasoning:** No public reference names the `css.PostCSS` `use`/`parser`/`stringifier`/`syntax` path (or the `strings.Fields` flag-injection) as a way for a theme to run Node code. That said, the maintainers' published threat model (CVE-2026-44301) already assumes Node tools execute theme-supplied code and relies on Node's permission model for containment, and that model is documented as not restricting network egress, so the residual "read tree + exfiltrate" capability may be considered accepted. The flag-injection and absolute `Config` path sub-points are the most likely to be genuinely new.
