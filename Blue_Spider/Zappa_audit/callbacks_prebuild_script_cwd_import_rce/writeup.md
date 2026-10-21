# VULN-014 — `callbacks`/`prebuild_script` config imports & calls a module from cwd (local RCE)

| | |
|---|---|
| **ID** | VULN-014 (merges VULN-015) |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | High · CVSS 3.1 **8.6** — `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None beyond running the `zappa` CLI in a directory whose config the attacker influenced (Surface C) |
| **Attacker gains** | Arbitrary code execution on the developer/CI host |

## Summary
Zappa's `callbacks` (and the sibling `prebuild_script`) take a dotted path from `zappa_settings`, import
that module **from the current working directory**, and call the named function. There is no allow-list and
no confirmation, and `callbacks["settings"]` fires on almost every command — including read-only ones like
`zappa status`. So merely running a Zappa command in a cloned/shared project executes attacker code on the
host. Verified live: a planted `evilcb.py` was imported from cwd and its function ran.

## How it works (mechanism & code trace)
```python
# targets/Zappa/zappa/cli.py:2554-2593  callback()
callback = self.stage_config.get("callbacks", {}).get(position)      # attacker-controlled dotted path
if callback:
    (mod_path, cb_func_name) = callback.rsplit(".", 1)
    ...
    working_dir_importer = pkgutil.get_importer(working_dir)          # working_dir = os.getcwd()
    module_ = working_dir_importer.find_spec(mod_name).loader.load_module(mod_name)  # executes module top-level
    cb_func = getattr(module_, cb_func_name)
    cb_func(self)                                                     # <-- calls attacker function
```
`loader.load_module()` executes the target module's top-level code from `os.getcwd()`, then the named
function is invoked. **Two aggravators:** (1) `callbacks["settings"]` is called from `load_settings` at
`cli.py:650`, so any command that loads settings (`status`, `package`, `tail`, …) triggers it; (2) the
`prebuild_script` twin (`cli.py:3391-3431`) fires via the offline, credential-free `zappa package`
(`cli.py:760-761`, `load_credentials=False`) — no AWS creds/network needed.

**The exact defect:** a config-named module is imported+executed from an arbitrary `cwd` with no
allow-list. Configuration is being treated as trusted code. The exploit sets
`callbacks={"settings":"evilcb.pwn"}`, plants `evilcb.py`, calls the real `callback("settings")`, and the
marker file proves execution (`response.txt`).

## Why it is a vulnerability (reasoning)
The workflow "clone a third-party repo, run `zappa`" routinely places semi-trusted `zappa_settings.*` and
adjacent `.py` files on disk. Treating those as trusted, executable code — on read-only commands, no less —
violates the trust boundary between "inspecting a project" and "running its code." The attacker's
capability (arbitrary local RCE) far exceeds the feature's intent (run *your own* deploy hooks).

## Reproduction
1. Lab up; run `./run.sh` (drives the real `callback()` in a hostile cwd).
2. Proof (`response.txt`): the config-named `evilcb.pwn` was imported from cwd and CALLED, writing a marker.
3. Real-world: a repo ships `zappa_settings.json` with `"callbacks":{"settings":"evil.pwn"}` + `evil.py`;
   victim runs `zappa status` → RCE. `zappa package` triggers `prebuild_script` offline with no creds.
4. Expected `[OK] exploit confirmed` / `==> VULN-014: CONFIRMED`.

## Impact
Local RCE on the operator/CI host from merely inspecting or packaging a hostile project, with that user's
file access and any AWS credentials in the environment. **Chains:** CI foothold → env AWS creds → cloud
compromise; VULN-016 is the sibling that persists code into the *deployed* artifact.

## Suggested fix
- Require an explicit `--allow-callbacks` / `--allow-prebuild` opt-in (default off).
- Never run `callbacks` for read-only/offline commands (`status`, `package`, `tail`).
- Require the hook module to live inside the declared project package, not arbitrary `cwd`; document
  `zappa_settings.*` + adjacent modules as a trust boundary.

## References
- CWE-94 (Code Injection). Upstream [#1373](https://github.com/Miserlou/Zappa/issues/1373).
- Sibling VULN-016 (persists into deployed artifact); amplifier VULN-017.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `zappa callbacks prebuild_script zappa_settings arbitrary code execution malicious project` — only Zappa docs/forks and the book; no advisory or report.
2. `Zappa serverless Python CVE security advisory` / GHSA / Snyk / OSV / repo security-advisories page — no Zappa advisory.
3. GitHub issue search `zappa/Zappa issues?q=prebuild_script OR callbacks OR "zappa_settings.py" injection` and the cited Miserlou/Zappa #1373 — #1373 is a feature question answered by pointing at `callbacks`; no one frames hooks as a hostile-config code-execution risk or notes they fire on read-only commands.
4. `cli.py` on master (fetched) — `callback()` and `execute_prebuild_script()` still `pkgutil.get_importer(cwd)...load_module()` with only a `hasattr` check; `dispatch_command` calls `self.callback("settings")` after every settings load.

**Related but distinct public references** (same class or component, not this bug):
- README "callbacks" / "prebuild_script" — documented as intended local deployment hooks; no security caveat.
- Miserlou/Zappa #1373 — hook feature request, non-bug.

**Reasoning:** Nothing public identifies `zappa_settings` hooks as a "clone-and-run-`zappa status`" local RCE vector. Caveat: the hooks are documented features and maintainers may regard the settings file as trusted (as git/npm did before similar "untrusted repo config executes code" issues were CVE'd), so the finding may be contested; still, no disclosure exists.
