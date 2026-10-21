# VULN-016 — Code injection into generated `zappa_settings.py` via unescaped `'{0!s}'` interpolation

| | |
|---|---|
| **ID** | VULN-016 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | High · CVSS 3.1 **8.4** — `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Hostile/shared scalar config value + a package/deploy run (Surface C → deployed runtime) |
| **Attacker gains** | Arbitrary module-level Python executed in the *deployed* Lambda at every cold start (persistent) |

## Summary
Zappa generates the Lambda's `zappa_settings.py` by string-formatting config scalars into Python source
with `'{0!s}'` and **no escaping**. A scalar containing a single quote and a newline closes the string
literal and injects arbitrary module-level code, which is baked into the deployed artifact and executed on
every cold start. Verified live: a malicious `api_stage` produced a generated file whose injected statement
executed on import.

## How it works (mechanism & code trace)
```python
# targets/Zappa/zappa/cli.py:3129 (representative — same pattern for DOMAIN, LOG_LEVEL, BASE_PATH,
#                                  REMOTE_ENV, APP_MODULE, EXCEPTION_HANDLER, DJANGO_SETTINGS, AUTHORIZER_FUNCTION…)
settings_s = settings_s + "API_STAGE='{0!s}'\n".format((self.api_stage))
```
A value such as `dev'\nINJECTED=__import__('os').getcwd()\n_x='` renders as:
```python
API_STAGE='dev'
INJECTED=__import__('os').getcwd()
_x=''
```
That file is written into the Lambda zip (`cli.py:3045-3047`) and imported at cold start
(`handler.py:76 importlib.import_module("zappa_settings")`), so the injected statements run in the deployed
function's IAM role. The exploit drives the real `get_zappa_settings_string()` with a malicious `api_stage`
and `exec()`s the output; the injected symbol appears in the namespace (`response.txt`).

**The exact defect:** string interpolation into generated *source* instead of `repr()`/`json.dumps`
(CWE-94). It is inconsistent with the already-safe dict-valued settings (`CONTEXT_HEADER_MAPPINGS`,
`ENVIRONMENT_VARIABLES`, rendered via a dict repr); specifically the **string scalar** settings are
injectable.

## Why it is a vulnerability (reasoning)
Config is being compiled into executable code without neutralisation. `S:C` (scope change): code influenced
on the build host executes later in a different security authority — the cloud function/account. Unlike
VULN-014 (local hooks), this is a **persistent backdoor in the deployed artifact** that survives even if
`callbacks`/`prebuild_script` are stripped. The attacker's capability (arbitrary cloud code exec) vastly
exceeds the feature's intent (record a settings value).

## Reproduction
1. Lab up; run `./run.sh` (drives the real settings generator + `exec`).
2. Proof (`response.txt`): generated line `INJECTED_<tok>=__import__('os').getcwd()`, and after import the
   symbol is set — attacker code executed.
3. Real-world: `{"dev":{"domain":"x'\nimport os;...\n#"}}` + `zappa save-python-settings-file dev`; inspect
   the generated `zappa_settings.py`; `python -c "import zappa_settings"` runs the injected code — and it
   ships to Lambda.
4. Expected `[OK] exploit confirmed` / `==> VULN-016: CONFIRMED`.

## Impact
Persistent RCE in the deployed Lambda at cold start, in the function's role → **VULN-017** account-wide
takeover. Distinct from VULN-014/015 because it runs in the *deployed* environment and outlives local hook
removal.

## Suggested fix
- Emit every scalar setting with `repr()` (or build the settings object as a dict and `json.dumps` it,
  then load), never bare `'{0!s}'` interpolation (`cli.py:3064-3202`).
- Validate module/handler string settings against a strict identifier/hostname regex before serialisation.

## References
- CWE-94 (Code Injection). Sibling VULN-014 (local hooks); amplifier VULN-017.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `zappa get_zappa_settings_string zappa_settings.py code injection api_stage domain` — only deployment tutorials and django-zappa pages; no relevant results.
2. `Zappa serverless Python CVE security advisory` / GHSA / Snyk / OSV / repo security-advisories page — no Zappa advisory.
3. GitHub issue search `zappa/Zappa issues?q=prebuild_script OR callbacks OR "zappa_settings.py" injection` — no issue about unescaped interpolation into the generated settings module.
4. `cli.py` on master (fetched) — `get_zappa_settings_string` still emits `DOMAIN='{0!s}'`, `LOG_LEVEL='{0!s}'`, `APP_TYPE='{0!s}'`, `APP_MODULE='{0!s}'` etc. via `str.format`, not `repr()`; no upstream fix.

**Related but distinct public references** (same class or component, not this bug):
- None found.

**Reasoning:** No advisory, issue or write-up mentions code injection through string-formatted scalars in the generated `zappa_settings.py`. The mechanism is internal and only reachable through a hostile settings value, so it is unlikely to have been reported; nothing public found.
