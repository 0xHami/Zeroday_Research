# VULN-008 — event `stageVariables` copied into `os.environ`, persisting across warm invocations

| | |
|---|---|
| **ID** | VULN-008 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | Medium · CVSS 3.1 **4.6** — `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:L/A:L` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Surface B — ability to place a direct-invoke event carrying `stageVariables` (any AWS account via VULN-012) |
| **Attacker gains** | Pollute the warm container's environment, bleeding into subsequent (incl. Surface-A) requests |

## Summary
At the very top of `handler()`, before any dispatch or authentication, Zappa copies every key of the
event's `stageVariables` into `os.environ` with no allow-list. Because Lambda reuses warm containers, a
value set by one direct invoke persists into subsequent invocations — including internet-facing HTTP
requests from other users. Verified live: invocation #1 set a var; a separate invocation #2 still saw it.

## How it works (mechanism & code trace)
```python
# targets/Zappa/zappa/handler.py:705-709
# Set any API Gateway defined Stage Variables as env vars
if event.get("stageVariables"):
    for key in event["stageVariables"]:
        os.environ[key] = event["stageVariables"][key]     # no allow-list, no restore
```
This runs for *any* event before the version/`httpMethod` dispatch. The exploit sends invocation #1 with
`stageVariables {ZAPPA_POLLUTED_<rand>: ...}`, then a separate invocation #2 (a `raw_command` that reads
`os.environ` and writes the value to a file); the value from #1 is present in #2 (`response.txt`), proving
persistence across invocations in the warm container.

**The exact defect:** blind copy of externally-influenced event data into `os.environ` with no allow-list,
no type check, and no per-request isolation/restore (CWE-15). Over real API Gateway `stageVariables` is
platform-set, so injecting them needs a direct invoke — not anonymous HTTP — but the persistence is what
makes it cross-request. (A non-string value additionally raises an uncaught `TypeError` — a minor
availability defect on the same line.)

## Why it is a vulnerability (reasoning)
`os.environ` is process-global and holds security-relevant config. One invoker mutating it and having the
change linger for *other* invocations on the same container crosses request/tenant boundaries (`S:C`). An
attacker can overwrite `REQUESTS_CA_BUNDLE` (weaken TLS), `DJANGO_SETTINGS_MODULE` (redirect settings), or
secrets that later Surface-A requests trust.

## Reproduction
1. Lab up; run `./run.sh` (two separate `/_sim/raw-event` invocations).
2. Proof (`response.txt`): invocation #2 reads back the var invocation #1 set.
3. Live AWS: `aws lambda invoke --payload '{"stageVariables":{"REQUESTS_CA_BUNDLE":"/tmp/evil-ca.pem"}}' out.json`; subsequent requests on the warm container see it.
4. Expected `[OK] exploit confirmed` / `==> VULN-008: CONFIRMED`.

## Impact
Config/TLS/settings poisoning that bleeds across request boundaries on a warm container; a pre-poison
primitive rather than a standalone breach. **Chains:** pairs with VULN-026 (same effect from S3); can set
`DJANGO_SETTINGS_MODULE`/DB env ahead of VULN-024.

## Suggested fix
- Allow-list the expected `stageVariables` names; ignore anything else (`handler.py:707-709`).
- Apply values into a per-request copy (or snapshot/restore `os.environ` around the request) so a mutation
  never leaks into a later invocation; validate each value is a `str`.

## References
- CWE-15 (External Control of System/Config Setting). Sibling VULN-026; feeds VULN-024.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `zappa stageVariables os.environ environment variables warm container pollution` — no relevant results (Harness/LangChain/Cloud Foundry noise).
2. `Zappa serverless Python CVE security advisory` / GHSA / Snyk / OSV / repo security-advisories page — no Zappa advisory.
3. GitHub issue search `zappa/Zappa issues?q=stageVariables OR "stage variables" environ` — no issue about the stageVariables -> `os.environ` copy.
4. README (master) — does not document stageVariables being exported to the environment; `handler.py` on master still copies every key unconditionally before dispatch.

**Related but distinct public references** (same class or component, not this bug):
- VULN-026 (`remote_env`) sibling — same CWE-15 pattern from S3 rather than the event; not public either.
- zappa #1456 — docs gap about `environment_variables` vs `aws_environment_variables`; unrelated mechanism.

**Reasoning:** Nothing public describes event `stageVariables` being written into the process environment without an allow-list or persisting across warm invocations. The impact is a pre-poison primitive requiring direct-invoke access, which lowers the chance anyone has bothered to report it; nothing found.
