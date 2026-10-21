# VULN-001 — `raw_command` event field passed straight to `exec()` (RCE)

| | |
|---|---|
| **ID** | VULN-001 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | High (Critical via VULN-012) · CVSS 3.1 **8.8** — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Surface B — `lambda:InvokeFunction` (any AWS account via VULN-012) |
| **Attacker gains** | Arbitrary Python + OS command execution inside the Lambda |

## Summary
The Lambda dispatcher contains a branch that runs an event-supplied string as Python via `exec()`, with no
authentication, allow-list, or sandbox. Anyone who can invoke the function with a `raw_command` event
executes arbitrary code in it. Verified live: a `raw_command` payload ran the OS command `id` and wrote its
output to disk.

## How it works (mechanism & code trace)
```python
# targets/Zappa/zappa/handler.py:914-920
# It's _extremely_ important we don't allow this event source
# to be overridden by unsanitized, non-admin user input.
elif event.get("raw_command", None):
    raw_command = event["raw_command"]
    exec(raw_command)          # <-- runs the event string as Python, module globals (os, sys, ... imported)
    return
```
`exec(raw_command)` executes in the handler process with the function's IAM role, network, `/tmp`, and
environment (which may hold DB creds, `REMOTE_ENV` secrets, and AWS session credentials). The library's own
comment states the "don't let untrusted input reach this" assumption but provides **no mechanism** to
enforce it — the entire trust decision is delegated to AWS invoke permissions.

**The exact defect:** `exec()` of an attacker-controlled event field (CWE-95). The exploit sends
`{"raw_command": "import os; open('/tmp/vuln001_<rand>','w').write('uid='+str(os.getuid())+' | '+os.popen('id').read())"}`; the recovered file (`response.txt`) contains the live `id` output — proving in-process code and
shell execution.

## Why it is a vulnerability (reasoning)
The invariant "only trusted, authenticated callers run code in the function" is violated: the dispatcher
treats any event that reaches it as trusted admin input. `exec()` of external data is unconditional code
injection. Its severity is *bounded by invoke-permission hygiene* — precisely what VULN-012 breaks by
granting `lambda:InvokeFunction` to `Principal:"*"`.

## Reproduction
1. Lab up; run `./run.sh` (Surface B via `/_sim/raw-event`).
2. Decisive request (`request.http`): `{"raw_command": "...os.popen('id')..."}`.
3. Proof: the marker file contains the real `id`/`uid` output (`response.txt`/`run.log`).
4. Expected `[OK] exploit confirmed` / `==> VULN-001: CONFIRMED`.

Live AWS: `aws lambda invoke --payload '{"raw_command":"import os;print(os.environ)"}' out.json`.

## Impact
Complete compromise of the function and everything its IAM role can reach: secret theft from `os.environ`,
lateral movement, and — via the account-wide default role (**VULN-017**) — account takeover. **Chains:**
VULN-012 (world-invokable) → **VULN-001** → VULN-017; pairs with VULN-008/026 (pre-poison `os.environ`).

## Suggested fix
- Remove the `raw_command`/`exec` branch (`handler.py:914-920`), or gate it behind an explicit opt-in
  setting that is **off by default** and requires a signed/HMAC'd payload.
- Never `exec()` an event field. Pair with the scoped-invoke fix in VULN-012 so invoke permission alone is
  not RCE.

## References
- CWE-95 (Eval Injection), CWE-94 (Code Injection). OWASP Serverless Top-10.
- Reachability enabler VULN-012; amplifier VULN-017; sibling VULN-002.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 55 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `Zappa serverless Python CVE security advisory` — only package-tracker pages (Safety, pyup, depscope); no Zappa CVE. OSV (PyPI/zappa), GitHub Advisory DB (`advisories?query=zappa`), Snyk (`pip/zappa`) and `github.com/zappa/Zappa/security/advisories` all return zero advisories.
2. `zappa handler.py raw_command exec remote code execution` — no relevant results (Ansible `raw` module, unrelated).
3. `zappa snyk OR huntr OR hackerone vulnerability report serverless framework python 2024 2025 2026` — no reports.
4. GitHub issue search `zappa/Zappa issues?q=raw_command OR exec OR "arbitrary code" OR RCE` — no issue describes the `raw_command` -> `exec()` branch as a vulnerability.
5. README (master) — `zappa invoke ... --raw` is documented as a feature ("invoke interpretable Python strings directly") with no security warning.

**Related but distinct public references** (same class or component, not this bug):
- README "invoke --raw" — documents the client side of this branch as an intended admin feature; not a vulnerability disclosure.
- `handler.py` in-code comment ("extremely important we don't allow this event source to be overridden by unsanitized, non-admin user input") — acknowledges the trust assumption but is not a public report.
- zappa/Zappa #1049 / #1039 — unscoped invoke permission for S3 event sources (same reachability class, different component).

**Reasoning:** No CVE, GHSA, Snyk/huntr/HackerOne report or upstream issue describes the server-side `exec(event["raw_command"])` sink as a vulnerability. Caveat: this is a documented, intentional "admin" feature whose safety is delegated entirely to `lambda:InvokeFunction` permission hygiene, so maintainers may consider it by design; the defensible novel part is its reachability through the unconditioned Function-URL `lambda:InvokeFunction` grant (VULN-012). Confidence is moderate for that reason.
