# VULN-002 — Arbitrary module import & callable invocation via event-controlled dotted paths

| | |
|---|---|
| **ID** | VULN-002 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | High · CVSS 3.1 **8.8** — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` (Critical when PR drops to N via VULN-012) |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Surface B — `lambda:InvokeFunction`, or publish to a wired SNS/async topic (VULN-030), or any AWS account when a public Function URL is enabled (VULN-012) |
| **Attacker gains** | Arbitrary in-process code execution in the Lambda |

## Summary
When an invocation event carries a `command` field, Zappa treats the string as a dotted path, imports the
named module, `getattr`s the named attribute, and calls it — with **no allow-list**. An attacker who can
deliver an event to the function therefore chooses which code runs inside it. The async transport
(`route_lambda_task`/`run_message`) extends this to an arbitrary callable *with attacker-controlled
arguments*, which is functionally remote code execution. Verified live: two unrelated stdlib modules were
imported and executed from event data alone, each returning its result to the caller.

## How it works (mechanism & code trace)
**Entry point** — `LambdaHandler.handler()` dispatches on event shape. The `command` branch:
```python
# targets/Zappa/zappa/handler.py:906-912
elif event.get("command", None):
    whole_function = event["command"]
    app_function = self.import_module_and_get_function(whole_function)
    result = self.run_function(app_function, event, context)
    ...
    return result
```
**Hop 1 — the sink.** `import_module_and_get_function` delegates to:
```python
# targets/Zappa/zappa/utilities.py:146-153
def import_and_get_function(dotted_path: str) -> Any:
    module, function = dotted_path.rsplit(".", 1)
    app_module = importlib.import_module(module)   # attacker-chosen module
    return getattr(app_module, function)           # attacker-chosen attribute
```
There is no validation that `module` belongs to the app package, nor any allow-list of callables.
**Hop 2 — invocation.** `run_function` (`handler.py:615-632`) calls the resolved object, trying
`(event, context)`, then `(event)`, then `()`. Zero-arg callables such as `os.getcwd` therefore execute
and return their value, which the handler returns to the caller.

**The exact defect** is that a *value from the untrusted event* (`event["command"]`) is used as the
target of `importlib.import_module` + `getattr` + call. The library assumes only "admin" callers set
`command`; nothing enforces that assumption.

**Why the platform doesn't save it** — in AWS, `command` events arrive through `lambda:InvokeFunction`
(or a wired event source). That is *not* internet-anonymous, but it is far from "admin only": VULN-012
(public Function URL) grants `lambda:InvokeFunction` to `Principal:"*"`, making this reachable by **any
AWS account**, and VULN-030 lets an SNS body carry the `command`, reachable by any topic publisher.

## Why it is a vulnerability (reasoning)
The trust boundary being violated is "who may choose the code that runs in the function." A dispatch
feature intended to run *pre-registered* admin tasks instead runs *any* importable callable named at
invocation time. The async variant even forwards attacker `args`/`kwargs` to that callable
(`asynchronous.py:305-309`), so `{"task_path":"os.system","args":["id"]}` is `os.system("id")`. This is
not "invoke a known task" — it is "call anything with anything," which is code injection (CWE-94) via
unsafe reflection (CWE-470).

## Reproduction
1. Bring the lab up (`docker compose -f targets/Zappa/_harness/docker-compose.yml -p cvehunterlab_zappa up -d`).
2. Run `./run.sh`. It POSTs two direct-invoke events to `/_sim/raw-event`.
3. Decisive request (see `request.http`):
   ```
   POST /_sim/raw-event  {"command": "os.getcwd"}
   ```
   Response (`response.txt`): `{"result": "/app/_harness"}` — the function imported `os` and ran
   `os.getcwd()`. `{"command": "platform.platform"}` → `"Linux-...-glibc2.41"`, proving an *arbitrary
   other* module is loaded and called.
4. Expected: `[OK] exploit confirmed` and `==> VULN-002: CONFIRMED`.

Live AWS equivalent: `aws lambda invoke --payload '{"command":"os.getcwd"}' out.json`; the RCE variant:
`--payload '{"command":"zappa.asynchronous.route_lambda_task","task_path":"os.system","args":["id"]}'`.

## Impact
Arbitrary in-process execution in the Lambda: read the function's environment/secrets, reach anything its
role can reach, and pivot. Blast radius is the whole AWS account because the default execution role
(VULN-017) grants `s3:*`, `route53:*`, `lambda:InvokeFunction *`, etc. **Chaining:** VULN-012 →
**VULN-002** → VULN-017 = cross-account account takeover; VULN-030 (SNS body) and the S3 `configurationId`
vector broaden reachability beyond `lambda:InvokeFunction`.

## Suggested fix
- In `import_and_get_function` (`utilities.py:146-153`), reject any dotted path whose top-level module is
  not inside the deployed app's own package, and resolve tasks only against an explicit allow-list
  registered at deploy time.
- Never derive a callable from an ARN (`resources[0]`), an SNS message body, or an S3 `configurationId`;
  consult only the admin-configured `AWS_EVENT_MAPPING`.
- Separate the async-task transport from a generic "call any function" primitive. Principle: allow-list,
  not denylist, and keep the set of runnable callables closed and deploy-time-fixed.

## References
- CWE-94 (Code Injection), CWE-470 (Unsafe Reflection).
- OWASP WSTG-INPV-11 (Code Injection).
- Sibling finding VULN-001 (`raw_command`→`exec`), reachability enabler VULN-012, amplifier VULN-017, SNS
  variant VULN-030.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 55 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `Zappa serverless Python CVE security advisory` / `GHSA zappa github advisory pypi zappa vulnerability` — no Zappa CVE or GHSA; OSV, GitHub Advisory DB, Snyk and the repo's security/advisories page are all empty.
2. `zappa "command" event import_module arbitrary import handler lambda vulnerability` — only generic dynamic-import guidance (CodeGuru, Sourcery) and other projects' CVEs (djust CVE-2026-61599, PraisonAI CVE-2026-40156); nothing on Zappa.
3. `zappa snyk OR huntr OR hackerone vulnerability report ... 2024 2025 2026` — no reports.
4. GitHub issue search `zappa/Zappa issues?q=raw_command OR exec OR "arbitrary code" OR RCE` — no issue describes the `command` -> `import_and_get_function` sink or `route_lambda_task`/`task_path` as a vulnerability.
5. `utilities.py` on master (fetched) — `import_and_get_function` still has no allow-list; no upstream fix.

**Related but distinct public references** (same class or component, not this bug):
- README "invoke" / async task docs — document `zappa invoke <dotted.path>` and `zappa.asynchronous` as intended features; not a vulnerability disclosure.
- CVE-2026-61599 (djust) — same "client-supplied dotted path imported" class in an unrelated project.
- zappa/Zappa #1049 / #1039 — unscoped S3-event invoke permission (reachability class, different component).

**Reasoning:** No public advisory, report or issue describes the event-controlled dotted-path import + call (`handler.py` `command` branch, `utilities.py` `import_and_get_function`, async `task_path` with attacker args) as a vulnerability. Caveat: like VULN-001 this is a documented admin feature guarded only by invoke permission, so the maintainer may treat it as by design; the novel claim rests on the VULN-012 / VULN-030 reachability. Confidence moderate.
