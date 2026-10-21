# VULN-030 — SNS message-body `command` overrides `AWS_EVENT_MAPPING` (topic-publisher RCE)

| | |
|---|---|
| **ID** | VULN-030 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | Medium (High if broadly publishable) · CVSS 3.1 **6.8** — `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Publish access to a wired SNS topic (Surface B, broader than `lambda:InvokeFunction`) |
| **Attacker gains** | Import + invoke an arbitrary callable (→ RCE via the VULN-002 args variant) |

## Summary
When Zappa handles an SNS record it honours a `command` field inside the (publisher-controlled) message
body and returns it as the function to run — **before** consulting the admin-configured
`AWS_EVENT_MAPPING`. So anyone who can publish to a subscribed topic chooses which importable callable the
Lambda runs, bypassing the mapping entirely. Verified live: an SNS event with body `{"command":"os.getcwd"}`
on an *unmapped* topic caused Zappa to run `os.getcwd()` and return `/app/_harness`.

## How it works (mechanism & code trace)
**Entry point** — the `Records` branch dispatches to `get_function_for_aws_event(records[0])`
(`handler.py:942-945`), which for SNS does:
```python
# targets/Zappa/zappa/handler.py:645-652
if "Sns" in record:
    try:
        message = json.loads(record["Sns"]["Message"])
        if message.get("command"):
            return [message["command"]]          # <-- publisher-chosen path wins
    except ValueError:
        pass
    arn = record["Sns"].get("TopicArn")
...
value = self.settings.AWS_EVENT_MAPPING.get(arn)  # only reached if there was no body `command`
```
**Sink** — the returned path is fed to `import_and_get_function` + `run_function`:
```python
# targets/Zappa/zappa/handler.py:947-949
app_function = self.import_module_and_get_function(whole_function)
result = self.run_function(app_function, event, context)
```
This is the **same sink as VULN-002** (`utilities.py:146-153`, no allow-list), reached through the SNS body.

**The exact defect** — the dispatcher trusts a field in the *message body* to name the callable, overriding
the admin mapping. Three feature-specific facts make it worse than a plain direct-invoke: (1) the vector is
the message body, not a Lambda invoke; (2) it overrides `AWS_EVENT_MAPPING`, so even a correctly restricted
mapping offers no protection; (3) reachability is "anyone who can publish to the topic" — broader than
`lambda:InvokeFunction` when the topic is shared/cross-account (a common reason to use an `events` SNS
integration).

## Why it is a vulnerability (reasoning)
The trust boundary "only the admin decides which function an event source runs" is violated: a message
publisher does. Combined with VULN-002's args variant, a body of
`{"command":"zappa.asynchronous.route_lambda_task","task_path":"subprocess.check_output","args":[["id"]]}`
yields `subprocess.check_output(["id"])` — arbitrary code execution reachable via a *topic-publish*
permission.

## Reproduction
1. Lab up; run `./run.sh`.
2. Decisive request (`request.http`): an SNS Records event with `Sns.Message = {"command":"os.getcwd"}` on
   an ARN absent from `AWS_EVENT_MAPPING`.
3. Response (`response.txt`): `{"result": "/app/_harness"}` — the body's `command` selected and ran the
   callable despite the empty mapping.
4. Expected `[OK] exploit confirmed` / `==> VULN-030: CONFIRMED`.

Live AWS: publish the same JSON to the subscribed topic.

## Impact
Topic-publisher RCE that bypasses the admin's event mapping — a wider surface than the direct-invoke
findings when the topic is shared. **Chains:** VULN-030 → VULN-002 sink → VULN-017 (account-wide role) =
account takeover reachable via a publish grant. The S3 `configurationId` vector (`handler.py:640-642`) is a
narrower sibling into the same sink.

## Suggested fix
- In `get_function_for_aws_event` (`handler.py:645-649`), **never** derive the callable from the SNS message
  body; consult only `AWS_EVENT_MAPPING[TopicArn]`, and apply the same allow-list fix as VULN-002.
- Document that subscribing a function to a shared/third-party topic exposes this override path unless the
  sink is locked to an allow-list.

## References
- CWE-94 (Code Injection), CWE-470 (Unsafe Reflection).
- Shared sink VULN-002; blast-amplifier VULN-017; upstream [#1039](https://github.com/zappa/Zappa/issues/1039).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `zappa SNS message "command" get_function_for_aws_event AWS_EVENT_MAPPING override topic publisher` — only generic Lambda event-source-mapping docs and a book excerpt; nothing on the SNS body `command` override.
2. `Zappa serverless Python CVE security advisory` / GHSA / Snyk / OSV / repo security-advisories page — no Zappa advisory.
3. GitHub issue search `zappa/Zappa issues?q=... "SNS" command ...` and cited #1039 (fetched) — #1039/#1049 concern unscoped S3-event invoke permissions; #1421 is about creating multiple SNS subscriptions; nothing about message-body `command`.
4. README (master) "Executing in Response to AWS Events" — documents only the `function` field in `events` settings (`AWS_EVENT_MAPPING`) and `kwargs`; the SNS-body `command` override is undocumented. `handler.py` on master still returns `[message["command"]]` before consulting the mapping.

**Related but distinct public references** (same class or component, not this bug):
- zappa #1049 / #1039 — cross-account event-source invocation exposure for S3 triggers (reachability class, different component).
- VULN-002 sibling — same `import_and_get_function` sink reached via direct invoke.

**Reasoning:** The undocumented precedence of an SNS message-body `command` over the admin-configured `AWS_EVENT_MAPPING` has not been described publicly; the only adjacent discussions are about scoping event-source permissions. The sink itself is the documented `command` feature, which is the main caveat on confidence.
