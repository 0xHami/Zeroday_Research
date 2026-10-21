# VULN-012 — Public Function URL also grants `lambda:InvokeFunction` to `Principal:"*"` (world direct-invoke)

| | |
|---|---|
| **ID** | VULN-012 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | High (chains to Critical) · CVSS 3.1 **8.9** — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | **CONFIRMED (dynamic — policy generation)** |
| **Auth required** | None on the victim's account — the attacker uses *their own* AWS account (config gate: public Function URL) |
| **Attacker gains** | Any AWS account can direct-invoke the function with an arbitrary event → the reachability spine of cross-account RCE |

## Summary
When a Zappa project enables a public Lambda **Function URL** (authorizer `NONE`), Zappa attaches *two*
resource-policy statements. The first (`lambda:InvokeFunctionUrl`, scoped with `FunctionUrlAuthType=NONE`)
is all a public URL needs. The **second** grants the generic control-plane action `lambda:InvokeFunction`
to `Principal:"*"` with **no** `FunctionUrlAuthType`, `SourceArn`, or `SourceAccount`. That lets **any AWS
account** call `aws lambda invoke` and deliver an arbitrary event dict straight to the handler — bypassing
the HTTP path and reaching Zappa's Surface-B code-execution sinks (VULN-001/002/024). Verified live by
driving the real policy builder.

## How it works (mechanism & code trace)
**Rule table:**
```python
# targets/Zappa/zappa/core.py:67-70
FUNCTION_URL_PUBLIC_PERMISSION_RULES = (
    ("FunctionURLAllowPublicAccess",       "lambda:InvokeFunctionUrl", True),   # auth-type attached
    ("FunctionURLAllowPublicAccessInvoke", "lambda:InvokeFunction",     False), # <-- NO auth-type
)
```
**Policy builder:**
```python
# targets/Zappa/zappa/core.py:1633-1649  update_function_url_policy()
if function_url_config["authorizer"] == "NONE":
    for sid, action, requires_auth_type in FUNCTION_URL_PUBLIC_PERMISSION_RULES:
        ...
        permission_kwargs = {"FunctionName": ..., "StatementId": sid, "Action": action, "Principal": "*"}
        if requires_auth_type:                       # only the FIRST rule
            permission_kwargs["FunctionUrlAuthType"] = function_url_config["authorizer"]
        self.lambda_client.add_permission(**permission_kwargs)
```
The exploit invokes this with `{"authorizer": "NONE"}` and a mock `lambda_client`; the captured calls
(see `response.txt`) show the second statement is `Action=lambda:InvokeFunction, Principal="*"` with no
auth-type condition. **The exact defect:** the second, unconditioned `lambda:InvokeFunction` grant. A
public Function URL needs only `lambda:InvokeFunctionUrl`; `lambda:InvokeFunction` is the API `aws lambda
invoke` uses, and it delivers a caller-supplied event to `LambdaHandler.handler()`, which applies **zero**
application-layer authentication to its non-HTTP branches (`handler.py:906-939`).

Contrast Zappa's correctly-scoped event grant `create_event_permission` (`core.py:3310-3331`), which sets
`SourceAccount`; the Function-URL public path omits that scoping.

## Why it is a vulnerability (reasoning)
The security invariant "only authorized principals may invoke the function" is broken: a `Principal:"*"`
statement with no source condition is public to every AWS account. The feature's intent is "let anyone GET
the HTTPS URL"; the implementation *additionally* opens the control-plane invoke API to the world, which is
a strictly larger capability (arbitrary event dicts, not just HTTP requests). That is the precise
reachability the Surface-B RCE sinks require, turning documented "admin-only" footguns into
anonymous-cross-account RCE.

## Reproduction
1. Lab up; run `./run.sh`. It drives `update_function_url_policy(..., {"authorizer":"NONE"})` with a mock
   client.
2. Proof (`response.txt`): `add_permission(... Action=lambda:InvokeFunction, Principal=*, AuthType=<none>)`.
3. Live AWS: deploy `{"prod":{"function_url_enabled":true}}`; from an unrelated account run
   `aws lambda invoke --function-name arn:aws:lambda:<region>:<victim>:function:<fn> --payload '{"raw_command":"import os;print(os.environ)"}' out.json` — the call is authorized by this statement and the
   payload is `exec()`'d (VULN-001).
4. Expected `[OK] exploit confirmed` / `==> VULN-012: CONFIRMED`.

## Impact
Cross-account remote code execution for the common public-Function-URL deployment: any AWS account →
`lambda:InvokeFunction` → VULN-001/002/024 sinks → code execution in the function → **VULN-017** (account-
wide default role) → read/write/delete every S3 bucket, hijack Route 53, invoke any Lambda across the
victim account. This is the audit's **headline chain: VULN-012 → VULN-001/002/024 → VULN-017 = cross-account
AWS takeover.**

## Suggested fix
- Delete the `FunctionURLAllowPublicAccessInvoke` statement (`core.py:69`) — a public Function URL needs
  only `lambda:InvokeFunctionUrl`.
- If direct invoke is genuinely required, scope the `lambda:InvokeFunction` grant with `SourceAccount`
  (and/or `SourceArn`), mirroring `create_event_permission` — never `Principal:"*"` unconditioned.
- Independently add an app-layer gate on the privileged dispatch branches (VULN-001/002/024) so invoke
  permission alone ≠ RCE. Principle: least privilege + defence in depth.

## References
- CWE-284, CWE-732. AWS Lambda resource-based policy documentation.
- Chain: VULN-001/002/024 (sinks), VULN-017 (amplifier). Upstream [#1121](https://github.com/zappa/Zappa/issues/1121), [#1039](https://github.com/zappa/Zappa/issues/1039).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 60 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `zappa function_url_enabled "lambda:InvokeFunction" Principal "*" FunctionURLAllowPublicAccessInvoke` — AWS docs and Zappa PR #1455 (docs) only; nothing framing the grant as a security issue.
2. `Zappa serverless Python CVE security advisory` / GHSA / Snyk / OSV / repo security-advisories page — no Zappa advisory.
3. GitHub issue search `zappa/Zappa issues?q=InvokeFunction "Principal" OR "function url" permission OR cross-account` plus #1121, PR #1183, PR #1393, PR #1455 (all fetched) — none mention `InvokedViaFunctionUrl`, `SourceAccount` or cross-account direct invoke for Function URLs.
4. `core.py` on master (fetched) — `FUNCTION_URL_PUBLIC_PERMISSION_RULES` still adds `lambda:InvokeFunction` with `Principal:"*"` and no condition.
5. AWS "Control access to Lambda function URLs" (fetched) — AWS's own default NONE-auth policy includes `Condition: {"Bool": {"lambda:InvokedViaFunctionUrl": "true"}}` and warns that without it "the principal can invoke your function through other invocation methods".

**Related but distinct public references** (same class or component, not this bug):
- AWS Lambda docs (urls-auth) — recommend the `lambda:InvokedViaFunctionUrl` condition; generic vendor guidance, not a report against Zappa.
- zappa #1049 "Security vulnerability - Zappa s3 event settings do not limit execution ... to a specific account" and #1039 — same "unscoped invoke grant" class for S3 event permissions (`create_event_permission`), which was later scoped with `SourceAccount`; different component.
- PR #1393 (Nov 2025) / PR #1455 (May 2026) — introduce and document the two-statement policy as "required by AWS"; no security discussion.

**Reasoning:** Zappa's unconditioned `lambda:InvokeFunction` grant to `Principal:"*"` has not been publicly identified as a cross-account direct-invoke exposure; the PRs that added it present it as an AWS requirement. Confidence is only moderate because AWS's documentation explicitly describes the exact mitigation and its absence is visible in Zappa's README, so the gap is discoverable, and the related #1049 shows the maintainers already accepted the same class for S3 events.
