# VULN-012 — Public Function URL grants lambda:InvokeFunction to Principal:* (world direct-invoke)

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: High (chains to Critical)
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- Direct invocation of the real `zappa.core.Zappa.update_function_url_policy` inside the lab container,
  with a mock `lambda_client` capturing `add_permission()` (no live AWS). Config gate: a public Function
  URL (`function_url_enabled`, authorizer `NONE`).

## Request / Response
See `request.http` / `response.txt` / `run.log`. Two `add_permission` calls are emitted; the second is:
`{StatementId: "FunctionURLAllowPublicAccessInvoke", Action: "lambda:InvokeFunction", Principal: "*"}` with
**no** `FunctionUrlAuthType`.

## Observation
`update_function_url_policy` (`core.py:1633-1649`), for `authorizer == "NONE"`, iterates
`FUNCTION_URL_PUBLIC_PERMISSION_RULES` (`core.py:67-70`). The second rule
(`"lambda:InvokeFunction", requires_auth_type=False`) produces an `add_permission` with `Principal:"*"` and
no auth-type/source condition — exactly as the static finding predicted. `lambda:InvokeFunction` is the
control-plane invoke API, so this grants **any AWS account** the ability to hand the handler an arbitrary
event (opening the Surface-B sinks VULN-001/002/024/008 cross-account).

## Side effects
None (mock AWS client; no real API calls).

## Research & references
- CWE-284 (Improper Access Control), CWE-732 (Incorrect Permission Assignment). AWS Lambda resource-policy
  docs (a `Principal:"*"` statement with no `SourceArn`/`SourceAccount` is public/cross-account).
- Upstream [#1121](https://github.com/zappa/Zappa/issues/1121)/[#1039](https://github.com/zappa/Zappa/issues/1039) (the second grant was added to avoid a 403; the unscoped-invoke security framing is the audit's).

## If FAILED / NEEDS_MANUAL
n/a — CONFIRMED at the policy-generation level. The live cross-account invoke requires a real AWS
deployment (out of lab scope), but the exact resource-policy statement Zappa builds is verified here.
