# VULN-028 — HTTP API v2 downgrades non-IAM authorizer to NONE, ignores api_key

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: High
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- Direct invocation of the real `zappa.core.Zappa.create_api_gateway_v2_routes` (builds a troposphere
  template) with `api_key_required=True, authorization_type="CUSTOM"`. Config gate: `apigateway_version:"v2"`.

## Request / Response
See `request.http` / `response.txt` / `run.log`. Generated `$default` route: `AuthorizationType == "NONE"`;
`ApiKeyRequired` unset.

## Observation
`create_api_gateway_v2_routes` (`core.py:2091-2103`) sets `AuthorizationType="AWS_IAM"` only for `AWS_IAM`;
any other authorizer is downgraded to `NONE` with a `logger.warning`. `api_key_required` (`:2047`) is
accepted but never applied to the v2 route. So an operator who configured a JWT/Lambda/custom authorizer or
an API key is served **unauthenticated**. Confirmed both effects against the real builder. (Stage 08/09
NEEDS_MANUAL because the lab HTTP harness is v1-only; validated here at the config-generation level.)

## Side effects
None (builds an in-memory troposphere template; no AWS calls).

## Research & references
- CWE-285 (Improper Authorization), CWE-1188 (Insecure Default). Fails **open**.
- Upstream [#2099](https://github.com/Miserlou/Zappa/issues/2099) (v2/HTTP-API "no API keys" limitation).

## If FAILED / NEEDS_MANUAL
n/a — CONFIRMED at config generation. A full live check would deploy a real v2 stage + Cognito/JWT
authorizer and curl a protected path with no token; the generated route already proves the downgrade.
