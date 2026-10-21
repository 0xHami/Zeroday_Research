# VULN-028 — HTTP API v2 silently drops `api_key_required` and downgrades a non-IAM authorizer to `NONE`

| | |
|---|---|
| **ID** | VULN-028 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | High · CVSS 3.1 **7.4** — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic — config generation)** |
| **Auth required** | None (anonymous internet). Config gate: `apigateway_version:"v2"` + a non-IAM authorizer / api_key the operator believes is enforced |
| **Attacker gains** | Full unauthenticated access to an app the operator intended to protect |

## Summary
On the v2 (HTTP API) path, Zappa's `$default` route builder maps any authorizer that isn't `AWS_IAM` to
`NONE` — emitting only a log warning — and never applies `api_key_required`. So an operator who configures a
JWT/Cognito/custom authorizer or an API key, re-deploys with `apigateway_version:"v2"`, and believes the API
is gated, actually serves the whole app unauthenticated. Verified live by driving the real route builder.

## How it works (mechanism & code trace)
```python
# targets/Zappa/zappa/core.py:2043-2049  (signature — api_key_required accepted…)
def create_api_gateway_v2_routes(self, lambda_arn, api_name=None, api_key_required=False,
                                 authorization_type="NONE", authorizer=None, ...):

# targets/Zappa/zappa/core.py:2091-2103  ($default route auth)
route = apigwv2.Route("RouteV2"); route.RouteKey = "$default"
if authorization_type == "AWS_IAM":
    route.AuthorizationType = "AWS_IAM"
elif authorization_type != "NONE":
    logger.warning("HTTP API v2 currently only supports AWS_IAM and NONE authorization types. Using NONE.")
    route.AuthorizationType = "NONE"     # <-- non-IAM authorizer silently downgraded
else:
    route.AuthorizationType = "NONE"
```
`api_key_required` is never referenced again in the v2 route/stage body. The exploit builds the route with
`api_key_required=True, authorization_type="CUSTOM"`; the generated `$default` route has
`AuthorizationType="NONE"` and no `ApiKeyRequired` (`response.txt`).

**The exact defect:** the v2 code accepts the auth settings but discards anything that isn't
`AWS_IAM`/`NONE` and ignores `api_key_required` — a silent divergence between configured and deployed
security posture (CWE-285 / CWE-1188). Contrast the v1 path, which enforces `api_key_required`
(`core.py:2365`) and builds a real Authorizer on every method. It **fails open**.

## Why it is a vulnerability (reasoning)
The invariant "the front-door auth control the operator configured is enforced" is broken: the control
evaporates with only a `logger.warning` that scrolls past in CI logs. Because v2/HTTP-API is AWS's
recommended modern path, an operator migrating v1→v2 with an existing authorizer/api-key silently exposes
their entire application. This is distinct from VULN-012 (Function-URL public-invoke over-grant).

## Reproduction
1. Lab up; run `./run.sh` (drives the real v2 route builder).
2. Proof (`response.txt`): `$default` route `AuthorizationType == "NONE"`, `ApiKeyRequired` unset, despite
   `authorization_type="CUSTOM"` + `api_key_required=True`.
3. Live AWS: deploy `{"prod":{"apigateway_version":"v2","authorizer":{"type":"COGNITO_USER_POOLS",...}}}`;
   `curl https://<api-id>.execute-api.<region>.amazonaws.com/prod/admin/users` with no token → served.
4. Expected `[OK] exploit confirmed` / `==> VULN-028: CONFIRMED`.

## Impact
Complete unauthenticated exposure of an app whose only front-door control was the (silently dropped)
authorizer/API key. All data and functionality behind the intended gate are reachable anonymously.

## Suggested fix
- If a non-IAM authorizer is configured with `apigateway_version:"v2"`, **fail the deploy** (or build a real
  HTTP-API JWT/Lambda authorizer that enforces it) rather than downgrading to `NONE` with a log line.
- If `api_key_required:true` on v2, error out (HTTP APIs don't support API keys) instead of silently
  ignoring it. Fail toward the stronger control, mirroring the safe v1 behaviour.

## References
- CWE-285 (Improper Authorization), CWE-1188 (Insecure Default Initialization).
- Upstream [#2099](https://github.com/Miserlou/Zappa/issues/2099). Distinct from VULN-012.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 50 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `zappa apigateway_version v2 HTTP API authorizer "only supports AWS_IAM and NONE" api_key_required ignored` — only generic API Gateway v2 authorizer docs; nothing on Zappa.
2. `Zappa serverless Python CVE security advisory` / GHSA / Snyk / OSV / repo security-advisories page — no Zappa advisory.
3. GitHub issue search `zappa/Zappa issues?q=apigateway_version OR "HTTP API" authorizer OR api_key_required` and cited Miserlou/Zappa #2099 — #2099 is the original HTTP-API feature request (2020) and never mentions authorizers or API keys; no later issue reports the downgrade.
4. PR #1391 "API Gateway v2 (HTTP API) Configuration Support" (merged 2025-11-10, fetched) — description states "HTTP API supports AWS_IAM and NONE authorization types" and "Falls back to NONE for unsupported auth types with warning"; no reviews, no security framing, `api_key_required` not mentioned.
5. `core.py` on master (fetched) — `$default` route still downgrades any non-IAM `authorization_type` to `NONE` with only `logger.warning`; `api_key_required` is never referenced in the v2 path.

**Related but distinct public references** (same class or component, not this bug):
- PR #1391 description — openly documents the fallback-to-NONE behaviour as a limitation (not as a security defect); the silent discard of `api_key_required` is not documented anywhere.
- AWS HTTP API docs — API keys/usage plans are unsupported on HTTP APIs (platform limitation underlying the finding).

**Reasoning:** No advisory or issue describes the v2 path as failing open. Confidence is reduced to 50 because the authorizer-to-NONE fallback is stated in the merged PR's description, so the maintainer could argue it is a documented limitation; the `api_key_required` half and the "operator believes the API is gated" security consequence are not publicly described.
