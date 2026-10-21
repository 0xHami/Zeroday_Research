# VULN-030 — SNS message-body `command` overrides AWS_EVENT_MAPPING (topic-publisher RCE)

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: Medium (High if the topic is broadly publishable)
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- Surface B via harness `/_sim/raw-event`, modelling an SNS record delivered to the Lambda. The lab's
  `AWS_EVENT_MAPPING` is empty (`{}`), which makes the override unmistakable — the ARN path would find no
  function.

## Request / Response
See `request.http` / `response.txt` / `run.log`. An SNS Records event with
`Sns.Message = {"command": "os.getcwd"}` on an **unmapped** topic → handler returns `"/app/_harness"`.

## Observation
`get_function_for_aws_event` (`handler.py:645-649`) parses the SNS *message body* and returns its `command`
field **before** consulting `AWS_EVENT_MAPPING[TopicArn]`. The returned dotted path flows into
`import_and_get_function` + `run_function` (`handler.py:947-949`). So a topic publisher — not merely a
`lambda:InvokeFunction` holder — chooses the callable, bypassing the admin mapping. Confirmed: `os.getcwd`
ran and returned despite the empty mapping.

## Side effects
None (benign `os.getcwd`). The RCE variant (`route_lambda_task`+`task_path`+`args`) is the same path and
would run attacker code; not executed to avoid side effects.

## Research & references
- CWE-94 (Code Injection), CWE-470 (Unsafe Reflection). Shares the VULN-002 sink. Upstream public-SNS-invoke
  concern [#1039](https://github.com/zappa/Zappa/issues/1039).

## If FAILED / NEEDS_MANUAL
n/a — CONFIRMED. Live-AWS reachability requires an `events` SNS integration on a topic the attacker can
publish to (often shared/cross-account, which is precisely when the `events` integration is used).
