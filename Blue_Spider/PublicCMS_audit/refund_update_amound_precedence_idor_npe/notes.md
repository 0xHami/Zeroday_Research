# VULN-009 — IDOR + NPE in refund updateAmound via operator-precedence bug

**Target name:** PublicCMS
**Target URL:** https://github.com/sanluan/PublicCMS
**Software version:** V5.202608.a
**Status**: CONFIRMED (cross-user edit). NPE-on-nonexistent-id: code-present, surfaces as HTTP 404.
**Severity (static)**: Medium
**Target commit**: e85ab023a22b19bff5b5b0c944440ab614df467f
**Validated at**: 2026-09-19

## Preconditions
- Any authenticated web user (own `@Csrf` session).
- A PAID payment (to pass the `pendingRefund` gate) + a victim-owned refund in status REFUSE(3).
  Seeded directly (no gateway configured); the exploit is the HTTP cross-user edit.

## Request / Response
See `request.http`, `response.txt`.
- `POST /tradePayment/refund` with `id=<victim REFUSE refund>`, `paymentId=<PAID payment>`,
  `amount=999.00`, `reason=PWNED_<S>` → 302.
- DB after: refund `amount=999.00`, `reason=PWNED_<S>`, `status=0`(PENDING), `user_id` still the victim.

## Observation
Confirmed. The guard `(A && owner && PENDING) || (status==REFUSE)` is true for any REFUSE refund
regardless of `userId`, so attacker id=29 edited victim id=28's refund — changing amount/reason and
resetting status to PENDING (re-entering the merchant approval queue). The actual source
(`updateAmound`) matches the report's excerpt exactly. The NPE branch (nonexistent `refundId` →
`entity.getStatus()` on null) is present in code; live it surfaces as HTTP 404 (abnormal
termination) rather than a logged 500 — the endpoint errors out, distinct from the normal 302.

## Side effects
Creates 2 users + 1 payment + 1 refund; edits the seeded refund. All script-created. Cleanup hint in footer.

## Research & references
- CVE-2026-2010 (class). CWE-639 (BOLA) + CWE-476 (NULL deref). CWE-783 (operator-precedence logic error).
- OWASP WSTG-ATHZ-02 (IDOR) — substitute another user's object id into a write and confirm mutation.

## If FAILED
n/a for the cross-user edit — CONFIRMED.
