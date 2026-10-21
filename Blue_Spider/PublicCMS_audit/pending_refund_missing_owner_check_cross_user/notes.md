# VULN-010 — Cross-user payment state change via refund-create pendingRefund

**Target name:** PublicCMS
**Target URL:** https://github.com/sanluan/PublicCMS
**Software version:** V5.202608.a
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: e85ab023a22b19bff5b5b0c944440ab614df467f
**Validated at**: 2026-09-19

## Preconditions
- Any authenticated web user (attacker acts with their own valid `@Csrf` session).
- A victim's PAID payment must exist. No gateway is configured on this install (payments can't be
  minted through the normal order→pay flow), so the victim's PAID `trade_payment` row is seeded
  directly. The exploit itself is the HTTP cross-user request.

## Request / Response
See `request.http`, `response.txt`.
- `POST /tradePayment/refund` with `paymentId=<victim payment>` (no `id`) → 302.
- DB after: `trade_payment` status 1(PAID) → 2(PENDING_REFUND); new `trade_refund` row owned by the
  attacker referencing the victim's `payment_id`.

## Observation
Confirmed. `refund()` calls `pendingRefund(site.getId(), paymentId)` with the attacker-chosen
paymentId before any ownership check; `pendingRefund` verifies only `siteId` + status
(PAID/REFUNDED) and mutates. The victim's payment was transitioned by a different user, and an
attacker-owned refund was attached to it (queue pollution). Not direct theft (settlement is signed
to the payer), but a cross-user integrity/DoS primitive in the CVE-2026-2010/8738 cluster.

## Side effects
Creates 2 users + 1 payment + 1 refund; mutates the seeded payment. All script-created. Cleanup hint in footer.

## Research & references
- CVE-2026-2010 / CVE-2026-8738 (trade-authz cluster). CWE-639 (BOLA — missing owner check on a
  state-changing operation).
- OWASP API Security Top 10 API1:2023 BOLA — write-side object authorization test.

## If FAILED
n/a — CONFIRMED.
