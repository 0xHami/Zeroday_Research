# VULN-009 — IDOR + NPE in refund `updateAmound` via an operator-precedence bug

## Header

- **Title:** IDOR + NULL-deref in refund `updateAmound` caused by an operator-precedence bug
- **ID:** VULN-009
- **Severity:** **Medium** — CVSS 3.1 **5.4** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L`
- **Status:** CONFIRMED (dynamic) — cross-user edit proven. NPE-on-nonexistent-id present in code; surfaces as HTTP 404.
- **Affected version / commit:** PublicCMS `V5.202608.a`, commit `e85ab023a22b19bff5b5b0c944440ab614df467f`
- **Auth required:** **Any authenticated web user** (the endpoint is `@Csrf` + `@SessionAttribute`; the attacker acts with their own valid session).
- **Known-issue status:** class of **CVE-2026-2010**; the sink is possibly novel.

## Summary

A missing pair of parentheses turns the ownership guard in `TradeRefundService.updateAmound` into `(entity != null && owner && PENDING) || (status == REFUSE)`. When a target refund's status is `REFUSE`, the whole condition is true **regardless of who owns it**, so any authenticated user can edit another user's refused refund — changing its amount and reason and resetting it to `PENDING` (re-entering the merchant approval queue). The same bug removes the null guard, so a non-existent `refundId` dereferences `null`. Confirmed: attacker id=29 edited victim id=28's REFUSE refund.

## Technical details

### Root cause

`targets/PublicCMS/publiccms-parent/publiccms-trade/src/main/java/com/publiccms/logic/service/trade/TradeRefundService.java:73-84`:

```java
public boolean updateAmound(long refundId, long userId, BigDecimal amount, String reason) {
    TradeRefund entity = getEntity(refundId);
    if (null != entity && entity.getUserId() == userId && entity.getStatus() == STATUS_PENDING
            || entity.getStatus() == STATUS_REFUSE) {          // <-- D bypasses the owner+null check
        entity.setAmount(amount);
        entity.setReason(reason);
        entity.setStatus(STATUS_PENDING);
        entity.setUpdateDate(CommonUtils.now());
        return true;
    }
    return false;
}
```

Java binds `&&` tighter than `||`, so the guard parses as `(entity != null && owner && PENDING) || (status == REFUSE)`.

### Data flow

Attacker (own valid `@Csrf` session) → `POST /tradePayment/refund` with `id=<victim REFUSE refund>` → `TradePaymentController.java:324` calls `updateAmound(refundId, attackerUserId, amount, reason)` → for a REFUSE refund the right operand `status == REFUSE` short-circuits the guard to true, ignoring `userId` → the victim's refund amount/reason are overwritten and status set to `PENDING`. If `refundId` doesn't exist, the left group short-circuits on `null` and the right operand dereferences `entity` → NPE (surfaces as HTTP 404).

### Why existing mitigations don't apply

Every other trade ownership check is correctly parenthesized — e.g. `updateStatus`/`cancel` use `(null == userId || entity.getUserId() == userId)`. This single line is the outlier; the `@Csrf`/`@SessionAttribute` on the controller do not help because the attacker is a legitimately authenticated user acting on someone else's object.

## Reproduction

1. **Bring up the target** (see the manifest `## Runtime`):
   ```bash
   cd targets/PublicCMS
   DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker compose -p cvehunt_publiccms up -d --build
   bash ../../claude_audit/PublicCMS/setup/install.sh   # first run only
   ```
2. **Run the exploit** from this directory:
   ```bash
   cd claude_audit/PublicCMS/exploits/VULN-009 && ./automation.sh
   ```
   No payment gateway is configured, so the script seeds the preconditions directly (a PAID payment + a victim-owned refund in status `REFUSE`) — the **exploit itself** is the HTTP cross-user edit. It logs in as the attacker (a different user) and `POST`s the refund edit against the victim's refund id, then asserts the amount/reason changed and status went 3→0.
3. **Expected output:** `[OK] exploit confirmed — attacker(id=29) edited victim(id=28)'s REFUSE refund (amount/reason changed, status 3->0)`.
4. **Confirm exploitation:** the DB shows the victim's refund `amount=999.00`, `reason=PWNED_<S>`, `status=0` (PENDING), `user_id` still the victim (see `run.log` `refund AFTER:` line). To isolate this bug from [VULN-010](../VULN-010/writeup.md), the seeded refund is already in `REFUSE`.

- See `request.http` / `response.txt` for the cross-user edit, and `run.log` for the before/after refund state.

## Impact

Cross-user tampering of refund records: an attacker re-opens another buyer's *refused* refunds with attacker-chosen amounts and reasons, polluting the merchant's approval queue and potentially causing an operator to approve a manipulated refund. The same bug is an authenticated NPE DoS on non-existent ids. Not direct theft — refunds require admin approval and pay the original payer. Part of the cluster with [VULN-008](../VULN-008/writeup.md) and [VULN-010](../VULN-010/writeup.md).

## Suggested fix

One-line parenthesization plus a null guard:

```java
public boolean updateAmound(long refundId, long userId, BigDecimal amount, String reason) {
    TradeRefund entity = getEntity(refundId);
    if (null != entity
            && entity.getUserId() == userId                                  // owner check now always applies
            && (entity.getStatus() == STATUS_PENDING || entity.getStatus() == STATUS_REFUSE)) {
        entity.setAmount(amount);
        entity.setReason(reason);
        entity.setStatus(STATUS_PENDING);
        entity.setUpdateDate(CommonUtils.now());
        return true;
    }
    return false;
}
```

The `null != entity` and `entity.getUserId() == userId` conditions must gate *both* status cases — wrapping the two status checks in parentheses fixes the precedence and the NPE at once.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `PublicCMS CVE 2025 2026 security advisory sanluan` + full PublicCMS CVE listing (releasealert.dev, 49 CVEs) — trade entries are CVE-2026-2010 (`TradePaymentService`, `paymentId`), CVE-2026-8738 (`TradeOrderController.pay` / `TradePaymentController.pay` / `AccountGatewayComponent.pay`), CVE-2026-1112, CVE-2026-8737, CVE-2026-110113, CVE-2026-109160 (`getSafeUrl` `returnUrl` open redirect on `pay`); nothing on `TradeRefundService`, `updateAmound`, or refunds
2. GitHub Advisory Database search `publiccms`, pages 1–3 (58 advisories) — same set
3. CVE-2026-2010 (Tenable) + sanluan/PublicCMS#108 — reports `TradePaymentController.cancel` → `TradePaymentService.cancel(siteId, paymentId)` with a site-only check; `refund`, `pendingRefund`, `updateAmound` not mentioned
4. CVE-2026-8738 (Tenable) — pay-flow functions only
5. sanluan/PublicCMS#125 (Aug 2026) — released tags including V5.202608.a removed the public `TradePaymentController` as part of the CVE-2026-2010 fix, while the default branch restored it; does not discuss refund logic
6. Fix commit 7329437 — touched `TradePaymentController.java` / `TradePaymentService.java` (diff not rendered) and two other controllers; `TradeRefundService.java` not changed
7. GitHub issue search `… refund …` — only #125, #113, #108, #107
8. (Planned WebSearch `PublicCMS TradeRefundService updateAmound IDOR` could not be executed — shared search budget exhausted; replaced by direct fetches 2–7)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-2010 / sanluan/PublicCMS#108 — IDOR in `TradePaymentService.cancel` (site-only check); same trade module, different service and function
- CVE-2026-8738 — unauthenticated pay flow (`TradeOrderController.pay` etc.); different function
- sanluan/PublicCMS#125 — reachability caveat: the public `TradePaymentController` (host of the `/tradePayment/refund` entry point used here) is reported absent in released tag V5.202608.a but present on the default branch; confirm the exact audited commit when disclosing

**Reasoning:** No public CVE, advisory or issue names `TradeRefundService.updateAmound` or the operator-precedence defect that drops the owner / null guard for `REFUSE` refunds. The surrounding trade-payment code has several public authorization CVEs in 2026, so the area is under active external scrutiny and a private report cannot be excluded, but the refund-amount sink itself appears undisclosed.
