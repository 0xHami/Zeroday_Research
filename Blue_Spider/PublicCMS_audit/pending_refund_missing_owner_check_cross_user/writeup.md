# VULN-010 — Cross-user payment state change via refund-create `pendingRefund`

## Header

- **Title:** Cross-user payment state change via refund-create `pendingRefund` (missing ownership check)
- **ID:** VULN-010
- **Severity:** **Medium** — CVSS 3.1 **5.4** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L`
- **Status:** CONFIRMED (dynamic)
- **Affected version / commit:** PublicCMS `V5.202608.a`, commit `e85ab023a22b19bff5b5b0c944440ab614df467f`
- **Auth required:** **Any authenticated web user** (`@Csrf` + `@SessionAttribute`; attacker uses their own session).
- **Known-issue status:** cluster of **CVE-2026-2010 / CVE-2026-8738**.

## Summary

The `refund` controller calls `pendingRefund(site.getId(), paymentId)` with an attacker-supplied `paymentId` **before** any ownership check, and `pendingRefund` filters on `siteId` and status only — not `userId` — while performing a state-changing write. Any authenticated user can therefore force another buyer's PAID payment into `PENDING_REFUND` and attach an attacker-owned refund row to it. Confirmed: attacker id=27 transitioned victim id=26's payment 1(PAID)→2(PENDING_REFUND).

## Technical details

### Root cause

`targets/PublicCMS/publiccms-parent/publiccms-trade/src/main/java/com/publiccms/logic/service/trade/TradePaymentService.java:136-149`:

```java
public boolean pendingRefund(short siteId, long paymentId) {
    TradePayment entity = getEntity(paymentId);
    if (null != entity && siteId == entity.getSiteId()
            && (entity.getStatus() == STATUS_PAID || entity.getStatus() == STATUS_REFUNDED)) {  // no userId check
        entity.setStatus(STATUS_PENDING_REFUND);   // <-- transitions ANOTHER user's payment
        ...
        historyDao.save(new TradePaymentHistory(...));
        return true;
    }
}
```

The correctly-scoped sibling `cancel():122` uses `(null == userId || entity.getUserId() == userId) && siteId == entity.getSiteId()`, confirming the omission.

### Data flow

Attacker (own valid `@Csrf` session) → `POST /tradePayment/refund` with `paymentId=<victim PAID payment>` → `TradePaymentController.refund` (`:310`, first line of the body) calls `pendingRefund(site.getId(), entity.getPaymentId())` **before** verifying ownership → `pendingRefund` checks only `siteId` + status and flips the victim's payment to `PENDING_REFUND`, writes a history row, and the controller then creates a `trade_refund` row **owned by the attacker** referencing the victim's `payment_id`.

### Why existing mitigations don't apply

`@Csrf` + `@SessionAttribute` authenticate the attacker but do not confine which `paymentId` they may act on; the service-layer function that performs the write is where the owner check belongs, and it is missing. The sibling `cancel` shows the intended guard.

## Reproduction

1. **Bring up the target** (see the manifest `## Runtime`):
   ```bash
   cd targets/PublicCMS
   DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker compose -p cvehunt_publiccms up -d --build
   bash ../../claude_audit/PublicCMS/setup/install.sh   # first run only
   ```
2. **Run the exploit** from this directory:
   ```bash
   cd claude_audit/PublicCMS/exploits/VULN-010 && ./automation.sh
   ```
   No gateway is configured, so the script seeds a victim's PAID `trade_payment` row directly — the **exploit itself** is the HTTP cross-user request. It logs in as the attacker (a different user) and `POST`s `/tradePayment/refund` with the victim's `paymentId`, then asserts the payment status changed and an attacker-owned refund row was created.
3. **Expected output:** `[OK] exploit confirmed — attacker forced victim's payment to PENDING_REFUND and created an attacker-owned refund`.
4. **Confirm exploitation:** the DB shows the victim's `trade_payment` status 1(PAID)→2(PENDING_REFUND) and a new `trade_refund` row `owner=<attacker>:pay=<victim payment>:status=0` (see `run.log` `payment status AFTER` line).

- See `request.http` / `response.txt` for the cross-user request and 302, and `run.log` for the before/after payment state.

## Impact

Authenticated cross-user integrity/DoS on other buyers' payments and refund-queue pollution: an attacker moves arbitrary paid payments into a refund-pending state and attaches spurious refund rows. Not direct theft (settlement is signed to the payer, report FP-07), but it disrupts merchant accounting and the refund workflow. Broadens the cluster with [VULN-008](../VULN-008/writeup.md) and [VULN-009](../VULN-009/writeup.md).

## Suggested fix

Add the owner check in `pendingRefund` (and pass the caller's userId from the controller), matching `cancel`:

```java
public boolean pendingRefund(short siteId, long userId, long paymentId) {
    TradePayment entity = getEntity(paymentId);
    if (null != entity
            && siteId == entity.getSiteId()
            && entity.getUserId() == userId                                          // <-- owner check
            && (entity.getStatus() == STATUS_PAID || entity.getStatus() == STATUS_REFUNDED)) {
        entity.setStatus(STATUS_PENDING_REFUND);
        ...
        return true;
    }
    return false;
}
```

Update the single caller in `TradePaymentController.refund` to pass `user.getId()`, and verify the target payment belongs to the calling user *before* creating the refund row.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 50 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `PublicCMS CVE 2025 2026 security advisory sanluan` + full PublicCMS CVE listing (releasealert.dev, 49 CVEs) — trade entries are CVE-2026-2010 (`TradePaymentService`, `paymentId`), CVE-2026-8738 (pay flow), CVE-2026-1112, CVE-2026-8737, CVE-2026-110113, CVE-2026-109160; none names `pendingRefund` or `TradePaymentController.refund`
2. GitHub Advisory Database search `publiccms`, pages 1–3 (58 advisories) — same set
3. CVE-2026-2010 (Tenable) + sanluan/PublicCMS#108 — reports `TradePaymentController.cancel` → `TradePaymentService.cancel(siteId, paymentId)` lacking a `userId` check; `pendingRefund` / `refund` not mentioned
4. CVE-2026-8738 (Tenable) — `TradeOrderController.pay`, `TradePaymentController.pay`, `AccountGatewayComponent.pay` only
5. sanluan/PublicCMS#125 — post-fix regression (public `TradePaymentController` removed in released tags incl. V5.202608.a, restored on default branch); no refund discussion
6. Fix commit 7329437 — changed `TradePaymentService.java` (diff not rendered); per this writeup `cancel()` now carries the owner check while `pendingRefund()` does not
7. (Planned WebSearch `PublicCMS pendingRefund paymentId ownership` could not be executed — shared search budget exhausted; replaced by direct fetches 2–6)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-2010 / sanluan/PublicCMS#108 — the sibling `TradePaymentService.cancel()` had the identical missing-`userId` defect (site-only check) and was fixed in commit 7329437; `pendingRefund()` in the same file was left without an owner check — this finding is effectively an incomplete-fix variant of that CVE (same file, different function and state transition)
- CVE-2026-8738 — unauthenticated pay flow; different functions
- sanluan/PublicCMS#125 — reachability caveat for the `/tradePayment/refund` entry point in released tags

**Reasoning:** No public reference names `pendingRefund` or the refund-create path, but CVE-2026-2010 publicly documents the same missing-owner-check pattern in the same service class and its fix did not cover this function. That is a partial match (same component, different sink), so confidence is set at the midpoint: the specific sink appears undisclosed, yet a vendor or CNA could reasonably fold it into the existing CVE as an incomplete fix.
