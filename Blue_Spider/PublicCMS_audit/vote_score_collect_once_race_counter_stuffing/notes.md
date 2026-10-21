# VULN-012 — Redemption race in "collect/vote/score once" → counter stuffing

**Target name:** PublicCMS
**Target URL:** https://github.com/sanluan/PublicCMS
**Software version:** V5.202608.a
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: e85ab023a22b19bff5b5b0c944440ab614df467f
**Validated at**: 2026-09-19

## Preconditions
- One authenticated web user (created via admin here). Content item to collect.

## Request / Response
See `request.http`, `response.txt`. 40 parallel `POST /collection/collect?contentId=1` from ONE
logged-in user.
- `content.collections`: before=9 → after=16 (delta **7**) in a representative run (delta=7 also on
  the manual run from before=2→9). Should be +1.
- `cms_user_collection` markers for the user: **1** (unique PK holds).

## Observation
Confirmed TOCTOU. Each request reads the per-user marker, then `updateCollections(+1)` and the
marker INSERT run as separate transactions with no lock/atomic-conditional; K concurrent requests
all pass the null-marker check and all commit their increment. The unique marker PK prevents
duplicate marker rows (so exactly 1 marker), but the counter over-counts (delta 7 for one user).
Magnitude varies per run with contention (observed 7 of 40); any delta > 1 proves the "collect
once" integrity guarantee is defeated. Same pattern applies to `/vote/vote` and `/score/score`
(class-level `@Transactional` services, non-transactional controllers).

## Side effects
Creates one user; inflates `content.collections` (cleanup hint restores it). Additive/reversible.

## Research & references
- CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization / race).
- OWASP WSTG-BUSL-* (business-logic testing) + PortSwigger "Race conditions" topic — technique:
  fire many parallel requests inside the check-then-act window ("limit overrun" race) and measure
  the over-increment of a supposedly once-per-user counter.

## If FAILED
If a run shows delta=1 (no contention won), re-run or raise `K`. The window is wide, so inflation
is reliably observed at K=40.
