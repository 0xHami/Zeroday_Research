# VULN-011 — Unauthenticated deanonymization of any user's votes/scores/collections by userId

**Target name:** PublicCMS
**Target URL:** https://github.com/sanluan/PublicCMS
**Software version:** V5.202608.a
**Status**: CONFIRMED (scores + collections proven; votes need an existing poll, same code path)
**Severity (static)**: Medium
**Target commit**: e85ab023a22b19bff5b5b0c944440ab614df467f
**Validated at**: 2026-09-19

## Preconditions
- None for the exploit (anonymous). `userScoreList`/`userCollectionList`/`userVoteList` are
  needAppToken=false/needUserToken=false (verified live).
- A victim with recorded activity. Seeded via the app: admin creates a user; the user collects
  and scores an existing content item.

## Request / Response
See `request.http`, `response.txt`, `evidence/collections.json`, `evidence/scores.json`.
- `GET /api/directive/cms/userCollectionList?userId=<v>` → `{"list":[{"id":{"userId":"<v>","contentId":"1"},…}]}`.
- `GET /api/directive/cms/userScoreList?userId=<v>` → `{"list":[{"id":{"userId":"<v>","itemType":"content","itemId":"1"},"score":5,"ip":"172.19.0.1",…}]}`.

## Observation
Confirmed as a targeted deanonymization primitive: naming any `userId` returns that user's exact
activity to an anonymous caller. The score record additionally discloses the **client IP** that
recorded the score — extra deanonymization signal not called out in the static finding. Distinct
from VULN-005's blind id iteration: here the harm is picking a *person* (userId) and reading their
behaviour. `userVoteList` is the same pattern (would expose non-anonymous poll choices) but needs
a poll present; not exercised (no polls seeded), noted as same-class.

## Side effects
Seeds one web user + one score + one collection per run. Additive. Cleanup hint in script footer.

## Research & references
- CWE-639 (BOLA) / CWE-306 (Missing Authentication); privacy angle (CWE-359).
- OWASP API Security Top 10 "API1:2023 BOLA" — method: substitute another principal's id into a
  per-user listing endpoint and confirm cross-user data returns. Sibling of CVE-2026-8737.

## If FAILED
n/a — CONFIRMED for scores + collections.
