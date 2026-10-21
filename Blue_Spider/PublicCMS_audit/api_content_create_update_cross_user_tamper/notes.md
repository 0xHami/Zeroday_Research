# VULN-007 — Cross-user content tampering / unpublish via /api/contentCreate update branch

**Target name:** PublicCMS
**Target URL:** https://github.com/sanluan/PublicCMS
**Software version:** V5.202608.a
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: e85ab023a22b19bff5b5b0c944440ab614df467f
**Validated at**: 2026-09-19

## Preconditions
- An app token authorized for `contentCreate` (provisioned via admin here) AND a valid user token
  (any registered user; obtained via `/api/login`). Both required; not anonymous.

## Request / Response
See `request.http`, `response.txt`, `evidence/content_after.txt`.
- `GET /api/contentCreate?id=<victim>&categoryId=14&modelId=article&title=PWNED_BY_ATTACKER_<S>&text=defaced_<S>`
  with headers `appToken`, `authToken`, `authUserId=<attacker>` → `{"result":"success","contentId":"<victim>"}`.
- DB after: victim content `title=PWNED_BY_ATTACKER_<S>`, `status=2`, `user_id=2` (unchanged owner).

## Observation
Confirmed exactly. The victim article (owner user id=2 = admin, status=1 NORMAL) was overwritten by
attacker user id=12 — a different principal — because the update branch checks only `siteId`, never
`oldEntity.getUserId()==user.getId()`. The status also dropped 1→2 (PEND) since `status` is not in
`ignoreProperties`, i.e. a published article was silently unpublished/censored on top of the content
overwrite. Owner field is left unchanged (so the victim still "owns" the defaced/unpublished item).

## Side effects
Creates one app + app token, one victim article, one attacker user per run (random suffix), and
mutates the victim article it created. Self-contained; cleanup hint in script footer.

## Research & references
- CWE-639 (Authorization Bypass Through User-Controlled Key / BOLA — missing object-level owner check).
- OWASP API Security Top 10 "API1:2023 BOLA" and WSTG-ATHZ-02 — method: perform a write against
  another principal's object id with a valid-but-unrelated session and confirm it mutates.

## If FAILED
n/a — CONFIRMED.
