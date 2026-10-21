# VULN-005 — Unauthenticated disclosure of draft/disabled/scheduled content via cms/content

**Target name:** PublicCMS
**Target URL:** https://github.com/sanluan/PublicCMS
**Software version:** V5.202608.a
**Status**: CONFIRMED
**Severity (static)**: Medium (High for embargoed/pre-publication content)
**Target commit**: e85ab023a22b19bff5b5b0c944440ab614df467f
**Validated at**: 2026-09-19

## Preconditions
- None for the exploit (anonymous). `cms/content` is `needAppToken=false`/`needUserToken=false`
  (verified live via `/api/namespaces`).
- A non-public content item must exist. Seeded here: a DRAFT (status=0) planted via the site-2
  demo admin (admin/admin — VULN-001). The anonymous reads carry `Host: site2.dev.publiccms.com`
  only to select the tenant that holds the demo data; no auth cookie is sent.

## Request / Response
See `request.http`, `response.txt`, `evidence/single_entity_leak.json`, `evidence/public_list.json`.
- `GET /api/directive/cms/content?id=<draft>` (anonymous) → `{"object":{"title":"DRAFT_SECRET_…","status":0,…}}`.
- `GET /api/directive/cms/contentList?pageSize=200` (anonymous) → totalCount 1, only the public id=1; the draft id is absent.

## Observation
Exactly the predicted differential. The single-entity directive returns a `status=0` (draft)
item after checking only `site.getId()==entity.getSiteId()`, while the sibling list directive —
same anonymous caller — applies the public-visibility predicate and omits it. This bypasses the
editorial publication/embargo control for anyone who can supply/enumerate a content id.

**Note on tenancy:** the report's repro hit `localhost` (site 1), which is empty on this install;
the demo content lives in site 2. The leak is identical once the correct tenant Host is used —
site resolution itself is attacker-controlled via the Host header (see VULN-001).

## Side effects
Seeds one DRAFT `cms_content` row per run (title `DRAFT_SECRET_<suffix>`). Additive, non-public,
harmless. Cleanup hint in the script footer.

## Research & references
- CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-306 (Missing Authentication).
- OWASP WSTG-ATHZ-02 (IDOR/BOLA) — method: request an object by id and compare against the
  listing endpoint's visibility rules; a single-object endpoint that returns more than the list
  is a missing-filter BOLA. Sibling of CVE-2026-8737.

## If FAILED
n/a — CONFIRMED.
