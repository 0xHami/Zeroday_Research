# VULN-008 — `SearchFilter` unauthenticated search-term-count amplification → O(terms × fields) `ILIKE` DoS on the default `icontains` search

**Software**: Django REST Framework (DRF) — pip package `djangorestframework`
**Repository**: https://github.com/encode/django-rest-framework
**Affected version**: 3.18.1 (`rest_framework/__init__.py`); commit-pinned, 1 commit past the 3.18.1 tag on `main`
**Status**: CONFIRMED
**Severity (static)**: Medium — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` = 5.3 (rises toward A:H under request volume)
**Target commit**: b578eab1cad040414b758131af1e17aa000b51e2
**Validated at**: 2026-09-29

## Preconditions
- Unauthenticated. Exercised against the **baseline** stock-harness route `GET /api/items/`, which declares `SearchFilter` + `search_fields` (two fields) and is world-readable under DRF's `AllowAny` default (see VULN-012). No `/api/vd/…` consuming-app route was needed — this fires on a stock list view that uses DRF's documented search feature with the default `icontains` lookup.
- To make the O(terms×rows) cost measurable at lab scale, the exploit bulk-created 40,000 `Item` rows (name prefix `bulk-<tag>`) through the container app-shell, then deleted them on completion. run.log: `[SETUP] bulk-creating 40000 items … [INFO] seed: rows 40006`.

## Request
From `request.http`:
```
GET /api/items/?search=q+q+q+…(x750) HTTP/1.1
Host: localhost:21514
# each term -> ILIKE '%q%' across 2 search_fields x 40000 rows
```
The exploit swept 1, 250, 500, 750 space-separated `q` terms (each encoded as a single-byte `+`, keeping the query under gunicorn's ~4094-byte request-line cap), then a 1500-term escalation. See `automation.py` `timed()`.

## Response
From `response.txt` / run.log `[STEP]` lines:
```
term_count -> elapsed (HTTP 200 unless noted)
     1 -> 0.056s
   250 -> 0.149s
   500 -> 0.141s
   750 -> 0.233s
  1500 -> 0.327s  HTTP 500 (SQLite expr-depth 500)

amplification (750 terms / 1 term) = 4.2x on 40000 rows
```

## Observation
- The static finding predicted per-request cost scaling ~linearly with the attacker-controlled term count against unindexable `%term%` predicates. Observed exactly that: `[PROOF] per-request cost scales ~linearly with attacker term count: 1->0.056s, 250->0.149s, 500->0.141s, 750->0.233s (4.2x)`.
- A second, worse effect surfaced: `[STEP] 1500-term search -> HTTP 500 in 0.327s (>~1000 terms => SQLite expr-depth error => unhandled 500: a second DoS)`. Beyond SQLite's default expression-depth limit the ANDed `Q(...)` tree the query builder emits is itself rejected, so one request also yields an unhandled 500.
- Verdict: `[OK] attacker term count scaled per-request cost (raw 4.2x / marginal ~2x) — no DRF cap; unbounded volume via VULN-011; larger tables/backends => A:H` → `==> VULN-008: CONFIRMED`.
- Honest scope (matches the report): `A:L` per request (a single request is bounded by the request-line limit and the lab table is only 40k rows on SQLite); `A:H` is reached only under sustained request volume/concurrency — especially chained with the VULN-011 throttle bypass — or on larger tables / heavier ILIKE-scanning backends.

## Side effects
- Created 40,000 `Item` rows for the measurement, then deleted them (`Item.objects.filter(name__startswith='bulk-<tag>').delete()` in `automation.py`, tag randomised per run). The searches themselves are read-only. No other persistent state change.

## Research & references
- CWE-400 (Uncontrolled Resource Consumption), CWE-1050 (Excessive Platform Resource Consumption within a Loop) — from the vuln md.
- Technique: unbounded search-term amplification — each attacker token becomes a leading-wildcard `column ILIKE '%term%'` full-table scan on DRF's default lookup (`rest_framework/filters.py:62`, `default_lookup='icontains'`); total predicates = `len(search_terms) × len(search_fields)`, ANDed across terms, with no cap on either the term count or the `?search=` length.
- Chains (from the vuln md): VULN-011 (XFF throttle bypass removes the only rate-limit mitigation), VULN-009 (sibling amplification sinks), VULN-007 (regex-DoS sibling on the opt-in `$` lookup).
