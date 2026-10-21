# VULN-008 — `SearchFilter` unauthenticated search-term-count amplification → O(terms × fields) `ILIKE` DoS on the default `icontains` search

- **Software**: Django REST Framework (DRF) — `djangorestframework`
- **Repository**: https://github.com/encode/django-rest-framework
- **Affected version**: 3.18.1 (`rest_framework/__init__.py`), commit-pinned 1 commit past the 3.18.1 tag on `main`
- **Commit**: b578eab1cad040414b758131af1e17aa000b51e2
- **Severity**: Medium — **CVSS 3.1**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`
- **Status**: CONFIRMED (dynamic)
- **Auth required**: none — the baseline list route `/api/items/` is world-readable under DRF's `AllowAny` default (VULN-012); a single anonymous GET triggers it.
- **What an attacker gains**: an unauthenticated DoS amplifier — one GET forces `O(terms × fields × rows)` unindexable `ILIKE` scans, and a term count above the DB expression-depth limit crashes the query into an unhandled HTTP 500.

## Summary
DRF's `SearchFilter` reads the `?search=` query parameter with no length or term-count cap and, using the default `icontains` lookup, builds one `column ILIKE '%term%'` predicate per `(search-term, search-field)` pair, ANDed across terms. The term list is fully attacker-controlled (`?search=a a a a …`), so a single anonymous request against any list view that declares `search_fields` forces a number of leading-wildcard, unindexable full-table scans that scales with the attacker's token count. Validated against the stock harness route `/api/items/` (two `search_fields`) on a 40,000-row table: request time rose 4.2x from a 1-term to a 750-term search, and a 1500-term search produced an unhandled HTTP 500 (SQLite expression-depth limit) — a second denial-of-service path from the same input. The flaw is DRF's own missing default guard; it needs only the documented default configuration (a `SearchFilter` + `search_fields`, no opt-in).

## How it works (mechanism & code trace)
Entry point — the `?search=` value is read and split with no bound. Per the vuln md, `rest_framework/filters.py:74-82` reads the search term (a `CharField` with no `max_length`, cross-referenced from VULN-007) and `search_smart_split` splits it into an **unbounded** list of terms on whitespace/commas.

Sink — `filter_queryset` fans each term across every search field and ANDs the terms together (`rest_framework/filters.py:138-167`, paraphrased in the vuln md):
```python
conditions = []
for term in search_terms:
    queries = [Q(**{orm_lookup: term}) for orm_lookup in orm_lookups]
    conditions.append(reduce(operator.or_, queries))
queryset = queryset.filter(reduce(operator.and_, conditions))
```
The defect: the number of predicates is `len(search_terms) × len(search_fields)`, and `search_terms` is attacker-controlled with no cap. Each predicate uses DRF's default lookup — `default_lookup = 'icontains'` (`rest_framework/filters.py:62`) — which compiles to `column ILIKE '%term%'`. The leading `%` makes the predicate **unindexable**, forcing a full-column scan for every `(term, field)` pair on every row. Related search fields (`author__name`) add JOINs; an m2m search field trips `must_call_distinct`, wrapping the query in an `Exists(...)` subquery and multiplying cost again.

Why the framework doesn't save it: there is no `max_length`/term-count guard anywhere in `get_search_terms` or `filter_queryset` (the vuln md pins the missing guard at `filters.py:74-82`). The only request-level bound is the WSGI server's request-line limit (gunicorn ~4094 bytes ≈ up to ~1800 one-char terms), which caps a *single* request but does nothing about aggregate volume — and, separately, once the term count exceeds the database's expression-depth limit (~1000 for SQLite) the generated `Q(...)` tree is itself rejected, surfacing as an unhandled 500.

## Why it is a vulnerability (reasoning)
The trust boundary crossed is unauthenticated client input → database query cost. A search endpoint should bound the work a single anonymous request can impose; here the attacker sets that work linearly (per-request) and without limit (in aggregate). This is not by-design: DRF documents `SearchFilter`/`search_fields` as the ordinary way to add search, with `icontains` as the shipped default, so a typical, correct-looking configuration is exploitable with no opt-in. It is a DRF fail-open default (no term-count/length cap on `?search=`, unindexable `icontains` default), realized by documented usage. The secondary unhandled-500 at high term counts is a defect regardless of table size — the framework builds a query it cannot execute from ordinary user input.

## Reproduction
From a clean lab (`http://localhost:21514`, DRF 3.18.1 @ `b578eab`):
1. Preconditions: the stock harness exposes `GET /api/items/` with `SearchFilter` + two `search_fields`, reachable anonymously. The exploit first seeds a measurable table: it bulk-creates 40,000 `Item` rows (prefix `bulk-<tag>`) via the container app-shell and deletes them at the end (`automation.py`).
2. Run it: `./run.sh` (ensures the shared `../.venv`, then runs `automation.py`).
3. The exploit issues `GET /api/items/?search=<N q-terms>` for N ∈ {1, 250, 500, 750}, then N = 1500. The decisive request (from `request.http`):
   ```
   GET /api/items/?search=q+q+q+…(x750) HTTP/1.1
   Host: localhost:21514
   # each term -> ILIKE '%q%' across 2 search_fields x 40000 rows
   ```
4. Expected/observed timing ladder (`response.txt`, run.log `[STEP]`):
   ```
        1 -> 0.056s
      250 -> 0.149s
      500 -> 0.141s
      750 -> 0.233s        (4.2x vs 1 term)
     1500 -> 0.327s  HTTP 500 (SQLite expr-depth 500)
   ```
5. Proof / verdict lines from run.log:
   - `[PROOF] per-request cost scales ~linearly with attacker term count: 1->0.056s, 250->0.149s, 500->0.141s, 750->0.233s (4.2x)`
   - `[PROOF] marginal scan cost scaled ~2x from 250->750 terms; >~1000 terms => HTTP 500 (SQLite expr-depth: a second unhandled-500 DoS)`
   - `[OK] attacker term count scaled per-request cost (raw 4.2x / marginal ~2x) — no DRF cap; unbounded volume via VULN-011; larger tables/backends => A:H`
   - `==> VULN-008: CONFIRMED`

Full capture: `exploits/VULN-008/request.http`, `response.txt`, `run.log`.

## Impact
Availability denial-of-service reachable by unauthenticated GETs on the **default** search configuration (no opt-in). Two distinct primitives:
- **Amplification:** each request costs `O(terms × fields × rows)` unindexable `ILIKE` scans; the attacker sets `terms`. `A:L` for one request (bounded by the request-line limit and lab table size), rising to `A:H` under request volume/concurrency or on larger tables and heavier backends (Postgres/MySQL doing real `ILIKE` scans on millions of rows).
- **Unhandled 500:** a term count above the DB expression-depth limit crashes the query — a cheap, single-request error-path DoS.

No confidentiality/integrity impact (C:N/I:N). Chaining: **VULN-011** (rotating `X-Forwarded-For` defeats the anonymous throttle, removing the only mitigation and turning `A:L` into sustained `A:H`); same DoS family as **VULN-009** (unbounded fan-out) and **VULN-007** (regex DoS on the `$` opt-in).

## Suggested fix
From the vuln md:
- **Framework-side:** cap both the number of search terms and the `?search=` length — a `max_length`/term-count guard inside `get_search_terms` (`rest_framework/filters.py:74-82`) before the term list is expanded into `Q(...)` predicates. Principle: bound attacker-controlled query fan-out at the framework layer rather than relying on the WSGI request-line limit and the DB expression-depth limit as accidental backstops.
- **Consuming app:** keep `search_fields` small and indexed; prefer anchored lookups (`^` / `=`) over the default `%…%` `icontains`; put list endpoints behind an effective throttle (and fix VULN-011 so the throttle can't be bypassed); use full-text search for large tables.

## References
- CWE-400 (Uncontrolled Resource Consumption) — the core weakness class (from the vuln md).
- CWE-1050 (Excessive Platform Resource Consumption within a Loop) — the per-`(term,field)` loop over rows (from the vuln md).
- Technique: leading-wildcard `ILIKE` search-term amplification — attacker-controlled `?search=` token count multiplied by `search_fields`, each an unindexable full scan under the default `icontains` lookup.
- Related VULN-IDs (chains, from the vuln md): VULN-011, VULN-009, VULN-007.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 50 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `github.com/encode/django-rest-framework/security` (vendor advisory list) — 5 advisories (Accept-header content-negotiation CPU, TokenProxy.delete, JSONParser codec, DATA_UPLOAD_MAX_MEMORY_SIZE bypass, AdminRenderer disclosure); none concern `SearchFilter`
2. `github.com/advisories?query=djangorestframework` — CVE-2024-21520, CVE-2020-25626 (browsable-API XSS) and a simplejwt advisory only; no SearchFilter / search-term entry
3. `security.snyk.io/package/pip/djangorestframework` — 10 historical vulns, none affecting 3.18.x, none search-related
4. DRF issue tracker query `SearchFilter denial of service / DoS / ReDoS / regex / terms` — only docs PR #10023 (regex warning) and unrelated items
5. DRF issue tracker query `search_smart_split / "search terms" / icontains denial` — issue #4655 (2016, exponential JOIN growth on m2m search fields, fixed by PR #5264); no item about capping term count or the expression-depth 500
6. DRF filtering API guide — documents term splitting and the `$`/iregex ReDoS warning; no term-count or length limit is documented or promised
7. DRF release notes 3.15.0–3.18.3 — SearchFilter changes are admin-alignment, quoting, unaccent and a `pk` crash fix; no term-count/DoS hardening. (NVD keyword search page did not render; general web search quota was exhausted for this session, so verification relied on direct advisory-database, docs and issue-tracker fetches.)

**Related but distinct public references** (same class or component, not this bug):
- DRF issue #4655 / PR #5264 (3.6.4) — "SearchFilter time grows exponentially by # of search terms": same component and same attacker input, but the mechanism was JOIN multiplication from chained `filter()` on m2m fields, fixed by combining conditions; it did not introduce a term-count cap and did not address the linear O(terms × fields) `ILIKE` fan-out or the DB expression-depth 500 described here
- DRF PR #10023 (docs, 2026-08-18) — ReDoS warning for the opt-in `$`/`iregex` prefix; different sink
- GHSA-2m8g-3cmr-wg3w / CVE-2026-73228 — `DATA_UPLOAD_MAX_MEMORY_SIZE` bypass in `request.data`; body-size vector, not query-string term count
- GHSA-33wh-fxxf-88vv — large `Accept` header CPU exhaustion in content negotiation; different component

**Reasoning:** No advisory, CVE or upstream issue describes the absence of a term-count/length cap on `?search=` producing unbounded `(terms × fields)` leading-wildcard predicates or the unhandled 500 once the generated `Q` tree exceeds the DB expression-depth limit. The closest public item (#4655) covers the same component and input but a different, already-fixed mechanism, and the "search should not DoS the application" concern voiced there was never turned into a cap, so this is scored as a partial match. Caveats: resource-exhaustion via search is a very common class, DRF 3.15 deliberately mirrors Django admin's unbounded term splitting, and a private report to the maintainers could exist.
