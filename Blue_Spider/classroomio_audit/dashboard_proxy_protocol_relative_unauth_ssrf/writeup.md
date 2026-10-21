# VULN-003 — Unauthenticated full-read SSRF via the dashboard `/proxy//host` protocol-relative path

| | |
|---|---|
| **ID** | VULN-003 (raw F-44) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned, no tagged release |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | High — **CVSS 3.1 8.6** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` (→ Critical where cloud IMDS is reachable) |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | **None** — the proxy branch runs before any authentication |
| **What an attacker gains** | Read the raw response body of any host reachable from the dashboard server (internal services, cloud metadata / IMDS credentials), and a credentialed open proxy |

## Summary

The SvelteKit dashboard exposes a reverse-proxy path `/proxy/*` that forwards to the
internal API. The forwarding is the **first thing** the request handler does, before
any session or auth handling, and it builds the upstream URL by passing the
attacker-controlled, prefix-stripped path as the *reference* argument of
`new URL(reference, apiBase)`. A request path beginning with `//` (e.g.
`/proxy//minio:9000/x`) becomes the reference `//minio:9000/x`, which WHATWG URL
parsing treats as a protocol-relative authority that **overrides** `apiBase`. The
server therefore fetches `http://minio:9000/x` and returns the body. Any
unauthenticated client can point the dashboard at arbitrary hosts. Confirmed live:
with no cookie, `GET /proxy//api:3081/` returned the internal API's welcome JSON and
`GET /proxy//minio:9000/minio/health/live` returned MinIO's health `200` — both hosts
resolvable only from inside the compose network.

## How it works (mechanism & code trace)

**Entry point — `apps/dashboard/src/hooks.server.ts:109-114`.** The SvelteKit
`handle` hook forwards `/proxy/*` (and `/api/*`) to the API as its very first action:

```ts
export const handle: Handle = async (args) => {
  const { event } = args;

  if (shouldForwardToApi(event.url.pathname)) {   // :112
    return proxyRequestToApi(event.request);      // :113  ← returns before any auth
  }

  console.log('page path', event.url.pathname);
  const sessionData = await getSessionData(event.cookies);   // auth only happens AFTER
  ...
```

`shouldForwardToApi` (`proxy-api-request.ts:28-35`) returns true for any path under
the `/proxy` prefix. No cookie, session, CSRF token, or origin is checked before
forwarding — the branch `return`s first.

**Prefix strip — `proxy-api-request.ts:37-43`.** The upstream path is the request
path with the literal `/proxy` sliced off the front:

```ts
function resolveApiUpstreamPath(pathname: string): string {
  if (pathname === PROXY_PREFIX || pathname.startsWith(`${PROXY_PREFIX}/`)) {
    return pathname.slice(PROXY_PREFIX.length) || '/';   // '/proxy//minio:9000/x' → '//minio:9000/x'
  }
  return pathname;
}
```

Crucially, `'/proxy//minio:9000/x'.slice('/proxy'.length)` = `'//minio:9000/x'` — the
interior double slash is preserved.

**The defect — `proxy-api-request.ts:128-129`.** The stripped path is passed as the
**first** (reference) argument of the two-argument URL constructor:

```ts
const upstreamPath = resolveApiUpstreamPath(url.pathname);      // '//minio:9000/x'
const upstreamUrl  = new URL(`${upstreamPath}${url.search}`, apiBase);  // apiBase = http://api:3081
```

Per the WHATWG URL Standard, when the reference string begins with `//` it is a
*protocol-relative* URL: parsing takes the scheme from the base (`http:`) but the
**authority from the reference**. So `new URL('//minio:9000/x', 'http://api:3081')`
resolves to `http://minio:9000/x` — `apiBase`'s host is discarded. There is no host
allowlist and interior `//` is never rejected or collapsed.

**Sink — `proxy-api-request.ts:133,155,157`.** The overridden authority is then used
verbatim, including setting the outgoing `Host` header to the attacker host, and the
body is returned to the caller (non-blind):

```ts
upstreamHeaders.set('host', upstreamUrl.host);      // :133  host := attacker's host
...
const upstreamResponse = await fetch(upstreamUrl, init);   // :155  server-side fetch
return buildProxiedApiResponse(upstreamResponse);          // :157  body → caller
```

**Why the framework doesn't save it.** SvelteKit's router does not normalize interior
`//` out of `event.url.pathname` (confirmed: `new URL('http://x/proxy//y').pathname`
is `'/proxy//y'`), so the `//` survives to the constructor. The proxy is `adapter-node`
served directly on host port 21526 with no fronting proxy to collapse the slashes.

**The safe sibling proves it's a bug.** `apps/tenant-router/src/index.ts:328-331`
does the same job correctly — it starts from a URL and assigns `.pathname`:

```ts
const upstreamUrl = new URL(request.url);
upstreamUrl.protocol = 'https:';
upstreamUrl.host = upstreamHost;      // fixed, trusted host
upstreamUrl.pathname = upstreamPath;  // the .pathname setter never reinterprets '//' as authority
```

The `.pathname` setter cannot introduce a new authority, so tenant-router is immune to
the identical input. The dashboard proxy simply uses the wrong URL-construction idiom.

## Why it is a vulnerability (reasoning)

The trust boundary being violated is *"the dashboard may only proxy to its own
configured API upstream."* The feature is intended to relay browser calls to
`PRIVATE_SERVER_URL` (the internal API). Instead, an unauthenticated remote attacker
chooses the destination host. Two invariants break:

1. **Server-side request origin.** The dashboard's Node process sits inside the
   compose network / cloud VM and can reach hosts the attacker cannot: `api:3081`,
   `minio:9000`, `postgres`/`redis`, and on a cloud host the link-local metadata
   service `169.254.169.254`. The exploit borrows the server's network position. We
   proved this by reaching `minio:9000` — a hostname that does not resolve at all from
   the attacker's machine, only inside the network — so the request unambiguously
   originated server-side.

2. **Authentication precedes nothing.** Because the forward happens before
   `getSessionData`, there is no gate at all; the capability is pre-auth. This is not
   "an authenticated admin can reach internal services" (which might be by design) —
   it is *anyone on the internet* who can reach port 21526.

A skeptic might argue the proxy is "supposed" to reach the API, so reaching `api:3081`
is expected. The `minio:9000` read refutes that: the proxy is only authorized to reach
the API upstream, yet it reached a different internal service purely from
attacker-supplied input. That is the definition of SSRF.

## Reproduction

Preconditions: none. The target must be up (`docker compose -p cvehunt_classroomio up -d`).

1. Baseline — observe the internal API's response when hit directly:
   `curl -s http://localhost:21527/` → `{"message":"\"Welcome to Classroomio.com API ...\""}`.
2. Fire the SSRF with **no** cookie:
   ```
   GET http://localhost:21526/proxy//api:3081/ HTTP/1.1
   Host: localhost:21526
   ```
   → HTTP 200, body identical to the baseline → the dashboard fetched `http://api:3081/`.
3. Reach an internal-only service (not the API):
   `curl -s -o /dev/null -w '%{http_code}\n' "http://localhost:21526/proxy//minio:9000/minio/health/live"` → `200`.
4. Automated: `./run.sh` → prints `[OK] exploit confirmed` and exits 0. Full transcript
   in `run.log`; the decisive request/response is saved in `request.http` / `response.txt`.

Observable proof: the proxied body for `//api:3081/` equals the internal API's welcome
JSON (byte-for-byte), and `//minio:9000/…` returns 200 for a host unreachable from the
attacker's network.

## Impact

- **Read any host reachable from the dashboard server.** Internal APIs, object storage
  (`minio:9000` — its admin/console API and bucket listings), and any HTTP-speaking
  service on the compose network, returned non-blind to the attacker.
- **Cloud credential theft.** On AWS/GCP/Azure the same `GET /proxy//169.254.169.254/…`
  reads the instance metadata service, including temporary IAM credentials → pivot to
  broader cloud compromise. This is what pushes the score toward Critical (~9.3) on a
  cloud VM.
- **Credentialed open proxy.** Method, body, and the caller's own headers/cookies are
  forwarded (`proxy-api-request.ts:130`), so the endpoint doubles as a relay that can
  carry a victim's forwarded credentials to an attacker host.
- **Blast radius:** whole instance + its network position; pre-auth. Chains with the
  recon findings (VULN-016/VULN-033/VULN-034) that leak internal ids/keys to then be
  fetched, and with any internal service that trusts network-local callers.

## Suggested fix

In `apps/dashboard/src/lib/utils/proxy-api-request.ts:128-129`, never pass the
untrusted path as the reference argument. Build from the trusted base and assign the
path, exactly as `tenant-router` does:

```ts
// before
const upstreamUrl = new URL(`${upstreamPath}${url.search}`, apiBase);
// after
const upstreamUrl = new URL(apiBase);          // trusted host, fixed
upstreamUrl.pathname = upstreamPath;            // .pathname setter can't introduce an authority
upstreamUrl.search = url.search;
```

Defence in depth: reject any `event.url.pathname` containing `//` or `\` before
forwarding (`shouldForwardToApi`), and assert `upstreamUrl.host === new URL(apiBase).host`
after construction. Principle: allowlist the single legitimate upstream host rather
than trusting attacker-influenced URL parsing.

## References

- OWASP WSTG-INPV-19 "Testing for Server-Side Request Forgery"; OWASP SSRF Prevention
  Cheat Sheet (allowlist the destination host).
- PortSwigger Web Security Academy — "SSRF against the back-end system" and the
  `169.254.169.254` IMDS credential-theft technique.
- WHATWG URL Standard, URL parsing — protocol-relative (`//authority`) references
  override the base authority: the root cause abused here.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 88 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE vulnerability` — only the 9 known ClassroomIO CVEs (all authorization/XSS issues); no SSRF.
2. `classroomio GHSA security advisory github.com/advisories` — 9 advisories listed at github.com/advisories?query=classroomio, none SSRF/proxy related; repo `security/advisories` page has none published.
3. `classroomio huntr OR hackerone OR snyk vulnerability report IDOR authorization` — no platform reports.
4. `classroomio SSRF dashboard proxy "/proxy" protocol-relative URL hooks.server.ts` — no ClassroomIO results; only generic protocol-relative SSRF bugs in other software (axios CVE-2024-39338, Gradio CVE-2024-2206).
5. `classroomio SSRF CVE server-side request forgery` — no ClassroomIO results (BigBlueButton CVE-2026-46404 and training material only).
6. `github.com/classroomio/classroomio issues security vulnerability 2026 IDOR SSRF anonymous` + direct read of the repo issue list filtered for security — no issue mentions the dashboard proxy or SSRF.
7. Read hackmd.io/@hieuPenguinnn/classroomio-course-resource-id-scoping-idor — no SSRF/proxy coverage.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2024-39338 (axios) — the same WHATWG protocol-relative-reference pitfall, but in a different product; not ClassroomIO's `proxy-api-request.ts`.
- CVE-2024-2206 (Gradio `/proxy` SSRF) — similar route shape, different software.

**Reasoning:** No public CVE, GHSA, advisory, issue or write-up mentions the SvelteKit dashboard `/proxy/*` forwarder (`apps/dashboard/src/hooks.server.ts` / `lib/utils/proxy-api-request.ts`) or any SSRF in ClassroomIO at all; every public ClassroomIO disclosure is an authorization or XSS issue. The proxy component is recent (post-1.0 Hono migration) and has had no public scrutiny. Caveat: the shared web-search budget was exhausted during this triage, so finding-specific queries were limited to those listed.
