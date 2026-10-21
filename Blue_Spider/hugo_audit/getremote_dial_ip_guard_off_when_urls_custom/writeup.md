# VULN-001 — `resources.GetRemote` dial-time SSRF guard is silently disabled when `security.http.urls` is customized

| | |
|---|---|
| **ID** | VULN-001 (merged HUGO-029 = the `proxyFromEnvironment` variant) |
| **Software** | Hugo — https://github.com/gohugoio/hugo |
| **Affected version** | 0.167.0-DEV (`common/hugo/version_current.go:19-24`); commit-pinned, no tagged release |
| **Commit** | `c7f9999309a2e7a12d24c03fe639008ddc4565f8` |
| **Severity** | Medium — CVSS 3.1 **6.9** `AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None (Hugo has no auth). Precondition: operator customized `security.http.urls`; actor is a theme (T2) or content (T1) supplying/redirecting a URL. |
| **Attacker gains** | SSRF to loopback / private / **cloud-metadata** during the build → IAM-credential theft, internal service reachability. |

## Summary

`resources.GetRemote` fetches build-time URLs. Its real anti-SSRF backstop is a
**dial-time resolved-IP check** (`net.Dialer.Control` → `CheckAllowedHTTPAddress`)
that rejects any resolved loopback/private/link-local/CGNAT/cloud-metadata address —
the *only* defense against a hostname that resolves internally, because the
`security.http.urls` allowlist inspects URL **text** and never sees the resolved IP.
That guard is silently skipped the instant `security.http.urls` differs from the
built-in default — even adding one trusted host disables the resolved-IP check for
**every** host. Confirmed dynamically: a hostname that passes the text allowlist but
resolves to loopback is **denied at dial under the default config** (the internal
listener receives zero requests) and **reaches the internal endpoint after a single
`urls` edit** (the listener is hit and the build renders the internal secret).

## How it works (mechanism & code trace)

**Source — an influenced/redirecting URL enters `GetRemote`.** A theme or content
does `{{ resources.GetRemote $url }}`. The URL is first text-checked against
`security.http.urls`.

**The default allowlist is text-only and permissive about hostnames.**
`targets/hugo/config/security/securityConfig.go:62-67`:

```go
URLs: MustNewWhitelist(
    `(?i)^https?://[a-z0-9]`,       // host starts with a letter/digit
    `! (?i)^https?://\d+\.`,        // deny bare dotted-IP literals
    `! (?i)localhost`,              // deny localhost
    `! (?i)^https?://[^/?#]*@`,     // deny userinfo
),
```

A normal-looking hostname like `internalcanary.test` passes all four — it is not an IP
literal, not `localhost`, has no userinfo. **The text layer cannot tell that this
hostname resolves to an internal IP.** That is the whole reason the dial-time guard
exists.

**The dial-time guard — and its short-circuit.**
`targets/hugo/config/security/securityConfig.go:233-240`:

```go
func (c Config) CheckAllowedHTTPAddress(network, address string) error {
    // Only enforced under the default hardened allowlist. If the user has
    // customized security.http.urls they have opted into whatever hosts they
    // listed, including internal ones ...
    if !slices.Equal(c.HTTP.URLs.patternsStrings, DefaultConfig.HTTP.URLs.patternsStrings) {
        return nil          // ← resolved-IP guard disabled for EVERY host
    }
    ...
    if !isPublicAddr(ip) {  // :258 — only runs under the exact default list
        return deny(host)
    }
```

`isPublicAddr` (`securityConfig.go:285-302`) rejects non-global-unicast, private,
link-local, CGNAT, TEST-NET, NAT64-embedded and (implicitly, via `IsGlobalUnicast`)
loopback and the metadata range. But `:238-240` returns `nil` **before** that runs
whenever `patternsStrings` isn't byte-identical to the default — so any edit to
`security.http.urls` drops the entire resolved-IP defense.

**The dial hook.** `resources/resource_factories/create/create.go` installs
`secureDialer.Control → sec.CheckAllowedHTTPAddress`; redirect hops re-check the URL
text (`create.go:109-117`) but are **not** IP-checked once the hook is a no-op.

**Dynamic confirmation.** With `internalcanary.test` pinned to `127.0.0.1`:
- Default config → the guard runs → `isPublicAddr(127.0.0.1)` is false → **deny**; the
  listener records **0 requests**, the build renders `FETCH_ERR: … error calling
  GetRemote`.
- `urls = ['(?i)^https?://']` → `:238-240` returns nil → the dial connects → the
  listener records **1 request** and the build renders `FETCHED:CANARY-2779fbe0`.

(HUGO-029, the merged variant: `create.go:192-195` routes proxied dials through a bare
`proxyDialer` with no `Control` hook, so `proxyFromEnvironment=true` skips the same
guard — an independent path to the identical hole.)

## Why it is a vulnerability

The trust boundary is the **network position of the build host**: `GetRemote` is meant
to fetch *public* assets, not to read internal/cloud infrastructure. The resolved-IP
guard is the only control that enforces this against a hostname that resolves inward
(DNS-rebinding, split-horizon DNS, an allowlisted host that 302-redirects to
`169.254.169.254`). Inferring "the operator trusts all internal addresses" from *any*
edit to a **URL text** list is far too coarse: an operator who adds
`^https://api.mycorp.com/` to fetch one partner API has said nothing about loopback or
metadata, yet the code silently drops the anti-rebind backstop for every host. A
skeptic can confirm the two halves directly from the evidence: the default build is
denied at dial (guard present and effective), and a one-line `urls` change makes the
identical internal fetch succeed (guard gone). Reaching `127.0.0.1` is equivalent to
reaching `169.254.169.254` — `isPublicAddr` classifies both as non-public by the same
code, so the metadata endpoint is reachable by the same primitive.

## Reproduction

1. `cd claude_audit/hugo/exploits/VULN-001 && ./run.sh`
2. The script starts a loopback canary HTTP listener serving a unique secret, pins
   `internalcanary.test → 127.0.0.1` in the build container (`--add-host`, `--network
   host`), and builds the same site twice:
   - Build #1: **no** `[security.http]` block (default `urls`).
   - Build #2: `[security.http] urls = ['(?i)^https?://']`.
   Layout: `{{ $r := try (resources.GetRemote "http://internalcanary.test:PORT/…") }}{{ with $r.Err }}FETCH_ERR:{{.}}{{ else }}FETCHED:{{ $r.Value.Content }}{{ end }}`.
3. Expected: `[OK] exploit confirmed …`, exit 0. Evidence (`response.txt`):
   ```
   [default]    hits=0 blocked=True    (FETCH_ERR)
   [customized] hits=1 fetched=True    (FETCHED:CANARY-2779fbe0)
   ```

## Impact

SSRF to loopback / private / **cloud-metadata** during the build. On a cloud/CI build
host, `GetRemote https://<attacker-or-rebinding-host>/` reaches
`http://169.254.169.254/latest/meta-data/iam/security-credentials/…` and the build
renders (and can exfiltrate) the IAM credentials → cloud-account compromise (`S:C`,
`C:H`). It also reaches internal admin/metadata services and enables internal port
probing (`I:L`). Pre-auth in the sense Hugo has none; the only gate is the operator
precondition (any `urls` customization — a very common action, hence AC:H not AC:L).
**Chains:** with **VULN-008** (a secret custom header forwarded to the SSRF/redirect
destination) and **VULN-018** (unbounded body read of the internal response); the
AsciiDoc `allow-uri-read` path (**VULN-025**) reaches metadata by a different route.

## Suggested fix

Do not infer internal-address trust from a URL-text edit. Gate the resolved-IP defense
behind an **explicit** opt-out and keep enforcing it otherwise
(`securityConfig.go:238-240`):

```go
func (c Config) CheckAllowedHTTPAddress(network, address string) error {
    if c.HTTP.AllowInternalAddresses {   // explicit, default false
        return nil
    }
    // ... always run isPublicAddr(ip), regardless of whether urls was customized ...
}
```

Apply the same resolved-address check to the **final** destination even when proxying
(closes HUGO-029). Principle: widening a text allowlist must not silently disable an
orthogonal anti-rebind control.

## References

- OWASP WSTG-INPV-19 (SSRF) and the SSRF Prevention Cheat Sheet — DNS-rebinding /
  resolve-then-validate guidance.
- PortSwigger "Server-side request forgery (SSRF)" — internal/metadata targeting and
  redirect-based SSRF.
- Hugo SSRF fix wave (present at *default*, residual here): CVE-2026-10582,
  CVE-2026-50134, CVE-2026-58404, CVE-2026-100693; Hugo security model
  https://gohugo.io/about/security/.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 30 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `Hugo GetRemote SSRF CheckAllowedHTTPAddress security.http.urls customized dial resolved IP check skipped` — only CVE-2026-10582 (text-only allowlist, Hugo ≤0.165.0); nothing about the check being skipped on a customized allowlist
2. `gohugoio hugo security advisory resources.GetRemote SSRF 2026 CVE` — CVE-2026-50134 (redirects), CVE-2026-58404 (IPv4 encodings), CVE-2026-100693 (mixed case), CVE-2026-10582 (no resolved-address check); none describes the post-fix short-circuit
3. `hugo GetRemote DNS rebinding resolved IP check only default allowlist customized urls disables` (extended) — only vendor docs and the v0.166.0 release notes, which describe the behaviour as intentional; no advisory, issue or third-party report
4. Fetched github.com/gohugoio/hugo/security/advisories pages 1-3 (23 advisories, 2020-2026-10-13) — no advisory covers the customized-allowlist or proxy-dial gap
5. Fetched gohugo.io/configuration/security/ and github.com/gohugoio/hugo/releases/tag/v0.166.0 — both state the resolved-address validation "is disabled if you override http.urls" and does not apply when a proxy is used

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-10582 (VulnCheck) — Hugo 0.91.0-0.165.0 had no resolved-address check at all; 0.166.0 added the dial-time check. This finding is the residual gap of that fix (check only enforced under the byte-identical default list), not the original bug.
- GHSA-vxgm-5rmg-5w8g / CVE-2026-50134, GHSA-r46f-3rpw-hxrv / CVE-2026-58404, GHSA-pmrv-x7gp-2rjw / CVE-2026-100693 — text-allowlist bypasses in the same `GetRemote` path; different sinks.
- gohugo.io/configuration/security/ and v0.166.0 release notes — document the exact behaviour ("This validation is disabled if you override `http.urls`"; proxied requests are not validated) as a deliberate trade-off.

**Reasoning:** No CVE, GHSA, issue or third-party write-up treats the "guard off when `http.urls` is customized" short-circuit (or the unchecked proxy dial) as a vulnerability. However, the behaviour itself is explicitly and publicly documented by the maintainers as intentional, so they are aware of it; a disclosure would be an argument that the design is too coarse rather than a report of an unknown bug, and may be answered "by design". Confidence is therefore low despite the absence of an advisory.
