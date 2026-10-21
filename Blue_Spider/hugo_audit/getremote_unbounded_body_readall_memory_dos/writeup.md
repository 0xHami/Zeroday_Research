# VULN-018 — `resources.GetRemote` reads the entire response body with `io.ReadAll` (no size cap) → build-time memory DoS

| | |
|---|---|
| **ID** | VULN-018 |
| **Software** | Hugo — https://github.com/gohugoio/hugo |
| **Affected version** | 0.167.0-DEV (`common/hugo/version_current.go:19-24`); commit-pinned, no tagged release |
| **Commit** | `c7f9999309a2e7a12d24c03fe639008ddc4565f8` |
| **Severity** | Medium — CVSS 3.1 **5.3** `AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | None. Actor is a theme/content (T2/T1) whose `GetRemote` URL reaches an attacker-controlled or malicious responder. |
| **Attacker gains** | OOM-kills the build (denial of service); the *remote server* sizes the allocation. |

## Summary

After the URL/method allowlist passes, `GetRemote` buffers the **entire** HTTP
response body with `io.ReadAll` — there is no `io.LimitReader` or
`http.MaxBytesReader` anywhere in the fetch/parse chain. The client timeout bounds
**time**, not **bytes**. Because the default `security.http.urls` permits any public
host, the responder need not be trusted: a streaming (or `Content-Length`-lying)
server dictates how much memory the build allocates. Confirmed dynamically — a 64 KiB
body builds fine, but a ~2.2 GB streamed body OOM-kills a 1 GB-capped build (exit 137).

## How it works (mechanism & code trace)

**Entry point — a remote fetch.** `{{ resources.GetRemote $url }}` (or a remote
`openapi3.Unmarshal`/`transform.Unmarshal` `$ref`, or an oEmbed shortcode) reaches the
fetch path.

**Sink — unbounded read.**
`targets/hugo/resources/resource_factories/create/remote.go:296`:

```go
body, err = io.ReadAll(res.Body)   // whole body buffered into RAM, unbounded
```

and the error/`responseToData` path at `:60` does the same. A repo-wide search finds
**zero** `io.LimitReader`/`http.MaxBytesReader` in the create/parser/`hugio` chain. The
only bound is `httpClient.Timeout` (~2 min), which limits how *long* the transfer may
run, not how *many bytes* are buffered — a fast loopback/LAN responder streams
gigabytes well within the timeout.

**The exact defect.** `io.ReadAll` grows its buffer as it reads to EOF. With no ceiling
and an attacker-chosen body length, the buffer size is set by the remote peer. Under
the container/CI memory cgroup, once the buffer exceeds the limit the process is
SIGKILLed (observed rc 137).

**Why the framework doesn't save it.** Go's `io.ReadAll` has no size argument; the
caller must wrap the reader in `io.LimitReader`. Hugo does not, so the untrusted server
controls the allocation.

**Dynamic confirmation.** Same template, same code path: a 64 KiB responder yields
`LEN=65536`, rc 0; a ~2.2 GB responder under `--memory=1g` → rc 137 (OOM-kill), the
responder log shows the single request that started the flood.

## Why it is a vulnerability

The invariant is that a build must not let a *remote peer* dictate its memory use. The
`GetRemote` allowlist decides *which hosts* may be fetched but says nothing about *how
much* may be read; combined with an unbounded `io.ReadAll`, any permitted host — and by
default that is every public host — can OOM the build by answering with an oversized
body. The attacker needs no privilege on Hugo and no special configuration: they only
need a `GetRemote` call to reach their server (a common pattern: a theme pulling a
remote JSON/asset, or a content-controlled URL). A skeptic can confirm from the trace
that no `LimitReader` exists and from the run that only the responder's body size
differs between the passing and OOMing builds.

## Reproduction

1. `cd claude_audit/hugo/exploits/VULN-018 && ./run.sh`
2. The script starts a responder that streams a chosen number of bytes and builds the
   same site twice (`{{ try (resources.GetRemote "http://bombhost.local:PORT/stream") }}`):
   - Control: 64 KiB body, 2 GB cap → builds, `LEN=65536`.
   - Attack: ~2.2 GB streamed body, `--memory=1g` → OOM (rc 137).
   (Customized `urls` is used only to make the loopback responder reachable; in the wild
   the responder is a public host the default allowlist already permits.)
3. Expected: `[OK] exploit confirmed …`, exit 0. Evidence in `response.txt` / `run.log`.

## Impact

Build-time memory-exhaustion DoS from a single remote fetch; on shared build infra one
page can OOM the host. It **amplifies VULN-001**: once the dial-IP guard is off, the
unbounded read can be pointed at an internal endpoint (slow-drain/buffer its whole
response). Recoverable, single-build scope, requires a reachable malicious responder →
Medium. Part of the build-DoS cluster with **VULN-004**/**VULN-017**/**VULN-023**.

## Suggested fix

Wrap the body in `io.LimitReader` with a configurable ceiling (default tens of MB) and
error on overflow, in `remote.go:296` and the `responseToData`/`Unmarshal` reuse paths:

```go
const maxRemoteBytes = 32 << 20 // configurable
lr := io.LimitReader(res.Body, maxRemoteBytes+1)
body, err := io.ReadAll(lr)
if err == nil && int64(len(body)) > maxRemoteBytes {
    return nil, fmt.Errorf("resources.GetRemote: response body exceeds %d bytes", maxRemoteBytes)
}
```

Principle: never `io.ReadAll` a network body without a limit.

## References

- CWE-770 Allocation of Resources Without Limits or Throttling.
- OWASP "Denial of Service" cheat sheet — bound response sizes (`MaxBytesReader`).
- Go docs: `io.LimitReader`, `net/http.MaxBytesReader`.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `hugo resources.GetRemote unbounded response body io.ReadAll memory denial of service` — only other projects (Tekton CVE-2026-40924, ffuf CVE-2026-73232, mcp-go); nothing for Hugo
2. `gohugoio hugo issue GetRemote response size limit "GetRemote" large file memory` — forum threads on the hard-coded client timeout and the 1 MiB `readFile` cap; no body-size limit or advisory
3. `hugo "GetRemote" "LimitReader" OR "max size" OR "response too large" OR "body size" github issue` (extended) — no Hugo issue; only a forum thread about fetching >100 MB files hitting the timeout
4. Fetched github.com/gohugoio/hugo/security/advisories pages 1-3 and release notes v0.163.1-v0.168.0 — SSRF/allowlist fixes only; no response-size bound

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-10582, CVE-2026-50134, CVE-2026-58404, CVE-2026-100693 — SSRF/allowlist bypasses in the same `resources.GetRemote` function; different sink (destination control, not body size)
- discourse.gohugo.io "Get large files by resources.GetRemote" — timeout discussion; not a security report

**Reasoning:** No public reference describes the unbounded `io.ReadAll` of remote bodies in `remote.go` as a vulnerability, and the 2026 advisory wave for `GetRemote` concerns destination validation only. The class is common, and the vendor may rate a build-time OOM from a remote peer as low priority, but nothing matching the component and sink is public.
