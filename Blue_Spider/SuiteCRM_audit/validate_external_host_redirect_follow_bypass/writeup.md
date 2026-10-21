# VULN-094 — `validate_external_host()` SSRF guard bypassable via an HTTP redirect chain

**ID**: VULN-094
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`suitecrm_version.php`), commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1 6.5** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N`
**Status**: CONFIRMED (dynamic)
**Auth required**: Any authenticated user — a freshly-created, non-admin regular user is used; RSS dashlets are a default, unrestricted feature of every user's Home dashboard.
**What an attacker gains**: a working bypass of the application's own internal-host SSRF allow-list, turning the *guarded* RSS dashlet into the same arbitrary-internal-target, response-reading primitive as the unguarded sinks in this SSRF cluster — using nothing more than a one-hop HTTP redirect.

## 1. Summary

SuiteCRM has a real SSRF guard, `validate_external_host()`, that correctly rejects private/reserved IP ranges. The RSS dashlet's render path calls it — but only against the URL the dashlet was *configured* with, and only once. The actual fetch (`file_get_contents()`) follows HTTP redirects by default, and every redirect hop is completely unvalidated. Any authenticated user can therefore configure their RSS dashlet with a URL on a genuinely public server (one they may not even control themselves — a public "redirect-to" test utility suffices) that returns a `302` to an internal address, and the guard never sees that second address at all.

## 2. How it works (mechanism & code trace)

**Guard + sink**, both in `modules/Home/Dashlets/RSSDashlet/RSSDashlet.php`, `getRSSOutput()`:
```php
protected function getRSSOutput($url) {
    libxml_use_internal_errors(true);

    if (validate_external_host((string) $url) === false) {   // :161 -- checked ONCE
        return $this->dashletStrings['ERR_LOADING_FEED'];
    }

    $data = file_get_contents($url);                          // :165 -- follows redirects
    ...
    $rssdoc = simplexml_load_string($data);                    // :170 -- parsed & rendered
```
`validate_external_host()` (`include/utils.php:6321`) does real work — it resolves the hostname and rejects the connection if any resolved IP is private/link-local/reserved (verified directly during analysis: pointing it at `172.18.0.1`, the docker bridge address this exploit's OOB listener uses, returns `false`). The defect is structural: the check runs against `$url` exactly once, at `:161`; the actual network operation at `:165`, PHP's `file_get_contents()` over the `http://` stream wrapper, follows `Location:` headers by default (`follow_location=1`, up to `max_redirects=20`) with **no hook back into `validate_external_host()`** for any of those hops. A URL that legitimately resolves to a public IP sails through `:161`; if that public server's *response* is a redirect, SuiteCRM will follow it anywhere, including back into its own private network.

**Entry point**: any authenticated user's own configured RSS dashlet, rendered through the standard, framework-level `action_callmethoddashlet()` (`include/MVC/Controller/SugarController.php:856`) at `index.php?module=Home&action=CallMethodDashlet&method=display&id=<dashlet id>` — the same request the real UI issues every time a user's Home page loads or refreshes a dashlet.

## 3. Why it is a vulnerability (reasoning)

"Validate once, then follow redirects with no re-validation" is a well-known, named SSRF-bypass pattern (OWASP explicitly calls out redirect-following as something an SSRF defense must account for). The code's own intent is clear from the guard's existence: SuiteCRM's developers recognised that RSS feed URLs are attacker/user-controlled and need to be kept off the internal network. That intent is defeated by a one-line HTTP response the *target* server controls, not the SuiteCRM user — meaning the security boundary silently degrades to "trust whatever the remote server's first response says," which is not what an allow-list is supposed to mean. This is a defect, not a design tradeoff: fixing it costs nothing more than disabling redirect-following (or re-validating each hop), and every other fetch call in this SSRF cluster ([VULN-045](../VULN-045/writeup.md), [VULN-014](../VULN-014/writeup.md), [VULN-047](../../vulns/VULN-047.md)) shows the project has not yet applied that fix consistently anywhere.

## 4. Reproduction

From a clean state:

1. **Preconditions**: `automation.py` creates a throwaway non-admin user, starts an OOB HTTP listener on `172.18.0.1:33119` (host-bound `0.0.0.0:33119`), and seeds that user's `dashlets` Home preference with an `RSSDashlet` whose `url` is `https://httpbin.org/redirect-to?url=<urlencoded http://172.18.0.1:33119/canary-...>&status_code=302` (a genuinely public, internet-reachable redirector — the app container has real outbound internet access, confirmed live).
2. **Attack request** (`request.http`):
   ```
   POST /index.php HTTP/1.1
   X-Requested-With: XMLHttpRequest

   to_pdf=1&module=Home&action=CallMethodDashlet&method=display&id=<dashlet_id>
   ```
3. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected/observed: exit 0, `==> VULN-094: CONFIRMED`.
4. **Observable proof** — two independent signals:
   - `evidence/oob_listener.log`: `GET /canary-rss094_ab9c346b` from the app container.
   - `response.txt`: HTTP 200 with the dashlet's rendered HTML containing `<h3><a href="" target="_child">hit</a></h3>` — `"hit"` is the `<title>` of the synthetic RSS document served by the OOB listener at the moment of the hit, i.e. the internal-only response content was parsed as XML and rendered directly into the authenticated user's page.
   - Cross-check: feeding `172.18.0.1` directly into `validate_external_host()` (no redirect involved) returns `false` — proving the guard is live and would have blocked a *direct* request to this address; it is only the redirect hop that evades it.

## 5. Impact

- **Confidentiality**: semi-blind read of internal HTTP/XML-serving resources — any internal endpoint that returns parseable RSS/Atom XML renders its content directly into the attacker's own dashboard; other responses still confirm reachability via the OOB channel.
- **Defeats a real, purpose-built control**: this is not "found a fetch with no guard" (that is [VULN-014](../VULN-014/writeup.md)) — it is a working bypass of the control SuiteCRM specifically added to prevent exactly this, demonstrating the fix must cover redirect-following, not just the initial URL.
- **Pre/post-auth**: post-auth, lowest privilege level — no admin/role/ACL requirement.
- **Chaining**: same cluster as [VULN-045](../VULN-045/writeup.md) (full-read), [VULN-014](../VULN-014/writeup.md) (unguarded sibling sink), [VULN-047](../../vulns/VULN-047.md) (TCPDF, likely the same validate-then-follow gap per the static finding's note on `SuiteTCPDF.php:95`), [VULN-085](../../vulns/VULN-085.md).

## 6. Suggested fix

- At `RSSDashlet.php:165`, disable redirect-following (`stream_context_create(['http' => ['follow_location' => 0]])` passed to `file_get_contents()`), or implement a manual redirect loop that calls `validate_external_host()` again on every `Location:` header before following it, capped at a small hop count.
- Better: resolve the final destination IP once validation passes and connect directly to that pinned IP for the actual request, so no amount of DNS or HTTP-level indirection between validation and connection can smuggle a different destination.
- Principle: an SSRF allow-list must cover the entire network path the request can end up taking, not just the address the caller typed in.

## 7. References

- CWE-918: Server-Side Request Forgery — https://cwe.mitre.org/data/definitions/918.html; CWE-441 (Unintended Proxy/Intermediary) for the redirect-following angle.
- OWASP SSRF Prevention Cheat Sheet ("Disable HTTP redirections"): https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy, "Server-side request forgery (SSRF)" — bypassing SSRF filters via open redirection: https://portswigger.net/web-security/ssrf
- Known-issue family: CVE-2026-29097 / GHSA-x3p2 (RSSDashlet SSRF+DoS, base fix in 7.15.1) and guard-bypass class CVE-2026-61649 / GHSA-r665 (`isSelfRequest()` substring bypass) — this finding is the distinct redirect-follow gap in the same function, which the base fix does not appear to close.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Fetched GHSA-x3p2-qcqh-qx2m (CVE-2026-29097, "SSRF and DoS via RSS Feed Dashlet", fixed 7.15.1) — names no file/parameter and does not mention redirects, `follow_location` or redirect chains. The v7.15.0..v7.15.1 diff shows the fix simply inserted `validate_external_host($url)` before the unchanged `file_get_contents($url)` in `RSSDashlet::getRSSOutput()`; no stream context disabling redirects was added.
2. Fetched GHSA-r665-27q3-wvg8 (CVE-2026-61649, fixed 7.15.2) — bypass of the same guard via `isSelfRequest()` substring matching; the v7.15.1..v7.15.2 diff replaces the `stripos()` check with host equality and does not touch redirect handling or `RSSDashlet.php`.
3. GitHub Advisory Database query `suitecrm ssrf` — CVE-2023-6388, CVE-2023-6124, CVE-2019-13335; none concern redirect-following past an allow-list.
4. Full SuiteCRM GHSA catalogue (77 advisories through 2026-10-12) — SSRF entries (Activity Stream, Connectors, RSS dashlet, PDF export, CalendarAccount, SchedulersJob, `isSelfRequest()`) include no redirect-chain bypass of `validate_external_host()`.
5. `include/utils.php::validate_external_host()` source as added in 7.15.1 (from the diff) — validates scheme/host/resolved IPs once and returns; it is never re-invoked per redirect hop by any caller.
(Note: the shared WebSearch budget was exhausted before this folder; checks were made by direct fetch of the advisory databases and the upstream repository.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-29097 / GHSA-x3p2-qcqh-qx2m — the original unguarded RSS-dashlet SSRF; the 7.15.1 fix introduced the guard this finding bypasses.
- CVE-2026-61649 / GHSA-r665-27q3-wvg8 — a different bypass of the same `validate_external_host()` guard (substring `isSelfRequest()`), fixed 7.15.2; this finding (redirect-following after a one-time check) survives that fix.
- CVE-2026-69137 / GHSA-72r3-24x4-j46c — CalendarAccount SSRF with `CURLOPT_FOLLOWLOCATION`; a separate unguarded sink.

**Reasoning:** Both public advisories on this guard describe other defects (absence of the guard; substring host matching) and neither their text nor their patches address `file_get_contents()` following `Location:` headers to unvalidated hosts, which the dynamic test shows still works on 7.15.2. Confidence is only moderate because this guard has already been bypassed once publicly within months of its introduction and redirect-following is the textbook next bypass, so a private report to the vendor is quite plausible even though nothing is public.
