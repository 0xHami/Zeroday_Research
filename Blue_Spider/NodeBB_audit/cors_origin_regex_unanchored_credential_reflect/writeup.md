# VULN-011 — CORS: unanchored admin regex + credentialed origin reflection

| | |
|---|---|
| **ID** | VULN-011 |
| **Software** | NodeBB |
| **Repository** | https://github.com/NodeBB/NodeBB |
| **Affected version** | 4.16.0 (`install/package.json:5`; commit-pinned, untagged `master`) |
| **Commit** | `20623201cbf2cc8a37612726cdf10ee82083c9c3` |
| **Severity** | Medium (conditional) — **CVSS 3.1 7.4** `AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic, config-gated)** |
| **Auth required** | None for the attacker page; a logged-in victim who visits it. Requires the admin to have enabled the two settings. |
| **Attacker gains** | Credentialed cross-origin reads of authenticated JSON (incl. `/api/config` → session `csrf_token`), enabling a full CSRF chain against the victim. |

## Summary
When an administrator configures `access-control-allow-origin-regex`, NodeBB tests the request `Origin` with an **unanchored** `regex.test(origin)` — a substring match — then reflects the matched origin verbatim into `Access-Control-Allow-Origin` and, independently, emits `Access-Control-Allow-Credentials: true`. A natural admin value like `example\.com` therefore matches attacker origins such as `https://example.com.attacker.net` and `https://notexample.com`, and a browser will allow those origins to read credentialed responses cross-origin. Confirmed dynamically: with the two settings enabled, both attacker origins were reflected with `credentials: true`, while an unrelated origin was not.

## How it works (mechanism & code trace)

`src/middleware/headers.js:42-59`:
```js
if (meta.config['access-control-allow-origin-regex']) {
    let originsRegex = meta.config['access-control-allow-origin-regex'].split(',');
    originsRegex = originsRegex.map(origin => { try { return new RegExp(origin.trim()); } catch { return null; } });
    originsRegex.forEach((regex) => {
        if (regex && regex.test(req.get('origin'))) {                       // :55  UNANCHORED substring match
            headers['Access-Control-Allow-Origin'] = encodeURI(req.get('origin'));  // :56  reflect attacker origin
            headers.Vary = headers.Vary ? `${headers.Vary}, Origin` : 'Origin';
        }
    });
}
...
if (meta.config['access-control-allow-credentials']) {
    headers['Access-Control-Allow-Credentials'] = meta.config['access-control-allow-credentials'];   // :65-66 independent
}
```

`new RegExp('example\\.com')` has no `^`/`$` anchors, so `.test('https://example.com.attacker.net')` and `.test('https://notexample.com')` both return `true` — any string that *contains* `example.com` matches. The matched `Origin` is echoed back verbatim (`:56`), and `Access-Control-Allow-Credentials: true` is emitted with no coupling that would forbid reflecting an origin while allowing credentials. That combination is precisely what the CORS spec says a server must never do for untrusted origins: an exact-origin ACAO plus ACAC:true tells the browser to expose the credentialed response to that origin's scripts.

## Why it is a vulnerability (reasoning)
CORS is an origin-based trust decision; the whole point of the regex feature is to restrict which external origins may read authenticated data. An unanchored regex silently widens "example.com" to "any host containing example.com", which an attacker trivially satisfies with a subdomain/suffix they own (`example.com.attacker.net`) or a lookalike (`notexample.com`). Reflecting that origin *with credentials* converts the feature from an allow-list into an origin-reflection gadget. The dynamic control (an unrelated origin is not reflected) proves the match is doing exactly the substring test, not something safe. This is a genuine misconfiguration-enablement defect (CWE-942/346): the framework should anchor the match and refuse to combine credentials with a reflected origin. It is conditional (needs the two settings on), hence Medium, but those are supported, commonly-used settings.

## Reproduction
1. As admin, set `access-control-allow-origin-regex` = `example\.com` and `access-control-allow-credentials` = `true` (ACP → Settings → Advanced, or `PUT /api/v3/admin/settings/:setting`).
2. Send `GET /api/config` with `Origin: https://example.com.attacker.net`.
3. Observe response headers `Access-Control-Allow-Origin: https://example.com.attacker.net` and `Access-Control-Allow-Credentials: true` (see `response.txt`).
4. `./run.sh` enables the settings, probes two attacker origins + one control, asserts the reflection, and **restores** the original config. Prints `[OK] exploit confirmed`.

Real-world: an attacker hosts a page on `https://example.com.attacker.net` that runs `fetch('http://<forum>/api/config', {credentials:'include'})`; the victim's browser, seeing ACAO=their origin + ACAC=true, hands the script the JSON — including the session `csrf_token`.

## Impact
Credentialed cross-origin theft of any authenticated JSON: `/api/config` (session `csrf_token`), `/api/self`, private category content, etc. Exfiltrating the CSRF token converts every state-changing `/api/v3` endpoint into a CSRF target (the write API has no additional per-request throttle), so this escalates from a read to full account actions. Complements VULN-023 (another CSRF-token exposure path). Conditional on the admin config, so kept as a conditional risk.

## Suggested fix
Anchor the match and require an exact full-origin comparison:
```js
origin = new RegExp(`^${escapeForRegex(entry.trim())}$`);   // or compare req.get('origin') to an allow-list of exact origins
```
Never combine `Access-Control-Allow-Credentials: true` with a reflected/substring-matched origin — only echo credentials for an exact, pre-registered origin. Document that credentials + reflected origins must not be combined.

## References
- PortSwigger Web Security Academy — CORS (origin reflection with credentials; broken regex/suffix matching).
- OWASP WSTG-CLNT-07 (Testing Cross Origin Resource Sharing); OWASP HTML5 Security Cheat Sheet.
- CWE-942 (Overly Permissive Cross-domain Whitelist); CWE-346 (Origin Validation Error).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `NodeBB CORS "access-control-allow-origin-regex" vulnerability origin reflection credentials` — only socketio/socket.io#3671 (2020 report against try.nodebb.org's `/socket.io/` endpoint), CVE-2023-2850 (CSWSH) and CVE-2024-29316 (admin tabs); nothing on the regex setting.
2. `NodeBB CORS misconfiguration CVE regex unanchored Access-Control-Allow-Origin` — same socket.io issue plus unanchored-regex CVEs in other libraries (rack-cors CVE-2017-11173, sanic-cors CVE-2026-37737); no NodeBB match.
3. `nodebb "access-control-allow-origin-regex"` — only the NodeBB community FAQ on websocket origins and a plugin README; no advisory or issue.
4. NodeBB GitHub security-advisories page + OpenCVE vendor listing (23 CVEs) — no CORS / origin-reflection entry.
5. Upstream history of `src/middleware/headers.js` (master) — no commit about anchoring the regex or coupling credentials to exact origins; the latest change to the file predates 2024.

**Related but distinct public references** (same class or component, not this bug):
- socketio/socket.io#3671 (2020) — credentialed origin reflection on `/socket.io/` of try.nodebb.org caused by socket.io v2's permissive default CORS, fixed in socket.io 2.4.0; different component from NodeBB's `access-control-allow-origin-regex` header middleware.
- CVE-2023-2850 / GHSA-4qcv-qf38-5j3j — cross-site websocket hijacking (websocket origin validation), not HTTP CORS header generation.
- CVE-2017-11173 (rack-cors), CVE-2026-37737 (sanic-cors) — the same unanchored-regex origin-matching pattern in unrelated libraries.

**Reasoning:** The unanchored `new RegExp(entry).test(origin)` substring match, verbatim origin reflection and independently-emitted `Access-Control-Allow-Credentials` in NodeBB's headers middleware have no public advisory, CVE, issue or fix commit. The bug is config-gated (an admin must enable both settings), which lowers the chance it has been reported and means maintainers could frame it as admin responsibility, so treat as borderline misconfiguration-enablement rather than a classic defect. Web-search quota was exhausted mid-triage; later checks were direct fetches of GitHub/OpenCVE pages.
