# VULN-028 — SSRF via unguarded `WebUserAgent` (admin config URLs)

| | |
|---|---|
| **ID** | VULN-028 (raw ZN-010) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium · CVSS 3.1 **5.8** — `AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** · **Auth**: admin |
| **Attacker gains** | Server-side HTTP requests to arbitrary internal hosts/ports (internal services, cloud metadata) from an admin-set URL. |

## Summary
Znuny's `WebUserAgent` fetches admin-configured URLs with `LWP::UserAgent->get/post` and no SSRF
protection — no scheme restriction, no host/internal-IP allowlist. Several admin features feed it
attacker-chosen URLs (package repository, OAuth2 token endpoints, RSS dashboard, mail-account
hosts). Confirmed: setting the package-manager repository `Source` to an out-of-band URL caused
the app container to issue a server-side `GET` to that host.

## How it works (mechanism & code trace)
`Kernel/System/WebUserAgent.pm`:
```perl
157:  my $UserAgent = LWP::UserAgent->new( ... );
...
225:  $Response = $UserAgent->get( $Param{URL} );        # no allowlist / internal-range check
237:  $Response = $UserAgent->post( $Param{URL}, ... );  # (SSL verify optionally disabled :172-180)
```
`$Param{URL}` is whatever the calling feature was configured with. For the package manager,
`Kernel/System/Package.pm` builds the online-repository URL from the admin-set `Source`
(`WebUserAgent->get($Source . '/otrs.xml')`). Entry over HTTP:
`AdminPackageManager;Subaction=ChangeRepository;Source=<url>` stores the source; loading
`AdminPackageManager` then fetches it. (`AdminPackageManager` requires `SecureMode=1`, which the
lab has.)

**Dynamic confirmation.** With the exploit's OOB listener at `http://172.18.0.1:<port>` and
`Source` pointed at it, the listener logged `GET /repo/otrs.xml` from **172.18.0.3** (the app
container). The server followed an attacker-chosen URL to an attacker-chosen host/port.

## Why it is a vulnerability
The URL fed to `WebUserAgent` is attacker-influenced (an admin sets it, but for the customer-
reachable variant VULN-040 the invoker is customer-driven), and there is no egress control. The
server will therefore connect to internal-only services (databases, admin panels, `169.254.169.254`
cloud metadata, `localhost` daemons) that are not reachable from the attacker's network — the
classic SSRF trust-boundary crossing (`S:C`). OTRS historically treats admin config as trusted,
which is why this is Medium rather than High, but "trusted admin" does not imply "may pivot to
arbitrary internal hosts", and the code takes no defensive measure (no allowlist, and SSL
verification can even be disabled). The captured cross-container request is direct proof the
request leaves the app with no filtering.

## Reproduction
1. As admin, set the package repository `Source` to an OOB URL you control
   (`Subaction=ChangeRepository`). 2. Load `AdminPackageManager`. 3. `./run.sh` runs a listener and
   shows the app container connecting:
   ```
   [PROOF] OOB listener received 2 request(s): [('GET','/repo/otrs.xml','172.18.0.3'), ...]
   ```

## Impact
Server-side requests to arbitrary internal/cloud endpoints (port scanning, hitting internal admin
services, cloud-metadata credential theft), with partial response reflection via the package path.
Other callers (OAuth2 token endpoints, RSS feed, mail-account host) broaden the surface; VULN-040
exposes an outbound-fetch tool to customers. On this libxml2 build the XSLT-mapping *network*
vector (VULN-025) is blocked, so this package/OAuth path is the live SSRF.

## Suggested fix
Route all outbound fetches through a single hardened client that: enforces an `https?`-only scheme
allowlist, resolves the host and rejects private/link-local/loopback/metadata ranges (re-checking
after redirects to prevent DNS-rebinding/redirect bypass), and never disables TLS verification by
default.

## References
- OWASP SSRF Prevention Cheat Sheet; PortSwigger Web Security Academy — SSRF. CWE-918.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. NVD API keyword pull for "Znuny" (17) and "OTRS" (120) grepped for SSRF / WebUserAgent / URL / repository — no SSRF CVE for either product; URL hits are XSS (CVE-2019-9751, CVE-2022-39049/39050), protocol-relative image loading (CVE-2023-38059 / ZSA-2023-01), and ICS banner (CVE-2022-32739)
2. Znuny advisory index ZSA-2021-01 … ZSA-2026-16, GitHub advisory DB, Debian tracker reviewed — no SSRF / outbound-request advisory
3. `gh search issues --repo znuny/Znuny "SSRF"` / `"package repository"` / `"WebUserAgent SSRF"` — none (only #36, a proxy configuration bug)
4. (Shared WebSearch budget was exhausted before this finding; evidence below comes from direct primary-source pulls: NVD CVE API, vendor advisory pages, GitHub advisory DB, Debian tracker, GitHub issue search.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2023-38059 / ZSA-2023-01 — protocol-relative external image loading leaks the viewer's IP; client-side fetch, not server-side
- CVE-2023-5422 — OTRS mail fetch/send does not verify TLS certificates; same outbound-connection area, different defect

**Reasoning:** No public reference treats `Kernel::System::WebUserAgent` fetching admin-configured URLs (package repository `Source`, OAuth2 endpoints, RSS, mail hosts) without scheme/host restrictions as a vulnerability. The vendor and OTRS have consistently treated admin-authored configuration as trusted, so this may be dismissed as by-design, and SSRF via admin config is a commonly accepted risk in this product family; the score reflects that classification uncertainty rather than any matching disclosure.
