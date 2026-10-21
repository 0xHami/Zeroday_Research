# VULN-046 — IMAP "Test Settings" SSRF + `valid_imap_ports` whitelist bypass

**ID**: VULN-046
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`suitecrm_version.php`), commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1 6.5** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N` (the static finding notes this "escalates toward High on an imap-enabled host" via the `connection_string` bypass — dynamic testing shows this lab **is** such a host, see §3)
**Status**: CONFIRMED (dynamic) — **the "imap extension absent" limitation does not apply here; see the correction in §2/§3**
**Auth required**: Any authenticated user — the "Test Settings" popup has no `is_admin`/owner gate; a freshly-created, non-admin regular user is used.
**What an attacker gains**: an SSRF/port-scan primitive with a real application-layer (IMAP) protocol oracle, plus a working bypass of the one control (`valid_imap_ports`) meant to constrain it.

## 1. Summary

SuiteCRM's IMAP "Test Settings" popup lets any authenticated user probe an arbitrary `host:port` and get a live IMAP connection outcome back. A port allow-list (`valid_imap_ports`) exists, but it only inspects one specific request field (`port`); a second, independent field (`connection_string`) is used verbatim to build the actual connection target and is never checked against that allow-list at all. Static analysis of the lab initially assumed this sink was unreachable because the classic PHP `imap` C extension isn't installed — dynamic testing disproves that: this SuiteCRM fork has switched to a pure-PHP IMAP client library that has no such dependency, and the sink is fully live.

## 2. How it works (mechanism & code trace)

**Entry point** — `modules/InboundEmail/Popup.php:112-138`, the "Test Settings" popup, reachable by any authenticated user with no admin/owner check:
```php
$ie->server_url = $_REQUEST['server_url'];
$ie->port       = $_REQUEST['port'];
...
if (!empty($_REQUEST['connection_string'])) {
    $ie->connection_string = urldecode($_REQUEST['connection_string'] ?? '');
}
if ($popupBoolean) {
    $msg = $ie->connectMailserver(true);
}
```

**The bypass** — `modules/InboundEmail/InboundEmail.php`:
```php
// :6407-6408, getConnectString()
if (!empty($this->connection_string)){
    $connectString = '{' . $this->connection_string . '}';   // used AS-IS, whatever port/host it names
} else {
    ...
}
// :6465, connectMailserver() -- the ONLY allow-list check in this whole flow
if (empty($this->port) || !in_array($this->port, $sugar_config['valid_imap_ports'] ?? [], true)) {
    return $mod_strings['ERR_INVALID_PORT'] ?? "Invalid port";
}
```
The port check at `:6465` inspects `$this->port` only. `getConnectString()` at `:6407` takes an entirely separate branch when `connection_string` is set, and that branch's host/port are never fed back into the `:6465` check. Sending a whitelisted `port` (e.g. `143`) satisfies the gate; the `connection_string` then determines where the real connection actually goes.

**The extension-dependency correction**: `InboundEmail::getImapHandlerType()` (`:8741`) is hardcoded `return 'imap2';`. `ImapHandlerFactory::getHandlers()` (`include/Imap/ImapHandlerFactory.php:262`) maps `'imap2'` to `Imap2Handler` (`include/Imap/Imap2Handler.php`), which is built on the Composer package `javanile/php-imap2` (`use Javanile\Imap2\Connection;` at the top of the file; confirmed installed via `composer show` inside the app container: `javanile/php-imap2  0.1.10`). This package is a **pure-PHP, socket-based** IMAP client — `Imap2Handler::isAvailable()` checks `function_exists('imap2_open')`, a function the *package* defines, with zero dependency on the PHP `imap` C extension. The classic, extension-gated `ImapHandler` class exists in the codebase but is simply never selected by this code path.

## 3. Why it is a vulnerability (reasoning)

Two independent things need to be true for the operator's stated control to hold, and neither does: (1) the allow-list must actually cover every way the destination can be specified, not just the field name that happens to be checked — `connection_string` is a second, unchecked route to the same underlying "where do we connect" decision `port`/`server_url` are meant to govern; (2) an environment lacking the historical `imap` extension must not be assumed safe from this class of bug — this fork's own dependency choice (`javanile/php-imap2`) quietly removed that assumption's validity without any corresponding update to the allow-list logic. Both are the kind of gap that's invisible from a quick code read of the "port whitelist" alone, and exactly why dynamic validation matters here: the static analysis's own caveat ("cannot be exercised live here") turned out to be based on a false premise about which IMAP backend actually runs.

## 4. Reproduction

From a clean state:

1. **Preconditions**: `automation.py` creates a throwaway non-admin user and starts a raw TCP listener on `172.18.0.1:33119` that sends an IMAP greeting banner with a random canary on accept.
2. **Attack request** (`request.http`):
   ```
   POST /index.php?module=InboundEmail&action=Popup&target=Popup
   port=143&connection_string=172.18.0.1:33119/imap/notls&server_url=172.18.0.1&protocol=imap&ssl=false
   ```
3. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected/observed: exit 0, `==> VULN-046: CONFIRMED`.
4. **Observable proof** — `evidence/oob_listener.log`:
   ```
   HIT from 172.18.0.3:55450: client sent b'A0001 CAPABILITY\r\n'
   ```
   `A0001 CAPABILITY` is a real, tagged IMAP client command — proof of a full protocol round-trip (banner read, command issued) with the internal-only listener, not merely a TCP SYN/connect.

## 5. Impact

- **Confidentiality/reconnaissance**: an IMAP-protocol-aware oracle for internal service discovery — success/failure and protocol-level responses (banners, error text surfaced in the popup) reveal open ports and service identity on hosts the attacker cannot reach directly.
- **Whitelist bypass**: demonstrates the one control present (`valid_imap_ports`) does not actually constrain the reachable target set, because a second field overrides it unchecked.
- **Escalation potential noted in the static finding**: the historical `imap_open()` `-oProxyCommand` RCE (CVE-2018-19518) is specific to the legacy C-extension client and does not apply to the `javanile/php-imap2` backend actually in use here; that escalation path is not established by this dynamic test and should not be assumed.
- **Pre/post-auth**: post-auth, lowest privilege — no admin/owner gate on the popup.
- **Chaining**: same SSRF cluster as [VULN-045](../VULN-045/writeup.md) (SMTP full-read), [VULN-014](../VULN-014/writeup.md), [VULN-094](../VULN-094/writeup.md), [VULN-085](../VULN-085/writeup.md), [VULN-047](../VULN-047/writeup.md).

## 6. Suggested fix

- Run `server_url` (and, critically, the host/port embedded in `connection_string`) through `validate_external_host()` before connecting, building an `http(s)://host:port`-shaped check target as the static finding recommends.
- **Remove the `connection_string` request field entirely**, or if it must remain for legitimate advanced configuration, parse it server-side and re-run the *same* port/host allow-list check against the parsed values before use — never accept a raw, unchecked connection descriptor from the client.
- Re-verify the port whitelist against whichever value is *actually* used to connect, not a separate, independently-suppliable field.

## 7. References

- CWE-918: Server-Side Request Forgery; CWE-863: Incorrect Authorization (whitelist bypass via an alternate parameter) — https://cwe.mitre.org/data/definitions/918.html
- OWASP SSRF Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy, "Server-side request forgery (SSRF)" — https://portswigger.net/web-security/ssrf
- `javanile/php-imap2`: https://github.com/javanile/php-imap2 (pure-PHP IMAP client — the dependency that makes this sink live without the `imap` C extension)
- Known-issue family: CVE-2026-69137 (test-connection SSRF cluster) — this is the concrete IMAP `connection_string`/port-bypass instance in that family.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 40 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM valid_imap_ports connection_string SSRF InboundEmail Popup test settings` — only community threads about `valid_imap_ports` rejecting ports after the 7.14.2 upgrade; no advisory on `connection_string`
2. `SuiteCRM InboundEmail "test settings" SSRF IMAP port scan CVE advisory` — CVE-2023-6388 (getimagesize), CVE-2025-54788 (InboundEmail SQLi), CVE-2026-29107 (PDF); none describe the IMAP test popup or a whitelist bypass
3. Fetched MITRE CVE-2023-6124 — "SSRF in salesagility/suitecrm prior to 7.14.2, 8.4.2, 7.12.14" (huntr aed4d8f3, huntr page does not render); no component in the text
4. Downloaded the CVE-2023-6124 fix commit (54bc56c3) diff — adds `valid_imap_ports` to config defaults and inserts the `in_array($this->port, $sugar_config['valid_imap_ports'])` check in `InboundEmail::connectMailserver()`; it does not touch `getConnectString()` or validate `connection_string`
5. `CVE-2026-69137 ...` / exploit-db 52686 — CalendarAccount `testConnection` CalDAV SSRF, different module
6. Fetched sonarsource.com "Breaking Into Your Internal Network" and CVE-2019-13335 — neither describes the IMAP test popup

**Related but distinct public references** (same class or component, not this bug):
- CVE-2023-6124 — SAME component (`InboundEmail::connectMailserver()` reached from the test popup). Its fix (7.14.2) is exactly the `valid_imap_ports` allow-list this finding bypasses; the public record does not describe the `connection_string` override in `getConnectString()`, which is the root cause here. The fix also never restricted the target host, so arbitrary-host probing on allow-listed ports was left as accepted residual
- CVE-2026-69137 / GHSA-72r3-24x4-j46c — "test connection" SSRF in CalendarAccount (<= 7.15.1); same pattern, different module
- CVE-2018-19518 — PHP `imap_open` `-oProxyCommand` RCE; historical context for why IMAP connection strings are dangerous, but not applicable to the `javanile/php-imap2` backend in use

**Reasoning:** The underlying "IMAP Test Settings reaches arbitrary host:port" SSRF is publicly known as CVE-2023-6124 and was patched in 7.14.2 by a port allow-list; what is not public is that `connection_string` is a second, unchecked request field that overrides the host and port used by `getConnectString()` and therefore defeats that allow-list on 7.15.2. This is an incomplete-fix bypass rather than a new sink, so confidence that it is unknown is low-moderate; it should be reported as a bypass of the CVE-2023-6124 fix rather than as an independent SSRF.
