# VULN-045 — SMTP "Test Settings" full-read SSRF (arbitrary host:port + transcript exfiltration)

**ID**: VULN-045
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`suitecrm_version.php`), commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: High — **CVSS 3.1 8.5** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`
**Status**: CONFIRMED (dynamic)
**Auth required**: Any authenticated user — a freshly-created, non-admin regular user (`is_admin=0`) is used in the reproduction; no elevated role, ACL grant, or admin panel access is needed.
**What an attacker gains**: server-side port-scanning/banner-grabbing of hosts on the application's internal network (databases, caches, metadata services, other containers/VMs) with the **full response content** of any server-speaks-first service returned directly in the HTTP response — not merely a blind "it connected" signal.

## 1. Summary

SuiteCRM's "Test Outbound Settings" feature (used to validate SMTP credentials before saving an email account) lets any logged-in user supply an arbitrary `mail_smtpserver`/`mail_smtpport` and have the **server** open a TCP/SMTP connection to it. The resulting PHPMailer session transcript — every byte the target sent back — is packaged into JSON and returned to the browser. Because there is no host/IP validation and no port allow-list, and because the transcript is disclosed rather than only a success/failure flag, this is a full-read SSRF primitive: an attacker with only a low-privilege CRM login can reach any host:port visible from the app server's network position (internal services, cloud metadata endpoints, etc.) and read back what they say.

## 2. How it works (mechanism & code trace)

**Entry point** — `modules/Emails/EmailUIAjax.php:1354`, `case "testOutbound":`
```php
$out = $email->sendEmailTest(
    $_REQUEST['mail_smtpserver'],
    $_REQUEST['mail_smtpport'],
    $_REQUEST['mail_smtpssl'],
    (isset($_REQUEST['mail_smtpauth_req']) ? 1 : 0),
    $_REQUEST['mail_smtpuser'],
    $pass,
    $_REQUEST['outboundtest_from_address'],
    $_REQUEST['outboundtest_from_address']
);
$out = $json->encode($out);
echo $out;
```
Reached via `index.php?module=Emails&action=EmailUIAjax` (any authenticated session — no `is_admin()` gate on this branch; the `is_admin` check earlier in the file at `:111` only controls *impersonating another user's* mail settings, not access to `testOutbound` itself).

**Sink** — `modules/Emails/Email.php:807-861`, `sendEmailTest()`:
```php
$mail = new SugarPHPMailer(true);
$mail->Mailer = strtolower($mail_sendtype);
if ($mail->Mailer == 'smtp') {
    $mail->Host = $mailserver_url;      // :822 — attacker-controlled, no validate_external_host()
    $mail->Port = $port;                // :823 — attacker-controlled, no port whitelist
    ...
}
...
if (!$mail->Send()) {
    ...
    $return['errorMessage'] = $app_strings['LBL_EMAIL_ERROR_PREPEND'] . $mail->ErrorInfo;
    $return['fullSmtpLog'] = $mail->fullSmtpLog;   // :859 — full SMTP transcript returned to the browser
    return $return;
}
```
`$mail->Host`/`$mail->Port` flow straight from `$_REQUEST['mail_smtpserver']`/`$_REQUEST['mail_smtpport']` with **no call to `validate_external_host()`** (the function that exists elsewhere in this codebase — `include/utils.php:6321` — specifically to reject private/link-local/reserved IPs) and **no port allow-list** (contrast the IMAP path at `InboundEmail.php:6465`, which at least checks `valid_imap_ports`). `include/SugarPHPMailer.php` records every line of the SMTP conversation into `fullSmtpLog` (`:513-527`); `Email::sendEmailTest()` puts that raw transcript directly into the JSON returned to the client.

**The defect in one line**: `modules/Emails/Email.php:822` — `$mail->Host = $mailserver_url;` — no allow-list, no `validate_external_host()`, no IP-literal/DNS-rebind protection, and the eventual transcript (`:859`) is handed back to the very same untrusted caller who chose the host.

## 3. Why it is a vulnerability (reasoning)

The trust boundary being violated is straightforward: the SuiteCRM application server sits on a network position (a Docker/VPC-internal network, cloud metadata endpoints, other backend services) that an external attacker's HTTP client cannot reach directly. A "test my mail server" feature legitimately needs to make *some* outbound connection, but it must be constrained to hosts the operator actually configured, or at minimum be blocked from RFC 1918 / link-local / loopback ranges the way `validate_external_host()` already does for other fetch paths in this same codebase (RSS dashlet, CalendarAccount). Here, neither control is applied, and the code goes one step further than a "blind" SSRF by echoing the literal bytes read from the target back to the attacker. There is no legitimate reason a mail-server connectivity test needs to expose the full protocol transcript (vs. a simple pass/fail) to the browser — this is what turns a garden-variety SSRF into a response-disclosing one, letting the attacker fingerprint and read the banners of arbitrary internal services from an ordinary, non-admin account.

## 4. Reproduction

From a clean state:

1. **Preconditions** (created by `automation.py`): a throwaway non-admin user is provisioned via the admin session (`_common.create_user`); a plain TCP listener is started on the host at `0.0.0.0:33119` that sends the single line `220 BANNER-LEAK-<random> ESMTP ready\r\n` on every accepted connection (the app container reaches this at `172.18.0.1:33119`, the docker bridge gateway, per `TARGET_FACTS.md`).
2. **Attack request** — the low-priv user's session POSTs:
   ```
   POST /index.php HTTP/1.1
   X-Requested-With: XMLHttpRequest
   Content-Type: application/x-www-form-urlencoded

   module=Emails&action=EmailUIAjax&emailUIAction=testOutbound
   &mail_smtpserver=172.18.0.1&mail_smtpport=33119&mail_smtpssl=0
   &mail_smtpauth_req=0&outboundtest_from_address=<addr>
   ```
   (full request in `request.http`).
3. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected/observed: exit 0, final line `==> VULN-045: CONFIRMED`.
4. **Observable proof** — `response.txt`'s JSON `fullSmtpLog` field contains, verbatim:
   ```
   2: SERVER -> CLIENT: 220 BANNER-LEAK-smtp_a11d457b ESMTP ready\r\n
   ```
   and `evidence/oob_listener.log` independently records the inbound connection from the app container's own IP:
   ```
   HIT from 172.18.0.3:47530: client sent b'EHLO localhost\r\n'
   ```
   Two independent signals — a real accepted TCP connection on a host the HTTP attacker cannot reach directly, and the exact random canary text reflected back through the unrelated HTTP response — together rule out coincidence or a cached/static response.

## 5. Impact

- **Confidentiality**: reads the banner/first response of any server-speaks-first service reachable from the app container (internal databases, caches, message queues, other microservices, cloud instance-metadata endpoints such as `169.254.169.254`). This is not limited to SMTP — any TCP service that "speaks first" (Redis, FTP, many internal RPC/health endpoints, SMTP/IMAP/POP relays) will have its greeting captured and returned.
- **Reconnaissance**: open/closed port state and service fingerprints across the internal network are trivially enumerable by iterating host:port, from a single ordinary user account.
- **Pre/post-auth**: post-auth, but requires only the lowest privilege level (a self-registered or admin-created regular user) — no special role or module ACL is checked on this branch.
- **Chaining**: combine with [VULN-036](../../vulns/VULN-036.md) (on-box mail-credential decryption) and the IDOR/SQLi read primitives in the report for deeper lateral movement once internal services are mapped; part of the same SSRF cluster as [VULN-047](../../vulns/VULN-047.md), [VULN-094](../../vulns/VULN-094.md), [VULN-014](../../vulns/VULN-014.md), [VULN-085](../../vulns/VULN-085.md).

## 6. Suggested fix

- At `modules/Emails/Email.php:822-823`, run `$mailserver_url` through `validate_external_host()` (`include/utils.php:6321`) before assignment, and enforce an SMTP-port allow-list (25/465/587) the same way `valid_imap_ports` gates the IMAP path.
- Never return `fullSmtpLog`/`ErrorInfo` verbatim to the client (`:859`); log server-side only, and return a generic boolean success/failure to the browser.
- Resolve the hostname once and connect to the pinned IP (prevents DNS-rebind bypass of the allow-list check, the same class of gap tracked in [VULN-014](../../vulns/VULN-014.md)).
- Principle: allow-list the destination (and pin the resolved IP), never merely deny-list; never forward raw upstream protocol bytes back to a lower-trust caller.

## 7. References

- CWE-918: Server-Side Request Forgery — https://cwe.mitre.org/data/definitions/918.html
- OWASP SSRF Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy, "Server-side request forgery (SSRF)" (blind vs. non-blind / response-disclosing SSRF) — https://portswigger.net/web-security/ssrf
- Related known-issue class in this codebase: CVE-2026-69137 / GHSA-72r3-24x4-j46c (CalendarAccount `testConnection` SSRF — same "test-connection returns data" pattern); guard-bypass class CVE-2026-61649 / GHSA-r665.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM testOutbound SSRF SMTP sendEmailTest mail_smtpserver fullSmtpLog` — only community "send test email" troubleshooting threads; no advisory
2. `SuiteCRM SSRF CVE outbound email test settings internal port scan 2024 2025 2026` — CVE-2026-29107 (PDF export), CVE-2023-6388 (getimagesize), CVE-2023-6124, CVE-2019-13335; none name the SMTP test
3. `GHSA-72r3-24x4-j46c SuiteCRM CalendarAccount testConnection SSRF` — CVE-2026-69137 confirmed as CalendarAccount `testConnection` (`server_url`, CalDAV), <= 7.15.1 / 8.10.1 (exploit-db 52686 fetched and verified)
4. `SuiteCRM "Test Settings" OR "testOutbound" OR "sendEmailTest" SSRF exploit huntr hackerone` (extended) — CVE-2026-69137, CVE-2026-29097 (RSS dashlet), CVE-2026-29107, CVE-2023-6388; nothing on the outbound-email test
5. `CVE-2023-6537 SuiteCRM SSRF description` — ID listed in 7.14.4 release notes but unresolvable in MITRE (404) / indexes; only CVE-2023-6388 returned
6. Fetched fluidattacks.com/advisories/leon (CVE-2023-6388) — `getimagesize` sink, no module named, fixed 7.14.4
7. Fetched MITRE CVE-2024-36414 — "connectors file verification" SSRF, fixed 7.14.4; not email
8. Fetched MITRE CVE-2023-6124 + downloaded fix commit 54bc56c3 diff — the SSRF fix is the `valid_imap_ports` check in `InboundEmail::connectMailserver()`; the only `modules/Emails/Email.php` hunk is null-coalescing in `save()`, so `sendEmailTest()` was not touched
9. Fetched sonarsource.com "SuiteCRM 7.11.4 Breaking Into Your Internal Network" — CVE-2019-12598 (Campaigns SQLi) + CVE-2019-12601 (OutboundEmail unserialize RCE); no SMTP/IMAP SSRF
10. Fetched CVE-2019-13335 (opencve) — generic "has SSRF" in 7.10.x < 7.10.19 / 7.11.x < 7.11.7; component not published

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-69137 / GHSA-72r3-24x4-j46c — same "test-connection SSRF" pattern but in `CalendarAccount::testConnection` (CalDAV `server_url`), not `Email::sendEmailTest()`
- CVE-2023-6124 — IMAP `InboundEmail::connectMailserver()` SSRF (fixed 7.14.2 with a port allow-list); sibling inbound path, not the SMTP outbound test
- CVE-2026-29097 (RSS dashlet), CVE-2026-29107 (PDF export), CVE-2024-36414 (connectors file verification), CVE-2023-6388 (`getimagesize`) — other SuiteCRM SSRF sinks, different components
- CVE-2019-13335 — SSRF in 7.10.x/7.11.x with no public component; cannot be fully excluded but was fixed long before 7.15.2 where this sink is confirmed live

**Reasoning:** SuiteCRM has at least seven published SSRF advisories, but none names the `EmailUIAjax` `testOutbound` action, `Email::sendEmailTest()`, `mail_smtpserver`/`mail_smtpport`, or the return of `fullSmtpLog` to the caller; the 7.14.2 SSRF fix commit was verified to touch only the IMAP path. Confidence is moderated because one old SSRF CVE (2019-13335) and one 7.14.4 ID (2023-6537) have no public component, and because the vendor has been actively fixing "test connection" SSRFs (CalendarAccount, March 2026), so a parallel private report on the SMTP sibling is plausible.
