# VULN-007 — CRLF / log injection into the Common Log Format access line

| | |
|---|---|
| **ID** | VULN-007 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | Medium · CVSS 3.1 **5.3** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic, in-lab end-to-end)** |
| **Auth required** | None (anonymous HTTP, Surface A) |
| **Attacker gains** | Forge arbitrary access-log records; corrupt audit/SIEM trails |

## Summary
Zappa writes every request to an NCSA Common Log Format line by interpolating request-derived strings with
**no CR/LF neutralisation**. The path is `unquote()`-decoded before it reaches the formatter, so `%0d%0a`
in the request path becomes a real CRLF inside the log line — letting an attacker inject newlines and forge
entire, attacker-authored log records. Verified live: a single crafted GET produced a standalone forged
access-log entry (spoofed source IP, fake request) in the container log stream. (Stage 09 had this as
NEEDS_MANUAL pending transport confirmation; the lab now confirms end-to-end reachability.)

## How it works (mechanism & code trace)
**Source** — the path is decoded early:
```python
# targets/Zappa/zappa/wsgi.py:129
path = unquote(event_info["path"])          # %0d%0a -> "\r\n"
# ...becomes environ["PATH_INFO"] via get_wsgi_string() (latin-1 round-trip, no stripping)
```
**Sink** — the log formatter interpolates it verbatim:
```python
# targets/Zappa/zappa/utilities.py:1039-1051
method = environ.get("REQUEST_METHOD", "")
path_info = environ.get("PATH_INFO", "")
...
request = f"{method} {path_info}{query_string} {server_protocol}"
referer = environ.get("HTTP_REFERER", "")
agent = environ.get("HTTP_USER_AGENT", "")
log_entry = f'{host} - - [{display_datetime}] "{request}" {status_code} {content_length} "{referer}" "{agent}"'
# common_log() then: logger.info(log_entry)   (wsgi.py:205)
```
No field (`path_info`, `query_string`, `host`, `referer`, `agent`) is escaped for CR/LF. An embedded newline
splits `log_entry` into multiple log lines, the extra ones fully attacker-authored.

**The exact defect** — untrusted request data flows into a newline-delimited log record with no
neutralisation (CWE-117). `host` here is itself `REMOTE_ADDR`, which is attacker-controlled via VULN-005,
so the forged line's source IP is also chosen by the attacker.

## Why it is a vulnerability (reasoning)
Access logs are an integrity/audit control. The invariant "one request → one, faithful log line" is broken:
an attacker writes arbitrary additional records — fake source IPs, fake requests, or planted error lines —
and can bury real activity. This defeats log-based detection/forensics and can inject content into a
downstream log viewer/SIEM.

## Reproduction
1. Lab up; run `./run.sh` (it uses a random marker so it matches only its own forged line).
2. Decisive request (`request.http`): `GET /x%0d%0a<URL-encoded forged CLF record>`.
3. Proof (`response.txt`/`run.log`): the container log contains a standalone line beginning
   `66.66.66.66 - - [01/Jan/2099:00:00:00 +0000] "GET /admin/PWN_<rand> HTTP/1.1" 200 0 "-" "-"` — an entry
   the server never actually served.
4. Expected `[OK] exploit confirmed` / `==> VULN-007: CONFIRMED`.

Reachability caveat: the lab preserves the encoded `%0d%0a` in `RAW_URI`, matching how API Gateway/ALB
forward percent-encoded path octets to the integration; a front proxy that pre-decodes and rejects control
chars would block the *path* vector (the sink stays vulnerable to any field delivered with a raw CR/LF).

## Impact
Log forging / audit-trail integrity loss for anyone relying on the CLF logs. Most valuable as the
"cover-the-tracks" tail of another attack. **Chains:** with VULN-005 the forged line's source IP is
attacker-chosen; compounds VULN-006 (verbose logging) and undermines any log-based rate-limit/fraud
detection.

## Suggested fix
- In `format_log` (`utilities.py:1039-1051`), strip or percent-encode CR/LF and other control characters
  from `path_info`, `query_string`, `host`, `referer`, and `agent` before assembling the line.
- Prefer structured (JSON) logging where each field is a discrete, escaped value. Principle: neutralise
  untrusted data at the log boundary.

## References
- CWE-117 (Improper Output Neutralization for Logs).
- OWASP "Log Injection" / Logging Cheat Sheet. Related: VULN-005 (spoofed source IP in the same line).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `zappa common_log format_log log injection CRLF newline access log` — only Rack's CVE-2025-25184 (`Rack::CommonLogger`) and generic CWE-117 material; nothing on Zappa.
2. `Zappa serverless Python CVE security advisory` / GHSA / Snyk / OSV / repo security-advisories page — no Zappa advisory.
3. GitHub issue search `zappa/Zappa issues?q="log injection" OR CRLF OR common_log OR format_log` — three unrelated hits (ASGI PR, response-time fix, JSON-logger request).
4. `utilities.py` on master (fetched) — `format_log` still interpolates `path_info`, `query_string`, referer and user-agent with no CR/LF neutralisation; no upstream fix.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2025-25184 (Rack `CommonLogger` CRLF log injection) — identical class in a different project; useful precedent that this class is CVE-worthy.
- zappa #750 "JSON logger with Request ID and User ID" — feature request, not a security report.

**Reasoning:** No public reference describes CR/LF injection into Zappa's Common-Log-Format line. The class is common and the sink is small, so a private report cannot be excluded, but the public record is empty.
