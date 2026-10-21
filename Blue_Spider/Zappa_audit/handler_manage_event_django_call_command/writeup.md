# VULN-024 — `manage` event field → Django `call_command` (command injection)

| | |
|---|---|
| **ID** | VULN-024 |
| **Software** | Zappa |
| **Repository** | https://github.com/zappa/Zappa |
| **Affected version** | 0.62.1 (`zappa/__init__.py:34`); untagged `master`, no tagged release |
| **Commit** | `e9ecb1feea14974f7bd76a908ca22ba1c9860d36` |
| **Severity** | High (Critical via VULN-012) · CVSS 3.1 **8.2** — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Surface B invoke on a Django deployment (any AWS account via VULN-012) |
| **Attacker gains** | Runs any Django management command: DB dump (`dumpdata`), DB wipe (`flush`), settings leak (`diffsettings`), etc. |

## Summary
On a Django deployment the handler runs whatever management command an event names, splitting the string
into `call_command` args. `call_command` is Django's full management surface, so the event controls DB
dumps, DB wipes, and settings disclosure with no allow-list. Verified live on a minimal Django project:
`{"manage":"diffsettings"}` printed the project `SECRET_KEY`.

## How it works (mechanism & code trace)
```python
# targets/Zappa/zappa/handler.py:922-939
elif event.get("manage", None):
    from django.core import management
    ...
    app_function = get_django_wsgi(self.settings.DJANGO_SETTINGS)   # full Django bootstrap
    management.call_command(*event["manage"].split(" "))            # <-- attacker-chosen argv
    return {}
```
The event string is `.split(" ")` and its tokens become the argv to `django.core.management.call_command`,
run with the app's real settings, DB connection, and the Lambda role. No allow-list, no argument
validation. The exploit stands up a minimal Django settings module, drives the real handler with
`{"manage":"diffsettings"}`, and captures stdout containing `SECRET_KEY = 'django-insecure-SECRET-<rand>'`
(`response.txt`).

**The exact defect:** the same single-trust dispatcher as VULN-001/002 (CWE-77) — the event is treated as
trusted admin input. The naive `split(" ")` (not `shlex.split`) bounds multi-word arguments but leaves
single-token commands fully effective.

## Why it is a vulnerability (reasoning)
The invariant "only an authenticated admin runs management commands" is broken: any Surface-B caller does.
`diffsettings` leaks all settings (incl. `SECRET_KEY`, DB creds); `dumpdata auth.User` dumps the user table
(password hashes) to logs; `flush --no-input` destroys all data. This is full Django-admin control granted
to whoever can invoke the function.

## Reproduction
1. Lab up; run `./run.sh` (installs Django in-container, builds a minimal project, drives the `manage` branch).
2. Proof (`response.txt`): `SECRET_KEY = 'django-insecure-SECRET-<rand>'` printed by `diffsettings`.
3. Live AWS (Django): `aws lambda invoke --payload '{"manage":"dumpdata auth.User"}' out.json` → user table
   to CloudWatch; `{"manage":"flush --no-input"}` → data wipe.
4. Expected `[OK] exploit confirmed` / `==> VULN-024: CONFIRMED`.

## Impact
Full DB read (`dumpdata`), DB destruction (`flush`), and settings/secret disclosure (`diffsettings`),
bounded to Surface B and space-free argv tokens. **Chains:** VULN-012 → **VULN-024** → VULN-017; VULN-008
can pre-set `DJANGO_SETTINGS_MODULE`/DB env on a warm container.

## Suggested fix
- Gate `manage` behind an explicit opt-in setting (default off).
- Enforce an allow-list of permitted management commands; only after the command name is allow-listed, parse
  the remaining argv with `shlex.split` (never `split(" ")`).
- Document that any principal able to invoke the function inherits full Django-admin control.

## References
- CWE-77 (Command Injection). Upstream [#715](https://github.com/Miserlou/Zappa/issues/715). Chain: VULN-012 → VULN-024 → VULN-017.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 55 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `zappa "manage" event call_command django management command lambda invoke security` — only Zappa docs (describes `zappa manage` as a convenience; IAM breadth is the only security note).
2. `Zappa serverless Python CVE security advisory` / GHSA / Snyk / OSV / repo security-advisories page — no Zappa advisory.
3. Cited/related issues fetched: Miserlou/Zappa #715 (feature proposal for deploy-time management commands; only an `eval` vs `ast.literal_eval` aside) and zappa #893 (use `shlex` to split management args) — neither frames the `manage` branch as "anyone who can invoke runs any management command".
4. `handler.py` on master (fetched) — `management.call_command(*event["manage"].split(" "))` unchanged, no allow-list.

**Related but distinct public references** (same class or component, not this bug):
- README "zappa manage" — documented remote Django management feature; no security caveat.
- zappa #893 — same code path, argument-splitting bug only.

**Reasoning:** No public reference treats the event-driven `manage` -> `call_command` dispatch as a vulnerability. Caveat: it is a documented admin feature gated solely by invoke permission (same family as VULN-001/002), so the maintainer may call it by design; the novel element is reachability via VULN-012. Confidence moderate.
