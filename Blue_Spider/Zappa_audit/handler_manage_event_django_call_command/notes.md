# VULN-024 — manage event field -> Django call_command (command injection)

**Software**: Zappa
**Repository**: https://github.com/zappa/Zappa
**Affected version**: 0.62.1 (`zappa/__init__.py:34`) | commit-pinned: untagged master, no tagged release
**Status**: CONFIRMED
**Severity (static)**: High (Critical via VULN-012)
**Target commit**: e9ecb1feea14974f7bd76a908ca22ba1c9860d36
**Validated at**: 2026-09-29

## Preconditions
- Django deployment (`DJANGO_SETTINGS` set). Django installed into the lab container (in-container pip,
  disposable lab) + a minimal Django settings module. Surface B via the handler `manage` branch.

## Request / Response
See `request.http` / `response.txt` / `run.log`. Driving `handler({"manage":"diffsettings"}, ctx)` printed
`SECRET_KEY = 'django-insecure-SECRET-<rand>'` — the attacker-chosen command ran and leaked the secret.

## Observation
`handler.py:922-939` bootstraps Django (`get_django_wsgi`) then runs
`management.call_command(*event["manage"].split(" "))`. The event fully controls the argv. `diffsettings`
leaked `SECRET_KEY`; the same path gives `dumpdata` (DB exfil), `flush` (DB wipe), etc. No allow-list.

## Side effects
Installed Django in the lab container (persists across restart; the gateway uses Flask and never imports
Django, so no behavioural change). Wrote a temp sqlite settings module + db under `/tmp` in the container.

## Research & references
- CWE-77 (Command Injection). Django `call_command` management surface. Note the naive `split(" ")` bounds
  multi-word args but single-token commands (`flush`, `dumpdata`, `diffsettings`) are fully effective.

## If FAILED / NEEDS_MANUAL
n/a — CONFIRMED. (Stage 08/09 marked it NEEDS_MANUAL because the default harness is Flask; validated here by
standing up a minimal Django project in the lab container.)
