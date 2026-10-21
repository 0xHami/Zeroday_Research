# VULN-007 — Broken `../` filter → admin arbitrary host file read

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (read); conditional High for the LFI→RCE `_pre.pm` variant
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- An admin-group agent session (the module is registered `Group=>['admin']`). Obtained by
  logging in as the seeded admin `root@localhost` / `ZnunyAdmin_2f8b`.
- No other state; the read targets host files that already exist (`/etc/passwd`, `/etc/shadow`).

## Request
See `request.http`. Decisive request (URL-decoded):

```
POST /znuny/index.pl
Action=AdminProcessManagement&Subaction=ProcessImport&ChallengeToken=<tok>
&ExampleProcess=/../../../../../etc/passwd
```

## Response
See `response.txt` / `run.log`. Screen-title oracle:
- `/etc/passwd`  → `Error - Admin - Znuny`            (file READ; content not valid process YAML)
- `/etc/shadow`  → `Fatal Error - Frontend - Znuny`   (present but not readable by www-data → "Could not read")
- nonexistent    → `Fatal Error - Frontend - Znuny`   (missing → "Could not read")

## Observation
Matches the static prediction exactly. The filter `s{/+|\.{2,}}{}smx` at
`AdminProcessManagement.pm:109` runs without `/g`; a leading-slash payload loses only that
first slash and every `../` survives, so `FileRead` at line 146 escapes
`$Home/var/processes/examples/` to arbitrary host paths. The readable/unreadable differential
(`passwd` vs `shadow`) proves the read genuinely hits the host FS with the web user's
privileges — not a path confined to the examples directory.

## Side effects
None. `ProcessImport` fails to parse `/etc/passwd` as a process (`ref ne 'HASH'`), so nothing
is written to the DB. Idempotent; safe to re-run.

## Research & references
- OWASP WSTG-ATHZ-01 "Testing Directory Traversal / File Include" — used the readable-vs-
  unreadable file differential (`/etc/passwd` vs `/etc/shadow`) as the confirmation technique
  for a blind/oracle traversal read. https://owasp.org/www-project-web-security-testing-guide/
- OWASP Path Traversal cheat: single-pass regex sanitisers (missing `/g`/recursion) are a
  classic bypass — confirmed here by tracing the Perl `s///` semantics.

## Content-exfil scope (honest bound)
Raw file bytes are not echoed back; the primitive is (a) a host-wide file **readability
oracle**, and (b) **full content disclosure only for files that parse as a process-YAML hash**
(these import and surface entity names). Perl files such as `Kernel/Config.pm` read
successfully (readable screen) but their contents are not reflected. The conditional
`_pre.pm`/`_post.pm` `Main::Require` (lines 124/192) is a separate LFI→RCE path that requires
staging a `.pm` at a resolvable location (not exercised here).
