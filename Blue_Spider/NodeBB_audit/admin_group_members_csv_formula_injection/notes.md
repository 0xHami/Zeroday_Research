# VULN-010 — CSV/formula injection in group-members export

**Software**: NodeBB
**Repository**: https://github.com/NodeBB/NodeBB
**Affected version**: 4.16.0 (install/package.json:5; commit-pinned, untagged master)
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 20623201cbf2cc8a37612726cdf10ee82083c9c3
**Validated at**: 2026-09-28

## Preconditions
- An attacker-controlled account whose username (or email) begins with a formula trigger. Usernames
  permit leading `+`/`-` (isUserNameValid, `public/src/utils.common.js:341-346`); the exploit uses
  `+HYPERLINK_<rand>`. An admin later exports the group CSV (getCSV requires a Referer under
  `/admin/manage/groups`, `src/controllers/admin/groups.js:87`).

## Request / Response
See `request.http` / `response.txt` / `evidence/group_members.csv` / `run.log`. Captured group CSV:
```
"email","username","uid"
"admin@example.com","admin",1
"","+HYPERLINK_6a600426",9      <-- attacker username cell, un-neutralized (no leading apostrophe)
```

## Observation
Confirmed. The group export emitted the attacker's username cell `+HYPERLINK_6a600426` verbatim — it
begins with `+`, a spreadsheet formula trigger, and is NOT prefixed with the neutralizing apostrophe.
This matches `src/controllers/admin/groups.js:97-105`, which builds the CSV from raw `email/username/uid`
with no `neutralizeCsvFormula`. The users export (`src/user/admin.js:91,106-110`) DOES neutralize the
identical class of cell (regex `/^[\t\r ]*[=+\-@]/` → prefixes `'`), so the group export is a regression.
(The users-CSV endpoint could not be captured for a live side-by-side — it returned Not Found without the
right referer — so the contrast is cited from source, which is unambiguous.)

## Notes on payload reach
Usernames block `=`, `@`, `(`, `)` (isUserNameValid regex), so a username payload is limited to `+`/`-`
leading (still a formula trigger → the injection). For a full DDE/exfil formula (`=cmd|'/C calc'!A1`,
`=HYPERLINK(...)`), the EMAIL field is the vector: `isEmailValid` (`utils.common.js:337-339`) only
forbids `,`/`;`, so `=cmd|'/C calc'!A1@a.aa` passes. Admin-created users don't populate `email` directly,
but a self-registered user setting their own email does — that cell reaches the group export unescaped.

## Side effects
Creates one user (`+HYPERLINK_<rand>`) and one group (`csvgrp_<rand>`). Harmless; random suffixes.

## Research & references
- OWASP "CSV Injection" (Formula Injection) — https://owasp.org/www-community/attacks/CSV_Injection
- CWE-1236 (Improper Neutralization of Formula Elements in a CSV File).

## If FAILED
n/a — CONFIRMED.
