# VULN-010 — AgentAppointmentEdit missing calendar authorization

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (6.5)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- A calendar in a group the attacker is NOT in, holding a confidential appointment (created via
  the Calendar/Appointment API). Attacker `CalendarPermissionGet` on it = '' (proven, no access).
- Attacker: any agent (module has empty Group/GroupRo).

## Request / Response
- READ: `POST index.pl Action=AgentAppointmentEdit;Subaction=EditMask;AppointmentID=<foreign>;
  ChallengeToken=<attacker>` → response contains the confidential appointment title.
- WRITE: `POST …Subaction=EditAppointment;CalendarID=<foreign>;Title=INJECTED;StartTime=…` (no
  AppointmentID) → new row in the foreign calendar. See `request.http`/`response.txt`.

## Observation
`CalendarPermissionGet(attacker, cal)=''`. EditMask still disclosed the appointment, and
EditAppointment created an appointment in the foreign calendar. Confirms
`AgentAppointmentEdit.pm` fetches but never enforces `CalendarPermissionGet` on EditMask
(:169-172) and skips the permission block on the create path (no AppointmentID → :1082-1120
skipped).

## Side effects
Creates a calendar + two appointments (setup + injected), all random-suffixed. Idempotent.
(Setup note: `CalendarCreate` returns empty due to a stale cache but the row is inserted; the
exploit reads the id from the DB and flushes cache.)

## Research & references
- OWASP WSTG-ATHZ-04 (IDOR)/API1:2023 BOLA. CWE-862. Source-diff: CVE-2021-36091 gated only the
  list feed (`AgentAppointmentList.pm:123`); the Edit read/create/move paths remain ungated.
