# VULN-010 — `AgentAppointmentEdit` missing calendar authorization (disclosure + create/move + delete side-effects)

| | |
|---|---|
| **ID** | VULN-010 (raw ZN-021/022/026) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium · CVSS 3.1 **6.5** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | any agent (module registered with empty Group/GroupRo) |
| **Attacker gains** | Reads appointments in, and creates/moves appointments into, calendars they have no permission on. |

## Summary
`AgentAppointmentEdit` is reachable by any agent. Its `EditMask` fetches the caller's
`CalendarPermissionGet` but never acts on it before rendering the appointment; its create path
(no `AppointmentID`) skips the permission block entirely. So any agent reads and writes
appointments across calendars they cannot access. Confirmed: an agent with `CalendarPermissionGet
= ''` on a foreign calendar both disclosed a confidential appointment via `EditMask` and created
a new appointment in that calendar via `EditAppointment`.

## How it works (mechanism & code trace)
Entry — `POST index.pl?Action=AgentAppointmentEdit` (any agent; `ChallengeTokenCheck` at `:89`
uses the attacker's own token). In `Kernel/Modules/AgentAppointmentEdit.pm`:

**Disclosure (EditMask).** The appointment is fetched and its permission computed but never
enforced:
```perl
143:  my %Appointment = $AppointmentObject->AppointmentGet( AppointmentID => $GetParam{AppointmentID} );
169:  my $Permissions = $CalendarObject->CalendarPermissionGet( CalendarID => $Appointment{CalendarID}, UserID => ... );
      # ... $Permissions is never checked; the mask renders %Appointment regardless
```
**Create (EditAppointment, no AppointmentID).** The permission block is inside
`if ($GetParam{AppointmentID})` (`:1082-1120`), so a create request bypasses it and reaches:
```perl
1554:  my $AppointmentID = $AppointmentObject->AppointmentCreate( %GetParam );   # into attacker-chosen CalendarID
```
The move variant checks only the *source* calendar (`:1088-1090`), never the destination
`$GetParam{CalendarID}`; the delete variant runs `LinkDelete`/plugin side-effects before the sole
gate inside `AppointmentDelete`.

**Confirmed at the boundary.** `CalendarPermissionGet(attacker, cal) = ''` (no access), yet
EditMask returned the confidential title and a new `calendar_appointment` row appeared in the
foreign calendar.

## Why it is a vulnerability
Calendars are group-scoped; the invariant is "you may read/modify appointments only in calendars
your group grants you access to." `AgentAppointmentEdit` computes that permission (proving intent)
but fails to enforce it on read, and omits it entirely on create/move — a Broken Object-Level
Authorization. The source-diff makes the omission concrete: the CVE-2021-36091 fix added the check
only to the *list feed* (`AgentAppointmentList.pm:123`); the Edit read/create/move/delete paths
were left ungated. Impact is confidentiality-high (cross-calendar appointment content, which can
include meeting subjects, attendees, locations, notes) plus integrity/availability from
unauthorized create/move and pre-delete side-effects.

## Reproduction
1. Create a group the attacker is not in; via the Calendar API create a calendar in it and a
confidential appointment. 2. As any agent, `POST …Subaction=EditMask;AppointmentID=<foreign>` →
title disclosed; `POST …Subaction=EditAppointment;CalendarID=<foreign>;Title=INJECTED;…` (no
AppointmentID) → new appointment. 3. `./run.sh`:
```
[PROOF] attacker CalendarPermissionGet on foreign calendar 8 = '' (empty = no access)
[PROOF] confidential appointment title 'CONFIDENTIAL-APPT-…' disclosed to attacker: True
[PROOF] attacker-created appointment in foreign calendar: [['8','INJECTED-…']]
```

## Impact
Any agent reads confidential appointments across all calendars (C:H) and injects/moves
appointments into calendars they cannot access (I/A:L). The delete path additionally executes
link/plugin side-effects before its permission gate. Broad because the module is open to every
agent.

## Suggested fix
Enforce `CalendarPermissionGet` in `EditMask` (deny render if the returned permission is
insufficient), and add the permission check to the create/move paths against the *destination*
`CalendarID` — not only inside the `if ($GetParam{AppointmentID})` branch. Move the delete-path
gate before the `LinkDelete`/plugin side effects.

## References
- CVE-2021-36091 (list-feed fix; siblings survive). OWASP API1:2023 BOLA, WSTG-ATHZ-04. CWE-862.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 55 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. ZSA-2021-10 advisory page fetched — "authenticated agent is able to list appointments for calendars which he has no access to"; names only the appointment *list*, not Edit/create/move/delete
2. OSA-2021-14 (CVE-2021-36091) advisory page fetched — same wording ("list appointments"), fixed OTRS 7.0.28 / CE 6.0.x; no mention of the edit screen
3. NVD API keyword pull for "Znuny"/"OTRS" grepped for calendar/appointment — CVE-2019-10066 (appointment XSS), CVE-2021-36091 (list), CVE-2021-36094 (appointment edit screen XSS), CVE-2022-32739 (ICS banner); no edit/create authorization CVE
4. Znuny advisory index ZSA-2021-01 … ZSA-2026-16, GitHub advisory DB, Debian tracker reviewed — no later calendar advisory
5. `gh search issues --repo znuny/Znuny "AgentAppointmentEdit"` / `"Appointment permission"` — no results
6. (Shared WebSearch budget was exhausted before this finding; evidence below comes from direct primary-source pulls: NVD CVE API, vendor advisory pages, GitHub advisory DB, Debian tracker, GitHub issue search.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2021-36091 / OSA-2021-14 / ZSA-2021-10 — same calendar subsystem and same missing-`CalendarPermissionGet` root cause, but the advisory and (per the scanner's source diff) the fix cover only the `AgentAppointmentList` feed; `AgentAppointmentEdit` read/create/move/delete were not addressed
- CVE-2021-36094 / OSA-2021-18 — XSS via a crafted request to the appointment *edit* screen; same module, different class

**Reasoning:** No public advisory describes missing calendar authorization in `AgentAppointmentEdit` (EditMask disclosure, create/move into a foreign calendar, pre-gate delete side-effects). It is, however, a close sibling of CVE-2021-36091 in the same subsystem with the same root cause, and a vendor could reasonably regard it as an incomplete fix of that CVE rather than a new issue, so confidence is only moderate.
