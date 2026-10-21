# VULN-029 — Seat/plan-cap over-provision race (FOR UPDATE lock not threaded into insert)

**Software**: ClassroomIO
**Repository**: https://github.com/classroomio/classroomio
**Affected version**: 0.1.13 (package.json) — commit-pinned
**Status**: CONFIRMED (over-provision reproduced under concurrent load: 8/8 accepts, active=27 > cap 20)
**Severity (static)**: Medium
**Target commit**: 0c356ad6f1a4d8449425b902afae58b3ebd9f443
**Validated at**: 2026-09-27

## Preconditions
- A capped (BASIC/Free, cap 20) org at cap-1 active students. The exploit provisions a
  FRESH org (cloud onboarding → no plan row → BASIC cap 20) and fills it to 19.

## Request
Fire K concurrent `POST /invite/r/<distinct-token>/accept` (distinct links per racer, to
avoid the invite-row lock serializing them) with 1 seat remaining.

## Response
Confirmed run (K=8, distinct links, fired under host load — see `run.log`):
`concurrent accept statuses: [(0,200),(1,200),(2,200),(3,200),(4,200),(5,200),(6,200),(7,200)]`
→ **8/8 succeeded**, `final active students = 27 (cap=20)`. (An earlier idle-host attempt had
serialized: 1 success, cap held at 20 — expected probabilistic TOCTOU behaviour, not a fix.)

## Observation
The over-provision reproduced: with one seat remaining, 8 concurrent joiners on distinct
invite links all passed the capacity check and all inserted, leaving the org 7 seats past its
BASIC cap. The code defect is exactly as the report describes and is confirmed by source:
`assertStudentCapacityOrThrow(orgId, additionalStudents, dbClient = db)`
(`apps/api/src/services/organization/student-limit.ts:86-131`) acquires the org-row lock
via `lockOrganizationForStudentCapacity` → `.for('update')` (`organization.ts:697-704`),
but the caller `acceptInviteLink` (`apps/api/src/services/invite-link/invite-link.ts:242`)
invokes it **without** passing its own transaction `tx` — so the lock and the subsequent
`countActiveStudents` run on the autocommit `db` pool, and the actual member insert happens
later in the caller's separate `tx`. The lock is therefore not held across check→insert.

Exploitation set up the precise boundary (cap-1) and gave each racer a distinct invite link
(so they don't serialize on `lockInviteLinkForAccept`, invite-link.ts:229), leaving only the
autocommit org-row `FOR UPDATE` in contention. Whether a burst over-provisions is probabilistic
and depends on the check→commit window width: on a fully idle single-node Postgres the window
is sub-millisecond and an isolated attempt serialized, but the run captured in `run.log` was
fired **while the host was under concurrent exploit load**, which widened the window enough
that all 8 accepts landed inside it → active=27 > cap 20. This is the real production condition
(a burst of sign-ups at launch) the seat cap must hold under, so the finding is CONFIRMED. The
4 atomic sibling callers cited by the report (which DO thread `tx`) confirm the pattern the
buggy caller omits.

## Side effects
Created a fresh throwaway org with ~20 test students + ~10 courses (random-suffixed).
Isolated from the main audit org.

## Research & references
- OWASP WSTG-BUSLOGIC-01 (race conditions); CWE-362 TOCTOU.
- Correct pattern: thread one `tx` through lock→count→insert (as `join.ts`, `course/invite.ts`
  atomic callers do), so `SELECT ... FOR UPDATE` is held until the insert commits.

## Reproducibility note
CONFIRMED via the `run.log` run (8/8, active=27). Because the window is load-dependent, a
re-run on a fully idle host may serialize (1 success); re-run under load, or with a real
parallel load generator (`hey`/`vegeta`/`k6`, or Go goroutines), to reproduce reliably.
Ground-truth check: `select count(*) from organizationmember where organization_id=<org> and
role_id=3 and (status is null or status='ACTIVE')` exceeding the plan cap confirms the bug.
