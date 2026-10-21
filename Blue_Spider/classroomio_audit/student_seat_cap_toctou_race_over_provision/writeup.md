# VULN-029 — Seat/plan-cap over-provision race (FOR UPDATE lock not threaded into the insert)

| | |
|---|---|
| **ID** | VULN-029 (raw F-45) |
| **Software** | ClassroomIO |
| **Repository** | https://github.com/classroomio/classroomio |
| **Affected version** | 0.1.13 (`package.json`) — commit-pinned |
| **Commit** | `0c356ad6f1a4d8449425b902afae58b3ebd9f443` |
| **Severity** | Medium — **CVSS 3.1 5.9** `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** — over-provision reproduced under concurrent load (8/8 accepts, active=27 > cap 20) |
| **Auth required** | K concurrent joiners (each a normal signup) near the plan's seat cap |
| **What an attacker gains** | Exceed a paid plan's student seat cap (billing/seat-integrity bypass) |

## Summary

The Free (BASIC) plan caps a workspace at 20 active students. Enrolment checks the count
under an org-row `SELECT ... FOR UPDATE`, but the lock is taken on the autocommit `db`
client and is **not** threaded into the transaction that performs the membership insert, so
the lock is released before the insert commits. Concurrent joiners that all pass the
"count < cap" check when one seat remains can all insert, over-provisioning the org.
**Confirmed dynamically:** a fresh BASIC org was filled to 19/20 and 8 concurrent
share-link accepts (each on a *distinct* invite link, to remove the unrelated invite-row
serializer) were fired for the single remaining seat — **all 8 returned 200** and the org's
active-student count rose to **27**, seven seats past the cap of 20. The race reproduces
when the check→commit window is widened by server load (the run that fired was executed
while the host was under concurrent exploit load); an earlier idle-host single attempt had
serialized, which is the expected probabilistic behaviour of a TOCTOU, not a mitigation.

## How it works (mechanism & code trace)

**The lock helper — `packages/db/src/queries/organization/organization.ts:697-704`:**

```ts
export async function lockOrganizationForStudentCapacity(orgId, dbClient = db): Promise<void> {
  await dbClient.select({ id: schema.organization.id })
    .from(schema.organization).where(eq(schema.organization.id, orgId))
    .for('update').limit(1);          // row lock — but only for the life of THIS statement's txn
}
```

**The check — `apps/api/src/services/organization/student-limit.ts:86-131`:**

```ts
export async function assertStudentCapacityOrThrow(orgId, additionalStudents, dbClient = db, ...) {
  if (additionalStudents <= 0) return null;
  if (env.PUBLIC_IS_SELFHOSTED === 'true') return null;
  await lockOrganizationForStudentCapacity(orgId, dbClient);   // lock on `dbClient`
  const activePlan = await getActiveOrganizationPlan(orgId, dbClient);
  const limit = getStudentLimit(activePlan?.planName);          // BASIC → 20
  const currentCount = await countActiveStudents(orgId, dbClient);
  if (currentCount + additionalStudents > limit) throw new AppError(..., 'UPGRADE_REQUIRED', 403);
  ...
}
```

**The buggy caller — `apps/api/src/services/invite-link/invite-link.ts:227-253`:**

```ts
const { ... } = await db.transaction(async (tx) => {
  const locked = await lockInviteLinkForAccept(tx, inviteId);          // :229  invite-row lock (in tx)
  ...
  await assertStudentCapacityOrThrow(organizationId, 1);               // :242  ← NO `tx` passed!
  await createOrganizationMember({ ...member... }, tx);                // :245  insert in the tx
});
```

At line 242 the capacity check is invoked **without** the surrounding `tx`, so it defaults to
the autocommit `db` pool. Therefore the org-row `FOR UPDATE` is acquired and released on a
*different* connection than the one doing the insert, and it is gone before
`createOrganizationMember` (line 245) runs and commits. The check and the insert are not
mutually exclusive across concurrent callers → classic TOCTOU. The report notes three
sibling callers (`join.ts:115`, `course/invite.ts:704`, `audience.ts:566`) with the same
shape, and contrasts the atomic callers that correctly thread one `tx` through lock→count→insert.

## Why it is a vulnerability (reasoning)

The invariant is "active students ≤ plan seat cap." Enforcing it requires the count and the
insert to be serialized so two joiners cannot both consume the last seat. The lock exists for
exactly this purpose but is applied to the wrong client, so it does not span the insert —
leaving a window where K joiners all read `count = cap-1`, all pass, and all insert. This is
a billing/seat-integrity control (a Free tenant could exceed its paid limit), so the impact
is integrity of the plan model (I:H), `AC:H` because it needs a precisely-timed concurrent
burst.

Because it is a TOCTOU, whether any single burst over-provisions is probabilistic and depends
on the width of the check→commit window. An idle-host attempt serialized (one success, cap
held); the run captured in `run.log` was fired while the host was under concurrent load, which
widened the window enough that **all 8 accepts landed inside it** — the over-provision is real
and repeatable when contention exists, which is precisely the production condition (a burst of
sign-ups at a popular launch) the seat cap is meant to hold under.

## Reproduction

From a clean target (`docker compose -p cvehunt_classroomio up -d`):

1. `./run.sh` — the exploit signs up a fresh admin, creates a fresh org (cloud onboarding →
   no plan row → BASIC cap 20), creates a course + share link, and fills the org to 19 active
   students (cap−1).
2. It then creates 8 distinct joiner accounts + 8 distinct course share-links and fires the 8
   `POST /invite/r/<distinct-token>/accept` requests concurrently for the one remaining seat.
3. Observed proof (`run.log`): `concurrent accept statuses: [(0,200),(1,200),…,(7,200)]` —
   **8/8 succeeded** — and `final active students = 27 (cap=20)`. Ground-truthed by
   `select count(*) from organizationmember where organization_id=<org> and role_id=3 and
   (status is null or status='ACTIVE')` = 27 > 20.
4. `[OK] exploit confirmed` / exit 0.

Because the window is load-dependent, a re-run on a fully idle host may serialize (1 success);
re-run under load, or with a real parallel load generator (`k6`/`vegeta`/`hey`), to reproduce
the over-provision reliably.

## Impact

- A capped (Free/paid) tenant exceeds its student seat allowance → billing/seat-integrity
  bypass in the cloud/multi-tenant product. Dormant on a genuine self-hosted install (the
  check short-circuits when `PUBLIC_IS_SELFHOSTED==='true'`). Integrity only (I:H), `AC:H`.

## Suggested fix

Thread the caller's transaction into the capacity check so the `FOR UPDATE` lock is held
across the insert:

```ts
await db.transaction(async (tx) => {
  await lockInviteLinkForAccept(tx, inviteId);
  await assertStudentCapacityOrThrow(organizationId, 1, tx);   // pass tx  ← fix
  await createOrganizationMember({ ...member... }, tx);
});
```

Apply the same one-line fix to the other non-atomic callers (`join.ts:115`,
`course/invite.ts:704`, `invite-link.ts:241`, `audience.ts:566`). Principle: a lock guarding a
check-then-insert must be held in the same transaction as the insert.

## References

- OWASP WSTG-BUSLOGIC-01 (race conditions); CWE-362 (TOCTOU).
- PostgreSQL row locking / `SELECT ... FOR UPDATE` semantics (lock lifetime = transaction).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `ClassroomIO CVE security vulnerability` — 7 CVEs; none is a race condition (CWE-362).
2. `classroomio github security advisory GHSA` — 9 GHSAs; none on seat caps or concurrency.
3. `classroomio huntr vulnerability report` — no huntr/HackerOne reports for the project.
4. NVD API `keywordSearch=classroomio` (8 CVEs), `osv.dev/list?q=classroomio` (8), Snyk search (none), repo `security/advisories` (none) — no match.
5. Issue tracker `"race condition" OR concurrent OR TOCTOU OR "FOR UPDATE" OR over-provision OR "student cap" OR seat` — 106 hits (#1374/#1384 bulk enrolment, #1336 role-aware invites); none report concurrent joins exceeding the plan cap.
6. Issue tracker `"rate limit" OR x-forwarded-for OR "body size" OR "race condition" OR "student limit"` — #1236 (explain student limit on join failure), #1008 (make invite enrollment atomic); inspected below.
7. Commit search `"rate limit" OR bodyLimit OR "body limit" OR "trusted proxy" OR "student limit"` — fd8bec3e (#733, enforce free-plan cap; dedupe batch ids), 8bed9f6b (#735 backfill), 64112dfc (#788 docs PRD that mentions closing a "student-limit TOCTOU" as design guidance for a future events feature).
8. Fetched PR #1008 (merged 2026-09-02) — wraps invite acceptance in one transaction so enrollment errors roll back; the body does not mention the capacity check, `FOR UPDATE`, or over-provisioning; only an auto-generated CodeRabbit line says capacity checks "reduce the risk of exceeding student limits during concurrent enrollments". The audited commit (2026-09-27) post-dates #1008 and still calls `assertStudentCapacityOrThrow(organizationId, 1)` without `tx`, and the over-provision was reproduced live.
(Note: WebSearch quota exhausted after the general sweep; items 4–8 are direct queries of the vulnerability databases and the upstream tracker/commit history.)

**Related but distinct public references** (same class or component, not this bug):
- PR #1008 "fix(api): make invite enrollment atomic" — same code path (invite accept), but described as atomicity/rollback of the enrollment steps, not as a seat-cap race; the org-row lock is still not threaded into the transaction after it.
- PR #788 (docs PRD, 2026-07-31) — mentions a student-limit TOCTOU as a design concern for a different (events) feature; not a report against the invite/join callers.
- PR #733 / commit fd8bec3e — cap enforcement and batch de-duplication; not concurrency.

**Reasoning:** No public issue or advisory describes the `lockOrganizationForStudentCapacity` lock being taken on the autocommit client and released before the membership insert commits. Upstream has touched the same code path (#1008) and a design doc acknowledges the TOCTOU concept, which makes this a near-miss and lowers confidence to 65, but neither artefact describes or fixes this specific defect, and it reproduced after #1008.
