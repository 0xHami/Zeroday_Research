# VULN-080 — Web-service `job_queue_next/cycle/run`: any authenticated user drives the scheduler/job queue

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 3.1 6.3 — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L`)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: see `run.log`

## Preconditions
- Ordinary low-priv user `mod_a58707f7` (id `4741aa67-1567-43b2-8d70-13b5584384d3`), `is_admin=0`,
  no special Role — the bug needs none.
- Pre-existing lab state (not created by this test): 14 Active schedulers, `job_queue` table
  empty, several schedulers never having run (`last_run=NULL`) because `cron.php` is CLI-only and
  has never executed in this container (confirmed in stage-01).
- Setup note: an idempotency guard clears any stale `status='queued'` `job_queue` rows for the
  due schedulers left by an *earlier run of this same script* before re-testing (the job-queue
  dedups by scheduler, so a leftover queued row would mask the effect on re-run). Nothing else is
  modified.

## Request
Control (`request.http`-adjacent, invalid session):
```
method=job_queue_cycle&rest_data=["not-a-real-session-id","<random clientid>"]
```
Decisive request (`request.http`):
```
POST /service/v4_1/rest.php
method=job_queue_cycle&input_type=JSON&response_type=JSON&rest_data=
  ["<low-priv session>","lowpriv_client_9dd61730"]
```

## Response
Control: `{"name":"Invalid Session ID","number":11,"description":"The session ID is invalid"}`
(correctly denied — confirms the method does check *something*).
Decisive (`response.txt`): `{"results":"ok"}`.

**Real side effect** (independent of the API's own "ok"): `job_queue` went from **0 rows to 6
rows** in a single call, each new row tied to a currently-due Active scheduler:
```
target='function::sendEmailReminders'                              scheduler=dda14421-... status=queued
target='function::pollMonitoredInboxesForBouncedCampaignEmails'     scheduler=a10a684f-... status=queued
target='function::runMassEmailCampaign'                             scheduler=4224c7eb-... status=queued
target='function::aorRunScheduledReports'                           scheduler=554c283a-... status=queued
target='function::pollMonitoredInboxesAOP'                          scheduler=609fd96e-... status=queued
target='function::processAOW_Workflow'                              scheduler=8c700b3c-... status=queued
```

## Observation
Matches the static finding exactly: `job_queue_cycle` (`service/v4/SugarWebServiceImplv4.php:719-730`)
is gated only by `checkSessionAndModuleAccess($session,...,'', 'read', ...)` — an empty module
argument, i.e. session-only, no `is_admin` check anywhere. Live evidence goes further than "it
returned ok": the DB shows six real business-process jobs (mass-email campaigns, inbound-mail
polling, workflow processing, scheduled report generation) were genuinely enqueued by a single call
from a brand-new, non-admin account — this is not a permission-error-shaped success, it is the
actual scheduler/job-queue machinery firing.

## Side effects
1 throwaway low-priv user. 6 `job_queue` rows created (status `queued`, never consumed since no
cron process runs in this lab) — these are the real, intended proof of execution, not incidental
noise; they do not send email or run reports themselves (that requires a subsequent
`job_queue_run`, which this test deliberately did not call, per the "call once, do not spam"
instruction). No destructive changes.

## Research & references
CWE-285 (Improper Authorization) / CWE-639. Adjacent public issue: CVE-2026-63111 /
GHSA-gx3x-3f4c-cjmx (non-admin `SchedulersJob` reach escalating to SSRF) — same non-admin reach
into the scheduler machinery, different exploitation angle (there: SSRF via job execution; here:
unauthorized triggering of the job-queue cycle itself).
