# VULN-080 — Web-Service `job_queue_cycle`: Any Authenticated User Drives the Scheduler/Job Queue

**ID**: VULN-080
**Software / Repository**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2, commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1 6.3** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L`
**Status**: `CONFIRMED (dynamic)`
**Auth required**: Any authenticated web-service user — no admin flag, no special Role
**What an attacker gains**: The ability to force SuiteCRM's scheduler/job-queue machinery — the
same machinery that fires marketing email blasts, workflow automation, and inbound-mail polling —
to run out-of-band, at a time of the attacker's choosing, from the lowest privilege level.

## Summary

`job_queue_cycle` (and its siblings `job_queue_next`/`job_queue_run`) are internal web-service
methods that back SuiteCRM's job-queue/scheduler system — normally driven exclusively by the
CLI-only `cron.php`. They are reachable over the legacy REST API because dispatch there is
`method_exists()`-based, not an allow-list (see [VULN-063](../../vulns/VULN-063.md)'s reflection
dump, which lists them), and each method's only self-check is that *a* session exists — no
`is_admin` gate, no module ACL. Live testing proves this is not a theoretical reach: a
brand-new, non-admin user account called `job_queue_cycle` exactly once and the live database
shows six real scheduled jobs — mass-email campaign delivery, inbound-mailbox polling, workflow
processing, scheduled report generation — were genuinely enqueued as a result, starting from an
empty job queue.

## How it works (mechanism & code trace)

**Entry point**: `POST /service/v4_1/rest.php`, `method=job_queue_cycle`,
`rest_data=[session, clientid]`. Dispatch (`service/core/REST/SugarRestJSON.php:88-100`) invokes
any `public` method that `method_exists` on the implementation — `job_queue_cycle` is defined on
`SugarWebServiceImplv4` and inherited by `v4_1`, and is not part of any documented public API
surface, yet is reachable the same as `login` or `get_entry`.

**The defect** — `service/v4/SugarWebServiceImplv4.php:719-730`:
```php
public function job_queue_cycle($session, $clientid)
{
    if (! self::$helperObject->checkSessionAndModuleAccess($session, 'invalid_session',
            '', 'read', 'no_access', $error)) {          // :723  empty module -> session-only
        return;
    }
    $queue = new SugarJobQueue();
    $queue->cleanup();
    $queue->runSchedulers();                             // :729-730  runs every DUE scheduler
    ...
    return array("results" => "ok");
}
```
The empty `''` module argument means `check_modules_access()` never evaluates any module-level or
admin-level permission for this call — it is satisfied by any valid session, admin or not. There
is no `is_admin($user)` check anywhere in the method.

**Live confirmation** (full transcript in `run.log`): before the call, `job_queue` held 0 rows.
A control call with a deliberately invalid session id was correctly rejected
(`{"name":"Invalid Session ID","number":11,...}`), confirming the method *does* check something —
just not privilege. A single call with a freshly created, `is_admin=0` user's valid session
returned `{"results":"ok"}`, and the database then held 6 new `job_queue` rows, each tied to a
currently-due Active scheduler (`function::sendEmailReminders`,
`function::pollMonitoredInboxesForBouncedCampaignEmails`, `function::runMassEmailCampaign`,
`function::aorRunScheduledReports`, `function::pollMonitoredInboxesAOP`,
`function::processAOW_Workflow`). This is a real, independently-observable side effect — not a
permission-error dressed up as success.

## Why it is a vulnerability (reasoning)

The trust boundary is "who may trigger business-process execution outside its schedule." The
Admin > Scheduler UI restricts scheduler management to administrators, and the intended execution
path — `cron.php` — is deliberately CLI-only (gated by `php_sapi_name()`, per stage-01 analysis),
precisely so that HTTP requests cannot influence when scheduled jobs fire. `job_queue_cycle`
reaches the exact same `SugarJobQueue::runSchedulers()` call over HTTP, self-gated by nothing more
than "is logged in." This is a channel-divergence bug: the same operation is admin/CLI-restricted
on one path and open to any authenticated user on another. It is not deliberate design — nothing
suggests `job_queue_*` was ever meant to be an external API; it has no WSDL/registry entry and (per
[VULN-063](../../vulns/VULN-063.md)) is only discoverable via an unauthenticated reflection leak,
consistent with "internal plumbing exposed by omission," not a published capability.

## Reproduction

1. **Preconditions**: an ordinary authenticated low-priv account. No special setup — this lab's
   pre-existing Active schedulers and empty job queue were enough (see `notes.md` for the one-time
   idempotency note about clearing stale queue rows from an earlier run of this same script).
2. **Decisive request** (`request.http`):
   ```
   POST /service/v4_1/rest.php
   method=job_queue_cycle&input_type=JSON&response_type=JSON&rest_data=["<low-priv session>","<clientid>"]
   ```
3. Run `./run.sh` (`run.log` has the full transcript, including the invalid-session control).
   Expected:
   ```
   ==> VULN-080: CONFIRMED — low-priv user (is_admin=0) called job_queue_cycle once; results='ok';
   real side effect: ... job_queue count 0->6
   ```
4. **Observable proof**: `response.txt` shows `{"results":"ok"}`;
   `evidence/new_job_queue_rows.json` lists the six genuinely new `job_queue` rows (scheduler id,
   target function, status) that did not exist before the call.

This exploit calls `job_queue_cycle` **exactly once**, per the stage-10 instruction not to
loop/spam a scheduler-affecting primitive — reachability and real execution are both already
unambiguous from a single call.

## Impact

Any authenticated user — the lowest privilege level — can force SuiteCRM's due scheduled jobs to
run outside their configured schedule: campaign email blasts, inbound-mail polling, workflow
(AOW) processing, and report generation, among whatever else an administrator has scheduled.
Repeated calls (which this test deliberately avoided) would let an attacker pin worker execution
or force jobs to run far more often than intended — a denial-of-service lever — and the identical
non-admin reach into `SchedulersJob` underlies the public CVE-2026-63111 SSRF escalation, meaning
this reach is a known-dangerous capability class in this codebase. Impact is bounded to jobs that
already exist and schedulers that are due, which is why this sits at Medium rather than High, but
it directly chains with any campaign/mail-related finding to weaponize the forced execution.

## Suggested fix

Gate `job_queue_next`/`job_queue_cycle`/`job_queue_run` behind an explicit `is_admin()` check (or
remove them from the legacy REST-reachable class entirely and keep scheduler/queue execution to
the CLI cron path only). Separately, replace the `method_exists()` dispatch in
`SugarRestJSON.php:88` with a registry allow-list so internal methods without a WSDL/registry entry
are never externally reachable regardless of individual method self-checks.

## References

- CWE-285 — Improper Authorization
- CWE-639 — Authorization Bypass Through User-Controlled Key
- Adjacent public issue: CVE-2026-63111 / GHSA-gx3x-3f4c-cjmx (non-admin `SchedulersJob` reach escalating to SSRF) — same non-admin reach into the scheduler machinery.
- Technique used: single-call reachability + real-effect verification (DB diff of `job_queue` before/after, cross-referenced against the live `schedulers` table), with a negative control (invalid session) to confirm the method's check is session-only rather than absent-and-coincidentally-succeeding.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Fetched GHSA-gx3x-3f4c-cjmx (CVE-2026-63111, cited by the scanner) — non-admin *creates* `SchedulersJobs` records via the V8 API (`/Api/V8/module`) with arbitrary `url::`/`function::` targets because the bean has no ACL, leading to SSRF when cron runs them; fixed 7.15.2. The advisory does not mention `job_queue_cycle`, `job_queue_next`, `job_queue_run`, the legacy web service, or forcing *existing* due schedulers to run.
2. GitHub Advisory Database query `suitecrm scheduler` — 0 advisories.
3. GitHub issue search `repo:SuiteCRM/SuiteCRM job_queue_cycle` — 0 results.
4. Full SuiteCRM GHSA catalogue (77 advisories through 2026-10-12) reviewed — the only scheduler-related entry is GHSA-gx3x-3f4c-cjmx.
5. GitHub commit history of `service/core/SugarWebServiceImpl.php` / `service/v4/SugarWebServiceImplv4.php` lineage — no admin gate added to the `job_queue_*` methods.
(Note: the shared WebSearch budget was exhausted before this folder; checks were made by direct fetch of the advisory databases and the upstream repository.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-63111 / GHSA-gx3x-3f4c-cjmx — non-admin job *creation* through the V8 API (missing ACL on the `SchedulersJob` bean); this finding is non-admin *execution* of the scheduler cycle through the legacy web service's session-only `job_queue_cycle`/`job_queue_next`/`job_queue_run` methods. Different entry point and different missing check (admin gate on the method vs. ACL on the bean).

**Reasoning:** No advisory, CVE or issue describes the legacy web-service `job_queue_*` methods being reachable by any authenticated user to drive `SugarJobQueue::runSchedulers()`/`runJobId()`. The closest public item is the V8 SchedulersJob-creation SSRF, which shares the "non-admin reach into the scheduler" theme but has a different vector and fix. Caveat: the SchedulersJob fix shipped in the audited release itself, so the vendor may have reviewed adjacent scheduler entry points privately; and this method set is inherited from SugarCRM CE, where an older report could exist.
