# VULN-005 — TOCTOU race-condition family (login throttle / poll / reputation / email)

| | |
|---|---|
| **Software** | MyBB |
| **Repository** | https://github.com/mybb/mybb |
| **Affected version** | 1.9.0-alpha.1 (`inc/src/Application.php:28`) |
| **Commit** | `f8bf4e840cd42f5d61bfb789eb3975674081d69e` (branch `dev-1.9`) |
| **Severity** | Medium — CVSS 3.1 **5.9** (`AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`) |
| **Status** | CONFIRMED (dynamic, poll-vote leg) — sibling legs share the root cause |
| **Confidence** | 6/10 — one leg proven; family is real but AC:H (must win a race) |
| **Auth required** | Varies by leg: none (login throttle) / a user (poll, reputation) / guest (registration) |
| **Attacker gains** | Ballot stuffing; weakened login throttle; reputation inflation; duplicate-email accounts |

## Summary

Several MyBB flows follow a "check then act" pattern with no transaction, row lock,
or `UNIQUE` constraint on the relevant columns, so concurrent requests all read the
same pre-write state and all proceed (CWE-367). Demonstrated end-to-end on poll
voting: a single user who has never voted cast **three** ballots on one poll by
firing concurrent vote requests. The headline leg — the login throttle — shares the
same shape and additionally checks the throttle *before* incrementing the counter,
the inverse of the correct order used in the ACP.

## How it works (mechanism & code trace)

Poll vote (the proven leg):

```php
// targets/mybb/polls.php:999-1010
$query = $db->simple_select("pollvotes", "*", "{$user_check} AND pid='".$poll['pid']."'");
$votecheck = $db->fetch_array($query);
if($votecheck) { error($lang->error_alreadyvoted); }   // CHECK
...
$db->insert_query("pollvotes", $votesql);               // ACT — no transaction/lock/UNIQUE
```

There is no `UNIQUE(pid,uid)` on `pollvotes` and no `SELECT … FOR UPDATE`/
transaction around the check+insert, so N requests that interleave between the
`SELECT` and the `INSERT` all see "not voted" and all insert.

Login throttle (headline leg) — same shape **plus** an ordering bug:

```php
// targets/mybb/member.php:1767-1769
$logins = login_attempt_check($login_user_uid);                        // CHECK (read-only gate)
$db->update_query("users", array('loginattempts' => 'loginattempts+1'),
                  "uid='".$login_user_uid."'", 1, true);               // INCREMENT after the gate
```

The ACP does the inverse (increments, then checks — `admin/index.php`), so the
front-end order is demonstrably wrong: N concurrent attempts at the threshold all
read a sub-limit count and are all evaluated. Legs C (reputation,
`reputation.php:152-369`) and D (duplicate-email registration,
`inc/datahandlers/user.php:280-291`) are the same check-then-insert without a
`UNIQUE` key.

**Dynamic confirmation (poll leg).** An open poll was created on a thread; a single
voter fired 30 concurrent `POST /polls.php?action=vote&option=1`. Result:

```
pollvotes rows for the single voter: before=0, after=3   (poll.numvotes=1)
```

Three ballots from one user — the check+insert was not atomic. (The poll's
`numvotes` counter, updated by a separate non-atomic `UPDATE`, lands at 1, so the
displayed tally even disagrees with the real ballot count.)

## Why it is a vulnerability (reasoning)

Each affected flow enforces a "once" or "limit" invariant — one vote per user, N
login attempts per window, one reputation entry per (rater, target), one account
per email. Those invariants are expressed as a read followed by a conditional write
with nothing guaranteeing the two happen as a unit, so an attacker who issues
requests concurrently overruns the limit. For voting this is ballot stuffing; for
the login throttle it means ~N guesses per window instead of the configured 10 (and
skips the mid-burst CAPTCHA), weakening the primary online-brute-force control. The
"check" code proves the intended invariant; its non-atomicity is the defect. Medium
and AC:H because landing it requires winning a millisecond race and the per-leg
impact is integrity/policy rather than RCE.

## Reproduction

From a clean lab (`http://localhost:25850`):

1. `./run.sh` creates a thread, provisions an open poll on it, creates a fresh
   voter, and fires 30 barrier-synchronised concurrent votes for option 1.
2. **Proof:** `SELECT COUNT(*) FROM pollvotes WHERE pid=<pid> AND uid=<voter>`
   returns >1 (3 in the recorded run) — multiple ballots from one user
   (`response.txt`).

```bash
cd claude_audit/mybb/exploits/VULN-005 && ./run.sh   # ==> VULN-005: CONFIRMED
```

Raise `CONCURRENCY` if a slow run doesn't land the race. The login-throttle,
reputation and email legs are the same pattern — see `notes.md` for their manual
race checklists.

## Impact

Ballot stuffing (demonstrated); amplified credential guessing against the login
throttle (the headline risk — more attempts per lockout window and a skipped
CAPTCHA); reputation inflation; and duplicate-email accounts. None reach RCE;
scored Confidentiality/Integrity Low, AC:H.

## Suggested fix

Make each check-then-act atomic and back it with a database constraint:

```sql
ALTER TABLE mybb_pollvotes  ADD UNIQUE KEY uniq_vote (pid, uid);
ALTER TABLE mybb_reputation ADD UNIQUE KEY uniq_rep  (adduid, uid, pid);
ALTER TABLE mybb_users      ADD UNIQUE KEY uniq_email (email);
```
and for the login throttle, increment-then-check with an atomic conditional update
(`UPDATE users SET loginattempts = loginattempts+1 WHERE uid=…` *before* the gate,
matching the ACP), or `UPDATE … WHERE loginattempts < :max`. Principle: enforce
"once/limit" invariants in the database, not in a read-then-write gap.

## References

- CWE-367 (TOCTOU Race Condition); OWASP WSTG-BUSL-05; PortSwigger "Race
  conditions" (limit-overrun / single-packet techniques).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Fetched GHSA-6pm8-c5c6-r45p — ACP lockout bypass caused by email-vs-username lookup; not a concurrency issue
2. Fetched github.com/mybb/mybb/security/advisories pages 1-7 — no race-condition / TOCTOU advisory; GHSA-23m9-w75q-ph4p is a poll SQL injection
3. Fetched mybb.com/versions/1.8.41/ — no race-condition fix among the 24 items
4. Fetched github.com/advisories mybb queries — nothing relevant

**Related but distinct public references** (same class or component, not this bug):
- GHSA-6pm8-c5c6-r45p — different login-throttle weakness (identifier resolution), not check-then-act ordering
- GHSA-23m9-w75q-ph4p — poll voting SQL injection (2021); different weakness in the same feature

**Reasoning:** No public reference describes non-atomic check-then-act flows in poll voting, login throttling, reputation or registration for MyBB. Caveats: the class is generic and often rated low, only the poll leg was proven dynamically, and vendors frequently decline race reports without a stronger impact.
