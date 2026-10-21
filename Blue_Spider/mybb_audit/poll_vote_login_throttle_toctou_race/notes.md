# VULN-005 — TOCTOU race-condition family (login throttle / poll / reputation / email)

**Software**: MyBB
**Repository**: https://github.com/mybb/mybb
**Affected version**: 1.9.0-alpha.1 (`inc/src/Application.php:28`; branch `dev-1.9`, commit-pinned — no tagged release)
**Status**: CONFIRMED (poll-vote TOCTOU dynamically won — ballot stuffing); the login-throttle/reputation/email legs share the identical check-then-act-without-atomicity root cause (static)
**Severity (static)**: Medium
**Confidence**: 6/10
**Confidence reasoning**: One leg (poll voting) dynamically proven (3 ballots from one user); the family is a real CWE-367 pattern, but exploitation requires winning a millisecond race (AC:H) and the per-leg impact is integrity/policy, not RCE.
**Target commit**: f8bf4e840cd42f5d61bfb789eb3975674081d69e
**Validated at**: 2026-10-02T01:54Z

## Preconditions
- A voting-eligible user and an open poll (provisioned: a thread + an open poll). No prior vote by the user. (Leg A needs only the guest login form; Legs C/D need a voting/registering user.)

## Request
See `request.http` — 30 of these fired concurrently as the SAME voter:
```
POST /polls.php?action=vote&pid=<pid>   action=vote&pid=<pid>&option=1&my_post_key=<key>
```

## Response
See `response.txt` — `pollvotes` rows for the single voter: before=0, after=**3** (poll.numvotes=1). Secure behaviour is exactly 1 ballot.

## Observation
Confirmed. `polls.php:999` does `SELECT * FROM pollvotes WHERE uid=… AND pid=…`; if a row exists it errors "already voted"; otherwise it `INSERT`s — with no transaction, row lock, or `UNIQUE(pid,uid)` key. Firing 30 concurrent votes, 3 of them read the empty pollvotes state before any INSERT committed, so all 3 passed the check and inserted → 3 ballots from one user. (The poll's own `numvotes` counter is itself updated non-atomically, landing at 1 — a second symptom of the same race, and why the displayed tally and the actual ballots disagree.)

The headline leg (login throttle, `member.php:1767-1769`) has the same shape plus an ordering bug: the front-end reads the throttle (`login_attempt_check`) *then* increments `loginattempts`, the inverse of the ACP order (`admin/index.php` increments before checking) — so N concurrent logins at the threshold are all evaluated. Legs C (reputation) and D (duplicate-email registration) are the same check-then-insert with no UNIQUE key.

## Side effects
A thread + open poll + 3 stray ballots + two throwaway users (author, voter). Benign lab data.

## Research & references
- OWASP WSTG-BUSL-05 (Test Number of Times a Function Can Be Used Limits) / race-condition testing — fire concurrent requests at a check-then-act flow and count the side effects.
- PortSwigger "Race conditions" (limit-overrun) — the barrier-synchronised concurrent-request technique used here.
- CWE-367 (TOCTOU). Fix pattern: atomic conditional writes + UNIQUE constraints.

## If FAILED
n/a — the race was won (3 > 1). On a slower run the race may not land; raise `CONCURRENCY` and retry (the exploit is safe to re-run with fresh random accounts).

## If NEEDS_MANUAL
The sibling legs were not separately raced here (the poll leg proves the class):
- **Leg A (login throttle, headline):** drive an account's `loginattempts` to `failedlogincount-1`, fire ~30 concurrent `do_login` with wrong passwords; all are evaluated (none lock out) — amplifies online guessing. (Note the default `failedcaptchalogincount=3` adds a CAPTCHA requirement mid-burst, which the race also skips.)
- **Leg C (reputation):** concurrent `reputation.php` POSTs → multiple rep rows for one (adduid,uid,pid).
- **Leg D (email):** concurrent registrations with the same email → duplicate-email accounts.

## If INTENDED
No — single-vote-per-user is the intended poll semantic (the "already voted" check exists); its non-atomicity is a defect, not design.
