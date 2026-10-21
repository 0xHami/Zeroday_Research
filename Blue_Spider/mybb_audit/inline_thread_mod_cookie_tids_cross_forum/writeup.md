# VULN-003 — Cross-forum inline multi-thread moderation via a client-controlled cookie

| | |
|---|---|
| **Software** | MyBB |
| **Repository** | https://github.com/mybb/mybb |
| **Affected version** | 1.9.0-alpha.1 (`inc/src/Application.php:28`) |
| **Commit** | `f8bf4e840cd42f5d61bfb789eb3975674081d69e` (branch `dev-1.9`) |
| **Severity** | High — CVSS 3.1 **7.5** (`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L`) |
| **Status** | CONFIRMED (dynamic) |
| **Confidence** | 8/10 — forum-A-only mod closed **and** soft-deleted a thread in forum B |
| **Auth required** | Moderator of ≥1 forum (a "section moderator") |
| **Attacker gains** | Open/close/stick/approve/unapprove/restore/**soft-delete** any thread board-wide |

## Summary

The eight inline forum-mode multi-thread moderation handlers in `moderation.php`
take the list of thread IDs to act on from a client-controlled cookie
(`inlinemod_forum{fid}`) but check the moderator's permission only against the
`fid` in the URL. A moderator of one forum can therefore manipulate threads in
forums they do not moderate by putting those threads' IDs in the cookie — a
horizontal privilege escalation that defeats MyBB's per-forum moderator
segmentation. Proven: a moderator of forum A (only) both closed and soft-deleted a
thread in forum B.

## How it works (mechanism & code trace)

Representative handler, `multiclosethreads`:

```php
// targets/mybb/moderation.php:1902-1915 (forum-mode branch)
else {
    $threads = getids($fid, 'forum');                 // tids from the client cookie
    if(!is_moderator($fid, 'canopenclosethreads')) {  // permission checked ONLY for the URL fid
        error_no_permission();
    }
}
if(count($threads) < 1) { error(...); }
$moderation->close_threads($threads);                 // acts on the tids, no re-check
```

`getids()` reads the tids straight from the cookie and int-casts them, with **no**
check that each tid belongs to `$fid`:

```php
// targets/mybb/moderation.php:3477-3506
$cookie = "inlinemod_".$type.$id;            // e.g. inlinemod_forum2
$cookie_ids = explode("|", $mybb->cookies[$cookie]);
foreach($cookie_ids as $cookie_id) {
    if($cookie_id == 'ALL') { $newids += getallids($id, $type); }
    else                    { $newids[] = (int)$cookie_id; }   // arbitrary tid
}
```

The sinks in `inc/class_moderation.php` perform no authorization of their own —
`close_threads()` is simply `UPDATE threads SET closed=1 WHERE tid IN (…) AND
moved='0'`. So authorization is entirely the caller's responsibility, and the
caller checks the wrong object: `is_moderator($fid /* from URL */, …)` instead of
`is_moderator_by_tids($threads, …)`. The **search-mode** branch of the very same
handlers *does* use `is_moderator_by_tids()` (e.g. `moderation.php:1897`), and every
inline **post** handler uses `is_moderator_by_pids()` — only the inline forum-mode
thread branch omits the per-object check, confirming a regression.

**Dynamic confirmation.** With forum A (the attacker's) and a cloned forum B (which
they do not moderate), and a victim thread `tid` in B:

```
POST /moderation.php   Cookie: …; inlinemod_forum2=<tid in B>
Body: action=multiclosethreads&fid=2&inlinetype=forum&my_post_key=<attacker key>
  -> forum-B thread: closed 0 -> 1
Body: action=multisoftdeletethreads&fid=2&inlinetype=forum&my_post_key=<attacker key>
  -> forum-B thread: visible 1 -> -1  (soft-deleted)
```

`is_moderator(2, …)` passes (the attacker moderates forum 2); `getids(2,'forum')`
returns the forum-B tid unfiltered; the sink mutates it.

## Why it is a vulnerability (reasoning)

MyBB's moderator model segments authority per forum: a section moderator is trusted
only within the forums assigned to them. The invariant "a moderator may only act on
threads in forums they moderate" is broken because the permission decision reads one
input (URL `fid`) while the action reads another (cookie tids), with no linkage
between them. The attacker's effective capability — manipulate any thread on the
board — vastly exceeds the authority their single-forum moderatorship grants. It is
High rather than Critical only because the operations are moderation actions (close,
open, stick, approve, soft-delete) that a higher moderator can mostly reverse, and
there is no direct data exfiltration or code execution.

## Reproduction

From a clean lab (`http://localhost:25850`):

1. `./run.sh` clones forum 2 → forum B (fid 3), provisions a victim thread in B,
   and makes a Registered user a moderator of forum A (2) **only**
   (`$cache->update_moderators()` rebuilt).
2. As that forum-A moderator it POSTs `multiclosethreads` with `fid=2` and
   `Cookie: inlinemod_forum2=<tid in B>`; the forum-B thread's `closed` flips to 1.
3. It then POSTs `multisoftdeletethreads` the same way; the thread's `visible` flips
   to -1 (soft-deleted). See `response.txt`.

```bash
cd claude_audit/mybb/exploits/VULN-003 && ./run.sh   # ==> VULN-003: CONFIRMED
```

## Impact

A single-forum moderator can open/close/stick/unstick/approve/unapprove/restore and
**soft-delete** arbitrary threads anywhere on the board — content suppression,
publishing of moderation-queued content, and destructive soft-deletion — defeating
the per-forum segmentation of the moderator model (Integrity High; Availability
Low). `multiapprovethreads` can force-publish content another moderator deliberately
held in the queue, which combined with a queued **VULN-001** payload widens who sees
a stored XSS.

## Suggested fix

In each inline forum-mode branch, authorize per object exactly as the search branch
already does:

```php
$threads = getids($fid, 'forum');
if(!is_moderator_by_tids($threads, 'canopenclosethreads')) {
    error_no_permission();
}
```

Defence in depth: have `getids($fid,'forum')` return only tids actually in `$fid`
(`SELECT tid FROM threads WHERE tid IN (…) AND fid='$fid'`), and add
`is_moderator_by_tids` guards inside the `inc/class_moderation.php` sinks. Principle:
authorize against the objects you mutate.

## References

- MyBB 1.8.41 moderation-authorization advisories: GHSA-hmjm-jvm7-2598,
  GHSA-9c3r-g4fj-2gp4, GHSA-76vm-4fx4-jr56 (same class; 1.9 not listed).
- OWASP WSTG-ATHZ-04; OWASP Top 10 A01:2021 Broken Access Control (object-level
  authorization).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 40 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Fetched GHSA-76vm-4fx4-jr56 (delayed moderation, 1.8.41) — describes the same mechanism (cookie-sourced thread IDs via `getids()`, permission checked against the request forum) but only for the delayed-moderation handlers
2. Fetched the fix commit 86a6f54 — changes only the delayed-moderation view/cancel/execute paths; `getids()` and the inline `multi*threads` handlers are not modified
3. Fetched raw `moderation.php` at tag mybb_1841 — the forum-mode branches of `multiclosethreads`, `multiopenthreads`, `multistickthreads`, `multiapprovethreads`, `multisoftdeletethreads` still use `getids($fid,'forum')` + `is_moderator($fid, ...)`, and `getids()` does not verify forum membership; so the inline handlers remain unfixed in 1.8.41 as well
4. Fetched GHSA-hmjm-jvm7-2598, GHSA-9c3r-g4fj-2gp4 and advisory pages 1-7, plus mybb.com/versions/1.8.41/ — no advisory names the inline multi-thread handlers

**Related but distinct public references** (same class or component, not this bug):
- GHSA-76vm-4fx4-jr56 — identical root-cause pattern in the delayed-moderation handler of the same file; fix did not extend to the inline handlers
- GHSA-hmjm-jvm7-2598, GHSA-9c3r-g4fj-2gp4, GHSA-fwfx-94pg-6f96, GHSA-rxgj-m9jm-mxxw, GHSA-p768-x2c9-7j8r — other 1.8.41 moderation/thread authorization fixes in different handlers

**Reasoning:** The mechanism is publicly described for a sibling handler, but the eight inline forum-mode multi-thread handlers are not named in any advisory and were left untouched by the vendor fix, so this specific instance appears undisclosed and is still present in 1.8.41 and 1.9. Confidence is reduced because the reporter of the 1.8.41 wave may already hold this sibling privately and the vendor may treat it as a variant of the published advisory.
