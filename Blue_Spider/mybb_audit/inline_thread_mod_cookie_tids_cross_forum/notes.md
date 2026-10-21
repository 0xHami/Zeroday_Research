# VULN-003 — Cross-forum inline multi-thread moderation via client-controlled cookie

**Software**: MyBB
**Repository**: https://github.com/mybb/mybb
**Affected version**: 1.9.0-alpha.1 (`inc/src/Application.php:28`; branch `dev-1.9`, commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: High
**Confidence**: 8/10
**Confidence reasoning**: Proven end-to-end with a 2-forum lab — a forum-A-only moderator both closed and soft-deleted a thread in forum B. Clear horizontal-authorization break; bounded to moderation ops (mostly reversible), hence High not Critical.
**Target commit**: f8bf4e840cd42f5d61bfb789eb3975674081d69e
**Validated at**: 2026-10-02T01:48Z

## Preconditions
- A moderator of ≥1 forum (A) holding the relevant per-forum flag (`canopenclosethreads`, `cansoftdeletethreads`, …). CSRF is enforced — the attacker uses their own valid `my_post_key`.
- A target thread in a forum (B) the attacker does not moderate. Setup clones forum 2 → forum B and provisions the thread + makes the attacker a moderator of forum A only.

## Request
See `request.http`:
```
POST /moderation.php
Cookie: mybbuser=<A-mod uid_loginkey>; inlinemod_forum2=<TID_in_B>
Body:   action=multiclosethreads&fid=2&inlinetype=forum&my_post_key=<key>
```

## Response
See `response.txt` — the forum-B thread: `closed 0 → 1` (multiclosethreads) and `visible 1 → -1` (multisoftdeletethreads), performed by the forum-A-only moderator.

## Observation
Exactly as predicted. `moderation.php:1904` `getids($fid,'forum')` reads the client cookie `inlinemod_forum2` and int-casts the tids with no forum filter; the permission check `is_moderator($fid='2', 'canopenclosethreads')` validates only the URL `fid`; `close_threads()` / `soft_delete_threads()` in `inc/class_moderation.php` perform no authorization. So a moderator of forum A closed (then soft-deleted) a thread living in forum B. The search-mode branch of the same handlers uses `is_moderator_by_tids()`, proving the forum-mode branch's omission is a regression.

## Side effects
Created forum B (fid 3, name "Forum B (cvh)"), a victim thread in it (now closed + soft-deleted), one forum-B-owner user, and the attacker moderator. These are lab artifacts; forum B and its thread can be deleted by an admin. Re-runs create fresh forum B rows (fid increments).

## Research & references
- OWASP WSTG-ATHZ-04 / A01 Broken Access Control — object-level authorization must be evaluated against the objects actually mutated, not a sibling request parameter.
- MyBB 1.8.41 moderation-authz advisory wave (GHSA-hmjm-jvm7-2598, GHSA-9c3r-g4fj-2gp4, GHSA-76vm-4fx4-jr56) — same class; this exact inline cookie-tid sink is not individually named and 1.9 is not listed.

## If FAILED
n/a — confirmed (both close and soft-delete).

## If NEEDS_MANUAL
n/a. The other six sibling handlers (multiopen/multiapprove/multiunapprove/multirestore/multistick/multiunstick) share the identical pattern (`getids($fid,'forum')` + `is_moderator($fid,…)`); `multiapprovethreads` additionally publishes queued content (a delivery amplifier for VULN-001). Not separately fired here — same root cause.

## If INTENDED
No — the search-mode branch and every inline *post* handler use per-object `is_moderator_by_*()`; the forum-mode thread branch omitting it is an inconsistency, not documented behaviour.
