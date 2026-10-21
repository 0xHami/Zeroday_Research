# VULN-014 — Socket `user.setModerationNote` broken access control

| | |
|---|---|
| **ID** | VULN-014 |
| **Software** | NodeBB |
| **Repository** | https://github.com/NodeBB/NodeBB |
| **Affected version** | 4.16.0 (`install/package.json:5`; commit-pinned, untagged `master`) |
| **Commit** | `20623201cbf2cc8a37612726cdf10ee82083c9c3` |
| **Severity** | Medium — **CVSS 3.1 5.4** `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | A category moderator (obtained here by an admin granting `moderate` on one category). |
| **Attacker gains** | Read any user's complete moderation-note history (staff-only free text) and write notes onto arbitrary profiles, **including administrators**. |

## Summary
The `user.setModerationNote` socket handler authorizes with `privileges.users.canEdit(caller, target)`, which correctly protects admin targets (`!isTargetAdmin`). But when `canEdit` is false it falls back to `user.isModeratorOfAnyCategory(socket.uid)` — a global "does this caller moderate *anything*" check that does not reference the target. So a moderator of any single category passes for any target, defeating the admin-target protection and exposing the target's entire moderation-note history. Confirmed: a moderator of one ordinary category (uid 3, not admin/global-mod) planted a note on the admin (uid 1) and read back the admin's note history.

## How it works (mechanism & code trace)

**Handler (`src/socket.io/user.js:145-154`):**
```js
let canEdit = await privileges.users.canEdit(socket.uid, data.uid, false);   // :145
if (!canEdit) {
    canEdit = await user.isModeratorOfAnyCategory(socket.uid);               // :147  broadening fallback — ignores data.uid
}
if (!canEdit) { throw new Error('[[error:no-privileges]]'); }
await user.appendModerationNote({ uid: data.uid, noteData });                // :152  write to arbitrary target
return await user.getModerationNotes(data.uid, 0, 0);                        // :153  return target's full history
```

**The intended gate.** `privileges.users.canEdit(caller, target, false)` (`src/privileges/users.js`) resolves to `isAdmin || ((isGlobalMod || admin:users) && !isTargetAdmin)` — importantly it returns *false* when the target is an admin (the `!isTargetAdmin` clause), and false for an ordinary category moderator.

**The fallback (`src/user/index.js:216-219`).** `user.isModeratorOfAnyCategory(uid)` → `getModeratedCids(uid).length > 0` — true if the caller moderates *any* category, with no reference to `data.uid`. Splicing this global test into a per-target decision broadens "may edit this target" into "moderates something", so it (a) overrides the `!isTargetAdmin` protection and (b) authorizes reading/writing notes for *every* user.

The dynamic run makes it concrete: `canEdit(3, 1, false)` is false (uid 1 is admin), yet the call succeeded because `isModeratorOfAnyCategory(3)` is true — and the ack returned the admin's note history with the attacker's note appended.

## Why it is a vulnerability (reasoning)
Moderation notes are staff-only free text about users; the intended model is that only someone authorized *over that specific user* (admin, or global-mod for non-admins) may read/write them, and admins are explicitly shielded. The fallback breaks the per-target invariant: a low-tier category moderator — a role a community routinely delegates — gains read/write over *all* users' notes, including admins'. The sibling handlers `editModerationNote`/`deleteModerationNote` (`user.js:157-197`) are stricter, which shows the loose check here is an oversight, not intent. It is horizontal privilege escalation (CWE-639) plus disclosure of staff data (CWE-284).

## Reproduction
1. As admin: create a user, then `PUT /api/v3/categories/<cid>/privileges/moderate` with `{"member": <uid>}` — the user now moderates that one category (not global-mod, not admin).
2. Log in as that user, open a Socket.IO connection (session cookie + `_csrf`).
3. Emit `user.setModerationNote` with `{"uid": 1, "note": "<marker>"}` (uid 1 = admin).
4. Observe the ack: `err === null` and the returned array is the admin's moderation-note history containing your note.
5. `./run.sh` performs the whole flow (fresh user + grant + socket call) and asserts the caller is unprivileged, the note was planted on the admin, and the history was returned. Prints `[OK] exploit confirmed`. Evidence in `response.txt`/`run.log`.

## Impact
Any single-category moderator can (a) read the complete moderation-note history of any user — staff-only free text that may contain PII, investigation details, or references to other users/tickets — and (b) tamper with notes on arbitrary profiles, including administrators (planting misleading notes on staff). Requires a moderator role, and the CIA impact is limited to notes, hence Medium. Compounds VULN-015 (public `mutedReason` leak) as a broader picture of moderation-data over-exposure.

## Suggested fix
Make the fallback per-target or drop it. Either require `privileges.users.canEdit` outright, or gate the fallback on moderation of a category relevant to the target and never let it override `!isTargetAdmin`:
```js
let canEdit = await privileges.users.canEdit(socket.uid, data.uid, false);
// remove the global isModeratorOfAnyCategory fallback, OR:
// canEdit ||= await user.isModeratorOfCategory(socket.uid, <cid the target participates in>) && !targetIsAdmin;
```
Model it on the stricter `editModerationNote`/`deleteModerationNote` handlers.

## References
- OWASP WSTG-ATHZ-02 (Bypassing Authorization Schema), WSTG-ATHZ-04 (IDOR).
- CWE-639 (Authorization Bypass Through User-Controlled Key); CWE-284 (Improper Access Control).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 55 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `NodeBB "setModerationNote" OR "moderation note" vulnerability moderator access control` — CVE-2024-57041 (moderator-view XSS in flags), GHSA-4qcv-qf38-5j3j, CVE-2020-15149, CVE-2022-46164; nothing on moderation-note authorization.
2. `NodeBB CVE moderator privilege escalation socket user admin notes isModeratorOfAnyCategory` — only CVE-2020-15149 / CVE-2022-46164 (socket.io account takeover); no match.
3. NodeBB GitHub security-advisories page + OpenCVE vendor listing (23 CVEs) — no moderation-note entry.
4. Upstream history of `src/socket.io/user.js` (master) — two relevant commits examined in full: `2d06a07` (v4.14.9, "fix: moderation note privileges") and `d92eb01` (v4.15.0, "restrict moderation note editing to admins and original authors"). Neither removes the `isModeratorOfAnyCategory` fallback from `setModerationNote`; no commit on the file after v4.16.0.

**Related but distinct public references** (same class or component, not this bug):
- NodeBB commit d92eb01 (v4.15.0) — removed the `isModeratorOfAnyCategory` fallback from `editModerationNote` only ("replaces a check that let any category moderator edit any note"); the identical fallback remains in `setModerationNote`, which also returns the target's full note history. Same file and same flawed check in a sibling handler; no advisory/CVE was issued.
- NodeBB commit 2d06a07 (v4.14.9) — passed `allowSelfEdit=false` to `canEdit` in `setModerationNote`/`editModerationNote` and added admin-only `deleteModerationNote`; left the fallback in place.
- CVE-2024-57041 — XSS reaching moderator views via `Flags.getTarget`; unrelated sink.

**Reasoning:** No public advisory, issue or fix describes the `setModerationNote` fallback that lets any single-category moderator write notes on, and read the full note history of, arbitrary users including administrators. However, upstream publicly fixed the identical fallback in the sibling `editModerationNote` handler in 4.15.0 with a commit message acknowledging the problem, so the maintainers are partly aware of the pattern and this is a near-miss; confidence is reduced accordingly. The `setModerationNote` path (admin targets + history read) remains unaddressed on master at the time of this check. Web-search quota was exhausted mid-triage; later checks were direct fetches of GitHub/OpenCVE pages.
