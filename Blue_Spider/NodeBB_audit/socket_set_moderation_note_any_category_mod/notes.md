# VULN-014 — Socket user.setModerationNote broken access control

**Software**: NodeBB
**Repository**: https://github.com/NodeBB/NodeBB
**Affected version**: 4.16.0 (install/package.json:5; commit-pinned, untagged master)
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 20623201cbf2cc8a37612726cdf10ee82083c9c3
**Validated at**: 2026-09-28

## Preconditions
- A user who moderates at least one category (not global-mod, not admin). The exploit creates a fresh
  user and grants them `moderate` on cid 2 only, via `PUT /api/v3/categories/2/privileges/moderate`.

## Request / Response
See `request.http` / `response.txt` / `run.log`. Key:
```
moderator session: uid=3 isAdmin=False isGlobalModerator=False
emit user.setModerationNote {uid:1, note:"PLANTED_BY_catmod_<rand>"}
ack = [null, [ { rawNote:"PLANTED_BY_catmod_<rand>", uid:3, ... } ]]   (uid 1 = admin)
```

## Observation
Confirmed exactly. A moderator of a single ordinary category (uid 3, not admin/global-mod) called
`user.setModerationNote` with `uid:1` (the admin). The call succeeded (`err===null`), the note was
appended to the ADMIN's profile, and the handler returned the ADMIN's full moderation-note history to
the caller. `privileges.users.canEdit(3, 1, false)` returns false (target is admin → `!isTargetAdmin`
blocks it), so it is solely the fallback `user.isModeratorOfAnyCategory(3)` at `src/socket.io/user.js:147`
— which ignores `data.uid` — that lets it through. Both the write-to-admin and the read of the admin's
note history are things the intended gate forbids.

## Side effects
Creates one moderator user (`catmod_<rand>`) and appends one moderation note to the admin's profile.
Low-risk; the note is clearly marked. Removable via ACP (user management → moderation notes) if
desired. Random suffixes avoid collisions on re-run.

## Research & references
- OWASP WSTG-ATHZ-02/04 (Bypassing Authorization Schema / IDOR) — the fallback broadens a per-target
  decision into a global one.
- CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-284 (Improper Access Control).

## If FAILED
n/a — CONFIRMED.
