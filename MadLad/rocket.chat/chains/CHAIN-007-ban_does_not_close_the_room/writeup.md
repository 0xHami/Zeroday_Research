# CHAIN-007: a room ban removes nobody

| Field | Value |
|-------|-------|
| **Chain** | CHAIN-007 |
| **Severity** | Medium |
| **Status** | CONFIRMED |
| **Validated at** | 2026-11-24 |
| **Software** | Rocket.Chat 9.1.0-develop (commit `9f3d6c8c48911e32ed6c2ce36befd431faa71190`) |
| **Pattern** | CH-FEATURE (findings composed with two intended features) |

Rocket.Chat's own documentation describes the ban as the moderator's tool for
shutting one person out of a room: a banned user "cannot re-enter the room
through any path" (`docs/features/ban-user.md`). The front door does close, and
the product gets several of the side doors right. The ones it misses compose into
the ban achieving nothing: the person keeps reading the room in real time, keeps
pulling its files, can turn the notifications up so nothing is missed, and
returns as a new account through an invite the room's owners cannot revoke.

## The chain

1. **[VULN-035](../../exploits/VULN-035-invite_links_unrevocable/writeup.md)**
   leaves the door open. While still a moderator, the attacker minted an invite
   with `days: 0` and `maxUses: 0`, which never expires and has no use limit.
   `listInvites` and `removeInvite` check `create-invite-links` with no room
   scope, which only global roles satisfy, so the room's **own owner** is refused
   on both (HTTP 403): it can neither see the invite nor revoke it.
2. **[VULN-009](../../exploits/VULN-009-ban_bypass_notifications_and_files/writeup.md)**
   keeps the reading going. After the ban, `groups.history` correctly answers
   HTTP 400 and the room's message stream correctly answers `nosub`, but the
   notification recipient query and the file-download check resolve the account
   with a subscription lookup that does not filter banned subscriptions. The
   banned account received the message posted after its ban, and downloaded the
   room's confidential file (HTTP 200, the file's contents).
3. **Per-room notification preferences**, working as designed, turn the leak up.
   `rooms.saveNotification` reaches the same status-blind subscription lookup, so
   the banned account set the room's desktop, email and mobile notification level
   to `all` (HTTP 200): mentions only would have been a trickle, every message is
   the whole room.
4. **Public self-registration**, the shipped default, closes the loop. The banned
   account's own invite redemption is correctly refused ("User is banned from this
   room"), so the attacker registered a new account through the public form and
   redeemed the same invite: HTTP 200, and the private group's history read back
   in full, including the message posted after the ban.

## Combined impact

**Before the ban:** a moderator of the private room, with everything that
implies.

**After the ban, which is supposed to remove them entirely:**

- they still receive every message posted in the room, in real time, through
  their own notification stream, at the notification level they chose after being
  banned;
- they still download the room's files by id;
- they are a full member again, under a new identity, through a link nobody in
  the room can take away: the run's member list ended as
  `['chair_7c13c9c0', 'consultant_7c13c9c0']`, the owner and the attacker's new
  account.

The blast radius is every private room whose moderation relies on the ban, and
the people in it who believe the room was closed to that person and keep talking
accordingly. The run's room held a file called "severance terms" and a message
about an acquisition price, which is the shape of conversation a ban is used to
protect.

Alone, VULN-035 is an invite hygiene problem, VULN-009 is a notification leak, and
neither reads as "the ban does not work". Composed with two features that behave
exactly as documented, they contradict the product's own documented guarantee.

## Reproduction

**Preconditions.** The attacker was a member of the room with the ability to
create an invite (a moderator, which any user becomes in a room they create), and
public self-registration is on, which is the shipped default. No setting is
changed.

**From a clean state:**

1. Bring the workspace up (lab: `BLUESPIDER_PORT_BASE=39649 audit/rocket.chat/setup/rebuild.sh`,
   serving `http://127.0.0.1:39649`).
2. From the attacker container, with `BASE_URL`, `ADMIN_USER` and `ADMIN_PASS`
   set (the administrator is used only to create the accounts and clean up):

   ```
   docker exec -w /chains/CHAIN-007-ban_does_not_close_the_room \
     -e BASE_URL -e ADMIN_USER -e ADMIN_PASS "$BLUESPIDER_ATTACKER" python3 automation.py
   ```

   Without an attacker container, run `python3 automation.py` from this folder
   with `requests` and `websocket-client` available.
3. The script creates the room's owner, the insider who will be banned and the
   room itself, uploads a confidential file, mints the invite, performs the ban
   through the product's own `rooms.banUser`, and then runs the four steps.

**Observed combined result** (full transcript in `run.log`):

```
[PROOF]     invite 5mbWkL created (HTTP 200); the room's own owner: listInvites -> HTTP 403 ...,
            removeInvite -> HTTP 403 ...
[STEP]      chair_7c13c9c0 banned insider_7c13c9c0 (HTTP 200); the front doors do close:
            groups.history -> HTTP 400, the room's message stream -> nosub
[STEP]      3/4 feature: the banned account sets this room to notify it of every message:
            rooms.saveNotification -> HTTP 200 {"success":true}
[PROOF]     the banned account received the message posted after its ban (yes) and downloaded the
            confidential file (HTTP 200, body=b'severance-terms-7c13c9c0\n')
[PROOF]     the banned account's own redemption is refused (HTTP 400 User is banned from this room ...),
            while the fresh account's succeeds (HTTP 200) and reads the private history including the
            post-ban message=True
[PROOF]     the private room's member list is now ['chair_7c13c9c0', 'consultant_7c13c9c0']
```

The script removes the invite, the group and all three accounts it created.

## Fix order

**The single highest-leverage fix is on step 1 and step 4, which are one place:
re-validate the invite at redemption time** in
`apps/meteor/server/lib/rooms/invites/useInviteToken.ts`, so an invite minted by
someone who has since been removed, demoted or banned stops admitting anybody,
and **scope the `create-invite-links` check in `listInvites` and `removeInvite`
to the room** so a room's owners can see and revoke the invites into their own
room.

That one change closes re-entry, which is the part of the chain that restores
full membership and makes the ban meaningless rather than merely leaky.

**Side effects of that fix.** It keeps the feature and removes only the weakness:
invites created by current members keep working exactly as they do now, while
invites whose creator has lost their standing in the room stop working, which
will surprise a room that has been relying on an old link in a wiki page; the
remedy is for a current member to mint a new one. Scoping the list and revoke
checks gives room owners a capability they do not have today, which is the
documented intent of a room-scoped permission.

**Next in order of leverage, and still worth doing:**

- Filter banned subscriptions in the notification recipient query and in
  `FileUpload.requestCanAccessFiles` (VULN-009). These continue regardless of the
  invite, so without this fix a banned member still reads the room; it is the
  other half of making a ban mean what it says. Side effect: a banned member
  stops receiving notifications for the room, which is the intent, and the file
  route starts refusing requests it used to serve, so a client that cached an
  upload id for an unrelated purpose sees a 403.
- Re-check the ban in `rooms.saveNotification` (the same status-blind lookup), so
  a banned member cannot change preferences for a room they are excluded from.

## Files

- `automation.py` - the whole chain, end to end, from a clean state; writes `run.log`.
- `run.log` - the transcript of the confirming run.
- `request.http`, `response.txt` - the decisive request and response: the fresh
  account redeeming the unrevocable invite, and the notification frame and file
  download that reached the banned account.
- `evidence/chain-007.json` - the invite, the ban, both leaks, the notification
  preference write and the re-entry as data.
- `chain.json` - this chain, machine-readable.

---

Blue Spider, a product of Kohi Research Corporation (kohirc.com). Copyright 2026 Kohi Research Corporation. All rights reserved. Blue Spider (TM) is a trademark of Kohi Research Corporation. Generated by Blue Spider; do not use or redistribute without attribution to Kohi Research Corporation.
