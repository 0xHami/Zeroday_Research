# CHAIN-008: deleting a message deletes nothing

| Field | Value |
|-------|-------|
| **Chain** | CHAIN-008 |
| **Severity** | Medium |
| **Status** | CONFIRMED |
| **Validated at** | 2026-11-24 |
| **Software** | Rocket.Chat 9.1.0-develop (commit `9f3d6c8c48911e32ed6c2ce36befd431faa71190`) |
| **Pattern** | CH-DATA (to cross-boundary data exposure) |

When a message is deleted, Rocket.Chat shows a "message removed" stub and the
room's history, search and thread list all stop returning it. This chain shows
the deletion holding at three different distances from the room and failing at
each one: an account with no relationship to the room learns what was deleted and
when, a member reads the text back, and, where anonymous read is on, so does a
caller with no account at all.

## The chain

1. **[VULN-010](../../exploits/VULN-010-deleted_message_metadata_disclosure/writeup.md)**
   gives the timeline. `chat.getDeletedMessages` has no room access check, so an
   account that cannot even open a private group (its `groups.history` answers
   HTTP 400) was answered HTTP 200 with the ids and timestamps of that room's
   deletions, including the one made seconds earlier.
2. **[VULN-059](../../exploits/VULN-059-deleted_thread_root_disclosure/writeup.md)**
   gives the content on the configuration Rocket.Chat ships. Deleting a message
   that started a thread always keeps a hidden full copy, whatever the history
   setting says, and `chat.syncThreadsList` returns it. Another member of the room
   read the deleted root's text back in full, with `Message_KeepHistory` still at
   its shipped `false`, while the room's own history withheld it.
3. **[VULN-049](../../exploits/VULN-049-deleted_content_via_edit_history/writeup.md)**
   widens that from thread roots to everything. With `Message_KeepHistory` on, a
   delete marks the message `_hidden` instead of removing it, and
   `chat.getMessage` returns it by id with no hidden filter: a member recovered the
   text of an ordinary deleted message (the run planted a pasted production
   password in it) while the room's history did not show it.
4. **[VULN-047](../../exploits/VULN-047-anonymous_read_omnichannel_rooms/writeup.md)**
   drops the last requirement. With `Accounts_AllowAnonymousRead` on,
   `channels.anonymousread` returns a channel's messages with no hidden-message
   filter, so an unauthenticated request returned both the deleted message and the
   deleted thread root.

The run also recorded the interaction that bounds this, because it matters to a
maintainer: with history keeping **on**, nothing is moved to the trash
collection, so step 1's timeline for that room is empty; with it **off**, the
timeline is complete but only thread roots keep their text. The two legs widen
the same hole from opposite ends, and neither step needs the other to work.

## Combined impact

**Before:** the attacker sees what everybody sees, a "message removed" stub.

**After, proven by the run:**

- from an ordinary account with no access to the room: the ids and times of every
  deletion in it, which is a retraction log of rooms the caller cannot read (it
  tells you that the legal team deleted something at 14:03, and gives you the id
  to ask about);
- from a member, on the shipped configuration: the full text of deleted thread
  roots;
- from a member, with history keeping on: the text of any deleted or
  edited-away message in the rooms it can read;
- from nobody at all, with anonymous read on: the same deleted text over an
  unauthenticated request.

The boundary the chain crosses is the one that matters: deleted content moves
from "the room's members, who saw it anyway" to "anybody who can reach the
workspace". The blast radius is everything anyone deleted because it should not
have been said: a pasted credential (the run planted one), a customer's details,
a sentence about a colleague, anything a compliance process assumes is gone.

## Reproduction

**Preconditions.** Any authenticated account for step 1, which needs only the
room id (ids travel in permalinks, invites and several API responses). Membership
of the room for steps 2 and 3. Nothing at all for step 4. Steps 3 and 4 need the
business features `Message_KeepHistory` (keep per-message editing history) and
`Accounts_AllowAnonymousRead` (let people read channels without an account), both
off by default; the run turns each on through the workspace's own settings API
and restores both before it exits. Step 2 needs neither.

**From a clean state:**

1. Bring the workspace up (lab: `BLUESPIDER_PORT_BASE=39649 audit/rocket.chat/setup/rebuild.sh`,
   serving `http://127.0.0.1:39649`).
2. From the attacker container, with `BASE_URL`, `ADMIN_USER` and `ADMIN_PASS`
   set (the administrator is used for the two settings and for cleanup):

   ```
   docker exec -w /chains/CHAIN-008-deleted_content_recovered_by_anyone \
     -e BASE_URL -e ADMIN_USER -e ADMIN_PASS "$BLUESPIDER_ATTACKER" python3 automation.py
   ```

   Without an attacker container, run `python3 automation.py` from this folder
   with `requests` available.
3. The script creates an author, a member and an outsider, a private group and a
   public channel, and posts and deletes the content each step needs.

**Observed combined result** (full transcript in `run.log`):

```
[PROOF]     the outsider cannot open the room at all (groups.history -> HTTP 400) yet
            chat.getDeletedMessages answers HTTP 200 with 1 deletion(s), including the id just deleted (True)
[PROOF]     the sync route returns the deleted root's text (True) while the room's own history
            withholds it (False), with Message_KeepHistory still at its shipped False
[PROOF]     chat.getMessage on the deleted id returns its text to a member (HTTP 200, text present=True)
            while the room's own history does not (False)
[INFO]      ... with history keeping on nothing is moved to the trash collection, so the step-1
            timeline for this channel is [] ...
[PROOF]     unauthenticated channels.anonymousread -> HTTP 200; it contains the deleted message (True)
            and the deleted thread root (True)
```

The script restores both settings and deletes the two rooms and three accounts it
created.

## Fix order

**The single highest-leverage fix is the one shared defect behind steps 2, 3 and
4: filter hidden documents in the readers that do not.** The list, search and
history routes already apply that filter; `chat.getMessage`
(`getSingleMessage.ts:7-19`), `chat.syncThreadsList` (`chat.ts:1212`),
`channels.anonymousread` (`channels.ts:2116-2122`) and the personal-data export
(`exportRoomMessagesToFile.ts:217-218`) do not. One change, applied to four
callers of the same pattern, removes the content disclosure at every distance and
leaves only the deletion metadata.

**Side effects of that fix.** It keeps the feature and removes only the weakness:
moderators keep reading message history through the feature built for it, and
clients catching up through the sync route stop receiving deleted documents. A
client that relied on the sync route to learn that a message had gone must read
the deletion list instead, which is what that route is for; this is a visible
change for any third-party client written against the current behaviour.

**Next in order of leverage, and still worth doing:**

- Add the room access check to `chat.getDeletedMessages` (VULN-010), so the
  retraction log of a room is visible only to people who can read the room. On
  its own this closes step 1, which is the only step that works with no
  relationship to the room at all. Side effect: a client reconciling its cache
  for a room the user has left gets an error where it used to get a list.
- Restrict `channels.anonymousread` to public channels and apply the hidden
  filter there (VULN-047), which also closes that route's unrelated Omnichannel
  leg. Side effect: an anonymous reader sees public channels only, which is what
  the setting's description promises.

## Files

- `automation.py` - the whole chain, end to end, from a clean state; writes `run.log`.
- `run.log` - the transcript of the confirming run.
- `request.http`, `response.txt` - the decisive request and response of step 1
  (the outsider's deletion listing for a private group it cannot open).
- `evidence/anonymous-read-of-deleted.json` - the unauthenticated response that
  carried both deleted texts, with an excerpt.
- `evidence/chain-008.json` - every step's inputs and observations as data,
  including the trash-collection interaction between the two configurations.
- `chain.json` - this chain, machine-readable.

---

Blue Spider, a product of Kohi Research Corporation (kohirc.com). Copyright 2026 Kohi Research Corporation. All rights reserved. Blue Spider (TM) is a trademark of Kohi Research Corporation. Generated by Blue Spider; do not use or redistribute without attribution to Kohi Research Corporation.
