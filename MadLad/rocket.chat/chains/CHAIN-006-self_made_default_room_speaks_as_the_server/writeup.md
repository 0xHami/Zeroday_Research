# CHAIN-006: an ordinary account builds a room every new employee joins, and speaks in it as the server

| Field | Value |
|-------|-------|
| **Chain** | CHAIN-006 |
| **Severity** | Medium |
| **Status** | CONFIRMED |
| **Validated at** | 2026-11-24 |
| **Software** | Rocket.Chat 9.1.0-develop (commit `9f3d6c8c48911e32ed6c2ce36befd431faa71190`) |
| **Pattern** | CH-FEATURE (a finding composed with an intended feature) |

Two mass assignments and one feature working exactly as designed. The flags let
an ordinary account mark its own room as one of the workspace's own; the feature
then recruits the audience, adding every newly registered account to it; and the
message-type confusion lets the same account post lines that are stored, and
render, as the workspace's own system notices.

## The chain

1. **[VULN-058](../../exploits/VULN-058-team_room_mass_assignment/writeup.md)**
   supplies the flags. `teams.create` spreads the caller's `room.extraData` into
   the stored room document, so an account with the default `user` role created a
   room with `default: true` and `featured: true`. The administrator's own view
   of that room reports both. The control is in the product itself:
   `channels.create` refuses the identical `extraData` with "must NOT have
   additional properties".
2. **Default channels and the featured directory**, the intended feature,
   supplies the audience. Rocket.Chat adds every newly registered account to
   every room flagged `default`, and the directory promotes `featured` rooms. An
   account registered afterwards through the public form was joined to the
   attacker's room with no invitation and no action of its own, and the room
   appears in the directory's featured list.
3. **[VULN-012](../../exploits/VULN-012-forged_system_messages_via_mediaconfirm/writeup.md)**
   supplies the voice. `rooms.mediaConfirm` spreads the request body into the
   message document, so the caller chooses `t`, the field the client uses to
   decide that a line is the server talking. The run stored three messages with
   the system types `r`, `au` and `subscription-role-added` and attacker-chosen
   text; the auto-joined member read all three back as system notices, while
   `chat.sendMessage` refused the identical message with "Cannot send system
   messages using 'chat.sendMessage'".

## Combined impact

**Before:** an account from the public registration form. It can post ordinary,
clearly attributed messages in rooms it belongs to, and it can create rooms that
nobody joins.

**After, proven by the run:** the same account owns a channel that

- looks like the workspace's own (named for IT, described as official, promoted
  in the directory's featured list);
- is joined by every account created from then on, automatically, with no
  invitation for anyone to be suspicious of;
- carries messages that are stored as system notices rather than as user
  messages, with text of the attacker's choosing. The run planted
  "IT added everyone to this channel: confirm your account at
  https://sso-verify.example/..." as a type-`au` notice.

The blast radius is every account created after the room exists, which on a
growing workspace is every new joiner, at the moment they are least able to tell
a real announcement from a fake one. The natural use is credential phishing, and
the natural second use is instruction injection: a notice that claims a rename, a
role grant or a policy change the workspace never made.

Alone, VULN-058 is a room with two odd flags and VULN-012 is a lie told inside a
room the attacker had to populate by hand. The composition is what makes the
product build the audience and lend the authority.

## Reproduction

**Preconditions.** An account from the public registration form, which is the
shipped default; the default `user` role already holds `create-team` and upload
rights. No setting is changed and no administrator action is involved.

**From a clean state:**

1. Bring the workspace up (lab: `BLUESPIDER_PORT_BASE=39649 audit/rocket.chat/setup/rebuild.sh`,
   serving `http://127.0.0.1:39649`).
2. From the attacker container, with `BASE_URL`, `ADMIN_USER` and `ADMIN_PASS`
   set (the administrator is used only as a witness, to read the room document
   back, and to clean up):

   ```
   docker exec -w /chains/CHAIN-006-self_made_default_room_speaks_as_the_server \
     -e BASE_URL -e ADMIN_USER -e ADMIN_PASS "$BLUESPIDER_ATTACKER" python3 automation.py
   ```

   Without an attacker container, run `python3 automation.py` from this folder
   with `requests` available.

**Observed combined result** (full transcript in `run.log`):

```
[PROOF]     HTTP 200: the administrator's own view of the room reports {"name": "it-announcements-...",
            "default": true, "featured": true, "t": "c", "description": "Official IT announcements"}
[INFO]      the control, the ordinary channel route: channels.create with the same extraData -> HTTP 400
            must NOT have additional properties
[PROOF]     the new account was joined to [... 'it-announcements-d726d931', 'general'] without any
            invitation: the attacker's room is there=True; rooms the directory now features: [...]
[PROOF]     stored message types ['r', 'au', 'subscription-role-added'] with attacker text; the
            product's own send route refuses the identical message: chat.sendMessage -> HTTP 400
            Cannot send system messages using 'chat.sendMessage'
[PROOF]     the auto-joined member reads them back as system notices: [{"t": "subscription-role-added",
            "msg": "joiner_... was set as owner by IT ...", "u": "newstarter_..."}, ...]
```

The script deletes the team, its room, the control channel and both accounts it
created.

## Fix order

**The single highest-leverage fix is on step 1: allow-list the keys
`teams.create` accepts in `room.extraData`**, the way `channels.create` already
does, so `default`, `featured` and the other room-administration fields cannot be
set by the caller.

That one change breaks the chain. Without `default` the workspace stops
recruiting the audience, and without `featured` the directory stops promoting the
room, so a forged notice reaches only the members the attacker managed to invite
by hand, which is the ordinary social-engineering problem rather than a
product-assisted one.

**Side effects of that fix.** It keeps the feature and removes only the weakness:
callers keep creating teams with the fields the route documents, and unknown keys
are refused, which the first-party client never sends. A deployment that scripted
`teams.create` with administrative flags (`default`, `featured`, retention
fields) would have to set them afterwards through the room-administration API
with the permission that route requires, which is the honest way to express it.

**Next in order of leverage, and still worth doing:**

- Stop the caller choosing `t` on the upload-confirm path (VULN-012), in
  `sendFileMessage`, so a message type is server-decided on every route as it
  already is in `chat.sendMessage`. On its own this leaves the attacker a room
  the workspace fills for them, but takes away the server's voice. Side effect:
  none for the shipped clients, which never send `t` to that route.

## Files

- `automation.py` - the whole chain, end to end, from a clean state; writes `run.log`.
- `run.log` - the transcript of the confirming run.
- `request.http`, `response.txt` - the decisive request and response: the
  `teams.create` call carrying the administrative flags.
- `evidence/forged-system-notices.json` - the stored room flags, where the new
  account was joined, the three forged notices and how the auto-joined member
  read them back.
- `chain.json` - this chain, machine-readable.

---

Blue Spider, a product of Kohi Research Corporation (kohirc.com). Copyright 2026 Kohi Research Corporation. All rights reserved. Blue Spider (TM) is a trademark of Kohi Research Corporation. Generated by Blue Spider; do not use or redistribute without attribution to Kohi Research Corporation.
