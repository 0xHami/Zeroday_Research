# CHAIN-004: a delegated help-desk role removes the workspace's administrators, then breaks what only they could repair

| Field | Value |
|-------|-------|
| **Chain** | CHAIN-004 |
| **Severity** | High |
| **Status** | CONFIRMED |
| **Validated at** | 2026-11-24 |
| **Software** | Rocket.Chat 9.1.0-develop (commit `9f3d6c8c48911e32ed6c2ce36befd431faa71190`) |
| **Pattern** | CH-PRIV (to administrative reach), ending in an unrepairable availability loss |

Rocket.Chat is built to let an administrator delegate user management without
giving away the workspace: a role is granted `assign-roles` and
`edit-other-user-info`, and `assign-admin-role` is deliberately withheld. The
promotion guard does hold. The removal side does not, and that asymmetry runs the
wrong way: the delegate cannot appoint an administrator, but it can remove every
one of them, and then do damage that only an administrator could undo.

## The chain

1. **[VULN-020](../../exploits/VULN-020-role_membership_authorization_oracle/writeup.md)**
   finds the targets. `roles.addUserToRole` answers `error-user-already-in-role`
   before it reaches the permission check, so each (account, `admin`) pair is a
   yes/no question answerable by any caller. The run swept 21 accounts and
   produced an administrator list identical to the administrator's own
   `roles.getUsersInRole` view, from a caller with no permission to read roles at
   all (`access-permissions` belongs to `admin`).
2. **[VULN-069](../../exploits/VULN-069-last_admin_removal/writeup.md)**
   removes them. `users.update` accepts a `roles` array that omits `admin` with
   only `assign-roles` plus `edit-other-user-info`, with no `assign-admin-role`
   check and no last-administrator guard. The run demoted the workspace's **own**
   administrator account (HTTP 200); that account's still-valid session was then
   refused on a protected setting, read and write (HTTP 403). The route built for
   this, `roles.removeUserFromRole`, refuses the same caller with HTTP 403, and
   `users.update` adding `admin` is refused with "Assigning admin is not
   allowed", so the change is one-way: not even the attacker can put it back.
3. **[VULN-057](../../exploits/VULN-057-settings_write_via_telemetry/writeup.md)**
   does the damage. With no administrator left, the same account raised
   `Accounts_Password_Policy_MinLength` from 14 to 414 through
   `statistics.telemetry`. Registration with a strong password and every password
   change were then refused workspace-wide, and the demoted administrator trying
   to put the setting back was answered HTTP 403.

## Combined impact

**Before:** an account holding a role an administrator delegated user management
to. It can rename users and assign ordinary roles. It cannot read the role map,
cannot grant `admin`, and cannot change a setting through the settings API.

**After, proven by the run:**

- the workspace's own administrator account is an ordinary user, and its live
  session is refused everywhere administration happens;
- no administrator remains except one the run created as its own safety net, and
  which the identical call removes (the run did not execute that, deliberately,
  because it would have left this lab with no administrator);
- there is no route back through the product: the promotion guard that the
  attacker could not pass also stops the attacker from appointing a replacement,
  and the demoted administrator cannot restore itself;
- the workspace refuses every registration, password change and password reset,
  and the only people who could change that setting back no longer exist.

This is seizure rather than takeover: the attacker does not become an
administrator, it removes the role from everyone and then makes the damage
unrepairable without direct database surgery. The blast radius is the whole
workspace.

Neither finding reaches this alone. The oracle is a disclosure. The demotion, as
a single finding, reads as "a delegate can demote one administrator", which an
operator would undo in a minute with another administrator's account. It is the
third step that turns the removal into a trap, and the removal that makes the
third step permanent.

## Reproduction

**Preconditions.** A role an administrator delegated user management to:
`assign-roles`, `edit-other-user-info` and `view-full-other-user-info`, with
`assign-admin-role` withheld. This is exactly what the admin Permissions screen
is for; because creating a custom role is a premium feature this Community
workspace refuses, the run grants those three permissions to the built-in
`moderator` role instead and records and restores the previous role lists
byte for byte. No other non-default setting is involved.

**Lab safety, which a reproducer should keep.** The run creates a spare
administrator **first** and never demotes it, so the workspace is not left
ownerless; at the end that spare restores the real administrator's role, puts the
policy value back and deletes itself. The script verifies the restore and says
loudly, with the spare's credentials, if it ever fails.

**From a clean state:**

1. Bring the workspace up (lab: `BLUESPIDER_PORT_BASE=39649 audit/rocket.chat/setup/rebuild.sh`,
   serving `http://127.0.0.1:39649`).
2. From the attacker container, with `BASE_URL`, `ADMIN_USER` and `ADMIN_PASS`
   set (the administrator is used to set up the delegation and as the demoted
   victim):

   ```
   docker exec -w /chains/CHAIN-004-delegated_role_strips_all_administrators \
     -e BASE_URL -e ADMIN_USER -e ADMIN_PASS "$BLUESPIDER_ATTACKER" python3 automation.py
   ```

   Without an attacker container, run `python3 automation.py` from this folder
   with `requests` available.

**Observed combined result** (full transcript in `run.log`):

```
[PROOF]     the oracle answered for 21 accounts and named the administrators ['admin', 'spare_08a9b1e2'];
            the administrator's own view of the admin role is ['admin', 'spare_08a9b1e2'] (identical=True)
[PROOF]     demoted [('admin', 200)]: the workspace's own admin account now holds ['user']
[PROOF]     with its own, still-valid session the demoted administrator reads a protected setting ->
            HTTP 403 and writes one -> HTTP 403: it is an ordinary user now
[PROOF]     administrators remaining in the workspace: ['spare_08a9b1e2']
[PROOF]     400 increments (last HTTP 200): Accounts_Password_Policy_MinLength went from 14 to 414;
            a new user's registration with a strong password -> HTTP 400 ..., and a password change -> HTTP 400 ...
[PROOF]     the workspace's own administrator trying to put Accounts_Password_Policy_MinLength back ->
            HTTP 403 ...; the setting is still 414
[INFO]      admin roles restored to ['admin']; its own session reads a protected setting again -> HTTP 200
[INFO]      delegated permissions put back: {"assign-roles": ["admin"], ...}
```

## Fix order

**The single highest-leverage fix is on step 2: require `assign-admin-role` to
remove the admin role as well as to grant it, and add the last-administrator
guard**, in `users.update` and `validateUserData`. The sibling route
`roles.removeUserFromRole` already enforces it; this is the same rule applied to
the route that writes the role list wholesale.

That one change breaks the chain. The oracle goes back to being a disclosure, and
the telemetry settings write stays repairable, because the administrators who can
repair it still exist.

**Side effects of that fix.** It keeps the feature and removes only the weakness:
a delegated role keeps managing ordinary roles and user profiles, and loses the
ability to remove `admin`, which it was never meant to have. A deployment that
genuinely wants a non-administrative role to be able to demote administrators
(nothing shipped does) would have to grant it `assign-admin-role`, which is the
honest way to express that intent. The last-administrator guard additionally
refuses the removal that would leave zero administrators, which an operator
deliberately decommissioning a workspace would have to work around by creating a
replacement first.

**Next in order of leverage, and still worth doing:**

- Close the set of settings ids `updateCounter` will touch (VULN-057), so the
  availability half of this chain, and CHAIN-002 entirely, go away. Side effect:
  the first-party counters keep working and other ids are refused.
- Move the `error-user-already-in-role` answer behind the permission check in
  `roles.addUserToRole` (VULN-020). Side effect: a client that distinguished
  "already in role" from "not allowed" sees one answer where it saw two.

## Files

- `automation.py` - the whole chain, end to end, from a clean state, including
  the safety net and the verified restore; writes `run.log`.
- `run.log` - the transcript of the confirming run.
- `request.http`, `response.txt` - the decisive request and response: the
  `users.update` call that demoted the workspace's own administrator.
- `evidence/step1-role-oracle.json` - the oracle's answer for every account.
- `evidence/chain-004.json` - the delegation, the demotions, the policy write,
  the demoted administrator's refused repair attempt and the restore, as data.
- `chain.json` - this chain, machine-readable.

---

Blue Spider, a product of Kohi Research Corporation (kohirc.com). Copyright 2026 Kohi Research Corporation. All rights reserved. Blue Spider (TM) is a trademark of Kohi Research Corporation. Generated by Blue Spider; do not use or redistribute without attribution to Kohi Research Corporation.
