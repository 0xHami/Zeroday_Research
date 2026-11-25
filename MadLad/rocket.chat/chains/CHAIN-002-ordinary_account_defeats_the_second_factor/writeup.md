# CHAIN-002: an ordinary account turns the workspace's second factor off, then guesses into an administrator

| Field | Value |
|-------|-------|
| **Chain** | CHAIN-002 |
| **Severity** | High |
| **Status** | CONFIRMED |
| **Validated at** | 2026-11-24 |
| **Software** | Rocket.Chat 9.1.0-develop (commit `9f3d6c8c48911e32ed6c2ce36befd431faa71190`) |
| **Pattern** | CH-ATO (to account takeover), reached from CH-PRIV primitives |

Two-factor authentication is the control that is supposed to make a leaked
password survivable. On this build an account created through the public
registration form can widen the workspace's TOTP acceptance window and lift the
per-address failed-login ceiling, both without any permission, and then guess
six-digit codes against a named administrator until one is accepted, without ever
being locked out.

## The chain

1. **[VULN-007](../../exploits/VULN-007-workspace_pii_disclosure_to_any_user/writeup.md)**
   supplies the target. `users.listByStatus` returns every account's email
   address and role list to the lowest-privileged caller and takes a `roles`
   filter, so one request named the workspace's administrators and gave their
   addresses, which is also the login identifier step 3 needs.
2. **[VULN-057](../../exploits/VULN-057-settings_write_via_telemetry/writeup.md)**
   removes both brakes. `statistics.telemetry` dispatches an `updateCounter`
   event to the settings store for any authenticated caller, so the attacker
   raised `Accounts_TwoFactorAuthentication_MaxDelta` from 1 to 4001 (the window
   is handed straight to `speakeasy.totp.verifyDelta`, so a random six-digit code
   now verifies about once in 125) and
   `Block_Multiple_Failed_Logins_Attempts_Until_Block_By_Ip` from 50 to 1550.
3. **[VULN-032](../../exploits/VULN-032-lockout_bypass_by_email/writeup.md)**
   makes the guessing unlimited. The per-user failed-login block reads the
   username as the caller typed it, so an account named by its email address is
   never locked, however many attempts fail against it. The run sent 525 guesses,
   every one answered `totp-invalid` and none refused by a lockout, and then got a
   session.

## Combined impact

**Before:** an account created through the shipped public registration form,
holding the default `user` role, plus the victim's password, phished, reused or
breached. That is the exact situation TOTP is sold as surviving; the victim had
enrolled it and their password login correctly answered `totp-required`.

**After, proven by the run:** a session on the TOTP-protected administrator. The
guessed session read a private, administrator-only setting (HTTP 200) that the
attacker's own ordinary account is refused (HTTP 403), which is what makes it an
administrator session and not just a login.

The blast radius is wider than the one account. Both settings are workspace-wide,
so while the window stays raised the second factor is weakened for **every**
account, and the per-address ceiling that bounds password and code guessing is
gone for every attacker sharing that address. The run restored both values.

No step reaches this alone. VULN-007 is a directory disclosure. VULN-057 is a
settings write with no obvious victim, and its own validation showed only that a
stale code becomes acceptable, which needs a code to have been observed.
VULN-032 at the shipped window leaves a blind guess landing once in 333,000, and
the per-address block would have stopped the attempt at fifty. Composed, they
turn a known password into an administrator session in about three minutes.

## Reproduction

**Preconditions.** A workspace in its shipped configuration with public
self-registration (the default). A victim account with TOTP enrolled whose
password the attacker knows. Nothing else: the chain changes the two settings
itself and the run puts them back.

**From a clean state:**

1. Bring the workspace up (lab: `BLUESPIDER_PORT_BASE=39649 audit/rocket.chat/setup/rebuild.sh`,
   serving `http://127.0.0.1:39649`).
2. From the attacker container, with `BASE_URL`, `ADMIN_USER` and `ADMIN_PASS`
   set (the administrator is used only to create the victim and to read the
   settings back as a witness):

   ```
   docker exec -w /chains/CHAIN-002-ordinary_account_defeats_the_second_factor \
     -e BASE_URL -e ADMIN_USER -e ADMIN_PASS "$BLUESPIDER_ATTACKER" python3 automation.py
   ```

   Without an attacker container, run `python3 automation.py` from this folder
   with `requests` and `pyotp` available. `CHAIN_TOTP_WINDOW` (default 4000),
   `CHAIN_IP_ALLOWANCE` (1500) and `CHAIN_MAX_GUESSES` (1200) tune how the work
   is split between widening the window and grinding codes.
3. The script registers its own attacker account, provisions a TOTP-enrolled
   administrator as the victim, and runs the three steps.

**Observed combined result** (full transcript in `run.log`):

```
[PROOF]     HTTP 200: 2 administrator(s) with their addresses, from an account with no permissions
[PROOF]     4000 + 1500 increments accepted ...; the workspace now reports
            Accounts_TwoFactorAuthentication_MaxDelta=4001 (was 1) and
            Block_Multiple_Failed_Logins_Attempts_Until_Block_By_Ip=1550 (was 50)
[INFO]      a random six-digit code now verifies with probability 0.8003% ... about 124 attempts
[PROOF]     525 guesses in 202s: answers {"totp-invalid": 524, "": 1}; a guessed code was accepted=True;
            any attempt refused by a lockout=False
[PROOF]     the guessed session is sadm_9f359e8a and reads a private setting (HTTP 200), which the
            attacker's own ordinary account cannot (HTTP 403)
```

Two operational notes for a re-run. The telemetry batches are deliberately small
(fifty increments per request, six-tenths of a second apart): the handler fires
every increment without awaiting it, and larger batches made the workspace answer
503, which is a denial of service this chain does not need. And a run that fails
to land a code leaves the source address under the shipped five-minute IP block,
because each further attempt extends it; a successful run does not, because the
successful login resets the counter.

## Fix order

**The single highest-leverage fix is on step 2: close the set of settings ids the
telemetry handler will touch** (`updateCounter` in
`apps/meteor/server/lib/statistics/functions/updateStatsCounter.ts`), so a
statistics event cannot write a security setting. Treat the counter ids as a
closed allow-list, or keep counters out of the settings collection altogether,
and bound the request array with `maxItems`.

That one change breaks the chain: at the shipped window of 1 a blind guess lands
once in 333,000, and at the shipped ceiling of 50 the attacker's address is
blocked long before that. Step 1 falls back to being a disclosure and step 3 to
being a slow, pointless grind.

**Side effects of that fix.** It keeps telemetry and removes only the weakness:
the handful of counters the first-party client reports keep working and any other
settings id is refused, which no shipped client sends. A deployment with a custom
client that incremented other settings through this route would have to use the
settings API with the matching permission instead.

**Next in order of leverage, and still worth doing:**

- Key the per-user failed-login counter on the resolved account rather than on
  the identifier as typed (VULN-032), so lockout follows the account whether it
  is named by username, by email address or inside a `totp` envelope. On its own
  this does not break the chain, because a widened window can be ground from many
  source addresses, but it restores the control the documentation describes. Side
  effect: logins by email address now count towards the lockout, so a user who
  mistypes their password at both spellings is locked out after ten attempts
  rather than twenty.
- Hide roles and email addresses from `users.listByStatus` for callers without a
  user-administration permission (VULN-007). Side effect: a client that built a
  directory from that route sees fewer fields.

## Files

- `automation.py` - the whole chain, end to end, from a clean state; writes `run.log`.
- `run.log` - the transcript of the confirming run, including every hundredth guess.
- `request.http`, `response.txt` - the decisive request and response of step 1
  (the administrator roster read by an unprivileged account).
- `evidence/chain-002.json` - the shipped values, the increments, the grind's
  answer histogram and the restore, as data.
- `evidence/guessed-admin-session.json` - what the guessed session was and what
  it could reach.
- `chain.json` - this chain, machine-readable.

---

Blue Spider, a product of Kohi Research Corporation (kohirc.com). Copyright 2026 Kohi Research Corporation. All rights reserved. Blue Spider (TM) is a trademark of Kohi Research Corporation. Generated by Blue Spider; do not use or redistribute without attribution to Kohi Research Corporation.
