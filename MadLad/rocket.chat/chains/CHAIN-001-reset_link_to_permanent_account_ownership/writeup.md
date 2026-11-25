# CHAIN-001: one captured password-reset link becomes permanent ownership of a TOTP-protected account

| Field | Value |
|-------|-------|
| **Chain** | CHAIN-001 |
| **Severity** | High |
| **Status** | CONFIRMED |
| **Validated at** | 2026-11-24 |
| **Software** | Rocket.Chat 9.1.0-develop (commit `9f3d6c8c48911e32ed6c2ce36befd431faa71190`) |
| **Pattern** | CH-ATO (to account takeover) |

A password-reset link is meant to be a single-use, short-lived credential: whoever
holds it can set a new password once, and a second factor is there so that a
compromised mailbox is not enough. On this build, one captured reset link ends
with the attacker holding the password, the second factor and the email address
every future recovery mail goes to, and the two remediations the product offers
(change the password, log out the other clients) do not evict them.

## The chain

1. **[VULN-015](../../exploits/VULN-015-mfa_bypass_via_password_reset/writeup.md)**
   contributes the entry. An anonymous `users.forgotPassword` mails the link; the
   DDP `resetPassword` method is exempted from the second factor and returns a
   login token with the new password. The run captured the link from the mailbox
   and came away with a working session on an account that had TOTP enrolled,
   while that account's password login still answered `totp-required`.
2. **[VULN-004](../../exploits/VULN-004-totp_seed_disclosed_to_session/writeup.md)**
   turns that session into a permanent credential. `users.info` for the caller's
   own id returns the stored `services` document, so the session read the
   account's base32 TOTP seed (identical to the enrolled one) and its twelve
   backup-code hashes. A session can be revoked; a seed cannot.
3. **The account-settings email change**, working exactly as designed,
   contributes the step the attacker could not take without step 2. Changing an
   account's address is a sensitive action, so Rocket.Chat demands a second
   factor for it; the attacker computed a code from the stolen seed and the
   change went through. The account's recovery channel is now the attacker's: a
   fresh anonymous reset request mailed the link to the attacker's mailbox, and
   the victim's own address produced none.
4. **[VULN-033](../../exploits/VULN-033-realtime_session_survives_revocation/writeup.md)**
   closes the escape routes. The attacker kept the stolen token's DDP socket
   open; `users.removeOtherTokens` did not close it, and when the administrator
   set a new password, that password arrived on the socket in clear. The attacker
   logged in again with it and a seed-derived code.

## Combined impact

**Before:** the attacker can read one message in a mailbox. No Rocket.Chat
account, no session, no knowledge of the victim's password, and the victim's
TOTP enrolment is intact.

**After, proven by the run:** the attacker holds

- a session on the account, obtained without ever presenting a second factor;
- the account's TOTP seed and backup-code hashes, which satisfy every future
  step-up and every future login;
- the account's email address, so the owner cannot start a recovery that reaches
  them (`users.forgotPassword` for their old address produces nothing, and the
  reset mail for the account now arrives in the attacker's mailbox);
- a realtime session that survived the user's "log out other clients" and an
  administrator's password reset, and that was handed the administrator's new
  password in clear.

The blast radius is one account per captured link, but it can be any account,
administrators included, and the hold does not decay: short of deactivating or
deleting the account, or regenerating its TOTP secret, nothing an operator does
in the product's interface removes the attacker.

Each step on its own is a smaller thing. VULN-015 is a session that an
administrator can revoke. VULN-004 only matters to someone who already has a
session. VULN-033 needs a token that was stolen some other way. Composed, they
are the difference between "we reset her password and logged out her devices"
and "the account is theirs".

## Reproduction

**Preconditions.** A Rocket.Chat workspace in its shipped configuration (no
setting is changed by this chain), with SMTP configured so the product can send
its own reset mail. A victim account with TOTP enrolled. Read access to one
password-reset mail for that account: in the lab this is the mail sink at
`http://mailpit:8025`, standing in for a shared or archived mailbox, a forwarded
message, or any other capture of the link.

**From a clean state:**

1. Bring the workspace up (lab: `BLUESPIDER_PORT_BASE=39649 audit/rocket.chat/setup/rebuild.sh`,
   which serves it at `http://127.0.0.1:39649`).
2. From the attacker container, with `BASE_URL`, `ADMIN_USER` and `ADMIN_PASS`
   set (the administrator is used only to create the victim account):

   ```
   docker exec -w /chains/CHAIN-001-reset_link_to_permanent_account_ownership \
     -e BASE_URL -e ADMIN_USER -e ADMIN_PASS "$BLUESPIDER_ATTACKER" python3 automation.py
   ```

   Without an attacker container, run `python3 automation.py` from this folder
   with `requests`, `websocket-client` and `pyotp` available, pointing
   `MAILPIT` at the mail sink.
3. The script provisions its own victim with a fresh random suffix, enrols TOTP,
   and then runs the four steps in order.

**Observed combined result** (full transcript in `run.log`):

```
[PROOF]     the reset handed back a working session with no TOTP code: /api/v1/me HTTP 200 as vic_5d7a3bf5
[PROOF]     services.totp.secret=NQSTMQJDJV4D... plus 12 backup-code hashes ... (matches the enrolled seed=True)
[PROOF]     HTTP 200: the account's address is now atk_5d7a3bf5@lab.invalid
[PROOF]     a fresh reset mail for the account arrived at the attacker's mailbox (token nG4ZxUkCXV...),
            while the victim's own address produced none (HTTP 200, token=None)
[PROOF]     after users.removeOtherTokens (HTTP 200) the socket is still alive=True; the administrator's
            reset (HTTP 200) arrived on it in clear: 'Admin-Reset-5d7a3bf5!7x'
[PROOF]     logging in with the administrator's new password and a code from the stolen seed: HTTP 200 success=True
```

The script deletes the victim account it created and clears its mail from the
sink, so the workspace is left as it was found.

## Fix order

**The single highest-leverage fix is on step 1: make the recovery path run the
second-factor check** (the `resetPassword` and `verifyEmail` login handlers
behind VULN-015). Either require the account's enrolled factor before
`resetPassword` issues a login token, or have the method set the password
without returning a session at all, so the user logs in afterwards through the
ordinary path that does ask.

That one change breaks the chain: steps 2, 3 and 4 are all built on the session
step 1 hands out, and without it a captured reset link is worth what it should be
worth, a password change that still has to get past the second factor.

**Side effects of that fix.** It keeps the feature and removes only the weakness.
A user with TOTP who resets their password must present a code or a backup code
before being logged in; someone who has lost both their password and their
authenticator can no longer self-recover and needs an administrator, which is the
behaviour a second factor implies. The reset mail, the token's lifetime and the
password write itself do not change, and accounts with no second factor are
unaffected.

**Next in order of leverage, and still worth doing:**

- Project `services` out of `users.info` (VULN-004). This breaks steps 2 and 3,
  so a stolen session stays a stolen session instead of becoming the second
  factor. Side effect: a client that read its own TOTP seed back from
  `users.info` (none ship) must use the enrolment response instead.
- Broadcast the token-list change on password change, password reset and
  `users.removeOtherTokens` (VULN-033), so the realtime sessions close with the
  REST ones. Side effect: users who change their password are disconnected on
  their other tabs, which is what the action promises.
- Never put a new password in a `userData` broadcast (VULN-033's second leg).

## Files

- `automation.py` - the whole chain, end to end, from a clean state; writes `run.log`.
- `run.log` - the transcript of the confirming run.
- `request.http`, `response.txt` - the decisive request and response of step 2
  (the `users.info` read that discloses the seed).
- `evidence/chain-001.json` - every step's inputs and observations as data.
- `evidence/reset-mail-to-attacker.txt` - the reset mail for the victim's account
  that arrived at the attacker's address after step 3.
- `chain.json` - this chain, machine-readable.

---

Blue Spider, a product of Kohi Research Corporation (kohirc.com). Copyright 2026 Kohi Research Corporation. All rights reserved. Blue Spider (TM) is a trademark of Kohi Research Corporation. Generated by Blue Spider; do not use or redistribute without attribution to Kohi Research Corporation.
