# CHAIN-005: an identity-provider account becomes an administrator past TOTP, and deactivation does not take it away

| Field | Value |
|-------|-------|
| **Chain** | CHAIN-005 |
| **Severity** | High |
| **Status** | CONFIRMED |
| **Validated at** | 2026-11-24 |
| **Software** | Rocket.Chat 9.1.0-develop (commit `9f3d6c8c48911e32ed6c2ce36befd431faa71190`) |
| **Pattern** | CH-ATO (to account takeover), with the incident response defeated |

Three findings sit at three different stages of the same login: who the federated
identity is bound to, whether a second factor is demanded, and whether the account
is allowed to log in at all. Together they defeat the whole incident-response
playbook for a compromised administrator: the password reset is performed by the
attack itself, the second factor is never requested, and deactivation, the action
an operator is told ends an account's access, is followed by another sign-in that
returns a token with the account's administrator rights intact.

## The chain

1. **[VULN-002](../../exploits/VULN-002-oauth_unverified_email_meld/writeup.md)**
   provides the binding. The meld finds the local account by the email address
   the identity provider asserts and never asks whether that address was
   verified, so an identity-provider account carrying the administrator's address
   was melded into the administrator's account. The callback came back with a
   login code, and the administrator's own password was reset in the process,
   which locks the real owner out.
2. **[VULN-043](../../exploits/VULN-043-oauth_login_skips_2fa_grace/writeup.md)**
   removes the second factor. On the OAuth path the decision is the account's
   age, not whether it has an enrolled method, so although the victim
   administrator had TOTP enrolled and its password login answered
   `totp-required`, the callback redirected straight to `/home` with a login code
   rather than to `/2fa/totp/<challengeId>`. Redeeming it gave a session that
   reaches `rooms.adminRooms` (HTTP 200).
3. **[VULN-030](../../exploits/VULN-030-deactivated_account_oauth_login_code/writeup.md)**
   defeats the response. The operator deactivated the compromised administrator,
   which deleted every one of its tokens: the stolen session stopped working
   (HTTP 401) and the password path refused the account, so the response did what
   it promises. Signing in through the same provider again and redeeming a new
   login code returned a working token: `/api/v1/me` reports `active: false` and
   `rooms.adminRooms` still answers HTTP 200.

## Combined impact

**Before:** an account at an identity provider the workspace trusts, on which the
attacker can type an email address. No Rocket.Chat account, no password, no
second factor.

**After, proven by the run:**

- a full administrator session on the workspace, with no code ever demanded even
  though the account had TOTP enrolled;
- the real administrator locked out of their own account, because the meld reset
  its password;
- administrative access that survives the three things an operator reaches for:
  resetting the password (the attack does that itself), relying on the second
  factor (never asked for), and deactivating the account (another sign-in
  restores the access, and the account's roles are unchanged by deactivation).

What does end it is deleting the account, stripping its roles, or removing the
provider. The blast radius is the whole workspace, since the account reached is
an administrator.

Alone, each is narrower. VULN-002 is a takeover an operator can respond to.
VULN-043 is a 2FA skip inside a window. VULN-030 needs an account that was
already linked to a provider. Composed, the response is what fails, which is the
part that turns an incident into a standing compromise.

## Reproduction

**Preconditions.** An OAuth login provider enabled whose users can set their own
profile email address without proving ownership: a self-managed GitLab, a custom
OIDC provider, any provider with a self-service address field. That is the
business configuration this chain is conditional on. The run enables
Rocket.Chat's built-in GitLab backend (`API_Gitlab_URL`,
`Accounts_OAuth_Gitlab*`) against a stand-in provider it starts inside the
attacker container, and restores all four settings afterwards.

Step 2 additionally needs the victim administrator to be inside the
`Accounts_TwoFactorAuthentication_RememberFor` window (1800 seconds by default),
which is where a freshly provisioned administrator lives. Outside it the chain
stops at the 2FA challenge, and what remains standing is the password reset, the
verified address and a permanent identity-provider link into the administrator's
account, which completes the takeover the moment the second factor is removed.

**Lab safety, which a reproducer should keep.** The victim is an extra
administrator the run creates, not the workspace's own, because the meld resets
the melded account's password and a re-run must not lock the lab out.

**From a clean state:**

1. Bring the workspace up (lab: `BLUESPIDER_PORT_BASE=39649 audit/rocket.chat/setup/rebuild.sh`,
   serving `http://127.0.0.1:39649`).
2. From the attacker container, with `BASE_URL`, `ADMIN_USER`, `ADMIN_PASS` and
   `ATTACKER_HOST` set (the administrator sets up the provider and plays the
   operator who deactivates the account):

   ```
   docker exec -w /chains/CHAIN-005-oauth_meld_to_admin_surviving_deactivation \
     -e BASE_URL -e ADMIN_USER -e ADMIN_PASS -e ATTACKER_HOST="$BLUESPIDER_ATTACKER" \
     "$BLUESPIDER_ATTACKER" python3 automation.py
   ```

   Without an attacker container, run `python3 automation.py` from this folder
   with `requests` and `pyotp` available, and set `ATTACKER_HOST` to a name the
   workspace can resolve back to the machine running the script.

**Observed combined result** (full transcript in `run.log`):

```
[SETUP]     victim administrator vicadm_574b6ae3 ... with TOTP enrolled: its own password login
            answers HTTP 401 totp-required; the grace window ... is 1800
[PROOF]     the callback ended at http://127.0.0.1:39649/home with loginCode=7d7bffe4ef75...
            (a second-factor challenge would have been /2fa/totp/<id>)
[PROOF]     the redeemed session is vicadm_574b6ae3 with roles ['user', 'admin'], and it reaches an
            administrator-only route: rooms.adminRooms HTTP 200
[PROOF]     meanwhile the real owner's own password answers HTTP 401 Unauthorized: the meld reset it
[INFO]      deactivation did what it promises for the stolen token (/api/v1/me -> HTTP 401) and for
            the password path (HTTP 401 Unauthorized)
[PROOF]     signing in again through the same provider returned a working token: /api/v1/me HTTP 200
            username=vicadm_574b6ae3 active=False, and rooms.adminRooms HTTP 200
```

One lab detail that is not part of any finding: the OAuth session cookie is
issued `Secure` on a production build, so the script walks the redirect chain
against the app's own address with `X-Forwarded-Proto: https`, which is what a
browser on the vendor's documented HTTPS deployment gets for itself. The
server-side code path is identical either way.

## Fix order

**The single highest-leverage fix is on step 1: link a federated identity to an
existing local account only on a verified-email claim** (the meld in
`apps/meteor/server/configuration/accounts_meld.js:14-31`), never on the asserted
address alone, and make the behaviour an administrator-visible choice rather than
an implicit one.

That one change breaks the chain: steps 2 and 3 both act on the account the meld
attached the attacker to, and without the meld the provider sign-in creates a new
account with no rights.

**Side effects of that fix.** It removes a convenience for some deployments: a
user whose provider does not assert `email_verified` is no longer linked
automatically to an existing local account, so either an administrator links them
by hand or the user signs in with their password once and connects the provider
from their account settings. Nothing changes for providers that do assert
verification, which is the common case for hosted identity providers.

**Next in order of leverage, and still worth doing:**

- Decide the second factor on the account's enrolled methods rather than on its
  age (VULN-043), on the OAuth path as on the password path. Side effect: a user
  who enrolled TOTP minutes ago is asked for a code on their first federated
  sign-in, which is what enrolling it means.
- Run the account-state checks where the token is issued, not only in the Meteor
  login pipeline (VULN-030): `issueLoginToken` and `loginCode.redeem` should
  refuse a deactivated or unapproved account, and REST authentication should
  re-check `active`. Side effect: a deactivated account can no longer be revived
  by signing in; an operator re-activates it deliberately, which is the point of
  the flag.

## Files

- `automation.py` - the whole chain, end to end, from a clean state, including
  the stand-in identity provider; writes `run.log`.
- `run.log` - the transcript of the confirming run.
- `request.http`, `response.txt` - the decisive exchange: the identity the
  provider asserted, the callback URL carrying the login code, and the
  redemption.
- `evidence/idp-requests.json` - every request the workspace made to the stand-in
  provider, in order.
- `evidence/chain-005.json` - the takeover, the deactivation and the second
  sign-in as data.
- `chain.json` - this chain, machine-readable.

---

Blue Spider, a product of Kohi Research Corporation (kohirc.com). Copyright 2026 Kohi Research Corporation. All rights reserved. Blue Spider (TM) is a trademark of Kohi Research Corporation. Generated by Blue Spider; do not use or redistribute without attribution to Kohi Research Corporation.
