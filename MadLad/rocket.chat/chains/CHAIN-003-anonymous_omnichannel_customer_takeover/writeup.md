# CHAIN-003: an anonymous outsider eavesdrops on support chats, becomes a customer, and has the workspace mail out their conversation

| Field | Value |
|-------|-------|
| **Chain** | CHAIN-003 |
| **Severity** | High |
| **Status** | CONFIRMED |
| **Validated at** | 2026-11-24 |
| **Software** | Rocket.Chat 9.1.0-develop (commit `9f3d6c8c48911e32ed6c2ce36befd431faa71190`) |
| **Pattern** | CH-DATA (to cross-boundary data exposure) into CH-ATO (the customer's identity) |

Omnichannel identifies a website visitor by a random token their browser keeps.
That token is the whole credential: it authorises reading the conversation,
writing into it, uploading to it and mailing its transcript. This chain starts
with no account and no token, and ends holding a chosen customer's token, their
conversation, and a copy of it delivered by the workspace's own mail server to
an address the attacker chose.

## The chain

1. **[VULN-076](../../exploits/VULN-076-livechat_stream_room_confusion/writeup.md)**
   opens the feed. The Livechat rule for `stream-room-messages` authorises the
   visitor token against the room named in the subscription's `extraData`, not
   against the room being subscribed to, so the attacker opened one anonymous
   chat of its own and then subscribed to a stranger's conversation while naming
   its own room. The subscription was accepted and the customer's messages
   arrived live, including the callback number the customer gave the agent.
2. **[VULN-001](../../exploits/VULN-001-livechat_visitor_token_idor/writeup.md)**
   turns an identifier into a credential. `registerGuest` tries to recognise a
   returning customer by phone number before it looks at the caller's own token,
   and the route returns the stored visitor document. Registering the harvested
   number under a fresh token of the attacker's own returned **the customer's own
   token**. With it, the attacker read the conversation history back and posted a
   message into the conversation as the customer.
3. **[VULN-051](../../exploits/VULN-051-livechat_transcript_html_relay/writeup.md)**
   carries the result out. `livechat/transcript` takes the recipient address from
   the request body and builds the mail by interpolating an attachment
   description into HTML unescaped. The attacker uploaded a file with an HTML
   description as the impersonated customer and asked for the transcript to be
   sent to its own address: the mail arrived from the workspace's own sender with
   the customer's whole conversation in it and a live attacker link.

## Combined impact

**Before:** an anonymous visitor who can open its own support chat. No account,
no credential, no knowledge of the workspace's customers.

**After, proven by the run:**

- a live read of a stranger's support conversation as the customer and the agent
  type (repeatable per room, so not one conversation but any);
- the chosen customer's visitor token, which is read and write access to
  everything that customer's token authorises: their history, their uploads,
  their transcripts, and posting as them (the run posted "please send the refund
  to my new account" into their conversation);
- their whole conversation delivered off-site by the organisation's own mail
  server, carrying its SPF and DKIM alignment, with an attacker-authored link
  inside it.

The blast radius is every Omnichannel conversation on the workspace plus the
reputation of its mail domain. The customer sees nothing: no login, no device
notification, no second factor, because a visitor has none of those.

On their own the three are smaller. VULN-076 is a read of conversations you have
to know the ids of; VULN-001 needs a phone number and gives you one customer;
VULN-051 lets a visitor mail its **own** conversation anywhere. Composed, the
feed supplies the identifiers, the identifier supplies the credential, and the
credential makes the trusted mail channel exfiltrate someone else's data.

## Reproduction

**Preconditions.** No account. Omnichannel in use (`Livechat_enabled`), which is
the business feature this chain abuses: it ships off in 9.x and is on wherever
the product's support offering is used. The run enables it, together with
`Livechat_accept_chats_with_no_agents` so that a conversation can be opened with
no agent online, through the workspace's own settings API, and restores both
before it exits.

**From a clean state:**

1. Bring the workspace up (lab: `BLUESPIDER_PORT_BASE=39649 audit/rocket.chat/setup/rebuild.sh`,
   serving `http://127.0.0.1:39649`).
2. From the attacker container, with `BASE_URL`, `ADMIN_USER` and `ADMIN_PASS`
   set (the administrator is used only for the Omnichannel switch):

   ```
   docker exec -w /chains/CHAIN-003-anonymous_omnichannel_customer_takeover \
     -e BASE_URL -e ADMIN_USER -e ADMIN_PASS "$BLUESPIDER_ATTACKER" python3 automation.py
   ```

   Without an attacker container, run `python3 automation.py` from this folder
   with `requests` and `websocket-client` available, pointing `MAILPIT` at the
   mail sink.
3. The script creates its own customer (with a random phone number) and its own
   anonymous attacker visitor, then runs the three steps. Every socket it opens
   is anonymous: it never calls `login`.

**Observed combined result** (full transcript in `run.log`):

```
[PROOF]     the anonymous subscription to a stranger's conversation was accepted: {"msg": "ready", ...}
[PROOF]     the customer's own messages arrived on the attacker's socket, including the number they
            gave the agent: harvested '+1555235835' from the live feed
[PROOF]     HTTP 200: the response carries token='customer-834e8323' (the customer's own=True)
[PROOF]     with that token: the conversation history reads back (HTTP 200, contains the customer's
            own line=True) and a message posted as the customer returned HTTP 200
[PROOF]     upload HTTP 200, transcript HTTP 200: a mail from 'rocketchat@lab.invalid' arrived at the
            attacker's address carrying the customer's conversation (their own line present=True) and
            the attacker's live HTML link=True
```

The script closes both conversations, clears its mail from the sink and restores
the two Omnichannel settings.

## Fix order

**The single highest-leverage fix is on step 2: never hand back a token the
caller did not present.** In `registerGuest`
(`packages/omni-core/src/visitor/create.ts:105-115`), a caller whose token is
unknown is a new visitor: create one instead of merging into a visitor found by
phone number or email address, and leave the linking of returning customers to
the agent-side contact merge the product already models. The route should also
project `token` out of its response unless it equals the token the caller sent.

That one change breaks the chain, because the credential is what turns
eavesdropping into impersonation and exfiltration, and it is the only step that
works from a phone number alone, which is the kind of thing printed on business
cards and sold in CRM exports.

**Side effects of that fix.** It keeps the feature and removes only the weakness:
returning customers who cleared their browser storage are no longer re-attached
to their old visitor record automatically, so their new chat starts fresh and an
agent merges the contact; the email branch stops rebinding an existing record,
which also closes the denial-of-service side of that finding (a customer losing
their own record to an attacker's token).

**Next in order of leverage, and still worth doing:**

- Authorise the Livechat message stream against the room being subscribed to
  rather than the room named in `extraData` (VULN-076). On its own this stops the
  eavesdropping but leaves any known phone number a route to a customer's token.
  Side effect: none for the shipped widget, which always names the room it is
  subscribing to.
- Bind `livechat/transcript` to the conversation's own visitor and escape
  attachment descriptions when building the mail (VULN-051). Side effect:
  transcripts can no longer be sent to an arbitrary third-party address, which a
  workspace that used that behaviour to forward transcripts to a CRM inbox would
  notice.

## Files

- `automation.py` - the whole chain, end to end, from a clean state; writes `run.log`.
- `run.log` - the transcript of the confirming run.
- `request.http`, `response.txt` - the decisive frames: the cross-visitor stream
  subscription and the visitor registration that returns the customer's token.
- `evidence/step1-live-feed.json` - the subscription, the pushed frame and the
  phone number harvested from it.
- `evidence/step3-transcript-mail.html` - the mail the workspace sent to the
  attacker's address, as delivered.
- `evidence/chain-003.json` - every step's inputs and observations as data.
- `chain.json` - this chain, machine-readable.

---

Blue Spider, a product of Kohi Research Corporation (kohirc.com). Copyright 2026 Kohi Research Corporation. All rights reserved. Blue Spider (TM) is a trademark of Kohi Research Corporation. Generated by Blue Spider; do not use or redistribute without attribution to Kohi Research Corporation.
