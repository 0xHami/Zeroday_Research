# VULN-008 — GenericInterface customer channel divergence: forge agent/internal articles & mass-assign

| | |
|---|---|
| **ID** | VULN-008 (raw ZN-048/049) |
| **Software** | Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev branch; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium · CVSS 3.1 **6.5** — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | a customer portal account + a configured GI web service exposing TicketCreate/TicketUpdate (the shipped `GenericTicketConnectorREST` example) |
| **Attacker gains** | Creates/updates tickets with staff-only properties — articles that render as internal **agent** notes with a **spoofed From**, plus Owner/State/Priority/Queue the customer UI never exposes. In-portal support-impersonation / phishing and data-integrity abuse. |

## Summary
Znuny's GenericInterface `TicketCreate`/`TicketUpdate` operations let a *customer*-authenticated
caller set the article `SenderType` to `agent`/`system` and `IsVisibleForCustomer=0`, spoof the
`From`, and assign Owner/State/Priority/Queue. The per-field customer permission guard added by
the CVE-2025-26846 fix is present but is a no-op for this channel. Confirmed live: a plain
customer account created a ticket whose article is stored `SenderType=agent`,
`IsVisibleForCustomer=0`, `From: IT Support <helpdesk@corp.example>` — an internal staff note
that the customer web UI can never produce.

## How it works (mechanism & code trace)

**Entry point** — `Kernel/GenericInterface/Operation/Ticket/TicketCreate.pm`, reachable at
`POST /znuny/nph-genericinterface.pl/Webservice/<name>/Ticket` with customer credentials in the
JSON body (`CustomerUserLogin`+`Password`). `TicketUpdate` (`PATCH /Ticket/:id`) is the sibling
channel.

**The SenderType defect (lines 553-554).** The operation only *defaults* the sender type when
the caller omits it:

```perl
553:  if ( !$Article->{SenderTypeID} && !$Article->{SenderType} ) {
554:      $Article->{SenderType} = $UserType eq 'User' ? 'agent' : 'customer';
555:  }
```

A customer request that *includes* `"SenderType":"agent"` never enters the `if`, so the
attacker-chosen value stands. `IsVisibleForCustomer` is likewise only defaulted (`:550-551`).
Both flow verbatim into article creation:

```perl
1716:  SenderType           => $Article->{SenderType},
1717:  IsVisibleForCustomer => $Article->{IsVisibleForCustomer},
```

`ArticleSenderTypeLookup` accepts `agent`/`system`/`customer`, so `agent` is stored as-is.

**Why the CVE-2025-26846 guard doesn't fire.** The fix added per-field
`TicketCustomerPermission(Type => …)` calls, intended to reject customer attempts to set
privileged fields. But two registered permission modules neutralise it:
- `CustomerPermission/CustomerUserIDCheck.pm` is registered `Granted=1` and returns **true** as
  soon as the customer is the ticket's customer-user — **ignoring** `$Param{Type}`. For the
  attacker's own ticket, every type check passes.
- `CustomerPermission/GroupCheck.pm`'s type comparison collapses to "all groups" under the
  shipped default `CustomerGroupSupport=0` (`Defaults.pm:1437`).

So the guard returns "granted" for `SenderType`, `IsVisibleForCustomer`, `Owner`, `State`, etc.
`TicketCreate` in addition never received *any* per-field customer check.

**Confirmed at the sink (DB).** After the call, the article row has
`article_sender_type.name='agent'`, `is_visible_for_customer=0`, and the spoofed `a_from`.

## Why it is a vulnerability
The trust boundary is customer → agent/system. A customer is authorised to correspond on their
own tickets as a *customer*; they are not authorised to author what the system presents to staff
and other customers as an **internal agent/system message**, nor to choose the owner, queue,
state, or priority. The customer web UI enforces exactly this (it hard-sets those fields). The
GI channel does not, and the compensating control that was supposed to close the gap
(CVE-2025-26846) is inert here. That divergence — same product, two channels, one enforces the
invariant and one doesn't — is the defect; it is not a documented capability of the customer
role. Impact is integrity-high (`I:H`) because forged staff correspondence and arbitrary
routing/state changes undermine the ticket system's authenticity.

## Reproduction
1. Import the shipped example web service:
   `znuny.Console.pl Admin::WebService::Add --name <ws> --source-path var/webservices/examples/GenericTicketConnectorREST.yml`
2. Create a plain customer (`Admin::CustomerUser::Add …`).
3. `POST /znuny/nph-genericinterface.pl/Webservice/<ws>/Ticket` with the JSON in `request.http`
   (customer creds; `Article.SenderType=agent`, `IsVisibleForCustomer=0`, spoofed `From`).
4. Run `./run.sh`. Expected:
   ```
   [PROOF] HTTP 200 -> {'ArticleID':.., 'TicketID':'..', 'TicketNumber':'..'}
   [PROOF] stored article (DB): sender_type=agent, is_visible_for_customer=0, from='IT Support <helpdesk@corp.example>'
   [OK] exploit confirmed ...
   ```
Capture: `request.http`, `response.txt`, `run.log`.

## Impact
- **Staff impersonation inside the portal:** a forged `SenderType=agent` article with a spoofed
  `From` looks like genuine support correspondence — a high-fidelity phishing/social-engineering
  primitive against other customers or agents.
- **Hidden internal notes:** `IsVisibleForCustomer=0` lets a customer plant content in the
  staff-only view.
- **Mass assignment / BFLA:** Owner/State/Priority/Queue assignment lets a customer route a
  ticket to a chosen agent, close/reopen it, or escalate priority.
- **Scope:** any ticket the customer can create/own; with `TicketUpdate` the same forgery lands
  on updatable tickets. Requires a GI web service — the shipped example suffices, and such
  connectors are commonly enabled for integrations.

## Suggested fix
In `TicketCreate.pm`/`TicketUpdate.pm`, when `$UserType` is a customer, **force**
`SenderType='customer'` and `IsVisibleForCustomer=1` and derive `From` from the authenticated
customer — never accept caller-supplied values (allowlist, not default-only). Independently, fix
`CustomerUserIDCheck.pm` to honour `$Param{Type}` so the per-field permission actually
discriminates read vs. the privileged writes.

## References
- CVE-2025-26846 / ZSA-2025-02 (fix present-but-ineffective for the customer channel).
- OWASP API Security Top 10 — API3:2023 (BOPLA / mass assignment), API5:2023 (BFLA).
- CWE-639 (authorization bypass through user-controlled key), CWE-269 (improper privilege mgmt).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 55 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. ZSA-2025-02 / CVE-2025-26846 advisory page fetched — "Ticket attributes could be changed with 'ro' permission" via the Generic Interface; no mention of customer users, SenderType, IsVisibleForCustomer or TicketCreate
2. Znuny fix commit 1aa6843 ("Fixed permission check in generic interface operation TicketUpdate") diff fetched — only change is `CheckAccessPermissions` gaining a `PermissionType` parameter and `TicketUpdate` requesting `rw` instead of `ro`; no field-level restriction, no change to `TicketCreate.pm`
3. OSA-2025-02 / CVE-2024-43446 advisory page fetched (OTRS counterpart) — "change of the Ticket status even if the user only has ro permissions"; same ro→rw issue, user type unspecified
4. NVD API keyword pull for "Znuny"/"OTRS" grepped for GenericInterface / SenderType / customer user — CVE-2014-9324 (OTRS 3/4 GI arbitrary ticket access, unspecified), CVE-2023-38060 (GI attachment ContentType header injection), CVE-2024-43446, CVE-2025-26846; nothing on customer-channel article forgery or mass assignment
5. Earlier web searches `Znuny CVE missing permission check ... article injection any ticket` and `ZSA-2025-02 ... details` — surfaced only CVE-2025-26846 (Wiz/NVD wording "ticket attributes changeable with ro")
6. Znuny advisory index, GitHub advisory DB, Debian tracker reviewed; `gh search issues "SenderType customer GenericInterface"` — none. (Shared WebSearch budget was exhausted before the remaining planned queries.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2025-26846 / ZSA-2025-02 and CVE-2024-43446 / OSA-2025-02 — same component (GI `TicketUpdate`) and same broad class (insufficient permission enforcement), but the published defect and fix concern agents holding only `ro` being able to update; they do not address a customer (who legitimately holds rw on their own ticket) choosing `SenderType=agent`, `IsVisibleForCustomer=0`, a spoofed `From`, Owner/State/Priority/Queue, nor `TicketCreate`
- CVE-2014-9324 / OTRS SA-2014-06 — "incomplete access control" in the GI of OTRS 3.2–4.0 (unspecified vectors, long fixed); ancestor of the same component

**Reasoning:** The customer-channel divergence (no field-level allowlist for the customer user type in `TicketCreate`/`TicketUpdate`, and customer permission modules ignoring `Type`) is not described in any advisory, and the vendor's ZSA-2025-02 fix demonstrably targets a different root cause (ro vs rw). The partial overlap in component and class with two recent advisories, plus the possibility the vendor regards customer-set article attributes via web services as the integrator's responsibility, keep confidence at 55.
