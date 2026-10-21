# VULN-003 — Unauthenticated `X-OTRS-*` header injection via trusted inbound mail

| | |
|---|---|
| **ID** | VULN-003 (raw ZN-032) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | High (conditional) · CVSS 3.1 **8.2** — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** · **Auth**: none (email) |
| **Attacker gains** | An unauthenticated emailer chooses a new ticket's queue/owner/state/priority/dynamic-fields and forges an internal agent-sender article. |

## Summary
Znuny treats inbound mail as **Trusted** by default, honouring `X-OTRS-*` control headers on
externally-originated email. An unauthenticated sender therefore dictates the routing/ownership/
state of the ticket they create and can forge an article that renders as an internal **agent**
note. Confirmed: a crafted email created a ticket in the attacker-chosen queue, owned by the
attacker-chosen agent, in state `closed successful`, with an `agent`-sender article hidden from the
customer.

## How it works (mechanism & code trace)
`Kernel/System/PostMaster.pm`:
```perl
 92:  $Self->{Trusted} = defined $Param{Trusted} ? $Param{Trusted} : 1;   # default TRUSTED
...
581:  if ( !$Self->{Trusted} ) { ... strip X-OTRS-* headers ... }         # strip ONLY when untrusted
```
The CLI reader defaults the same (`Console/Command/Maint/PostMaster/Read.pm:119`), and the shipped
`.procmailrc.dist`/`.mailfilter.dist` pipe without `--untrusted`. So on a trusted deployment the
`X-OTRS-*` headers survive into `%GetParam` and reach the ticket sinks in
`Kernel/System/PostMaster/NewTicket.pm`:
- queue: `X-OTRS-Queue`/`QueueID` (`DestQueue.pm`);
- owner/responsible/state/priority/type/service/SLA/dynamic-fields: `X-OTRS-Owner[ID]` etc.;
- **article forgery**: `X-OTRS-SenderType` (validated against the DB sender types, so `agent`/
  `system` are accepted) + `X-OTRS-IsVisibleForCustomer` (`NewTicket.pm:602-616`).

Dynamic proof (DB): `queue=Junk, owner uid=2, state=closed successful, article sender=agent,
is_visible_for_customer=0` — every attacker-chosen field honoured.

## Why it is a vulnerability
The security boundary is external (anonymous) sender → the ticket system's trusted control plane.
`X-OTRS-*` headers are meant for *internal* mail-processing filters to set fields — not for the
untrusted originator. Because the default is Trusted and the shipped MTA glue doesn't pass
`--untrusted`, an anonymous emailer gains privileged control over new tickets: routing them to a
chosen agent, pre-closing them (evading SLAs/queues), setting dynamic fields, and — most
seriously — planting content that looks like a genuine internal staff note (`SenderType=agent`,
hidden from the customer). That is integrity-high. It is a documented "trusted mail" footgun, but
the *default* is dangerous and the shipped `.dist` strip recipe is scoped to a placeholder domain,
so real deployments frequently run wide-open.

## Reproduction
Feed the raw email in `request.http` to the trusted mail path
(`Maint::PostMaster::Read`, no `--untrusted`). `./run.sh` proof:
```
[PROOF] created ticket: [['<tn>', 'Junk', '2', 'closed successful', 'agent', '0']]
```

## Impact
Unauthenticated control of new tickets: queue/owner/state/priority/DF assignment and forged
internal/agent-sender articles (in-portal impersonation, evidence planting, SLA evasion). Chains
with VULN-006/VULN-031 (inject into *existing* tickets) and VULN-019 (bounce channel). High where
inbound mail is trusted (the shipped default).

## Suggested fix
Default inbound mail to **untrusted**; only honour `X-OTRS-*` from explicitly configured, internal,
authenticated relays. Never derive article `SenderType`/visibility or ownership/state from headers
on externally-originated mail. Ship the MTA glue with `--untrusted` and a domain-agnostic X-OTRS
strip.

## References
- OWASP Email Header Injection; OTRS/Znuny admin docs (`PostmasterX-Header`, Trusted). CWE-807
  (Reliance on Untrusted Inputs in a Security Decision).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 50 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `OTRS "X-OTRS-" headers trusted email spoofing vulnerability CVE postmaster` — only CVE-2020-1765 (agent-screen From spoofing), CVE-2021-36093 (PostMaster filter DoS), CVE-2008-728x (old mail issues)
2. `OTRS security advisory X-OTRS header injection queue owner state external mail OSA` — only CVE-2023-38060 (GI attachment ContentType header injection); nothing on X-OTRS control headers
3. `"X-OTRS-SenderType" OR "X-OTRS-Owner" OR "X-OTRS-Queue" header vulnerability trusted default Znuny OTRS exploit` — no advisory; nearest is CVE-2026-93582/93483 (HTTP Remote-User header trust, unrelated path)
4. `Znuny PostMaster Trusted default X-OTRS headers github issue security untrusted` — only vendor docs (annexes/x_headers) and community threads describing the trusted-mailbox behaviour as a feature
5. NVD API keyword pull for "Znuny"/"OTRS" grepped for X-OTRS/trusted/header — no match; Znuny advisory index and GitHub advisory DB reviewed — no entry

**Related but distinct public references** (same class or component, not this bug):
- Znuny documentation "E-Mail Headers" annex (doc.znuny.org) — documents that trusted mailboxes / local procmail delivery apply X-OTRS-* headers; it is a feature description, not a vulnerability disclosure
- CVE-2020-1765 / OSA-2020-01 — From-field spoofing in agent compose/forward/bounce screens, not inbound control headers
- CVE-2026-93483 / ZSA-2026-14 — trusting an attacker-controllable HTTP `Remote-User` header; different channel

**Reasoning:** No CVE/ZSA/OSA treats the Trusted-by-default PostMaster path (`PostMaster.pm` `Trusted => 1`, shipped `.procmailrc.dist` without `--untrusted`) honouring attacker-supplied X-OTRS-* headers as a vulnerability. However, the behaviour itself is openly documented by the vendor as the intended trusted-mail design and widely discussed on community forums, so the vendor may classify this as a configuration footgun rather than a defect; confidence is therefore moderate. The specific `X-OTRS-SenderType=agent` article-forgery consequence is not described anywhere public.
