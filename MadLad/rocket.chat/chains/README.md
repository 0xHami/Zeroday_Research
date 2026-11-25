# rocket.chat: vulnerability chains

Eight chains, all CONFIRMED against the running lab on 2026-11-24
(Rocket.Chat 9.1.0-develop, commit `9f3d6c8c48911e32ed6c2ce36befd431faa71190`).
`index.json` is the machine-readable list, built by the engine from the per-chain
`chain.json` files; each `CHAIN-NNN-*/` folder holds the end-to-end
`automation.py` that proves it, the `run.log` of the confirming run, its evidence
and its `writeup.md`.

| Chain | Severity | What it reaches | Steps |
|-------|----------|-----------------|-------|
| CHAIN-001 | High | one captured reset link becomes permanent ownership of a TOTP-protected account, recovery address included | VULN-015, VULN-004, the email-change step-up, VULN-033 |
| CHAIN-002 | High | an account from the public form defeats the second factor and logs in as an administrator | VULN-007, VULN-057, VULN-032 |
| CHAIN-003 | High | an anonymous outsider reads support conversations, becomes a customer, and has the workspace mail out their transcript | VULN-076, VULN-001, VULN-051 |
| CHAIN-004 | High | a delegated help-desk role removes every administrator, then breaks what only they could repair | VULN-020, VULN-069, VULN-057 |
| CHAIN-005 | High | an identity-provider account becomes an administrator past TOTP, and deactivation does not end it | VULN-002, VULN-043, VULN-030 |
| CHAIN-006 | Medium | an ordinary account owns a room the workspace joins every new employee to, and speaks in it as the server | VULN-058, default channels, VULN-012 |
| CHAIN-007 | Medium | a room ban removes nobody: live reads, files, and re-entry through an unrevocable invite | VULN-035, VULN-009, notification preferences, public registration |
| CHAIN-008 | Medium | a deleted message is readable by an outsider, by a member, and by nobody at all | VULN-010, VULN-059, VULN-049, VULN-047 |

## Every chain candidate triage proposed, and what happened to it

`report.json`'s `attack_chains` listed twelve candidates. None is silently
dropped:

| Triage candidate | Outcome |
|------------------|---------|
| Anonymous takeover of Omnichannel customer conversations (VULN-001, VULN-076, VULN-051) | **Proven as CHAIN-003**, with the stream step first so the phone number is harvested in band rather than assumed. |
| Delegated integration role to server code execution (VULN-061, VULN-027) | **Dropped.** Its destination rests on VULN-027, which stage 11 recorded FAILED (the isolate escape did not reproduce), so there is no proven link to code execution. The non-RCE variant (a role rewriting the other family's outgoing integration so it posts a room's messages to an attacker URL) would add only the delivery that VULN-061 and VULN-019 each already prove, so the whole would not exceed the sum. |
| Any user weakens the second factor, then guesses into accounts (VULN-057, VULN-032, VULN-007, VULN-040) | **Proven as CHAIN-002.** VULN-040's code replay was not needed: blind guessing landed inside the widened window, which is the stronger claim. |
| One leaked token becomes permanent account control (VULN-034, VULN-004, VULN-033) | **Proven as CHAIN-001 with a substituted entry.** VULN-034 is NEEDS_MANUAL (it needs a real browser and an owner of the `rocketchat://` scheme), and a chain may only be built on CONFIRMED findings, so CHAIN-001 enters through VULN-015 instead and reaches the same end state, plus the move of the recovery address. |
| OAuth email meld into the env-created administrator (VULN-002, VULN-043, VULN-030) | **Proven as CHAIN-005**, against an extra administrator rather than the workspace's own, because the meld resets the melded account's password. |
| CAS session fixation to persistent takeover (VULN-044, VULN-004, VULN-033) | **Dropped.** VULN-044 is NEEDS_MANUAL: it needs a CAS server serving `validate` over HTTPS with a certificate the app trusts, which is not in the lab's side services and which the sealed lab cannot add. Without the entry step there is nothing to compose; the persistence half is proven in CHAIN-001. |
| Unauthenticated workspace outage (VULN-073, VULN-074, VULN-078) | **Dropped deliberately.** Each leg is already a workspace-wide denial of service on its own, so the composition adds no capability the report does not have; and proving it means driving the shared lab to memory exhaustion, which stages 14 to 16 depend on. Considered, not run. |
| Same-origin phishing with system authority (VULN-012, VULN-021, VULN-046) | **Replaced by CHAIN-006.** VULN-021 is FAILED (uploads do not render inline on this build), so the same-origin HTML host the candidate relied on does not exist. CHAIN-006 keeps the surviving half, the server's voice, and composes it with a stronger audience mechanism: VULN-058's self-made default room. |
| Pre-registered squat survives the owner's arrival (VULN-042, VULN-037) | **Considered, not built.** Both are CONFIRMED and the story is coherent, but the only thing the composition adds over VULN-037 alone is the lure's delivery, which is exactly what VULN-042 already proves (the workspace's own mail carrying attacker text to any address). The end state, a surviving personal access token inside the claimed account, is VULN-037's own proven effect, so the whole would not exceed the sum. |
| Deleted content stays recoverable (VULN-059, VULN-049, VULN-047) | **Proven as CHAIN-008**, with VULN-010 added as the timeline step so the chain starts outside the room. |
| A banned member keeps the room (VULN-009, VULN-035, VULN-003) | **Proven as CHAIN-007.** VULN-003's forged events were not needed; the re-entry is carried by two intended features instead (per-room notification preferences and public self-registration), which makes the point sharper. |
| A delegated Omnichannel role becomes the customer, then a standing export channel (VULN-077, VULN-081, VULN-051) | **Considered, not built.** CHAIN-003 already proves the customer-impersonation-and-transcript half from a strictly stronger position (unauthenticated, no agent role at all). What this candidate would add is VULN-081's standing export, which needs a second non-admin Omnichannel role (`livechat-manager`); it is a lower-value variant of the same pattern and was left out in favour of the chains above. A reproducer wanting it has both findings' own exploits. |

## Combinations considered beyond triage's list

- **VULN-057 raising `Message_MaxAllowedSize` to amplify the parser denial of
  service (VULN-026, VULN-045).** Real, and deliberately not run: the
  amplification is a severity increase of a denial of service the report already
  has, and proving it means stalling the shared lab for the later stages.
- **VULN-079 (private-room names by regular expression) feeding the room-id
  oracles (VULN-068's ban list, VULN-010's deletion timeline, VULN-071's E2E
  member list).** This would be a strong reconnaissance chain, and it has a real
  gap: every one of those routes needs a room **id**, and for a private group
  VULN-079 yields only the name (its match answers with an error code, not the
  room document). No proven step converts a private room's name into its id for a
  non-member, so the chain is left unbuilt rather than assumed. If an id oracle
  turns up, this composition is worth revisiting.
- **VULN-067 (a join code recovered by the sort oracle) into membership and the
  channel's history.** Already proven end to end inside that finding's own
  escalation record, so a chain would restate one finding rather than compose two.
- **VULN-019 (`/hooks` accepts any integration id and token) with VULN-061 (the
  integration type confusion).** Both end at "an integration posts where the
  attacker chooses"; neither extends the other's reach.
- **VULN-063 and VULN-078 (missing and mis-keyed rate limits) as enablers for
  CHAIN-002's code grind.** Not needed: no per-route limiter applies to
  `POST /api/v1/login` on this build, so the grind ran at full speed without
  them. Noted inside CHAIN-002 rather than claimed as a step.

Blue Spider, a product of Kohi Research Corporation (kohirc.com). Copyright 2026 Kohi Research Corporation. All rights reserved.
