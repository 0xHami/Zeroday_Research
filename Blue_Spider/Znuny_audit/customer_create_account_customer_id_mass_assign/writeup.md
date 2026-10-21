# VULN-018 — `CustomerCreateAccount` mass-assigns `UserCustomerID` (self-registration on by default)

| | |
|---|---|
| **ID** | VULN-018 (raw ZN-043) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium · CVSS 3.1 **5.3** — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** · **Auth**: none (unauthenticated self-registration) |
| **Attacker gains** | Chooses their own `CustomerID` at registration — company-scope / identity spoofing. |

## Summary
The customer self-registration handler binds the **entire** configurable `CustomerUser` field map
from request parameters instead of a fixed safe set, and only *defaults* `UserCustomerID` when it
is absent. An unauthenticated registrant can therefore set their `CustomerID` to an arbitrary
value (e.g. a target company). Self-registration is enabled by default. Confirmed: an unauth POST
created a customer whose `customer_id` was the attacker-chosen `VictimCorp-<sfx>`.

## How it works (mechanism & code trace)
Entry — `POST customer.pl?Action=CustomerCreateAccount;Subaction=CreateAccount`.
`Kernel/System/Web/InterfaceCustomer.pm`:
```perl
917:  for my $Entry ( @{ $ConfigObject->Get('CustomerUser')->{Map} } ) {   # the WHOLE map
918:      $GetParams{ $Entry->[0] } = $ParamObject->GetParam( Param => $Entry->[0] ) || '';
      ...
927:  # UserCustomerID is only DEFAULTED to the email if not provided:
929:  $GetParams{UserCustomerID} ||= $GetParams{UserEmail};
1032: my $Add = $CustomerUserObject->CustomerUserAdd( %GetParams, ... );
```
Because the loop reads every map field from the request, `UserCustomerID` (and `UserLogin`) are
attacker-controllable; the `||=` at `:929` only fills a *missing* value, so a supplied one wins.
`CustomerPanelCreateAccount` ships `1` (enabled) in `Framework.xml`, making this reachable
unauthenticated. Dynamic proof: `customer_user.customer_id = 'VictimCorp-<sfx>'`.

## Why it is a vulnerability
`CustomerID` is an authorization-relevant attribute: many deployments grant visibility of a
company's tickets to customer users sharing that `CustomerID` (company tickets). Letting an
anonymous registrant pick it is a mass-assignment/BOLA-adjacent flaw — they can join a target
company's scope, or impersonate an identity, purely by choosing the field. Even where CustomerID
isn't used for company scoping, it is a data-integrity/spoofing issue. The safe design binds only
an allowlisted set of self-service fields and derives `CustomerID` server-side. There is also no
CAPTCHA/creation rate-limit (account spam).

## Reproduction
`./run.sh` sends one unauthenticated `CustomerCreateAccount` POST with
`UserCustomerID=VictimCorp-<sfx>` and shows the created `customer_user` row carries that CustomerID.

## Impact
Unauthenticated identity/company-scope spoofing at registration; where CustomerID gates company
ticket visibility, the attacker inherits that company's ticket access. Plus unauthenticated
account creation with no rate limit.

## Suggested fix
On self-registration, bind only an explicit allowlist of safe fields
(`UserFirstname/UserLastname/UserEmail`), derive `UserLogin`/`UserCustomerID` server-side (e.g.
from the verified email), and add a CAPTCHA + per-IP creation rate limit.

## References
- OWASP Mass Assignment Cheat Sheet; OWASP API Security API3:2023 (BOPLA). CWE-915.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. NVD API keyword pull for "Znuny" (17) and "OTRS" (120) grepped for register / CustomerID / customer user — CVE-2023-5421 (CustomerID XSS by a privileged user), CVE-2026-78359 (customer-user uniqueness across backends, requires privileges), CVE-2025-24391 (external-interface account enumeration); none concerns self-registration mass assignment
2. Znuny advisory index ZSA-2021-01 … ZSA-2026-16, GitHub advisory DB (19 entries), Debian tracker reviewed — no CustomerCreateAccount advisory
3. `gh search issues --repo znuny/Znuny "CreateAccount"` / `"CustomerCreateAccount CustomerID"` — no results
4. Earlier web search `OTRS Znuny follow-up email ... unauthenticated ...` surfaced CVE-2026-78359 only, which explicitly states it "does not allow unauthenticated users to create customer accounts"
5. (Shared WebSearch budget was exhausted before this finding; evidence below comes from direct primary-source pulls: NVD CVE API, vendor advisory pages, GitHub advisory DB, Debian tracker, GitHub issue search.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-78359 — OTRS customer-user identity uniqueness across backends; requires customer-admin privileges, not the self-registration path
- CVE-2023-5421 / OSA-2023-06 — CustomerID field XSS by a user who may edit customer data; different class and actor
- CVE-2025-24391 — OTRS external interface user enumeration; adjacent unauthenticated surface, different defect

**Reasoning:** No public disclosure describes `CustomerCreateAccount` binding the whole `CustomerUser` map from request parameters so that an anonymous registrant chooses `UserCustomerID` (and `UserLogin`). The code is inherited from OTRS CE 6 and self-registration is a long-standing feature, so community discussion of the behaviour may exist outside advisory channels and the vendor may treat CustomerID scoping as deployment-specific; confidence is therefore not above 70.
