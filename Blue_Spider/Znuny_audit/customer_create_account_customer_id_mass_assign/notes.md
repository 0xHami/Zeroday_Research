# VULN-018 — CustomerCreateAccount mass-assigns UserCustomerID (self-registration on by default)

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (5.3)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
None — `CustomerPanelCreateAccount` ships enabled; the request is fully unauthenticated.

## Request / Response
`POST /znuny/customer.pl Action=CustomerCreateAccount;Subaction=CreateAccount;UserFirstname=…;
UserLastname=…;UserEmail=attacker_<sfx>@example.test;UserCustomerID=VictimCorp-<sfx>` → a
`customer_user` row is created with `customer_id='VictimCorp-<sfx>'` (attacker-chosen). See
`response.txt`.

## Observation
Confirms `InterfaceCustomer.pm:917-929` binds the whole configurable CustomerUser Map from request
params and only defaults `UserCustomerID` to the email when absent — so a supplied value is kept.

## Side effects
Creates one customer account (unique email). Cleanable; idempotent per-run (random suffix).

## Research & references
- OWASP Mass Assignment Cheat Sheet; API6:2019 / API3:2023. CWE-915. No CAPTCHA/creation
  rate-limit (account spam).

## Notes
Impact depends on deployment: where company-ticket access is keyed on CustomerID, the self-
registrant inherits that company's ticket visibility; otherwise it is identity/data-integrity
spoofing. Correction from prior stages: self-registration is ON by default (Framework.xml).
