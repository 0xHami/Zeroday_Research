# VULN-004 — vCard.php cross-user PII export via ACL-less loadContact() (IDOR)

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:39Z

## Preconditions
- Admin creates victim **V** and attacker **A** (fresh, unrelated low-priv users).
- As **V**: `module=Contacts&action=Save` creates a Contact with a unique `last_name` and a unique `phone_work` marker, owned by V.

## Request
See `request.http`:
```
GET /index.php?entryPoint=vCard&module=Contacts&contact_id=<victim_contact_id> HTTP/1.1
Cookie: PHPSESSID=<attacker session>
```

## Response
See `response.txt`. HTTP 200, `Content-Type: text/x-vcard; charset=UTF-8`, body:
```
BEGIN:VCARD
N;CHARSET=utf-8:V004Contact_ad3551c8;Victim004;;
FN;CHARSET=utf-8: Victim004 V004Contact_ad3551c8
...
TEL;WORK;CHARSET=utf-8:555-e5aa4d
...
END:VCARD
```
Both the victim's unique `last_name` and `phone_work` marker are present, proving the export read the real, victim-owned bean (not just echoing the requested id).

## Observation
Matches the static finding exactly: `vCard.php:54-60` passes `$_REQUEST['contact_id']` straight to `include/vCard.php:60-66` `loadContact()`, which does `$contact->retrieve($contactid)` with no `ACLAccess()` call anywhere in the method, then serializes name/birthdate/phones/email/address/org into the vCard body (`include/vCard.php:76-89`). The only input filtering present, `clean_string($_REQUEST['module'])` on the `module` parameter, constrains which bean class can be instantiated (preventing arbitrary-class abuse) but performs no authorization check whatsoever — confirmed dynamically: the export succeeded immediately, with no denial page, redirect, or missing-field degradation.

## Side effects
None destructive. One Contact and two low-priv Users created (random-suffixed, harmless).

## Research & references
- CWE-639 — Authorization Bypass Through User-Controlled Key.
- OWASP WSTG-ATHZ-04 — Testing for Insecure Direct Object References.
- Relevant regulatory framing: this is a GDPR/PII-class confidentiality breach (name, phone, and — for contacts with more fields populated — birthdate/email/postal address) reachable by any authenticated low-privilege account.

## If FAILED
N/A — CONFIRMED.
