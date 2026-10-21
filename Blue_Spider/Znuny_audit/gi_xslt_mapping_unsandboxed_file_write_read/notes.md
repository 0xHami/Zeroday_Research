# VULN-025 — GenericInterface XSLT mapping unsandboxed → file R/W (+ build-dependent SSRF)

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (6.5)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- Admin able to author/import a GenericInterface web service with an XSLT mapping (trusted actor).
  Exercised here via Znuny's own `Mapping::XSLT->Map` with a malicious stylesheet.

## Request / Response
Malicious XSLT `Template` (see `request.http`) with `<exsl:document href="/tmp/xslt_write_<sfx>.txt"
method="text">PWNED-XSLT-<sfx></exsl:document>` and `document('file://…')`. After `Map`:
`/tmp/xslt_write_<sfx>.txt` contains `PWNED-XSLT-<sfx>` on the host FS. See `response.txt`.

## Observation
Confirms `XSLT.pm:167` instantiates `XML::LibXSLT->new()` with **no** `security_callbacks`, and
`:180-184` `load_xml` with no `no_network`/`expand_entities(0)`. The `exsl:document` EXSLT
extension performed an arbitrary host file **write**; `document('/etc/passwd')` (tested separately)
opened the file (libxml parser error on the non-XML content proves the read reached the file) —
arbitrary file **read** reachability.

## Side effects
Writes `/tmp/xslt_write_<sfx>.txt` inside the app container. Harmless marker; idempotent.

## Research & references
- OWASP XXE Prevention / "XSLT injection"; libxslt `document()` + EXSLT `exsl:document` security
  notes. CWE-611 / CWE-73. Net-based `document('http://…')` is blocked on this libxml2 2.9.14 build
  (no nanohttp) — file R/W is not.

## Scope / RCE
The arbitrary file write is an RCE path: write a `.pm` into an `@INC`/require-reachable location, a
cron file, or a webshell. Admin-authored (trusted), but it crosses to host file R/W (S:C).
