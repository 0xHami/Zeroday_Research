# VULN-002 — Mime `ParameterizedHeader` quoted param-value injection (attachment-filename spoofing)

**Software**: Symfony (the Symfony PHP framework)
**Repository**: https://github.com/symfony/symfony
**Affected version**: 8.2.x-dev — commit-pinned, no tagged release (branch `8.2`)
**Status**: CONFIRMED (component-level — rendered an attachment Content-Disposition with 3 `filename=` params; the `"` is written unescaped; same class escapes `"`→`%22` on a form-data disposition)
**Severity (static)**: Medium (CVSS 3.1 4.3 — `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N`)
**Confidence**: 8/10
**Confidence reasoning**: Deterministic byte-level header injection, verified live against the shipped code; it is a real spec violation and a sibling sink of CVE-2026-45070 still live at this commit. Capped below 9 because practical harm is recipient-side deception (UI:R) and depends on the MUA honouring the last duplicate `filename`.
**Target commit**: e6df33ba170c94e68f907712798cdaa9aa10bc05
**Validated at**: 2026-10-02T21:41:55Z

## Preconditions
- An application that places attacker-influenced text into an attachment filename (or any
  Content-* parameter value) on outbound mail — e.g. "we email you back your uploaded file under
  its original name", receipts, report exports. Unauthenticated if that mail feature is public.
- No special flag; this is the default rendering of `Email::attach($bytes, $filename)`.
- A recipient MUA that honours the *last* of duplicate `filename` parameters (common).

## Request
Component-level PoC (symfony/mime is a library; there is no HTTP route, and the lab has no
`egulias/email-validator`, so `Email`/`Address` cannot be instantiated). We exercise the exact
same sink via `DataPart` — the object `Email::attach()` builds internally — and render its
prepared headers. Full invocation + PHP source in `request.http`. Core:

```php
$payload = 'safe.txt"; filename="evil.html';
$part = new DataPart('ATTACHMENT-BYTES', $payload, 'text/plain');   // == Email::attach() internals
echo $part->getPreparedHeaders()->toString();
```

## Response
From `response.txt` (unfolded logical headers):

```
Content-Disposition: attachment; name="safe.txt"; filename="evil.html"; filename="safe.txt"; filename="evil.html"
Content-Type: text/plain; name="safe.txt"; filename="evil.html"
```
`filename=` appears 3 times; the injected `filename="evil.html"` is present verbatim with the
`"` **unescaped** (`CDISP_HAS_BACKSLASH_QUOTE::0`).

Contrast (same `ParameterizedHeader` class, `form-data` disposition):
```
Content-Disposition: form-data; filename="safe.txt%22; filename=%22evil.html"
```
Here the `"` is neutralised to `%22` (`FORMDATA_PCT22::1`, `FORMDATA_INJECTED::0`).

## Observation
`ParameterizedHeader::getEndOfParameterValue()` (`.../Mime/Header/ParameterizedHeader.php:177-180`)
wraps a non-token value in double quotes with no escaping:

```php
if ($forceHttpQuoting || !preg_match('/^'.self::TOKEN_REGEX.'$/D', $value)) {
    $value = '"'.$value.'"';   // :179  — never addcslashes($value, '"\\')
}
```
A `"` (0x22) is printable ASCII, so the RFC-2231 encoding gate (`:120`) never fires for it. The
only path that neutralises `"` is the WHATWG one at `:127-134`, gated on
`'form-data' === $this->getValue()` — i.e. multipart form-data field/file names, **not** an email
attachment whose disposition is `attachment`. So the attacker-controlled filename reaches the
unescaped quote-wrap and injects a second `filename=` parameter. The same class demonstrably
*can* escape (the form-data `%22` path), and `AbstractHeader::createPhrase` escapes display-name
quotes as `\"` (`:103-105,118-119`) — so this is an internal inconsistency, not a deliberate policy.

Both legs ran against the shipped source. The injection is CONFIRMED. (Pure intra-header parameter
injection — a CRLF in the filename is percent-encoded/folded, so this is not CRLF header
splitting; impact is confined to parameter spoofing/override on that one header.)

## Side effects
None. Read-only header rendering; no mail is actually sent, no state written.

## Research & references
- **CVE-2026-45070 / GHSA-vqc8-7275-q272** — the sibling fix that rejected non-token parameter
  *names* but did not escape quoted *values*; this quoted-value sink is the uncovered leg.
- **OWASP WSTG-INPV-16 (HTTP/Header Splitting)** and the **OWASP Secure Headers / output-encoding**
  guidance — a value placed inside a quoted-string must have `"`/`\` escaped (RFC 2045/2231
  `quoted-string` ABNF requires `\"`, `\\`).
- **PortSwigger — "HTTP response header injection"** background on quoted-parameter breakout
  (the Content-Disposition `filename` duplicate-parameter / RFC 6266 last-wins ambiguity used here).
- **RFC 6266 §4.3 / RFC 2183** — `filename` vs `filename*`; MUAs differ on which duplicate wins,
  which is what makes the injected second `filename` a spoofing primitive.

## Fix (for the report)
In `getEndOfParameterValue()`, escape before wrapping:
`$value = '"'.addcslashes($value, '"\\').'"';` (mirrors `AbstractHeader::createPhrase`), or force
RFC-2231 `filename*=` extended encoding for any value containing `"` or `\`.
