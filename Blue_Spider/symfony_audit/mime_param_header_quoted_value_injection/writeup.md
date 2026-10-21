# VULN-002 — Mime `ParameterizedHeader` quoted param-value injection (attachment-filename spoofing)

| | |
|---|---|
| **Status** | CONFIRMED (component-level — rendered an attachment Content-Disposition with 3 `filename=` params; the `"` is written unescaped) |
| **Confidence** | 8/10 |
| **Severity** | Medium — CVSS 3.1 4.3 (`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N`) |
| **Component** | Mime (`ParameterizedHeader`) |
| **CWE** | CWE-93 / CWE-116 (improper neutralization of a value placed into a header parameter) |
| **Target commit** | e6df33ba170c94e68f907712798cdaa9aa10bc05 |

## Summary
Symfony's `ParameterizedHeader` renders Content-Type / Content-Disposition parameters (an
attachment's `filename` / `name`) by wrapping any non-token value in double quotes **without
backslash-escaping an embedded `"` or `\`**. An attacker who controls an attachment filename can
therefore embed a `"` that closes the quoted value early and inject an arbitrary second parameter
into the header — e.g. a second `filename=`. Receiving MUAs that honour the *last* `filename`
save the attachment under the spoofed name/extension. This is a sibling sink of CVE-2026-45070,
whose published fix escaped parameter *names* but not quoted parameter *values*; the gap is still
present at this commit.

## How it works (mechanism & code trace)
The rendering sink, `.../Mime/Header/ParameterizedHeader.php:175-180`:

```php
private function getEndOfParameterValue(string $value, bool $encoded = false, bool $firstLine = false): string
{
    $forceHttpQuoting = 'form-data' === $this->getValue() && 'content-disposition' === strtolower($this->getName());
    if ($forceHttpQuoting || !preg_match('/^'.self::TOKEN_REGEX.'$/D', $value)) {
        $value = '"'.$value.'"';          // :179  — wraps in DQUOTE, never escapes embedded " or \
    }
    ...
}
```

Source → sink for an email attachment:

1. `Email::attach($bytes, $filename)` builds `new DataPart($bytes, $filename)`
   (`.../Mime/Email.php:332-335`), which calls `setName($filename)` and
   `setDisposition('attachment')` (`.../Mime/Part/DataPart.php:40-44`).
2. `DataPart::getPreparedHeaders()` sets the `filename` parameter on `Content-Disposition`
   (`:97-98`) and, via the parent `TextPart`, the `name` parameter on both `Content-Type`
   (`TextPart.php:178-180`) and `Content-Disposition` (`:185-187`).
3. Each parameter is rendered by `ParameterizedHeader::createParameter()`. The value
   `safe.txt"; filename="evil.html` is printable ASCII, so the non-ASCII RFC-2231 encoding gate
   (`:120-125`) does not fire. The WHATWG quote-neutralising path (`:127-134`) **does** escape
   `"` → `%22`, but it is gated on `'form-data' === $this->getValue()` (`:127`) — an email
   attachment's disposition is `attachment`, so that path is skipped.
4. Control reaches `getEndOfParameterValue()` (`:167`), which wraps the value in `"..."` with no
   escaping (`:179`). The embedded `"` therefore survives verbatim and splits the parameter list.

Observed live rendering (unfolded), from `response.txt`:

```
Content-Disposition: attachment; name="safe.txt"; filename="evil.html"; filename="safe.txt"; filename="evil.html"
Content-Type: text/plain; name="safe.txt"; filename="evil.html"
```

The decisive contrast — the **same class** on a `form-data` disposition neutralises the quote:

```
Content-Disposition: form-data; filename="safe.txt%22; filename=%22evil.html"
```

So the component is perfectly capable of escaping; the `attachment`/`inline` and Content-Type
`name` paths are simply unprotected. (`AbstractHeader::createPhrase` likewise escapes display-name
quotes as `\"` at `:103-105,118-119`.)

## Why it is a vulnerability
RFC 2045/2231 `quoted-string` requires `"` and `\` inside the quotes to be backslash-escaped.
Emitting them raw lets attacker-controlled parameter text break out of its value and inject or
override sibling parameters on the same header. For an attachment, the practical primitive is a
duplicate `filename` (and `name`) — a classic Content-Disposition filename-spoofing ambiguity
(RFC 6266): the sender's UI shows `safe.txt`, but a recipient MUA that honours the last `filename`
saves `evil.html`. The attacker can also override other parameters (e.g. `charset`, or inject a
spurious `name`).

## Reproduction
```bash
cd claude_audit/symfony/exploits/VULN-002
NO_COLOR=1 ./run.sh 2>&1 | tee run.log
```
Expected (see `run.log`): the PoC prints the rendered `Content-Disposition` with **3** `filename=`
parameters, `CDISP_HAS_BACKSLASH_QUOTE::0` (not escaped), and the form-data contrast showing
`%22`. It prints `[OK] ... CONFIRMED` and exits 0.

**Proof line:** `Content-Disposition: attachment; name="safe.txt"; filename="evil.html"; filename="safe.txt"; filename="evil.html"` — the single attacker-supplied filename produced multiple `filename=` parameters, the injected `"` unescaped.

## Impact
MIME parameter injection on outbound mail: attachment extension/type spoofing (a benign `.pdf`
name shown, a `.html`/`.exe` saved) and arbitrary override/addition of parameters on the
Content-Type / Content-Disposition header. Recipient-side deception (malware delivery under a
trusted-looking name), hence `UI:R`; no server-side compromise. Medium (CVSS 4.3).

## Suggested fix
In `getEndOfParameterValue()` (`ParameterizedHeader.php:179`), escape before wrapping:

```php
if ($forceHttpQuoting || !preg_match('/^'.self::TOKEN_REGEX.'$/D', $value)) {
    $value = '"'.addcslashes($value, '"\\').'"';   // mirror AbstractHeader::createPhrase
}
```
Alternatively, force RFC-2231 extended encoding (`filename*=`) for any value containing `"` or
`\`, consistent with how non-ASCII values are already handled.

## References
- CVE-2026-45070 / GHSA-vqc8-7275-q272 (sibling fix — covered parameter *names*, not quoted values).
- RFC 2045 §5.1 / RFC 2231 (`quoted-string` requires escaping of `"` and `\`); RFC 6266 §4.3
  (`filename` duplicate / last-wins ambiguity).
- OWASP WSTG-INPV-16 (HTTP/header splitting & injection); OWASP output-encoding guidance.
- PortSwigger Web Security Academy — HTTP response header injection (quoted-value breakout).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `symfony.com/blog/category/security-advisories` pages 1–7 (all advisories back to Nov 2024) — Mime-related entries are CVE-2026-45070 (non-token characters in parameter *names*) and CVE-2026-45067 (CRLF in `Mime\Address`); nothing on `"`/`\` inside quoted parameter values or attachment-filename spoofing
2. `github.com/symfony/symfony/security/advisories?state=published` and `github.com/advisories?query=CVE-2026-45070` (GHSA-vqc8-7275-q272) — advisory text states parameter values are "validated and encoded" and that the issue "concerns names only"
3. Fix commit `e62ea217f8b4ca8ae922ad0f949e0c4dc1f9b613` for CVE-2026-45070 — diff only adds a `TOKEN_REGEX` check on parameter names in `setParameters()` plus tests; `getEndOfParameterValue()` and value quoting are untouched
4. Current `src/Symfony/Component/Mime/Header/ParameterizedHeader.php` on branch `7.4` — `getEndOfParameterValue()` still emits `'"'.$value.'"'` with no `addcslashes`/escaping; the `%22` replacement in `createParameter()` is gated on `form-data` Content-Disposition only, so `attachment`/`inline` and Content-Type `name` remain unescaped at head
5. symfony/symfony issue tracker query `ParameterizedHeader / filename quote / escape / mime attachment` — PR #65778 (control characters, Aug 2026, explicitly "double quote and backslash: not changed"), #63826 (Brevo non-string params crash), #44255 (array parameter values feature request, closed not planned), #36738 (HttpClient multipart form-data filename, 2020); none report the quoted-value breakout. (General web search quota was exhausted for this session, so verification relied on direct advisory, commit, source and issue-tracker fetches.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-45070 / GHSA-vqc8-7275-q272 — same class (`ParameterizedHeader`), but the sink is non-token bytes in parameter *names*; its fix does not escape `"`/`\` in quoted *values*
- CVE-2026-45067 — CRLF header/SMTP injection via `Mime\Address`; different class and character set
- symfony/symfony PR #65778 (2026-08-31) — encodes raw control characters (`\x00-\x1F\x7F`) in headers/parameters; explicitly leaves double quote and backslash handling unchanged
- symfony/symfony issue #36738 (2020) — HttpClient multipart `form-data` filename handling, which is why only the `form-data` path percent-encodes `"` today
- PHPMailer CVE-2020-13625 — the same bug pattern (unescaped `"` in an attachment filename lets the file type be misrepresented) in a different library; not a Symfony disclosure

**Reasoning:** Every public Symfony Mime disclosure addresses parameter names, CRLF, or raw control characters, and the CVE-2026-45070 advisory explicitly asserts that values are already safe, which indicates the maintainers have not recognised the unescaped `"`/`\` in quoted `attachment`/`inline`/Content-Type `name` values; the head of the 7.4 branch still contains the unescaped concatenation. Caveats: the Mime component was heavily audited in 2026 and a private report to security@symfony.com may be pending, and Symfony could classify filename-parameter spoofing as low-impact hardening rather than a vulnerability.
