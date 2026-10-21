# VULN-008 — `trustProxies(at: '*')` → client-controlled `request()->ip()`: bypassable rate limiting + audit-log poisoning

| | |
|---|---|
| **ID** | VULN-008 |
| **Severity** | Medium |
| **CVSS 3.1** | 5.3 — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Affected commit** | `a6518355c3a30818044c46a9fc7fd53da34ab7f7` |
| **Auth required** | None (unauthenticated) |
| **Attacker gains** | Defeats IP-keyed rate limiting (unbounded brute-force / registration flooding) and forges the source IP recorded in logs, activitylog and Sentry |

## Summary

The application trusts every proxy (`bootstrap/app.php:16`,
`$middleware->trustProxies(at: '*')`) even though FrankenPHP terminates client
connections directly with no fronting reverse proxy. Consequently Laravel resolves
`request()->ip()` from the client-supplied `X-Forwarded-For` header. Two concrete
consequences follow and both were demonstrated live: (1) the Filament login throttle,
whose 5-attempt bucket is keyed on `request()->ip()`, is completely bypassed by
rotating the header per request; and (2) the source IP recorded for audit purposes is
whatever the attacker puts in the header.

## How it works (mechanism & code trace)

**Root cause** — `targets/academico/bootstrap/app.php:16`:

```php
$middleware->trustProxies(at: '*');   // trust ALL proxies
```

With all proxies trusted, Symfony's `Request::getClientIp()` (and thus Laravel's
`request()->ip()`) returns the left-most entry of `X-Forwarded-For`. That header is
sent by the client, and the shipped `docker/Caddyfile` never strips or overwrites it,
so it is pure attacker input.

**Consumer 1 — the login throttle** (`targets/academico/app/Filament/Auth/Login.php:18-24`):

```php
public function authenticate(): ?LoginResponse
{
    try {
        $this->rateLimit(5);
    } catch (TooManyRequestsException $exception) {
        $this->getRateLimitedNotification($exception)?->send();
        return null;                       // <- no credential check when throttled
    }
    ...
}
```

`rateLimit()` (the `DanHarrin\LivewireRateLimiting` trait) builds its cache key from
`static::class | method | request()->ip()`. Because the IP component is the
attacker-controlled header, a fresh header value = a fresh, empty bucket.

**Consumer 2 — the registration limiter**
(`targets/academico/app/Livewire/RegistrationWizard.php:163`):

```php
$key = 'registration:'.request()->ip();
if (RateLimiter::tooManyAttempts($key, 5)) { ...; return; }
```

Same defect: the key embeds the forgeable IP.

**Audit trail** — every place that logs `request()->ip()` (Laravel logs,
`spatie/laravel-activitylog`, Sentry) records the attacker's chosen value.

## Why it is a vulnerability (reasoning)

The trust boundary crossed is "what the network says the client is" vs. "what the app
records and rate-limits on." A trusted-proxy list exists precisely to distinguish a
*legitimate* forwarded header (set by your own load balancer) from a *forged* one (set
by a malicious client). `'*'` erases that distinction: with no real proxy in front, the
only entity setting `X-Forwarded-For` is the client, so the app is accepting the
client's self-declared IP as ground truth. That breaks two security invariants at once:
rate-limit counters are supposed to be keyed on something the attacker cannot rotate at
will, and audit logs are supposed to attribute actions to the real origin. Both are now
attacker-controlled, which is by definition not the intended behavior.

Per triage policy, *missing* rate limiting alone is not reported; this finding is
retained for the audit-log-integrity impact and because it is the shared root cause with
[VULN-002] (the same `trustProxies('*')` makes `X-Forwarded-Host` attacker-controlled,
enabling the password-reset ATO).

## Reproduction

1. Target up at `http://localhost:20000`.
2. Run `./run.sh`. It sends failed logins against a random nonexistent account:
   - **Phase A** — 8 attempts, all with one fixed `X-Forwarded-For`.
   - **Phase B** — 8 attempts, each with a different `X-Forwarded-For`.
3. Expected output (`run.log`, this run):
   ```
   Phase A (fixed XFF 203.0.113.165):  attempts 1-5 CREDS, attempts 6-8 THROTTLED   (limiter works)
   Phase B (rotating XFF):             0/8 throttled                                 (limiter bypassed)
   tinker: resolved_ip=203.0.113.77    (request()->ip() == left-most X-Forwarded-For)
   ```
   Verdict: `CONFIRMED`. Full capture in `response.txt` / `run.log`.

Non-destructive: only failed logins against a nonexistent email; the throttle is per-IP,
so no real account is locked and nothing is persisted.

## Impact

- **Rate-limit bypass:** unbounded credential brute-force against the admin panel login
  and unbounded abuse of public registration (amplifying [VULN-007] and [VULN-010]).
- **Audit-log poisoning:** every recorded source IP is forgeable, so incident response /
  attribution against logs, activitylog, and Sentry is unreliable — an attacker can frame
  an arbitrary IP for their actions.
- **Enabler for [VULN-002]:** the identical setting makes `X-Forwarded-Host` trusted,
  which is the mechanism of the password-reset account takeover.

Pre-auth, network-exploitable, whole-instance scope.

## Suggested fix

`targets/academico/bootstrap/app.php:16` — do not trust arbitrary proxies. Since
FrankenPHP faces clients directly here:

```php
$middleware->trustProxies(at: null);   // app terminates connections; ignore forwarded headers
```

or, if a known proxy is later placed in front, trust only its IP/CIDR:
`$middleware->trustProxies(at: ['10.0.0.0/8'], headers: Request::HEADER_X_FORWARDED_FOR | Request::HEADER_X_FORWARDED_HOST | ...)`.
Principle: an allowlist of trusted proxy addresses, never `'*'`. This single change also
closes [VULN-002].

## References

- Laravel — *Configuring Trusted Proxies* (Illuminate `TrustProxies`): never trust `*`
  unless every hop is your own infrastructure that overwrites the forwarded headers.
- OWASP WSTG — **WSTG-ATHN-04** (testing for anti-automation / rate limiting) and
  IP-spoofing via `X-Forwarded-For`. <https://owasp.org/www-project-web-security-testing-guide/>
- OWASP Cheat Sheet — *Logging*: log a trustworthy source identity, not a client-supplied one.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory Database query `academico`, NVD API `keywordSearch=academico`, OSV query `academico`, huntr repo page — only CVE-2025-10763 (`/edit-photo` upload); nothing on trusted proxies, IP spoofing or rate limiting.
2. academico-sis/academico published advisories + issue/PR search `security` + `main` commit log through 2026-10-21 — no change to proxy trust; `bootstrap/app.php` history: `6b71126` "trust proxies for traefik deployment" (Mar 2026) introduced `trustProxies(at: '*')`, unchanged since, and current `main` still has it with no `trustHosts`.
3. GitHub Advisory Database query `filament` (33 advisories by title) — nothing on login rate limiting keyed on `request()->ip()`.
4. Sibling compared: Coolify CVE-2026-34198 / GHSA-cgj8-7m5q-x5gv — same trust-all-proxies root cause, but its disclosed impact is reset-link poisoning, not rate-limit bypass or log poisoning in academico.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-34198 / GHSA-cgj8-7m5q-x5gv (Coolify) — the same `trustProxies('*')` misconfiguration in another Laravel app, disclosed for its password-reset consequence.
- academico commit efcd183 (Apr 2026, "improve security") — added the IP-keyed registration rate limiter that this finding bypasses; not a disclosure.
- Laravel "Configuring Trusted Proxies" documentation — generic guidance against trusting `*` with no fronting proxy.

**Reasoning:** No public disclosure covers academico's trust-all-proxies setting or its rate-limit-bypass / audit-log-poisoning consequences. This is a well-documented Laravel misconfiguration class and shares its root cause with the password-reset finding (fixing one fixes both); maintainers may regard rate-limit bypass alone as hardening rather than a vulnerability, so the score is moderate. All academico checks were direct GHSA/NVD/OSV/repository queries because the web-search quota was exhausted earlier in this triage.
