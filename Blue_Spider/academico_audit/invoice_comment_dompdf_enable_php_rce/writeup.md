# VULN-001 — Stored invoice comment → dompdf `enable_php` → server-side RCE

| | |
|---|---|
| **ID** | VULN-001 |
| **Severity** | Critical |
| **CVSS 3.1** | 9.0 — `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H` (unattended `BuildInvoicesZip` render → `UI:N` → 9.9) |
| **Status** | **CONFIRMED (dynamic)** |
| **Affected commit** | `a6518355c3a30818044c46a9fc7fd53da34ab7f7` |
| **Auth required** | Inject: **secretary** (`enrollments.edit`). Trigger: **admin** downloads the PDF (routine). |
| **Attacker gains** | Arbitrary OS command execution on the application server (observed as **root** in-container) |

## Summary

The invoice-PDF pipeline renders an HTML document with dompdf configured to **execute
embedded PHP** (`enable_php = true`). The only invoice field emitted through Blade *raw*
output (`{!! !!}`) is `notes`, and `InvoiceService::download()` builds `notes` by
concatenating stored `Comment` bodies. Those comment bodies are written at checkout from the
client-controlled `data.invoice_comment` by any `enrollments.edit` holder (a secretary). So a
secretary can store `<script type="text/php"> system('id > …'); </script>` as an invoice
comment; when an admin later downloads that invoice's PDF, dompdf executes the PHP and the
attacker's OS command runs as the web-server user. Proven live end-to-end: after an admin
invoked the `download_pdf` action over HTTP, a marker file on the server contained the output
of `id` — `uid=0(root) gid=0(root)` — i.e. arbitrary command execution as root.

## How it works (mechanism & code trace)

This is a four-part chain: a dangerous renderer default, a raw output sink, a store→consume
bridge, and a low-priv injection point crossed by an admin trigger.

**1. Dangerous renderer default** — `targets/academico/config/invoices.php:105-113`:

```php
'dompdf_options' => [
    'enable_php' => true,          // dompdf executes <script type="text/php">
    'logOutputFile' => '',
],
```

Verified at runtime: `config('invoices.dompdf_options.enable_php') === true`. dompdf's
`<script type="text/php">…</script>` tag is a documented code-execution feature that fires
only when `isPhpEnabled` is set — which this config does.

**2. The raw sink** — the vendored template
`vendor/laraveldaily/laravel-invoices/resources/views/templates/default.blade.php:363` prints:

```blade
{!! $invoice->notes !!}      {{-- every other field there is {{ }}-escaped --}}
```

`{!! !!}` is Blade *unescaped* output, so whatever is in `notes` reaches dompdf as literal
HTML (including a `<script type="text/php">` tag).

**3. The store→consume bridge** — `targets/academico/app/Services/InvoiceService.php:30-36,50`:

```php
$notes = [$invoice->invoiceType->notes];
foreach ($invoice->comments as $comment) {
    $notes[] = $comment->body;                 // stored, user-influenced, raw
}
$notes = implode('<br><br>', $notes);
...
    ->notes($notes ?? '');
```

The invoice's `notes` are assembled from the invoice-type notes plus **every stored comment
body**, with no escaping.

**4. The injection point (low-priv)** — `targets/academico/app/Filament/Pages/CheckoutPage.php:663-670`:

```php
if (! empty($data['invoice_comment'])) {
    Comment::create([
        'body' => $data['invoice_comment'],    // $data client-controlled Livewire array
        'commentable_id' => $invoice->id,
        'commentable_type' => Invoice::class,
        'author_id' => Auth::id(),
    ]);
}
```

`CheckoutPage::canAccess()` requires only `enrollments.edit`, held by the secretary. The
`->maxLength(500)` on the form field is a client-side cap; 500 chars is ample for a payload.

**5. The trigger (admin)** — `targets/academico/app/Filament/Resources/Invoices/InvoiceResource.php:41-44,226-234`
and `ViewInvoice.php:83-93`:

```php
public static function canAccess(): bool { return auth()->user()?->hasRole('admin') ?? false; }
...
Action::make('download_pdf')->action(function () {
    $service = app(InvoiceService::class);
    return response()->streamDownload(function () use ($service, $record) {
        echo $service->download($record)->stream()->getContent();   // dompdf render -> PHP executes
    }, ...);
});
```

`->stream()` (laravel-invoices → barryvdh/laravel-dompdf) applies `config('invoices.dompdf_options')`
including `enable_php`, then renders — executing the embedded PHP.

**Why nothing saves it.** There is no HTML sanitization between the stored comment and the
renderer; `notes` is the single raw field; and dompdf is explicitly told to run PHP. The
`maxLength(500)` is client-side only.

## Why it is a vulnerability (reasoning)

Two trust boundaries are crossed. **Application → OS:** dompdf executes arbitrary PHP as the
server process (observed as root), escaping the web-app sandbox entirely (`S:C`, and code
execution rather than mere data disclosure). **Secretary → admin:** a low-privilege role
plants a payload that runs under admin-triggered rendering. The application's implicit trust
assumption — "stored invoice comments are inert display text" — is false, because the renderer
is configured to treat them as executable. The intended capability of an invoice comment is to
annotate an invoice; the actual capability is to run code on the server. The only "user
interaction" element is that an admin performs the routine act of downloading the invoice PDF
(and the queued `BuildInvoicesZip` job renders invoices with no human at all, removing even
that). This is unambiguously unintended: the legitimate in-template PHP use (page numbering) is
also available via dompdf's `{PAGE_NUM}`/`{PAGE_COUNT}` placeholders, so `enable_php` is not
required for any feature here.

## Reproduction

1. Target up at `http://localhost:20000` (shipped `config/invoices.php`; `enable_php=true`).
2. Run `./run.sh`. It:
   - creates a secretary and stores an invoice `Comment` whose body is
     `<script type="text/php"> system('id > /tmp/pwn_<rnd> 2>&1'); </script>` (the exact value
     `CheckoutPage::submit()` writes from `data.invoice_comment`);
   - logs in as admin and invokes the `download_pdf` action over HTTP (`mountAction` →
     `callMountedAction`);
   - reads the marker file from inside the container.
3. Expected output (`run.log`, this run):
   ```
   marker /tmp/pwn_2099405b before trigger: <absent>
   download_pdf action HTTP 200 (download effect: yes)
   the marker file now contains the output of `id`: "uid=0(root) gid=0(root) groups=0(root)"
   ```
   Verdict: `CONFIRMED`. Decisive requests are in `request.http`; full capture in
   `response.txt` / `run.log`.

**Manual UI path:** as a secretary, open `/admin/checkout-page?enrollment_id=<id>`, put the
payload in the *Invoice comment* field, submit; as admin, open **Invoices → (that invoice) →
Download PDF**.

## Impact

Full remote code execution on the application server, observed running as **root** inside the
container: read `.env`/`APP_KEY`, dump the MariaDB database (all student PII + financials),
write/modify files, install persistence, and pivot to the host or other containers on the
Docker network. It is a superset of SSRF/LFI. It also completes the highest-impact attack
chain in this report: [VULN-002] (unauthenticated password-reset poisoning) takes over an
admin account, and that admin then triggers this RCE by downloading a poisoned invoice PDF —
turning an unauthenticated foothold into root code execution. [VULN-003] additionally lets a
low-priv user poison the `Fee`/`Tax` reference data that flows onto the invoices this rides on,
and [VULN-008] forges the source IP recorded against the malicious checkout.

## Suggested fix

`targets/academico/config/invoices.php:105-113` — disable PHP in the renderer (one line):

```php
'dompdf_options' => [
    'enable_php' => false,      // remove the code-execution primitive; use {PAGE_NUM}/{PAGE_COUNT} for paging
    'logOutputFile' => '',
],
```

Defense in depth: escape `notes` in the template (`{{ }}` instead of `{!! !!}`), or run
comment bodies through `strip_tags()`/an HTML sanitizer before they reach `notes`, and treat
`data.invoice_comment` as untrusted. Principle: never enable a template engine's
code-execution feature, and never emit stored user-influenced data as raw HTML into a renderer.

## References

- **dompdf inline PHP execution** — `<script type="text/php">` runs when `isPhpEnabled` is
  true (documented dompdf behavior); see dompdf security notes and public write-ups on
  "dompdf enable_php RCE".
- OWASP Top 10 2021 — **A03:2021 Injection** (Code Injection, CWE-94) and second-order/stored
  injection. <https://owasp.org/Top10/A03_2021-Injection/>
- OWASP WSTG — **WSTG-INPV-11** (Testing for Code Injection). laravel-invoices default dompdf
  options (`enable_php=true`) + raw `{!! notes !!}` in `templates/default.blade.php`.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory Database query `academico` — 2 results: GHSA-52xw-7w25-5w5q / CVE-2025-10763 (`/edit-photo` unrestricted upload) and an unrelated SWA.JACAD SQLi; nothing on invoices, dompdf or comments.
2. NVD API `keywordSearch=academico` — 1 result (CVE-2025-10763, profile-picture upload); OSV query `academico` — no results; huntr repo page — none.
3. academico-sis/academico published advisories — only GHSA-w76j-4qgr-3r9f (resource write permissions) and GHSA-x47v-xg6f-42xj (grade-page IDOR), both 2026-10-19; neither concerns the invoice PDF pipeline.
4. Repository issue/PR search `security` (first page of 120) and `main` commit log through 2026-10-21 — no invoice/dompdf/`enable_php` change; `config/invoices.php` and `app/Services/InvoiceService.php` histories contain no security commit; current `main` still has `'enable_php' => true`.
5. GitHub Advisory Database queries `laravel-invoices` and `dompdf enable_php` — no advisory for laraveldaily/laravel-invoices or for dompdf's `enable_php` option; LaravelDaily/laravel-invoices tracker query `enable_php` — only config/logging issues (#186, #127, #254), none about PHP execution or the raw `notes` sink.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2025-10763 / GHSA-52xw-7w25-5w5q — academico `/edit-photo` unrestricted upload; different component.
- GHSA-w76j-4qgr-3r9f, GHSA-x47v-xg6f-42xj (academico, 2026-10-19) — authorization issues in resources and grade pages; unrelated components.
- dompdf's documented `isPhpEnabled` / `<script type="text/php">` behaviour and laravel-invoices' default `enable_php => true` with raw `{!! $invoice->notes !!}` — generic dependency-level footguns with no advisory; the secretary-stored comment → `notes` → admin PDF render chain in academico is not described anywhere public.

**Reasoning:** No advisory, CVE, issue or fix covers a stored invoice comment reaching dompdf with PHP execution enabled in academico, and the sink is unchanged on `main` as of 2026-10-21. The underlying footgun is widely documented and the project has recently received several private security reports (kta1kri, tonghuaroot, M4ru-0x03), so rediscovery or an in-flight private report is plausible, hence a moderate score. All academico checks were direct GHSA/NVD/OSV/repository queries because the web-search quota was exhausted earlier in this triage.
