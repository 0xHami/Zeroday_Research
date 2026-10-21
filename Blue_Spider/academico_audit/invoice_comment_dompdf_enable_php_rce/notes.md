# VULN-001 — Stored invoice comment → dompdf enable_php → server-side RCE

**Target name:** academico
**Target URL:** https://github.com/academico-sis/academico
**Software version:** untagged, commit a6518355 (2026-05-31)
**Status**: CONFIRMED
**Severity (static)**: Critical (CVSS 9.0)
**Target commit**: a6518355c3a30818044c46a9fc7fd53da34ab7f7
**Validated at**: 2026-09-25

## Preconditions
- Injection: a **secretary** (any `enrollments.edit` holder) stores an invoice comment at
  checkout. The exploit seeds this stored `Comment` (author_id = a real secretary account it
  creates), representing what `CheckoutPage::submit()` writes from client-controlled
  `data.invoice_comment` (`CheckoutPage.php:663-670`).
- Trigger: an **admin** (`hasRole('admin')`) downloads the invoice PDF — done here over real
  HTTP via the `download_pdf` action.
- Config `config/invoices.php` as shipped: `dompdf_options.enable_php = true` (verified at
  runtime). No feature flag.

## Request
See `request.http`. Trigger is `POST /livewire-5f244c96/update` (admin session, ViewInvoice):
`mountAction('download_pdf')` then `callMountedAction`.

## Response
See `response.txt`. This run:
- Injected payload body: `<script type="text/php"> system('id > /tmp/pwn_2099405b 2>&1'); </script>`
- `download_pdf` action: HTTP 200, download effect present.
- Marker `/tmp/pwn_2099405b` before trigger: absent → after trigger:
  **`uid=0(root) gid=0(root) groups=0(root)`** — the output of `id` executed by the server.

## Observation
Exactly the static chain. `InvoiceService::download()` concatenates stored `Comment` bodies
into `$notes` (`:30-36`), the vendor template prints `notes` with Blade raw output
(`{!! $invoice->notes !!}`), and dompdf renders it with `enable_php=true`, so
`<script type="text/php">` executes. The command ran as **root** (the FrankenPHP process runs
as root in this container), i.e. full RCE with the highest in-container privilege. A separate
direct-render sanity check (via `InvoiceService::download()->stream()`) reproduced the marker
independently, isolating the sink from the trigger mechanism.

## Side effects
- Created a secretary account, an InvoiceType (if none), a Config `invoice_footer`, one
  Invoice + InvoiceDetail + Comment, and a marker file `/tmp/pwn_<suffix>` inside the app
  container (harmless; remove with `docker compose -p cvehunt_academico exec app rm -f /tmp/pwn_*`).
- The command executed is read-only (`id`); no destructive OS action taken.

## Research & references
- dompdf inline PHP: `<script type="text/php">` executes when `isPhpEnabled`/`enable_php` is
  true — a long-documented dompdf footgun. See dompdf docs/issues and PortSwigger/GHSA
  write-ups on "dompdf enable_php code execution".
- laravel-invoices ships `enable_php=true` in its default dompdf options and prints `notes`
  with `{!! !!}` in `templates/default.blade.php` — the raw sink.
- OWASP — **A03:2021 Injection** / Code Injection (CWE-94); *second-order injection*:
  attacker data stored under one authority is interpreted as code under another.
  https://owasp.org/Top10/A03_2021-Injection/
- Technique applied: plant a `<script type="text/php">system(...)</script>` in the one raw
  field (`notes`, fed by comment bodies) and trigger the render via the admin download action.

## If FAILED
n/a — CONFIRMED (RCE as root).
