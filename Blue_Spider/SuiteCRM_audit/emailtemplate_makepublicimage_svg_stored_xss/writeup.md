# VULN-042 — Authenticated stored XSS via attacker-controlled SVG published to public/

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
   if (in_array($this->upload_file->file_ext, $sugar_config['upload_badext'])) { ... }
   $focus->filename = $this->upload_file->get_stored_file_name();
   $focus->save();
   $this->upload_file->final_move($focus->id);   // writes upload://<Note id>
   ```
   The only gate is `upload_badext` (`include/utils.php:205-224`), a
   denylist of executable/script extensions (`php`, `js`, `html`, ...) that
   does **not** include `svg`. There is no image-content check anywhere on
   this path — the raw bytes I supplied are written verbatim to
   `upload://995b1a92-a9d2-46e4-8e05-f61cc1451183`.
2. **Reference it from an EmailTemplate**: `body_html` is set (via
   `set_entry`) to contain
   `<img src="{site_url}/index.php?entryPoint=download&type=Notes&id=995b1a92-a9d2-46e4-8e05-f61cc1451183&filename=x.svg">`.
   No validation of `body_html` content happens at save time.
3. **Trigger the publish**: `EmailTemplate::retrieve()`
   (`modules/EmailTemplates/EmailTemplate.php:890-901`) — called on every
   load of the template (here, via a `get_entry` REST call, but equally
   reachable by opening the template in the UI) — calls
   `repairEntryPointImages()`:
   ```php
   // EmailTemplate.php:919-947
   $regex = '#<img[^>]*[\s]+src=[\s]*["\'']('
       . preg_quote($siteUrl) . '\/index\.php\?entryPoint=download&type=Notes&id=([a-f0-9]{8}-...)&filename=.+?)["\'']#si';
   if (preg_match($regex, $html, $match)) {
       $fileExtension = end(explode('.', $match[1]));     // 'svg' from filename=x.svg
       if (!has_valid_image_extension(..., $toFile)) { return; }
       $this->makePublicImage($match[2], $fileExtension);  // :941
       ...
   }
   ```
4. **The defect**: `makePublicImage()` (`EmailTemplate.php:949-966`):
   ```php
   protected function makePublicImage($id, $ext = 'jpg')
   {
       $toFile = 'public/' . $id . '.' . $ext;
       ...
       $fdata = file_get_contents($fromFile);      // upload://<id> — attacker's raw SVG
       file_put_contents($toFile, $fdata);         // public/<id>.svg — byte-for-byte, no checks
   }
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
   observed). A browser navigating to `public/995b1a92-a9d2-46e4-8e05-f61cc1451183.svg` renders it as
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
   and `EmailTemplates` (`used_admin=False` this run — see notes.md).
2. `set_entry` (Notes) to create an empty note -> id `995b1a92-a9d2-46e4-8e05-f61cc1451183`.
3. `set_note_attachment` with `filename=payload.svg` and `file=`
   base64 of:
   ```
   <svg xmlns="http://www.w3.org/2000/svg" onload="window.top.__vuln042_fired=true; alert(document.domain)"><circle cx="10" cy="10" r="5"/></svg>
   ```
4. `set_entry` (EmailTemplates) with `body_html` containing
   `<img src="{BASE_URL}/index.php?entryPoint=download&type=Notes&id=995b1a92-a9d2-46e4-8e05-f61cc1451183&filename=x.svg">`
   -> id `36f01f76-51d2-4033-89d0-8dac169b956c`.
5. `get_entry` (EmailTemplates, id `36f01f76-51d2-4033-89d0-8dac169b956c`) — triggers the publish.
6. Run `./run.sh` (venv auto-provisioned). Expected terminal output ends
   with `[OK]` / `==> VULN-042: CONFIRMED — ...`.
7. Observable proof: `docker compose exec app cat public/995b1a92-a9d2-46e4-8e05-f61cc1451183.svg`
   returns the exact uploaded SVG bytes (response.txt); `GET
   http://localhost:33116/public/995b1a92-a9d2-46e4-8e05-f61cc1451183.svg` with **no cookies** returns `Content-Type: image/svg+xml`
   inline; a real headless Chromium navigating directly to that URL
   (`evidence/fired.png`) shows `window.top.__vuln042_fired` set to `true` and
   an `alert(document.domain)` dialog firing with message `'localhost'`
   (full transcript in run.log).

## Impact
Any authenticated, non-admin user can plant a persistent, same-origin
script-execution page at a predictable URL
(`{BASE_URL}/public/<Note-id>.svg`) and lure any other user — including an
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
  `RedirectMatch 403 .../public/.*\.(svg|html?|phar|php)$` to the shipped
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

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 50 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `CVE-2026-29104 SuiteCRM` — admin-only PDF font upload bypass in Configurator (GHSA-5hx9-cmmx-26p3), unrelated component
2. `CVE-2023-6127 SuiteCRM stored XSS huntr` — "Unrestricted Upload of File with Dangerous Type" prior to 7.14.2 (huntr bf10c72b); huntr page would not render, but no source ties it to EmailTemplates/public/
3. `SuiteCRM SVG stored XSS public directory email template image makePublicImage` — CVE-2021-39268 (SVG XSS via `clean_file_output` bypass in download path, fixed 7.11.19), CVE-2020-14208 (document preview XSS); no public/-directory republish match
4. `SuiteCRM svg upload XSS CVE Notes attachment entryPoint download` — CVE-2021-39268, CVE-2021-39267 (Content-Type bypass), CVE-2021-45903 (attachment XSS <7.10.35/7.12.2), CVE-2025-54787; all download/attachment-side sinks, not public/ publication
5. `SuiteCRM "repairEntryPointImages" OR "makePublicImage" vulnerability` (extended) — CVE-2021-45897 (authenticated RCE via `.php` copied to public/, fixed 7.12.3/8.0.2); PoC README fetched: no mention of SVG or XSS
6. `SuiteCRM email template SVG XSS "public" folder advisory 2024 2025 2026` — CVE-2025-54784 (email viewer XSS), nothing on SVG in public/
7. `SuiteCRM "has_valid_image_extension" svg XSS public` — no hit for the function; only CVE-2021-39268 again

**Related but distinct public references** (same class or component, not this bug):
- CVE-2021-45897 (manuelz120 PoC) — SAME component (`EmailTemplate::repairEntryPointImages()` -> `makePublicImage()` copying a Note attachment into `public/`), but the disclosed bug was arbitrary extension -> `.php` RCE, fixed in 7.12.3 by an image-extension allow-list. This finding is the residual: the allow-list still admits `svg` and no content validation exists, yielding stored XSS rather than RCE
- CVE-2021-39268 — SVG stored XSS via `clean_file_output` bypass on the download entry point (fixed 7.11.19); different sink (download_file), whereas here Apache serves `public/*.svg` directly with no PHP involved
- CVE-2021-45903 / CVE-2021-39267 — attachment upload XSS / Content-Type filter bypass in older versions, different sinks
- CVE-2023-6127 — unrestricted upload prior to 7.14.2 (component not published in indexed sources)

**Reasoning:** The vulnerable component and the "copy attachment verbatim into public/" mechanism are publicly known from CVE-2021-45897, and SVG-based XSS in SuiteCRM is publicly known from CVE-2021-39268 in a different sink; however no public source describes the post-7.12.3 residual where `makePublicImage()` still publishes attacker-controlled SVG to a same-origin, unauthenticated `public/<id>.svg` URL. Because this is effectively an incomplete-fix variant of a known CVE in the same function, confidence that it is unknown is only moderate; the vendor may already consider SVG-in-public/ covered or have an unpublished report.
