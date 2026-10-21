# VULN-042 — Authenticated stored XSS via attacker-controlled SVG published to public/

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 3.1 6.1 — AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:59:19.132686+00:00

## Preconditions
- Created a fresh low-privileged (regular, non-admin) user via admin
  (`_common.create_user`): `mod_1ee64d6c` (id `4fca9b3a-57ec-44a8-b5e3-db875e6f93c2`).
  `used_admin=False` (whether the low-priv account's own legacy REST
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
See response.txt — `GET http://localhost:33116/public/995b1a92-a9d2-46e4-8e05-f61cc1451183.svg` with **no session cookie**.

## Observation
- `public/995b1a92-a9d2-46e4-8e05-f61cc1451183.svg` written to disk, byte-identical to the uploaded
  SVG: `True` (verified via `docker compose exec app cat ...`).
- Served back over plain, unauthenticated HTTP with
  `Content-Type: image/svg+xml`, inline (no `Content-Disposition:
  attachment`): `served_inline=True`.
- Body bytes match the uploaded SVG exactly: `True`.
- Real-browser proof (Playwright/Chromium, top-level navigation to the
  public URL, no cookies/auth): the SVG root element's `onload` handler
  executed. DOM sentinel `window.top.__vuln042_fired` observed as `True`.
  `alert(document.domain)` dialog fired with message: `'localhost'`.
  Screenshot: evidence/fired.png.
- Confirms the static finding precisely: `makePublicImage()`
  (`EmailTemplate.php:949-966`) copies `upload://<id>` to `public/<id>.svg`
  with only an extension-string check (`has_valid_image_extension()`,
  `include/utils.php:6011-6028`, which allows `svg`) — no
  `getimagesize()`/raster validation, no re-encode. The install `.htaccess`
  (confirmed on the live container) has no rule for `public/`, and Apache's
  stock mime.types maps `.svg` to `image/svg+xml`, served inline.

## Side effects
- One new Users record (`mod_1ee64d6c`), one Notes record
  (`995b1a92-a9d2-46e4-8e05-f61cc1451183`) with a malicious SVG attachment in `upload://995b1a92-a9d2-46e4-8e05-f61cc1451183`,
  one EmailTemplates record (`36f01f76-51d2-4033-89d0-8dac169b956c`), and one file written at
  `targets/SuiteCRM/public/995b1a92-a9d2-46e4-8e05-f61cc1451183.svg` inside the app container
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
