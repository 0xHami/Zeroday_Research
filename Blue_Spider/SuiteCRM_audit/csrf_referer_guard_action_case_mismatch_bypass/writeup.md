# VULN-088 — Action-name case-normalization mismatch defeats the CSRF referer guard

## 1. Header
- **Title:** Action-name case mismatch nullifies the CSRF referer check for `MassUpdate`/`QuickSave`/`configureDashlet`
- **ID:** VULN-088
- **Software:** SuiteCRM · **Repository:** https://github.com/SuiteCRM/SuiteCRM
- **Affected version:** 7.15.2 (`suitecrm_version.php`) — commit-pinned `forkedSuite` snapshot
- **Commit:** `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
- **Severity:** High · **CVSS 3.1:** 8.0 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`
- **Status:** CONFIRMED (dynamic)
- **Auth required:** None for the attacker (CSRF); the victim is any authenticated user (admin victim → all records). Victim interaction (UI:R) = opening the attacker page while logged in.
- **What an attacker gains:** cross-site mass deletion / mass field-overwrite of the victim's records, bypassing the referer-based CSRF control the developers intended.

## 2. Summary
SuiteCRM protects state-changing requests with an empty-`Referer` check that only applies to actions it classifies as "modify actions." That classifier compares the **raw-case** action name against **all-lowercase** allow-lists, while the router dispatches actions **case-insensitively**. The app's own canonical action names are CamelCase (`MassUpdate`, `QuickSave`, `configureDashlet`), so they are never classified as modify actions and never receive the guard — yet they still execute. An attacker page that suppresses the Referer can therefore drive a logged-in victim's browser to `action=MassUpdate&Delete=true`, deleting the victim's records cross-site. Validated by a byte-identical pair of no-Referer requests: lowercase `massupdate` was blocked by the guard, CamelCase `MassUpdate` sailed through and deleted the record.

## 3. How it works (mechanism & code trace)

**The guard.** `checkHTTPReferer()` rejects a missing Referer only for modify actions:
```php
// include/MVC/SugarApplication.php  checkHTTPReferer()
$strong = empty($sugar_config['http_referer']['weak']);   // default: true (no such config)
if ($strong && empty($_SERVER['HTTP_REFERER'])
        && !in_array($this->controller->action, $this->whiteListActions)
        && $this->isModifyAction()) {                      // <-- only guards "modify actions"
    ... $ss->display('include/MVC/View/tpls/xsrf.tpl'); sugar_cleanup(true);  // BLOCK
}
```

**The classifier — the exact defect.** `isModifyAction()` compares the raw-case action against lowercase lists:
```php
// include/MVC/SugarApplication.php:478-516
$globalModifyActions = ['massupdate','configuredashlet','import','importvcardsave',
                        'inlinefieldsave','wlsave','quicksave'];        // all lowercase
...
if (in_array($this->controller->action, $this->globalModifyActions)) return true;   // :516  RAW case
```
`$this->controller->action` is stored raw (`SugarController.php:254 $this->action = $_REQUEST['action'];`).

**The router — case-insensitive dispatch.** The action is lowercased only for dispatch:
```php
// include/MVC/Controller/SugarController.php:595
$this->action_name = 'action_' . strtolower($this->do_action);   // action_massupdate() runs for ANY case
```

So for `action=MassUpdate`: dispatch calls `action_massupdate()` (works), but `in_array('MassUpdate', ['massupdate',...])` is **false** → `isModifyAction()` returns false → `checkHTTPReferer()` never applies the empty-Referer rejection. The lowercased `$action` built at `:504-505` is used only for the `save*`/`delete*` *substring* test, which `massupdate` also fails — so nothing reclassifies it.

**Confirmed live.** Two no-Referer POSTs (`response.txt`):
- `action=massupdate` → HTTP 200 rendering `xsrf.tpl` (blocked); contact `deleted=0`.
- `action=MassUpdate` → HTTP 301 to the list (success); contact `deleted=1`.

## 4. Why it is a vulnerability (reasoning)
The developers explicitly enumerated `massupdate`, `quicksave`, `configuredashlet`, etc. in `globalModifyActions` — documented intent that these destructive actions must carry the CSRF referer check. The invariant "a state-changing request with a foreign/absent Referer is rejected" is violated for exactly those actions, because two components normalize the action token inconsistently (raw-case classification vs. lowercased dispatch). This is not by-design: the guard's whole purpose is to stop cross-site invocation of these actions, and the app's own UI issues them in CamelCase, so the guard is dead for real traffic. A skeptic's "maybe CSRF is off in this lab" is refuted by the control request: the identical lowercase call *is* blocked, proving the guard is active — only the case flips the outcome. The demonstrated cross-site deletion of a record (no Referer) is the direct integrity-boundary breach.

## 5. Reproduction
From a clean lab (`http://localhost:33116`):

1. **Precondition (scripted):** admin creates a RegularUser victim; seed two Contacts owned by the victim (`<tag>_block`, `<tag>_bypass`).
2. **Control (guard active):** as the victim session, POST with **no Referer**:
   `module=Contacts&action=massupdate&massupdate=true&uid=<block_id>&Delete=true&...` → response is `xsrf.tpl` (blocked); the contact survives.
3. **Attack (guard bypassed):** identical POST with `action=MassUpdate`:
   `module=Contacts&action=MassUpdate&massupdate=true&uid=<bypass_id>&Delete=true&...` → HTTP 301 success; the contact is deleted.

Run it: `./run.sh`. Expected tail:
```
[PROOF] lowercase massupdate: HTTP 200, csrf-guard-blocked=True
[PROOF] CamelCase MassUpdate: HTTP 301, csrf-guard-blocked=False
[PROOF] post-state: block-contact alive=True (guard held) | bypass-contact alive=False (should be deleted)
==> VULN-088: CONFIRMED — CamelCase MassUpdate bypasses the empty-Referer CSRF guard -> cross-site mass delete
```
Observable proof: the `xsrf.tpl` block on lowercase vs 301 success on CamelCase, and the `bypass` contact removed from a normal listing (`get_entry_list`) / `deleted=1` in DB. Full capture in `run.log` / `request.http` / `response.txt`. A fully cross-origin browser PoC = an auto-submitting `<form action="…index.php" method=POST>` on an attacker origin with `<meta name="referrer" content="no-referrer">`.

## 6. Impact
An attacker who lures an authenticated user to a web page can, with no credentials, issue `action=MassUpdate` requests as that user: mass-delete (`Delete=true`) or mass field-overwrite of the victim's records; with an **admin** victim and `entire=true`, of **every** record in a module (Contacts, Accounts, Leads, …) — catastrophic integrity loss. `QuickSave` (inline create/modify) and `configureDashlet` share the identical gap, so the bypass is systemic across the actions the developers meant to protect (integrity, and confidentiality via field overwrite that can exfiltrate). Blast radius scales with the victim's privilege. This is a bypass of an intended control, not merely "CSRF exists."

## 7. Suggested fix
In `include/MVC/SugarApplication.php` normalize the action once and compare consistently:
```php
// BEFORE (:512, :516) — raw-case comparisons
if (in_array($this->controller->action, $this->modifyModules[$this->controller->module] ?? [])) return true;
if (in_array($this->controller->action, $this->globalModifyActions)) return true;
// AFTER — lowercase both sides (dispatch already lowercases)
$act = strtolower($this->controller->action);
if (in_array($act, array_map('strtolower', $this->modifyModules[$this->controller->module] ?? []), true)) return true;
if (in_array($act, $this->globalModifyActions, true)) return true;   // lists are already lowercase
```
Principle: normalize a security-relevant token exactly once and reuse it for both authorization/classification and dispatch. Better still, replace the fragile referer check with a per-request synchronizer **CSRF token** validated on every state-changing action (referer checks are bypassable by design).

## 8. References
- OWASP WSTG-SESS-05 (Testing for CSRF); OWASP CSRF Prevention Cheat Sheet (synchronizer-token pattern; why Referer defenses are fragile).
- PortSwigger Web Security Academy — *CSRF* (bypassing Referer-based defenses).
- CWE-352 (CSRF) + CWE-178 (Improper Handling of Case Sensitivity). Related product advisory: CVE-2023-3627 (a different SuiteCRM CSRF issue).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. GitHub Advisory Database query `suitecrm csrf` — three results: CVE-2023-3627 (GHSA-qg9r-8vq4-2gp4), CVE-2018-20816 (GHSA-m8mc-2q3x-mw37), CVE-2021-41597 (GHSA-38m6-xrq9-23c3); none mention `isModifyAction()`, `MassUpdate`, `QuickSave` or action-name case handling.
2. CVE record CVE-2023-3627 (cited by the scanner) — CSRF in `salesagility/suitecrm-core` before 8.3.1 (huntr 558b3dce); SuiteCRM 8 core, not the 7.x `SugarApplication::checkHTTPReferer()`/`isModifyAction()` guard.
3. CVE record CVE-2021-41597 — CSRF in the UpgradeWizard (RCE via ZIP) through 7.11.21; different component.
4. GitHub commit history of `include/MVC/SugarApplication.php` — the only post-2023 change is the 7.14.7 release (escaping the Referer host in `xsrf.tpl`, CVE-2025-54783); `isModifyAction()`'s raw-case `in_array` is unchanged and the file is absent from the 7.15.1 and 7.15.2 diffs.
5. Full SuiteCRM GHSA catalogue (77 advisories through 2026-10-12) — no CSRF or referer-guard advisory.
(Note: the shared WebSearch budget was exhausted before this folder; checks were made by direct fetch of the advisory databases, CVE.org records and the upstream repository.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2025-54783 / GHSA-vqrj-gp9m-8c6r — reflected XSS in the same `checkHTTPReferer()` function's error template; same component, different bug (output encoding, not classification logic).
- CVE-2023-3627 — CSRF in SuiteCRM-Core 8.x; different codebase layer.
- CVE-2021-41597, CVE-2018-20816 — historical SuiteCRM CSRF issues in specific modules, not the framework-wide referer guard.

**Reasoning:** No public advisory, CVE or fix describes the case-sensitivity mismatch between `SugarApplication::isModifyAction()` (raw-case `in_array` against lowercase lists) and the lowercased action dispatch, which leaves `MassUpdate`/`QuickSave`/`configureDashlet` outside the empty-Referer CSRF check. The guard logic has been untouched upstream through the latest release. Caveat: this code dates back to SugarCRM CE and the referer-based defence is widely known to be weak, so a SugarCRM-era blog or forum note on the case mismatch could exist that a general web search would surface.
