# VULN-008 — API authorization structurally coarser than the UI

| | |
|---|---|
| **ID** | VULN-008 |
| **Software** | Joomla! CMS |
| **Repository** | https://github.com/joomla/joomla-cms |
| **Affected version** | 5.4.9-rc2-dev (commit-pinned, no tagged release) |
| **Commit** | a8bd3564ef52e830069aeb91286c2fd67bb3872d |
| **Severity** | Medium (conditional) |
| **CVSS 3.1** | 6.5 (widened config) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED (widened-config BFLA); baseline INTENDED (Super-User-only) |
| **Confidence** | 5/10 |
| **Confidence reasoning** | Structural coarseness real and demonstrated, but needs an operator to widen two non-default gates; baseline API is Super-User-only (no impact). |
| **Auth required** | A valid API identity. Exposure materialises only if an operator grants API login to a non-Super-User group. |
| **Attacker gain** | A limited backend group reads every component's admin data (all users, all plugins/extensions, any content state) via the API. |

## Summary
Joomla's REST API applies no per-component authorization gate and no publication-state filter on reads. At the secure baseline the API is reachable only by Super Users — enforced by two independent gates — so this is latent/intended. But when an operator grants API access to a non-Super-User group (a documented way to wire up an integration), that group can read every component's administrative data through the API, strictly more than it can see in any UI channel. This was proven live by minting Joomla API tokens directly and reading `/users` and `/plugins` as a group-7 Administrator once the two gates were widened.

## How it works (mechanism & code trace)
**No gate on the API dispatch path** — `libraries/src/Dispatcher/ApiDispatcher.php`:
```php
46:  public function dispatch() {
48:      $task = $this->input->getCmd('task', 'display');
...
60:      $controller->execute($task);   // <- no checkAccess() call at all
62:  }
```
The parent `ComponentDispatcher::checkAccess()` *would* enforce `core.manage`, but only for the administrator client:
```php
// libraries/src/Dispatcher/ComponentDispatcher.php
98:  if ($this->app->isClient('administrator') && !$this->app->getIdentity()->authorise('core.manage', $this->option)) {
```
The API app's client name is `'api'`, so that gate never runs. The base read actions add no ACL of their own — `ApiController::displayList()` (`:201`) and `displayItem()` (`:146`) contain no `authorise()` — and the admin list models they reuse apply no default publication-state restriction (`/content/articles?filter[state]=-2` returns trashed items). The **only** thing standing between an identity and the whole API is "does it hold `core.login.api`?"

**Two gates keep that Super-User-only by default.** Authentication via the token plugin requires the user to be in `plg_user_token`'s `allowedUserGroups`, which defaults to `[8]` (`getAllowedUserGroups()` fallback when the param is absent). Then `ApiApplication.php:353` requires `core.login.api`, seeded only to group 8. A group-7 token therefore fails at authentication (observed: 401).

**Widening collapses it.** Granting group 7 in both places — `allowedUserGroups += "7"` and root `core.login.api += {"7":1}` — makes the same group-7 token authenticate and authorise. With no per-component gate downstream, it then reads `/users`, `/plugins`, and any content state. Observed under the widened config: `/users` → 200 (7 accounts with emails/block/lastvisit), `/plugins` → 200 (20 plugins + state), `/content/articles?filter[state]=-2` → 200.

## Why it is a vulnerability
In the UI, a group only sees the components it was granted `core.manage` on. The API erases that distinction: a single `core.login.api` bit admits an identity to **every** component's read endpoints, with unpublished/trashed states included. So a role an operator intended to limit to (say) content management can, through the API, enumerate all user accounts and the full extension inventory — a horizontal/vertical read escalation relative to the same role's UI authority. The security invariant "a backend role sees only what its per-component ACL grants" holds in the UI but not the API; the dispatcher simply never checks. Writes stay gated, so the breach is confidentiality (excessive data exposure / BFLA on reads).

## Reproduction
1. Lab up at `http://localhost:34931`.
2. `./run.sh`. It mints a Super-User token (shows reads + no state filter), creates a group-7 Administrator and mints its token (401 at baseline), then temporarily widens both gates and shows the group-7 token reading `/users` + `/plugins` + trashed content, and reverts both gates.
3. Expected: `==> VULN-008: CONFIRMED — widened-config BFLA …; baseline INTENDED (SU-only)`. Evidence: `run.log`, `response.txt`.

## Impact
Under the widened config: a non-Super-User group reads all users (emails, block status, last-visit), every plugin/extension and its state, menus, and content in any publication state via the API — bulk cross-component administrative data it cannot reach in the UI. Writes remain per-component gated, so impact is confidentiality (High). At the documented baseline (no widening) there is no exposure. Chains with VULN-007 (if Basic auth is also enabled) or any leaked/forged token to broaden what a lower-tier identity harvests.

## Suggested fix
1. Add a per-component authorization gate on the API path — have `ApiDispatcher::dispatch()` call an access check, or make `ComponentDispatcher::checkAccess()` enforce `core.manage` for the `'api'` client too.
2. Apply publication-state/view-access filtering to API reads equivalent to the UI/viewer ACL, instead of inheriting the admin model's unfiltered state set.
3. Verify the 5.4.9/6.1.4 API-ACL fixes (CVE-2026-90913/90917/92226/90916) close the structural dispatcher gap, not only specific endpoints.

## References
- OWASP API Security Top 10 — API5 (BFLA), API3 (Excessive Data Exposure).
- CVE-2023-23752 (ancestor API info-disclosure); 5.4.9 point-fixes CVE-2026-90913/90917/92226/90916.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 40 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. Fetched osv.dev records for CVE-2026-90913, CVE-2026-90917, CVE-2026-92226, CVE-2026-90916, CVE-2026-92223 — each is an endpoint-specific ACL fix (access-level endpoint mutations, tagged-item output, webservice edit tasks, content-history compare, workflow stage); none describes a missing per-component gate on API reads
2. Fetched github.com/advisories?query=joomla+api+authorization+2026 — 0 results
3. Fetched joomla-cms issue search `ApiDispatcher checkAccess core.manage` — 0 results
4. Fetched raw `libraries/src/MVC/Controller/ApiController.php` at tag 5.4.9 — `displayList()`/`displayItem()` still perform no `authorise()` call; only add/edit/delete are gated via `allowAdd`/`allowEdit`/`allowDelete`, so the structural read gap persists after the 5.4.9 point fixes
5. Fetched Joomla issues #26925 / PR #27021 — API access intentionally limited to Super Users via token auth; no discussion of per-component read authorization
6. developer.joomla.org security centre returned HTTP 521 on three attempts and could not be read directly

**Related but distinct public references** (same class or component, not this bug):
- CVE-2023-23752 — unauthenticated API information disclosure via a request-parameter bypass; different root cause
- CVE-2026-90913, CVE-2026-92226, CVE-2026-92223 — write-side ACL point fixes in specific API/webservice tasks
- CVE-2026-90917, CVE-2026-90916 — read-side ACL point fixes in specific views, not the generic dispatcher

**Reasoning:** No public reference describes the generic absence of a per-component `core.manage` gate (and publication-state filtering) on API reads as a vulnerability; the 2026 fixes address individual endpoints. Confidence is low-moderate because the finding only materialises after an operator widens two non-default gates, the vendor documents the API as Super-User-only, and it may be classified as hardening rather than a vulnerability.
