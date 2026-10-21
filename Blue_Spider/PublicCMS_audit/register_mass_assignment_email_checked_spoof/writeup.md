# VULN-006 — Registration mass-assignment sets `emailChecked=true` / arbitrary `email`

## Header

- **Title:** Registration mass-assignment → verified-email spoofing (`emailChecked` / `email` bound from the request)
- **ID:** VULN-006
- **Severity:** **Medium** — CVSS 3.1 **6.5** `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`
- **Status:** CONFIRMED (dynamic)
- **Affected version / commit:** PublicCMS `V5.202608.a`, commit `e85ab023a22b19bff5b5b0c944440ab614df467f`
- **Auth required:** **None** (public registration endpoint)
- **Known-issue status:** no matching public advisory — possibly novel.

## Summary

`doRegister` binds the whole `SysUser` command object and hardens the *privilege* fields by hand (superuser/roles/deptId/contentPermissions) but **omits `email` and `emailChecked`**. Since `SysUser` exposes public `setEmail`/`setEmailChecked` and there is no binder denylist, an anonymous `POST /doRegister` with extra params `email=<victim@corp.com>&emailChecked=true` persists a "verified" email the attacker never proved they own. Because `findByEmail` only returns rows with `emailChecked=true`, the forged state makes login-by-email work — confirmed end-to-end.

## Technical details

### Root cause

`targets/PublicCMS/publiccms-parent/publiccms-core/src/main/java/com/publiccms/controller/web/LoginController.java:258-267` (success branch):

```java
entity.setPassword(UserPasswordUtils.passwordEncode(entity.getPassword(), null, encode));
entity.setLastLoginIp(ip);
entity.setSiteId(site.getId());
entity.setDisabled(false);
entity.setRoles(null);            // privilege fields reset by hand...
entity.setSuperuser(false);
entity.setContentPermissions(SysUserService.CONTENT_PERMISSIONS_SELF);
entity.setLoginCount(0);
entity.setDeptId(null);
service.save(entity);             // <-- entity.email and entity.emailChecked come straight from the request
```

`emailChecked` is load-bearing: `SysUserDao.findByEmail` returns a user only if `emailChecked=true`.

### Data flow

Attacker → `POST /doRegister` with body `name=…&nickname=…&password=…&repassword=…&email=victim@corp.com&emailChecked=true` → Spring binds all matching bean properties of `SysUser entity` → the success branch resets privilege fields but leaves `email`/`emailChecked` as bound → `service.save(entity)` persists a row with `email_checked=1` and an attacker-chosen address. Verified on the first manual run: DB row shows `email_checked=1`, arbitrary `email`, `superuser=0`, `disabled=0`.

### Why existing mitigations don't apply

- The admin write paths enforce "any email change ⇒ re-verify" (`SysUserAdminController` sets `emailChecked=false` on change); the self-service registration path does not.
- The verification control (`saveEmail` → emailed UUID → `verifyEmail`) is the *only* thing meant to flip `emailChecked=true` — registration bypasses it entirely.
- There is **no** global `@InitBinder` denylist anywhere in the project (report FP-15 confirms only the privilege fields were correctly hardened).
- **Repro correction (important):** the Spring command object is `SysUser entity`, whose bean property is `name`, **not** `username`. The report's `username=` binds nothing and silently creates no account (302 back to the register page). The working parameter is `name=`.

## Reproduction

1. **Bring up the target** (see the manifest `## Runtime`):
   ```bash
   cd targets/PublicCMS
   DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker compose -p cvehunt_publiccms up -d --build
   bash ../../claude_audit/PublicCMS/setup/install.sh   # first run only
   ```
2. **Run the exploit** from this directory:
   ```bash
   cd claude_audit/PublicCMS/exploits/VULN-006 && ./automation.sh
   ```
   The script registers one account (`name=poc_<suffix>`, `email=exploit_<suffix>@example.invalid`, `emailChecked=true`, never verified), then logs in **by email** via `/api/login` to prove the forged verified state resolves.
3. **Expected output:** `[OK] exploit confirmed — logged in by an unverified email marked emailChecked=true`.
4. **Confirm exploitation:** the `/api/login?username=<email>` response returns `{"authToken":"…","user":{"email":"exploit_…@example.invalid","emailChecked":true,…}}` (`evidence/api_login_response.json`). Manual DB check: the new `sys_user` row has `email_checked=1` with the attacker-supplied address.

- See `request.http` for the registration + login requests, `response.txt` / `evidence/api_login_response.json` for the authenticated response, and `run.log` for the full run.

## Impact

Forged "verified" identities: an attacker creates accounts whose email is marked verified without any mailbox proof, enabling email-login for accounts bound to arbitrary addresses and permanent squatting/denial of a victim's real email ([VULN-015](../VULN-015/writeup.md)). Bounded because there is no password-reset-by-email flow (so it stops short of a GitLab-CVE-2023-7028-style takeover). Chains with [VULN-002](../VULN-002/writeup.md): a harvested customer address becomes the target for a forged verified identity.

## Suggested fix

1. **Force `emailChecked=false` (and clear/ignore `email` unless re-verified) after binding**, in the `doRegister` success branch alongside the other resets:
   ```java
   entity.setDeptId(null);
   entity.setEmailChecked(false);          // never trust a request-supplied verified flag
   // optionally: require the email to go through saveEmail -> verifyEmail before it is stored at all
   service.save(entity);
   ```
2. **Add a global `@InitBinder` denylist** (or an allowlist of bindable fields) so security-relevant properties (`emailChecked`, `superuser`, `roles`, `deptId`, `contentPermissions`, `siteId`) can never be bound from request parameters on any command object:
   ```java
   @InitBinder
   void initBinder(WebDataBinder binder) {
       binder.setDisallowedFields("emailChecked","superuser","roles","deptId","contentPermissions","siteId","id");
   }
   ```
3. Enforce email uniqueness at registration (`findByEmail`) — see [VULN-015](../VULN-015/writeup.md).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `PublicCMS CVE 2025 2026 security advisory sanluan` + full PublicCMS CVE listing (releasealert.dev, 49 CVEs) — no entry for `/doRegister`, `LoginController`, `emailChecked`, registration, or mass assignment
2. GitHub Advisory Database search `publiccms`, pages 1–3 (58 advisories) — none on registration or email verification
3. GitHub issue search `register OR emailChecked OR contentCreate OR refund OR directive OR vote OR race OR draft OR userId` — 4 results, none about registration
4. GitHub issue search `xss OR vulnerability OR security OR CVE OR 漏洞` (43 issues) — closest are CVE-2024-31759 (change-password privilege escalation) and #11 / CVE-2018-11500 (CSRF admin add); nothing on registration binding
5. Fix commit 7329437 for CVE-2026-2010 — adds `userId` / `siteId` to `ignoreProperties` in `TradeAddressController` and `CmsContentSourceAdminController` (over-binding hardening elsewhere); `doRegister` not touched
6. (Planned WebSearch `PublicCMS doRegister emailChecked mass assignment` could not be executed — shared search budget exhausted; replaced by direct fetches 2–5)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2024-31759 — privilege escalation via the change-password function; different endpoint
- commit 7329437 (CVE-2026-2010 fix) — request over-binding hardening in trade address / content source controllers; not the registration path
- CVE-2018-11500 — CSRF that adds an admin account; different mechanism

**Reasoning:** Nothing public names the self-service registration binding of `email` / `emailChecked`. The project has public history of over-binding fixes in other controllers, which shows the class is familiar to reporters, but no report targets `LoginController.doRegister`. A private report could exist; none was found.
