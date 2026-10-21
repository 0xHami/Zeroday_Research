# VULN-001 — Bundled demo default-credential superuser reachable via the `Host` header

## Header

- **Title:** Bundled demo data ships a default-credential superuser (`admin`/`admin`) reachable unauthenticated via the `Host` header (+ hard-coded `ENCRYPT_KEY`)
- **ID:** VULN-001
- **Severity:** **Critical** — CVSS 3.1 **9.8** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Status:** CONFIRMED (dynamic)
- **Affected version / commit:** PublicCMS `V5.202608.a`, commit `e85ab023a22b19bff5b5b0c944440ab614df467f`
- **Auth required:** **None** (unauthenticated). Deployment precondition: the installer imported the bundled demo dataset (`useSimple=true`) — recorded as done for this target.

## Summary

Any install that imported the bundled demo data ships a second `sys_user` row (id=2, `site_id=2`, `superuser=1`) whose password hash is the sample credential `admin`/`admin`. Admin login is scoped to the site chosen by the attacker-controlled `Host` header, and the installer only re-secures user id=1, so sending `Host: site2.dev.publiccms.com` with `admin`/`admin` to `/admin/login` yields a full superuser session in a single unauthenticated request. This is a one-request site takeover: content, users, roles, templates, the file manager, DB tools, and every admin-gated finding (notably the VULN-003 SSRF) become reachable.

## Technical details

### Root cause

Three independent facts combine into an unauthenticated takeover.

**1. The demo dataset ships a superuser with a known password** (`targets/PublicCMS/data/publiccms/publiccms.sql:189`, `:169`):

```sql
-- publiccms.sql:189  (site_id=2, superuser=1, disabled=0; password = salt.hash)
INSERT INTO `sys_user` VALUES (2, 2, 'admin',
  '0123456789.2134b56595c73a647716b0a8e33f9d50243fb1c1a088597ba5aa6d9ccadacbd8fc8307bda2adfc8362abe611420bd48263bdcfd91c1c26566ad3a29d79cffd9c',
  1, 'admin', NULL, 2, 1, '2', '', 0, 1, 0, ...);
-- publiccms.sql:169  maps a domain to site 2:
INSERT INTO `sys_domain` VALUES ('site2.dev.publiccms.com', 2, 1, '');
```

The stored password is `salt.hash` with salt `0123456789`. Recomputing `sha512(sha512("admin") + "0123456789")` reproduces the shipped hash **byte-for-byte** — verified programmatically this run (`run.log` line `[SETUP] hash-crack: … == shipped hash -> credential is admin/admin`). So the credential is `admin`/`admin` (CWE-798, use of hard-coded credentials).

**2. The installer only re-secures id=1** (`targets/PublicCMS/publiccms-parent/publiccms-core/src/main/java/com/publiccms/common/base/AbstractCmsUpgrader.java:85`):

```java
"update sys_user set name=?,password=? where id = 1"
```

Demo import runs *after* the installer's `setPassword`, so the id=2 superuser is never re-secured.

**3. Site selection trusts the `Host` header, and login is site-scoped** (`AdminContextInterceptor.java:49-50`, `LoginAdminController.java:108`):

```java
SysDomain domain = siteComponent.getDomain(request.getServerName());   // request.getServerName() == Host header
SysSite site = siteComponent.getSite(domain, request.getServerName(), null);
...
SysUser user = service.findByName(site.getId(), username);             // findByName(2, "admin") -> id=2
```

### Data flow

Attacker sets `Host: site2.dev.publiccms.com` → `getServerName()` resolves site 2 → `findByName(2, "admin")` selects the demo superuser (id=2) → password `admin` matches the shipped hash → a `PUBLICCMS_ADMIN` session cookie prefixed `2_` is issued. Captcha and OTP are off by default, so nothing else gates the login.

### Why existing mitigations don't apply

- The installer's per-install password reset is pinned to `where id = 1`; id=2 is out of its scope.
- No DNS control is needed — the `Host` header alone drives tenant resolution, so the attacker reaches site 2 from any network position.
- Secondary defect: `CommonConstants.ENCRYPT_KEY = "publiccms"` (`CommonConstants.java:44`) is a compile-time constant shared by every install and encrypts `database.properties` at rest (CWE-321), so any file-read primitive discloses the DB credentials.

## Reproduction

1. **Bring up the target** (from the repo root; see the manifest `## Runtime`):
   ```bash
   cd targets/PublicCMS
   DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker compose -p cvehunt_publiccms up -d --build
   bash ../../claude_audit/PublicCMS/setup/install.sh   # first run only; imports demo data
   ```
2. **Run the exploit** from this directory:
   ```bash
   cd claude_audit/PublicCMS/exploits/VULN-001 && ./automation.sh
   ```
   The script (read-only, no writes as superuser): offline-cracks the shipped hash to prove the credential is `admin`/`admin`, then `POST`s `username=admin&password=admin` to `/admin/login` with `Host: site2.dev.publiccms.com`, asserts a `302` + a `PUBLICCMS_ADMIN` cookie whose id-prefix is `2` (the demo superuser), and re-uses that cookie to render `/admin/index`.
3. **Expected output:** `[OK] exploit confirmed — unauthenticated superuser session on site 2 (dashboard rendered)`, followed by `<title>企业中英文站点 - Management system</title>`.
4. **Confirm exploitation:** the login response is `302 → index.html` with `Set-Cookie: PUBLICCMS_ADMIN=2_<uuid>` (the `2_` prefix proves the session is the demo superuser, not the installer-secured id=1); the dashboard fetch returns `200` with the management console. Negative control in the notes: `password=wrongpass123` with the same Host stays `200` on the login page with no cookie — proving the success is genuine authentication, not an unconditional redirect.

- See `request.http` for the exact two requests, `response.txt` for the login headers, `evidence/dashboard.html` for the rendered superuser console, and `run.log` for the full run.

## Impact

Unauthenticated, single-request superuser takeover of the affected site. The session grants full read/write of content, users, roles, templates, the file manager and DB tools, and is the springboard into every admin-gated finding:

- **Chains to [VULN-003](../VULN-003/writeup.md)** (UEditor `catchimage` SSRF) → internal-network / cloud-metadata access and IAM credential theft.
- **Chains to [VULN-023](../VULN-023/writeup.md)** (admin-only AI-chat SSRF) — once the admin console is owned, both the SSRF's enabler and trigger are satisfied.
- The hard-coded `ENCRYPT_KEY` chains with any file read to disclose DB credentials from `database.properties`.

Because site selection is `Host`-header driven, the attacker needs no credentials the operator ever chose — only a value from the shipped SQL and a header they set.

## Suggested fix

Multiple layers, any one of which breaks the chain:

1. **Remove the demo superuser from sample data.** In `data/publiccms/publiccms.sql`, delete the `sys_user` id=2 row (or ship it `disabled=1`, `superuser=0`, with no usable password). Sample data must never contain a login-capable privileged account.
2. **Secure *all* privileged rows at install, not just id=1.** In `AbstractCmsUpgrader.java:85`, replace the `where id = 1` reset with one that re-secures every `superuser=1` row (or force a password reset for any account whose password matches a known sample hash), and run it *after* any demo import:
   ```java
   // pseudocode: after demo import
   for (SysUser u : service.getListByParam(siteId, /* superuser */ true)) {
       service.updatePassword(u.getId(), UserPasswordUtils.passwordEncode(randomStrongSecret(), null, encode));
   }
   ```
3. **Replace the shared `ENCRYPT_KEY`.** In `CommonConstants.java:44`, generate a per-install random key at first boot and persist it outside the source tree (e.g. alongside `database.properties`), instead of the compile-time constant `"publiccms"`.

Defense-in-depth: do not resolve the admin tenant purely from the raw `Host` header for authentication; require the domain to be an operator-registered `sys_domain` and reject unknown hosts.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 60 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `PublicCMS demo data default admin password superuser site2 CVE` — only unrelated PublicCMS CVEs (XSS CVE-2026-36521, CVE-2020-21333, CSRF CVE-2018-11500, priv-esc CVE-2024-31759); nothing on demo data / site2 / default credentials
2. `PublicCMS Host header site resolution admin login default credential vulnerability` — Host-header results are for other CMSes (ApostropheCMS, Pimcore); PublicCMS hits are XSS and CVE-2026-6796 (cleartext failed-login logging), not site selection
3. `PublicCMS ENCRYPT_KEY "publiccms" hardcoded key database.properties decrypt CVE` — found CVE-2026-8739 (hard-coded `privatefile_key` in `SafeConfigComponent.getSignKey`), a different key / component
4. `PublicCMS CVE 2025 2026 security advisory sanluan` + full CVE listing (releasealert.dev, 49 CVEs) — no entry for default credentials, demo dataset, installer `setPassword`, or `AdminContextInterceptor` Host-based site resolution
5. `github sanluan PublicCMS issue "site2.dev.publiccms.com" OR "demo data" admin admin default password security` — only the Gitee/GitHub README line documenting the data script's built-in admin/admin account; no issue or advisory
6. `PublicCMS "publiccms.sql" sys_user admin default credential unauthenticated takeover` — no relevant results
7. `PublicCMS default credentials admin/admin weak password CWE-798 vulnerability installer` — no PublicCMS results (only Puppet, ASUSTOR, newbee-mall CWE-798 entries)
8. Fetched CVE-2023-34852 ("Insecure Permissions", <=4.0.202302) writeup (funny-kill) — stub with no component or mechanism; does not mention credentials, demo data or Host header

**Related but distinct public references** (same class or component, not this bug):
- PublicCMS README (Gitee mirror): "数据脚本内置管理员账号/密码:admin/admin" — documents that the data script contains an admin/admin account, but does not disclose that the installer re-secures only `id=1`, that a second `superuser=1` row for site 2 survives install, or that it is reachable unauthenticated via the `Host` header
- CVE-2026-8739 — hard-coded cryptographic key in `SafeConfigComponent.getSignKey` (`privatefile_key`); different key and component from `CommonConstants.ENCRYPT_KEY`
- jas502n/publiccms_decrypt — public tool that decrypts `database.properties` using the constant key; shows the secondary `ENCRYPT_KEY` issue is informally known, but it is not an advisory and not the primary finding
- CVE-2023-34852 / CVE-2024-31759 — generic "insecure permissions" / change-password privilege escalation in 4.0.x; no stated relation to demo data or site resolution

**Reasoning:** No CVE, GHSA, vendor advisory, or issue describes the specific chain (bundled `publiccms.sql` superuser id=2 on site 2 never re-secured by `AbstractCmsUpgrader.setPassword ... where id = 1`, reachable because `AdminContextInterceptor` resolves the tenant from the raw `Host` header). The README's admin/admin line and the public `ENCRYPT_KEY` decryptor are near-misses that lower confidence, and default-credential findings are often reported privately or dismissed as configuration, so a private report could exist. The primary unauthenticated-superuser-via-Host finding appears undisclosed.
