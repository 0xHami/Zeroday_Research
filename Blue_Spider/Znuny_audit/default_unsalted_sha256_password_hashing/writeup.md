# VULN-030 — Weak password hashing: unsalted single-round SHA-256 (default) + legacy formats accepted

| | |
|---|---|
| **ID** | VULN-030 (raw ZN-036/037) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium · CVSS 3.1 **5.9** — `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (post-DB-exposure) |
| **Status** | **CONFIRMED (dynamic)** · **Auth**: none for the crack (needs a DB/backup read) |
| **Attacker gains** | Fast offline recovery of agent/customer passwords from any DB or backup leak. |

## Summary
Znuny's shipped default password scheme (`CryptType=sha2`) stores an **unsalted, single-round**
SHA-256 of the password. Identical passwords produce identical hashes and the digest is
GPU/rainbow-table crackable. Confirmed: two agents given the same password have byte-identical
`users.pw` values, and that value equals `sha256_hex(password)`.

## How it works (mechanism & code trace)
`Kernel/System/User.pm`:
```perl
868:  my $CryptType = $ConfigObject->Get('AuthModule::DB::CryptType') || 'sha2';
...
963:  my $SHAObject = Digest::SHA->new('sha256');
966:  $SHAObject->add($Pw);                 # <-- no salt
967:  $CryptedPw = $SHAObject->hexdigest();
```
The default when `AuthModule::DB::CryptType` is unset is `sha2`; the customer side mirrors it
(`CustomerUser/DB.pm`, `Framework.xml` customer `sha2`). No per-password salt is added, so the
mapping password→hash is deterministic. bcrypt exists in the code but is opt-in.

Dynamic proof: `users.pw` of two same-password accounts are identical and equal
`hashlib.sha256(pw).hexdigest()`.

Verification is additionally format-driven (`Kernel/System/Auth/DB.pm`) and accepts
`plain`/`md5`/`sha1`/DES-`crypt` — the DES branch is exactly what authenticates the VULN-004 seed
hash.

## Why it is a vulnerability
Password storage must resist offline cracking after a DB/backup compromise; the accepted practice
(OWASP) is a slow, salted KDF (bcrypt/argon2/scrypt). Unsalted single-round SHA-256 is neither
slow nor salted: an attacker who obtains the `users`/`customer_user` tables cracks weak/common
passwords at billions/sec and instantly spots password reuse (identical hashes) across accounts.
This is a default-configuration weakness, not a misconfiguration, and it amplifies the blast
radius of any read primitive (VULN-007/026/027 file reads of `Config.pm`→DB creds, VULN-017 SQLi,
a stolen backup).

## Reproduction
`./run.sh` creates two agents with the same password and shows `users.pw` identical and equal to
`sha256_hex(password)`.

## Impact
Post-DB-exposure confidentiality: rapid mass password recovery and reuse detection for all agent
and customer accounts. Rated Medium because it requires a separate DB/backup read to weaponise,
but it converts such a read into full credential compromise.

## Suggested fix
Default `CryptType` to bcrypt (or argon2) with a per-password salt and a sane work factor;
opportunistically re-hash on successful login; gate acceptance of legacy formats
(plain/md5/sha1/DES) behind an explicit, temporary migration flag.

## References
- OWASP Password Storage Cheat Sheet. CWE-916, CWE-759.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 40 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. NVD API keyword pull for "Znuny" (17) and "OTRS" (120) grepped for hash / salt / sha / password / bcrypt — CVE-2019-13458 (hashed passwords disclosed via notification tags), CVE-2020-1773 (predictable session IDs / reset tokens), CVE-2024-43444 and CVE-2025-26847 (plaintext passwords in logs / support bundles); no CVE on the hashing scheme itself
2. Znuny advisory index ZSA-2021-01 … ZSA-2026-16, GitHub advisory DB, Debian tracker reviewed — no password-storage advisory
3. `gh search issues --repo znuny/Znuny "bcrypt"` / `"sha256 salt password"` — only dependency/migration issues (#713, #706, #307, #36)
4. (Shared WebSearch budget was exhausted before this finding; evidence below comes from direct primary-source pulls: NVD CVE API, vendor advisory pages, GitHub advisory DB, Debian tracker, GitHub issue search.)

**Related but distinct public references** (same class or component, not this bug):
- Znuny/OTRS SysConfig documentation for `AuthModule::DB::CryptType` (`sha2` default, `bcrypt` optional) — publicly documents the scheme as a configuration choice, not as a vulnerability
- CVE-2019-13458 / OSA-2019-11 — disclosure of the (weak) hashes via templates; exploits the storage weakness indirectly but is a different defect

**Reasoning:** No CVE, ZSA or OSA has been issued for unsalted single-round SHA-256 as the default `CryptType`, so there is no formal public disclosure of this finding. However, the scheme is openly documented in vendor configuration docs and has been a widely discussed, long-standing OTRS-family characteristic (bcrypt has been offered as an opt-in since OTRS 4), so it is best described as publicly known weak-by-default behaviour rather than an undisclosed bug; the low score reflects that.
