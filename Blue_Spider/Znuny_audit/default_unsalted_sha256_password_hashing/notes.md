# VULN-030 — Weak password hashing: unsalted single-round SHA-256 (default)

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (5.9)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- Ability to set an agent password (default flow) and read the `users.pw` column (post-DB-read /
  the lab DB). The finding is a storage weakness that amplifies any DB/backup leak.

## Request / Response
Created two agents with the SAME password. `users.pw` for both = the identical value
`722d721f…3475dbb`, which equals `sha256_hex("SharedPass_<sfx>")`. See `response.txt`.

## Observation
Confirms `User.pm:868` default `CryptType=sha2` and `:963-973` `Digest::SHA('sha256')->add($Pw)`
with no salt: identical passwords → identical hashes, and the hash is a plain unsalted SHA-256.

## Side effects
Creates two throwaway agents. Idempotent.

## Research & references
- OWASP Password Storage Cheat Sheet (use bcrypt/argon2/scrypt with per-password salt). CWE-916,
  CWE-759. Verify-side also accepts plain/md5/sha1/DES (`Auth/DB.pm`), the DES branch being what
  authenticates the VULN-004 seed hash.
