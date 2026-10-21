#!/usr/bin/env python3
r"""
VULN-030 — Weak password hashing: unsalted single-round SHA-256 (default)
=========================================================================
Vulnerable code : targets/Znuny/Kernel/System/User.pm:868,963-973 (sha2 default, Digest::SHA add($Pw))
Vulnerability   : CWE-916 Use of Password Hash With Insufficient Computational Effort; CWE-759 no salt

The shipped default CryptType is `sha2`, storing an UNSALTED single-round SHA-256 of the password
(identical passwords -> identical hashes; GPU-crackable). Provable: set a known password and show
the stored `users.pw` equals sha256_hex(password) with no salt (two users with the same password
get identical hashes).
"""
import os, sys, hashlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C
HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    C.banner("VULN-030", "Weak password hashing: unsalted single-round SHA-256",
             ["User.pm:868 CryptType defaults to sha2; :963-973 Digest::SHA('sha256')->add($Pw), no salt"])
    sfx = C.rid()
    pw = f"SharedPass_{sfx}"
    u1, _ = C.create_agent(login=f"h30a_{sfx}", password=pw)
    u2, _ = C.create_agent(login=f"h30b_{sfx}", password=pw)   # same password -> same hash if unsalted
    C.log("SETUP", f"two agents {u1}, {u2} with the SAME password")
    h1 = C.db(f"SELECT pw FROM users WHERE login='{u1}'")[0][0]
    h2 = C.db(f"SELECT pw FROM users WHERE login='{u2}'")[0][0]
    expect = hashlib.sha256(pw.encode()).hexdigest()
    C.log("PROOF", f"stored hash user1 = {h1}")
    C.log("PROOF", f"stored hash user2 = {h2}")
    C.log("PROOF", f"sha256_hex(password) = {expect}")
    open(os.path.join(HERE, "response.txt"), "w").write(
        f"user1 pw={h1}\nuser2 pw={h2}\nsha256_hex(pw)={expect}\nidentical={h1==h2}\n")
    open(os.path.join(HERE, "request.http"), "w").write("N/A — storage characteristic verified via DB\n")

    unsalted_match = (h1 == expect)
    identical = (h1 == h2)
    C.log("PROOF", f"hash == unsalted sha256_hex(pw): {unsalted_match}; two users share the hash: {identical}")
    if unsalted_match and identical:
        C.confirmed("stored password hash equals unsalted sha256_hex(password) and two accounts with "
                    "the same password have identical hashes — no salt, single round SHA-256 "
                    "(GPU-crackable, rainbow-tableable).")
    else:
        C.failed(f"hash did not match unsalted sha256 (match={unsalted_match}, identical={identical})")

if __name__ == "__main__":
    main()
