# VULN-001 — Unauthenticated mailer previews (show_previews) + live reset-token leak → account takeover

**Software**: Ruby on Rails
**Repository**: https://github.com/rails/rails
**Affected version**: 8.2.0.alpha (from `RAILS_VERSION`, confirmed in `activesupport/lib/active_support/gem_version.rb`) — commit-pinned: no tagged release
**Status**: CONFIRMED (unauthenticated /rails/mailers exposure + live admin reset-token leak + leaked-token→ATO, all shown over HTTP); requires config.action_mailer.show_previews=true (a documented operator toggle, off by default)
**Severity (static)**: High (Critical when the flag is enabled) (CVSS 9.1 for the enabled config)
**Confidence**: 7/10
**Confidence reasoning**: Entire chain proven over HTTP — unauth GET of the preview .eml returned the admin's live reset token (resolves to id 1), the guard is inverted in source, and a leaked reset token → full ATO (PATCH + login shown on a throwaway victim). Held at 7 (not 9) because it is gated on the operator enabling a non-default feature (show_previews) outside development.
**Target commit**: c9e85dbe297e248dd2f217d04f84a94881ac046a
**Validated at**: 2026-10-03T03:00:00Z

## Preconditions
- For the unauth-route leg: `config.action_mailer.show_previews = true` outside development (off by default — verified `/rails/mailers` → 404 on the baseline). The script's `ENABLE_PREVIEWS=1` mode enables it in-container, demonstrates, and reverts.
- The Rails 8 auth generator's default `PasswordsMailerPreview#reset` (present) for the ATO leg.
- No attacker authentication at any point.

## Request
See `request.http` (the ATO leg). Full chain:
- UNAUTH `GET /rails/mailers/download/passwords_mailer/reset` (no cookie) → the admin's `.eml` with a live token.
- `GET /passwords/<leaked-token>/edit` → mints a CSRF token + cookie.
- `PATCH /passwords/<leaked-token>` with `password`/`password_confirmation` (+ cookie + authenticity_token + Sec-Fetch-Site) → sets the password.
- `POST /session` with the new password → login.

## Response
See `run.log` and `evidence/`:
```
@@legA token_present=true resolves_id=1 is_admin_take=true admin_email=admin@example.com
@@legB guard_line="before_action :require_local!, unless: :show_previews?"   routes_mounted_iff_show_previews=true
Leg C: edit 200 ; PATCH 302 -> /session/new ; login 302 -> https://localhost:27966/   (ATO)
ENABLE_PREVIEWS: unauth route status=200 ; @@r id=1 admin=true email=admin@example.com
baseline restored: GET /rails/mailers -> 404
```
Captured artefacts: `evidence/reset_email.eml` (unauth .eml), `evidence/leaked_admin_token.txt`, `evidence/mailers_index.html`, `evidence/reset_preview.html`, `evidence/legC_ato.txt`.

## Observation
Every leg reproduced exactly as predicted:
- **Unauthenticated route exposure (with the flag on):** `GET /rails/mailers` → 200 listing, and the preview `.eml` → 200, served to a client with **no cookie, no auth** — because `require_local!` is skipped when `show_previews?` is true (the same flag that mounts the routes).
- **Live admin token leak:** the preview renders `edit_password_url(@user.password_reset_token)` for `User.take`; the extracted token resolves via `find_by_token_for(:password_reset, …)` to **id 1 / admin@example.com** — a genuine, in-window admin reset credential, decoded purpose `User\npassword_reset\n900` (15-min).
- **Account takeover:** a leaked reset token → `PATCH /passwords/:token` sets a new password (302 "Password has been reset.") → login with the new password succeeds (302 → root). Shown on a throwaway victim to leave the admin credential intact.

## Side effects
- The in-container `ENABLE_PREVIEWS=1` run edits `/harness/config/environments/production.rb` and restarts, then **reverts** (restores from backup, restarts, verifies `/rails/mailers` → 404 and admin login works). Verified baseline after the run: `show_previews=false`, `/rails/mailers`→404, admin login→302.
- Leg C leaves a throwaway victim user `victim_<suffix>@example.invalid` with a changed password (random suffix; harmless). The admin account is untouched.

## Research & references
- CWE-284 (improper access control), CWE-200 (info disclosure), CWE-640 (weak password-recovery / ATO). OWASP WSTG-ATHZ / A01:2021 Broken Access Control; OWASP "Forgot Password" cheat sheet (reset tokens must not be exposed). Technique applied: enumerate the preview routes unauthenticated, pull the reset `.eml`, extract the live token, and drive the shipped reset controller to take over the account.
- The `show_previews`-drops-`require_local!` footgun is widely discussed (no CVE); the live-reset-token → ATO sharpening is a possibly-novel escalation on top of it.
- Chains with VULN-011 (the leaked token is a stateless replayable bearer credential).

## If FAILED
n/a — CONFIRMED end-to-end.

## If NEEDS_MANUAL
n/a — all legs automated (the route leg via the self-reverting ENABLE_PREVIEWS=1 mode).

## If INTENDED
No. `show_previews` is documented as a plain on/off toggle with **no security caveat** in the guides; nothing tells an operator that enabling it outside development publishes an unauthenticated endpoint that renders live credentials. The inverted guard (`unless: :show_previews?`) is a genuine code defect independent of config — the local-only protection can never apply when the routes exist.
