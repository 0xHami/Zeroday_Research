# VULN-001 — Unauthenticated mailer previews → live reset-token leak → account takeover

| | |
|---|---|
| **ID** | VULN-001 |
| **Software** | Ruby on Rails |
| **Repository** | https://github.com/rails/rails |
| **Affected version** | 8.2.0.alpha (commit-pinned; no tagged release) |
| **Commit** | `c9e85dbe297e248dd2f217d04f84a94881ac046a` |
| **Severity** | High (Critical when `show_previews` is enabled) |
| **CVSS 3.1** | 9.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (scored for the enabled config) |
| **Status** | CONFIRMED (dynamic) — unauth `/rails/mailers` exposure + live admin reset-token leak + leaked-token→ATO, all shown over HTTP; requires `config.action_mailer.show_previews=true` (documented operator toggle, off by default) |
| **Confidence** | 7/10 |
| **Confidence reasoning** | Entire chain proven over HTTP (unauth .eml returned the admin's live token resolving to id 1; inverted guard in source; leaked token → full ATO). Held at 7 because it is gated on the operator enabling a non-default feature. |
| **Auth required** | None — unauthenticated, remote, any origin (preview endpoints are GET) |
| **What an attacker gains** | Unauthenticated account takeover of `User.take` (typically the admin) plus bulk disclosure of all mailer content. |

## Summary
`Rails::MailersController` renders mailer previews into HTTP responses. Its routes mount **only** when `config.action_mailer.show_previews` is true, and its only access-control filter — `require_local!` — is skipped **exactly** when `show_previews?` is true (`before_action :require_local!, unless: :show_previews?`). So whenever the preview endpoints are reachable, they are reachable by any unauthenticated remote client: the loopback guard is vestigial. The Rails 8 auth generator's default `PasswordsMailerPreview#reset` renders `PasswordsMailer.reset(User.take)`, whose view embeds a **genuine, in-window** `password_reset_token` for the admin. The shipped unauthenticated `PasswordsController#update` then accepts that token to set a new password → full account takeover. Validated end-to-end over HTTP: with the flag enabled, an unauthenticated GET of the preview `.eml` returned the admin's live token (resolved to id 1 / admin@example.com), and a leaked reset token set a new password and logged in.

## How it works (mechanism & code trace)
**The inverted guard** — `targets/rails/railties/lib/rails/mailers_controller.rb:9-11`:
```ruby
around_action :set_locale, only: [:preview, :download]
before_action :find_preview, only: [:preview, :download]
before_action :require_local!, unless: :show_previews?        # guard inverted
```
**The predicate** — `mailers_controller.rb:65-67`: `show_previews? -> ActionMailer::Base.show_previews`.
**The routes mount only when the flag is on** — `targets/rails/actionmailer/lib/action_mailer/railtie.rb:81-87`:
```ruby
if options.show_previews
  app.routes.prepend do
    get "/rails/mailers" => "rails/mailers#index", internal: true
    get "/rails/mailers/download/*path" => "rails/mailers#download", internal: true
    get "/rails/mailers/*path" => "rails/mailers#preview", internal: true
  end
end
```
Routes exist *iff* `show_previews?`; the guard is suppressed *iff* `show_previews?` — so the local-only restriction can never apply when the endpoints exist. (Confirmed live from source: `@@legB guard_line="before_action :require_local!, unless: :show_previews?"`, `routes_mounted_iff_show_previews=true`.)

**The default preview renders a live secret** — `.../previews/passwords_mailer_preview.rb:4-6` (`PasswordsMailer.reset(User.take)`) and `app/views/passwords_mailer/reset.html.erb` (`edit_password_url(@user.password_reset_token)`). `password_reset_token` is a genuine signed token defined by `has_secure_password` (`secure_password.rb:245-247`), valid 15 minutes, bound to the user id + bcrypt salt. (Live: the rendered preview body contained a token that `find_by_token_for(:password_reset, …)` resolved to **id 1 / admin@example.com**.)

**The shipped reset controller completes the takeover** — `app/controllers/passwords_controller.rb`:
```ruby
before_action :set_user_by_token, only: %i[ edit update ]   # User.find_by_token_for(:password_reset, params[:token])
def update
  if @user.update(params.permit(:password, :password_confirmation))
    @user.sessions.destroy_all
    redirect_to new_session_path, notice: "Password has been reset."
```
No authentication — only possession of the token. (Live: `PATCH /passwords/<token>` → 302 "Password has been reset."; login with the new password → 302 → root.)

**The exact defect:** a single business toggle (`show_previews`) simultaneously mounts the preview routes **and** disables the only access-control filter on them, and the default preview turns that surface into a live-credential surface.

## Why it is a vulnerability
Two trust boundaries are crossed. First, the local-request/authenticated-operator boundary: preview content and the `require_local!` gate are meant for developers on loopback, but enabling the feature exposes them to the whole network with the gate inverted off — textbook broken access control (the business toggle silently also disables authentication). Second, the credential boundary: mailer previews are assumed to render *sample* mail, but the default scaffold renders mail built from a **real user record and a real signed token**, so reading a "preview" yields a valid admin reset link. The attacker's capability (unauthenticated GET → admin password reset) vastly exceeds what a preview feature is supposed to grant (developers eyeballing templates). The dynamic proof removes any doubt that the leaked token is "just a sample": it resolved to the real admin and drove a real password change + login.

## Reproduction
From a clean state (`docker compose -p cvehunterlab_rails up -d`):
1. `cd exploits/VULN-001 && ENABLE_PREVIEWS=1 ./run.sh` — the script:
   - **Leg A:** renders the reset preview in-process and resolves its token → admin (id 1);
   - **Leg B:** reads the inverted guard from the running source;
   - **Leg C:** creates a throwaway victim, and from its leaked reset token does `GET /passwords/:token/edit` → `PATCH /passwords/:token` (new password) → `POST /session` (login) = ATO;
   - **Route demo (ENABLE_PREVIEWS=1):** enables `config.action_mailer.show_previews=true`, `GET`s the preview `.eml` with **no cookie**, extracts the admin's live token, then **reverts** and verifies `/rails/mailers` → 404.
2. Expected tail:
   ```
   [PROOF] the reset preview renders a LIVE password_reset_token that resolves to User.take = the admin ...
   [PROOF] the require_local! guard is inverted ... vestigial
   [PROOF] the leaked reset token set a NEW password and the attacker logged in ... full account takeover
   [PROOF] UNAUTHENTICATED GET of the preview .eml returned the admin's live password-reset token ...
   ==> VULN-001: CONFIRMED ...
   ```
Without `ENABLE_PREVIEWS=1` the run is non-mutating (Legs A+B+C only) and still CONFIRMED. Observable proof: `evidence/reset_email.eml` (unauth admin `.eml`), `evidence/leaked_admin_token.txt`, `evidence/legC_ato.txt`, `run.log`.

## Impact
- **Unauthenticated, no-interaction remote account takeover** of `User.take` (the first-seeded admin in most apps) via the leaked live reset token, plus **bulk disclosure** of every registered mailer preview (order confirmations, invitations, one-time codes, PII).
- **Pre-auth:** entirely — the preview endpoints are GET with no cookie/token/Sec-Fetch-Site.
- **Prerequisite:** `config.action_mailer.show_previews = true` outside development (a documented toggle the guides present with no security caveat) — Critical on any deployment that has set it; High overall because it is a non-default toggle.
- **Chaining:** this is the concrete, high-impact realization of **VULN-011** — the leaked `password_reset_token` is a stateless replayable bearer credential valid until the password changes, which is exactly why reading it once yields takeover.

## Suggested fix
1. **Fix the inverted guard** at `targets/rails/railties/lib/rails/mailers_controller.rb:11`: keep `before_action :require_local!` unconditional (or add an app-supplied auth callback) so the local-only check runs **even when previews are enabled**:
   ```ruby
   before_action :require_local!          # not `unless: :show_previews?`
   ```
2. **Do not render live secrets in previews:** the generated `PasswordsMailerPreview#reset` should use a throwaway/fixture user or a clearly-fake token so a preview never emits a valid `password_reset_token`.
3. **Document loudly** that `show_previews` outside development exposes an unauthenticated endpoint that can render mail containing live tokens; recommend gating it behind app auth or an internal network. Principle: a feature toggle must never silently disable authentication.

## References
- CWE-284 (improper access control), CWE-200 (information exposure), CWE-640 (weak password recovery / ATO).
- OWASP A01:2021 Broken Access Control; OWASP WSTG-ATHZ; "Forgot Password" cheat sheet (reset tokens must never be exposed).
- Chains with VULN-011 (stateless replayable reset token).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 50 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `gh api search/issues q='repo:rails/rails show_previews require_local'` — 0 results.
2. `gh api search/issues q='repo:rails/rails PasswordsMailerPreview OR "passwords_mailer_preview"'` — 0 results.
3. `gh api search/issues q='repo:rails/rails "mailer previews" security OR unauthenticated OR production'` — 64 hits, all functional (iframe content, scrollbars, authentication generator test files); none reports remote exposure or token leakage.
4. `gh api search/issues q='repo:rails/rails mailers controller "require_local"'` — 0 results.
5. GitHub advisory DB listing for RubyGems `railties` and `actionmailer` (gh GraphQL) — only CVE-2019-5420 (railties secret_key_base) and ReDoS CVE-2024-47889 (actionmailer); no advisory on mailer previews.
6. WebFetch `raw.githubusercontent.com/rails/rails/main/railties/lib/rails/mailers_controller.rb` — `before_action :require_local!, unless: :show_previews?` is still present with no explanatory comment; the design is public source but not documented as a security boundary.

**Related but distinct public references** (same class or component, not this bug):
- The `config.action_mailer.show_previews` option is documented in the Rails guides as a plain toggle (default true in development); that is a generic configuration note, not a disclosure of this chain.
- CVE-2019-5420 / GHSA-m42h-mh85-4qgc — railties, unrelated (development secret).

**Reasoning:** No advisory, issue or discussion describes the combination of (a) the guard being disabled exactly when the preview routes are mounted and (b) the Rails 8 authentication generator's default preview rendering a live `password_reset_token` for `User.take`. However, the inverted guard is deliberate, publicly visible code and the toggle is off outside development by default, so Rails maintainers are likely to classify the exposure as an operator misconfiguration; the live-token sharpening is the only clearly novel element. Hence NOT KNOWN at mid confidence. WebSearch queries for this folder could not be run (session budget exhausted).
