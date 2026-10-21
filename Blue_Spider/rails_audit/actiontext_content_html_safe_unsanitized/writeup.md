# VULN-008 — `ActionText::Content#html_safe` / `#to_html` / `#as_json` return unsanitized rich text

| | |
|---|---|
| **ID** | VULN-008 |
| **Software** | Ruby on Rails |
| **Repository** | https://github.com/rails/rails |
| **Affected version** | 8.2.0.alpha (commit-pinned; no tagged release) |
| **Commit** | `c9e85dbe297e248dd2f217d04f84a94881ac046a` |
| **Severity** | Medium (Low–Medium) |
| **CVSS 3.1** | 5.4 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` |
| **Status** | CONFIRMED (dynamic) — the three methods return unsanitized markup; browser-firing needs an app rendering via that path |
| **Confidence** | 4/10 |
| **Confidence reasoning** | Method behaviour 100% proven; the idiomatic `<%= content %>` path is safe, so exploitation needs the specific (natural, given the name) app misuse. |
| **Auth required** | A low-privilege user who can store rich text (comment/post/message body) |
| **What an attacker gains** | Stored XSS in a viewer's authenticated context (session/CSRF-token theft, actions as the victim, takeover of a privileged moderator) when the app renders stored rich text via `.html_safe`/`raw`/`as_json`. |

## Summary
Action Text's security model is **sanitize-on-render**: `<%= content %>` goes through `to_s`, which scrubs. But a public method literally named `html_safe` is delegated to `to_html`, which returns the **raw, unsanitized** stored markup wrapped in an `ActiveSupport::SafeBuffer` — so Action View emits it without escaping. `to_html` and `as_json` return the same raw markup. An app that renders stored rich text via `content.html_safe`, `raw(content)`, or by JSON-serializing a bare `Content` and injecting it client-side therefore emits attacker `<script>`/`<img onerror>` verbatim. Proven live: for a payload containing both, `to_s` stripped them while `html_safe`/`to_html`/`as_json` returned them intact, with `html_safe? == true`.

## How it works (mechanism & code trace)
**`html_safe` is delegated to the unsanitized `to_html`** — `targets/rails/actiontext/lib/action_text/content.rb:30`:
```ruby
delegate :blank?, :empty?, :html_safe, :present?, to: :to_html   # by-product: html_safe => to_html
```
**`to_html` returns the raw fragment; `as_json` serialises it raw** — `content.rb:168-170,191-193`:
```ruby
def to_html
  fragment.to_html          # canonicalised but NOT scrubbed
end
def as_json(*)
  to_html                   # raw, unsanitized
end
```
**The safe path used by `<%= %>`** — `content.rb:187-189`:
```ruby
def to_s
  to_rendered_html_with_layout   # -> render_action_text_content -> sanitize_action_text_content
end
```
`fragment.to_html` canonicalises the HTML but does **not** run the sanitizer; `to_s` does. Because the delegate wraps the result as a `SafeBuffer` (`html_safe?` true — confirmed live), Action View treats it as already-safe and emits it without HTML-escaping.

**The exact defect:** three public methods — one of them named `html_safe`, the core Rails XSS-safety primitive — return XSS-capable markup flagged safe, the opposite of what the name advertises.

## Why it is a vulnerability
The violated boundary is output encoding: stored, attacker-authored markup reaches a viewer's browser as active HTML/JS instead of inert sanitized content. `html_safe` is universally understood in Rails to mean "this string is safe to emit." Here it returns unsanitized rich text, inverting that contract, and `as_json` extends the trap to JSON APIs. The live comparison is decisive: the *same* payload is scrubbed by `to_s` and preserved verbatim by `html_safe`/`to_html`/`as_json` — so the difference is purely which method the app happened to call, and nothing in the name warns the developer. This is stored XSS on misuse driven by a misleading API (CWE-79), not a theoretical concern: the markup emitted is `<img src="x" onerror="alert(1)"><script>alert(2)</script>`.

## Reproduction
> Not reachable on the stock harness (no view renders Action Text via the footgun path). Validated at the framework layer where the defect lives; the app-side trigger is one view line.
1. `cd exploits/VULN-008 && ./run.sh`.
2. Expected tail:
   ```
   [PROOF] to_s (the <%= content %> path) SCRUBBED both <script> and onerror — the idiomatic path is safe
   [PROOF] html_safe returned the <script> and onerror VERBATIM, flagged html_safe? = true ...
   [PROOF] to_html and as_json also return the raw, unsanitized markup ...
   ==> VULN-008: CONFIRMED ...
   ```
To see it fire in a browser: store `<img src=x onerror=alert(document.cookie)>` as a rich-text body (low-priv user), render it in a view with `<%= post.content.body.html_safe %>`, and load the page as a victim. `response.txt` holds the decisive `to_s` vs `html_safe` outputs; `evidence/runner.rb` the exact script.

## Impact
- Stored XSS in the victim's authenticated context: session/CSRF-token theft, requests as the victim, and takeover of a higher-privilege viewer (e.g. an admin moderating user-submitted rich text).
- **PR:L / UI:R:** a low-priv user stores the payload; a viewer must load the rendering page. **S:C:** the script runs in the viewer's browser session, a different component than the storage controller.
- Bounded at Medium because the idiomatic `<%= content %>` path is safe; it requires the app to use the footgun method.

## Suggested fix
At `targets/rails/actiontext/lib/action_text/content.rb:30`, remove `html_safe` from the `delegate … to: :to_html` list so it falls back to the sanitized `to_s` (or drop it so callers must choose explicitly); make `as_json` (`:191-193`) return sanitized HTML or clearly non-HTML-safe output. At minimum, rename/annotate so a `html_safe`-named method never returns unsanitized markup. Principle: a method named after a safety guarantee must honour it. App-side: never `html_safe`/`raw` Action Text content — rely on `<%= content %>`.

## References
- CWE-79 (stored XSS); OWASP XSS Prevention Cheat Sheet; OWASP WSTG-CLNT-01.
- rails/rails#54087 (the ergonomics of this footgun); Rails Security Guide (sanitize-on-render; avoid `html_safe`/`raw` on user content).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 45 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `gh api search/issues q='repo:rails/rails ActionText html_safe to_html unsanitized'` — 1 result: PR #50257.
2. WebFetch `github.com/rails/rails/pull/50257` ("Sanitize and treat `ActionText::Content#to_{trix_html,html}` as safe", Dec 2023, closed unmerged) — maintainer georgeclaghorn stated `to_html` output is unsanitized and must not be marked `html_safe` because sanitization happens in `render_action_text_content`; the `delegate :html_safe ... to: :to_html` footgun itself was not raised.
3. `gh api search/issues q='repo:rails/rails "ActionText::Content" html_safe OR as_json XSS'` and `... actiontext "html_safe" content delegate` — no issue describing `Content#html_safe` or `#as_json` returning unsanitized markup.
4. `gh api search/issues q='repo:rails/rails actiontext as_json unsanitized OR raw'` — only `ActionText::Attachable#as_json` fixes (#49272, #46126); different method/class.
5. WebFetch `github.com/rails/rails/issues/54087` — ergonomics request (sanitized output without the Trix layout); no mention of `html_safe`/`to_html`/`as_json`; closed stale.
6. GitHub advisory DB listing for RubyGems `actiontext` (gh GraphQL) — CVE-2024-32464 (ContentAttachment unsanitized HTML), CVE-2024-34341 (Trix), CVE-2024-47888 (ReDoS); none concerns `Content#html_safe`/`to_html`/`as_json`.
7. `gh api repos/rails/rails/contents/actiontext/lib/action_text/content.rb?ref=main` — line 30 still `delegate :blank?, :empty?, :html_safe, :present?, to: :to_html # Delegating to to_html to avoid including the layout` (deliberate, unchanged).

**Related but distinct public references** (same class or component, not this bug):
- PR #50257 — public maintainer acknowledgement that `to_html` is unsanitized and that marking it `html_safe` would be wrong; partial overlap (same method, same property) but it does not identify the `html_safe` delegation or `as_json`.
- CVE-2024-32464 / GHSA-prjp-h48f-jgf6 — unsanitized HTML in `ContentAttachment` within `rich_text_area`; different sink.
- Rails Security Guide — generic "do not `html_safe`/`raw` user content" guidance (generic caution, not this bug).

**Reasoning:** Nothing public reports that `ActionText::Content#html_safe` returns unsanitized markup flagged safe, or that `as_json` serialises raw markup; the delegation is still on `main` with a comment showing it is intentional. Confidence is below 50 because the maintainers' public position (PR #50257) already treats `to_html` as deliberately unsanitized with sanitize-on-render, so they are likely to classify this as documented API behaviour/app misuse rather than a framework vulnerability. WebSearch queries for this folder could not be run (session budget exhausted).
