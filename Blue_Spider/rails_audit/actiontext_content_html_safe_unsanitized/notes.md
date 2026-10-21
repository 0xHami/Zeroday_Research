# VULN-008 — ActionText::Content#html_safe / #to_html / #as_json return UNSANITIZED rich text

**Software**: Ruby on Rails
**Repository**: https://github.com/rails/rails
**Affected version**: 8.2.0.alpha (from `RAILS_VERSION`, confirmed in `activesupport/lib/active_support/gem_version.rb`) — commit-pinned: no tagged release
**Status**: CONFIRMED (the three methods return unsanitized markup; stored-XSS end-to-end requires an app rendering rich text via that footgun path)
**Severity (static)**: Medium/Low–Medium (CVSS base 5.4)
**Confidence**: 4/10
**Confidence reasoning**: The method behaviour is 100% proven (html_safe/to_html/as_json return raw markup flagged html_safe?; to_s sanitizes). Scored 4 as a framework-default bug because the idiomatic `<%= content %>` path is safe — exploitation needs the specific (if very natural, given the name) app misuse.
**Target commit**: c9e85dbe297e248dd2f217d04f84a94881ac046a
**Validated at**: 2026-10-03T02:32:00Z

## Preconditions
- None beyond the framework for the method behaviour. End-to-end stored XSS needs app code that renders stored rich text via `content.html_safe`, `raw(content)`, or by JSON-serializing a bare `Content` and injecting it as HTML client-side. The idiomatic `<%= content %>` is safe.

## Request
Framework-library finding — exercised via `bin/rails runner` (see `evidence/runner.rb`). The stock harness has no view rendering Action Text via the footgun path.

## Response
See `response.txt`:
```
@@to_s script=false onerror=false
@@html_safe script=true onerror=true is_html_safe=true
@@to_html script=true onerror=true
@@as_json script=true onerror=true
@@sample to_s="<div class=\"trix-content\">\n  <p>hi</p><img src=\"x\">alert(2)\n</div>\n"
@@sample html_safe="<p>hi</p><img src=\"x\" onerror=\"alert(1)\"><script>alert(2)</script>"
```

## Observation
For the rich-text value `<p>hi</p><img src=x onerror=alert(document.cookie)><script>alert(1)</script>`:
- `to_s` (the `<%= content %>` path) **scrubbed** both the `<script>` and the `onerror` attribute — the idiomatic render path is safe.
- `html_safe` returned the `<script>` and `onerror` **verbatim**, and the returned buffer is `html_safe? == true`, so Action View emits it **without escaping**.
- `to_html` and `as_json` likewise returned the raw, unsanitized markup.

So a method literally named `html_safe` returns XSS-capable markup flagged safe-to-emit — the inverse of its name's contract. The `as_json` leg extends the trap to JSON APIs that inject the value as HTML client-side.

## Side effects
None (pure in-memory `ActionText::Content`).

## Research & references
- OWASP XSS Prevention Cheat Sheet / WSTG-CLNT (stored XSS); the Rails Security Guide's "never trust `html_safe`/`raw` on user content" guidance. Technique applied: render the same payload through the sanitizing (`to_s`) and the raw (`html_safe`/`to_html`/`as_json`) paths and compare, and check the `html_safe?` flag that governs auto-escaping.
- rails/rails#54087 (ergonomics of this footgun). CWE-79.

## If FAILED
n/a — CONFIRMED (method behaviour).

## If NEEDS_MANUAL
To observe the script *firing in a browser*, add a view that renders stored rich text via `<%= post.content.body.html_safe %>` (or `raw`), store the payload as a low-priv user, and load the page as a victim — the `onerror`/`<script>` executes. This is an app-code render-path item, not a framework reproduction gap; the framework behaviour that makes it XSS is fully shown here.

## If INTENDED
Sanitize-on-render (via `to_s`) is the documented, deliberate design, and "never `html_safe`/`raw` rich text" is standard guidance — so this is a **footgun**, not a framework-default vulnerability. It is carried (not INTENDED) because a public method named `html_safe` returning unsanitized markup is a genuine API-contract trap a reasonable developer falls into; the fix is to stop that method returning raw markup.
