
$stdout.sync = true
html = '<p>hi</p><img src=x onerror=alert(document.cookie)><script>alert(1)</script>'
c = ActionText::Content.new(html)
to_s      = c.to_s                      # idiomatic <%= content %> path
html_safe = c.html_safe                 # the footgun
to_html   = c.to_html
as_json   = c.as_json
puts "@@to_s script=#{to_s.include?('<script>')} onerror=#{to_s.include?('onerror')}"
puts "@@html_safe script=#{html_safe.include?('<script>')} onerror=#{html_safe.include?('onerror')} is_html_safe=#{html_safe.html_safe?}"
puts "@@to_html script=#{to_html.include?('<script>')} onerror=#{to_html.include?('onerror')}"
puts "@@as_json script=#{as_json.to_s.include?('<script>')} onerror=#{as_json.to_s.include?('onerror')}"
puts "@@sample to_s=#{to_s.inspect}"
puts "@@sample html_safe=#{html_safe.inspect}"
puts "@@done"
