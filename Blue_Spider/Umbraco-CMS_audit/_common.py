"""
Shared helpers for Umbraco-CMS (18.3.0-rc) stage-10 dynamic validation exploits.

Provides:
  * colored, tty-gated logging (log / banner / verdict) matching CLAUDE.md format
  * the full backoffice OAuth flow so exploits can obtain a Management-API bearer
    token as any user (admin or a provisioned low-priv user)
  * user/group provisioning helpers built on the Management API

Backoffice auth model (Umbraco 18):
  1. POST .../security/back-office/login {username,password}  -> sets UMB_UCONTEXT cookie
  2. GET  .../security/back-office/authorize?client_id=...&response_type=code&PKCE  (cookie)
        -> 302 redirect_uri?code=...
  3. POST .../security/back-office/token grant_type=authorization_code + code_verifier
        -> {access_token: ...}   (NOT redacted for the dev "umbraco-swagger" client)
  The real backoffice client "umbraco-back-office" has its token redacted to a
  __Host- cookie; we deliberately use the dev "umbraco-swagger" client so the bearer
  is returned in the body and usable from a script.
"""
import base64
import hashlib
import os
import secrets
import sys
import urllib.parse

import requests

BASE_URL = os.environ.get("BASE_URL", "http://localhost:29184").rstrip("/")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin@cvehunter.test")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "CveHunterUmbraco18!")

MGMT = f"{BASE_URL}/umbraco/management/api/v1"
SEC = f"{MGMT}/security/back-office"

# dev OAuth client present only in non-Production; its token is NOT redacted
SWAGGER_CLIENT = "umbraco-swagger"
SWAGGER_REDIRECT = f"{BASE_URL}/umbraco/openapi/oauth2-redirect.html"

# ---------------------------------------------------------------------------
# logging (colored on a tty, plain when captured to a file; honors NO_COLOR)
# ---------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag: str, msg: str) -> None:
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}", flush=True)
    else:
        print(f"[{tag}] {msg}", flush=True)


def banner(vuln_id: str, title: str, code_path: str) -> None:
    line = "=" * 78
    print(line, flush=True)
    print(f"{vuln_id}: {title}", flush=True)
    print(line, flush=True)
    log("INFO", f"target: {BASE_URL}")
    log("INFO", f"vulnerable code path: {code_path}")


def verdict(vuln_id: str, status: str, msg: str) -> int:
    """Print the final one-line verdict; return process exit code."""
    text = f"==> {vuln_id}: {status} — {msg}"
    if _USE_COLOR:
        color = {"CONFIRMED": "32", "FAILED": "31", "NEEDS_MANUAL": "33"}.get(status, "0")
        print(f"\033[1;{color}m{text}\033[0m", flush=True)
    else:
        print(text, flush=True)
    return 0 if status in ("CONFIRMED", "NEEDS_MANUAL") else 1


def rnd(n: int = 4) -> str:
    return secrets.token_hex(n)


# ---------------------------------------------------------------------------
# OAuth / auth
# ---------------------------------------------------------------------------
def _pkce():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def cookie_login(username: str, password: str) -> requests.Session:
    """Step 1: backoffice cookie login. Returns a session carrying UMB_UCONTEXT."""
    s = requests.Session()
    r = s.post(
        f"{SEC}/login",
        json={"username": username, "password": password},
        timeout=15,
    )
    if r.status_code != 200:
        raise RuntimeError(f"login failed for {username}: HTTP {r.status_code} {r.text[:200]}")
    return s


def get_bearer(session: requests.Session) -> str:
    """Steps 2+3: run the PKCE authorization-code flow via the dev swagger client
    on an already-cookie-authenticated session; return the raw access_token."""
    verifier, challenge = _pkce()
    state = rnd(8)
    params = {
        "client_id": SWAGGER_CLIENT,
        "response_type": "code",
        "redirect_uri": SWAGGER_REDIRECT,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    r = session.get(f"{SEC}/authorize", params=params, allow_redirects=False, timeout=15)
    if r.status_code not in (301, 302, 303, 307, 308):
        raise RuntimeError(f"authorize did not redirect: HTTP {r.status_code} {r.text[:300]}")
    loc = r.headers.get("Location", "")
    q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
    if "code" not in q:
        raise RuntimeError(f"no code in authorize redirect: {loc[:300]}")
    code = q["code"][0]
    r = session.post(
        f"{SEC}/token",
        data={
            "grant_type": "authorization_code",
            "client_id": SWAGGER_CLIENT,
            "code": code,
            "redirect_uri": SWAGGER_REDIRECT,
            "code_verifier": verifier,
        },
        timeout=15,
    )
    if r.status_code != 200:
        raise RuntimeError(f"token exchange failed: HTTP {r.status_code} {r.text[:300]}")
    tok = r.json().get("access_token")
    if not tok:
        raise RuntimeError(f"no access_token in token response: {r.text[:300]}")
    return tok


class ApiClient:
    """A Management-API client for a given user: cookie session + bearer token."""

    def __init__(self, username: str, password: str, label: str = ""):
        self.username = username
        self.label = label or username
        self.session = cookie_login(username, password)
        self.token = get_bearer(self.session)
        self.session.headers["Authorization"] = f"Bearer {self.token}"

    def req(self, method: str, path: str, **kw):
        url = path if path.startswith("http") else f"{MGMT}{path}"
        return self.session.request(method, url, timeout=30, **kw)

    def get(self, path, **kw):
        return self.req("GET", path, **kw)

    def post(self, path, **kw):
        return self.req("POST", path, **kw)

    def put(self, path, **kw):
        return self.req("PUT", path, **kw)

    def delete(self, path, **kw):
        return self.req("DELETE", path, **kw)


def admin_client() -> ApiClient:
    return ApiClient(ADMIN_USER, ADMIN_PASS, label="admin")


# ---------------------------------------------------------------------------
# provisioning helpers (create low-priv users / groups via admin)
# ---------------------------------------------------------------------------
def get_user_groups(admin: ApiClient) -> list:
    r = admin.get("/user-group?take=100")
    r.raise_for_status()
    return r.json().get("items", [])


def group_key_by_alias(admin: ApiClient, alias: str):
    for g in get_user_groups(admin):
        if g.get("alias") == alias:
            return g.get("id")
    return None


def create_user(admin: ApiClient, group_keys: list, name: str = None, email: str = None):
    """Create a backoffice user in the given user-groups.

    Returns dict {id, email, name}. The user has NO password yet; use
    set_password_for_user() to give it one so it can log in."""
    suffix = rnd(4)
    name = name or f"lowuser_{suffix}"
    email = email or f"lowuser_{suffix}@example.invalid"
    r = admin.post(
        "/user",
        json={"email": email, "userName": email, "name": name, "userGroupIds": [{"id": k} for k in group_keys]},
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create_user failed: HTTP {r.status_code} {r.text[:300]}")
    # id may be in Location header (CreatedAtId) or body
    uid = None
    loc = r.headers.get("Location", "")
    if loc:
        uid = loc.rstrip("/").split("/")[-1]
    if not uid:
        try:
            uid = r.json().get("id")
        except Exception:
            pass
    return {"id": uid, "email": email, "name": name}


def set_password_for_user(admin: ApiClient, user_id: str, password: str) -> None:
    r = admin.post(f"/user/{user_id}/change-password", json={"newPassword": password})
    if r.status_code not in (200, 204):
        raise RuntimeError(f"set password failed: HTTP {r.status_code} {r.text[:300]}")


# ---------------------------------------------------------------------------
# content provisioning (document type + documents), for BOLA/content findings
# ---------------------------------------------------------------------------
TEXTSTRING_DATATYPE = "0cc0eba1-9960-42c9-bf9b-60e150b429ae"  # Constants.DataTypes.Guids.Textstring


def create_doctype(admin: ApiClient, prop_alias: str = "body", name: str = None):
    """Create a minimal invariant document type allowed at root with one text property.
    Returns {id, alias, propAlias}."""
    import uuid
    suffix = rnd(4)
    name = name or f"AuditType {suffix}"
    alias = f"auditType{suffix}"
    dt_id = str(uuid.uuid4())
    prop_id = str(uuid.uuid4())
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
        "properties": [{
            "id": prop_id,
            "container": None,
            "sortOrder": 0,
            "alias": prop_alias,
            "name": prop_alias.capitalize(),
            "description": None,
            "dataType": {"id": TEXTSTRING_DATATYPE},
            "variesByCulture": False,
            "variesBySegment": False,
            "validation": {"mandatory": False, "mandatoryMessage": None, "regEx": None, "regExMessage": None},
            "appearance": {"labelOnTop": False},
        }],
        "containers": [],
        "allowedTemplates": [],
        "defaultTemplate": None,
        "cleanup": {"preventCleanup": False, "keepAllVersionsNewerThanDays": None, "keepLatestVersionPerDayForDays": None},
        "allowedDocumentTypes": [],
        "compositions": [],
        "parent": None,
    }
    r = admin.post("/document-type", json=payload)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create_doctype failed: HTTP {r.status_code} {r.text[:400]}")
    return {"id": dt_id, "alias": alias, "propAlias": prop_alias}


def create_document(admin: ApiClient, doctype_id: str, name: str, prop_alias: str, value: str, parent_id: str = None):
    """Create (save, unpublished) an invariant document. Returns its GUID id."""
    import uuid
    doc_id = str(uuid.uuid4())
    payload = {
        "id": doc_id,
        "parent": {"id": parent_id} if parent_id else None,
        "documentType": {"id": doctype_id},
        "template": None,
        "values": [{"culture": None, "segment": None, "alias": prop_alias, "value": value}],
        "variants": [{"culture": None, "segment": None, "name": name}],
    }
    r = admin.post("/document", json=payload)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create_document failed: HTTP {r.status_code} {r.text[:400]}")
    return doc_id


def create_group_with_start_node(admin: ApiClient, section_aliases: list, doc_start_node: str = None,
                                  has_doc_root: bool = False, name: str = None):
    """Create a user group with given sections and (optionally) a restricted document start node.
    Returns the group id (GUID)."""
    suffix = rnd(4)
    name = name or f"auditgrp_{suffix}"
    payload = {
        "name": name,
        "alias": f"auditgrp{suffix}",
        "icon": "icon-users",
        "sections": section_aliases,
        "languages": [],
        "hasAccessToAllLanguages": True,
        "documentStartNode": {"id": doc_start_node} if doc_start_node else None,
        "documentRootAccess": has_doc_root,
        "mediaStartNode": None,
        "mediaRootAccess": True,
        "permissions": [],
        "fallbackPermissions": ["Umb.Document.Read", "Umb.Document.Create", "Umb.Document.Update"],
        "documentPermissions": [],
    }
    r = admin.post("/user-group", json=payload)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create_group failed: HTTP {r.status_code} {r.text[:500]}")
    gid = None
    loc = r.headers.get("Location", "")
    if loc:
        gid = loc.rstrip("/").split("/")[-1]
    if not gid:
        try:
            gid = r.json().get("id")
        except Exception:
            pass
    return gid
