"""
Shared helpers for ClassroomIO dynamic-validation exploits (Stage 10).

Every exploit imports from this module so that individual `automation.py`
files stay short and focused on the specific vulnerability. It centralises:

  * config (base URLs / admin creds / org id) read from the environment,
  * a colored, TTY-aware `log()` helper (plain when captured to a file),
  * a thin `Client` wrapper over requests.Session (cookie jar, cio-org-id
    header, origin header so better-auth/CORS accept the request),
  * the account/state primitives the exploits reuse as *preconditions*:
      - admin_login()        -> logged-in ADMIN session
      - anon_session()       -> unauthenticated better-auth anonymous session
      - signup()             -> fresh account (session, empty orgRoles)
      - make_student()       -> a real STUDENT member of the org, enrolled in a course
      - create_course()      -> a course owned by the caller
      - course_share_link()  -> a reusable COURSE join link token

All primitives use the app's own HTTP API (never direct DB writes), so the
state they create is exactly what a real attacker/admin would produce.

Runtime facts (manifest classroomio_summary.md, commit 0c356ad):
  API        http://localhost:21527
  dashboard  http://localhost:21526   (a trusted CORS origin)
  admin      admin@cvehunt.local / CveHunt!Admin2026
  org id     48bbdff8-2ad5-46a3-a259-2ca3d52677dd
  roles      ADMIN=1 TUTOR=2 STUDENT=3
  session    cookie classroomio.session_token (HttpOnly, SameSite=Lax)
"""

import os
import sys
import secrets
import subprocess
import requests

# ---- config (env-overridable, defaults match the manifest Runtime block) ----
API = os.environ.get("API_URL", "http://localhost:21527")           # Hono API
BASE_URL = os.environ.get("BASE_URL", "http://localhost:21526")      # dashboard (trusted origin)
ADMIN_EMAIL = os.environ.get("ADMIN_USER", "admin@cvehunt.local")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "CveHunt!Admin2026")
ORG_ID = os.environ.get("ORG_ID", "48bbdff8-2ad5-46a3-a259-2ca3d52677dd")
ADMIN_USER_ID = os.environ.get("ADMIN_USER_ID", "0419cf7a-0f8b-4797-b953-e8747cc41939")

ROLE = {"ADMIN": 1, "TUTOR": 2, "STUDENT": 3}

# ---- colored, TTY-aware logging (plain in a captured run.log) ----------------
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag: str, msg: str) -> None:
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}", flush=True)
    else:
        print(f"[{tag}] {msg}", flush=True)


def banner(vuln_id: str, title: str) -> None:
    line = "=" * 72
    print(line, flush=True)
    print(f"{vuln_id}: {title}", flush=True)
    print(f"target: API={API}  dashboard={BASE_URL}", flush=True)
    print(line, flush=True)


def verdict(vuln_id: str, status: str, msg: str) -> None:
    """Final one-line verdict, colored green/red/yellow by status."""
    color = {"CONFIRMED": "32", "FAILED": "31", "NEEDS_MANUAL": "33"}.get(status, "0")
    text = f"==> {vuln_id}: {status} — {msg}"
    if _USE_COLOR:
        print(f"\033[1;{color}m{text}\033[0m", flush=True)
    else:
        print(text, flush=True)


def rid(prefix: str = "x") -> str:
    """Random suffix so every run is independent (no orphaned-state collisions)."""
    return f"{prefix}_{secrets.token_hex(4)}"


PG_CONTAINER = os.environ.get("PG_CONTAINER", "cio-postgres")


def psql(sql: str):
    """Run a read query against the target Postgres for ground-truth side-effect
    verification. Returns stripped stdout (rows as text) or None on error."""
    try:
        return subprocess.check_output(
            ["docker", "exec", PG_CONTAINER, "psql", "-U", "postgres", "-d", "classroomio",
             "-t", "-A", "-c", sql],
            text=True, timeout=25).strip()
    except Exception as e:
        log("INFO", f"  (psql failed: {e})")
        return None


# ---- HTTP client -------------------------------------------------------------
class Client:
    """requests.Session wrapper with a cookie jar and ClassroomIO conventions.

    - Adds the `Origin: <dashboard>` header (a trusted CORS origin) so
      better-auth accepts sign-in/sign-up as first-party.
    - `org=True` attaches the `cio-org-id` header org-scoped routes require.
    """

    def __init__(self, label: str = "client"):
        self.s = requests.Session()
        self.label = label
        self.user = None  # populated after login/signup
        # Test-isolation only: the global limiter keys authenticated requests per
        # user, but unauthenticated requests share the socket-IP bucket. Setting
        # CVEHUNT_XFF gives concurrent runs distinct rate-limit buckets (the API
        # trusts X-Forwarded-For — that bypassability is itself VULN-036). Off by default.
        self._xff = os.environ.get("CVEHUNT_XFF")

    def _url(self, path: str) -> str:
        return path if path.startswith("http") else API + path

    def request(self, method: str, path: str, org=False, org_id=None, headers=None, **kw):
        h = {"Origin": BASE_URL}
        if self._xff:
            h["X-Forwarded-For"] = self._xff
        if headers:
            h.update(headers)
        if org:
            h["cio-org-id"] = org_id or ORG_ID
        kw.setdefault("timeout", 30)
        kw.setdefault("allow_redirects", False)
        return self.s.request(method, self._url(path), headers=h, **kw)

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)

    def put(self, path, **kw):
        return self.request("PUT", path, **kw)

    def patch(self, path, **kw):
        return self.request("PATCH", path, **kw)

    def delete(self, path, **kw):
        return self.request("DELETE", path, **kw)

    def session_info(self) -> dict:
        """Return better-auth get-session payload (includes orgRoles), or {}."""
        r = self.s.get(API + "/api/auth/get-session", headers={"Origin": BASE_URL}, timeout=30)
        try:
            data = r.json()
        except Exception:
            return {}
        return data or {}

    def org_roles(self) -> dict:
        info = self.session_info()
        return (info or {}).get("orgRoles", {}) if isinstance(info, dict) else {}


# ---- account primitives ------------------------------------------------------
def admin_login(label: str = "admin") -> Client:
    c = Client(label)
    r = c.post("/api/auth/sign-in/email", json={"email": ADMIN_EMAIL, "password": ADMIN_PASS})
    if r.status_code != 200:
        raise RuntimeError(f"admin login failed: {r.status_code} {r.text[:300]}")
    info = c.session_info()
    c.user = (info or {}).get("user")
    return c


def anon_session(label: str = "anon") -> Client:
    """Mint an unauthenticated better-auth anonymous session (VULN-018 primitive)."""
    c = Client(label)
    r = c.post("/api/auth/sign-in/anonymous", json={})
    if r.status_code != 200:
        raise RuntimeError(f"anonymous sign-in failed: {r.status_code} {r.text[:300]}")
    info = c.session_info()
    c.user = (info or {}).get("user")
    return c


def signup(email=None, password="CveHunt!Pass2026", name=None, org_id=ORG_ID, label=None) -> Client:
    """Create a fresh account. Passes cio-org-id so the self-hosted signupGuard
    admits the signup. The new account has a session but EMPTY orgRoles until it
    accepts an invite (see make_student)."""
    email = email or f"{rid('u')}@cvehunt.local"
    name = name or email.split("@")[0]
    c = Client(label or email)
    r = c.post("/api/auth/sign-up/email",
               json={"email": email, "password": password, "name": name},
               headers={"cio-org-id": org_id})
    if r.status_code not in (200, 201):
        raise RuntimeError(f"signup failed for {email}: {r.status_code} {r.text[:300]}")
    info = c.session_info()
    c.user = (info or {}).get("user")
    c.email = email
    c.password = password
    return c


def create_course(admin: Client, title=None, ctype="SELF_PACED", org_id=ORG_ID) -> dict:
    """Create a course as an org ADMIN. Returns the created course object
    (includes id, groupId, slug…)."""
    title = title or f"CveHunt {rid('course')}"
    r = admin.post("/course", org=True, org_id=org_id,
                   json={"title": title, "description": f"seed {title}",
                         "type": ctype, "organizationId": org_id})
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create_course failed: {r.status_code} {r.text[:400]}")
    data = r.json().get("data", {})
    # response shape: data = { course: {...}, groupId, memberId }
    course = dict(data.get("course", data))
    course.setdefault("groupId", data.get("groupId"))
    course["memberId"] = data.get("memberId")
    return course


def course_share_link(admin: Client, course_id: str, org_id=ORG_ID) -> str:
    """Create/fetch the reusable COURSE join link and return its token."""
    r = admin.post(f"/course/{course_id}/invites/link", org=True, org_id=org_id, json={})
    if r.status_code not in (200, 201):
        raise RuntimeError(f"course_share_link failed: {r.status_code} {r.text[:400]}")
    data = r.json().get("data", {})
    token = data.get("token") or data.get("link", "").rstrip("/").split("/")[-1]
    if not token:
        raise RuntimeError(f"no token in share-link response: {data}")
    return token


def make_student(admin: Client, course_id=None, org_id=ORG_ID, label=None):
    """Provision a real STUDENT member of the org, enrolled in `course_id`
    (a fresh course is created if none is given), entirely via the app API:

      admin creates course + COURSE share link  ->
      fresh signup                              ->
      new user accepts the share link           ->  STUDENT membership (roleId=3)

    Returns (student_client, info_dict) where info_dict has course_id, group_id,
    student user id/email, and the accepted role.
    """
    if course_id is None:
        course = create_course(admin, org_id=org_id)
        course_id = course["id"]
        group_id = course.get("groupId") or course.get("group", {}).get("id")
    else:
        group_id = None

    token = course_share_link(admin, course_id, org_id=org_id)

    stu = signup(org_id=org_id, label=label or "student")
    r = stu.post(f"/invite/r/{token}/accept", json={})
    if r.status_code not in (200, 201):
        raise RuntimeError(f"accept share link failed: {r.status_code} {r.text[:400]}")

    roles = stu.org_roles()
    info = {
        "course_id": course_id,
        "group_id": group_id,
        "share_token": token,
        "user_id": (stu.user or {}).get("id"),
        "email": getattr(stu, "email", None),
        "org_roles": roles,
        "role_in_org": roles.get(org_id),
    }
    return stu, info


if __name__ == "__main__":
    # Smoke test: exercise every primitive and print the resulting state.
    banner("RECON", "shared-primitive smoke test")
    log("SETUP", "admin login")
    admin = admin_login()
    log("OK", f"admin user={admin.user.get('id') if admin.user else None} roles={admin.org_roles()}")

    log("SETUP", "anonymous session (VULN-018 primitive)")
    try:
        anon = anon_session()
        log("OK", f"anon user={anon.user.get('id') if anon.user else None} "
                  f"isAnonymous={anon.user.get('isAnonymous') if anon.user else None} roles={anon.org_roles()}")
    except Exception as e:
        log("FAIL", f"anon: {e}")

    log("SETUP", "create course as admin")
    course = create_course(admin)
    log("OK", f"course id={course['id']} group={course.get('groupId')}")

    log("SETUP", "provision a STUDENT via course share-link accept")
    stu, info = make_student(admin, course_id=course["id"])
    log("OK", f"student user={info['user_id']} role_in_org={info['role_in_org']} (expect 3=STUDENT)")
    print("RECON_STATE:", info, flush=True)
