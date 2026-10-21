"""
joomla_common.py — shared setup helpers for the joomla-cms exploit suite.

This module is NOT where the vulnerabilities live. It only automates the boring,
identical preconditions every exploit needs: logging into the Joomla backend,
scraping the per-session CSRF form token out of a page, creating the
low-privileged backend users some findings require, and reading captured mail.

Each finding's automation.py keeps its *exploit* logic inline and well-commented;
it imports these helpers purely for the plumbing so the exploit itself stays
readable. Config comes from environment variables with defaults matching the
lab manifest (claude_audit/joomla-cms/joomla-cms_summary.md).
"""
import os
import re
import sys
import subprocess
import secrets
import requests

# ---- lab config (defaults from the manifest ## Runtime block) ---------------
BASE_URL    = os.environ.get("BASE_URL", "http://localhost:34931").rstrip("/")
ADMIN_USER  = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS  = os.environ.get("ADMIN_PASS", "Admin!CVEhunt2026")
APP_CT      = os.environ.get("APP_CONTAINER", "cvehunterlab_joomla-cms_app")
COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT", "cvehunterlab_joomla-cms")

ADMIN_INDEX = f"{BASE_URL}/administrator/index.php"
SITE_INDEX  = f"{BASE_URL}/index.php"

# Joomla's per-session CSRF token appears in forms as <input name="<32hex>" value="1">
_TOKEN_RE = re.compile(r'name="([0-9a-f]{32})"\s+value="1"')
# ...and in every admin page's script-options JSON as "csrf.token":"<32hex>"
_TOKEN_RE2 = re.compile(r'"csrf\.token":"([0-9a-f]{32})"')


# ---- colored, file-safe logging (per CLAUDE.md evidence discipline) ---------
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}

def log(tag, msg):
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}", flush=True)
    else:
        print(f"[{tag}] {msg}", flush=True)

def banner(vuln_id, title):
    line = "=" * 72
    print(line, flush=True)
    print(f"{vuln_id}: {title}", flush=True)
    print(f"target: {BASE_URL}", flush=True)
    print(line, flush=True)

def verdict(vuln_id, status, msg):
    """Final one-line verdict, colored by status when on a TTY."""
    color = {"CONFIRMED": "32", "FAILED": "31", "NEEDS_MANUAL": "33",
             "INTENDED": "33"}.get(status, "0")
    text = f"==> {vuln_id}: {status} — {msg}"
    if _USE_COLOR:
        print(f"\033[1;{color}m{text}\033[0m", flush=True)
    else:
        print(text, flush=True)


# ---- token scraping ---------------------------------------------------------
def find_token(html):
    """Return the 32-hex CSRF form token present on a rendered Joomla page."""
    m = _TOKEN_RE.search(html) or _TOKEN_RE2.search(html)
    if not m:
        raise RuntimeError("no CSRF form token found on page")
    return m.group(1)


# ---- backend (administrator) login ------------------------------------------
def admin_session(user=None, passwd=None):
    """Log into /administrator and return an authenticated requests.Session."""
    user = user or ADMIN_USER
    passwd = passwd or ADMIN_PASS
    s = requests.Session()
    s.headers["User-Agent"] = "cvehunter-stage10"
    r = s.get(ADMIN_INDEX, timeout=30)
    token = find_token(r.text)
    r = s.post(ADMIN_INDEX, data={
        "username": user,
        "passwd": passwd,
        "option": "com_login",
        "task": "login",
        "return": "aW5kZXgucGhw",   # base64("index.php")
        token: "1",
    }, timeout=30, allow_redirects=True)
    # A successful backend login lands on the control panel (com_cpanel).
    cp = s.get(ADMIN_INDEX + "?option=com_cpanel", timeout=30)
    if "logout" not in cp.text.lower() and "task=logout" not in cp.text.lower():
        raise RuntimeError(f"admin login failed for {user!r} (no logout link on cpanel)")
    return s


def admin_edit_token(session, option, view=None):
    """Fetch an admin component page and return (html, token) for a save POST."""
    url = f"{ADMIN_INDEX}?option={option}"
    if view:
        url += f"&view={view}"
    r = session.get(url, timeout=30)
    return r.text, find_token(r.text)


# ---- backend user creation (via com_users save) -----------------------------
def create_backend_user(admin, group_id, prefix="pov"):
    """
    Create a backend user in the given usergroup via com_users and return
    (username, password, user_id). group_id: 6=Manager, 7=Administrator.
    Uses a random suffix so re-runs never collide.
    """
    suffix = secrets.token_hex(4)
    username = f"{prefix}_{suffix}"
    password = f"Pw!{secrets.token_hex(6)}Aa1"
    email = f"{prefix}_{suffix}@example.invalid"

    # New User form: task=user.add primes the state, final page is view=user&layout=edit
    r = admin.get(f"{ADMIN_INDEX}?option=com_users&task=user.add", timeout=30, allow_redirects=True)
    token = find_token(r.text)
    data = {
        "jform[name]": f"PoV {suffix}",
        "jform[username]": username,
        "jform[password]": password,
        "jform[password2]": password,
        "jform[email]": email,
        "jform[block]": "0",
        "jform[groups][]": str(group_id),
        "jform[id]": "0",
        "option": "com_users",
        "task": "user.save",
        token: "1",
    }
    r = admin.post(ADMIN_INDEX, data=data, timeout=30, allow_redirects=True)
    if "error" in r.url.lower() or "token" in r.text.lower() and "invalid" in r.text.lower():
        # fall through; caller verifies via login
        pass
    # Verify by logging the new user into the backend.
    try:
        us = admin_session(username, password)
        uid = _user_id_for(admin, username)
        return username, password, uid, us
    except Exception as e:
        raise RuntimeError(f"backend user {username} creation/login failed: {e}")


def _user_id_for(admin, username):
    """Look up a user id from the DB (read-only) for precise assertions."""
    out = db_query(
        f"SELECT id FROM jos_users WHERE username='{username}' LIMIT 1;"
    )
    m = re.search(r"(\d+)", out)
    return int(m.group(1)) if m else None


# ---- container / DB helpers (read-only unless noted) ------------------------
def docker_exec(args, check=True, text=True):
    """Run a command inside the app container; return stdout."""
    cmd = ["docker", "exec", APP_CT] + args
    p = subprocess.run(cmd, capture_output=True, text=text)
    if check and p.returncode != 0:
        raise RuntimeError(f"docker exec failed: {p.stderr}")
    return p.stdout


def db_query(sql):
    """Run a SQL query in the db container and return raw stdout."""
    cmd = ["docker", "exec", os.environ.get("DB_CONTAINER", "cvehunterlab_joomla-cms_db"),
           "mysql", "-ujoomla", "-pjoomla_db_Pw!2026", "joomla", "-N", "-e", sql]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"db query failed: {p.stderr}")
    return p.stdout


# ---- mail capture helpers ---------------------------------------------------
MAIL_DIR = "/var/mailcapture"

def mail_clear():
    """Delete all captured mail (reset between tests)."""
    subprocess.run(["docker", "exec", APP_CT, "sh", "-c", f"rm -f {MAIL_DIR}/*.eml 2>/dev/null || true"])

def mail_count():
    out = docker_exec(["sh", "-c", f"ls -1 {MAIL_DIR}/*.eml 2>/dev/null | wc -l"])
    return int(out.strip() or "0")

def mail_list():
    out = docker_exec(["sh", "-c", f"ls -1t {MAIL_DIR}/*.eml 2>/dev/null || true"])
    return [l for l in out.splitlines() if l.strip()]

def mail_read(path):
    return docker_exec(["sh", "-c", f"cat '{path}'"])

def mail_read_all():
    """Concatenate every captured message (newest first)."""
    paths = mail_list()
    return "\n\n==== NEXT MESSAGE ====\n\n".join(mail_read(p) for p in paths)
