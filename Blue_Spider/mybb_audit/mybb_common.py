"""
mybb_common.py — shared provisioning & auth plumbing for the MyBB exploit suite.

This module holds ONLY the boring, security-irrelevant scaffolding that nearly
every per-finding exploit needs:

  * db(sql)          — run SQL inside the lab's MySQL container (lab provisioning
                       + reading side-effects for evidence). We own the lab, so
                       using the DB to *provision* test accounts / forums / flags
                       and to *observe* server-side effects is legitimate harness
                       work. The actual vulnerability in every finding is always
                       triggered over real HTTP against BASE_URL — never via SQL.
  * create_user()    — insert a fully-activated forum user. The lab has
                       regtype=verify (email activation) + CAPTCHA + a security
                       question on the public registration form; those are
                       anti-abuse controls, not the security boundary under test,
                       so we skip them and create the account directly, exactly as
                       an operator's "Add User" ACP action would. Password is a
                       standard bcrypt hash of the plaintext (verified empirically
                       against the shipped MyBB 1.9 illuminate/hashing 'bcrypt'
                       driver — the per-user `salt` column is vestigial for
                       bcrypt). The account is then proven real by logging in over
                       the live web login form.
  * login()          — authenticate over the real member.php?action=do_login form
                       (exercises the genuine auth path; sets the mybbuser cookie).
  * post_key()       — scrape MyBB's CSRF token (`my_post_key`, a.k.a.
                       mybb.post_code) out of a rendered page.

Everything vulnerability-specific lives inline in each finding's automation.py,
where it is narrated step by step.

Config via env (defaults match claude_audit/mybb/mybb_summary.md § Runtime):
  BASE_URL     http://localhost:25850
  ADMIN_USER   admin
  ADMIN_PASS   AdminLab!2026
  DB_CONTAINER cvehunterlab_mybb_db   (docker exec target for SQL)
"""
import os
import re
import subprocess
import secrets
import time

import bcrypt
import requests

BASE_URL = os.environ.get("BASE_URL", "http://localhost:25850").rstrip("/")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "AdminLab!2026")
DB_CONTAINER = os.environ.get("DB_CONTAINER", "cvehunterlab_mybb_db")
DB_USER = os.environ.get("DB_USER", "mybb")
DB_PASS = os.environ.get("DB_PASS", "mybbpass")
DB_NAME = os.environ.get("DB_NAME", "mybb")

UA = "cvehunter-mybb-validation/1.0"


# --------------------------------------------------------------------------- #
#  Lab database access (provisioning + evidence only — never the exploit sink) #
# --------------------------------------------------------------------------- #
def db(sql, tab_separated=True):
    """Run one SQL statement in the lab DB container and return stdout (rows).

    Uses `docker exec` by container name so it works regardless of cwd. -N drops
    the header row; rows are tab-separated, one per line.
    """
    args = [
        "docker", "exec", "-i", DB_CONTAINER,
        "mysql", f"-u{DB_USER}", f"-p{DB_PASS}", DB_NAME, "-N",
    ]
    if tab_separated:
        args.append("--batch")
    args += ["-e", sql]
    out = subprocess.run(args, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"DB query failed: {out.stderr.strip()}\nSQL: {sql}")
    return out.stdout.rstrip("\n")


def db_rows(sql):
    """Return the query result as a list of column-lists."""
    raw = db(sql)
    if raw == "":
        return []
    return [line.split("\t") for line in raw.split("\n")]


def _sql_str(s):
    """Minimal single-quote escaping for provisioning literals we control."""
    return "'" + str(s).replace("\\", "\\\\").replace("'", "\\'") + "'"


# --------------------------------------------------------------------------- #
#  Account provisioning                                                        #
# --------------------------------------------------------------------------- #
def bcrypt_hash(password):
    """Standard bcrypt hash in PHP's $2y$ form (MyBB's default 'bcrypt' driver).

    Verified empirically: bcrypt.checkpw(plaintext, <admin hash>) is True, i.e.
    the shipped driver hashes the raw plaintext and the stored `salt` is not used
    for bcrypt rows. Python emits $2b$; normalise to $2y$ to match MyBB exactly
    (the two prefixes are algorithmically identical and interchangeable).
    """
    h = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    if h.startswith("$2b$"):
        h = "$2y$" + h[4:]
    return h


def create_user(username, password, email=None, usergroup=2,
                additionalgroups="", displaygroup=0):
    """Provision a fully-activated MyBB user via a direct row insert; return uid.

    usergroup=2 is the default Registered group. All NOT-NULL/no-default columns
    (the 6 TEXT fields) are supplied as ''; every other column uses its schema
    default. A fresh 50-char loginkey + 8-char salt are set so the mybbuser cookie
    and post_key seed are well-formed.
    """
    email = email or f"{username}@example.invalid"
    loginkey = secrets.token_hex(25)          # 50 hex chars
    salt = secrets.token_hex(4)               # 8 hex chars (vestigial for bcrypt)
    now = int(time.time())
    pw = bcrypt_hash(password)
    cols = {
        "username": _sql_str(username),
        "password": _sql_str(pw),
        "salt": _sql_str(salt),
        "loginkey": _sql_str(loginkey),
        "password_algorithm": _sql_str("bcrypt"),
        "email": _sql_str(email),
        "usergroup": str(int(usergroup)),
        "additionalgroups": _sql_str(additionalgroups),
        "displaygroup": str(int(displaygroup)),
        "regdate": str(now),
        "lastactive": str(now),
        "lastvisit": str(now),
        "buddylist": "''", "ignorelist": "''", "notepad": "''",
        "pmfolders": "''", "signature": "''", "usernotes": "''",
    }
    collist = ",".join(cols.keys())
    vallist = ",".join(cols.values())
    db(f"INSERT INTO mybb_users ({collist}) VALUES ({vallist});")
    uid = db(f"SELECT uid FROM mybb_users WHERE username={_sql_str(username)} LIMIT 1;")
    return int(uid.strip())


def set_mod(uid, fid, flags=None):
    """Make uid a per-forum moderator of forum `fid` (moderators table row).

    flags: dict of canXXX permission columns to 1 (defaults to a broad set). This
    is the ACP "Add moderator" operation expressed directly against the table.
    """
    # Columns per the mybb_moderators schema (1.9).
    default_flags = {
        "caneditposts": 1, "cansoftdeleteposts": 1, "canrestoreposts": 1,
        "candeleteposts": 1, "cansoftdeletethreads": 1, "canrestorethreads": 1,
        "candeletethreads": 1, "canviewips": 1, "canviewunapprove": 1,
        "canviewdeleted": 1, "canopenclosethreads": 1, "canstickunstickthreads": 1,
        "canapproveunapprovethreads": 1, "canapproveunapproveposts": 1,
        "canapproveunapproveattachs": 1, "canmanagethreads": 1, "canmanagepolls": 1,
        "canpostclosedthreads": 1, "canmovetononmodforum": 1, "canusecustomtools": 1,
        "canmanageannouncements": 1, "canmanagereportedposts": 1, "canviewmodlog": 1,
    }
    if flags:
        default_flags.update(flags)
    # remove any existing row for idempotency, then insert
    db(f"DELETE FROM mybb_moderators WHERE id={int(uid)} AND fid={int(fid)} AND isgroup=0;")
    cols = {"fid": str(int(fid)), "id": str(int(uid)), "isgroup": "0"}
    cols.update({k: str(int(v)) for k, v in default_flags.items()})
    db(f"INSERT INTO mybb_moderators ({','.join(cols)}) VALUES ({','.join(cols.values())});")
    # bump moderators cache version so MyBB reloads it
    rebuild_moderators_cache()


def rebuild_moderators_cache():
    """Rebuild MyBB's 'moderators' datacache from the moderators table.

    is_moderator() reads this cache, so after inserting a moderators row we must
    regenerate it exactly as the ACP does — via $cache->update_moderators() — run
    inside the app container against MyBB's own bootstrap.
    """
    app = os.environ.get("APP_CONTAINER", "cvehunterlab_mybb_app")
    php = (
        "define('IN_MYBB',1);require '/var/www/html/inc/class_error.php';"
        "require '/var/www/html/inc/init.php';"
        "$cache->update_moderators();$cache->update_forumpermissions();"
    )
    r = subprocess.run(["docker", "exec", "-i", app, "php", "-r", php],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"moderators cache rebuild failed: {r.stderr.strip()}")


def setting(name, value):
    """Set a board setting and rebuild the settings cache file (ACP would do this)."""
    db(f"UPDATE mybb_settings SET value={_sql_str(value)} WHERE name={_sql_str(name)};")
    # MyBB reads settings from inc/settings.php (cache). Rebuild it via the app
    # container's own rebuild_settings() so the change takes effect.
    rebuild_settings()


def rebuild_settings():
    """Regenerate inc/settings.php inside the app container from the DB."""
    app = os.environ.get("APP_CONTAINER", "cvehunterlab_mybb_app")
    php = (
        "define('IN_MYBB',1);require '/var/www/html/inc/class_error.php';"
        "require '/var/www/html/inc/init.php';"
        "require_once MYBB_ROOT.'inc/functions_task.php';rebuild_settings();"
    )
    subprocess.run(["docker", "exec", "-i", app, "php", "-r", php],
                   capture_output=True, text=True)


def rebuild_forums_cache():
    """Rebuild MyBB's 'forums' datacache (get_forum() reads it) after a forums UPDATE."""
    app = os.environ.get("APP_CONTAINER", "cvehunterlab_mybb_app")
    php = (
        "define('IN_MYBB',1);require '/var/www/html/inc/class_error.php';"
        "require '/var/www/html/inc/init.php';"
        "$cache->update_forums();"
    )
    r = subprocess.run(["docker", "exec", "-i", app, "php", "-r", php],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"forums cache rebuild failed: {r.stderr.strip()}")


# --------------------------------------------------------------------------- #
#  Live HTTP client                                                            #
# --------------------------------------------------------------------------- #
#
# MyBB sets its session cookies with `domain=localhost`. Python's http.cookiejar
# normalises that to `.localhost` and then refuses to send a dotted-domain cookie
# back to the bare host `localhost` (the "domain must have embedded dots" rule) —
# so a stock requests.Session silently drops the `sid`/`mybbuser` cookies and the
# server issues a fresh guest session (and thus a fresh, non-matching post_key) on
# every request. We side-step the jar entirely and carry cookies in a plain dict
# that we pass explicitly on each call, which requests sends host-only.
_POST_KEY_RE = re.compile(r'name="my_post_key"\s+value="([0-9a-f]{32})"')
_POST_KEY_JS_RE = re.compile(r'my_post_key\s*=\s*"([0-9a-f]{32})"')


def _scrape_key(text):
    m = _POST_KEY_RE.search(text) or _POST_KEY_JS_RE.search(text)
    return m.group(1) if m else None


class Client:
    """Minimal HTTP client with stable, host-only cookie handling for MyBB."""

    def __init__(self):
        self._s = requests.Session()
        self._s.headers["User-Agent"] = UA
        self.cookies = {}          # host-only cookie jar we control

    def _abs(self, path):
        return path if path.startswith("http") else BASE_URL + path

    def _merge(self, r):
        for resp in r.history + [r]:
            for c in resp.cookies:
                self.cookies[c.name] = c.value

    def get(self, path, **kw):
        kw.setdefault("cookies", dict(self.cookies))
        r = self._s.get(self._abs(path), **kw)
        self._merge(r)
        return r

    def post(self, path, **kw):
        kw.setdefault("cookies", dict(self.cookies))
        r = self._s.post(self._abs(path), **kw)
        self._merge(r)
        return r


def new_session():
    return Client()


def post_key(client, path="/newthread.php?fid=2"):
    """Scrape MyBB's CSRF token (my_post_key / mybb.post_code) from a page."""
    r = client.get(path)
    k = _scrape_key(r.text)
    if not k:
        raise RuntimeError(f"could not find my_post_key on {path}")
    return k


def login(client, username, password):
    """Authenticate over the genuine web login form; return True on success.

    Fetches the login page (establishes a guest session + its matching guest
    post key), then POSTs do_login. Success is indicated by the mybbuser cookie.
    """
    r = client.get("/member.php?action=login")
    guest_key = _scrape_key(r.text) or ""
    data = {
        "action": "do_login",
        "url": BASE_URL + "/index.php",
        "quick_login": "1",
        "quick_username": username,
        "quick_password": password,
        "username": username,
        "password": password,
        "remember": "yes",
        "my_post_key": guest_key,
        "submit": "Login",
    }
    client.post("/member.php", data=data, allow_redirects=False)
    return "mybbuser" in client.cookies


def admin_session():
    """Return a logged-in Client for the admin forum account."""
    c = new_session()
    if not login(c, ADMIN_USER, ADMIN_PASS):
        raise RuntimeError("admin login failed")
    return c


def rand(prefix):
    """Random, collision-free identifier for accounts/resources this run creates."""
    return f"{prefix}{secrets.token_hex(4)}"


# --------------------------------------------------------------------------- #
#  Real-browser XSS execution proof (Playwright container)                     #
# --------------------------------------------------------------------------- #
EXPLOITS_DIR = os.path.dirname(os.path.abspath(__file__))
WORK_DIR = os.path.dirname(EXPLOITS_DIR)          # claude_audit/mybb  (mounted at /work)
PW_IMAGE = os.environ.get("PW_IMAGE", "mcr.microsoft.com/playwright/python:latest")
PW_VERSION = os.environ.get("PW_VERSION", "1.46.0")   # matches the cached browsers


def browser_dialog_check(url, mybbuser=None, screenshot_rel=None, marker="", extra_cookies=None):
    """Open `url` in a real Chromium (Playwright container) carrying the victim's
    session and return (fired: bool, transcript: str).

    `fired` is True iff an alert()/confirm()/prompt() dialog fired — proof the
    injected JS executed. The cached Playwright image ships browsers but not the
    python package, so we pip-install the matching pinned version at runtime
    (browsers live at /ms-playwright). screenshot_rel is a path under
    claude_audit/mybb (e.g. 'exploits/VULN-001/evidence/xss.png').
    """
    cookies = []
    if mybbuser:
        cookies.append({"name": "mybbuser", "value": mybbuser,
                        "domain": "localhost", "path": "/"})
    if extra_cookies:
        cookies.extend(extra_cookies)
    shot = f"/work/{screenshot_rel}" if screenshot_rel else "/work/xss.png"
    inner = (f"pip install -q playwright=={PW_VERSION} >/dev/null 2>&1 && "
             f"python /work/exploits/browser_xss_probe.py")
    cmd = [
        "docker", "run", "--rm", "--network", "host", "--ipc=host", "--memory=2g",
        "-v", f"{WORK_DIR}:/work", "-w", "/work",
        "-e", "HOME=/tmp", "-e", "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright",
        "-e", f"TARGET_URL={url}",
        "-e", "COOKIES=" + __import__("json").dumps(cookies),
        "-e", f"SHOT={shot}",
        "-e", f"MARKER={marker}",
        PW_IMAGE, "bash", "-lc", inner,
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    except Exception as e:
        return False, f"browser step error: {e}"
    transcript = (out.stdout or "") + (out.stderr or "")
    return ("DIALOG_FIRED" in transcript), transcript
