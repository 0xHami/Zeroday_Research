"""
Shared helper library for Znuny stage-10 dynamic validation exploits.

Every exploit under exploits/<VULN-ID>/automation.py imports this module. It
centralises:
  * colored, tty-gated logging (plain in captured run.log) + banners/verdicts
  * HTTP clients for the agent / customer / public / GenericInterface surfaces,
    including Znuny login and ChallengeToken (CSRF) extraction
  * privileged *setup* primitives driven through the app's own admin console
    (`znuny.Console.pl`) and a Perl/ObjectManager evaluator — used only to
    provision the preconditions an attacker would already find (users, groups,
    queues, tickets). The vulnerability itself is always triggered over HTTP as
    the low-privileged actor the finding names.
  * a DB read helper and an out-of-band HTTP listener for SSRF proofs.

All identifiers created for setup carry a random suffix (rid()) so re-runs never
collide with orphaned state.
"""
import os, sys, re, json, time, secrets, subprocess, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

# --------------------------------------------------------------------------- #
# Config (env-overridable, defaults match Znuny_summary.md ## Runtime)
# --------------------------------------------------------------------------- #
BASE_URL   = os.environ.get("BASE_URL", "http://localhost:25114").rstrip("/")
AGENT_URL  = BASE_URL + "/znuny/index.pl"
CUST_URL   = BASE_URL + "/znuny/customer.pl"
PUBLIC_URL = BASE_URL + "/znuny/public.pl"
GI_URL     = BASE_URL + "/znuny/nph-genericinterface.pl"
RPC_URL    = BASE_URL + "/znuny/rpc.pl"

ADMIN_USER = os.environ.get("ADMIN_USER", "root@localhost")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "ZnunyAdmin_2f8b")

APP_CONTAINER = os.environ.get("APP_CONTAINER", "cvehunterlab_znuny_app")
DB_CONTAINER  = os.environ.get("DB_CONTAINER",  "cvehunterlab_znuny_db")
DB_ROOT_PASS  = os.environ.get("DB_ROOT_PASS",  "ZnunyRoot_a1b2c3")
DB_NAME       = os.environ.get("DB_NAME",       "znuny")
ZHOME         = "/opt/znuny"
# Host gateway reachable from inside the app container (docker bridge).
OOB_HOST      = os.environ.get("OOB_HOST", "172.18.0.1")

requests.packages.urllib3.disable_warnings()  # noqa

# --------------------------------------------------------------------------- #
# Colored, report-grade logging (plain when captured to a file)
# --------------------------------------------------------------------------- #
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}
_VID = "VULN-???"

def log(tag, msg):
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}")
    else:
        print(f"[{tag}] {msg}")
    sys.stdout.flush()

def banner(vid, title, info_lines=None):
    global _VID
    _VID = vid
    print("=" * 74)
    print(f"{vid}: {title}")
    print(f"Target: {BASE_URL}")
    for line in (info_lines or []):
        log("INFO", line)
    print("=" * 74)

def _verdict(status, msg):
    color = {"CONFIRMED": "32", "FAILED": "31", "NEEDS_MANUAL": "33"}.get(status, "0")
    line = f"==> {_VID}: {status} — {msg}"
    if _USE_COLOR:
        print(f"\033[1;{color}m{line}\033[0m")
    else:
        print(line)
    sys.stdout.flush()

def confirmed(msg):
    log("OK", f"exploit confirmed — {msg}")
    _verdict("CONFIRMED", msg)
    sys.exit(0)

def failed(msg):
    log("FAIL", msg)
    _verdict("FAILED", msg)
    sys.exit(1)

def needs_manual(msg):
    _verdict("NEEDS_MANUAL", msg)
    sys.exit(2)

def rid(n=4):
    """Random hex suffix so every created identifier is unique across re-runs."""
    return secrets.token_hex(n)

# --------------------------------------------------------------------------- #
# Container-side helpers (privileged SETUP only — never the exploit trigger)
# --------------------------------------------------------------------------- #
def console(*args, timeout=180):
    """Run znuny.Console.pl as the web user inside the app container."""
    cmd = ["docker", "exec", "-u", "www-data", APP_CONTAINER, "perl",
           f"{ZHOME}/bin/znuny.Console.pl"] + [str(a) for a in args]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def perl_eval(body, timeout=180):
    """Execute a Perl snippet inside the container with the ObjectManager ready.
    Used only for setup (create tickets/articles, read config objects)."""
    code = (
        "use lib '%s';use lib '%s/Kernel/cpan-lib';"
        "use Kernel::System::ObjectManager;"
        "local $Kernel::OM=Kernel::System::ObjectManager->new();\n%s"
        % (ZHOME, ZHOME, body)
    )
    cmd = ["docker", "exec", "-u", "www-data", APP_CONTAINER, "perl", "-e", code]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def container_sh(cmd, user=None, timeout=60):
    """Run a shell command inside the app container (setup convenience)."""
    pre = ["docker", "exec"] + (["-u", user] if user else []) + [APP_CONTAINER, "sh", "-c", cmd]
    p = subprocess.run(pre, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def postmaster_read(raw_email, untrusted=False, timeout=120):
    """Feed a raw RFC822 message to Maint::PostMaster::Read (the exact code path the mail pipe
    uses). Default is TRUSTED (X-OTRS-* headers honoured) unless untrusted=True."""
    cmd = ["docker", "exec", "-i", "-u", "www-data", APP_CONTAINER, "perl",
           f"{ZHOME}/bin/znuny.Console.pl", "Maint::PostMaster::Read"]
    if untrusted:
        cmd.append("--untrusted")
    p = subprocess.run(cmd, input=raw_email, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def db(sql, timeout=60):
    """Run a SQL query as root and return rows (list of lists). Verification only."""
    cmd = ["docker", "exec", DB_CONTAINER, "mysql", "-uroot", f"-p{DB_ROOT_PASS}",
           DB_NAME, "-N", "-B", "-e", sql]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError("DB error: " + p.stderr)
    return [ln.split("\t") for ln in p.stdout.splitlines() if ln != ""]

def config_read(name):
    rc, out, err = console("Admin::Config::Read", "--setting-name", name)
    m = re.search(r"Setting:\s*%s\s*\n(.*)" % re.escape(name), out, re.S)
    return (m.group(1).strip() if m else out.strip())

def config_set(name, value):
    rc, out, err = console("Admin::Config::Update", "--setting-name", name, "--value", str(value))
    if rc != 0:
        raise RuntimeError(f"config_set {name} failed: {err or out}")
    return True

def cache_delete():
    console("Maint::Cache::Delete")

def sysconfig_enable(name, timeout=180):
    """Enable a setting (IsValid=1) keeping its shipped EffectiveValue — for hash/complex
    settings whose default value is already what we want (e.g. ShowAgentOnline ships ShowEmail=1)."""
    perl = (
        "my $SC=$Kernel::OM->Get('Kernel::System::SysConfig');"
        "my %%s=$SC->SettingGet(Name=>'%s');"
        "my $g=$SC->SettingLock(UserID=>1,LockAll=>1);"
        "$SC->SettingUpdate(Name=>'%s',IsValid=>1,EffectiveValue=>$s{EffectiveValue},"
        "ExclusiveLockGUID=>$g,UserID=>1);"
        "my %%d=$SC->ConfigurationDeploy(Comments=>'poc',UserID=>1,Force=>1,DirtySettings=>['%s']);"
        "print 'deploy=',($d{Success}//0),\"\\n\";" % (name, name, name))
    rc, out, err = perl_eval(perl, timeout=timeout)
    if "deploy=1" not in out:
        raise RuntimeError(f"sysconfig_enable {name} failed: {out}\n{err}")
    return True

def sysconfig_reset(name, timeout=180):
    """Reset a setting to its default (used to revert a toggle after a test)."""
    console("Admin::Config::Update", "--setting-name", name, "--reset", timeout=timeout)

def sysconfig_set(pairs, timeout=180):
    """Enable + set several SysConfig settings atomically and deploy once.
    `pairs` maps setting name -> scalar EffectiveValue. Running mod_perl workers
    pick up the deployed value on the next request (no apache restart needed).
    Used to satisfy the documented preconditions of config-gated findings
    (SMIME, SAML, 2FA, ShowAgentOnline, AutoLink, HTTPSForceRedirect, ...)."""
    def q(v):
        if isinstance(v, bool):
            return "1" if v else "0"
        if isinstance(v, (int, float)):
            return str(v)
        return "'" + str(v).replace("\\", "\\\\").replace("'", "\\'") + "'"
    names = list(pairs.keys())
    setlines = "\n".join(
        "$SC->SettingUpdate(Name=>'%s',IsValid=>1,EffectiveValue=>%s,"
        "ExclusiveLockGUID=>$g,UserID=>1);" % (n, q(pairs[n])) for n in names)
    namelist = ",".join("'%s'" % n for n in names)
    perl = (
        "my $SC=$Kernel::OM->Get('Kernel::System::SysConfig');\n"
        "my $g=$SC->SettingLock(UserID=>1,LockAll=>1);\n"
        + setlines + "\n"
        "my %%d=$SC->ConfigurationDeploy(Comments=>'poc',UserID=>1,Force=>1,"
        "DirtySettings=>[%s]);\nprint 'deploy=',($d{Success}//0),\"\\n\";" % namelist)
    rc, out, err = perl_eval(perl, timeout=timeout)
    if "deploy=1" not in out:
        raise RuntimeError(f"sysconfig_set failed: {out}\n{err}")
    return True

# ---- provisioning primitives (random-suffixed) ---------------------------- #
def create_group(name=None):
    name = name or f"grp_{rid()}"
    rc, out, err = console("Admin::Group::Add", "--name", name)
    if rc != 0 and "already" not in (out + err):
        raise RuntimeError(f"create_group failed: {err or out}")
    return name

def create_queue(name=None, group="users"):
    name = name or f"q_{rid()}"
    rc, out, err = console("Admin::Queue::Add", "--name", name, "--group", group,
                           "--system-address-id", "1")
    if rc != 0 and "already" not in (out + err):
        raise RuntimeError(f"create_queue failed: {err or out}")
    return name

def create_agent(login=None, password=None, groups=None):
    """Create an agent. `groups` grants rw on each (console --group => rw)."""
    login = login or f"agent_{rid()}"
    password = password or ("Pw9!" + rid())
    args = ["Admin::User::Add", "--user-name", login, "--first-name", "T",
            "--last-name", login, "--email-address", f"{login}@example.invalid",
            "--password", password]
    for g in (groups or []):
        args += ["--group", g]
    rc, out, err = console(*args)
    if rc != 0:
        raise RuntimeError(f"create_agent failed: {err or out}")
    return login, password

def group_link(user, group, permission="rw"):
    rc, out, err = console("Admin::Group::UserLink", "--user-name", user,
                           "--group-name", group, "--permission", permission)
    return rc == 0

def ensure_webservice(name=None, yml="/opt/znuny/var/webservices/examples/GenericTicketConnectorREST.yml"):
    """Import the shipped GenericTicketConnectorREST example under a fresh name.
    Returns (name, base_route_url). Reproducible: the random name avoids collisions."""
    name = name or ("GTCR_" + rid())
    rc, out, err = console("Admin::WebService::Add", "--name", name, "--source-path", yml)
    if rc != 0 and "Done" not in out:
        raise RuntimeError(f"ensure_webservice failed: {err or out}")
    return name, f"{GI_URL}/Webservice/{name}"

def gi_post(route_base, path, body, method="POST", timeout=25):
    """Call a GenericInterface REST route with a JSON body. Returns (status, json_or_text)."""
    url = route_base + path
    r = requests.request(method, url, json=body, timeout=timeout,
                         headers={"Content-Type": "application/json"})
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, r.text

def create_customer(login=None, password=None, customer_id=None, first="T", last="C"):
    login = login or f"cust_{rid()}"
    password = password or ("Pw9!" + rid())
    customer_id = customer_id or login
    rc, out, err = console("Admin::CustomerUser::Add", "--user-name", login,
                           "--first-name", first, "--last-name", last,
                           "--email-address", f"{login}@example.invalid",
                           "--customer-id", customer_id, "--password", password)
    if rc != 0:
        raise RuntimeError(f"create_customer failed: {err or out}")
    return login, password, customer_id

def agent_uid(login):
    rows = db("SELECT id FROM users WHERE login=%s" % ("'" + login.replace("'", "") + "'"))
    return int(rows[0][0]) if rows else None

def perm_check(login, ticket_id, types=("ro", "note", "rw")):
    """Return {type: 0|1} = the agent's real TicketPermission on a ticket (ground truth via
    the app's own permission engine). Used to prove the access-control gap in IDOR/BAC findings."""
    perl = (
        "my $U=$Kernel::OM->Get('Kernel::System::User');my %%h=$U->UserList(Type=>'Short');"
        "my ($uid)=grep{ $h{$_} eq '%s' }keys %%h;"
        "my $T=$Kernel::OM->Get('Kernel::System::Ticket');"
        "for my $p (qw(%s)){ print \"$p=\",($T->TicketPermission(Type=>$p,TicketID=>%d,UserID=>$uid)||0),\"\\n\"; }"
        % (login.replace("'", ""), " ".join(types), int(ticket_id)))
    rc, out, err = perl_eval(perl)
    res = {}
    for line in out.splitlines():
        if "=" in line and line.split("=")[0] in types:
            k, v = line.split("=", 1)
            res[k] = int(v.strip())
    return res

def create_ticket(title, queue, body="body", customer_id="", customer_user="",
                  sender="customer", visible=1, state="open", owner_id=1):
    """Create a ticket with one article via ObjectManager. Returns (TicketID, TN)."""
    perl = r'''
my $T=$Kernel::OM->Get('Kernel::System::Ticket');
my $tid=$T->TicketCreate(Title=>'%(title)s',Queue=>'%(queue)s',Lock=>'unlock',
  Priority=>'3 normal',State=>'%(state)s',CustomerID=>'%(cid)s',
  CustomerUser=>'%(cu)s',OwnerID=>%(owner)d,UserID=>1);
die "no tid" unless $tid;
my $A=$Kernel::OM->Get('Kernel::System::Ticket::Article');
my $B=$A->BackendForChannel(ChannelName=>'Internal');
$B->ArticleCreate(TicketID=>$tid,IsVisibleForCustomer=>%(vis)d,SenderType=>'%(sender)s',
  From=>'setup <setup@example.invalid>',Subject=>'%(title)s',Body=>'%(body)s',
  ContentType=>'text/plain; charset=utf-8',HistoryType=>'AddNote',
  HistoryComment=>'setup',UserID=>1);
my %%t=$T->TicketGet(TicketID=>$tid);
print "TID=$tid TN=$t{TicketNumber}\n";
''' % dict(title=title.replace("'", ""), queue=queue, state=state,
           cid=customer_id, cu=customer_user, owner=owner_id, vis=visible,
           sender=sender, body=body.replace("'", ""))
    rc, out, err = perl_eval(perl)
    m = re.search(r"TID=(\d+) TN=(\d+)", out)
    if not m:
        raise RuntimeError(f"create_ticket failed: {out}\n{err}")
    return int(m.group(1)), m.group(2)

# --------------------------------------------------------------------------- #
# HTTP clients
# --------------------------------------------------------------------------- #
_TOKEN_RE = re.compile(r'name="ChallengeToken"\s+value="([^"]+)"')
_TOKEN_RE2 = re.compile(r'"ChallengeToken":"([^"]+)"')

_INPUT_RE = re.compile(r'<input\b[^>]*>', re.I)
_SEL_NAME_RE = re.compile(r'name="([^"]+)"')
_SEL_VAL_RE = re.compile(r'value="([^"]*)"')
_NAME_ATTR = re.compile(r'\bname="([^"]+)"')
_VALUE_ATTR = re.compile(r'\bvalue="([^"]*)"')

def parse_form_fields(html):
    """Best-effort: harvest name=value pairs from <input> tags (hidden + text).
    Lets an exploit replay a real form and override only the fields it attacks."""
    out = {}
    for tag in _INPUT_RE.findall(html):
        n = _NAME_ATTR.search(tag)
        if not n:
            continue
        v = _VALUE_ATTR.search(tag)
        out[n.group(1)] = v.group(1) if v else ""
    return out

class Client:
    """A logged-in Znuny web session (agent/customer/public)."""
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) ZnunyPoC"
        self.token = None

    def login(self, user, pw):
        # GET first so the app sees the OTRSBrowserHasCookie support cookie.
        self.s.get(self.endpoint, timeout=20)
        r = self.s.post(self.endpoint, data={
            "Action": "Login", "User": user, "Password": pw,
            "Lang": "en", "TimeOffset": "0", "RequestedURL": ""},
            allow_redirects=False, timeout=20)
        ok = r.status_code in (301, 302) and any(
            "Interface" in c.name for c in self.s.cookies)
        return ok, r

    def refresh_token(self, url=None):
        r = self.s.get(url or (self.endpoint + "?Action=AgentDashboard"), timeout=20)
        m = _TOKEN_RE.search(r.text) or _TOKEN_RE2.search(r.text)
        self.token = m.group(1) if m else None
        return self.token, r

    def get(self, params=None, url=None, **kw):
        return self.s.get(url or self.endpoint, params=params, timeout=kw.pop("timeout", 25), **kw)

    def post(self, data=None, url=None, **kw):
        return self.s.post(url or self.endpoint, data=data, timeout=kw.pop("timeout", 25), **kw)

def agent_client(user, pw):
    c = Client(AGENT_URL)
    ok, r = c.login(user, pw)
    if not ok:
        raise RuntimeError(f"agent login failed for {user} (HTTP {r.status_code})")
    return c

def customer_client(user, pw):
    c = Client(CUST_URL)
    ok, r = c.login(user, pw)
    if not ok:
        raise RuntimeError(f"customer login failed for {user} (HTTP {r.status_code})")
    return c

# --------------------------------------------------------------------------- #
# Out-of-band HTTP listener (SSRF / DDE-callback proofs)
# --------------------------------------------------------------------------- #
class OOB:
    """Threaded HTTP listener on the host, reachable from the app container at
    OOB_HOST:<port>. Records every request path it receives."""
    def __init__(self, port=0, bind="0.0.0.0"):
        self.hits = []
        outer = self
        class H(BaseHTTPRequestHandler):
            def _rec(self):
                outer.hits.append({"path": self.path, "cmd": self.command,
                                   "client": self.client_address[0],
                                   "headers": dict(self.headers)})
                body = b"OOB-CANARY-%s" % outer.token.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            do_GET = do_POST = do_HEAD = _rec
            def log_message(self, *a): pass
        self.token = rid()
        self.httpd = ThreadingHTTPServer((bind, port), H)
        self.port = self.httpd.server_address[1]

    def __enter__(self):
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()
        return self

    @property
    def url(self):
        return f"http://{OOB_HOST}:{self.port}"

    def wait_hit(self, seconds=15):
        end = time.time() + seconds
        while time.time() < end:
            if self.hits:
                return True
            time.sleep(0.3)
        return bool(self.hits)

    def __exit__(self, *a):
        self.httpd.shutdown()
