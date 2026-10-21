"""
Cluster C1 (legacy SOAP/REST API, read + BOLA) shared helpers.

Additive companion to the shared `_common.py` -- deliberately a SEPARATE
file so cluster C1's exploits never race-edit the shared helper/requirements
that other stage-10 clusters are writing to concurrently. Import alongside
`_common`:

    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from _common import ...
    from _c1_common import db, db_rows, restrict_role, ACL_ALLOW_NONE

What this adds, and why:
  - db()/db_rows()      -- run SQL inside the live `db` container (docker exec,
                            not docker run: no new container, no forbidden
                            flags) to seed ACL precondition state and to
                            verify real side effects (new/changed rows).
  - restrict_role()      -- provisions a throwaway ACL Role that DENIES
                            specific (category, action) pairs and assigns it
                            to one test user. This models the real-world
                            restrictive Role / Security-Group configuration
                            that production SuiteCRM instances run (a fresh
                            install with zero roles defaults every module's
                            aclaccess to ALL=90 for everyone -- verified via
                            `SELECT * FROM acl_actions WHERE category=
                            'Opportunities'`, so the bypass is only visible
                            once a Role actually restricts something). Every
                            role/action/assignment row this creates is
                            scoped to ONE freshly created random-suffixed
                            test user, so it never touches any other
                            account's access.
"""
import subprocess
import uuid

DB_CONTAINER = "cvehunterlab_SuiteCRM_db"
APP_CONTAINER = "cvehunterlab_SuiteCRM_app"
DB_USER = "root"
DB_PASS = "SuiteRoot!2026x"
DB_NAME = "suitecrm"

# modules/ACLActions/actiondefs.php
ACL_ALLOW_ALL = 90
ACL_ALLOW_OWNER = 75
ACL_ALLOW_NONE = -99


def db(sql, timeout=30):
    """Run `sql` inside the live db container; return stdout (warning line stripped)."""
    cmd = ["docker", "exec", DB_CONTAINER, "mysql", f"-u{DB_USER}", f"-p{DB_PASS}", DB_NAME, "-e", sql]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"db() failed rc={r.returncode}\nSQL: {sql}\nstderr: {r.stderr}")
    return "\n".join(l for l in r.stdout.splitlines() if "Using a password" not in l)


def db_rows(sql, timeout=30):
    """Run a SELECT; return list[dict] parsed from mysql's tab-separated `-e` output."""
    out = db(sql, timeout=timeout)
    lines = [l for l in out.splitlines() if l.strip() != ""]
    if not lines:
        return []
    header = lines[0].split("\t")
    return [dict(zip(header, line.split("\t"))) for line in lines[1:]]


def app_exec(cmd, timeout=30):
    """Run a shell command inside the app container; return stdout text."""
    full = ["docker", "exec", APP_CONTAINER, "sh", "-c", cmd]
    r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"app_exec() failed rc={r.returncode}\ncmd: {cmd}\nstderr: {r.stderr}")
    return r.stdout


def restrict_role(user_id, restrictions, name_prefix="stage10_acl"):
    """
    Create a throwaway ACL Role that overrides specific (category, action)
    pairs (action in {'view','list','edit','delete','export','import'}) and
    assign it to `user_id`. Returns role_id. The row this looks up in
    acl_actions already exists (seeded at install) -- this only adds the
    *override* + the role<->user link, both deletable/uniquely named.

    Each item in `restrictions` is either:
      - (category, action)         -> access_override = ACL_ALLOW_NONE (deny)
      - (category, action, level)  -> access_override = level (e.g. ACL_ALLOW_OWNER=75
        to test row-level "only your own records" scoping, used by VULN-076)
    """
    role_id = str(uuid.uuid4())
    role_name = f"{name_prefix}_{uuid.uuid4().hex[:8]}"
    db(
        "INSERT INTO acl_roles (id, date_entered, date_modified, name, description, deleted) "
        f"VALUES ('{role_id}', NOW(), NOW(), '{role_name}', 'cvehunter stage10 test role (random suffix, safe to delete)', 0);"
    )

    for restriction in restrictions:
        if len(restriction) == 3:
            category, action, level = restriction
        else:
            category, action = restriction
            level = ACL_ALLOW_NONE
        rows = db_rows(
            f"SELECT id FROM acl_actions WHERE category='{category}' AND name='{action}' AND acltype='module';"
        )
        if not rows:
            raise RuntimeError(f"restrict_role: no acl_actions row for category={category!r} action={action!r}")
        action_id = rows[0]["id"]
        ra_id = str(uuid.uuid4())
        db(
            "INSERT INTO acl_roles_actions (id, role_id, action_id, access_override, date_modified, deleted) "
            f"VALUES ('{ra_id}', '{role_id}', '{action_id}', {level}, NOW(), 0);"
        )

    ru_id = str(uuid.uuid4())
    db(
        "INSERT INTO acl_roles_users (id, role_id, user_id, date_modified, deleted) "
        f"VALUES ('{ru_id}', '{role_id}', '{user_id}', NOW(), 0);"
    )
    return role_id
