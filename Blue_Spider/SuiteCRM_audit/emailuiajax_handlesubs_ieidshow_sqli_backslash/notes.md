# VULN-044 — `folders` subscription SQL injection via unescaped backslash (EmailUIAjax)

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium (CVSS 3.1 6.5 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`)
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:31:12Z (lab wall-clock, see run.log)

## Preconditions
- `./run.sh` creates a fresh non-admin user (`_common.create_user`/`web_login`) — matches the doc's "any authenticated user."
- No other setup: `setFolderViewSelection` is reachable immediately after login.

## Request
`POST /index.php?module=Emails&action=EmailUIAjax` with `emailUIAction=setFolderViewSelection&ieIdShow[]=<marker><N backslashes>`, sent 4 times with `N ∈ {0,1,2,3}` and a fresh random marker each time (`request.http` captures the decisive ODD (`N=1`) and control EVEN (`N=2`) requests).

## Response
Byte-identical HTTP 200 HTML page for **every** case, regardless of `N` (`response.txt`). This is expected and explained by the code: `handleSubs()` computes its JSON return value (`$out`, from the mailbox-tree render) **before** the per-folder `$db->query($query)` loop runs (`EmailUIAjax.php:70-72` vs `:76-79`), and that query result is never reflected back to the client — so the HTTP response cannot be the oracle here.

## Observation
`suitecrm.log`, grepped for each request's unique marker, gives a clean 2×2 split:

| backslashes (N) | parity | log result |
|---|---|---|
| 0 | even | no entry (clean parse) |
| 1 | **odd** | `Query Failed: ... MySQL error 1064` containing our marker |
| 2 | even | no entry (clean parse) |
| 3 | **odd** | `Query Failed: ... MySQL error 1064` containing our marker |

Exact captured line (N=1): `Query Failed: SELECT * FROM folders WHERE folders.id LIKE "ODD-10c7698dbdf\" OR folders.parent_folder LIKE "ODD-10c7698dbdf\": MySQL error 1064: ... near 'ODD-10c7698dbdf\"' at line 1`. This is a **deterministic, attacker-controlled, two-outcome oracle**: flipping the parity of a single character (one more/less trailing `\`) flips the SQL from valid to a guaranteed syntax error, 2/2 times for each parity in this run — full detail and reasoning for *why* this specific parity rule holds is in the module docstring of `automation.py` and in `writeup.md` §3.

## Side effects
- 1 non-admin user created.
- No persistent state change from the injection itself (the malformed queries touch the read-only `folders` table via `SELECT`; `$db->query()` is called with default `$dieOnError=false`, so a failure just logs and returns `false`, execution continues normally).
- suitecrm.log grown by our test lines (read via `docker compose -p cvehunterlab_suitecrm exec -T app grep -F <marker> /var/www/html/suitecrm.log` — read-only verification of the HTTP-triggered attack, not itself an attack step).

## Research & references
- Technique: error-based SQL injection detection via a controlled parser-desync signal, per OWASP WSTG-INPV-05 (Testing for SQL Injection) and PortSwigger's "Detecting SQL injection vulnerabilities" (https://portswigger.net/web-security/sql-injection#detecting-sql-injection-vulnerabilities) — specifically the "does a single extra special character break the query" test, applied to backslash-escape parity in a MySQL non-ANSI-quotes double-quoted string rather than the usual single-quote break-out.
- MySQL manual §9.1.1 "String Literals" — backslash escape rules in default `sql_mode` (no `NO_BACKSLASH_ESCAPES`), which is what makes the parity rule hold.

## Exfiltration depth (why this stays an injection-primitive CONFIRM, not a data-exfil CONFIRM)
`$f` is substituted **twice**, with the **identical** value, into `... LIKE "$f" OR ... LIKE "$f"`, and `securexss()` makes a literal `"` unreachable (rewritten to `&quot;`). Since $f contains no quote character, the string opened by the first delimiter quote can only close at one of the two remaining template-provided quote positions — and because both use the same $f, the parity decision (open vs. force-through-to-error) is identical at both positions. Worked through in full in the module docstring: this means $f's content is **always** either (a) inert string data inside two ordinary LIKE clauses (even parity — never parsed as SQL), or (b) part of one giant unterminated string literal that always ends in a syntax error (odd parity) — there is no reachable third state where injected text becomes live, executable SQL. That is why the static finding (and this dynamic validation) mark the **injection primitive** CONFIRMED while explicitly not claiming a working UNION/boolean data-read through this exact sink.

## If FAILED
N/A — CONFIRMED.
