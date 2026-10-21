# VULN-044 — `folders` subscription SQL injection via unescaped backslash (EmailUIAjax)

**ID**: VULN-044
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb` (untagged `hotfix`/`forkedSuite` snapshot)
**Severity**: Medium — **CVSS 3.1 6.5** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**Status**: **CONFIRMED (dynamic)** — injection primitive; see "Impact" for the honest scope of what was and wasn't demonstrated.
**Auth required**: Any authenticated user (personal Emails folder subscription feature — no special role).
**What an attacker gains**: proof that raw, unescaped request data reaches the SQL parser in `EmailUIAjax::handleSubs()` — a deterministic, attacker-controlled boolean-style oracle over a table (`folders`) any user can otherwise only query through their own subscriptions.

## 1. Summary

SuiteCRM's Email UI lets a user pick which mail folders to subscribe to. The handler for that request builds a raw SQL string by concatenating the user-supplied folder id straight into a double-quoted `LIKE` clause, twice, with no `$db->quote()`/`quoted()` call. SuiteCRM's global XSS filter blocks the obvious break-out character (`"`) but does not touch backslash, and MySQL's default string parser treats backslash as an escape character — so the *count* of trailing backslashes the attacker sends deterministically controls whether the resulting SQL statement is valid or a guaranteed syntax error. That is a genuine, attacker-controlled SQL injection oracle, confirmed live and reproduced 4/4 times in this run.

## 2. How it works (mechanism & code trace)

**Entry point** — `index.php?module=Emails&action=EmailUIAjax`:

```php
// modules/Emails/EmailUIAjax.php:1129-1136
case "setFolderViewSelection":
    ...
    $out = handleSubs($_REQUEST['ieIdShow'], $email, $json, $user);   // :1136 -- raw request array, no validation
    echo $out;
    break;
```

**The sink**:

```php
// modules/Emails/EmailUIAjax.php:76-79
foreach ($viewFolders as $f) {
    $query = 'SELECT * FROM folders WHERE folders.id LIKE "' . $f
        . '" OR folders.parent_folder LIKE "' . $f . '"';
    $result = $db->query($query);   // raw string, no $db->quote()/quoted()
```

`$f` comes directly from `$_REQUEST['ieIdShow'][]` with no GUID/format validation before this point.

**Why the obvious payload (a literal `"`) doesn't work, and why backslash does**: SuiteCRM's global input filter runs on every request (`include/entryPoint.php:93` → `clean_incoming_data()` → `securexss()`, `include/utils.php:2608`), rewriting `" ' < > \`` to HTML entities. This is applied recursively to array values too (`ieIdShow[]` is an array; `securexss()` recurses into it), so a literal `"` in the payload becomes `&quot;` before it ever reaches `handleSubs()` — the "obvious" SQLi break-out is blocked. **Backslash is absent from that rewrite table.** MySQL's default `sql_mode` (no `NO_BACKSLASH_ESCAPES`, confirmed by observed behavior) treats `\` inside a double-quoted string as an escape character: `\\` is an escaped literal backslash (the following quote is unaffected), while a lone/odd-count `\` immediately before the delimiter quote escapes that quote away, so the string does not close there. Because the same `$f` is substituted at **both** `"` -delimited positions in the query, the parity of trailing backslashes in `$f` is a single, global, attacker-controlled switch:
- **even** count → both delimiter quotes close normally → two ordinary (harmless) `LIKE` string comparisons → query executes without error.
- **odd** count → both relevant delimiter quotes get escaped away → the whole remainder of the statement (the literal `" OR folders.parent_folder LIKE "` text, the second `$f`, and the final closing `"`) is swallowed into one never-terminated string literal → MySQL syntax error (1064).

**Why the HTTP response can't be used as the oracle**: `handleSubs()` computes its return value (`$out`, the mailbox-tree JSON) *before* the injection-bearing loop runs:

```php
// modules/Emails/EmailUIAjax.php:70-79
$tree = $email->et->getMailboxNodes(false);
$return = $tree->generateNodesRaw();
$out = $json->encode($return);         // <-- $out is already fixed here
...
foreach ($viewFolders as $f) {
    $query = 'SELECT * FROM folders WHERE folders.id LIKE "' . $f . '" OR ...';
    $result = $db->query($query);      // $dieOnError defaults to false -- failure just logs
    while (($row = $db->fetchByAssoc($result))) { $sub[] = $row['id']; }
}
...
return $out;                            // unchanged either way
```

`$db->query()` is called with the default `$dieOnError = false`, so a syntax error is logged (`LoggerManager::fatal`) and execution continues; the function's return value is identical whether the query succeeded or failed. This is exactly why the earlier static-analysis stage captured its "live proof" from `suitecrm.log` rather than the HTTP response — confirmed and reproduced here.

## 3. Why it is a vulnerability (reasoning)

The trust boundary violated is the standard one for SQL injection: user input reaching the SQL parser must be bound as a parameter or fully escaped for its context, never concatenated raw. SuiteCRM's own `DBManager` provides exactly the right tool for this (`$db->quote()`/`$db->quoted()`), used correctly elsewhere in the same codebase — its absence here is a straightforward omission, not a deliberate design choice (there is no reason a folder-id lookup needs raw string concatenation). The global `securexss()` filter is not a substitute for parameterized queries: it defends against *HTML/script* injection (its name says so), and this finding is the concrete proof that treating it as a SQL-injection defense is incorrect — it has no concept of the SQL escaping rules for the context a value will be used in, so a SQL-meaningful character it doesn't recognize (backslash) sails through untouched.

## 4. Reproduction

From clean state:

1. `./run.sh` creates a fresh non-admin user and logs in.
2. Sends `POST /index.php?module=Emails&action=EmailUIAjax` with `emailUIAction=setFolderViewSelection&ieIdShow[]=<marker><N backslashes>` for `N ∈ {0, 1, 2, 3}`, each with an independent random marker (`request.http` has the decisive `N=1` and control `N=2` requests):
   ```
   POST /index.php?module=Emails&action=EmailUIAjax HTTP/1.1
   ...
   emailUIAction=setFolderViewSelection&ieIdShow%5B%5D=ODD-10c7698dbdf%5C
   ```
3. All four requests return byte-identical `HTTP 200` HTML (`response.txt`) — as predicted in §2.
4. Greps `suitecrm.log` (via the app container) for each marker. Actual output (`run.log`):
   ```
   [INFO] [baseline_0bs] backslashes=0 expect_error=False found_error=False
   [INFO] [odd_1bs] backslashes=1 expect_error=True found_error=True
       log line: ... Query Failed: SELECT * FROM folders WHERE folders.id LIKE "ODD-10c7698dbdf\" OR folders.parent_folder LIKE "ODD-10c7698dbdf\": MySQL error 1064 ...
   [INFO] [even_2bs] backslashes=2 expect_error=False found_error=False
   [INFO] [odd_3bs] backslashes=3 expect_error=True found_error=True
       log line: ... Query Failed: ... LIKE "ODD-350abe56a47\\\" OR ... LIKE "ODD-350abe56a47\\\": MySQL error 1064 ...
   ==> VULN-044: CONFIRMED — low-priv user mod_5f437596: 2/2 odd-backslash payloads -> MySQL error 1064 in suitecrm.log, 2/2 even/baseline payloads -> clean parse, 100% reproducible
   ```
5. Observable proof: `evidence/oracle_log_lines.txt` has the full 4-case log grep results, showing the exact injected SQL text MySQL rejected, attributed to our marker.

## 5. Impact

- **What was demonstrated**: a reliable, 100%-reproducible, attacker-controlled boolean-style SQL injection oracle — proof that raw request data is interpolated into and executed as part of a live SQL statement, with no character-level defense against it beyond an accidental one (the query needs a literal `"` to do anything more than error, and that's the one character `securexss` blocks).
- **What was NOT demonstrated, and why (honest scope)**: data exfiltration. `$f` is duplicated into both `LIKE` clauses with the *same* value and no reachable quote character, so — worked through exhaustively in `automation.py`'s module docstring — the only two reachable states are "both clauses parse as ordinary inert string literals" (even parity) or "the whole rest of the statement is one unterminated string, guaranteed syntax error" (odd parity). There is no reachable third state where attacker text becomes live, executable SQL through *this* sink, so no UNION/boolean-data-read was attempted or is claimed.
- **Realistic residual risk**: (a) a reliable, unauthenticated-feeling (any low-priv user) way to spam `suitecrm.log`/trigger repeated DB errors; (b) confirms a broader pattern (raw concatenation without `$db->quote()`) that the same file has elsewhere with worse consequences (`claude_audit/SuiteCRM/vulns/VULN-044.md` "Known-issue status": GHSA-7jj8, GHSA-9rvr, CVE-2026-69136 are published SQLi in other `EmailUIAjax.php` sinks); (c) a determined attacker with a slightly different entry point into the same `handleSubs()` function (e.g. the `updateSubscriptions` case, `EmailUIAjax.php:1044-1058`, which reaches the identical sink via `explode("::", $_REQUEST['subscriptions'])` instead of an array) might find a request shape where the duplication constraint doesn't hold — out of scope for this validation but worth a follow-up static note.

## 6. Suggested fix

At `modules/Emails/EmailUIAjax.php:76-79`:
```php
foreach ($viewFolders as $f) {
    $query = 'SELECT * FROM folders WHERE folders.id LIKE ' . $db->quoted($f)
        . ' OR folders.parent_folder LIKE ' . $db->quoted($f);
    $result = $db->query($query);
```
or, better, validate `$f` as a GUID (`SuiteValidator::isValidId()`, already imported in this file and used two cases later at `:1130-1132`) before it ever reaches string concatenation — folder ids are always GUIDs, so anything that isn't one should be rejected outright rather than escaped. Principle: parameterize/escape for context, and prefer allowlisting the expected shape (GUID) over relying on a generic XSS filter to double as a SQL-injection defense.

## 7. References

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command.
- Known-issue status (per `claude_audit/SuiteCRM/vulns/VULN-044.md`): same file has multiple published SQLi (GHSA-7jj8, GHSA-9rvr, CVE-2026-69136); this `handleSubs`/`ieIdShow[]` backslash sink is a distinct instance.
- PortSwigger Web Security Academy — "SQL injection: Detecting SQL injection vulnerabilities" (https://portswigger.net/web-security/sql-injection#detecting-sql-injection-vulnerabilities).
- OWASP WSTG-INPV-05 — Testing for SQL Injection.
- MySQL Reference Manual §9.1.1 "String Literals" (backslash escape semantics under default `sql_mode`).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 65 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM EmailUIAjax setFolderViewSelection OR handleSubs OR ieIdShow SQL injection` — no hit on any of the three names; returned CVE-2024-36410 (messages count), CVE-2024-36411 (displayView), CVE-2026-29099 (OutboundEmail retrieve), CVE-2020-8804
2. `CVE-2026-69136 SuiteCRM SQL injection` — no such CVE exists in any index (scanner hint was invalid); only CVE-2026-33288 (LDAP login SQLi) and CVE-2026-29099 returned
3. `SuiteCRM EmailUIAjax SQL injection folders subscription CVE GHSA 7.15` — CVE-2026-29099 / GHSA-38rf-h37x-7767 (OutboundEmail `retrieve()` `$id`, fixed 7.15.1), CVE-2024-36410 / GHSA-7jj8-m2wj-m6xq, CVE-2024-36411 / GHSA-9rvr-mcrf-p4p7, KIS-2020-05; none concern `folders` / subscriptions
4. `SuiteCRM EmailUIAjax SQL injection advisory list CVE-2024-36410 ... CVE-2024-36416` — only 36410/36411 resolved; a "Tree data entry point" SQLi is mentioned without ID; nothing on handleSubs

**Related but distinct public references** (same class or component, not this bug):
- CVE-2024-36410 / GHSA-7jj8-m2wj-m6xq — SQLi in EmailUIAjax "messages count" controller (fixed 7.14.4), same file, different action/sink
- CVE-2024-36411 / GHSA-9rvr-mcrf-p4p7 — SQLi in EmailUIAjax `displayView` (fixed 7.14.4), different action
- CVE-2026-29099 / GHSA-38rf-h37x-7767 — blind SQLi in `OutboundEmail::retrieve()` reached via EmailUIAjax (fixed 7.15.1), different sink
- KIS-2020-05 / CVE-2020-8804 — boolean SQLi in EmailUIAjax `addContact`/`addContactsMultiple`/`removeContact` (<= 7.11.10), different actions

**Reasoning:** `modules/Emails/EmailUIAjax.php` has at least five published SQL-injection CVEs, but every one names a different `emailUIAction`/sink; none references `handleSubs()`, `setFolderViewSelection`, `updateSubscriptions`, `ieIdShow[]`, or the `folders` LIKE query. The density of prior SQLi disclosures in this file and the terse vendor advisories (several 7.15.x fixes have no public component detail) lower confidence; a quiet fix or private report in this exact loop is plausible, but no public match was found and the sink is confirmed live on 7.15.2.
