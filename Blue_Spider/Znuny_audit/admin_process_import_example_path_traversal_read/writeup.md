# VULN-007 — Broken `../` filter in AdminProcessManagement → admin arbitrary host file read

| | |
|---|---|
| **ID** | VULN-007 (raw ZN-005/006) |
| **Software** | Znuny |
| **Repository** | https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release) |
| **Commit** | `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium · CVSS 3.1 **6.5** — `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N` (read); LFI→RCE variant conditionally High |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | admin-group agent (`root@localhost`; any operator in the `admin` group reaches `AdminProcessManagement`) |
| **Attacker gains** | Reads files anywhere on the host FS that the web user can open — a host-wide readability oracle crossing the application→OS trust boundary. |

## Summary

`AdminProcessManagement`'s "import example process" feature sanitises the caller-supplied
`ExampleProcess` filename with a single-pass regex that is missing the `/g` modifier. Only the
*first* traversal token is stripped, so a payload that begins with `/` loses just that leading
slash and keeps every subsequent `../`. The value flows unchanged into `Main::FileRead` under
`$Home/var/processes/examples/`, letting an admin read arbitrary host files. Dynamic testing
confirms `/etc/passwd` is read while `/etc/shadow` (present but root-only) and nonexistent
paths are not — proving the read reaches the host filesystem with the web user's own
privileges, outside the intended directory.

## How it works (mechanism & code trace)

**Entry point.** `Kernel/Modules/AdminProcessManagement.pm`, subaction `ProcessImport`
(line 92). It first reads the attacker-controlled parameter:

```perl
103:  my $ExampleProcess = $ParamObject->GetParam( Param => 'ExampleProcess' );
...
108:  my $ExampleProcessFilename = $ParamObject->GetParam( Param => 'ExampleProcess' );
109:  $ExampleProcessFilename =~ s{/+|\.{2,}}{}smx;    # remove slashes and ..
```

**The exact defect (line 109).** The substitution `s{ /+ | \.{2,} }{}smx` has **no `/g`
flag**, so Perl replaces only the *leftmost single* match of the alternation. Trace the
payload `"/../../../../../etc/passwd"`:

- The engine scans from offset 0. The first position matches the `/+` branch — the single
  leading `/`. That one match is deleted.
- Because there is no `/g`, substitution stops. The remaining `../../../../../etc/passwd`
  (all `..` sequences intact) is **not** examined again.

Result: `../../../../../etc/passwd`. The comment "remove slashes and .." is simply wrong about
what the code does.

**The sink (lines 146-147).** The "cleaned" value is concatenated into a path and read:

```perl
146:  $Content = $MainObject->FileRead(
147:      Location => "$Home/var/processes/examples/$ExampleProcessFilename",
148:      Mode     => 'utf8',
149:  );
```

With `$Home = /opt/znuny`, the location becomes
`/opt/znuny/var/processes/examples/../../../../../etc/passwd`, which the OS resolves to
`/etc/passwd`. `Kernel/System/Main.pm::FileRead` performs **no** traversal filtering of its own
— it opens exactly the path it is handed.

**Why `.yml` does not save it.** Line 118 (`$ExampleProcessFilename =~ m{(.*?)\.yml$}smx;`)
captures a base name only to build the optional `_pre.pm`/`_post.pm` require path (lines
122-128). It never re-assigns `$ExampleProcessFilename` and is **not** a guard on the
`FileRead` — so any extension is read. Confirmed dynamically: `/etc/passwd` (no `.yml`) reads
fine.

**What the content becomes.** After the read, `ProcessImport` (`Kernel/System/ProcessManagement/
DB/Process.pm:1713`) runs `YAML->Load` and rejects non-hash content:

```perl
1716:  if ( ref $ProcessData ne 'HASH' ) {
1717:      return ( Message => "Couldn't read process configuration YAML file. ..." );
1718:  }
```

So the byte stream isn't echoed for a file like `/etc/passwd`, but the three distinct outcomes
form a reliable oracle (see Reproduction). CSRF is not the gap here — `ProcessImport` is
`ChallengeToken`-protected — the defect is the traversal + host-FS read.

## Why it is a vulnerability

The feature's intended capability is narrow: import one of the *shipped example* process
definitions that live under `var/processes/examples/`. The security invariant is therefore
"read only files inside that directory." The trust boundary crossed is application → host
operating system: an admin-frontend operator is trusted to administer Znuny, **not** to read
arbitrary operating-system files (`/etc/passwd`, other tenants' data, secrets outside Znuny,
mail spools, keys). The `S:C` (scope-changed) CVSS metric reflects exactly this — the impact
lands on the host, a different security authority than the app.

The developer clearly *intended* to confine the path (the `s///` and its comment prove intent),
so the escape is a bug, not a documented capability. The `/etc/passwd`-readable vs
`/etc/shadow`-unreadable result is decisive: a confined implementation would treat both
identically (both "inside examples/? no → reject"); instead the app faithfully reports the
host FS's own permission decision, which is only possible if it actually `open()`ed the host
path.

## Reproduction

From a clean lab (`docker compose -p cvehunterlab_znuny up -d`):

1. Log in as admin and read the `ChallengeToken` from `AdminProcessManagement`.
2. POST three imports and compare the resulting screen `<title>`:

   ```
   POST /znuny/index.pl
   Action=AdminProcessManagement&Subaction=ProcessImport&ChallengeToken=<tok>
   &ExampleProcess=/../../../../../etc/passwd     -> "Error - Admin - Znuny"          (READ)
   &ExampleProcess=/../../../../../etc/shadow     -> "Fatal Error - Frontend - Znuny" (blocked)
   &ExampleProcess=/../../../../../etc/zzz_random -> "Fatal Error - Frontend - Znuny" (blocked)
   ```

3. Run `./run.sh`. Expected tail:

   ```
   [PROOF] passwd   -> 'Error - Admin - Znuny'          => READABLE
   [PROOF] shadow   -> 'Fatal Error - Frontend - Znuny' => UNREADABLE
   [PROOF] missing  -> 'Fatal Error - Frontend - Znuny' => UNREADABLE
   [OK] exploit confirmed ...
   ```

The `passwd` (readable) vs `shadow`/`missing` (not readable) split is the proof. Full capture in
`request.http`, `response.txt`, `run.log`.

## Impact

- **Host file readability oracle** as an admin operator: probe existence/readability of any path
  the web user (`www-data`) can open, across the whole host — not confined to Znuny.
- **Content disclosure** for any file that parses as a process-YAML hash (imports and surfaces
  entity names). Perl configs read successfully but aren't reflected, so `Kernel/Config.pm`
  DB-credential exfil via *this* path is limited to confirming readability.
- **Chains** with VULN-025 / VULN-026 / VULN-027 (other admin file-read/SSRF primitives) to map
  and read the host, and with VULN-030/VULN-041 (weak hashes / cleartext mail creds) once a
  readable secret is located.
- **Conditional RCE:** the `_pre.pm`/`_post.pm` `Main::Require` (lines 124/192) turns a
  writable, traversal-reachable `.pm` into code execution — High if an attacker can stage such
  a file (e.g. via another upload primitive).

## Suggested fix

At `AdminProcessManagement.pm:109`, replace the single-pass denylist with confinement:

```perl
# reject any path separator / traversal outright, then confine with abs_path
use Cwd qw(abs_path);
my $Base = "$Home/var/processes/examples";
$ExampleProcessFilename =~ s{[/\\]}{}g;                 # no separators at all
$ExampleProcessFilename =~ s{\.\.+}{}g;                 # and no dot-runs (belt & braces)
my $Full = abs_path("$Base/$ExampleProcessFilename") // '';
return $LayoutObject->FatalError( Message => 'Invalid example process.' )
    if $Full !~ m{^\Q$Base\E/} || $Full !~ /\.yml$/;   # must stay inside base AND be .yml
```

Principle: allowlist by canonicalising (`abs_path`) and asserting the result is *inside* the
intended directory, rather than trying to scrub bad characters out of the input. Enforce the
`.yml` requirement on the actual read path, not just the require path.

## References
- OWASP WSTG-ATHZ-01 — Testing Directory Traversal / File Include (readable-vs-unreadable
  differential as an oracle for blind traversal reads).
- OWASP "Path Traversal" cheat sheet — canonicalise + confine over character-scrubbing.
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. ZSA-2024-01 / CVE-2024-32491 advisory page fetched (scanner's cited "known class") — it is a path traversal in the AJAX *file upload* (arbitrary write location), not `AdminProcessManagement` `ExampleProcess` read
2. NVD API keyword pull for "Znuny" (17) and "OTRS" (120) grepped for traversal/process/import — CVE-2024-32491, CVE-2024-23793 (OTRS upload traversal), CVE-2026-78355 (OTRS SendSupportBundle traversal/delete), CVE-2024-43443 and CVE-2024-48937 (process-management XSS); none is the example-process import
3. Znuny advisory index ZSA-2021-01 … ZSA-2026-16, GitHub advisory DB (19 entries), Debian security tracker for znuny reviewed — no process-import traversal entry
4. `gh search issues --repo znuny/Znuny "ExampleProcess"` / `"ProcessImport"` — no results
5. (WebSearch `Znuny OTRS AdminProcessManagement "ExampleProcess" path traversal ProcessImport` could not be executed: shared web-search budget exhausted)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2024-32491 / ZSA-2024-01 — path traversal in file upload (write), different module and sink
- CVE-2026-78355 — OTRS SendSupportBundle admin path traversal (delete / bundle inclusion); different module, OTRS 7+ product line
- CVE-2024-43443, CVE-2024-48937 / ZSA-2024-05 — XSS in Process Management; same admin module family, different class

**Reasoning:** No public advisory or issue mentions the single-pass `s{/+|\.{2,}}{}smx` sanitiser (missing `/g`) on `ExampleProcess` in `AdminProcessManagement::ProcessImport` or an arbitrary host file read through it. The traversal class has three recent Znuny/OTRS CVEs in other modules, so the class is well-trodden, but this specific sink is unlisted; admin-only preconditions also make it a less-targeted area, supporting the not-known verdict.
