# VULN-025 — GenericInterface XSLT mapping unsandboxed → file R/W + SSRF (admin)

| | |
|---|---|
| **ID** | VULN-025 (raw ZN-008) · **Software** Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium · CVSS 3.1 **6.5** — `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** · **Auth**: admin (web-service author/importer) |
| **Attacker gains** | Arbitrary host file **write** (→ RCE) and **read** from an admin-authored XSLT mapping. |

## Summary
Znuny's GenericInterface XSLT mapping instantiates the `XML::LibXSLT`/`XML::LibXML` engines with no
security callbacks and no network/entity restrictions. An admin-authored (or imported) stylesheet
can therefore use the `exsl:document` EXSLT extension to **write** arbitrary host files and libxslt
`document()` to **read** them. Confirmed: driving Znuny's own `Mapping::XSLT->Map` with a malicious
stylesheet wrote `PWNED-XSLT-<sfx>` to `/tmp/xslt_write_<sfx>.txt` on the host.

## How it works (mechanism & code trace)
`Kernel/GenericInterface/Mapping/XSLT.pm`:
```perl
167:  my $LibXSLT = XML::LibXSLT->new();                 # <-- no ->security_callbacks(...)
...
180:  $StyleDoc = XML::LibXML->load_xml(
181:      string => $Template, ...                        # <-- no no_network=>1, no expand_entities(0)
183:  );
...
285:  my $Results = $Stylesheet->transform( $SourceXML );  # runs the attacker stylesheet
```
A grep of the tree confirms `security_callbacks`, `no_network`, and `expand_entities(0)` are absent
codebase-wide. With no `XML::LibXSLT->security_callbacks()` denying read/write/net, the stylesheet
gets the engine's full capabilities:
- **Write:** `<exsl:document href="/path" method="text">…</exsl:document>` (EXSLT) writes an
  arbitrary file — dynamically confirmed (`/tmp/xslt_write_<sfx>.txt` = `PWNED-XSLT-<sfx>`).
- **Read:** `document('file:///path')` opens an arbitrary host file — reachability confirmed
  (`document('/etc/passwd')` produced a libxml parse error on the non-XML content, i.e. the file
  was opened and fed to the parser).
- **Network SSRF:** `document('http://…')` — blocked on *this* libxml2 2.9.14 build (no nanohttp),
  so net-SSRF is not exploitable here; file R/W is.

## Why it is a vulnerability
The XSLT mapping is meant to transform GenericInterface request/response data — a pure,
side-effect-free data transformation. Granting the stylesheet filesystem read/write (and, on other
builds, network) capabilities crosses the application→host trust boundary (`S:C`). Although the
stylesheet author is an admin, "admin may configure web-service mappings" does not imply "admin may
write arbitrary host files / read `/etc`" — and, crucially, the arbitrary **write** is a direct
remote-code-execution primitive (write a `.pm` to an `@INC`-reachable path, a cron entry, or a
webshell), escalating a config capability into host compromise. A hardened XSLT processor is
sandboxed by default (deny file/net); Znuny disables none of it.

## Reproduction
`./run.sh` builds a stylesheet with `exsl:document` (write) + `document()` (read), runs it through
`Kernel::GenericInterface::Mapping::XSLT`, and shows:
```
[PROOF] arbitrary file WRITE: /tmp/xslt_write_<sfx>.txt contains 'PWNED-XSLT-<sfx>' ...
```
(In production the same stylesheet is reached by importing a web service whose mapping backend is
XSLT and invoking the operation/invoker.)

## Impact
Arbitrary host file write (→ RCE) and read as the web user, from an admin-authored/imported
web-service mapping — full host compromise potential. Net-SSRF is build-gated (blocked on libxml2
2.9.14). Chains with VULN-047 (module-load) and the admin file-reads (VULN-007/026/027).

## Suggested fix
Register `XML::LibXSLT->security_callbacks()` that deny file read, file write, and network; and
parse the stylesheet/source with `no_network => 1`, `expand_entities => 0`, `load_ext_dtd => 0`.
Disable EXSLT `document`/write extensions unless explicitly required.

## References
- OWASP XXE Prevention Cheat Sheet; XSLT injection guidance; libxslt security docs
  (`exsl:document`, `document()`). CWE-611, CWE-73.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. NVD API keyword pull for "Znuny"/"OTRS" grepped for XSLT / GenericInterface / web service — CVE-2014-9324 (GI arbitrary ticket access, OTRS 3/4), CVE-2023-38060 (GI attachment ContentType header injection), CVE-2024-43446 and CVE-2025-26846 (GI permission checks), CVE-2022-4427 (GI TicketSearch SQLi); nothing on XSLT mapping sandboxing
2. Znuny advisory index ZSA-2021-01 … ZSA-2026-16 reviewed — admin-to-code advisories exist (ZSA-2022-02 authenticated RCE, ZSA-2022-04 Template Toolkit, ZSA-2022-05/06 Perl code in AdminUser/ACLs) but none for `Kernel::GenericInterface::Mapping::XSLT`
3. GitHub advisory DB (19 Znuny entries) and Debian tracker reviewed — no XSLT entry
4. `gh search issues --repo znuny/Znuny "XSLT"` / `"XSLT mapping"` — functional bugs only (#807 whitespace, #804 interpolation, #694 base64)
5. (Shared WebSearch budget was exhausted before this finding; evidence below comes from direct primary-source pulls: NVD CVE API, vendor advisory pages, GitHub advisory DB, Debian tracker, GitHub issue search.)

**Related but distinct public references** (same class or component, not this bug):
- ZSA-2022-02 / ZSA-2022-04 / ZSA-2022-05 / ZSA-2022-06 — admin-level code execution via other features (Template Toolkit, AdminUser, ACLs); same "admin to host" family, different sinks
- CVE-2026-53804 — OTRS CE PGP module OS command injection via admin-supplied binary path; same actor/impact family, different module

**Reasoning:** No public reference describes `XML::LibXSLT`/`XML::LibXML` being instantiated without `security_callbacks`/`no_network` in the GI XSLT mapping, nor `exsl:document` file write through it. The vendor has historically patched admin-to-RCE paths (four ZSAs in 2022), suggesting it would treat this as in scope, but it has also treated admin-authored configuration as trusted, so a by-design dismissal is possible; nothing public matches the component.
