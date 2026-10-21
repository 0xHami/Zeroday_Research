# VULN-027 — AdminOAuth2TokenManagement `TokenConfigTemplateFilename` arbitrary `*.yml` read

| | |
|---|---|
| **ID** | VULN-027 (raw ZN-007) |
| **Software** | Znuny · **Repository** https://github.com/znuny/Znuny |
| **Affected version** | 7.3.x (post-7.3.7, dev branch; commit-pinned) · **Commit** `b6c9d94c197d1b8a50c17247705ab5cc85b85e13` |
| **Severity** | Medium · CVSS 3.1 **4.9** — `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | admin-group agent (`root@localhost`); no CSRF token on the subaction |
| **Attacker gains** | Reads any `*.yml` file on the host, cross-directory, with its content reflected into the response. |

## Summary
The "add token config from a template file" action concatenates the caller-controlled
`TokenConfigTemplateFilename` into a path under a fixed base directory and reads it with
`Main::FileRead`, with no traversal filtering. `../` escapes the base directory; the file's
content is parsed and reflected into the Edit form. `.yml` is hard-appended, constraining the
read to YAML files, but that still exposes any `*.yml` on the host and is a clear traversal.

## How it works (mechanism & code trace)
**Entry** — `Kernel/Modules/AdminOAuth2TokenManagement.pm:61` dispatches `Subaction=
AddTokenConfigByTemplateFile` → `_AddTokenConfigByTemplateFile` (`:356`), which reads the
parameter at `:366`:
```perl
366:  my $TokenConfigTemplateFilename = $ParamObject->GetParam( Param => 'TokenConfigTemplateFilename' );
```
**Sink** — `_GetTokenConfigTemplate` builds the path and reads it:
```perl
 43:  $Self->{TokenConfigTemplateFilesBasePath} = $HomePath . '/scripts/OAuth2TokenManagement/TokenConfigTemplates';
...
977:  my $TokenConfigTemplateFilePath = $Self->{TokenConfigTemplateFilesBasePath}
978:      . '/' . $Param{TokenConfigTemplateFilename} . '.yml';
979:  my $TokenConfigTemplateFileContent = $MainObject->FileRead( Location => $TokenConfigTemplateFilePath, ... );
```
**Exact defect.** `$Param{TokenConfigTemplateFilename}` is interpolated with no
`FilenameCleanUp`/`abs_path`/`..` rejection. `../oauth2_token_config_example` yields
`.../TokenConfigTemplates/../oauth2_token_config_example.yml`, i.e. a file one directory *above*
the intended template dir. The parsed array is reflected into the `AdminOAuth2TokenManagement/
Edit` template (`:398`). The `.yml` suffix is appended unconditionally, so only YAML files are
reachable, and full reflection requires the file to be a YAML *array* (`IsArrayRefWithData`).
No `ChallengeTokenCheck` guards this subaction.

## Why it is a vulnerability
The intended read scope is the shipped template directory only. Reading files outside it
(`../…`) violates that confinement. It is a lower-severity sibling of VULN-026 (constrained to
`*.yml`, `S:U` not `S:C` because reachable secrets are usually within the app tree), but it is
still an unintended traversal: the code names a fixed base path precisely because it means to
stay there. Confirmed by the differential — a file that exists *outside* the base is read and
reflected, while a nonexistent name errors.

## Reproduction
1. Log in as admin. 2. Tokenless GET:
```
GET /znuny/index.pl?Action=AdminOAuth2TokenManagement;Subaction=AddTokenConfigByTemplateFile;TokenConfigTemplateFilename=../oauth2_token_config_example
```
3. `./run.sh` → the out-of-base file's marker `Microsoft Outlook` is reflected in the response
   (title stays `Manage OAuth2 tokens…`), whereas `../<random>` returns `Error -
   AdminOAuth2TokenManagement`. Capture: `request.http`, `response.txt`, `run.log`.

## Impact
Cross-directory disclosure of any `*.yml` the web user can read (other web-service configs,
mail/OAuth templates that may embed client IDs/secrets). Combined with the broader reads of
VULN-007/VULN-026 it aids host recon. Lower ceiling than 026 because of the `.yml` suffix and
YAML-array reflection constraint.

## Suggested fix
At `AdminOAuth2TokenManagement.pm:977`: `FilenameCleanUp(Type=>'Local')` on the parameter, then
`abs_path` and assert the result is inside `TokenConfigTemplateFilesBasePath`; or allowlist
against the actual filenames in that directory. Add `ChallengeTokenCheck` to the subaction.

## References
- OWASP WSTG-ATHZ-01 (Directory Traversal). CWE-22.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. NVD API keyword pull for "Znuny" (17) and "OTRS" (120) grepped for OAuth / token / traversal — no OAuth2 entry at all; traversal CVEs are CVE-2024-32491 (upload), CVE-2024-23793 (upload), CVE-2026-78355 (SendSupportBundle)
2. Znuny advisory index ZSA-2021-01 … ZSA-2026-16, GitHub advisory DB (19 entries), Debian tracker reviewed — no AdminOAuth2TokenManagement entry
3. `gh search issues --repo znuny/Znuny "OAuth2 template"` — functional issues only (#709 refresh token, #702 Google OAuth2, #340 template error); `"TokenConfigTemplateFilename"` issue search — none (commit search blocked by API rate limit)
4. ZSA-2024-01 advisory page fetched (scanner's cited class) — unrelated upload traversal
5. (Shared WebSearch budget was exhausted before this finding; evidence below comes from direct primary-source pulls: NVD CVE API, vendor advisory pages, GitHub advisory DB, Debian tracker, GitHub issue search.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2024-32491 / ZSA-2024-01 — AJAX upload path traversal (write); different module and sink
- CVE-2026-78355 — OTRS 7+ SendSupportBundle admin traversal; OTRS product line, different module

**Reasoning:** `AdminOAuth2TokenManagement` is a Znuny-only module (no OTRS CE lineage), and no ZSA, CVE, GHSA or GitHub issue mentions `TokenConfigTemplateFilename` or `_GetTokenConfigTemplate` traversal. The impact is bounded (admin, `.yml` suffix, YAML-array reflection), which also makes it a less likely target for prior research; nothing public matches.
