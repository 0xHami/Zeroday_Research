# VULN-027 — AdminOAuth2TokenManagement TokenConfigTemplateFilename cross-dir *.yml read

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (4.9)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- Admin-group agent session (`root@localhost` / `ZnunyAdmin_2f8b`). No other state.

## Request
Tokenless GET (see `request.http`):
```
GET /znuny/index.pl?Action=AdminOAuth2TokenManagement;Subaction=AddTokenConfigByTemplateFile;TokenConfigTemplateFilename=../oauth2_token_config_example
```

## Response
- Traversal → title `Manage OAuth2 tokens and their configurations.` (success) and the response
  body contains `Microsoft Outlook …` — content of `oauth2_token_config_example.yml`, which
  lives *outside* `scripts/OAuth2TokenManagement/TokenConfigTemplates/`.
- Nonexistent path → `Error - AdminOAuth2TokenManagement`.

## Observation
Confirms `AdminOAuth2TokenManagement.pm:977` builds `base . '/' . $Filename . '.yml'` and
`FileRead`s it with no `../` filtering; `../` escapes the base dir. The `.yml` suffix is
hard-appended (read is constrained to `*.yml`), and full content is reflected only for files
that parse as a YAML array of templates (Name/ClientID/… surface in the Edit form). No CSRF
token on this subaction.

## Side effects
None (read only; nothing saved unless the admin then submits SaveTokenConfig). Idempotent.

## Research & references
- OWASP WSTG-ATHZ-01 — Directory Traversal / File Include (out-of-base read via `../`).
- CWE-22.

## Scope / bound
Weaker than VULN-026: constrained to `*.yml` and content-reflection needs a YAML-array file.
Still a genuine cross-directory read primitive crossing out of the intended template directory.
