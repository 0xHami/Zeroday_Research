# VULN-032 — Authenticated XML-import entity-expansion / unbounded in-memory-DOM DoS (NOT XXE)

> Note (2026-10-21 triage): this folder shipped without a `writeup.md`; the finding is documented in `notes.md` (validated 2026-09-29) and in `Umbraco-CMS_audit/vulns/VULN-032.md`. This file was created to hold the Known Issue Check below. Software: Umbraco CMS, https://github.com/umbraco/Umbraco-CMS, 18.3.0-rc, commit `cee7d8981ab0fd18b4dc96449ae071edf1aaf21e`, Severity Medium (CVSS 4.9), Status CONFIRMED.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 70 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `gh api search/issues q='repo:umbraco/Umbraco-CMS "billion laughs" OR "entity expansion" OR DtdProcessing OR XmlResolver'` — only PR #22550 "Security: Prevent XXE opportunity in `OEmbedProviderBase`" (different component) and unrelated UI items.
2. `gh api search/issues q='repo:umbraco/Umbraco-CMS dictionary import XML "XDocument" OR "entity"'` — only packaging/dependency PRs; nothing about entity expansion or DoS on import/analyze.
3. GitHub advisory DB full listing for NuGet `Umbraco.Cms` (gh GraphQL) — nearest: CVE-2025-66625 / GHSA-hfv2-pf68-m33x (temporary-file handling in dictionary import, 13.12.1) and CVE-2025-32017 (path traversal); no entity-expansion/DoS advisory.
4. `gh api repos/umbraco/Umbraco-CMS/commits?path=src/Umbraco.Core/Services/ImportExport/TemporaryFileToXmlImportService.cs&since=2026-01-01` — only a documentation commit; current `main` still calls `XDocument.LoadAsync(fileStream, LoadOptions.None, ...)` with no hardened `XmlReaderSettings`.
5. Umbraco Aug-18-2026 / Oct-6-2026 security advisories (WebFetch) — no XML import item.
6. WebSearch queries for this folder could not be run (session search budget exhausted); CVE-2017-15280 was verified via the scanner's cited cvedetails reference as the historical XXE fix.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2017-15280 — XXE in Umbraco 7.x XML import (fixed 7.7.3 via `XmlResolver = null`); external entities, not internal expansion/DOM DoS, and a legacy code path.
- PR #22550 — XXE hardening in `OEmbedProviderBase`; different component.
- CVE-2025-66625 / GHSA-hfv2-pf68-m33x — dictionary-import temporary-file handling; same feature area, different root cause.

**Reasoning:** No public advisory or issue describes internal entity expansion / uncapped DOM materialisation on the Management API `import/analyze` or dictionary-import `XDocument.LoadAsync` path, and the code is unchanged upstream. Confidence is capped at 70 because .NET's default `MaxCharactersFromEntities` limit bounds the amplification (impact is modest, A:L) and vendors often treat authenticated XML-parse DoS as low priority or by-design.
