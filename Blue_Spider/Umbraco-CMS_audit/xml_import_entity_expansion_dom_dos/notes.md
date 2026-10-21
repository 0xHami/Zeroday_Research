# VULN-032 — XML-import internal entity-expansion / uncapped in-memory DOM DoS (NOT XXE)

**Software**: Umbraco CMS
**Repository**: https://github.com/umbraco/Umbraco-CMS
**Affected version**: 18.3.0-rc (version.json; commit-pinned)
**Commit**: cee7d8981ab0fd18b4dc96449ae071edf1aaf21e
**Validated**: 2026-09-29
**Status**: CONFIRMED
**Category**: CWE-776 (recursive entity references / billion laughs) + CWE-400 (uncontrolled resource consumption)

## Preconditions
- Any authenticated backoffice user (import/analyze + temp-file are floor-only). Admin token used here.

## What was run
1. `POST /umbraco/management/api/v1/temporary-file` (multipart `Id`+`File`, `.xml`) to stage a payload.
2. `GET /umbraco/management/api/v1/import/analyze?temporaryFileId=<key>` triggers `XDocument.LoadAsync` at TemporaryFileToXmlImportService.cs:66.

## Measured result (entity-expansion amplification)
| input bytes | expanded chars | analyze time |
|---|---|---|
| 36 (trivial) | – | 8 ms |
| 455 | 262,144 | 23 ms |
| 439 | 1,048,576 | 44 ms |
| 435 | 6,291,456 | 170 ms |

A ~435-byte request forced ~6.29M chars of parse + DOM work (**amplification ×14,463**); parse time grows monotonically with expanded size (~linear in expanded chars, the in-memory-DOM cost). Bounded well under the ~10M ceiling; disk/CPU never exhausted.

## Not-XXE confirmation (report correction verified)
External-entity payload `<!ENTITY xxe SYSTEM "file:///etc/passwd">` → analyze HTTP 400 in 15 ms, `/etc/passwd` contents **absent** from the response. `XmlReaderSettings.XmlResolver` defaults to `null` on .NET Core+ and no call site overrides it → external entities do not resolve → **DoS-only, not XXE**. (Internal expansion still runs because `LoadOptions.None` parses the DTD, `DtdProcessing = Parse`.)

## Interpretation
Internal entity expansion executes and materializes a multi-megabyte DOM from a few hundred input bytes, with no pre-load size cap; concurrent requests multiply the CPU/memory. Per-request cost is modest (hence Medium/A:L), but the amplification + missing hardened reader = CONFIRMED. Analyze returns 400 because the `<lolz>` root is an undetermined entity type — the expensive load already completed before that check (`AnalyzeAsync` loads first, then classifies).

## Reproduce
`cd exploits/VULN-032 && NO_COLOR=1 ./run.sh` (env `BASE_URL`, `ADMIN_USER`, `ADMIN_PASS`).

## References
- CWE-776 (billion laughs), CWE-400. OWASP API4:2023 Unrestricted Resource Consumption.
- Historical: CVE-2017-15280 (XXE in Umbraco XML import, fixed via `XmlResolver=null`) — that fix blocks external XXE here; the residual internal-expansion/DOM DoS is unadvised.
