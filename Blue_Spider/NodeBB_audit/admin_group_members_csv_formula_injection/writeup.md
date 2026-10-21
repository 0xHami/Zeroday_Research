# VULN-010 — CSV / formula injection in the group-members export

| | |
|---|---|
| **ID** | VULN-010 |
| **Software** | NodeBB |
| **Repository** | https://github.com/NodeBB/NodeBB |
| **Affected version** | 4.16.0 (`install/package.json:5`; commit-pinned, untagged `master`) |
| **Commit** | `20623201cbf2cc8a37612726cdf10ee82083c9c3` |
| **Severity** | Medium — **CVSS 3.1 6.3** `AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:N` |
| **Status** | **CONFIRMED (dynamic)** |
| **Auth required** | Attacker: any registered account. Victim: an admin who exports the group and opens the CSV. |
| **Attacker gains** | Formula/DDE execution in the admin's spreadsheet client (data exfiltration via `HYPERLINK`/`WEBSERVICE`, or command execution via DDE). |

## Summary
The ACP group-members CSV export writes each member's `email`/`username`/`uid` cell verbatim, with no formula neutralization. An unprivileged user whose username (or email) begins with a formula trigger (`= + - @`) therefore plants an active formula in the file; when an admin later opens the exported CSV in Excel/LibreOffice, the cell is interpreted as a formula/DDE and executes on the admin's workstation. NodeBB's *users* export already neutralizes exactly this — the group export is a regression. Confirmed dynamically: a member registered as `+HYPERLINK_<rand>` appears in the group CSV as the raw cell `"+HYPERLINK_<rand>"` with no neutralizing apostrophe.

## How it works (mechanism & code trace)

**Vulnerable export (`src/controllers/admin/groups.js:96-105`):**
```js
const groupName = req.params.groupname;
const members = (await groups.getMembersOfGroups([groupName]))[0];
const fields = ['email', 'username', 'uid'];
const userData = await user.getUsersFields(members, fields);
const json2csvAsync = new AsyncParser({ fields });
const csvContent = await json2csvAsync.parse(userData).promise();   // raw cells, no neutralization
res.attachment(`${slugify(groupName)}_members.csv`);
res.end(csvContent);
```

**The sibling that gets it right (`src/user/admin.js:106-110`):**
```js
function neutralizeCsvFormula(value) {
    const str = String(value);
    return (/^[\t\r ]*[=+\-@]/).test(str) ? `'${str}` : str;   // prefix ' when a cell starts with = + - @
}
```
The users export calls this on every cell (`admin.js:91`); the group export does not.

**Attacker-controlled cells.** `isUserNameValid` (`public/src/utils.common.js:341-346`) permits leading `+` and `-` (both formula triggers). `isEmailValid` (`:337-339`) only forbids `,`/`;`, so an email like `=cmd|'/C calc'!A1@a.aa` — a classic DDE payload — passes validation. Either lands unescaped in the group CSV. Dynamically the username cell came through as `+HYPERLINK_<rand>` (leading `+`, no apostrophe).

## Why it is a vulnerability (reasoning)
A CSV cell whose first character is `=`, `+`, `-`, or `@` is treated as a formula by every major spreadsheet; serving user-controlled data into such a cell without neutralization is CSV/formula injection (CWE-1236, OWASP). This is a *second-order* injection: the unprivileged attacker plants the payload (in their own username/email), and the trusted admin triggers it by exporting and opening the file. Crucially it is **not** an "admin can do X" issue — the admin is the victim, the attacker is unprivileged. NodeBB clearly considers this in scope (it neutralizes the users export); the group export simply omits the same call, so the defect is a genuine regression, not intended behavior.

## Reproduction
1. As any user (open self-registration), register with a username beginning with `+` (e.g. `+HYPERLINK_<rand>`), or set an email beginning with `=`.
2. Get added to / join any group.
3. As admin, export the group: `GET /api/admin/groups/<group>/csv` with `Referer: <url>/admin/manage/groups`.
4. Inspect the CSV: the member's cell begins with the formula trigger and has no leading apostrophe (see `evidence/group_members.csv`).
5. `./run.sh` creates the user + group, adds the member, exports the group CSV, and asserts the cell is an un-neutralized formula. Prints `[OK] exploit confirmed`.
6. Opening the file in Excel/LibreOffice evaluates the cell as a formula (the victim step; gated by the spreadsheet's own "enable content/DDE" prompt).

## Impact
When the admin opens the exported group CSV, attacker-controlled cells execute as formulas/DDE in the admin's spreadsheet: data exfiltration via `=HYPERLINK(...)`/`=WEBSERVICE(...)`, or command execution via DDE (`=cmd|'/C ...'!A1`), on the admin's workstation. The attacker is unprivileged; the blast radius is the admin's endpoint. Impact is gated by the victim opening the file and clearing spreadsheet security prompts (UI:R), hence Medium.

## Suggested fix
Apply `neutralizeCsvFormula` to every exported cell in `src/controllers/admin/groups.js` (mirror `src/user/admin.js`); ideally factor the helper into a shared util and use it in all CSV exporters (also the admin error-log export, `src/controllers/admin/errors.js`). Consider rejecting leading `= + - @` (and tab/CR) in usernames at registration as defense in depth.

## References
- OWASP CSV Injection (Formula Injection) — https://owasp.org/www-community/attacks/CSV_Injection
- CWE-1236 (Improper Neutralization of Formula Elements in a CSV File).
- Related NodeBB class: user-export CSV injection CVE-2023-26045 (this is the un-fixed group-export sibling).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 85 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `NodeBB CSV injection formula group members export admin groups csv vulnerability` — only CVE-2023-26045 (user-export path traversal, different class) and Ghost CVE-2024-34448 (CSV injection in a different product); nothing on a NodeBB group export.
2. `NodeBB "neutralizeCsvFormula" OR "csv injection" OR "formula injection" commit fix` — only CWE-1236 CVEs in other projects (yii-helpers, admidio, phpmyfaq); no NodeBB hit.
3. `GHSA NodeBB path traversal 2026 security advisory` + NodeBB GitHub security-advisories page (9 advisories, 2020–2023) — none mention CSV, formula injection, exports or groups.
4. OpenCVE vendor listing for nodebb (23 CVEs through 2026-08) — no CSV/formula-injection entry.
5. Upstream history of `src/controllers/admin/groups.js` and `src/user/admin.js` (master) — no commit mentioning formula/injection/neutralize; `groupsController.getCSV` on current master still feeds `email`/`username`/`uid` to `@json2csv/node` with no neutralization.

**Related but distinct public references** (same class or component, not this bug):
- CVE-2023-26045 / GHSA-vh2g-6c4x-5hmp — path traversal + code execution via the *user*-export code path; different class and component.
- CVE-2024-34448 (Ghost) — CSV injection in a member export of a different product; same class only.
- NodeBB `src/user/admin.js` `neutralizeCsvFormula` (users CSV export) — upstream hardening of the sibling exporter with no advisory/CVE; the group exporter never received the same treatment.

**Reasoning:** No CVE, GHSA, vendor advisory, issue or upstream commit describes formula injection in the ACP group-members CSV export, and the sink is unchanged on current master. CSV injection is a very common class and the maintainers evidently know of it (they neutralize the users export), so a private report or quiet future fix is plausible, but nothing public covers this component. Note: the web-search quota was exhausted mid-triage; later checks were direct fetches of GitHub/OpenCVE pages rather than additional search-engine queries.
