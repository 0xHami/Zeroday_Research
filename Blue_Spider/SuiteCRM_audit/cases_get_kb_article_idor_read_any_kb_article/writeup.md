# VULN-032 — Cases: read any Knowledge Base article by id (IDOR)

**ID**: VULN-032
**Software**: SuiteCRM — https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (`targets/SuiteCRM/suitecrm_version.php`) — commit `62effd0ceb767ed3b634ade585b19a6633eb4fcb`
**Severity**: Medium — **CVSS 3.1: 5.3** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (report's conservative figure; a strict PR:L/C:H calculation lands at 6.5 — either way, Medium confidentiality-only)
**Status**: CONFIRMED (dynamic)
**Auth required**: any authenticated user (`PR:L`) — no KB-specific grant needed.
**What an attacker gains**: full read (title + body + additional-info) of any Knowledge Base article, including drafts and unpublished/team-restricted content, by guessing or enumerating its GUID.

## Summary
The Cases module exposes a small AJAX helper used by the "suggested KB article" tooltip. It takes an article id straight from the POST body and echoes the article's full content back — no authorization check, and the KB bean itself has row-level security switched off. Any authenticated user can dump any Knowledge Base article, published or not.

## How it works (mechanism & code trace)

**Entry point / sink** — `modules/Cases/controller.php:88-107`:
```php
88:  public function action_get_kb_article()
89:  {
        global $mod_strings;
92:     $article_id = $_POST['article'];
93:     $article = BeanFactory::newBean('AOK_KnowledgeBase');
94:     $article->retrieve($article_id);
96:     echo '...<strong>' . $mod_strings['LBL_TOOL_TIP_TITLE'] . '</strong>' . $article->name . '...';
97:     echo '...<strong>' . $mod_strings['LBL_TOOL_TIP_BODY'] . '</strong>...' . html_entity_decode((string) $article->description);
        if (!$this->IsNullOrEmptyString($article->additional_info)) {
            ...
            echo '...' . $article->additional_info . '...';
        }
        die();
    }
```
`$article_id` is used directly, unsanitized, as the primary key for `retrieve()`. There is no `ACLAccess()`, `ACLController::checkAccess()`, status check (`Draft` vs `Published`/`Expired`), or team/Security-Group check anywhere in this method — or, per a full read of `CasesController`, anywhere else in the file.

**Compounding factor** — `modules/AOK_KnowledgeBase/AOK_KnowledgeBase_sugar.php:56`:
```php
public $disable_row_level_security = true; // to ensure that modules created and deployed under CE
                                             // will continue to function under team security if the
                                             // instance is upgraded to PRO
```
Even the generic Security-Group row filtering that `SugarBean::retrieve()` would otherwise apply for free is explicitly disabled for this bean class. So there is no layer — controller-level or bean-level — that gates this read.

**The exact defect**: line 94 needs an authorization gate between `retrieve()` and the three `echo`s that follow it; none exists.

## Why it is a vulnerability (reasoning)
Knowledge Base articles have an explicit **publication/visibility model** — a `status` field (`Draft`/`Published`/`Expired`/etc.) and, per the module's own comment, an intended team-security boundary that the developers consciously chose to bypass "to ensure CE continues to function" (a CE/PRO parity shortcut, not a deliberate "everything is public" design decision — nothing in the product's UI or documentation suggests Draft articles are meant to be world-readable to any logged-in user). `action_get_kb_article` is reachable by any authenticated user regardless of whether they have any relationship to Cases, the KB module, or the specific article's team — it's a caller-supplied primary-key lookup with the authorization step simply missing. That KB content commonly includes internal runbooks, escalation procedures, and (per this proof) credentials pasted into resolution notes makes the missing check a genuine confidentiality boundary violation, not a cosmetic one.

## Reproduction
From a clean state (`./run.sh`):
1. **Preconditions** — as admin, create a KB article with `status=Draft` (unpublished) and a unique title + body. Create a fresh low-priv attacker with zero KB grant.
2. **Attack request**, as the attacker:
   ```
   POST /index.php?module=Cases&action=get_kb_article
   Content-Type: application/x-www-form-urlencoded

   article=<kb_article_id>
   ```
   (full request in `request.http`)
3. Run `NO_COLOR=1 ./run.sh 2>&1 | tee run.log`. Expected tail:
   ```
   [PROOF] KB article title '...' leaked to attacker: True
   [PROOF] KB article (Draft) body '...' leaked to attacker: True
   ==> VULN-032: CONFIRMED — attacker read unpublished KB article ... via Cases get_kb_article, no ACL check
   ```
4. **Observable proof** — `response.txt` is a 200 OK whose entire 231-byte body is the article's `name` and `description`, verbatim, including the "CONFIDENTIAL ... escalation credentials go here" marker planted by the harness. See `evidence/leaked_kb_article.txt`.

## Impact
- **Confidentiality (broad, high)**: complete read of any Knowledge Base article's title, body, and additional-info fields — including Draft/unpublished/team-restricted articles that the KB's own status/visibility model was meant to withhold.
- The sibling `action_get_kb_articles` (search variant, `controller.php:48`) independently `BeanFactory::getBean()`s every match with the same lack of per-record ACL, functioning as an id-enumeration oracle over the entire KB table.
- No integrity/availability impact; the read is confidentiality-only but broad (every article, every status) and trivially scriptable.

## Suggested fix
```php
public function action_get_kb_article()
{
    global $mod_strings;
    $article_id = $_POST['article'];
    $article = BeanFactory::getBean('AOK_KnowledgeBase', $article_id);
    if (empty($article) || empty($article->id) || !$article->ACLAccess('view') || $article->status !== 'Published') {
        die($mod_strings['LBL_NO_ACCESS'] ?? 'No access');
    }
    ...
}
```
Do not rely on `disable_row_level_security = true` making the bean "safe by obscurity" — gate this controller action explicitly with an ACL check and a publication-status check before returning any field.

## References
- CWE-639 — Authorization Bypass Through User-Controlled Key.
- GHSA-wphj-qjgj-4j23 / CVE-2026-69141 — published SQLi in the same file's `search`/`get_kb_articles` sibling (a different angle on the same controller's lack of input/authorization discipline).
- OWASP Top 10 2021 — A01:2021 Broken Access Control; OWASP WSTG-ATHZ-04 (IDOR).

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 80 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `SuiteCRM get_kb_article Cases controller knowledge base article IDOR missing authorization` — only CVE-2026-32697 (v8 getRecord), CVE-2026-29189 (V8 API), CVE-2026-108712 (DetailUserRole); nothing on `get_kb_article`
2. `SuiteCRM AOK_KnowledgeBase unauthorized read draft article CVE OR advisory` — CVE-2025-64490, CVE-2025-54787 (attachment downloads), CVE-2020-8802; no KB-article read advisory
3. `"SuiteCRM" "get_kb_article" OR "get_kb_articles" vulnerability` (extended) — generic SuiteCRM CVE lists; no result names either function
4. Fetched github.com/SuiteCRM/SuiteCRM/security/advisories/GHSA-wphj-qjgj-4j23 (CVE-2026-69141) — SQL injection via `$_POST['search']` in `action_get_kb_articles`, fixed in 7.15.2; it does not mention `action_get_kb_article`, the `article` parameter, missing ACL, or Draft/unpublished article disclosure
5. Reviewed all 8 pages of github.com/SuiteCRM/SuiteCRM/security/advisories (77 advisories) — no knowledge-base authorization advisory

**Related but distinct public references** (same class or component, not this bug):
- GHSA-wphj-qjgj-4j23 / CVE-2026-69141 — SQLi in the sibling `action_get_kb_articles` (`search` parameter) of the same controller; different function, different vuln class (injection, not missing authorization), and already fixed in 7.15.2
- CVE-2026-32697 — SuiteCRM 8 `RecordHandler::getRecord()` missing `ACLAccess('view')`; same IDOR class but a SuiteCRM-Core (v8) component
- GHSA-8r72-224q-g9fv / CVE-2025-54787 — improper authorization on attachment downloads; different component

**Reasoning:** No public advisory describes the missing authorization / publication-status check in `CasesController::action_get_kb_article` that returns any `AOK_KnowledgeBase` article by POSTed id. The one advisory touching this controller is an injection bug in a different method and was fixed in the audited version, so it cannot be the same issue. SuiteCRM's IDOR advisory volume is high and the KB module is small, so a vaguely-worded or unpublished report is possible but none was found.
