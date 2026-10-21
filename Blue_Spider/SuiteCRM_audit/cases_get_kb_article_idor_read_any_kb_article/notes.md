# VULN-032 — Cases: read any Knowledge Base article by id (IDOR)

**Software**: SuiteCRM
**Repository**: https://github.com/SuiteCRM/SuiteCRM
**Affected version**: 7.15.2 (suitecrm_version.php) — commit-pinned forkedSuite snapshot
**Status**: CONFIRMED
**Severity (static)**: Medium
**Target commit**: 62effd0ceb767ed3b634ade585b19a6633eb4fcb
**Validated at**: 2026-09-28T20:33Z

## Preconditions
- As admin: `module=AOK_KnowledgeBase&action=Save` creates a KB article with `status=Draft` (an explicitly unpublished state — a real, intended visibility restriction, not an arbitrary record) and a unique name + body.
- A fresh low-priv attacker is created (`create_user`) — never granted any KB-related capability, never shown a link to the article.

## Request
See `request.http`:
```
POST /index.php?module=Cases&action=get_kb_article
Cookie: PHPSESSID=<attacker session>
Content-Type: application/x-www-form-urlencoded

article=<kb_article_id>
```

## Response
See `response.txt`. HTTP 200, 231-byte body:
```
<span class="tool-tip-title"><strong>Title:</strong>V032KB-Internal-Runbook_5590cc63</span><br />
<span class="tool-tip-title"><strong>Body:</strong></span>CONFIDENTIAL body SECRETKBBODY032_f8349ef9 -- escalation credentials go here
```
Both the article `name` and full `description` are returned verbatim, HTML-entity-decoded, to a user with zero KB grant, for an article that isn't even published.

## Observation
Matches the static finding exactly: `modules/Cases/controller.php:88-107` (`action_get_kb_article`) takes `$_POST['article']` straight into `BeanFactory::newBean('AOK_KnowledgeBase')->retrieve($article_id)` with no `ACLAccess`/`checkAccess`/status/team check anywhere in the method or the rest of `CasesController`. Independently, `modules/AOK_KnowledgeBase/AOK_KnowledgeBase_sugar.php:56` sets `$disable_row_level_security = true` on the bean class itself, so even the generic Security-Group row filtering that other modules get "for free" via `retrieve()` never applies to this bean type — the finding's two compounding root causes are both source- and dynamically-confirmed.

## Side effects
None destructive. One KB article (Draft) and one low-priv User created (random-suffixed, harmless).

## Research & references
- CWE-639 — Authorization Bypass Through User-Controlled Key.
- Known-issue cross-check (stage-07): the *same file* (`modules/Cases/controller.php`) has a published SQLi in its `search`/`get_kb_articles` sibling action, GHSA-wphj-qjgj-4j23 / CVE-2026-69141 — a different angle (injection) on the same controller; this finding is the no-ACL read on the *single-article* helper, `action_get_kb_article`.
- OWASP WSTG-ATHZ-04 — Testing for Insecure Direct Object References.

## If FAILED
N/A — CONFIRMED.
