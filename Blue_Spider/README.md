<p align="center"><img src="spider.png" alt="Blue Spider" width="160"></p>
<h1 align="center">Blue Spider — Audit Archive</h1>
<p align="center"><b>176 confirmed, previously undisclosed vulnerabilities across 17 open-source projects</b></p>

## What is Blue Spider?

Blue Spider is an autonomous source-code security auditor built by Kohi Research Corporation. It takes a repository URL or an uploaded archive, builds the software, and brings it up inside an isolated Docker lab. A team of AI agents then audits the code the way a human research team would: mapping the attack surface, hunting vulnerability classes, checking whether past CVE fixes still hold, and finally **proving every finding with a working exploit** launched from a sandboxed attacker container. Anything that cannot be demonstrated against the running software is marked as such instead of being reported as fact.

What comes out of a scan:

- **Exploit-proven findings.** Each one ships as a folder with a full technical write-up, researcher notes, a reproducible `run.sh` plus `automation.py`, the raw request/response pair, the run log, and captured evidence.
- **Deterministic CVSS 3.1 scoring.** Vectors are computed by code, never by the model.
- **Known-issue intelligence.** Findings are cross-referenced against public advisories, and old CVE fixes are tested for regressions and bypasses.
- **Browser-grade validation.** The attacker container carries Playwright and Chromium, so client-side bugs are verified in a real browser.
- **Re-validation and upstream watch.** Exploits are re-run against new releases and labelled still-vulnerable or fixed; significant upstream commits trigger a rescan.
- **Detection artifacts.** A software fingerprint, a Sigma rule per confirmed finding (tested against the lab's own logs), and a Metasploit module where the bug earns one.
- **Hardened sandbox.** Capability-stripped attacker containers, a Docker policy guard, egress logging, and a private home per target.

## About this archive

This folder holds the output of Blue Spider runs against 17 projects, filtered down to what matters for disclosure:

- Only findings the engine **dynamically confirmed** in the lab are kept; anything needing manual follow-up or that failed validation was dropped.
- Only **Medium severity and above** (CVSS 3.1).
- Every finding was then **checked against public sources** (CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, upstream commits) on 2026-10-21. Findings matching an existing disclosure or upstream fix were removed. Each remaining `writeup.md` ends with a **Known Issue Check** section listing the searches performed, any related-but-distinct references, and a **novelty score** (0–100 confidence that nothing public matches).

| | |
|---|---|
| Projects | 17 |
| Findings | 176 |
| Critical / High / Medium | 5 / 50 / 120 |
| Unauthenticated | 49 |
| Most common weakness classes | CWE-639 (30), CWE-862 (10), CWE-284 (9), CWE-94 (8), CWE-915 (7) |

## Table of contents

| Project | Version audited | Findings | Critical | High | Medium |
|---|---|---:|---:|---:|---:|
| [SuiteCRM](#suitecrm) | 7.15.2 | 47 | 2 | 15 | 30 |
| [ClassroomIO](#classroomio) | 0.1.13 | 29 | 1 | 13 | 15 |
| [Znuny](#znuny) | 7.3.x | 21 | 0 | 3 | 18 |
| [Zappa](#zappa) | 0.62.1 | 18 | 0 | 8 | 10 |
| [PublicCMS](#publiccms) | V5.202608.a | 9 | 1 | 1 | 7 |
| [Umbraco CMS](#umbraco-cms) | 18.3.0-rc | 9 | 0 | 1 | 7 |
| [Filament](#filament) | v4.14.0 | 8 | 0 | 1 | 7 |
| [Hugo](#hugo) | 0.167.0-DEV | 7 | 0 | 2 | 5 |
| [MyBB](#mybb) | 1.9.0-alpha.1 | 6 | 0 | 4 | 2 |
| [academico](#academico) | commit a6518355c3a3 | 5 | 1 | 1 | 3 |
| [NodeBB](#nodebb) | 4.16.0 | 5 | 0 | 0 | 5 |
| [Gin](#gin) | v1.12.0 | 3 | 0 | 0 | 3 |
| [Django](#django) | 6.2.0a0 | 2 | 0 | 0 | 2 |
| [Joomla CMS](#joomla-cms) | 5.4.9-rc2-dev | 2 | 0 | 0 | 2 |
| [Ruby on Rails](#ruby-on-rails) | 8.2.0.alpha | 2 | 0 | 1 | 1 |
| [Symfony](#symfony) | commit e6df33ba170c | 2 | 0 | 0 | 2 |
| [Django REST Framework](#django-rest-framework) | 3.18.1 | 1 | 0 | 0 | 1 |

Columns in the per-project tables: **CVSS** is the engine's computed 3.1 base score; **CWE** is as cited in the write-up (— when none is cited); **Auth** is the lowest privilege needed; **Novelty** is the Known Issue Check confidence that the finding is not already public.

## SuiteCRM

**Repository:** https://github.com/SuiteCRM/SuiteCRM  
**Version audited:** 7.15.2  
**Commit:** `62effd0ceb76`  
**Findings:** 47

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [AOR_Reports DATE_ADD interval SQL injection → full authenticated DB read](SuiteCRM_audit/aor_report_date_param_interval_unit_sqli/) | Critical | 8.8 | — | Any authenticated user with Reports | 50 |
| 2 | [Authenticated RCE via dashlet-preference poisoning → require_once webshell](SuiteCRM_audit/configuredashlet_pref_filelocation_include_rce/) | Critical | 8.8 | CWE-94 | Any authenticated user with Emails | 75 |
| 3 | [SMTP "Test Settings" full-read SSRF (arbitrary host:port + transcript exfiltration)](SuiteCRM_audit/emails_testoutbound_smtp_ssrf_transcript_leak/) | High | 8.5 | CWE-918 | Any authenticated user | 65 |
| 4 | [AOR_Reports condition field used as a raw column identifier (SQL injection)](SuiteCRM_audit/aor_condition_field_raw_identifier_sqli/) | High | 8.1 | CWE-89 | Any authenticated user with default Reports m | 45 |
| 5 | [Two-Factor (Email OTP) Bypass via Empty factor_token](SuiteCRM_audit/email_otp_2fa_bypass_empty_factor_token/) | High | 8.1 | CWE-697, CWE-1284, CWE-303 | The attacker must already hold the account's | 75 |
| 6 | [Action-name case-normalization mismatch defeats the CSRF referer guard](SuiteCRM_audit/csrf_referer_guard_action_case_mismatch_bypass/) | High | 8.0 | CWE-352, CWE-178 | None for the attacker | 75 |
| 7 | [Second-Order Merge-Token Injection Exfiltrates the Assigned User's Password Hash](SuiteCRM_audit/template_merge_second_order_user_hash_exfil/) | High | 8.0 | CWE-200, CWE-522 | Any authenticated user able to create/edit a | 70 |
| 8 | [Unauthenticated System-Generated Password Uses Predictable mt_rand](SuiteCRM_audit/generatepassword_mt_rand_predictable_password/) | High | 7.4 | CWE-338, CWE-330, CWE-640 | None | 65 |
| 9 | [AOW_WorkFlow testFlow runs all active workflows for any authenticated user](SuiteCRM_audit/aow_testflow_run_all_workflows_any_user/) | High | 7.1 | CWE-862 | — | 85 |
| 10 | [DeleteRelationship: delete any relationship on any record (aclroles-only ACL copy-paste bug)](SuiteCRM_audit/deleterelationship_aclroles_only_acl_bypass/) | High | 7.1 | CWE-284, CWE-639, CWE-89 | any authenticated user | 70 |
| 11 | [Save2: create relationships / relate arbitrary records on any record (no ACL)](SuiteCRM_audit/save2_relate_any_record_no_acl/) | High | 7.1 | CWE-284 | any authenticated user | 70 |
| 12 | [Administration action=repair global rebuild runnable by any authenticated user](SuiteCRM_audit/administration_repair_rebuild_no_admin_gate/) | High | 6.5 | CWE-862, CWE-400 | — | 75 |
| 13 | [JSON-RPC retrieve: Authenticated IDOR, Read Any Record of Any Module](SuiteCRM_audit/jsonrpc_retrieve_idor_read_any_record/) | High | 6.5 | CWE-639, CWE-284 | Any authenticated user | 80 |
| 14 | [Legacy Web Service Leaks OAuth Token & Client-Secret Material](SuiteCRM_audit/legacy_ws_oauth_token_secret_field_disclosure/) | High | 6.5 | CWE-213, CWE-359 | Any authenticated web-service user | 70 |
| 15 | [OAuth2Tokens massupdate (mass[] branch) revokes/deletes any user's token by id (BOLA)](SuiteCRM_audit/oauth2tokens_massupdate_revoke_any_token_bola/) | High | 6.5 | CWE-639, CWE-862, CWE-522 | — | 80 |
| 16 | [SubPanelViewer: read any record's subpanel (parent-ACL bypass)](SuiteCRM_audit/subpanelviewer_parent_record_acl_bypass_read/) | High | 6.5 | CWE-639 | any authenticated user | 80 |
| 17 | [get_document_revision: Authenticated IDOR, Download Any Document File](SuiteCRM_audit/get_document_revision_idor_file_download/) | High | 6.5 | CWE-639 | Any authenticated web-service user | 75 |
| 18 | [Unauthenticated jjwg_Maps geocode batch discloses CRM data to Google and drives an unauthorized write/DoS job](SuiteCRM_audit/jjwg_maps_unauth_cron_geocode_batch_trigger/) | Medium | 7.3 | CWE-284, CWE-770 | None | 80 |
| 19 | [AOW_WorkFlow DATE_ADD / identifier SQL injection (admin-authored, scheduler-run)](SuiteCRM_audit/aow_workflow_date_condition_interval_sqli/) | Medium | 6.5 | CWE-89 | Workflow authoring requires admin | 75 |
| 20 | [Authenticated SSRF via user-settable token URL on a personal ExternalOAuthProvider](SuiteCRM_audit/personal_external_oauth_provider_token_url_ssrf/) | Medium | 6.5 | CWE-918 | Any authenticated user | 70 |
| 21 | [CSV Import forges audit/provenance metadata + updates records by id with no row ACL](SuiteCRM_audit/csv_import_audit_forgery_update_by_id_no_acl/) | Medium | 6.5 | CWE-915, CWE-639 | Any authenticated user holding the standard | 65 |
| 22 | [Calendar shared view reads any user's Meetings/Calls/Tasks (IDOR)](SuiteCRM_audit/calendar_shared_ids_idor_read_any_user_calendar/) | Medium | 6.5 | CWE-862 | any authenticated user | 80 |
| 23 | [IMAP "Test Settings" SSRF + valid_imap_ports whitelist bypass](SuiteCRM_audit/imap_test_connection_string_port_whitelist_bypass/) | Medium | 6.5 | CWE-918, CWE-863 | Any authenticated user | 40 |
| 24 | [Legacy set_entry: Unbounded Property Mass-Assignment (Chosen-ID Insert, Audit-Trail Forgery)](SuiteCRM_audit/legacy_set_entry_control_flag_mass_assignment/) | Medium | 6.5 | CWE-915, CWE-472 | Any authenticated web-service user | 65 |
| 25 | [Non-admin writes to global config (config_override.php) via ungated Administration actions](SuiteCRM_audit/admin_updateajaxui_ungated_config_override_write/) | Medium | 6.5 | CWE-285, CWE-1220 | any authenticated user | 75 |
| 26 | [QuickSearch attacker-controlled limit bypasses the list cap -> memory/DB exhaustion](SuiteCRM_audit/quicksearch_limit_uncapped_memory_exhaustion/) | Medium | 6.5 | CWE-770, CWE-23 | Any authenticated user | 80 |
| 27 | [TCPDF remote <img> SSRF on PDF generation (redirect-bypass of a real guard)](SuiteCRM_audit/pdf_tcpdf_img_ssrf_redirect_guard_bypass/) | Medium | 6.5 | CWE-918, CWE-441 | Any authenticated user with access to Quotes/ | 50 |
| 28 | [download.php isTempFile ACL bypass: read any file under upload/ by GUID](SuiteCRM_audit/download_istempfile_acl_bypass_file_read/) | Medium | 6.5 | CWE-639 | any authenticated user | 60 |
| 29 | [folders subscription SQL injection via unescaped backslash (EmailUIAjax)](SuiteCRM_audit/emailuiajax_handlesubs_ieidshow_sqli_backslash/) | Medium | 6.5 | CWE-89 | Any authenticated user | 65 |
| 30 | [vCard.php cross-user PII export via ACL-less loadContact() (IDOR)](SuiteCRM_audit/vcard_entrypoint_idor_contact_pii_export/) | Medium | 6.5 | CWE-639 | any authenticated user | 80 |
| 31 | [validate_external_host() SSRF guard bypassable via an HTTP redirect chain](SuiteCRM_audit/validate_external_host_redirect_follow_bypass/) | Medium | 6.5 | CWE-918, CWE-441 | Any authenticated user | 65 |
| 32 | [Web-Service job_queue_cycle: Any Authenticated User Drives the Scheduler/Job Queue](SuiteCRM_audit/legacy_ws_job_queue_cycle_no_admin_check/) | Medium | 6.3 | CWE-285, CWE-639 | Any authenticated web-service user | 70 |
| 33 | [Alerts action_redirect: Cross-User Stored Open Redirect](SuiteCRM_audit/alerts_action_redirect_cross_user_open_redirect/) | Medium | 6.1 | CWE-639, CWE-601 | Any authenticated user can plant | 75 |
| 34 | [Authenticated stored XSS via attacker-controlled SVG published to public/](SuiteCRM_audit/emailtemplate_makepublicimage_svg_stored_xss/) | Medium | 6.1 | CWE-79, CWE-434 | Any authenticated user with default access to | 50 |
| 35 | [Reflected XSS via JS-context injection in EAPM::action_oauth (executes in window.opener)](SuiteCRM_audit/eapm_oauth_callbackfunction_js_injection_xss/) | Medium | 6.1 | CWE-79 | Victim must be an authenticated user with | 85 |
| 36 | [SugarController Post-Save/Delete Redirect to Raw return_url (Framework-Wide Open Redirect)](SuiteCRM_audit/sugarcontroller_return_url_open_redirect/) | Medium | 6.1 | CWE-601 | Any authenticated user | 68 |
| 37 | [Unauthenticated Open Redirect in Web-to-Lead Capture (default config)](SuiteCRM_audit/web_to_lead_redirect_allowlist_fail_open/) | Medium | 6.1 | CWE-601 | None | 35 |
| 38 | [Connectors module admin-gate bypass: non-admin writes global connector config](SuiteCRM_audit/connectors_savemodifymapping_admin_gate_bypass/) | Medium | 5.4 | CWE-285, CWE-863, CWE-22 | any authenticated user | 70 |
| 39 | [FP_events: systemic missing ACL on event actions (attendance tamper / email harvest / mass invite)](SuiteCRM_audit/fp_events_actions_missing_acl_attendance_tamper/) | Medium | 5.4 | CWE-285 | any authenticated user | 80 |
| 40 | [Legacy set_note_attachment/set_document_revision: Write-Side IDOR](SuiteCRM_audit/legacy_set_note_attachment_doc_revision_write_idor/) | Medium | 5.4 | CWE-639 | Any authenticated web-service user | 65 |
| 41 | [Legacy set_relationship: Relate/Detach Arbitrary Records With Only View on the Primary (BOLA)](SuiteCRM_audit/legacy_set_relationship_no_acl_on_related_ids/) | Medium | 5.4 | CWE-639, CWE-285 | Any authenticated web-service user | 60 |
| 42 | [SavedSearch: read / delete / hijack any user's saved search (IDOR)](SuiteCRM_audit/savedsearch_by_id_idor_read_delete_hijack/) | Medium | 5.4 | CWE-639 | any authenticated user | 80 |
| 43 | [Users signatures: read + overwrite any user's e-mail signature (IDOR)](SuiteCRM_audit/users_signature_idor_read_overwrite_any_user/) | Medium | 5.4 | CWE-639 | any authenticated user | 80 |
| 44 | [jjwg_Maps add_to_target_list: cross-ACL add-to-list, CSRF-able](SuiteCRM_audit/jjwg_maps_add_to_target_list_cross_acl_csrf/) | Medium | 5.4 | — | Any authenticated user | 80 |
| 45 | [targetlistupdate: cross-ACL add-to-list (uids branch), CSRF-able](SuiteCRM_audit/targetlistupdate_uids_cross_acl_add_to_list_csrf/) | Medium | 5.4 | — | Any authenticated user | 75 |
| 46 | [Cases: read any Knowledge Base article by id (IDOR)](SuiteCRM_audit/cases_get_kb_article_idor_read_any_kb_article/) | Medium | 5.3 | CWE-639 | any authenticated user | 80 |
| 47 | [Unauthenticated ReflectionClass Dump of the Legacy Web-Service Implementation](SuiteCRM_audit/legacy_rest_unauth_reflectionclass_method_dump/) | Medium | 5.3 | CWE-200, CWE-215 | None | 55 |

## ClassroomIO

**Repository:** https://github.com/classroomio/classroomio  
**Version audited:** 0.1.13  
**Commit:** `0c356ad6f1a4`  
**Findings:** 29

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [Community forum BOLA: post & comment as any user, with forged votes](classroomio_audit/community_post_author_spoof_vote_forgery_bola/) | Critical | 9.6 | CWE-639, CWE-915 | Any authenticated org member | 85 |
| 2 | [Unauthenticated full-read SSRF via the dashboard /proxy//host protocol-relative path](classroomio_audit/dashboard_proxy_protocol_relative_unauth_ssrf/) | High | 8.6 | — | None | 88 |
| 3 | [Course clone: cross-course theft (content + answer keys) + self-granted TUTOR](classroomio_audit/course_clone_any_course_theft_self_tutor/) | High | 8.5 | CWE-639, CWE-269 | Any org member | 82 |
| 4 | [POST /agent/credits/purchase mints unlimited AI credits for any org](classroomio_audit/agent_credits_purchase_unsigned_credit_minting/) | High | 8.5 | — | Any session | 88 |
| 5 | [Cohort creation self-grants cohort TUTOR (+ mass-assigned organizationId)](classroomio_audit/cohort_create_self_grant_tutor_body_orgid/) | High | 8.1 | CWE-269, CWE-915 | Any session | 78 |
| 6 | [Dashboard analytics cross-org PII IDOR (authz on header, data on query orgId)](classroomio_audit/dash_analytics_query_orgid_cross_org_pii_idor/) | High | 8.1 | CWE-639 | Any org member | 35 |
| 7 | [Lesson-comment edit/delete IDOR via a sequential integer id](classroomio_audit/lesson_comment_sequential_id_edit_delete_idor/) | High | 8.1 | CWE-639, CWE-284 | Any course member | 60 |
| 8 | [Submission file-answer IDOR: presigned download minted for any client-supplied fileKey](classroomio_audit/submission_filekey_presigned_download_idor/) | High | 8.1 | CWE-639 | Any enrolled course member | 80 |
| 9 | [Unvalidated storageKey at asset creation → server processes/publishes arbitrary storage objects](classroomio_audit/asset_create_arbitrary_storagekey_thumb_leak/) | High | 8.1 | CWE-639, CWE-441 | Any org member | 85 |
| 10 | [Arbitrary-user PII oracle via analytics endpoints](classroomio_audit/user_analytics_userid_global_pii_oracle/) | High | 7.7 | CWE-639, CWE-200 | Low | 40 |
| 11 | [Reusable, non-expiring ADMIN link-invite → any account becomes permanent org admin](classroomio_audit/admin_link_invite_reusable_raw_token_takeover/) | High | 7.5 | CWE-284, CWE-522 | Redeem: any authenticated account that obtain | 80 |
| 12 | [Unauthenticated GET /course/slug/:slug leaks any course + member emails](classroomio_audit/course_by_slug_unauth_member_email_leak/) | High | 7.5 | CWE-639, CWE-200 | None | 70 |
| 13 | [Unauthenticated session via the better-auth anonymous() plugin](classroomio_audit/better_auth_anonymous_signin_unauth_session/) | High | 7.4 | — | None | 85 |
| 14 | [HLS multi-slash keys misclassified "legacy" → cross-org presigned download (fail open)](classroomio_audit/hls_presign_multislash_key_fail_open_download/) | High | 7.1 | CWE-636, CWE-639 | Any signed-in org member | 85 |
| 15 | [Attendance forgery via trusted body params](classroomio_audit/attendance_body_courseid_cross_course_forgery/) | Medium | 6.5 | CWE-639, CWE-915 | Low | 80 |
| 16 | [Course create writes body organizationId (cross-tenant course injection)](classroomio_audit/course_create_body_organization_id_cross_tenant/) | Medium | 6.5 | CWE-639, CWE-915 | Org ADMIN | 85 |
| 17 | [isCustomDomainVerified mass-assignment → instance-wide credentialed-CORS trust](classroomio_audit/org_update_is_custom_domain_verified_cors_trust/) | Medium | 6.5 | CWE-915, CWE-346 | Org ADMIN | 80 |
| 18 | [Login CSRF / session fixation via reusable self-mintable login-link GET](classroomio_audit/login_link_get_login_csrf_session_fixation/) | Medium | 6.1 | CWE-352, CWE-384 | Any authenticated user | 85 |
| 19 | [Open redirect in login/signup and in the auth-handoff (//evil.com)](classroomio_audit/login_link_token_exchange_open_redirect/) | Medium | 6.1 | CWE-601 | None | 85 |
| 20 | [Seat/plan-cap over-provision race (FOR UPDATE lock not threaded into the insert)](classroomio_audit/student_seat_cap_toctou_race_over_provision/) | Medium | 5.9 | CWE-362 | K concurrent joiners | 65 |
| 21 | [disableEmailPassword/disableGoogleAuth enforced UI-only (dead-code server guards)](classroomio_audit/disable_email_password_auth_flag_ui_only_bypass/) | Medium | 5.8 | CWE-284, CWE-1188 | None to abuse | 85 |
| 22 | [Community title/body persisted without server-side sanitization (latent stored XSS)](classroomio_audit/community_question_body_unsanitized_stored_xss/) | Medium | 5.4 | CWE-79 | Any authenticated org member | 80 |
| 23 | [Course newsfeed item IDOR (read/react across courses)](classroomio_audit/course_newsfeed_feedid_unscoped_cross_course_idor/) | Medium | 5.4 | CWE-639, CWE-284 | Any course member | 75 |
| 24 | [Public-API /v1/courses/* ignores the key actor's current role (stale privilege)](classroomio_audit/public_api_courses_automation_key_stale_privilege/) | Medium | 5.4 | CWE-284, CWE-613 | Possession of an org automation key whose cre | 70 |
| 25 | [Client-asserted lesson completion → self-issued certificate / fake compliance](classroomio_audit/self_asserted_lesson_completion_fake_certificate/) | Medium | 5.3 | CWE-602, CWE-807 | Any enrolled STUDENT | 75 |
| 26 | [GET /organization discloses full org config to any/anon session](classroomio_audit/get_organization_lists_all_org_config_any_session/) | Medium | 5.3 | CWE-284, CWE-200 | Any session | 75 |
| 27 | [No global JSON body-size limit (memory-exhaustion DoS)](classroomio_audit/api_no_json_body_size_limit_memory_dos/) | Medium | 5.3 | CWE-770, CWE-400 | None | 85 |
| 28 | [Rate-limit bypass via spoofable client-IP headers (+ fail-open on Redis error)](classroomio_audit/rate_limit_spoofable_ip_header_bypass_fail_open/) | Medium | 5.3 | — | None | 55 |
| 29 | [Unauthenticated draft-catalog enumeration via GET /organization/setup](classroomio_audit/org_setup_unauth_draft_course_enumeration/) | Medium | 5.3 | CWE-200 | None | 75 |

## Znuny

**Repository:** https://github.com/znuny/Znuny  
**Version audited:** 7.3.x  
**Commit:** `b6c9d94c197d`  
**Findings:** 21

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [Unauthenticated X-OTRS-* header injection via trusted inbound mail](Znuny_audit/postmaster_trusted_x_otrs_header_unauth_inject/) | High | 8.2 | CWE-807 | — | 50 |
| 2 | [AgentTicketBulk;Do merges/links into an unchecked target ticket (any agent)](Znuny_audit/ticket_bulk_merge_link_target_no_permission_check/) | High | 7.1 | CWE-639, CWE-862 | any agent reaching the bulk screen with rw on | 80 |
| 3 | [AgentTicketNoteToLinkedTicket;Store writes articles + changes state on ANY ticket](Znuny_audit/note_to_linked_ticket_store_idor_write_any_ticket/) | High | 7.1 | CWE-639, CWE-862 | any agent with note on a single ticket | 85 |
| 4 | [AdminSMIME Filename unconfined arbitrary file read (no CSRF token) + delete](Znuny_audit/admin_smime_download_filename_traversal_read/) | Medium | 6.5 | CWE-22, CWE-352 | admin-group agent | 80 |
| 5 | [AgentAppointmentEdit missing calendar authorization (disclosure + create/move + delete side-effects)](Znuny_audit/appointment_edit_missing_calendar_permission/) | Medium | 6.5 | CWE-862 | any agent | 55 |
| 6 | [AgentTicketProcess split reads an arbitrary ticket + article body without ro](Znuny_audit/ticket_process_split_link_ticket_read_without_ro/) | Medium | 6.5 | CWE-639 | any agent | 75 |
| 7 | [Broken ../ filter in AdminProcessManagement → admin arbitrary host file read](Znuny_audit/admin_process_import_example_path_traversal_read/) | Medium | 6.5 | CWE-22 | admin-group agent | 80 |
| 8 | [Extra PostMaster follow-up detectors broaden the unauth arbitrary-ticket injection](Znuny_audit/postmaster_body_followup_detectors_unauth_inject/) | Medium | 6.5 | CWE-862 | — | 40 |
| 9 | [GenericInterface XSLT mapping unsandboxed → file R/W + SSRF (admin)](Znuny_audit/gi_xslt_mapping_unsandboxed_file_write_read/) | Medium | 6.5 | CWE-611, CWE-73 | — | 75 |
| 10 | [GenericInterface customer channel divergence: forge agent/internal articles & mass-assign](Znuny_audit/gi_customer_forges_agent_article_mass_assign/) | Medium | 6.5 | CWE-639, CWE-269 | a customer portal account | 55 |
| 11 | [Unauthenticated article injection into arbitrary tickets via e-mail follow-up](Znuny_audit/postmaster_followup_subject_unauth_article_inject/) | Medium | 6.5 | CWE-862 | — | 40 |
| 12 | [Request Limit/FilterLimit → raw LIMIT/TOP clause (SQL injection; two channels)](Znuny_audit/ticket_search_limit_param_raw_sql_limit_injection/) | Medium | 6.3 | CWE-89 | any agent | 80 |
| 13 | [Weak password hashing: unsalted single-round SHA-256 (default) + legacy formats accepted](Znuny_audit/default_unsalted_sha256_password_hashing/) | Medium | 5.9 | CWE-916, CWE-759 | — | 40 |
| 14 | [SSRF via unguarded WebUserAgent (admin config URLs)](Znuny_audit/web_user_agent_admin_config_url_ssrf/) | Medium | 5.8 | CWE-918 | — | 65 |
| 15 | [Active=0 preference-group bypass → clear admin-provisioned 2FA secret](Znuny_audit/prefs_inactive_group_bypass_clears_2fa_secret/) | Medium | 5.4 | CWE-862 | — | 70 |
| 16 | [AgentTicketZoom;FormDraftDelete cross-user draft deletion (no owner check + no CSRF token)](Znuny_audit/ticket_zoom_form_draft_delete_idor_no_csrf/) | Medium | 5.4 | CWE-639, CWE-352 | any agent with ro on one ticket | 60 |
| 17 | [Password change and lost-password reset do NOT invalidate existing sessions](Znuny_audit/password_change_does_not_invalidate_sessions/) | Medium | 5.4 | CWE-613 | — | 50 |
| 18 | [AgentTicketToUnitTest no ticket authz + no CSRF → dump/exfil any ticket](Znuny_audit/ticket_to_unit_test_no_ticket_authz_no_csrf_dump/) | Medium | 5.3 | CWE-862, CWE-352 | agent in the admin frontend group | 85 |
| 19 | [Bounce-detection spoofing bypasses the trusted gate](Znuny_audit/postmaster_bounce_dsn_spoof_bypasses_trusted_gate/) | Medium | 5.3 | CWE-345 | — | 80 |
| 20 | [CustomerCreateAccount mass-assigns UserCustomerID (self-registration on by default)](Znuny_audit/customer_create_account_customer_id_mass_assign/) | Medium | 5.3 | CWE-915 | — | 70 |
| 21 | [AdminOAuth2TokenManagement TokenConfigTemplateFilename arbitrary *.yml read](Znuny_audit/admin_oauth2_token_template_filename_traversal/) | Medium | 4.9 | CWE-22 | admin-group agent | 85 |

## Zappa

**Repository:** https://github.com/zappa/Zappa  
**Version audited:** 0.62.1  
**Commit:** `e9ecb1feea14`  
**Findings:** 18

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [Public Function URL also grants lambda:InvokeFunction to Principal:"*" (world direct-invoke)](Zappa_audit/function_url_invokefunction_principal_star/) | High | 8.9 | CWE-284, CWE-732 | None on the victim's account | 60 |
| 2 | [Arbitrary module import & callable invocation via event-controlled dotted paths](Zappa_audit/handler_command_dotted_path_import_rce/) | High | 8.8 | CWE-94, CWE-470 | Surface B | 55 |
| 3 | [raw_command event field passed straight to exec() (RCE)](Zappa_audit/handler_raw_command_exec_event_rce/) | High | 8.8 | CWE-95, CWE-94 | Surface B | 55 |
| 4 | [callbacks/prebuild_script config imports & calls a module from cwd (local RCE)](Zappa_audit/callbacks_prebuild_script_cwd_import_rce/) | High | 8.6 | CWE-94 | None beyond running the zappa CLI in a direct | 65 |
| 5 | [Code injection into generated zappa_settings.py via unescaped '{0!s}' interpolation](Zappa_audit/zappa_settings_py_scalar_code_injection/) | High | 8.4 | CWE-94 | Hostile/shared scalar config value | 85 |
| 6 | [manage event field → Django call_command (command injection)](Zappa_audit/handler_manage_event_django_call_command/) | High | 8.2 | CWE-77 | Surface B invoke on a Django deployment | 55 |
| 7 | [Predictable, world-writable /tmp wheel cache → poisoning → code execution](Zappa_audit/tmp_cached_wheels_poisoning_no_integrity/) | High | 7.5 | CWE-377, CWE-494, CWE-427 | Local unprivileged user / co-tenant on the bu | 75 |
| 8 | [HTTP API v2 silently drops api_key_required and downgrades a non-IAM authorizer to NONE](Zappa_audit/apigw_v2_authorizer_downgrade_to_none/) | High | 7.4 | CWE-285, CWE-1188 | None | 50 |
| 9 | [SNS message-body command overrides AWS_EVENT_MAPPING (topic-publisher RCE)](Zappa_audit/sns_message_command_overrides_event_mapping/) | Medium | 6.8 | CWE-94, CWE-470 | Publish access to a wired SNS topic | 75 |
| 10 | [Unsanitized tarfile.extractall of the S3 project archive (tar-slip → cold-start RCE)](Zappa_audit/slim_handler_s3_archive_tar_slip_extractall/) | Medium | 6.8 | CWE-22 | Write access to the ARCHIVE_PATH S3 object on | 25 |
| 11 | [slim_handler cdll.LoadLibrary of a tar-extracted .so → native code execution at cold start](Zappa_audit/slim_handler_include_so_dlopen_cold_start/) | Medium | 6.8 | CWE-94, CWE-114 | Write access to the ARCHIVE_PATH S3 object on | 70 |
| 12 | [remote_env S3 JSON overwrites existing os.environ keys at cold start](Zappa_audit/remote_env_s3_json_overwrites_environ/) | Medium | 6.5 | CWE-15 | Write access to the REMOTE_ENV S3 object on a | 65 |
| 13 | [cloudfront-host request header overwrites the app's Host (Function URL)](Zappa_audit/cloudfront_host_header_overrides_host_v1/) | Medium | 6.1 | CWE-644 | None | 80 |
| 14 | [ASGI Host header reflected into scope["server"] (client-controlled server identity)](Zappa_audit/asgi_scope_server_client_host_header/) | Medium | 5.3 | CWE-644 | None | 80 |
| 15 | [CRLF / log injection into the Common Log Format access line](Zappa_audit/common_log_crlf_log_injection/) | Medium | 5.3 | CWE-117 | None | 85 |
| 16 | [DEBUG tracebacks (with secrets & file paths) returned to the client](Zappa_audit/debug_default_traceback_in_500_response/) | Medium | 5.3 | CWE-209, CWE-489 | None | 30 |
| 17 | [REMOTE_ADDR spoofing via the X-Forwarded-For addresses[-2] heuristic](Zappa_audit/xff_second_last_remote_addr_spoof/) | Medium | 5.3 | CWE-348, CWE-290 | None | 35 |
| 18 | [event stageVariables copied into os.environ, persisting across warm invocations](Zappa_audit/stage_variables_os_environ_pollution/) | Medium | 4.6 | CWE-15 | Surface B | 80 |

## PublicCMS

**Repository:** https://github.com/sanluan/PublicCMS  
**Version audited:** V5.202608.a  
**Findings:** 9

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [Bundled demo default-credential superuser reachable via the Host header](PublicCMS_audit/demo_site2_superuser_admin_admin_host_header/) | Critical | 9.8 | CWE-798, CWE-321 | None | 60 |
| 2 | [Stored XSS: rich-text sanitizer skipped on the web & API content-save channels](PublicCMS_audit/content_save_api_sanitizer_skipped_stored_xss/) | High | 8.0 | — | User | 45 |
| 3 | [Cross-user content tampering / unpublish via /api/contentCreate update branch](PublicCMS_audit/api_content_create_update_cross_user_tamper/) | Medium | 6.5 | — | App token | 75 |
| 4 | [Registration mass-assignment sets emailChecked=true / arbitrary email](PublicCMS_audit/register_mass_assignment_email_checked_spoof/) | Medium | 6.5 | — | None | 80 |
| 5 | [Cross-user payment state change via refund-create pendingRefund](PublicCMS_audit/pending_refund_missing_owner_check_cross_user/) | Medium | 5.4 | — | Any authenticated web user | 50 |
| 6 | [IDOR + NPE in refund updateAmound via an operator-precedence bug](PublicCMS_audit/refund_update_amound_precedence_idor_npe/) | Medium | 5.4 | — | Any authenticated web user | 70 |
| 7 | [Redemption race in "vote/score/collect once" → counter / ballot stuffing](PublicCMS_audit/vote_score_collect_once_race_counter_stuffing/) | Medium | 5.3 | CWE-362 | Authenticated web user for score/collect and | 85 |
| 8 | [Unauthenticated deanonymization of any user's votes / scores / collections](PublicCMS_audit/user_vote_score_collection_list_userid_leak/) | Medium | 5.3 | — | None | 65 |
| 9 | [Unauthenticated disclosure of draft / disabled / scheduled content](PublicCMS_audit/cms_directive_single_entity_draft_content_leak/) | Medium | 5.3 | — | None | 75 |

## Umbraco CMS

**Repository:** https://github.com/umbraco/Umbraco-CMS  
**Version audited:** 18.3.0-rc  
**Commit:** `cee7d8981ab0`  
**Findings:** 9

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [Host-header-controlled OAuth redirect-URI pollution of the backoffice client → open redirect + account takeover](Umbraco-CMS_audit/host_header_oauth_redirect_uri_pollution_ato/) | High | 8.1 | — | None to poison | 70 |
| 2 | [UserGroup create/update mass-assignment → a delegated Users-administrator self-escalates to whole-tree, all-verb, all-language access](Umbraco-CMS_audit/usergroup_definition_mass_assign_self_escalation/) | Medium | 8.0 | CWE-915, CWE-269, CWE-266 | A non-admin backoffice user whose group holds | 55 |
| 3 | [Preview cookie mints a full, non-expiring, non-revocable backoffice identity](Umbraco-CMS_audit/preview_cookie_nonexpiring_backoffice_identity/) | Medium | 6.8 | CWE-613, CWE-384, CWE-522 | None to *replay* | 70 |
| 4 | [Member self-registration mass-assignment of non-member-editable properties](Umbraco-CMS_audit/member_register_mass_assign_noneditable_props/) | Medium | 6.5 | CWE-915 | None | 80 |
| 5 | [Server-Side Request Forgery via unvalidated webhook target URL](Umbraco-CMS_audit/webhook_url_ssrf_no_host_filtering/) | Medium | 6.5 | — | A backoffice user with the Settings section | 25 |
| 6 | [Lucene NativeQuery injection + cross-index content disclosure in the backoffice searcher](Umbraco-CMS_audit/searcher_query_lucene_injection_content_leak/) | Medium | 5.5 | — | A backoffice user holding the Settings sectio | 30 |
| 7 | [item/element[/search] is floor-only with an uncapped take → cross-section element disclosure + full enumeration](Umbraco-CMS_audit/item_element_search_floor_only_uncapped_take/) | Medium | 5.3 | — | Any authenticated backoffice user | 65 |
| 8 | [item/member[/search] omits the Members-section check → cross-section member PII enumeration](Umbraco-CMS_audit/item_member_search_missing_members_section/) | Medium | 4.3 | — | Any authenticated backoffice user with no Mem | 65 |
| 9 | [Authenticated XML-import entity-expansion / unbounded in-memory-DOM DoS (NOT XXE)](Umbraco-CMS_audit/xml_import_entity_expansion_dom_dos/) | — | — | — | — | 70 |

## Filament

**Repository:** https://github.com/filamentphp/filament  
**Version audited:** v4.14.0  
**Commit:** `154a22c52498`  
**Findings:** 8

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [Select::editOptionForm() IDOR: read + write of arbitrary related-model records](filament_audit/select_edit_option_form_idor_read_write/) | High | 8.1 | CWE-639, CWE-862 | Any authenticated panel user | 65 |
| 2 | [Bulk "select-all" hydrates the entire table into memory (DoS)](filament_audit/bulk_select_all_unbounded_hydration_dos/) | Medium | 6.5 | CWE-770 | Any authenticated user who can reach a table | 55 |
| 3 | [Select::createOptionForm() creates related-model records with no create authorization](filament_audit/select_create_option_form_missing_create_authz/) | Medium | 6.5 | CWE-862 | Any authenticated panel user | 60 |
| 4 | [Unbounded tableRecordsPerPage forces a full-table load (DoS)](filament_audit/table_records_per_page_unbounded_full_load_dos/) | Medium | 6.5 | CWE-770 | Any authenticated panel user | 60 |
| 5 | [generate_href_html() does not scheme-sanitize ->url() → javascript: href XSS](filament_audit/generate_href_html_javascript_scheme_xss/) | Medium | 5.4 | CWE-79 | Low-priv author to store the value | 60 |
| 6 | [RichEditor::customBlocks() preview rendered via innerHTML, sanitizer never invoked → stored XSS](filament_audit/rich_editor_custom_block_preview_unsanitized_xss/) | Medium | 4.4 | CWE-79 | Low-priv author to store the block | 40 |
| 7 | [Repeater/Builder accept an unbounded number of client items (DoS)](filament_audit/repeater_builder_unbounded_items_dos/) | Medium | 4.3 | CWE-770 | None on the lab demo form page | 60 |
| 8 | [callSchemaComponentMethod enforces hidden() but not disabled()](filament_audit/call_schema_component_method_ignores_disabled/) | Medium | 4.3 | CWE-862 | Inherits the host page's auth | 60 |

## Hugo

**Repository:** https://github.com/gohugoio/hugo  
**Version audited:** 0.167.0-DEV  
**Commit:** `c7f9999309a2`  
**Findings:** 7

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [AsciiDoc content rendering runs Asciidoctor in unsafe safe-mode → arbitrary host-file read (LFI) + stored XSS](hugo_audit/asciidoc_unsafe_safe_mode_include_lfi_xss/) | High | 8.1 | CWE-829, CWE-79 | None | 55 |
| 2 | [reStructuredText content runs rst2html with docutils file-insertion/raw enabled → arbitrary host-file read (LFI) + stored XSS](hugo_audit/rst2html_file_insertion_raw_enabled_lfi_xss/) | High | 8.1 | CWE-829, CWE-79 | None | 65 |
| 3 | [resources.GetRemote dial-time SSRF guard is silently disabled when security.http.urls is customized](hugo_audit/getremote_dial_ip_guard_off_when_urls_custom/) | Medium | 6.9 | — | None | 30 |
| 4 | [Node code execution via css.PostCSS --use module injection](hugo_audit/css_postcss_use_option_node_module_injection/) | Medium | 5.9 | CWE-94 | None | 35 |
| 5 | [Image pipeline has no target-dimension bound (or source-pixel cap) → build-time DoS](hugo_audit/image_resize_unbounded_target_dimensions_dos/) | Medium | 5.3 | CWE-789, CWE-409 | None | 70 |
| 6 | [resources.GetRemote reads the entire response body with io.ReadAll (no size cap) → build-time memory DoS](hugo_audit/getremote_unbounded_body_readall_memory_dos/) | Medium | 5.3 | CWE-770 | None | 75 |
| 7 | [Pandoc content rendering keeps raw_html enabled → stored XSS](hugo_audit/pandoc_raw_html_passthrough_stored_xss/) | Medium | 4.7 | CWE-79 | None | 65 |

## MyBB

**Repository:** https://github.com/mybb/mybb  
**Version audited:** 1.9.0-alpha.1  
**Commit:** `f8bf4e840cd4`  
**Findings:** 6

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [Stored XSS in the Moderator Report Center via thread subject](mybb_audit/modcp_reports_thread_subject_stored_xss/) | High | 8.7 | — | Any registered user | 75 |
| 2 | [Stored XSS via bypassable fix_javascript when "Allow HTML" is enabled](mybb_audit/fix_javascript_slash_handler_bypass_allowhtml/) | High | 8.7 | — | A registered user / moderator plus an operato | 45 |
| 3 | [Reflected XSS in report.php via the type parameter](mybb_audit/report_php_type_param_reflected_xss_regress/) | High | 8.2 | — | None for the attacker | 25 |
| 4 | [Cross-forum inline multi-thread moderation via a client-controlled cookie](mybb_audit/inline_thread_mod_cookie_tids_cross_forum/) | High | 7.5 | — | Moderator of ≥1 forum | 40 |
| 5 | [Stored XSS in moderator "user notes" (moderator → staff/admin → RCE)](mybb_audit/modcp_usernotes_update_path_stored_xss/) | Medium | 6.8 | — | Moderator with caneditprofiles | 65 |
| 6 | [TOCTOU race-condition family (login throttle / poll / reputation / email)](mybb_audit/poll_vote_login_throttle_toctou_race/) | Medium | 5.9 | CWE-367 | Varies by leg: none | 70 |

## academico

**Repository:** https://github.com/academico-sis/academico  
**Commit:** `a6518355c3a3`  
**Findings:** 5

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [Stored invoice comment → dompdf enable_php → server-side RCE](academico_audit/invoice_comment_dompdf_enable_php_rce/) | Critical | 9.0 | CWE-94 | Inject: secretary | 75 |
| 2 | [Password-reset link built from attacker-controlled Host / X-Forwarded-Host → account takeover](academico_audit/password_reset_forwarded_host_poisoning_ato/) | High | 8.8 | — | None | 80 |
| 3 | [CSV / DDE formula injection in Filament exports via unauthenticated-controllable name/ID fields](academico_audit/student_export_csv_formula_injection/) | Medium | 6.1 | CWE-1236 | None to inject | 80 |
| 4 | [Public registration: server-side validation is bypassable (only the client-claimed wizard step is validated)](academico_audit/registration_wizard_step_validation_bypass/) | Medium | 5.3 | — | None | 85 |
| 5 | [trustProxies(at: '*') → client-controlled request()->ip(): bypassable rate limiting + audit-log poisoning](academico_audit/trust_all_proxies_xff_ip_spoof_ratelimit_bypass/) | Medium | 5.3 | — | None | 70 |

## NodeBB

**Repository:** https://github.com/NodeBB/NodeBB  
**Version audited:** 4.16.0  
**Commit:** `20623201cbf2`  
**Findings:** 5

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [CORS: unanchored admin regex + credentialed origin reflection](NodeBB_audit/cors_origin_regex_unanchored_credential_reflect/) | Medium | 7.4 | CWE-942, CWE-346 | None for the attacker page | 85 |
| 2 | [/info over-exposes session IP/UA + email & username history under a weaker privilege](NodeBB_audit/account_info_sessions_emails_weak_privilege/) | Medium | 6.5 | CWE-200, CWE-284 | A member of a group to which view:users:info | 80 |
| 3 | [Unbounded server-side export process-fork DoS](NodeBB_audit/user_export_unbounded_child_process_fork_dos/) | Medium | 6.5 | CWE-400, CWE-770 | Any registered user | 80 |
| 4 | [CSV / formula injection in the group-members export](NodeBB_audit/admin_group_members_csv_formula_injection/) | Medium | 6.3 | CWE-1236 | Attacker: any registered account | 85 |
| 5 | [Socket user.setModerationNote broken access control](NodeBB_audit/socket_set_moderation_note_any_category_mod/) | Medium | 5.4 | CWE-639, CWE-284 | A category moderator | 55 |

## Gin

**Repository:** https://github.com/gin-gonic/gin  
**Version audited:** v1.12.0  
**Commit:** `1bd0ecf2d3e0`  
**Findings:** 3

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [ClientIP() returns the unvalidated TrustedPlatform header ⇒ spoof (defeats SetTrustedProxies) + log injection](gin_audit/trusted_platform_unvalidated_clientip_spoof_logs/) | Medium | 6.5 | CWE-290, CWE-117 | None | 55 |
| 2 | [Reflection binder maps all exported fields (untagged ⇒ by field name) ⇒ mass assignment](gin_audit/form_binder_untagged_fields_mass_assignment/) | Medium | 6.5 | CWE-915 | None | 60 |
| 3 | [X-Forwarded-Prefix empty-prefix ⇒ protocol-relative external open redirect](gin_audit/x_forwarded_prefix_dotdot_open_redirect_bypass/) | Medium | 6.1 | CWE-601 | None | 40 |

## Django

**Repository:** https://github.com/django/django  
**Version audited:** 6.2.0a0  
**Commit:** `9e06baf2e4dd`  
**Findings:** 2

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [ASGI handler spools the entire request body to disk before any size check; body_receive_timeout is dead code → unauthenticated disk/worker DoS](django_audit/asgi_read_body_unbounded_disk_spool_dos/) | Medium | 7.5 | CWE-400, CWE-770 | None | 30 |
| 2 | [Admin ForeignKeyRawIdWidget discloses any related object's str() with no permission check (staff IDOR → auth.User enumeration)](django_audit/admin_raw_id_widget_related_label_idor/) | Medium | 4.3 | — | Any is_staff user with add/change on a model | 55 |

## Joomla CMS

**Repository:** https://github.com/joomla/joomla-cms  
**Version audited:** 5.4.9-rc2-dev  
**Commit:** `a8bd3564ef52`  
**Findings:** 2

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [Host-header password-reset-link poisoning → account takeover](joomla-cms_audit/users_reset_link_host_header_poisoning_ato/) | Medium | 6.8 | CWE-644, CWE-640 | None | 45 |
| 2 | [API authorization structurally coarser than the UI](joomla-cms_audit/api_reads_no_per_component_acl_gate_bfla/) | Medium | 6.5 | — | A valid API identity | 40 |

## Ruby on Rails

**Repository:** https://github.com/rails/rails  
**Version audited:** 8.2.0.alpha  
**Commit:** `c9e85dbe297e`  
**Findings:** 2

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [Unauthenticated mailer previews → live reset-token leak → account takeover](rails_audit/mailer_preview_unauth_reset_token_leak_ato/) | High | 9.1 | CWE-284, CWE-200, CWE-640 | None | 50 |
| 2 | [ActionText::Content#html_safe / #to_html / #as_json return unsanitized rich text](rails_audit/actiontext_content_html_safe_unsanitized/) | Medium | 5.4 | CWE-79 | A low-privilege user who can store rich text | 45 |

## Symfony

**Repository:** https://github.com/symfony/symfony  
**Commit:** `e6df33ba170c`  
**Findings:** 2

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [JsonPath: attacker-controlled query causes unbounded node-set / re-parse DoS (three sinks)](symfony_audit/jsonpath_unbounded_nodeset_reparse_dos/) | Medium | 5.3 | CWE-407, CWE-1333 | — | 75 |
| 2 | [Mime ParameterizedHeader quoted param-value injection (attachment-filename spoofing)](symfony_audit/mime_param_header_quoted_value_injection/) | Medium | 4.3 | CWE-93, CWE-116 | — | 80 |

## Django REST Framework

**Repository:** https://github.com/encode/django-rest-framework  
**Version audited:** 3.18.1  
**Commit:** `b578eab1cad0`  
**Findings:** 1

| # | Finding | Severity | CVSS | CWE | Auth | Novelty |
|---:|---|---|---:|---|---|---:|
| 1 | [SearchFilter unauthenticated search-term-count amplification → O(terms × fields) ILIKE DoS on the default icontains search](django-rest-framework_audit/searchfilter_unbounded_terms_ilike_dos/) | Medium | — | CWE-400, CWE-1050 | none | 50 |

---

*Generated from the `writeup.md` of every finding in this folder. Blue Spider is a product of [Kohi Research Corporation](kohirc.com).*
