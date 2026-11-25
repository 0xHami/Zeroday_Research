# Detection rules (Sigma)

Blue Spider wrote one Sigma rule for every CONFIRMED finding of **Rocket.Chat 9.1.0-develop** (`9f3d6c8`) whose attack is visible in an access log, and validated each one against the log lines the lab wrote while the exploit ran and against `clean.log`, 400 lines of the same workspace used legitimately.

| Finding | Rule | Level | Verdict | Positives | Clean set | pySigma |
|---------|------|-------|---------|-----------|-----------|---------|
| [VULN-001](../exploits/VULN-001-livechat_visitor_token_idor/writeup.md) | [`VULN-001.sigma.yml`](VULN-001.sigma.yml) | high | **CONFIRMED** | 6/6 fired | 0/400 fired | valid |
| [VULN-007](../exploits/VULN-007-workspace_pii_disclosure_to_any_user/writeup.md) | [`VULN-007.sigma.yml`](VULN-007.sigma.yml) | medium | **CONFIRMED** | 1/1 fired | 0/400 fired | valid |
| [VULN-010](../exploits/VULN-010-deleted_message_metadata_disclosure/writeup.md) | [`VULN-010.sigma.yml`](VULN-010.sigma.yml) | medium | **CONFIRMED** | 2/2 fired | 0/400 fired | valid |
| [VULN-014](../exploits/VULN-014-import_file_path_control/writeup.md) | [`VULN-014.sigma.yml`](VULN-014.sigma.yml) | medium | **CONFIRMED** | 6/6 fired | 0/400 fired | valid |
| [VULN-019](../exploits/VULN-019-hooks_integration_token_confusion/writeup.md) | [`VULN-019.sigma.yml`](VULN-019.sigma.yml) | medium | **CONFIRMED** | 3/3 fired | 0/400 fired | valid |
| [VULN-020](../exploits/VULN-020-role_membership_authorization_oracle/writeup.md) | [`VULN-020.sigma.yml`](VULN-020.sigma.yml) | medium | **CONFIRMED** | 4/4 fired | 0/400 fired | valid |
| [VULN-041](../exploits/VULN-041-star_privacy_bypass/writeup.md) | [`VULN-041.sigma.yml`](VULN-041.sigma.yml) | medium | **CONFIRMED** | 1/1 fired | 0/400 fired | valid |
| [VULN-046](../exploits/VULN-046-livechat_page_visited_anonymous_write/writeup.md) | [`VULN-046.sigma.yml`](VULN-046.sigma.yml) | medium | **CONFIRMED** | 2/2 fired | 0/400 fired | valid |
| [VULN-047](../exploits/VULN-047-anonymous_read_omnichannel_rooms/writeup.md) | [`VULN-047.sigma.yml`](VULN-047.sigma.yml) | medium | **CONFIRMED** | 2/2 fired | 0/400 fired | valid |
| [VULN-051](../exploits/VULN-051-livechat_transcript_html_relay/writeup.md) | [`VULN-051.sigma.yml`](VULN-051.sigma.yml) | medium | **CONFIRMED** | 1/1 fired | 0/400 fired | valid |
| [VULN-054](../exploits/VULN-054-offline_form_html_injection/writeup.md) | [`VULN-054.sigma.yml`](VULN-054.sigma.yml) | medium | **CONFIRMED** | 2/2 fired | 0/400 fired | valid |
| [VULN-059](../exploits/VULN-059-deleted_thread_root_disclosure/writeup.md) | [`VULN-059.sigma.yml`](VULN-059.sigma.yml) | medium | **CONFIRMED** | 1/1 fired | 0/400 fired | valid |
| [VULN-060](../exploits/VULN-060-password_policy_bypass_via_ddp/writeup.md) | [`VULN-060.sigma.yml`](VULN-060.sigma.yml) | medium | **CONFIRMED** | 2/2 fired | 0/400 fired | valid |
| [VULN-066](../exploits/VULN-066-forgot_password_ddp_when_disabled/writeup.md) | [`VULN-066.sigma.yml`](VULN-066.sigma.yml) | medium | **CONFIRMED** | 9/9 fired | 0/400 fired | valid |
| [VULN-067](../exploits/VULN-067-join_code_recovery_via_sort_oracle/writeup.md) | [`VULN-067.sigma.yml`](VULN-067.sigma.yml) | medium | **CONFIRMED** | 60/60 fired | 0/400 fired | valid |
| [VULN-073](../exploits/VULN-073-mailer_placeholder_redos/writeup.md) | [`VULN-073.sigma.yml`](VULN-073.sigma.yml) | high | **CONFIRMED** | 1/1 fired | 0/400 fired | valid |
| [VULN-074](../exploits/VULN-074-metric_label_cardinality/writeup.md) | [`VULN-074.sigma.yml`](VULN-074.sigma.yml) | high | **CONFIRMED** | 300/300 fired | 0/400 fired | valid |
| [VULN-077](../exploits/VULN-077-visitor_tokens_in_pages_visited/writeup.md) | [`VULN-077.sigma.yml`](VULN-077.sigma.yml) | medium | **CONFIRMED** | 1/1 fired | 0/400 fired | valid |
| [VULN-081](../exploits/VULN-081-livechat_webhook_ssrf/writeup.md) | [`VULN-081.sigma.yml`](VULN-081.sigma.yml) | medium | **CONFIRMED** | 3/3 fired | 0/400 fired | valid |
| [VULN-084](../exploits/VULN-084-register_account_enumeration/writeup.md) | [`VULN-084.sigma.yml`](VULN-084.sigma.yml) | informational | **CONFIRMED** | 2/2 fired | 0/400 fired | valid |

Every rule: fired on all of its own exploit's attack lines, stayed silent on all 400 clean lines and on its own run's setup traffic, and passed pySigma's `sigma check` inside the attacker container. `<VULN-ID>.validation.log` holds each verdict verbatim.

## Not given a rule

37 of the 57 CONFIRMED findings cannot be detected from this product's access log: the request is identical to what the workspace's own client sends, and the attack is in the JSON body, a header, the response or a `/websocket` session. `index.json` lists each with the line the lab logged and the log source that would see it.

| Finding | Why no rule |
|---------|-------------|
| [VULN-002](../exploits/VULN-002-oauth_unverified_email_meld/writeup.md) | NEEDS_MANUAL (the attack traffic never reaches the proxy, and the decisive value is the identity provider's claim) |
| [VULN-003](../exploits/VULN-003-realtime_event_injection_notify_room_users/writeup.md) | NEEDS_MANUAL (the attack is DDP frames inside a websocket session) |
| [VULN-004](../exploits/VULN-004-totp_seed_disclosed_to_session/writeup.md) | NEEDS_MANUAL (the request is the web client's own profile fetch; the disclosure is in the response body) |
| [VULN-005](../exploits/VULN-005-anonymous_permission_map/writeup.md) | NEEDS_MANUAL (the attack is a single anonymous DDP method call) |
| [VULN-006](../exploits/VULN-006-anonymous_apps_stream_subscription/writeup.md) | NEEDS_MANUAL (the attack is an anonymous DDP subscription) |
| [VULN-008](../exploits/VULN-008-stale_stream_subscription_after_revocation/writeup.md) | NEEDS_MANUAL (the attack is a websocket subscription that is never re-evaluated) |
| [VULN-009](../exploits/VULN-009-ban_bypass_notifications_and_files/writeup.md) | NEEDS_MANUAL (an ordinary file download; the ban state is not in the request) |
| [VULN-011](../exploits/VULN-011-typing_write_into_inaccessible_room/writeup.md) | NEEDS_MANUAL (the attack is a DDP method call on a stream the caller may not read) |
| [VULN-012](../exploits/VULN-012-forged_system_messages_via_mediaconfirm/writeup.md) | NEEDS_MANUAL (the forged message type is in the request body) |
| [VULN-015](../exploits/VULN-015-mfa_bypass_via_password_reset/writeup.md) | NEEDS_MANUAL (the second-factor bypass runs over DDP) |
| [VULN-018](../exploits/VULN-018-oauth_userinfo_expired_token/writeup.md) | NEEDS_MANUAL (the token and its expiry are in the Authorization header) |
| [VULN-024](../exploits/VULN-024-protected_files_public_cache/writeup.md) | NEEDS_MANUAL (the defect is in the response's Cache-Control header) |
| [VULN-026](../exploits/VULN-026-markdown_parser_dos/writeup.md) | NEEDS_MANUAL (the payload is a long string in the request body and the effect is latency) |
| [VULN-030](../exploits/VULN-030-deactivated_account_oauth_login_code/writeup.md) | NEEDS_MANUAL (the attack traffic never reaches the proxy; the account's state is not in the request) |
| [VULN-032](../exploits/VULN-032-lockout_bypass_by_email/writeup.md) | NEEDS_MANUAL (the bypass is the identifier form in the request body) |
| [VULN-033](../exploits/VULN-033-realtime_session_survives_revocation/writeup.md) | NEEDS_MANUAL (the surviving session is a websocket, and the broadcast is a frame) |
| [VULN-035](../exploits/VULN-035-invite_links_unrevocable/writeup.md) | NEEDS_MANUAL (a revoked invite is used on the same route as a valid one) |
| [VULN-036](../exploits/VULN-036-role_mandatory_2fa_client_side/writeup.md) | NEEDS_MANUAL (the bypass is the absence of a second-factor field in the body) |
| [VULN-037](../exploits/VULN-037-pre_registration_squatting_survives_meld/writeup.md) | NEEDS_MANUAL (the squatter's traffic is an ordinary authenticated read) |
| [VULN-040](../exploits/VULN-040-totp_code_replay/writeup.md) | NEEDS_MANUAL (the replayed code is in the request body) |
| [VULN-042](../exploits/VULN-042-attacker_text_in_platform_email/writeup.md) | NEEDS_MANUAL (the attacker-chosen text is in the request body) |
| [VULN-043](../exploits/VULN-043-oauth_login_skips_2fa_grace/writeup.md) | NEEDS_MANUAL (the attack traffic never reaches the proxy; the grace window is server state) |
| [VULN-045](../exploits/VULN-045-profanity_filter_dos/writeup.md) | NEEDS_MANUAL (the payload is a long message body and the effect is latency) |
| [VULN-049](../exploits/VULN-049-deleted_content_via_edit_history/writeup.md) | NEEDS_MANUAL (the request is the client's own message fetch; the deleted text is in the response) |
| [VULN-055](../exploits/VULN-055-retention_override_without_permission/writeup.md) | NEEDS_MANUAL (the retention override is a field in the request body) |
| [VULN-057](../exploits/VULN-057-settings_write_via_telemetry/writeup.md) | NEEDS_MANUAL (the setting that gets incremented is named in the request body) |
| [VULN-058](../exploits/VULN-058-team_room_mass_assignment/writeup.md) | NEEDS_MANUAL (the administrative flags are in the request body's room.extraData) |
| [VULN-061](../exploits/VULN-061-integration_type_confusion/writeup.md) | NEEDS_MANUAL (the confused type is a field in the request body) |
| [VULN-062](../exploits/VULN-062-preview_revocation_alternate_routes/writeup.md) | NEEDS_MANUAL (the ten routes that still serve a non-member are the ordinary read routes) |
| [VULN-063](../exploits/VULN-063-missing_rest_rate_limiting/writeup.md) | NEEDS_MANUAL (the finding is the absence of a limit, and each request is ordinary) |
| [VULN-068](../exploits/VULN-068-ban_list_disclosure_to_any_member/writeup.md) | NEEDS_MANUAL (the caller's permission is not in the request) |
| [VULN-069](../exploits/VULN-069-last_admin_removal/writeup.md) | NEEDS_MANUAL (the role list that removes the administrator is in the request body) |
| [VULN-070](../exploits/VULN-070-autotranslate_missing_permission/writeup.md) | NEEDS_MANUAL (the missing permission is not in the request) |
| [VULN-071](../exploits/VULN-071-e2e_waiting_users_membership_disclosure/writeup.md) | NEEDS_MANUAL (the request is the shape the product's own E2E client sends) |
| [VULN-076](../exploits/VULN-076-livechat_stream_room_confusion/writeup.md) | NEEDS_MANUAL (the room confusion is in a websocket subscription's extraData) |
| [VULN-078](../exploits/VULN-078-ddp_rest_shared_rate_limit_key/writeup.md) | NEEDS_MANUAL (the shared bucket is keyed on a request header, and the route is the client's own) |
| [VULN-079](../exploits/VULN-079-nosql_operator_room_name_oracle/writeup.md) | NEEDS_MANUAL (the Mongo operator is a DDP method parameter) |

## Files

| File | What it is |
|------|------------|
| `index.json` | the stage's artifact: every rule with its measured validation, and every finding that could not have one |
| `clean.log` | the shared negative set: this workspace used legitimately (the product's own web client in Chromium, then a documented-API client on the findings' own routes) |
| `<VULN-ID>.sigma.yml` | the rule (a copy also sits beside the finding, in `exploits/<VULN-ID>/detection/`) |
| `<VULN-ID>.positive.log` | the attack's own request lines, as the lab logged them during the replay |
| `<VULN-ID>.capture.log` | the whole log window of that replay, the exploit's setup traffic included |
| `<VULN-ID>.validation.log` | `sigma_problems`, `validate_sigma` and `sigma check`, verbatim |

Blue Spider, a product of Kohi Research Corporation (kohirc.com).
