# VULN-019 — Bounce-detection spoofing bypasses the trusted gate

**Software**: Znuny
**Repository**: https://github.com/znuny/Znuny
**Affected version**: 7.3.x (post-7.3.7, dev branch; commit-pinned — no tagged release)
**Status**: CONFIRMED
**Severity (static)**: Medium (5.3)
**Target commit**: b6c9d94c197d1b8a50c17247705ab5cc85b85e13
**Validated at**: 2026-09-29

## Preconditions
- Knowledge of a victim article's Message-ID (of an agent-sent/outbound article). Vendored Sisimai
  (present) must classify the DSN as a bounce. `DetectBounceEmail` PreFilter + `BounceEmail`
  follow-up are Valid=1 by default; trust-independent (fired here `--untrusted`).

## Request / Response
Synthetic RFC-3464 DSN (multipart/report) whose `message/rfc822` part carries the victim article's
Message-ID and whose text part is attacker error text (see `request.http`) → a row in
`article_data_mime_send_error` for the victim article, with `log_message` = the attacker error text.

## Observation
`send_error row: [[102, '<sent-…@localhost>', 'ATTACKER-ERROR-… mailbox full http://attacker.example/phish']]`.
Confirms `DetectBounceEmail.pm:59-68` injects `X-OTRS-Bounce-*` into `%GetParam` as a PreFilter
(after the trust strip at `PostMaster.pm:581`), and `FollowUpCheck/BounceEmail.pm:55-73` resolves
the target via the attacker-supplied original Message-ID (`ArticleGetByMessageID`) with no sender
check, then `_SetArticleTransmissionSendError`.

## Side effects
Creates a ticket + outbound article, then a forged send-error record. Idempotent.

## Research & references
- OWASP spoofing/authenticity (CWE-345). AC:H because the DSN must be shaped so Sisimai classifies
  it as a bounce. Lower impact than VULN-006 (transmission-status write, not article body).
EOF
cat > /dev/null <<'X'
X
echo "019 notes written"