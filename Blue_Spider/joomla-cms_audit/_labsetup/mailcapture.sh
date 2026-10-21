#!/bin/sh
# Lab mail-capture sink for the joomla-cms CVE-hunter lab.
#
# Purpose: the php:8.2-apache base image ships no MTA, so PHP mail() (which
# Joomla's default `mailer=mail` uses) silently fails and nothing is observable.
# This script is wired in as PHP's sendmail_path so every message Joomla emits
# is written verbatim to /var/mailcapture/ for inspection.
#
# It is TRANSPORT-ONLY instrumentation: it changes only WHERE a mail is
# delivered, never WHAT Joomla renders into it. All mail-related findings
# (VULN-004 host-header link poisoning, VULN-010 / VULN-013b raw {TAG}
# substitution, VULN-015 reset flooding) are about rendered content, which is
# produced upstream in MailTemplate/ResetModel before this sink is reached.
# This is the equivalent of pointing the app at an OOB listener.
#
# Invoked by PHP as:  mailcapture -t -i   (args ignored; message on stdin)
set -eu
OUT_DIR=/var/mailcapture
mkdir -p "$OUT_DIR"
# Unique filename per message (nanosecond ts + pid) so concurrent sends (VULN-015)
# never overwrite each other.
TS=$(date +%s_%N)
OUT="$OUT_DIR/mail_${TS}_$$.eml"
# Persist the full raw RFC822 message (headers + body) exactly as handed to us.
cat > "$OUT"
exit 0
