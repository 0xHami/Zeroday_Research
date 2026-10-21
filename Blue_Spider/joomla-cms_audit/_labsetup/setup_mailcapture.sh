#!/usr/bin/env bash
# Installs the lab mail-capture sink into the running app container.
# Idempotent: safe to re-run. Reads nothing; writes only inside the container.
set -euo pipefail
cd "$(dirname "$0")"
PROJ=cvehunterlab_joomla-cms
CT=${APP_CONTAINER:-cvehunterlab_joomla-cms_app}

echo "[SETUP] copying mail-capture sink + php.ini drop-in into $CT"
docker cp mailcapture.sh      "$CT":/usr/local/bin/mailcapture
docker cp zz-mailcapture.ini  "$CT":/usr/local/etc/php/conf.d/zz-mailcapture.ini

echo "[SETUP] preparing capture dir and permissions"
docker exec "$CT" sh -c '
  chmod 0755 /usr/local/bin/mailcapture &&
  mkdir -p /var/mailcapture &&
  chmod 0777 /var/mailcapture &&
  # graceful apache reload so mod_php picks up the new sendmail_path
  (apache2ctl graceful 2>/dev/null || apachectl graceful 2>/dev/null || true)
'
echo "[SETUP] verifying sendmail_path is now the capture sink (apache SAPI)"
docker exec "$CT" php -i | grep -i 'sendmail_path' || true
echo "[OK] mail capture installed -> /var/mailcapture/ inside $CT"
