#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://localhost:8003/api/v1}"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  ✅ PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  ❌ FAIL: $1 — $2"; }

echo "============================================"
echo "  Rust Auth Template — Curl Test Suite"
echo "  Base URL: $BASE_URL"
echo "============================================"

echo ""
echo "--- Health ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/../health")
[ "$STATUS" = "200" ] && pass "GET /health → 200" || fail "GET /health → 200" "got $STATUS"

echo ""
echo "--- Auth: Register + Login ---"
REGISTER=$(curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"testuser@example.com","password":"SecurePass123!","first_name":"Test","last_name":"User"}')
echo "$REGISTER" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'user' in d['data']" && pass "POST /auth/register" || fail "POST /auth/register" "$REGISTER"

LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" -d '{"email":"testuser@example.com","password":"SecurePass123!"}')
TOKEN=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['access_token'])")
REFRESH=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['refresh_token'])")
[ -n "$TOKEN" ] && pass "POST /auth/login → token" || fail "POST /auth/login" "no token"

echo ""
echo "--- Auth: Me ---"
ME=$(curl -s "$BASE_URL/auth/me" -H "Authorization: Bearer $TOKEN")
echo "$ME" | python3 -c "import sys,json; assert json.load(sys.stdin)['data']['email']=='testuser@example.com'" && pass "GET /auth/me" || fail "GET /auth/me" "$ME"

echo ""
echo "--- Auth: Refresh ---"
REFRESHED=$(curl -s -X POST "$BASE_URL/auth/refresh" \
  -H "Content-Type: application/json" -d "{\"refresh_token\":\"$REFRESH\"}")
NEW_TOKEN=$(echo "$REFRESHED" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['access_token'])")
[ -n "$NEW_TOKEN" ] && pass "POST /auth/refresh" || fail "POST /auth/refresh" "$REFRESHED"
TOKEN="$NEW_TOKEN"

echo ""
echo "--- Auth: Forgot Password ---"
FORGOT=$(curl -s -X POST "$BASE_URL/auth/forgot-password" \
  -H "Content-Type: application/json" -d '{"email":"testuser@example.com"}')
echo "$FORGOT" | python3 -c "import sys,json; assert 'message' in json.load(sys.stdin)['data']" && pass "POST /auth/forgot-password" || fail "POST /auth/forgot-password" "$FORGOT"

echo ""
echo "--- Auth: Logout ---"
LOGOUT=$(curl -s -X POST "$BASE_URL/auth/logout" \
  -H "Content-Type: application/json" -d "{\"refresh_token\":\"$REFRESH\"}")
echo "$LOGOUT" | python3 -c "import sys,json; assert 'message' in json.load(sys.stdin)['data']" && pass "POST /auth/logout" || fail "POST /auth/logout" "$LOGOUT"

echo ""
echo "--- RBAC: Admin without role → 403 ---"
ADMIN_REG=$(curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"AdminPass123!","first_name":"Admin","last_name":"User"}')
ADMIN_LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" -d '{"email":"admin@example.com","password":"AdminPass123!"}')
ADMIN_TOKEN=$(echo "$ADMIN_LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['access_token'])")
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/admin/roles" -H "Authorization: Bearer $ADMIN_TOKEN")
[ "$STATUS" = "403" ] && pass "GET /admin/roles without role → 403" || fail "GET /admin/roles without role → 403" "got $STATUS"

echo ""
echo "--- RBAC: Assign super_admin + test endpoints ---"
CONTAINER=$(docker ps --filter "publish=8003" --format "{{.Names}}" | head -1)
if [ -n "$CONTAINER" ]; then
  ADMIN_USER_ID=$(echo "$ADMIN_LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['user']['id'])")
  docker exec "$CONTAINER" psql -U postgres -d rust_auth_db -c "INSERT INTO user_roles (user_id, role_id) SELECT '$ADMIN_USER_ID', id FROM roles WHERE name='super_admin' ON CONFLICT DO NOTHING;" 2>/dev/null || true
fi
ROLES=$(curl -s "$BASE_URL/admin/roles" -H "Authorization: Bearer $ADMIN_TOKEN")
echo "$ROLES" | python3 -c "import sys,json; assert len(json.load(sys.stdin)['data']) > 0" && pass "GET /admin/roles with role" || fail "GET /admin/roles" "$ROLES"

PERMS=$(curl -s "$BASE_URL/admin/permissions" -H "Authorization: Bearer $ADMIN_TOKEN")
echo "$PERMS" | python3 -c "import sys,json; assert len(json.load(sys.stdin)['data']) > 0" && pass "GET /admin/permissions" || fail "GET /admin/permissions" "$PERMS"

USERS=$(curl -s "$BASE_URL/admin/users" -H "Authorization: Bearer $ADMIN_TOKEN")
echo "$USERS" | python3 -c "import sys,json; assert len(json.load(sys.stdin)['data']) >= 2" && pass "GET /admin/users" || fail "GET /admin/users" "$USERS"

echo ""
echo "============================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "============================================"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
