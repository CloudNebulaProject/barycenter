#!/usr/bin/env bash
# validate-oidc.sh — Validate OIDC endpoints on a running Barycenter instance.
#
# Usage: ./scripts/validate-oidc.sh [BASE_URL]
#   BASE_URL defaults to http://localhost:9090

set -euo pipefail

BASE_URL="${1:-http://localhost:9090}"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
check() {
    local desc="$1" actual="$2" expected="$3"
    if [ "$actual" = "$expected" ]; then
        pass "$desc"
    else
        fail "$desc (expected '$expected', got '$actual')"
    fi
}

echo "=== Barycenter OIDC Validation ==="
echo "Base URL: $BASE_URL"
echo

# ─── 1. Discovery ───────────────────────────────────────────────────────────
echo "--- 1. Discovery Document ---"
DISCO=$(curl -sf "$BASE_URL/.well-known/openid-configuration" 2>/dev/null) || {
    fail "Discovery endpoint unreachable"
    echo "Cannot continue without discovery. Is the server running?"
    exit 1
}

check "issuer present" "$(echo "$DISCO" | jq -r '.issuer')" "$BASE_URL"
check "authorization_endpoint" "$(echo "$DISCO" | jq -r '.authorization_endpoint')" "$BASE_URL/authorize"
check "token_endpoint" "$(echo "$DISCO" | jq -r '.token_endpoint')" "$BASE_URL/token"
check "userinfo_endpoint" "$(echo "$DISCO" | jq -r '.userinfo_endpoint')" "$BASE_URL/userinfo"
check "jwks_uri" "$(echo "$DISCO" | jq -r '.jwks_uri')" "$BASE_URL/.well-known/jwks.json"
check "registration_endpoint" "$(echo "$DISCO" | jq -r '.registration_endpoint')" "$BASE_URL/connect/register"
check "revocation_endpoint" "$(echo "$DISCO" | jq -r '.revocation_endpoint')" "$BASE_URL/revoke"
check "introspection_endpoint" "$(echo "$DISCO" | jq -r '.introspection_endpoint')" "$BASE_URL/introspect"

# Check supported values
check "response_types includes code" \
    "$(echo "$DISCO" | jq '[.response_types_supported[] | select(. == "code")] | length')" "1"
check "code_challenge_methods includes S256" \
    "$(echo "$DISCO" | jq '[.code_challenge_methods_supported[] | select(. == "S256")] | length')" "1"
check "auth methods include client_secret_basic" \
    "$(echo "$DISCO" | jq '[.token_endpoint_auth_methods_supported[] | select(. == "client_secret_basic")] | length')" "1"
check "auth methods include client_secret_post" \
    "$(echo "$DISCO" | jq '[.token_endpoint_auth_methods_supported[] | select(. == "client_secret_post")] | length')" "1"
check "signing alg includes RS256" \
    "$(echo "$DISCO" | jq '[.id_token_signing_alg_values_supported[] | select(. == "RS256")] | length')" "1"
echo

# ─── 2. JWKS ────────────────────────────────────────────────────────────────
echo "--- 2. JWKS ---"
JWKS=$(curl -sf "$BASE_URL/.well-known/jwks.json" 2>/dev/null) || {
    fail "JWKS endpoint unreachable"
    JWKS="{}"
}

KEY_COUNT=$(echo "$JWKS" | jq '.keys | length' 2>/dev/null || echo 0)
if [ "$KEY_COUNT" -gt 0 ]; then
    pass "JWKS has $KEY_COUNT key(s)"
    HAS_KID=$(echo "$JWKS" | jq -r '.keys[0].kid // empty')
    if [ -n "$HAS_KID" ]; then
        pass "First key has kid: $HAS_KID"
    else
        fail "First key missing kid"
    fi
else
    fail "JWKS has no keys"
fi
echo

# ─── 3. Dynamic Client Registration ─────────────────────────────────────────
echo "--- 3. Client Registration ---"
REG_RESP=$(curl -sf -X POST "$BASE_URL/connect/register" \
    -H "Content-Type: application/json" \
    -d '{
        "redirect_uris": ["http://localhost:8080/callback"],
        "client_name": "Validation Script Client",
        "token_endpoint_auth_method": "client_secret_basic"
    }' 2>/dev/null) || {
    fail "Client registration failed"
    REG_RESP="{}"
}

CLIENT_ID=$(echo "$REG_RESP" | jq -r '.client_id // empty')
CLIENT_SECRET=$(echo "$REG_RESP" | jq -r '.client_secret // empty')

if [ -n "$CLIENT_ID" ] && [ -n "$CLIENT_SECRET" ]; then
    pass "Client registered (client_id: ${CLIENT_ID:0:12}...)"
else
    fail "Client registration did not return client_id/client_secret"
fi
echo

# ─── 4. PKCE Generation ─────────────────────────────────────────────────────
echo "--- 4. PKCE Generation ---"
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=' | tr '+/' '-_')
CODE_CHALLENGE=$(printf '%s' "$CODE_VERIFIER" | openssl dgst -binary -sha256 | base64 | tr -d '=' | tr '+/' '-_')
pass "code_verifier generated (${#CODE_VERIFIER} chars)"
pass "code_challenge generated (S256)"
echo

# ─── 5. Authorization URL ───────────────────────────────────────────────────
echo "--- 5. Authorization ---"
AUTH_URL="$BASE_URL/authorize?client_id=$CLIENT_ID&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&response_type=code&scope=openid%20profile%20email&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256&state=validate123&nonce=nonce456"

AUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$AUTH_URL" 2>/dev/null)
# Expect 302 redirect (to login) or 200 (if already logged in)
if [ "$AUTH_STATUS" = "302" ] || [ "$AUTH_STATUS" = "303" ] || [ "$AUTH_STATUS" = "200" ]; then
    pass "Authorization endpoint responds ($AUTH_STATUS)"
else
    fail "Authorization endpoint returned $AUTH_STATUS"
fi
echo

# ─── 6. UserInfo (unauthenticated — expect 401) ─────────────────────────────
echo "--- 6. UserInfo (unauthenticated) ---"
UI_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/userinfo" 2>/dev/null)
check "UserInfo without token returns 401" "$UI_STATUS" "401"
echo

# ─── 7. Token Introspection (with invalid token) ────────────────────────────
echo "--- 7. Token Introspection ---"
if [ -n "$CLIENT_ID" ] && [ -n "$CLIENT_SECRET" ]; then
    AUTH_HEADER=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64 -w0 2>/dev/null || printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64 2>/dev/null)
    INTROSPECT_RESP=$(curl -sf -X POST "$BASE_URL/introspect" \
        -H "Authorization: Basic $AUTH_HEADER" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "token=invalid_token_12345" 2>/dev/null) || INTROSPECT_RESP="{}"

    ACTIVE=$(echo "$INTROSPECT_RESP" | jq -r '.active // empty')
    check "Introspection of invalid token returns active=false" "$ACTIVE" "false"
else
    fail "Skipping introspection (no client credentials)"
fi
echo

# ─── 8. Token Revocation (with invalid token — should return 200) ───────────
echo "--- 8. Token Revocation ---"
if [ -n "$CLIENT_ID" ] && [ -n "$CLIENT_SECRET" ]; then
    REVOKE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/revoke" \
        -H "Authorization: Basic $AUTH_HEADER" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "token=invalid_token_12345" 2>/dev/null)
    check "Revocation of unknown token returns 200" "$REVOKE_STATUS" "200"
else
    fail "Skipping revocation (no client credentials)"
fi
echo

# ─── Summary ─────────────────────────────────────────────────────────────────
echo "=== Summary ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo

if [ "$FAIL" -gt 0 ]; then
    echo "Some checks failed. Ensure the server is running and configured correctly."
    exit 1
else
    echo "All checks passed."
    exit 0
fi
