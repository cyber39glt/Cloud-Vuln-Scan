#!/usr/bin/env bash
# Starts the PRODUCTION stack (deploy/compose.prod.yml) on this machine with
# DOMAIN=localhost (Caddy's local certificate authority) and checks its security
# properties. Used by CI; safe to run locally. Cleans up after itself.
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
compose() { docker compose -p cloudsecura-smoke --env-file "$work/.env" -f deploy/compose.prod.yml "$@"; }
cleanup() { compose down --volumes >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT

cp deploy/init-env.sh "$work/"
printf 'localhost\nops@example.com\nSmokeTest\n' | bash "$work/init-env.sh" >/dev/null
printf 'HTTP_PORT=8080\nHTTPS_PORT=8443\nEDGE_NET=172.31.249\n' >> "$work/.env"
app_password=$(grep '^POSTGRES_APP_PASSWORD=' "$work/.env" | cut -d= -f2)

# SMOKE_NO_BUILD=1 with CLOUDSECURA_IMAGE=<image> reuses an image built elsewhere.
if [ "${SMOKE_NO_BUILD:-}" = "1" ]; then compose up -d --no-build --wait; else compose up -d --build --wait; fi
fail() { echo "FAIL: $*" >&2; compose logs --tail=50 >&2; exit 1; }

headers=$(curl -sk -D - -o /dev/null https://localhost:8443/health)
grep -q "^HTTP/2 200" <<<"$headers" || fail "HTTPS health check"
grep -qi "^strict-transport-security: max-age=31536000" <<<"$headers" || fail "HSTS header"
grep -qi "^server:" <<<"$headers" && fail "Server header present"
[ "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/)" = "308" ] || fail "HTTP->HTTPS redirect"
[ "$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:8443/docs)" = "404" ] || fail "API docs exposed"
curl -sk https://localhost:8443/ | grep -q "<title>CloudSecura</title>" || fail "dashboard"
[ "$(curl -sk https://localhost:8443/api/v1/setup)" = '{"needed":true}' ] || fail "fresh install"

api=$(compose ps -q api)
docker exec "$api" sh -c 'touch /app/x' 2>/dev/null && fail "API file system writable"
docker exec "$api" sh -c 'env | grep -q POSTGRES_OWNER_PASSWORD' && fail "owner password in API"
docker exec "$api" python -c "import socket; socket.create_connection(('1.1.1.1', 443), timeout=3)" 2>/dev/null \
  && fail "API container can reach the internet"

db=$(compose ps -q db)
for statement in "DELETE FROM audit_events" "ALTER TABLE scan_runs DISABLE TRIGGER ALL" "DROP TABLE users"; do
  docker exec -e PGPASSWORD="$app_password" "$db" \
    psql -h 127.0.0.1 -U cloudsecura_app -d cloudsecura -tAc "$statement" >/dev/null 2>&1 \
    && fail "application login allowed: $statement"
done

docker exec "$api" python -m app.demo --save "Smoke Client" >/dev/null || fail "saving a scan"
echo "Production stack smoke test passed."
