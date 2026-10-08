#!/usr/bin/env bash
# CI smoke test against the running Compose stack: bootstrap an admin from the
# command line, log in with password + authenticator code, change the temporary
# password, then API -> queue -> worker. CI has no cloud credentials, so the queued
# scan must FAIL with a clear reason: that proves the worker picked it up.
set -euo pipefail

api=http://127.0.0.1:8000/api/v1
jar=$(mktemp)
trap 'rm -f "$jar"' EXIT

post() { curl --fail-with-body --silent --show-error -b "$jar" -c "$jar" \
    -H 'content-type: application/json' -d "$2" "$api/$1"; }
get() { curl --fail-with-body --silent --show-error -b "$jar" -c "$jar" "$api/$1"; }
field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
# RFC 6238 TOTP with the standard library only.
totp() { python3 -c "
import base64, hashlib, hmac, struct, sys, time
key = base64.b32decode(sys.argv[1])
digest = hmac.new(key, struct.pack('>Q', int(time.time()) // 30), hashlib.sha1).digest()
offset = digest[-1] & 15
print('%06d' % ((struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000))
" "$1"; }

out=$(docker compose run --rm api python -m app.cli users create --admin \
    --email ci@subtletech.test --name "CI admin")
temporary=$(printf '%s\n' "$out" | sed -n 's/^    \(\S\+\)$/\1/p')

post auth/login "{\"email\":\"ci@subtletech.test\",\"password\":\"$temporary\"}" >/dev/null
secret=$(post auth/mfa/setup '{}' | field '["secret"]')
post auth/mfa/activate "{\"code\":\"$(totp "$secret")\"}" >/dev/null
post auth/password "{\"current_password\":\"$temporary\",\"new_password\":\"ci smoke test passphrase\"}"
get auth/me; echo

client=$(post clients '{"name":"CI smoke"}' | field '["id"]')
conn=$(post "clients/$client/connections/aws" '{"account_id":"111122223333"}' | field '["connection"]["id"]')
assessment=$(post "clients/$client/assessments" "{\"connection_id\":\"$conn\",\"name\":\"smoke\"}" | field '["id"]')
job=$(post "clients/$client/assessments/$assessment/scans" '{}' | field '["id"]')
status=queued
for _ in $(seq 1 30); do
    status=$(get "clients/$client/scan-jobs/$job" | field '["status"]')
    [ "$status" = failed ] && break
    sleep 2
done
get "clients/$client/scan-jobs/$job"; echo
test "$status" = failed

# Without the session cookie, the same data is refused.
code=$(curl --silent -o /dev/null -w '%{http_code}' "$api/clients/$client")
test "$code" = 401
echo "Smoke test passed."
