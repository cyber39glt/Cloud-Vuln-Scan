#!/usr/bin/env bash
# Creates deploy/.env with fresh random secrets (run once on the server).
# Nothing is printed except the non-secret values you chose.
set -euo pipefail
cd "$(dirname "$0")"
if [ -e .env ]; then
  echo "deploy/.env already exists; not overwriting it." >&2
  exit 1
fi
read -rp "Domain name for the platform (e.g. cloudsecura.example.com): " DOMAIN
read -rp "E-mail for certificate expiry notices (Let's Encrypt): " ACME_EMAIL
read -rp "Consultancy name, letters/digits/hyphens [SubtleTech]: " CONSULTANCY_NAME
CONSULTANCY_NAME=${CONSULTANCY_NAME:-SubtleTech}
secret() { head -c 48 /dev/urandom | base64 | tr -d '/+=\n' | cut -c1-48; }
umask 077 # the file is readable by its owner only
cat > .env <<ENV
# CloudSecura production settings. Contains secrets: never commit or share this file.
DOMAIN=${DOMAIN}
ACME_EMAIL=${ACME_EMAIL}
CONSULTANCY_NAME=${CONSULTANCY_NAME}
LOG_LEVEL=INFO

# Encrypts MFA secrets, signs stored results, derives the setup code. Changing it
# invalidates every MFA enrolment and every stored signature: keep it, back it up.
APP_SECRET_KEY=$(secret)

POSTGRES_DB=cloudsecura
POSTGRES_OWNER_USER=cloudsecura_owner
POSTGRES_OWNER_PASSWORD=$(secret)
POSTGRES_APP_USER=cloudsecura_app
POSTGRES_APP_PASSWORD=$(secret)

INVITE_VALID_HOURS=48

# Platform cloud identity (see docs/deployment.md). Leave empty until needed.
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
ENV
echo "Created deploy/.env for ${DOMAIN}. Back it up somewhere safe (a password manager)."
