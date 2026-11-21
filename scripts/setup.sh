#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== SOC-AI setup =="

command -v docker >/dev/null || { echo "Docker is required: https://docs.docker.com/engine/install/"; exit 1; }
docker compose version >/dev/null || { echo "The docker compose plugin is required."; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required (usually preinstalled on Ubuntu)."; exit 1; }

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

if grep -q '^JWT_SECRET=change_me_jwt_secret' .env; then
  SECRET=$(openssl rand -hex 32)
  sed -i "s#^JWT_SECRET=.*#JWT_SECRET=${SECRET}#" .env
  echo "Generated JWT_SECRET"
fi

if grep -q '^ADMIN_PASSWORD=change_me_admin_password' .env; then
  PASSWORD=$(openssl rand -base64 18)
  sed -i "s#^ADMIN_PASSWORD=.*#ADMIN_PASSWORD=${PASSWORD}#" .env
  echo
  echo "Generated the dashboard admin login (save this now — it is not stored anywhere else):"
  echo "  username: $(grep '^ADMIN_USERNAME=' .env | cut -d= -f2)"
  echo "  password: ${PASSWORD}"
  echo
fi

if grep -q '^MONGO_PASSWORD=change_me_mongo' .env; then
  MONGO_PASS=$(openssl rand -base64 18 | tr -d '=+/')
  sed -i "s#^MONGO_PASSWORD=.*#MONGO_PASSWORD=${MONGO_PASS}#" .env
  sed -i "s#^MONGO_URI=.*#MONGO_URI=mongodb://socadmin:${MONGO_PASS}@mongodb:27017#" .env
  echo "Generated MONGO_PASSWORD"
fi

bash scripts/generate-certs.sh

echo
echo "Setup complete. Next steps:"
echo "  1. (optional for now) edit .env and fill in WAZUH_INDEXER_HOST/USER/PASSWORD"
echo "     once you have your real Wazuh manager's indexer details — the stack runs"
echo "     fine without this, it just won't have real alerts yet."
echo "  2. make pull-models"
echo "  3. make build && make up"
echo "  4. make seed   (optional: load synthetic demo alerts so you have something to see)"
echo "  5. Open https://localhost:8443 (self-signed cert — your browser will warn, that's expected)"
