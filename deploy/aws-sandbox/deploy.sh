#!/usr/bin/env bash
# Run this AFTER you've launched the EC2 instance yourself in the console (see README.md) and
# have its public IP + your downloaded .pem key. Rsyncs the repo up, waits out the Docker
# install from User data, then builds and starts the stack remotely. Safe to re-run — rsync
# only sends what changed, and `docker compose up -d` is a no-op on containers already running
# with the current image.
#
# Usage: ./deploy.sh <public-ip> <path-to-key.pem>
set -euo pipefail
cd "$(dirname "$0")"

PUBLIC_IP="${1:?Usage: $0 <public-ip> <path-to-key.pem>}"
KEY_PATH="${2:?Usage: $0 <public-ip> <path-to-key.pem>}"
PROJECT_ROOT="$(cd ../.. && pwd)"
REMOTE_DIR="/opt/soc-ai"
SSH="ssh -i ${KEY_PATH} -o StrictHostKeyChecking=accept-new ec2-user@${PUBLIC_IP}"

chmod 600 "${KEY_PATH}"

echo "== Waiting for SSH on ${PUBLIC_IP} =="
for i in $(seq 1 30); do
  if $SSH -o ConnectTimeout=5 'echo ok' >/dev/null 2>&1; then
    break
  fi
  sleep 10
done
$SSH 'echo "SSH is up"'

echo "== Waiting for the User data script (Docker install) to finish =="
for i in $(seq 1 30); do
  if $SSH 'test -f /opt/soc-ai/.cloud-init-done' 2>/dev/null; then
    break
  fi
  sleep 10
done
if ! $SSH 'test -f /opt/soc-ai/.cloud-init-done' 2>/dev/null; then
  echo "Still not done after 5 minutes. If you didn't paste user_data.sh into the launch"
  echo "wizard's User data field, run its commands manually over SSH instead:"
  echo "  cat user_data.sh | ${SSH} sudo bash"
  exit 1
fi

echo "== Syncing repo to ${PUBLIC_IP}:${REMOTE_DIR} =="
rsync -az --delete \
  --exclude '.git' \
  --exclude 'node_modules' \
  --exclude 'frontend/dist' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude 'certs' \
  --exclude '.env' \
  --exclude 'deploy/aws-sandbox/*.pem' \
  -e "ssh -i ${KEY_PATH} -o StrictHostKeyChecking=accept-new" \
  "${PROJECT_ROOT}/" "ec2-user@${PUBLIC_IP}:${REMOTE_DIR}/"

echo "== Running setup + TLS cert (with the public IP added) + build + up =="
$SSH bash -s <<REMOTE
set -euo pipefail
cd ${REMOTE_DIR}
bash scripts/setup.sh

# scripts/generate-certs.sh only knows about this box's PRIVATE IP (it auto-detects via the
# default route) — your browser will connect via the PUBLIC IP instead, which would cause a
# certificate hostname mismatch. Regenerate it here with both IPs in the SAN.
rm -f certs/server.crt certs/server.key
PRIVATE_IP="\$(hostname -I | awk '{print \$1}')"
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout certs/server.key -out certs/server.crt -days 825 \
  -subj "/CN=soc-ai-sandbox" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:\${PRIVATE_IP},IP:${PUBLIC_IP}"
chmod 600 certs/server.key

# AI features come up once you connect Bedrock from the dashboard (see README.md's post-deploy
# steps) — nothing to install on this box for it.

docker compose build
docker compose up -d
REMOTE

echo
echo "== Done =="
echo "Dashboard: https://${PUBLIC_IP}:8443"
echo "SSH:       ssh -i ${KEY_PATH} ec2-user@${PUBLIC_IP}"
echo
echo "Admin credentials were printed above by scripts/setup.sh on first run only — they are"
echo "not stored anywhere else. If you missed them, SSH in and check: cat ${REMOTE_DIR}/.env"
