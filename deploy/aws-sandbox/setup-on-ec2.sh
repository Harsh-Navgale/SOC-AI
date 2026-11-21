#!/usr/bin/env bash
# Run this ON THE EC2 INSTANCE ITSELF, after you've SSHed in and copied the repo onto the box
# (e.g. from your own machine: `rsync -az --exclude .git --exclude node_modules --exclude
# certs --exclude .env /path/to/SOC-AI/ ec2-user@<public-ip>:/home/ec2-user/SOC-AI/`).
#
# Usage (from inside the copied repo's root on the instance):
#   bash deploy/aws-sandbox/setup-on-ec2.sh
#
# Does everything deploy.sh does remotely, just run locally instead of driven over SSH from
# your laptop: installs Docker if it's not already there (so this works even if you skipped
# pasting user_data.sh at launch), runs scripts/setup.sh, fixes the TLS cert to include this
# instance's public IP (auto-detected — no need to pass it in), then builds and starts the
# stack. Safe to re-run.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${PROJECT_ROOT}"

if [ ! -f docker-compose.yml ]; then
  echo "Expected to find docker-compose.yml in ${PROJECT_ROOT} — make sure you copied the"
  echo "whole repo onto this instance first (see the comment at the top of this script)."
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  # Docker Engine comes from AL2023's OWN repo here — Docker's official docker-ce.repo 404s on
  # Amazon Linux, because its $releasever substitution resolves to AL2023's own version string,
  # which doesn't exist in download.docker.com's CentOS tree. The `docker compose` v2 plugin
  # isn't in AL2023's repo at all though, so that part still comes from upstream directly.
  echo "== Docker not found — installing (Amazon Linux 2023: dnf's own docker package + the upstream compose plugin binary) =="
  sudo dnf update -y
  sudo dnf install -y docker rsync make openssl
  sudo mkdir -p /usr/libexec/docker/cli-plugins
  sudo curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
    -o /usr/libexec/docker/cli-plugins/docker-compose
  sudo chmod +x /usr/libexec/docker/cli-plugins/docker-compose
  sudo usermod -aG docker "$(whoami)"
  sudo systemctl enable --now docker
  echo "Docker installed. If the next command fails with a permission error, log out and back"
  echo "in once (group membership needs a fresh shell), then re-run this script."
fi

# `docker compose build` requires buildx >= 0.17.0, which a bare AL2023 `docker` install
# doesn't reliably bring along at a current enough version — pinned to a known release and
# always (re)installed, rather than checking for "any buildx" first: a prior pass through this
# script, or `dnf install docker-buildx-plugin`, can leave a plugin present that's still below
# 0.17.0, which a simple presence check wouldn't catch.
BUILDX_VERSION="v0.36.1"
echo "== Installing docker buildx ${BUILDX_VERSION} (compose build requires >= 0.17.0) =="
sudo mkdir -p /usr/libexec/docker/cli-plugins
sudo curl -fsSL "https://github.com/docker/buildx/releases/download/${BUILDX_VERSION}/buildx-${BUILDX_VERSION}.linux-amd64" \
  -o /usr/libexec/docker/cli-plugins/docker-buildx
sudo chmod +x /usr/libexec/docker/cli-plugins/docker-buildx
docker buildx version

echo "== Running scripts/setup.sh =="
bash scripts/setup.sh

echo "== Fixing the TLS cert to include this instance's public IP =="
# scripts/generate-certs.sh only knows about this box's PRIVATE IP (it auto-detects via the
# default route) — your browser will connect via the PUBLIC IP instead, which would cause a
# certificate hostname mismatch. Regenerate it here with both IPs in the SAN. Public IP comes
# from the instance metadata service (IMDSv2) rather than requiring you to pass it in.
TOKEN="$(curl -sX PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')"
PUBLIC_IP="$(curl -s -H "X-aws-ec2-metadata-token: ${TOKEN}" http://169.254.169.254/latest/meta-data/public-ipv4)"
PRIVATE_IP="$(hostname -I | awk '{print $1}')"

if [ -z "${PUBLIC_IP}" ]; then
  echo "Could not auto-detect a public IP from instance metadata — this instance may not have"
  echo "one (no Elastic IP / no auto-assigned public IP). The cert will only cover the"
  echo "private IP; you'll need to reach the dashboard from inside the VPC, or assign a"
  echo "public/Elastic IP and re-run this script."
fi

rm -f certs/server.crt certs/server.key
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout certs/server.key -out certs/server.crt -days 825 \
  -subj "/CN=soc-ai-sandbox" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:${PRIVATE_IP}$([ -n "${PUBLIC_IP}" ] && echo ",IP:${PUBLIC_IP}")"
chmod 600 certs/server.key

# AI features come up once you connect Bedrock from the dashboard (README.md's post-deploy
# steps) — nothing to install on this box for it.

echo "== Building and starting the stack =="
docker compose build
docker compose up -d

echo
echo "== Done =="
echo "Dashboard: https://${PUBLIC_IP:-$PRIVATE_IP}:8443"
echo
echo "Admin credentials were printed above by scripts/setup.sh on first run only — they are"
echo "not stored anywhere else. If you missed them: cat .env"
