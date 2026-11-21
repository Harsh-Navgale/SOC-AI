#!/usr/bin/env bash
# Paste this whole file into the EC2 launch wizard's "Advanced details -> User data" field
# (see README.md) so it runs automatically, as root, on first boot. Only prepares the box
# (Docker + tooling); it does NOT fetch or start the app — that's deploy.sh, run from your own
# machine afterward, which rsyncs the actual repo up over SSH (keeping this independent of any
# git remote). If you launched the instance without pasting this in, SSH in and run it by hand
# instead: `cat user_data.sh | ssh -i <key> ec2-user@<ip> sudo bash`.
#
# Written for Amazon Linux 2023 (dnf, ec2-user). Docker Engine comes from AL2023's OWN repo
# (`dnf install docker`) — Docker's official docker-ce.repo 404s here, because its $releasever
# substitution resolves to Amazon Linux's own version string (e.g. "2023.12.2026..."), which
# doesn't exist in download.docker.com's CentOS tree (confirmed by hitting that 404 directly).
# The `docker compose` v2 plugin isn't in AL2023's repo at all though, so that part still comes
# from upstream: the plugin binary itself, fetched straight from docker/compose's releases.
# Same story for `docker buildx` — `docker compose build` requires buildx >= 0.17.0, which the
# bare AL2023 `docker` package doesn't reliably bring along at a current enough version. Pinned
# to a known release rather than resolving "latest" at runtime: that was fetched via GitHub's
# API, which can silently fail (rate limiting, JSON parsing) and leave the plugin half-installed.
# `dnf install docker-buildx-plugin` isn't used either — it can "succeed" while installing a
# version still below 0.17.0, which looks fine (exit 0) but leaves compose build broken anyway.
set -euo pipefail

BUILDX_VERSION="v0.36.1"

dnf update -y
dnf install -y docker rsync make openssl

mkdir -p /usr/libexec/docker/cli-plugins
curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
  -o /usr/libexec/docker/cli-plugins/docker-compose
chmod +x /usr/libexec/docker/cli-plugins/docker-compose

curl -fsSL "https://github.com/docker/buildx/releases/download/${BUILDX_VERSION}/buildx-${BUILDX_VERSION}.linux-amd64" \
  -o /usr/libexec/docker/cli-plugins/docker-buildx
chmod +x /usr/libexec/docker/cli-plugins/docker-buildx

usermod -aG docker ec2-user
systemctl enable --now docker

mkdir -p /opt/soc-ai
chown ec2-user:ec2-user /opt/soc-ai

touch /opt/soc-ai/.cloud-init-done
