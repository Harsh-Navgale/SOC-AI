#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p certs

if [ -f certs/server.crt ] && [ -f certs/server.key ]; then
  echo "certs/server.crt and certs/server.key already exist, skipping."
  echo "Delete certs/server.crt and certs/server.key first if you need to regenerate (e.g. the LAN IP changed)."
  exit 0
fi

# Auto-detect this machine's primary LAN IP so the cert is valid when reached from other
# devices on the network, not just localhost. Falls back gracefully if detection fails (e.g.
# no default route) — the cert still works for local-only access either way.
LAN_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')"

SAN="DNS:localhost,DNS:soc-ai.local,IP:127.0.0.1"
if [ -n "$LAN_IP" ]; then
  SAN="${SAN},IP:${LAN_IP}"
  echo "Detected LAN IP ${LAN_IP} — adding it to the certificate so LAN clients don't get a hostname-mismatch error."
else
  echo "Could not auto-detect a LAN IP — certificate will only cover localhost."
fi

openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -days 825 \
  -subj "/CN=soc-ai.local" \
  -addext "subjectAltName=${SAN}"

chmod 600 certs/server.key
echo "Generated self-signed TLS certificate in certs/ (valid 825 days)."
echo "Browsers will warn about it being self-signed — that's expected for a local/lab deployment."
echo "If this machine's LAN IP changes later (DHCP), re-run this script after deleting certs/server.crt and certs/server.key."
