#!/usr/bin/env bash
# Run this AFTER you've launched the Wazuh EC2 instance yourself in the console (see
# README.md), pasted the one-line installer command into User data (or run it by hand over
# SSH), and have its public IP + your downloaded .pem key.
#
# Waits for Wazuh's own all-in-one installer to finish (it keeps running in the background for
# several minutes after the instance itself is up), then extracts and prints the generated
# admin passwords.
#
# Usage: ./deploy.sh <public-ip> <path-to-key.pem>
set -euo pipefail
cd "$(dirname "$0")"

PUBLIC_IP="${1:?Usage: $0 <public-ip> <path-to-key.pem>}"
KEY_PATH="${2:?Usage: $0 <public-ip> <path-to-key.pem>}"
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

echo "== Waiting for wazuh-install.sh to finish (this takes several minutes) =="
for i in $(seq 1 60); do
  if $SSH 'test -f /root/.wazuh-install-done' 2>/dev/null; then
    break
  fi
  sleep 15
done
if ! $SSH 'test -f /root/.wazuh-install-done' 2>/dev/null; then
  echo "Still not done after 15 minutes. If you haven't started the install yet, SSH in and run:"
  echo "  curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash wazuh-install.sh -a | sudo tee /root/wazuh-install.log && sudo touch /root/.wazuh-install-done"
  echo "Otherwise check progress with:"
  echo "  ssh -i ${KEY_PATH} ec2-user@${PUBLIC_IP} 'sudo tail -50 /root/wazuh-install.log'"
  exit 1
fi

echo "== Install finished — extracting the generated admin passwords =="
$SSH sudo bash -c "cd /root && tar -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O" \
  | tee ./wazuh-passwords.txt
echo
echo "(Also saved locally to deploy/aws-sandbox/wazuh/wazuh-passwords.txt — gitignored.)"

PRIVATE_IP="$($SSH 'hostname -I | awk "{print \$1}"')"

echo
echo "== Done =="
echo "Dashboard:    https://${PUBLIC_IP}  (log in as 'admin' with the password shown above)"
echo "SSH:          ssh -i ${KEY_PATH} ec2-user@${PUBLIC_IP}"
echo "Private IP:   ${PRIVATE_IP}   (use this for WAZUH_INDEXER_HOST/WAZUH_MANAGER_HOST and for install-wazuh-agent.sh)"
