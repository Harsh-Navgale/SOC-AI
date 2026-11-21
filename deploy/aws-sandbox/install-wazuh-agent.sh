#!/usr/bin/env bash
# Installs and registers a Wazuh agent ON THE SOC-AI SANDBOX INSTANCE ITSELF, so it becomes the
# demo's "monitored endpoint" — zero extra cost, real alerts (SSH logins, rootcheck, log
# analysis) start flowing into Wazuh (and from there, into SOC-AI) within minutes.
#
# Run this from your own machine, AFTER both instances are up (the SOC-AI box's deploy.sh has
# already run, and the Wazuh box has finished its installer):
#
#   ./install-wazuh-agent.sh <soc-ai-public-ip> <soc-ai-key.pem> <wazuh-manager-private-ip>
set -euo pipefail

SOC_AI_IP="${1:?Usage: $0 <soc-ai-public-ip> <soc-ai-key.pem> <wazuh-manager-private-ip>}"
KEY_PATH="${2:?Usage: $0 <soc-ai-public-ip> <soc-ai-key.pem> <wazuh-manager-private-ip>}"
WAZUH_MANAGER_IP="${3:?Usage: $0 <soc-ai-public-ip> <soc-ai-key.pem> <wazuh-manager-private-ip>}"
SSH="ssh -i ${KEY_PATH} -o StrictHostKeyChecking=accept-new ec2-user@${SOC_AI_IP}"

echo "== Installing the Wazuh agent on ${SOC_AI_IP}, pointed at manager ${WAZUH_MANAGER_IP} =="
# Amazon Linux 2023 (dnf/rpm) — Wazuh's documented yum/dnf repo setup, not the apt one.
$SSH sudo bash -s <<REMOTE
set -euo pipefail

rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat > /etc/yum.repos.d/wazuh.repo <<'REPO'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPO

WAZUH_MANAGER="${WAZUH_MANAGER_IP}" dnf install -y wazuh-agent

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
systemctl --no-pager status wazuh-agent
REMOTE

echo
echo "== Done =="
echo "Check enrollment either from the Wazuh dashboard's Agents page, or by SSHing into the"
echo "Wazuh instance and running:"
echo "  sudo /var/ossec/bin/agent_control -l"
echo
echo "Next: point the SOC-AI backend at this real Wazuh manager/indexer — see README.md's"
echo "\"Wire SOC-AI to the real Wazuh instance\" section."
