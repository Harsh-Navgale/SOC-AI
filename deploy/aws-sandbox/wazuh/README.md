# Wazuh sandbox (for the SOC-AI demo)

A second, separate EC2 instance running a real Wazuh deployment, so the demo has actual
Wazuh-sourced alerts flowing through SOC-AI instead of (or alongside) the synthetic
`make seed` data. Same "just the EC2 console" approach as `../README.md` — no
CloudFormation/Terraform here either.

Uses Wazuh's own official all-in-one quickstart installer (server + indexer + dashboard,
native packages on one host) — the officially documented, officially supported way to run all
three Wazuh components together. One command, run over SSH or pasted into User data.

## Architecture

```
soc-ai-sandbox instance ──private IP:9200──▶  wazuh-sandbox instance
   (backend reads alerts)                        indexer + manager + dashboard
                         ──private IP:55000──▶   (Wazuh's official all-in-one install)
   (agent on this box)   ──private IP:1514/1515▶

Your browser ──HTTPS:443 (your IP only)──▶ wazuh-sandbox instance (Wazuh's own dashboard UI)
```

Both instances need to be in the **same VPC** so they can reach each other over private IPs —
launch this one into the same default VPC the `soc-ai-sandbox` instance is in (the launch
wizard defaults to your account's default VPC either way, so unless you changed it for the
first instance, you don't need to do anything special here).

**Sizing**: Wazuh's own docs call for 4 vCPU / 8 GiB RAM minimum for an all-in-one install
with up to 25 agents. This demo only has one agent (the SOC-AI box monitoring itself), but use
`t3.xlarge` (4 vCPU/16GB) rather than the bare `t3.large` floor — the indexer's
cert-generation/init step during install is CPU-sensitive, and a `t3.large`'s burstable CPU
credits can throttle right when it matters. Drop to `t3.large` if cost matters more than that
safety margin.

## Cost estimate

~$0.1664/hr (`t3.xlarge`) + ~$4/month for the 50GB gp3 volume if left running. Combined with
the SOC-AI box (~$0.0832/hr), the whole demo is well under $1 for a few hours of testing.
Terminate both instances when done.

## Steps

### 1. Find the SOC-AI instance's private IP and security group

EC2 console → instances → `soc-ai-sandbox` → details tab: note its **Private IPv4 address**
and its **Security group** name/ID — you'll point this stack's inbound rules at that security
group (or, just as simply, that private IP) in step 2.

### 2. Launch the instance (AWS Console)

1. EC2 console → **Launch instance**.
2. **Name**: `wazuh-sandbox`.
3. **AMI**: Amazon Linux 2023 (the default "Quick Start" selection) — same family as the SOC-AI instance, so `wazuh-install.sh` sees the same dnf/rpm environment on both boxes.
4. **Instance type**: `t3.xlarge` (see Sizing above).
5. **Key pair**: create a new one, `wazuh-sandbox-key`, download the `.pem`, move it into
   `deploy/aws-sandbox/wazuh/` or remember its path.
6. **Network settings → Edit**:
   - **Same VPC** as `soc-ai-sandbox` (see Architecture above).
   - New security group. Rules:
     - SSH (22) from **My IP**.
     - Custom TCP 443 (Wazuh's own dashboard) from **My IP**.
     - Custom TCP 9200 (indexer), 55000 (manager API), 1514 and 1515 (agent ports) — source:
       the `soc-ai-sandbox` instance's **security group** (type to search for it by name in
       the source field) if you'd rather reference it directly, or its **private IP** as a
       `/32` CIDR if that's simpler. Either way: never "Anywhere" for these four.
7. **Storage**: bump the root volume to **50 GB** (gp3).
8. **Advanced details → User data** — paste:
   ```bash
   #!/usr/bin/env bash
   set -euo pipefail
   dnf update -y
   cd /root
   curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
   bash wazuh-install.sh -a > /root/wazuh-install.log 2>&1
   touch /root/.wazuh-install-done
   ```
9. **Launch instance**. Find its **Public IPv4 address** once it's running.

### 3. Wait for the install and get the generated passwords

```bash
cd deploy/aws-sandbox/wazuh
chmod 600 wazuh-sandbox-key.pem
./deploy.sh <public-ip> <path-to-wazuh-sandbox-key.pem>
```

Waits for `wazuh-install.sh -a` to actually finish (several minutes — it's installing and
initializing the indexer, manager, and dashboard), then prints every component's
auto-generated password. **Save these** — they're also saved locally to
`wazuh-passwords.txt` (gitignored), but nowhere else. Also prints the instance's **private
IP**, needed in steps 4 and 5.

### 4. Open Wazuh's own dashboard (optional, nice for the demo)

`https://<public-ip>` (port 443, no `:8443` here — that's the SOC-AI box). Log in as `admin`
with the password `deploy.sh` printed. Self-signed cert warning expected.

### 5. Install the agent on the SOC-AI box

From `deploy/aws-sandbox/` (one level up):

```bash
cd deploy/aws-sandbox
./install-wazuh-agent.sh <soc-ai-public-ip> <soc-ai-key.pem> <wazuh-private-ip>
```

Installs the Wazuh agent on the SOC-AI instance, pointed at this manager — within a minute or
two it should appear on Wazuh's dashboard's **Agents** page, and start generating real alerts
(SSH logins, rootcheck, log analysis) just from normal activity on that box.

### 6. Wire SOC-AI to the real Wazuh instance

**First, open the indexer up beyond localhost.** The all-in-one installer binds the indexer to
`127.0.0.1` only (`/etc/wazuh-indexer/opensearch.yml`'s `network.host`) — nothing outside this
one box can reach port 9200 by default, which is exactly why the SOC-AI box can authenticate
against the manager (port 55000) but gets "connection refused" against the indexer. Fix it on
the **Wazuh box**:

```bash
sudo sed -i 's/^network.host:.*/network.host: "0.0.0.0"/' /etc/wazuh-indexer/opensearch.yml
sudo systemctl restart wazuh-indexer
sudo ss -tlnp | grep 9200   # should now show 0.0.0.0:9200, not 127.0.0.1:9200
```

Use `0.0.0.0`, not the instance's own private IP specifically — Filebeat (which ships the
manager's alerts into the indexer, all on this same box) is configured to reach it via
`127.0.0.1`, and OpenSearch only binds to exactly the host(s) you give it. `0.0.0.0` covers
both that internal loopback traffic and external access from the SOC-AI box at once.

Then SSH into the SOC-AI box and edit `.env`:

```bash
ssh -i ../soc-ai-sandbox-key.pem ec2-user@<soc-ai-public-ip>
cd /opt/soc-ai
nano .env
```

Set:
```
WAZUH_INDEXER_HOST=https://<wazuh-private-ip>:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=<the "indexer" admin password from wazuh-passwords.txt>
WAZUH_INDEXER_VERIFY_SSL=false   # self-signed cert from the all-in-one installer

WAZUH_MANAGER_HOST=https://<wazuh-private-ip>:55000
WAZUH_MANAGER_USER=wazuh-wui
WAZUH_MANAGER_PASSWORD=<the "wazuh-wui" password from wazuh-passwords.txt>
WAZUH_MANAGER_VERIFY_SSL=false
```

Then recreate the backend so it picks up the change (`restart` does **not** reload `.env` —
this bit the primary deployment too, see `PRODUCTION.md`):

```bash
docker compose up -d backend
docker compose restart frontend   # avoids nginx caching the old backend IP
```

### 7. Confirm it

Open the SOC-AI dashboard → **System Health** — the Wazuh indexer and manager cards should
flip from "not configured" to real cluster/agent stats. Give the agent a few minutes to
generate activity, then check **Alerts**/**Incidents** for real Wazuh-sourced data instead of
the synthetic seed.

## Teardown

EC2 console → select the `wazuh-sandbox` instance → **Instance state → Terminate instance**.
Delete its dedicated security group afterward too if you made one.


06/10/2026 17:06:09 INFO: Wazuh dashboard web application initialized.
06/10/2026 17:06:09 INFO: --- Summary ---
06/10/2026 17:06:09 INFO: You can access the web interface https://<wazuh-dashboard-ip>:443
    User: admin
    Password: JZhZLu+jlaJVqy8Vd8cI2+zDCHYGZ.w+
06/10/2026 17:06:09 INFO: Installation finished.
