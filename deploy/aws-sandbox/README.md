# SOC-AI: simple EC2 sandbox deployment

A throwaway, test-only copy of the stack on a single EC2 instance — same `docker-compose.yml`,
same containers, nothing re-architected. The point is to validate the deployment itself (does
it come up cleanly outside your laptop, does the TLS/login/dashboard flow work from a real
public IP), not to stand up a second production system. **Just the EC2 console, no
CloudFormation/Terraform** — launch it by hand, run one script to deploy the app.

## Blocker: check your AWS credentials first

The AWS CLI in this environment is already authenticated, but as IAM user `ISS-474912`
(account `563936302824`), which is scoped tightly enough that it can't even run
`ec2:DescribeVpcs` — confirmed by actually calling it. If you're using the **Console** (which
this plan assumes), this doesn't matter as long as the person logging into the console has
permission to launch EC2 instances. If you want to use the AWS CLI for any of this instead,
you'll need different credentials.

## Architecture

```
Your browser ──HTTPS:8443──▶ EC2 (Amazon Linux 2023, t3.large)
                               └── docker compose (unchanged from local):
                                     nginx (frontend) ──▶ backend (FastAPI) ──▶ mongodb
                                                                            └─▶ chromadb
                                     correlator (background worker) ──▶ mongodb
                               outbound only: Bedrock, S3, VirusTotal/AbuseIPDB APIs
```

One EC2 instance, one security group (22 + 8443 only). Mongo/Chroma/backend stay
container-internal — only nginx's 8443 is reachable from outside, exactly like the current
local deployment's "single TLS entry point" design (see `PRODUCTION.md`). No managed
databases, no load balancer — deliberately skipped as unnecessary for a single-box sandbox.

**AI provider: AWS Bedrock.** Plan is to connect Bedrock from the dashboard after deploy and
set it as the default model for both chat and background jobs, exactly as already configured
on the primary deployment.

**Wazuh: a real deployment in the sandbox, not your LAN manager.** Your actual Wazuh
Manager/Indexer lives on a LAN machine, not reachable from the internet, and tunneling it in
just for a demo isn't a reasonable trade. Instead, `wazuh/` in this directory launches a real
Wazuh (server + indexer + dashboard) as its own EC2 instance, with a Wazuh agent installed on
this box so real alerts (SSH logins, rootcheck, log analysis) flow end to end — see
`wazuh/README.md`. Until that's up (or if you'd rather skip it), `make seed` loads the same
synthetic demo alerts `BUILD_GUIDE.md` already uses.

## What's in this directory

| File | Purpose |
|---|---|
| `user_data.sh` | Paste this into the launch wizard's "User data" field — installs Docker, nothing app-specific |
| `deploy.sh` | Run from YOUR machine after the instance is up — rsyncs the repo, fixes the TLS cert for the public IP, builds and starts the stack |
| `setup-on-ec2.sh` | The same job as `deploy.sh`, but run ON the instance itself after you've copied the repo there and SSHed in |
| `install-wazuh-agent.sh` | Installs a Wazuh agent on this instance, pointed at a Wazuh manager — run after `wazuh/` (below) is up |
| `wazuh/` | The same simple-EC2 approach, for a real Wazuh instance to generate demo alerts from — see `wazuh/README.md` |

## Cost estimate

~$0.0832/hr (`t3.large` on-demand) + ~$3–4/month for the 40GB gp3 volume if left running. **A
few hours of testing costs well under $1** — the only way to spend real money is leaving it
running. Terminate the instance when you're done (see Teardown).

## Steps

### 1. Launch the instance (AWS Console)

1. Open the [EC2 console](https://console.aws.amazon.com/ec2/) → **Launch instance**.
2. **Name**: `soc-ai-sandbox`.
3. **AMI**: Amazon Linux 2023 (the default "Quick Start" selection).
4. **Instance type**: `t3.large` (8GB/2vCPU — comfortably runs mongo+chroma+backend+correlator+
   frontend together, including the memory spike during `docker compose build`).
5. **Key pair**: create a new one, name it `soc-ai-sandbox-key`, download the `.pem` file —
   this is the only way in once the instance exists, so keep it. Move it into this directory
   (`deploy/aws-sandbox/`) to match the commands below, or just remember its path.
6. **Network settings → Edit**:
   - Create a new security group (or reuse one you make for this).
   - Allow **SSH (22)** from **My IP** (auto-fills your current IP) — never "Anywhere".
   - **Add rule**: Custom TCP, port **8443**, source **Anywhere** (`0.0.0.0/0`) — the
     dashboard, behind TLS + login either way. Narrow this to "My IP" too if you'd rather not
     expose even a login page publicly.
7. **Storage**: bump the root volume to **40 GB** (gp3).
8. **Advanced details** → **User data**: paste the entire contents of `user_data.sh`.
9. **Launch instance**. Wait ~30 seconds, then find its **Public IPv4 address** on the
   instance's detail page.

### 2. Deploy the app

```bash
cd deploy/aws-sandbox
chmod 600 soc-ai-sandbox-key.pem   # or wherever you saved it
./deploy.sh <public-ip> <path-to-soc-ai-sandbox-key.pem>
```

This waits for the User data script (Docker install) to finish, rsyncs the whole repo up
(excluding `.git`, `node_modules`, `certs`, `.env` — all regenerated fresh on the box), runs
`scripts/setup.sh` remotely (generates `.env`, JWT secret, admin password, Mongo password —
printed once, during this run, same as the local `make setup` flow), regenerates the TLS cert
to include the public IP (the stock `generate-certs.sh` only knows the private IP, which would
otherwise cause a certificate hostname mismatch), then `docker compose build && up -d`.

**Save the admin password it prints — it's shown exactly once.**

**Prefer to drive it from inside the instance instead?** Copy the repo up yourself and run
`setup-on-ec2.sh` directly over SSH, rather than having `deploy.sh` orchestrate everything
remotely from your laptop:

```bash
# From your own machine:
rsync -az --exclude .git --exclude node_modules --exclude certs --exclude .env \
  -e "ssh -i <path-to-key.pem>" \
  /path/to/SOC-AI/ ec2-user@<public-ip>:/home/ec2-user/SOC-AI/

# Then SSH in and run the one setup script:
ssh -i <path-to-key.pem> ec2-user@<public-ip>
cd SOC-AI
bash deploy/aws-sandbox/setup-on-ec2.sh
```

It installs Docker itself if it's missing (so this works even if you skipped pasting
`user_data.sh` at launch), auto-detects the public IP from instance metadata for the TLS cert
(no need to pass it in), then runs `scripts/setup.sh` and ` ` —
same end result as `deploy.sh`, just run locally on the box instead of over SSH from outside.

### 3. Open the dashboard

`https://<public-ip>:8443`. Your browser will warn about the self-signed cert (expected —
accept it, same as local). Log in with the admin credentials from step 2.

### 4. Get real alerts flowing (or fall back to synthetic ones)

**Recommended for a demo:** launch a real Wazuh instance next to this one and install an
agent here — see `wazuh/README.md` for the full flow.

**Quicker, no real Wazuh:**
```bash
ssh -i soc-ai-sandbox-key.pem ec2-user@<public-ip> 'cd /opt/soc-ai && make seed'
```

### 5. Connect Bedrock and set it as the default AI provider

In the dashboard: **AI Chat → AI provider settings → Connect Bedrock** (API key or IAM access
key — whichever you used on the primary deployment), then set:
- **Default model for background AI jobs** → a Bedrock chat model (e.g. Claude Haiku 4.5, or
  whatever you're already using)
- **Default embedding model** → `amazon.titan-embed-text-v2:0` (or your usual choice)

Without this, AI investigation/Ask AI will 503 with "AI generation/embedding service
unavailable" — expected, since Bedrock is the only AI provider and nothing is connected yet.

### 6. Re-deploying after a code change

Just re-run `./deploy.sh <public-ip> <key.pem>` — rsync only sends the diff, and the remote
`docker compose build && up -d` picks it up.

## Security notes (sandbox-appropriate, not production-hardened)

- SSH restricted to "My IP" in the security group — never leave it open to `0.0.0.0/0`.
- Mongo/Chroma/backend are never exposed past the Docker bridge network — only nginx's 8443,
  same as the local deployment's existing design.
- This is still a self-signed cert and a single box with no patching/monitoring pipeline —
  fine for a short-lived test, not something to leave running unattended for weeks.
- The `.pem` key only exists on your machine and the instance's `authorized_keys` — AWS never
  sees it after you download it once at launch. Don't commit it (already gitignored here).

## Teardown

EC2 console → select the instance → **Instance state → Terminate instance**. Also delete the
security group afterward if you created a dedicated one (**Security Groups** in the left nav)
— it costs nothing to leave behind, but keeps the console tidy.


ADMIN_PASSWORD=jUOgp6N6fbnkR3tUevhhMaAH
