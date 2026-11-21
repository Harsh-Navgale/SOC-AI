# Sample Incident Response Playbook — SSH Brute Force

1. Identify the source IP from the correlated incident.
2. Check if the IP has hit multiple agents (possible lateral movement).
3. Block the IP at the firewall / via Wazuh active response.
4. Reset credentials for any account with a successful login (rule level >= 10) from that IP.
5. Document the incident and notify the on-call lead.

Drop your own `.md` or `.txt` files in this folder (org policies, playbooks, past incident
write-ups). Run the console's "Ingest" option to load them into the Vector DB so the AI
assistant can use them as context when answering questions.
