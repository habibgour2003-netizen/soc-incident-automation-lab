# Next: true SOC tool integration

Do not claim the Phase 1 demo actually runs Wazuh, TheHive or Shuffle.

**Low-RAM progression**
1. Export alerts from an existing Wazuh lab using a sanitized copy of `alerts.json` where each line is valid Wazuh JSON.
2. Reuse the existing pipeline against the exported JSONL. Sensitive source IPs, usernames and hostnames should be redacted before upload to GitHub.
3. If running TheHive in a remote trial or lab is feasible, integrate REST API using documentation that matches that version. Use a test API key stored in environment variables; verify HTTP status and prevent duplicate cases.
4. For Shuffle, set up a webhook-triggered workflow and only enable real IP reputation enrichment with keys configured in a secret store.
5. Never auto-block network traffic without human approval and authorized scope.

Future screenshot checklist: local case report, test output, redacted Wazuh log, optional real TheHive case and Shuffle workflow (only once actually deployed).
