# SOC Incident Automation Lab — Phase 2 (Wazuh JSONL export integration)

**Offline, defensive blue-team portfolio project** using Python's standard library and SQLite, designed for Windows 10 / low-memory PCs.

## What is implemented and tested

- **Phase 1:** synthetic Wazuh-like security events → rule severity filtering → MOCK IoC context → correlation/deduplication → local SQLite incidents → HTML/CSV/JSON report.
- **Phase 2:** import a **local Wazuh `alerts.json` export** in newline-delimited JSON (JSONL) format using `import-wazuh`, without starting Wazuh or contacting any external service.
- Support common Linux event `data.srcip` and Windows event `data.win.eventdata.ipAddress` layouts. IP-less alerts are skipped and counted as invalid; this lab does **not** claim to parse all Wazuh rules.
- **Important:** Mock threat reputation is **automatically disabled** on exported-alert imports. Real IOC lookup, Shuffle SOAR and TheHive have **not been implemented**.
- Original event IDs are tracked in SQLite for idempotent imports. Repeated import into the same DB does not create duplicate incidents.
- Unit tests, including a Windows cleanup test that closes SQLite connections.

## Quick start: synthetic samples

Extract this archive, open PowerShell in this README's folder, then:

```powershell
py -m soclab run
py -m unittest discover -s tests -v
start .\outputs\report.html
```

## Phase 2 demo: realistic JSONL export shape (synthetic data)

```powershell
py -m soclab import-wazuh --input data/exported_wazuh_demo.jsonl
start .\outputs\real-lab\report.html
```

## Import your own authorized Wazuh lab logs (optional)

In an existing **Wazuh lab** on Linux, the manager typically writes one JSON alert per line in `/var/ossec/logs/alerts/alerts.json`. Copy a SMALL sanitized subset to a local text file. Example Windows import:

```powershell
py -m soclab import-wazuh --input "C:\lab\wazuh_export.jsonl" --min-level 7
```

**Security/privacy:** Do not publish actual alerts, user IDs, machine names, or IP addresses on GitHub. Make sure the export contains no secrets or identifiable information. Never commit your own `outputs` directory or private exports. Consider using this project *only* with the included synthetic fixtures if permissions/data handling requirements are unclear.

**Note:** This phase is an **export-file integration**, NOT a live connected Wazuh instance. No API keys or cloud services are needed.

## How the automation works

```text
Synthetic Wazuh-style JSONL OR exported Wazuh alerts.json
       ↓
Validate alert IDs / timestamps / source IPs
       ↓
Filter by Wazuh rule level (default >= 7)
       ↓
[Demo only] Mock IoC context | [Export] No IoC enrichment
       ↓
Correlate same source IP, agent and rule in a 10-min window
       ↓
Create / update local SQLite incident tickets
       ↓
Generate CSV, JSON and static HTML report
```

## Limitations

- No live Wazuh API / manager connection; no real Shuffle, TheHive, AbuseIPDB, VirusTotal integration.
- Basic Wazuh fields only; events without source IP are excluded by design.
- Simple fixed rules and grouped incidents only, not a production incident response system.
- Synthetic fixtures are NOT evidence of real intrusions or real-world detection accuracy.
- No automatic blocking or active response (intentional safety limit).

## Resume description (accurate)

> SOC Automation & Incident Response (Python, SQLite) — Built a lightweight workflow for Wazuh-format alert ingestion (including exported JSONL), severity filtering, event correlation, local incident creation and HTML reporting. Tested with synthetic data; no live TheHive/Shuffle integration.

## Next phases (not yet implemented)

- Optional real threat intelligence lookups with API credentials stored in environment variables.
- Optional TheHive alerts/cases REST API integration (version-specific) with explicit test credentials and retry controls.
- Optional Shuffle SOAR workflow integration, if lab capacity permits.
