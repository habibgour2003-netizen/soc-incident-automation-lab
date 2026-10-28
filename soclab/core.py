"""Local security event -> incident automation prototype (offline, Python stdlib)."""
from __future__ import annotations

import csv
import hashlib
import html
import ipaddress
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

# Intentionally MOCK reputation, never a claim about any real IP address.
MOCK_REPUTATION = {
    "203.0.113.50": {"score": 85, "classification": "Lab-only suspicious SSH activity"},
    "198.51.100.70": {"score": 60, "classification": "Lab-only suspicious authentication activity"},
}
SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  agent_name TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  rule_description TEXT NOT NULL,
  severity TEXT NOT NULL,
  reputation_score INTEGER,
  reputation_note TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  event_count INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'NEW'
);
CREATE TABLE IF NOT EXISTS processed_events (
  event_id TEXT PRIMARY KEY,
  incident_id INTEGER NOT NULL,
  FOREIGN KEY(incident_id) REFERENCES incidents(id)
);
"""


def parse_time(raw: str) -> datetime:
    if not isinstance(raw, str):
        raise ValueError("timestamp must be an ISO-8601 string")
    when = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if when.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return when.astimezone(timezone.utc)


def normalize_event(raw: dict) -> dict:
    rule = raw["rule"]
    agent = raw["agent"]
    event_id = str(raw["id"])
    if not event_id.strip():
        raise ValueError("Missing alert id")
    when = parse_time(raw["timestamp"])
    data = raw.get("data") or {}
    if not isinstance(data, dict):
        raise ValueError("data field should be an object")
    win = data.get("win") or {}
    win_events = win.get("eventdata") or {} if isinstance(win, dict) else {}
    # Wazuh Windows event 4625 uses ipAddress, Linux sshd typically uses srcip.
    source_ip = (data.get("srcip") or data.get("src_ip") or
                 win_events.get("ipAddress") or raw.get("srcip"))
    # SOC rules without a source IP are ignored in this deliberately narrow demo.
    if not source_ip:
        raise ValueError("Missing data.srcip")
    ipaddress.ip_address(source_ip)
    return {
        "event_id": event_id,
        "timestamp": when,
        "rule_id": str(rule["id"]),
        "rule_level": int(rule["level"]),
        "rule_description": str(rule.get("description", "Security alert")),
        "agent_id": str(agent["id"]),
        "agent_name": str(agent.get("name", "unknown")),
        "source_ip": source_ip,
    }


def severity(event: dict, reputation: dict) -> str:
    if event["rule_level"] >= 10 or reputation["score"] >= 80:
        return "HIGH"
    return "MEDIUM"


def fingerprint(event: dict) -> str:
    label = "|".join([event["rule_id"], event["agent_id"], event["source_ip"]])
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def process_file(input_file: Path, db_file: Path, min_rule_level: int = 7, dedup_minutes: int = 10, mock_context: bool = True) -> dict:
    """Import exported Wazuh-shaped JSONL; group matching events into local incidents."""
    if min_rule_level < 0 or dedup_minutes <= 0:
        raise ValueError("Thresholds must be positive")
    db_file.parent.mkdir(parents=True, exist_ok=True)
    stats = {"read": 0, "accepted": 0, "below_threshold": 0, "invalid": 0, "duplicate_event": 0, "created": 0, "grouped": 0}
    with closing(sqlite3.connect(db_file)) as conn:
        conn.executescript(SCHEMA)
        conn.execute("PRAGMA foreign_keys=ON")
        # transaction rollback on unexpected errors
        with conn:
            for line_no, line in enumerate(input_file.read_text(encoding="utf-8").splitlines(), start=1):
                if not line.strip():
                    continue
                stats["read"] += 1
                try:
                    event = normalize_event(json.loads(line))
                except (KeyError, ValueError, TypeError, json.JSONDecodeError):
                    stats["invalid"] += 1
                    continue
                if event["rule_level"] < min_rule_level:
                    stats["below_threshold"] += 1
                    continue
                if conn.execute("SELECT 1 FROM processed_events WHERE event_id=?", (event["event_id"],)).fetchone():
                    stats["duplicate_event"] += 1
                    continue
                # Exported Wazuh alerts must never receive made-up IP threat scores.
                rep = (MOCK_REPUTATION.get(event["source_ip"], {"score": 0, "classification": "No offline reputation data"})
                       if mock_context else {"score": None, "classification": "Not queried (offline real-log import)"})
                level = severity(event, {"score": rep["score"] or 0})
                fp = fingerprint(event)
                iso = event["timestamp"].isoformat()
                candidates = conn.execute("""SELECT id, last_seen, severity FROM incidents
                    WHERE fingerprint=? ORDER BY last_seen DESC""", (fp,)).fetchall()
                incident_id = None
                for case_id, last_seen, prior_severity in candidates:
                    age = (event["timestamp"] - parse_time(last_seen)).total_seconds()
                    if 0 <= age <= 60 * dedup_minutes:
                        incident_id = case_id
                        conn.execute("UPDATE incidents SET last_seen=?, event_count=event_count+1, severity=? WHERE id=?",
                                     (iso, "HIGH" if "HIGH" in (prior_severity, level) else "MEDIUM", incident_id))
                        stats["grouped"] += 1
                        break
                if incident_id is None:
                    cursor = conn.execute("""INSERT INTO incidents
                        (fingerprint,source_ip,agent_name,rule_id,rule_description,severity,reputation_score,reputation_note,first_seen,last_seen)
                        VALUES (?,?,?,?,?,?,?,?,?,?)""",
                        (fp,event["source_ip"],event["agent_name"],event["rule_id"],event["rule_description"],
                         level,rep["score"],rep["classification"],iso,iso))
                    incident_id = cursor.lastrowid
                    stats["created"] += 1
                conn.execute("INSERT INTO processed_events (event_id,incident_id) VALUES (?,?)", (event["event_id"],incident_id))
                stats["accepted"] += 1
    return stats


def read_incidents(db_file: Path) -> list[dict]:
    if not db_file.exists():
        raise FileNotFoundError(f"Database missing: {db_file}. Run 'run' first.")
    with closing(sqlite3.connect(db_file)) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute("""SELECT id,source_ip,agent_name,rule_id,rule_description,
            severity,reputation_score,reputation_note,first_seen,last_seen,event_count,status
            FROM incidents ORDER BY CASE severity WHEN 'HIGH' THEN 0 ELSE 1 END, last_seen DESC""")]


def export_results(db_file: Path, out_dir: Path, stats: dict | None = None, mock_context: bool = True) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    cases = read_incidents(db_file)
    with (out_dir / "incidents.json").open("w", encoding="utf-8") as f:
        json.dump(cases, f, indent=2, ensure_ascii=False)
    with (out_dir / "incidents.csv").open("w", encoding="utf-8", newline="") as f:
        if cases:
            writer = csv.DictWriter(f, fieldnames=cases[0].keys())
            writer.writeheader()
            writer.writerows(cases)
    if stats is not None:
        (out_dir / "execution_summary.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    rows = "\n".join(
        "<tr>" + "".join(f"<td>{html.escape(str(case[col]))}</td>" for col in
        ("id", "source_ip", "agent_name", "rule_description", "severity", "reputation_score", "event_count", "status")) + "</tr>"
        for case in cases
    )
    high = sum(c["severity"] == "HIGH" for c in cases)
    events = sum(c["event_count"] for c in cases)
    description = ("Wazuh-style SYNTHETIC JSON alerts → Filtering → Mock IOC context → Local incidents"
                   if mock_context else "Exported Wazuh JSON alerts → Filtering → No external IOC enrichment → Local incidents")
    disclaimer = ("Events, IP context and reputation scores are synthetic / mock only. "
                  "No real Wazuh, TheHive, Shuffle, VirusTotal or AbuseIPDB API is connected in Phase 1."
                  if mock_context else "Imported alerts may be real and sensitive: keep this report private. "
                  "Reputation was NOT looked up; no TheHive, Shuffle, VirusTotal or AbuseIPDB API is connected.")
    report = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SOC Incident Automation — Local Lab</title><style>
*{{box-sizing:border-box}}body{{font-family:system-ui,Segoe UI,Arial;background:#091424;color:#e8eff7;margin:0;padding:40px}}
main{{max-width:1200px;margin:auto}}header{{border-bottom:1px solid #294057;padding-bottom:22px}}
h1{{font-size:34px;margin:8px 0}}p{{color:#9fb5c9}}.tag{{color:#51debf;letter-spacing:2px;font-size:12px;font-weight:bold}}
.cards{{display:flex;gap:16px;flex-wrap:wrap;margin:30px 0}}.card{{background:#122438;border:1px solid #284158;border-radius:12px;padding:22px;min-width:190px;flex:1}}
.num{{font-size:32px;font-weight:700}}.label{{color:#99b2c8;font-size:14px}}table{{border-collapse:collapse;width:100%;font-size:14px;overflow:hidden}}
th,td{{padding:14px;border-bottom:1px solid #254058;text-align:left}}th{{color:#8cd1ed;background:#172c43}}tr:hover{{background:#19324a}}
.diagram{{display:flex;gap:10px;flex-wrap:wrap;margin:20px 0 34px}}.step{{padding:12px 18px;border:1px solid #29627c;border-radius:9px;background:#102c41}}
.notice{{padding:18px;border:1px solid #88692f;background:#292517;border-radius:10px;color:#e5c889;margin-top:30px}}
</style></head><body><main><header><div class="tag">DEFENSIVE SECURITY ENGINEERING • OFFLINE PROTOTYPE</div>
<h1>Incident Automation Lab</h1><p>{html.escape(description)}</p></header>
<div class="cards"><div class="card"><div class="num">{len(cases)}</div><div class="label">Incidents</div></div>
<div class="card"><div class="num">{high}</div><div class="label">High severity</div></div>
<div class="card"><div class="num">{events}</div><div class="label">Correlated alerts</div></div></div>
<h2>Automation flow</h2><div class="diagram"><div class="step">1. Ingest Wazuh JSONL</div><div class="step">→ 2. Filter rules</div>
<div class="step">→ 3. {'Mock IOC enrichment' if mock_context else 'No IOC lookups'}</div><div class="step">→ 4. Correlate / deduplicate</div><div class="step">→ 5. Create local incidents</div></div>
<h2>Incident queue</h2><table><thead><tr><th>Case</th><th>Source IP</th><th>Agent</th><th>Detection</th><th>Severity</th><th>Mock score</th><th>Events</th><th>Status</th></tr></thead>
<tbody>{rows}</tbody></table>
<div class="notice"><strong>Important:</strong> {html.escape(disclaimer)} This is not a production SOC and does not establish real-world detection performance.</div>
</main></body></html>"""
    target = out_dir / "report.html"
    target.write_text(report, encoding="utf-8")
    return target
