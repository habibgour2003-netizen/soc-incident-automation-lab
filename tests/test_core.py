import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from soclab.core import process_file, read_incidents, export_results, normalize_event, MOCK_REPUTATION

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "data" / "sample_wazuh_alerts.jsonl"


class SOCWorkflowTests(unittest.TestCase):
    def test_grouping_and_filtering(self):
        with tempfile.TemporaryDirectory() as root:
            db = Path(root) / "cases.db"
            stats = process_file(SAMPLE, db)
            cases = read_incidents(db)
            self.assertEqual(stats["read"], 6)
            self.assertEqual(stats["below_threshold"], 2)
            self.assertEqual(stats["created"], 2)
            self.assertEqual(stats["grouped"], 2)
            self.assertEqual(len(cases), 2)
            self.assertEqual(sum(c["event_count"] for c in cases), 4)

    def test_idempotent_import(self):
        with tempfile.TemporaryDirectory() as root:
            db = Path(root) / "cases.db"
            process_file(SAMPLE, db)
            stats = process_file(SAMPLE, db)
            self.assertEqual(stats["duplicate_event"], 4)
            self.assertEqual(stats["created"], 0)
            self.assertEqual(len(read_incidents(db)), 2)

    def test_reports_and_schema(self):
        with tempfile.TemporaryDirectory() as root:
            out = Path(root)
            db = out / "db.sqlite"
            stats = process_file(SAMPLE, db)
            path = export_results(db, out / "reports", stats)
            self.assertTrue(path.is_file())
            self.assertIn("Mock IOC enrichment", path.read_text(encoding="utf-8"))
            self.assertEqual(len(json.loads((out / "reports" / "incidents.json").read_text())), 2)

    def test_invalid_events_skipped(self):
        with tempfile.TemporaryDirectory() as root:
            infile = Path(root) / "bad.jsonl"
            infile.write_text('{invalid json}\n' + SAMPLE.read_text(encoding='utf-8'), encoding="utf-8")
            stats = process_file(infile, Path(root) / "cases.db")
            self.assertEqual(stats["invalid"], 1)
            self.assertEqual(stats["accepted"], 4)

    def test_missing_timezone_rejected(self):
        sample = json.loads(SAMPLE.read_text(encoding="utf-8").splitlines()[0])
        sample["timestamp"] = "2026-10-27T18:00:00"
        with self.assertRaises(ValueError):
            normalize_event(sample)

    def test_no_network_dependency(self):
        self.assertIn("203.0.113.50", MOCK_REPUTATION)
        self.assertNotIn("8.8.8.8", MOCK_REPUTATION)

    def test_imported_real_format_disables_mock_reputation(self):
        """A real exported log cannot acquire an artificial reputation score."""
        with tempfile.TemporaryDirectory() as root:
            db = Path(root) / "real.db"
            sample = json.loads(SAMPLE.read_text(encoding="utf-8").splitlines()[0])
            infile = Path(root) / "export.json"
            infile.write_text(json.dumps(sample) + "\n", encoding="utf-8")
            stats = process_file(infile, db, mock_context=False)
            self.assertEqual(stats["accepted"], 1)
            cases = read_incidents(db)
            self.assertIsNone(cases[0]["reputation_score"])
            self.assertIn("Not queried", cases[0]["reputation_note"])
            path = export_results(db, Path(root) / "out", stats, mock_context=False)
            self.assertIn("keep this report private", path.read_text(encoding="utf-8"))
            self.assertNotIn("Mock IOC context", path.read_text(encoding="utf-8"))

    def test_windows_ip_address_compatible(self):
        example = {"id": "windemo1", "timestamp": "2026-10-27T18:00:00Z",
                   "rule": {"id": "60122", "level": 10, "description": "Failed logon"},
                   "agent": {"id": "002", "name": "lab-win"},
                   "data": {"win": {"eventdata": {"ipAddress": "198.51.100.42"}}}}
        self.assertEqual(normalize_event(example)["source_ip"], "198.51.100.42")

    def test_closed_db_windows_tempfile(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "result.db"
            process_file(SAMPLE, path)
            self.assertEqual(len(read_incidents(path)), 2)
            path.unlink()  # fails on Windows if SQLite connections are leaked
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
