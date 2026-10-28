"""Entry point: python -m soclab run ..."""
import argparse
import json
from pathlib import Path
from .core import process_file, export_results


def main():
    parser = argparse.ArgumentParser(description="Local SOC incident automation with safe Wazuh JSONL import")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for command in ("run", "import-wazuh"):
        cmd = sub.add_parser(command, help=("Run synthetic demonstration" if command == "run" else "Import local Wazuh alerts.json export with no network requests"))
        cmd.add_argument("--input", type=Path, default=(Path("data/sample_wazuh_alerts.jsonl") if command == "run" else None), required=(command == "import-wazuh"))
        cmd.add_argument("--db", type=Path, default=(Path("outputs/incidents.db") if command == "run" else Path("outputs/real-lab/incidents.db")))
        cmd.add_argument("--out", type=Path, default=(Path("outputs") if command == "run" else Path("outputs/real-lab")))
        cmd.add_argument("--min-level", type=int, default=7)
        cmd.add_argument("--dedup-minutes", type=int, default=10)
    args = parser.parse_args()
    mock_context = args.cmd == "run"
    if not args.input.is_file():
        parser.error(f"Input file not found: {args.input}")
    stats = process_file(args.input, args.db, args.min_level, args.dedup_minutes, mock_context=mock_context)
    html_file = export_results(args.db, args.out, stats, mock_context=mock_context)
    print(json.dumps(stats, indent=2))
    print(f"Report: {html_file.resolve()}")
    if args.cmd == "import-wazuh":
        print("No Wazuh service or external intelligence API was contacted.")
        print("The generated report can contain sensitive IPs, hostnames or alerts. Keep it private.")
    print("Use a NEW DB filename for a clean import; repeats are de-duplicated by alert ID.")


if __name__ == "__main__":
    main()
