"""CLI utility to export a sanitized JSON or CSV evidence report from the database."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.db.session import SessionLocal
from app.services.report_service import build_csv_report, build_json_report


def main() -> int:
    """Export a sanitized evidence report to stdout or a file."""
    parser = argparse.ArgumentParser(description="Export sanitized FaceTrust Auditor evidence report.")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format")
    parser.add_argument("--run-id", default=None, help="Optional evaluation run ID filter (JSON only)")
    parser.add_argument("--output", default=None, help="Optional output file path")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        if args.format == "csv":
            data = build_csv_report(db).decode("utf-8")
        else:
            report = build_json_report(db, run_id=args.run_id)
            data = json.dumps(report, indent=2, ensure_ascii=True)
    finally:
        db.close()

    if args.output:
        Path(args.output).write_text(data, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        sys.stdout.write(data + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
