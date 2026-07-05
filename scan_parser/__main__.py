"""CLI: parse scanner exports, consolidate, and report.

Usage:
    python -m scan_parser scan1.csv scan2.nessus -o report.csv
    python -m scan_parser scan.csv --min-severity Medium --markdown report.md
"""
import argparse
import sys
from datetime import date
from pathlib import Path
from .model import SEVERITY_ORDER
from .prioritize import load_policy, prioritize
from .nessus_csv import parse_csv
from .nessus_xml import parse_nessus
from .consolidate import consolidate, filter_min_severity
from .report import summary, top_table, to_csv, to_markdown


def parse_any(path: str):
    """Dispatch on file extension."""
    lower = path.lower()
    if lower.endswith(".nessus") or lower.endswith(".xml"):
        return parse_nessus(path)
    if lower.endswith(".csv"):
        return parse_csv(path)
    raise ValueError(f"Unsupported input format: {path} (expected .csv or .nessus)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scan_parser",
        description="Consolidate vulnerability scanner exports into a prioritized report.",
    )
    parser.add_argument("inputs", nargs="+", help="Input files (.csv or .nessus)")
    parser.add_argument("-o", "--output", help="Write consolidated report as CSV")
    parser.add_argument("--markdown", help="Write consolidated report as Markdown")
    parser.add_argument(
        "--min-severity", choices=SEVERITY_ORDER, default="Info",
        help="Drop findings below this severity (default: keep all)",
    )
    parser.add_argument(
        "--top", type=int, default=10, metavar="N",
        help="Number of findings shown in the terminal table (default: 10)",
    )
    parser.add_argument(
        "--policy", metavar="POLICY_JSON",
        help="Custom priority matrix (JSON). Default: built-in risk-based matrix",
    )
    parser.add_argument(
        "--scan-date", metavar="YYYY-MM-DD",
        help="Scan date used to compute SLA due dates (default: today)",
    )
    parser.add_argument(
        "--per-report", action="store_true",
        help="Prioritize each input separately: one P1-P4 section per input, "
             "with auto-named output files (prioritization_report_<input>.csv/.md)",
    )
    parser.add_argument(
        "--outdir", default=".", metavar="DIR",
        help="Directory for auto-named per-report outputs (default: current dir)",
    )
    args = parser.parse_args(argv)

    policy = load_policy(args.policy)
    scan_date = date.fromisoformat(args.scan_date) if args.scan_date else date.today()

    if args.per_report:
        outdir = Path(args.outdir)
        outdir.mkdir(parents=True, exist_ok=True)
        for path in args.inputs:
            items = parse_any(path)
            consolidated = filter_min_severity(consolidate(items), args.min_severity)
            prioritized = prioritize(consolidated, policy)
            stem = Path(path).stem
            print()
            print("=" * 70)
            print(f"Prioritization report: {stem}")
            print("=" * 70)
            print(summary(prioritized, len(items)))
            print()
            print(top_table(prioritized, scan_date, args.top))
            csv_path = outdir / f"prioritization_report_{stem}.csv"
            md_path = outdir / f"prioritization_report_{stem}.md"
            to_csv(prioritized, str(csv_path), scan_date)
            to_markdown(prioritized, str(md_path), scan_date)
            print(f"\nWritten: {csv_path}  |  {md_path}")
        return 0

    raw = []
    for path in args.inputs:
        items = parse_any(path)
        print(f"Parsed {len(items):>5} rows from {path}")
        raw.extend(items)

    consolidated = consolidate(raw)
    consolidated = filter_min_severity(consolidated, args.min_severity)
    prioritized = prioritize(consolidated, policy)

    print()
    print(summary(prioritized, len(raw)))
    print()
    print(top_table(prioritized, scan_date, args.top))

    if args.output:
        to_csv(prioritized, args.output, scan_date)
        print(f"\nCSV report written to {args.output}")
    if args.markdown:
        to_markdown(prioritized, args.markdown, scan_date)
        print(f"Markdown report written to {args.markdown}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
