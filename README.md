# scan-report-parser

Consolidate Tenable and Nessus vulnerability scan exports into prioritized, report-ready findings.

Scanner exports repeat every vulnerability once per affected host, port, or URL. The result is hundreds of rows for what is actually a few dozen distinct issues. This tool parses raw exports, deduplicates findings across occurrences, keeps the worst observed score per finding, and outputs a severity-sorted report. On real lab scan data: **317 raw rows → 93 unique findings (71% reduction)**.

Pure Python standard library. No dependencies.

## Usage

```
# Merge everything into one prioritized report
python -m scan_parser scan1.csv scan2.nessus -o report.csv

# One prioritization report per input, auto-named
# (writes prioritization_report_<input>.csv and .md for each)
python -m scan_parser vuln-m1.csv vuln-m2.csv --per-report --outdir reports/

# Filter and show the full table in the terminal
python -m scan_parser scan.csv --min-severity Medium --top 0
```

Two modes:

- **Merged** (default): all inputs consolidate into a single prioritized list. Answers "what does the organization fix first."
- **Per-report** (`--per-report`): each input gets its own P1-P4 breakdown and its own auto-named output files. Answers "what does the owner of each machine or application fix first." Useful when different teams own different scan scopes.

```
Parsed   124 rows from WAS_scan_1.csv
Parsed   193 rows from WAS_scan_2.csv

Raw scanner rows : 317
Unique findings  : 93  (71% consolidation)

  Critical 20
  High     18
  Medium   22
  Low      9
  Info     24
```

## Supported inputs

| Format | Notes |
|--------|-------|
| Nessus / Tenable WAS **CSV** | Detailed exports, one row per finding per host. Handles export schema variants: column sets differ depending on export settings (13-column minimal to 29-column extended with VPR/EPSS/CVSS v4). Everything beyond the core columns is optional. |
| Tenable **Security Center** summary CSV | Pre-aggregated exports (Plugin / Plugin Name / Severity / VPR / EPSS / Total). Occurrence counts carry through consolidation. EPSS is normalized: SC exports it as a percentage, Nessus as a 0-1 probability. |
| Native **.nessus** (XML v2) | Per-host `ReportItem` parsing with severity, CVSS (v4 > v3 > v2 preference), VPR, EPSS, CVEs. |

Input format and CSV schema are auto-detected. Mixed inputs consolidate together: web app scan CSVs, SC summary exports, and network scan .nessus files merge into one report. Unrecognized CSV schemas fail loudly with the columns found, rather than silently producing an empty report. Additional scanner formats (Qualys, OpenVAS) are a matter of adding one parser module, since the data model and consolidation logic are format-agnostic.

## How consolidation works

1. Each input row/item is normalized into a common `Finding` model
2. Findings group by `(plugin ID, name)`
3. Per group: worst severity wins, scores aggregate with `max()`, affected locations collect into a list
4. Output sorts by severity, then CVSS descending

WAS findings are handled per-URL (the host field is a full URL), network findings per host:port.

## Prioritization matrix

Each consolidated finding is classified P1-P4 with a remediation SLA and a computed due date (`scan date + SLA`). The default matrix is risk-based: exploitation likelihood (EPSS) and threat-informed scoring (VPR) escalate beyond raw CVSS.

SLAs are graduated within priority classes: two P1 findings can carry different deadlines depending on exploitation likelihood. Rules evaluate top-down, most urgent first.

| Priority | SLA | Assigned when |
|----------|-----|---------------|
| P1 Emergency | 24 hours | EPSS >= 0.9 (exploitation near-certain) |
| P1 Critical threat | 72 hours | VPR >= 9, or EPSS >= 0.5 |
| P1 Immediate | 7 days | Critical with VPR >= 7 |
| P2 Urgent | 30 days | Critical, or VPR >= 7, or EPSS >= 0.1 |
| P3 Planned | 90 days | High or Medium |
| P4 Best effort | 180 days | Everything else |

Every finding gets an individual due date (`scan date + its SLA`), so the report reads "fix this by 2026-07-06", not "P1 means soon". Rules accept `sla_hours` or `sla_days`.

The matrix is a policy decision, not a formula. Override it with your organization's own thresholds via `--policy my_matrix.json` (rules evaluate in order, first match wins; see `scan_parser/prioritize.py` for the schema). Reference points: CISA BOD 19-02 mandates 15 days for critical and 30 for high; PCI DSS requires criticals fixed within 30 days.

Set the scan date for accurate due dates: `--scan-date 2026-07-01` (defaults to today).

## Output

- **CSV**: one row per unique finding with priority, SLA, due date, severity, CVSS/VPR/EPSS, CVEs, occurrence count, affected locations, solution
- **Markdown**: summary table plus a detail section per finding
- **Terminal**: severity breakdown, consolidation ratio, and a prioritized top-N findings table (`--top N`, default 10)

## Project layout

```
scan_parser/
├── model.py         # Normalized Finding / ConsolidatedFinding
├── nessus_csv.py    # CSV parser (schema-variant tolerant)
├── nessus_xml.py    # .nessus XML parser
├── consolidate.py   # Dedup and aggregation
├── prioritize.py    # P1-P4 matrix with SLAs (configurable)
├── report.py        # CSV / Markdown / terminal output
└── __main__.py      # CLI
samples/             # Synthetic test data (no real scan data is ever committed)
tests/               # pytest suite
```

## Tests

```
python -m pytest tests/
```

Test data is synthetic. Real scan exports contain internal hostnames, URLs, and vulnerability details, so they stay out of version control.

## Roadmap

- Direct Tenable API integration via pyTenable (pull scan results without manual export)
- Qualys and OpenVAS input parsers
- HTML report output
- Trend comparison between two scans (fixed / new / persisting findings)
