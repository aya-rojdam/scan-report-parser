"""Parser for Nessus / Tenable WAS CSV exports.

Handles schema variants: Tenable CSV exports differ depending on the
columns selected at export time. A minimal export has 13 columns; an
extended one can include CVSS v3/v4, VPR, EPSS, exploit framework flags,
and more. Every column beyond the core set is treated as optional.
"""
import csv
from .model import Finding

# Risk column value -> normalized severity ("" / "None" = informational)
RISK_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "none": "Info",
    "": "Info",
}

# Preference order for the CVSS score to report
CVSS_COLUMNS = [
    "CVSS v4.0 Base Score",
    "CVSS v3.0 Base Score",
    "CVSS v2.0 Base Score",
]


def _to_float(value: str | None) -> float | None:
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def parse_csv(path: str) -> list[Finding]:
    """Dispatch on the CSV schema.

    Two Tenable CSV families exist:
      - Nessus / WAS detailed exports: one row per finding per host,
        headers include "Plugin ID" and "Risk"
      - Security Center summary exports: one row per plugin with
        pre-aggregated counts, headers include "Plugin" and "Plugin Name"
    """
    with open(path, newline="", encoding="utf-8-sig") as fh:
        header = next(csv.reader(fh), [])
    if "Plugin ID" in header:
        return _parse_detailed(path)
    if "Plugin" in header and "Plugin Name" in header:
        return _parse_sc_summary(path)
    raise ValueError(
        f"Unrecognized CSV schema in {path}. "
        f"Expected a Nessus/WAS detailed export ('Plugin ID' column) "
        f"or a Tenable SC summary export ('Plugin'/'Plugin Name' columns). "
        f"Found columns: {', '.join(header[:8])}..."
    )


def _parse_sc_summary(path: str) -> list[Finding]:
    """Tenable Security Center vulnerability summary export.

    Pre-aggregated: no host/port detail, 'Total' carries the occurrence
    count. Severity is a direct label. EPSS is expressed as a percentage
    (0-100) in SC exports, unlike the 0-1 probability in Nessus exports,
    so it is normalized here.
    """
    findings: list[Finding] = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            severity = (row.get("Severity") or "Info").strip()
            if severity.lower() not in {"critical", "high", "medium", "low", "info"}:
                severity = "Info"
            else:
                severity = severity.capitalize()
                if severity == "Info":
                    severity = "Info"

            epss = _to_float(row.get("EPSS"))
            if epss is not None and epss > 1:
                epss = epss / 100.0  # SC exports EPSS as a percentage

            total = _to_float(row.get("Total"))

            findings.append(Finding(
                plugin_id=(row.get("Plugin") or "").strip(),
                name=(row.get("Plugin Name") or "").strip(),
                severity=severity,
                host="",  # summary export carries no host detail
                vpr=_to_float(row.get("VPR")),
                epss=epss,
                count=int(total) if total else 1,
            ))
    return findings


def _parse_detailed(path: str) -> list[Finding]:
    findings: list[Finding] = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            risk = (row.get("Risk") or "").strip().lower()
            severity = RISK_MAP.get(risk, "Info")

            cvss = None
            for col in CVSS_COLUMNS:
                cvss = _to_float(row.get(col))
                if cvss is not None:
                    break

            cve_raw = (row.get("CVE") or "").strip()
            cves = [c.strip() for c in cve_raw.split(",") if c.strip()] if cve_raw else []

            findings.append(Finding(
                plugin_id=(row.get("Plugin ID") or "").strip(),
                name=(row.get("Name") or "").strip(),
                severity=severity,
                host=(row.get("Host") or "").strip(),
                port=(row.get("Port") or "").strip(),
                protocol=(row.get("Protocol") or "").strip(),
                cvss=cvss,
                vpr=_to_float(row.get("VPR Score")),
                epss=_to_float(row.get("EPSS Score")),
                cves=cves,
                solution=(row.get("Solution") or "").strip(),
            ))
    return findings
