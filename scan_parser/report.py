"""Output formats for prioritized, consolidated findings."""
import csv
from datetime import date, timedelta
from .model import ConsolidatedFinding, SEVERITY_ORDER
from .prioritize import PriorityAssignment

Prioritized = list[tuple[ConsolidatedFinding, PriorityAssignment]]


def _due(scan_date: date, sla_hours: int) -> str:
    return (scan_date + timedelta(hours=sla_hours)).isoformat()


def summary(prioritized: Prioritized, raw_count: int) -> str:
    sev_counts = {s: 0 for s in SEVERITY_ORDER}
    tier_counts: dict[tuple[str, int], int] = {}
    tier_labels: dict[tuple[str, int], str] = {}
    for c, p in prioritized:
        sev_counts[c.severity] += 1
        key = (p.priority, p.sla_hours)
        tier_counts[key] = tier_counts.get(key, 0) + 1
        tier_labels[key] = p.sla_str + (f", {p.label}" if p.label else "")

    lines = [
        f"Raw scanner rows : {raw_count}",
        f"Unique findings  : {len(prioritized)}"
        + (f"  ({100 - round(len(prioritized) / raw_count * 100)}% consolidation)" if raw_count else ""),
        "",
        "  Priority breakdown:",
    ]
    for key in sorted(tier_counts):
        prio, _ = key
        lines.append(f"    {prio}  {tier_counts[key]:>3}  (SLA {tier_labels[key]})")
    lines.append("")
    lines.append("  Severity breakdown:")
    for sev in SEVERITY_ORDER:
        lines.append(f"    {sev:<8} {sev_counts[sev]}")
    return "\n".join(lines)


def top_table(prioritized: Prioritized, scan_date: date, limit: int = 10) -> str:
    """Human-readable table of the highest-priority findings."""
    if not prioritized:
        return "No findings match the current filter."
    rows = prioritized if limit <= 0 else prioritized[:limit]
    name_width = min(max(len(c.name) for c, _ in rows), 52)
    lines = [
        f"Top {len(rows)} findings (scan date {scan_date.isoformat()}):",
        f"  {'PRIO':<5} {'DUE':<11} {'SEVERITY':<9} {'CVSS':>5} {'VPR':>5} {'EPSS':>6} {'HITS':>4}  NAME",
    ]
    for c, p in rows:
        cvss = f"{c.cvss:.1f}" if c.cvss is not None else "-"
        vpr = f"{c.vpr:.1f}" if c.vpr is not None else "-"
        epss = f"{c.epss:.2f}" if c.epss is not None else "-"
        name = c.name if len(c.name) <= name_width else c.name[: name_width - 3] + "..."
        lines.append(
            f"  {p.priority:<5} {_due(scan_date, p.sla_hours):<11} {c.severity:<9}"
            f" {cvss:>5} {vpr:>5} {epss:>6} {c.occurrences:>4}  {name}"
        )
    if limit > 0 and len(prioritized) > limit:
        lines.append(f"  ... and {len(prioritized) - limit} more (use --top 0 to show all, or see the CSV/Markdown output)")
    return "\n".join(lines)


def to_csv(prioritized: Prioritized, path: str, scan_date: date) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "Priority", "SLA", "Due Date", "Severity", "CVSS", "VPR", "EPSS",
            "Plugin ID", "Name", "CVEs", "Occurrences", "Affected Locations", "Solution",
        ])
        for c, p in prioritized:
            writer.writerow([
                p.priority,
                p.sla_str,
                _due(scan_date, p.sla_hours),
                c.severity,
                c.cvss if c.cvss is not None else "",
                c.vpr if c.vpr is not None else "",
                c.epss if c.epss is not None else "",
                c.plugin_id,
                c.name,
                ", ".join(c.cves),
                c.occurrences,
                "; ".join(c.locations),
                c.solution,
            ])


def to_markdown(prioritized: Prioritized, path: str, scan_date: date) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# Consolidated Vulnerability Report\n\n")
        fh.write(f"Scan date: {scan_date.isoformat()}\n\n")
        fh.write("| Priority | Due | Severity | CVSS | Finding | Occurrences |\n")
        fh.write("|----------|-----|----------|------|---------|-------------|\n")
        for c, p in prioritized:
            cvss = c.cvss if c.cvss is not None else "-"
            fh.write(f"| {p.priority} | {_due(scan_date, p.sla_hours)} | {c.severity} | {cvss} | {c.name} | {c.occurrences} |\n")
        fh.write("\n")
        for c, p in prioritized:
            fh.write(f"## [{p.priority} / {c.severity}] {c.name}\n\n")
            fh.write(f"- **Priority:** {p.priority} ({p.label}) - remediate within {p.sla_str} (due {_due(scan_date, p.sla_hours)})\n")
            fh.write(f"- **Plugin ID:** {c.plugin_id}\n")
            if c.cvss is not None:
                fh.write(f"- **CVSS:** {c.cvss}\n")
            if c.vpr is not None:
                fh.write(f"- **VPR:** {c.vpr}\n")
            if c.epss is not None:
                fh.write(f"- **EPSS:** {c.epss}\n")
            if c.cves:
                fh.write(f"- **CVEs:** {', '.join(c.cves)}\n")
            fh.write(f"- **Affected ({c.occurrences}):** {'; '.join(c.locations)}\n")
            if c.solution:
                fh.write(f"- **Solution:** {c.solution}\n")
            fh.write("\n")
