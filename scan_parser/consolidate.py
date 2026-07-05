"""Consolidation: collapse raw scanner rows into unique findings.

Scanner exports repeat the same vulnerability once per affected
host/port/URL. Reporting works the other way around: one finding, a list
of affected locations. Grouping key is (plugin_id, name); scores are
aggregated with max() so the consolidated finding reflects the worst
observed instance.
"""
from collections import defaultdict
from .model import Finding, ConsolidatedFinding


def _max_optional(values: list[float | None]) -> float | None:
    present = [v for v in values if v is not None]
    return max(present) if present else None


def consolidate(findings: list[Finding]) -> list[ConsolidatedFinding]:
    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        groups[(f.plugin_id, f.name)].append(f)

    consolidated: list[ConsolidatedFinding] = []
    for (plugin_id, name), items in groups.items():
        # Worst severity across occurrences (lowest rank = most severe)
        worst = min(items, key=lambda f: f.severity_rank)
        locations = sorted({f.location for f in items if f.location})
        cves = sorted({c for f in items for c in f.cves})
        consolidated.append(ConsolidatedFinding(
            plugin_id=plugin_id,
            name=name,
            severity=worst.severity,
            cvss=_max_optional([f.cvss for f in items]),
            vpr=_max_optional([f.vpr for f in items]),
            epss=_max_optional([f.epss for f in items]),
            cves=cves,
            solution=worst.solution,
            locations=locations,
            occurrences=sum(f.count for f in items),
        ))

    # Sort: severity first, then CVSS descending, then name
    consolidated.sort(key=lambda c: (c.severity_rank, -(c.cvss or 0), c.name))
    return consolidated


def filter_min_severity(
    consolidated: list[ConsolidatedFinding], min_severity: str
) -> list[ConsolidatedFinding]:
    from .model import SEVERITY_ORDER
    threshold = SEVERITY_ORDER.index(min_severity)
    return [c for c in consolidated if c.severity_rank <= threshold]
