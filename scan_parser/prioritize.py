"""Priority matrix: classify consolidated findings into P1-P4 with SLAs.

The matrix is rule-based and configurable. Rules are evaluated in order;
the first matching rule assigns the priority. Each rule can test:

    severity  - list of severity labels
    min_cvss  - CVSS greater than or equal
    min_vpr   - VPR greater than or equal
    min_epss  - EPSS greater than or equal

combined with "match": "all" (every stated condition) or "any" (at least
one). Missing scores never satisfy a threshold condition.

The default matrix below is a reasonable risk-based policy: exploitation
likelihood (EPSS) and Tenable's threat-informed VPR escalate beyond raw
CVSS. Override it with your organization's own matrix via --policy.
"""
import json
from dataclasses import dataclass
from .model import ConsolidatedFinding

# SLAs are graduated WITHIN priority classes: two P1 findings can carry
# different deadlines depending on exploitation likelihood. Rules are
# evaluated top-down, most urgent first; each rule sets its own SLA
# (sla_hours or sla_days).
DEFAULT_POLICY = {
    "rules": [
        {
            "priority": "P1", "sla_hours": 24, "label": "Emergency",
            "match": "all", "min_epss": 0.9,
        },
        {
            "priority": "P1", "sla_hours": 72, "label": "Critical threat",
            "match": "any", "min_vpr": 9.0, "min_epss": 0.5,
        },
        {
            "priority": "P1", "sla_days": 7, "label": "Immediate",
            "match": "all", "severity": ["Critical"], "min_vpr": 7.0,
        },
        {
            "priority": "P2", "sla_days": 30, "label": "Urgent",
            "match": "any", "severity": ["Critical"], "min_vpr": 7.0, "min_epss": 0.1,
        },
        {
            "priority": "P3", "sla_days": 90, "label": "Planned",
            "match": "any", "severity": ["High", "Medium"],
        },
    ],
    "default": {"priority": "P4", "sla_days": 180, "label": "Best effort"},
}


@dataclass
class PriorityAssignment:
    priority: str
    sla_hours: int
    label: str

    @property
    def sla_days(self) -> float:
        return self.sla_hours / 24

    @property
    def sla_str(self) -> str:
        """Human display: hours below 72h, days above."""
        if self.sla_hours < 72:
            return f"{self.sla_hours}h"
        return f"{self.sla_hours // 24}d"


def _rule_sla_hours(rule: dict) -> int:
    if "sla_hours" in rule:
        return int(rule["sla_hours"])
    if "sla_days" in rule:
        return int(rule["sla_days"]) * 24
    raise ValueError(f"Rule missing sla_hours/sla_days: {rule}")


def load_policy(path: str | None) -> dict:
    if path is None:
        return DEFAULT_POLICY
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _conditions(rule: dict, finding: ConsolidatedFinding) -> list[bool]:
    checks: list[bool] = []
    if "severity" in rule:
        checks.append(finding.severity in rule["severity"])
    if "min_cvss" in rule:
        checks.append(finding.cvss is not None and finding.cvss >= rule["min_cvss"])
    if "min_vpr" in rule:
        checks.append(finding.vpr is not None and finding.vpr >= rule["min_vpr"])
    if "min_epss" in rule:
        checks.append(finding.epss is not None and finding.epss >= rule["min_epss"])
    return checks


def assign_priority(finding: ConsolidatedFinding, policy: dict) -> PriorityAssignment:
    for rule in policy["rules"]:
        checks = _conditions(rule, finding)
        if not checks:
            continue
        matched = all(checks) if rule.get("match", "all") == "all" else any(checks)
        if matched:
            return PriorityAssignment(rule["priority"], _rule_sla_hours(rule), rule.get("label", ""))
    d = policy["default"]
    return PriorityAssignment(d["priority"], _rule_sla_hours(d), d.get("label", ""))


def prioritize(
    consolidated: list[ConsolidatedFinding], policy: dict
) -> list[tuple[ConsolidatedFinding, PriorityAssignment]]:
    """Assign priorities and sort by priority, then CVSS descending."""
    assigned = [(c, assign_priority(c, policy)) for c in consolidated]
    assigned.sort(key=lambda pair: (
        pair[1].priority, pair[1].sla_hours, pair[0].severity_rank, -(pair[0].cvss or 0)
    ))
    return assigned
