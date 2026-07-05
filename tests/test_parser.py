"""Tests run against the synthetic sample files in samples/."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scan_parser.nessus_csv import parse_csv
from scan_parser.nessus_xml import parse_nessus
from scan_parser.consolidate import consolidate, filter_min_severity

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")
CSV_SAMPLE = os.path.join(SAMPLES, "sample_was_scan.csv")
NESSUS_SAMPLE = os.path.join(SAMPLES, "sample_scan.nessus")


def test_csv_parses_rows():
    findings = parse_csv(CSV_SAMPLE)
    assert len(findings) > 0
    assert all(f.plugin_id for f in findings)


def test_csv_severity_normalization():
    findings = parse_csv(CSV_SAMPLE)
    severities = {f.severity for f in findings}
    # Empty Risk column must normalize to Info, never crash
    assert severities <= {"Critical", "High", "Medium", "Low", "Info"}
    assert "Info" in severities


def test_nessus_parses_hosts_and_items():
    findings = parse_nessus(NESSUS_SAMPLE)
    assert len(findings) == 4
    hosts = {f.host for f in findings}
    assert hosts == {"192.0.2.10", "192.0.2.20"}


def test_nessus_severity_mapping():
    findings = parse_nessus(NESSUS_SAMPLE)
    crit = [f for f in findings if f.severity == "Critical"]
    assert len(crit) == 1
    assert crit[0].cvss == 9.8
    assert crit[0].vpr == 8.9


def test_consolidation_dedupes():
    findings = parse_nessus(NESSUS_SAMPLE)
    consolidated = consolidate(findings)
    # 4 raw items, TLS finding appears on 2 hosts -> 3 unique findings
    assert len(consolidated) == 3
    tls = next(c for c in consolidated if "TLS" in c.name)
    assert tls.occurrences == 2


def test_consolidation_sorted_by_severity():
    findings = parse_nessus(NESSUS_SAMPLE)
    consolidated = consolidate(findings)
    ranks = [c.severity_rank for c in consolidated]
    assert ranks == sorted(ranks)
    assert consolidated[0].severity == "Critical"


def test_min_severity_filter():
    findings = parse_csv(CSV_SAMPLE)
    consolidated = consolidate(findings)
    high_up = filter_min_severity(consolidated, "High")
    assert all(c.severity in ("Critical", "High") for c in high_up)
    assert len(high_up) < len(consolidated)


def test_mixed_inputs_consolidate_together():
    findings = parse_csv(CSV_SAMPLE) + parse_nessus(NESSUS_SAMPLE)
    consolidated = consolidate(findings)
    assert len(consolidated) < len(findings)


def test_priority_assignment():
    from scan_parser.prioritize import load_policy, prioritize
    findings = parse_nessus(NESSUS_SAMPLE)
    prioritized = prioritize(consolidate(findings), load_policy(None))
    # The Critical RCE (CVSS 9.8, VPR 8.9) must land in P1 or P2, first in sort order
    first_finding, first_prio = prioritized[0]
    assert first_finding.severity == "Critical"
    assert first_prio.priority in ("P1", "P2")
    assert first_prio.sla_days <= 30
    # Priorities are sorted ascending (P1 before P4)
    prios = [p.priority for _, p in prioritized]
    assert prios == sorted(prios)


def test_custom_policy(tmp_path):
    import json
    from scan_parser.prioritize import load_policy, assign_priority
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({
        "rules": [
            {"priority": "P1", "sla_days": 15, "match": "all", "severity": ["Critical"]},
            {"priority": "P2", "sla_days": 30, "match": "all", "severity": ["High"]},
        ],
        "default": {"priority": "P3", "sla_days": 90},
    }))
    policy = load_policy(str(policy_file))
    findings = consolidate(parse_nessus(NESSUS_SAMPLE))
    crit = next(c for c in findings if c.severity == "Critical")
    assert assign_priority(crit, policy).sla_days == 15


def test_sc_summary_schema():
    findings = parse_csv(os.path.join(SAMPLES, "sample_sc_summary.csv"))
    assert len(findings) == 5
    kernel = next(f for f in findings if "Kernel" in f.name)
    assert kernel.severity == "High"
    assert kernel.count == 2
    # EPSS percentage must be normalized to 0-1
    assert kernel.epss is not None and 0 < kernel.epss <= 1
    assert abs(kernel.epss - 0.7631) < 1e-6


def test_sc_summary_occurrences_carry_through():
    findings = parse_csv(os.path.join(SAMPLES, "sample_sc_summary.csv"))
    consolidated = consolidate(findings)
    info = next(c for c in consolidated if "HTTP Server" in c.name)
    assert info.occurrences == 5


def test_unknown_csv_schema_raises(tmp_path):
    import pytest
    bad = tmp_path / "bad.csv"
    bad.write_text("Foo,Bar,Baz\n1,2,3\n")
    with pytest.raises(ValueError, match="Unrecognized CSV schema"):
        parse_csv(str(bad))
