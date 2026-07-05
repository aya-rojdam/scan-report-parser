"""Parser for native .nessus (XML v2) exports.

A .nessus file contains one or more <ReportHost> elements, each with
<ReportItem> children carrying the plugin results. Severity is encoded
as an integer attribute (0=Info .. 4=Critical); score and metadata live
in child elements that may or may not be present.
"""
import xml.etree.ElementTree as ET
from .model import Finding

SEVERITY_INT_MAP = {
    "4": "Critical",
    "3": "High",
    "2": "Medium",
    "1": "Low",
    "0": "Info",
}

CVSS_TAGS = ["cvss4_base_score", "cvss3_base_score", "cvss_base_score"]


def _child_float(item: ET.Element, tag: str) -> float | None:
    el = item.find(tag)
    if el is None or el.text is None:
        return None
    try:
        return float(el.text.strip())
    except ValueError:
        return None


def _child_text(item: ET.Element, tag: str) -> str:
    el = item.find(tag)
    return el.text.strip() if el is not None and el.text else ""


def parse_nessus(path: str) -> list[Finding]:
    findings: list[Finding] = []
    tree = ET.parse(path)
    root = tree.getroot()

    for host in root.iter("ReportHost"):
        host_name = host.get("name", "")
        for item in host.iter("ReportItem"):
            cvss = None
            for tag in CVSS_TAGS:
                cvss = _child_float(item, tag)
                if cvss is not None:
                    break

            cves = [el.text.strip() for el in item.findall("cve") if el.text]

            findings.append(Finding(
                plugin_id=item.get("pluginID", ""),
                name=item.get("pluginName", ""),
                severity=SEVERITY_INT_MAP.get(item.get("severity", "0"), "Info"),
                host=host_name,
                port=item.get("port", ""),
                protocol=item.get("protocol", ""),
                cvss=cvss,
                vpr=_child_float(item, "vpr_score"),
                epss=_child_float(item, "epss_score"),
                cves=cves,
                solution=_child_text(item, "solution"),
            ))
    return findings
