"""Normalized data model shared by all input parsers."""
from dataclasses import dataclass, field

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


@dataclass
class Finding:
    """A single scanner result row/item, normalized across input formats."""
    plugin_id: str
    name: str
    severity: str          # Critical / High / Medium / Low / Info
    host: str
    port: str = ""
    protocol: str = ""
    cvss: float | None = None   # best available: v4 > v3 > v2
    vpr: float | None = None
    epss: float | None = None
    cves: list[str] = field(default_factory=list)
    solution: str = ""
    count: int = 1   # occurrence count (SC summary exports pre-aggregate)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.index(self.severity)

    @property
    def location(self) -> str:
        # WAS exports put a full URL in Host (port already included);
        # network scans put a bare IP/hostname there.
        if "://" in self.host or self.host.endswith(f":{self.port}"):
            return self.host
        if self.port and self.port not in ("", "0"):
            return f"{self.host}:{self.port}"
        return self.host


@dataclass
class ConsolidatedFinding:
    """One unique vulnerability, aggregated across all its occurrences."""
    plugin_id: str
    name: str
    severity: str
    cvss: float | None
    vpr: float | None
    epss: float | None
    cves: list[str]
    solution: str
    locations: list[str]
    occurrences: int

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.index(self.severity)
