"""Shared finding/severity types used by both the static heuristics pass and the report."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


@dataclass
class Finding:
    """A single observation, static or behavioral, feeding into the report."""

    category: str
    severity: Severity
    summary: str
    detail: str = ""
    source: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity.value,
            "summary": self.summary,
            "detail": self.detail,
            "source": self.source,
            "extra": self.extra,
        }
