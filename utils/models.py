"""
Core data models for scan findings and results.

Every scanner module returns a list of Finding objects. The orchestrator
collects them into a ScanResult that feeds scoring, storage, and reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Finding severity aligned with common SOC triage levels."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class ScanStatus(str, Enum):
    """Whether a check passed, failed, or needs attention."""

    PASS = "Pass"
    FAIL = "Fail"
    WARNING = "Warning"
    INFO = "Info"
    ERROR = "Error"


@dataclass
class Finding:
    """
    A single security check result.

    score_impact: points deducted from the 100-point baseline when status
    indicates a misconfiguration (typically FAIL or WARNING).
    """

    category: str
    title: str
    description: str
    severity: Severity
    status: ScanStatus
    recommendation: str
    evidence: str = ""
    score_impact: int = 0
    check_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["status"] = self.status.value
        return data


@dataclass
class ScanResult:
    """Complete output of a system security scan."""

    hostname: str
    findings: list[Finding] = field(default_factory=list)
    score: int = 100
    risk_level: str = "Secure"
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "scanned_at": self.scanned_at,
            "score": self.score,
            "risk_level": self.risk_level,
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "total": len(self.findings),
                "fail": sum(1 for f in self.findings if f.status == ScanStatus.FAIL),
                "warning": sum(
                    1 for f in self.findings if f.status == ScanStatus.WARNING
                ),
                "pass": sum(1 for f in self.findings if f.status == ScanStatus.PASS),
            },
        }
