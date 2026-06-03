"""
Risk scoring engine.

SecureAudit starts at 100 points and deducts score_impact from each finding
whose status indicates a misconfiguration. The final score maps to a risk tier
suitable for executive-style reporting.
"""

from __future__ import annotations

from utils.models import Finding, ScanResult, ScanStatus


# Risk tier thresholds (inclusive lower bound)
RISK_TIERS = [
    (80, "Secure"),
    (60, "Moderate Risk"),
    (40, "High Risk"),
    (0, "Critical Risk"),
]

# Only these statuses contribute to score deductions
DEDUCTIBLE_STATUSES = {ScanStatus.FAIL, ScanStatus.WARNING}


def calculate_risk_score(findings: list[Finding]) -> tuple[int, str]:
    """
    Compute a 0–100 security score and risk classification.

    Returns:
        (score, risk_level) tuple
    """
    score = 100

    for finding in findings:
        if finding.status in DEDUCTIBLE_STATUSES and finding.score_impact > 0:
            score -= finding.score_impact

    score = max(0, min(100, score))

    risk_level = "Critical Risk"
    for threshold, label in RISK_TIERS:
        if score >= threshold:
            risk_level = label
            break

    return score, risk_level


def apply_scoring(result: ScanResult) -> ScanResult:
    """Update score and risk_level on an existing ScanResult."""
    score, risk_level = calculate_risk_score(result.findings)
    result.score = score
    result.risk_level = risk_level
    return result
