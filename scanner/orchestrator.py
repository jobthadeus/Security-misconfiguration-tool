"""
Scan orchestrator — runs all modules and assembles a ScanResult.
"""

from __future__ import annotations

import socket

from scanner.firewall import scan_firewall
from scanner.network import scan_network
from scanner.remote_access import scan_remote_access
from scanner.services import scan_services
from scanner.windows_security import scan_windows_security
from utils.models import Finding, ScanResult, ScanStatus, Severity
from utils.risk_scorer import apply_scoring


def _get_hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def run_full_scan() -> ScanResult:
    """
    Execute all security scanners and return a scored ScanResult.

    Each module is isolated in a try/except so one failure does not
    abort the entire audit — important for production-style tooling.
    """
    scanners: list[tuple[str, callable]] = [
        ("Firewall", scan_firewall),
        ("Network", scan_network),
        ("Remote Access", scan_remote_access),
        ("Windows Security", scan_windows_security),
        ("Services & Startup", scan_services),
    ]

    all_findings: list[Finding] = []

    for module_name, scan_fn in scanners:
        try:
            findings = scan_fn()
            all_findings.extend(findings)
        except Exception as exc:
            all_findings.append(
                Finding(
                    category=module_name,
                    check_id=f"{module_name.lower().replace(' ', '_')}_error",
                    title=f"{module_name} Module Error",
                    description=f"The {module_name} scanner encountered an unexpected error.",
                    severity=Severity.INFO,
                    status=ScanStatus.ERROR,
                    recommendation="Review logs and re-run with Administrator privileges.",
                    evidence=str(exc),
                    score_impact=0,
                )
            )

    result = ScanResult(hostname=_get_hostname(), findings=all_findings)
    return apply_scoring(result)
