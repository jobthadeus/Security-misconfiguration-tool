"""
Startup persistence and security service checks.

Malware often achieves persistence via Run/RunOnce registry keys.
Critical security services (Defender, Firewall, Event Log) should run.
"""

from __future__ import annotations

import os
import subprocess

from utils.models import Finding, ScanStatus, Severity
from utils.registry_helper import enum_registry_values

# Common autorun locations targeted by malware and legitimate software
AUTORUN_LOCATIONS = {
    "HKLM Run": (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    "HKCU Run": (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    "HKLM RunOnce": (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
    "HKCU RunOnce": (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
}

# Suspicious patterns in startup command lines (heuristic, not definitive)
SUSPICIOUS_PATTERNS = [
    "powershell -enc",
    "powershell -e ",
    "cmd /c start",
    "mshta ",
    "rundll32 javascript",
    "\\temp\\",
    "\\appdata\\local\\temp\\",
]

SECURITY_SERVICES = {
    "WinDefend": "Windows Defender Antivirus Service",
    "mpssvc": "Windows Defender Firewall",
    "EventLog": "Windows Event Log",
    "wscsvc": "Security Center",
}


def _check_startup_programs() -> Finding:
    """Enumerate programs registered in common Run/RunOnce keys."""
    all_entries: list[str] = []
    suspicious: list[str] = []

    for label, (path, hive) in AUTORUN_LOCATIONS.items():
        values = enum_registry_values(hive, path)
        for name, command in values.items():
            entry = f"[{label}] {name}: {command}"
            all_entries.append(entry)
            cmd_lower = str(command).lower()
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern in cmd_lower:
                    suspicious.append(entry)
                    break

    # Startup folder (user-level)
    startup_folder = os.path.join(
        os.environ.get("APPDATA", ""),
        r"Microsoft\Windows\Start Menu\Programs\Startup",
    )
    folder_items: list[str] = []
    if os.path.isdir(startup_folder):
        folder_items = os.listdir(startup_folder)

    evidence_parts = []
    if all_entries:
        evidence_parts.append(f"Registry ({len(all_entries)}): " + "; ".join(all_entries[:8]))
        if len(all_entries) > 8:
            evidence_parts.append(f"...+{len(all_entries) - 8} more registry entries")
    if folder_items:
        evidence_parts.append(f"Startup folder: {', '.join(folder_items)}")

    if suspicious:
        return Finding(
            category="Startup & Persistence",
            check_id="startup_programs",
            title="Startup & Autorun Programs",
            description=(
                f"Found {len(all_entries)} autorun entries; "
                f"{len(suspicious)} match suspicious patterns."
            ),
            severity=Severity.HIGH,
            status=ScanStatus.WARNING,
            recommendation=(
                "Investigate flagged startup entries. Remove unknown persistence "
                "and validate legitimate software paths."
            ),
            evidence=" | ".join(suspicious[:5]),
            score_impact=10,
        )

    return Finding(
        category="Startup & Persistence",
        check_id="startup_programs",
        title="Startup & Autorun Programs",
        description=f"Found {len(all_entries)} registry autorun entries and {len(folder_items)} startup folder items.",
        severity=Severity.INFO,
        status=ScanStatus.INFO,
        recommendation="Periodically review startup programs in Task Manager > Startup.",
        evidence=" | ".join(evidence_parts) if evidence_parts else "No autorun entries found.",
        score_impact=0,
    )


def _check_security_services() -> list[Finding]:
    """Verify critical security-related Windows services are running."""
    findings: list[Finding] = []

    for service_name, display_name in SECURITY_SERVICES.items():
        try:
            result = subprocess.run(
                ["sc", "query", service_name],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            output = result.stdout
            running = "RUNNING" in output
            missing = "1060" in output or "does not exist" in output.lower()
        except (subprocess.TimeoutExpired, OSError) as exc:
            findings.append(
                Finding(
                    category="System Hardening",
                    check_id=f"service_{service_name.lower()}",
                    title=f"Security Service: {display_name}",
                    description=f"Could not query service {service_name}.",
                    severity=Severity.INFO,
                    status=ScanStatus.ERROR,
                    recommendation=f"Check service status: sc query {service_name}",
                    evidence=str(exc),
                    score_impact=0,
                )
            )
            continue

        if missing:
            status = ScanStatus.INFO
            severity = Severity.INFO
            score = 0
            desc = f"Service {service_name} not found (may vary by Windows edition)."
        elif not running:
            status = ScanStatus.FAIL
            severity = Severity.HIGH
            score = 12
            desc = f"{display_name} is not running."
        else:
            status = ScanStatus.PASS
            severity = Severity.INFO
            score = 0
            desc = f"{display_name} is running."

        findings.append(
            Finding(
                category="System Hardening",
                check_id=f"service_{service_name.lower()}",
                title=f"Security Service: {display_name}",
                description=desc,
                severity=severity,
                status=status,
                recommendation=(
                    f"Start and enable the {display_name} service."
                    if not running and not missing
                    else "No action required."
                ),
                evidence=output.strip()[:300],
                score_impact=score,
            )
        )

    return findings


def scan_services() -> list[Finding]:
    """Run startup persistence and security service checks."""
    findings = [_check_startup_programs()]
    findings.extend(_check_security_services())
    return findings
