"""
Windows Defender Firewall checks.

Uses the registry paths documented by Microsoft for firewall profiles.
Each profile (Domain, Private, Public) can be enabled/disabled independently;
a disabled profile is a common misconfiguration on laptops that roam networks.
"""

from __future__ import annotations

import subprocess

from utils.models import Finding, ScanStatus, Severity
from utils.registry_helper import read_registry_value

FIREWALL_BASE = (
    r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
)

PROFILES = {
    "Domain": "DomainProfile",
    "Private": "StandardProfile",
    "Public": "PublicProfile",
}


def _check_profile(profile_label: str, profile_key: str) -> Finding:
    """Check whether a specific firewall profile is enabled."""
    path = f"{FIREWALL_BASE}\\{profile_key}"
    enabled = read_registry_value("HKLM", path, "EnableFirewall", default=None)

    if enabled is None:
        return Finding(
            category="Firewall",
            check_id=f"firewall_{profile_key.lower()}",
            title=f"Firewall {profile_label} Profile",
            description=f"Could not read {profile_label} firewall profile status.",
            severity=Severity.INFO,
            status=ScanStatus.ERROR,
            recommendation="Run SecureAudit as Administrator for full firewall visibility.",
            evidence="Registry key unavailable or access denied.",
            score_impact=0,
        )

    is_enabled = int(enabled) == 1
    return Finding(
        category="Firewall",
        check_id=f"firewall_{profile_key.lower()}",
        title=f"Firewall {profile_label} Profile",
        description=(
            f"The {profile_label} firewall profile is "
            f"{'enabled' if is_enabled else 'disabled'}."
        ),
        severity=Severity.HIGH if not is_enabled else Severity.INFO,
        status=ScanStatus.PASS if is_enabled else ScanStatus.FAIL,
        recommendation=(
            "Enable Windows Defender Firewall for all profiles via "
            "Windows Security > Firewall & network protection."
            if not is_enabled
            else "No action required."
        ),
        evidence=f"EnableFirewall={enabled}",
        score_impact=0 if is_enabled else 20,
    )


def _check_firewall_service() -> Finding:
    """Verify the Windows Firewall service (mpssvc) is running."""
    try:
        result = subprocess.run(
            ["sc", "query", "mpssvc"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        output = result.stdout
        running = "RUNNING" in output
    except (subprocess.TimeoutExpired, OSError) as exc:
        return Finding(
            category="Firewall",
            check_id="firewall_service",
            title="Firewall Service (mpssvc)",
            description="Unable to query firewall service status.",
            severity=Severity.INFO,
            status=ScanStatus.ERROR,
            recommendation="Verify Windows Firewall service manually with 'sc query mpssvc'.",
            evidence=str(exc),
            score_impact=0,
        )

    return Finding(
        category="Firewall",
        check_id="firewall_service",
        title="Firewall Service (mpssvc)",
        description=(
            "Windows Defender Firewall service is running."
            if running
            else "Windows Defender Firewall service is not running."
        ),
        severity=Severity.HIGH if not running else Severity.INFO,
        status=ScanStatus.PASS if running else ScanStatus.FAIL,
        recommendation=(
            "Start the Windows Defender Firewall service and set startup type to Automatic."
            if not running
            else "No action required."
        ),
        evidence=output.strip()[:500],
        score_impact=0 if running else 15,
    )


def scan_firewall() -> list[Finding]:
    """Run all firewall-related security checks."""
    findings = [_check_firewall_service()]
    for label, key in PROFILES.items():
        findings.append(_check_profile(label, key))
    return findings
