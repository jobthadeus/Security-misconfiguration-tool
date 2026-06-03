"""
Remote access misconfiguration checks.

RDP and legacy SMBv1 are frequent entry points in enterprise breaches.
Settings are read from well-known registry locations and optional features.
"""

from __future__ import annotations

import subprocess

from utils.models import Finding, ScanStatus, Severity
from utils.registry_helper import read_registry_value

RDP_KEY = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
SMBV1_KEY = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"


def _check_rdp() -> Finding:
    """
    Check if Remote Desktop is enabled.

    fDenyTSConnections: 0 = RDP allowed, 1 = RDP denied
    """
    deny = read_registry_value("HKLM", RDP_KEY, "fDenyTSConnections", default=None)

    if deny is None:
        return Finding(
            category="Remote Access",
            check_id="rdp_status",
            title="Remote Desktop Protocol (RDP)",
            description="Could not determine RDP configuration.",
            severity=Severity.INFO,
            status=ScanStatus.ERROR,
            recommendation="Check RDP status in System > Remote Desktop settings.",
            evidence="Registry value fDenyTSConnections unavailable.",
            score_impact=0,
        )

    rdp_enabled = int(deny) == 0
    return Finding(
        category="Remote Access",
        check_id="rdp_status",
        title="Remote Desktop Protocol (RDP)",
        description=(
            "Remote Desktop is enabled on this system."
            if rdp_enabled
            else "Remote Desktop is disabled."
        ),
        severity=Severity.MEDIUM if rdp_enabled else Severity.INFO,
        status=ScanStatus.WARNING if rdp_enabled else ScanStatus.PASS,
        recommendation=(
            "Disable RDP if not required. If needed, enforce NLA, strong passwords, "
            "and restrict access via firewall/VPN."
            if rdp_enabled
            else "No action required."
        ),
        evidence=f"fDenyTSConnections={deny}",
        score_impact=10 if rdp_enabled else 0,
    )


def _check_smbv1() -> Finding:
    """
    Detect SMBv1 protocol status.

    Tries PowerShell Get-WindowsOptionalFeature first (most reliable on
    modern Windows), then falls back to the SMB1 registry DWORD.
    """
    # Attempt PowerShell optional feature query
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol "
                "-ErrorAction SilentlyContinue).State",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        state = result.stdout.strip()
        if state:
            enabled = state.lower() == "enabled"
            return Finding(
                category="Remote Access",
                check_id="smbv1_status",
                title="SMBv1 Protocol",
                description=(
                    f"SMBv1 is {'enabled' if enabled else 'disabled'} on this system."
                ),
                severity=Severity.HIGH if enabled else Severity.INFO,
                status=ScanStatus.FAIL if enabled else ScanStatus.PASS,
                recommendation=(
                    "Disable SMBv1 — it is deprecated and exploited by worms like EternalBlue. "
                    "Use 'Turn Windows features on or off' or: "
                    "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
                    if enabled
                    else "No action required."
                ),
                evidence=f"Get-WindowsOptionalFeature State={state}",
                score_impact=15 if enabled else 0,
            )
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Registry fallback: SMB1 value under LanmanServer
    smb1 = read_registry_value("HKLM", SMBV1_KEY, "SMB1", default=None)
    if smb1 is not None:
        enabled = int(smb1) == 1
        return Finding(
            category="Remote Access",
            check_id="smbv1_status",
            title="SMBv1 Protocol",
            description=f"SMBv1 appears {'enabled' if enabled else 'disabled'} (registry).",
            severity=Severity.HIGH if enabled else Severity.INFO,
            status=ScanStatus.FAIL if enabled else ScanStatus.PASS,
            recommendation=(
                "Disable SMBv1 via Windows Features or Group Policy."
                if enabled
                else "No action required."
            ),
            evidence=f"SMB1 registry value={smb1}",
            score_impact=15 if enabled else 0,
        )

    return Finding(
        category="Remote Access",
        check_id="smbv1_status",
        title="SMBv1 Protocol",
        description="SMBv1 status could not be determined.",
        severity=Severity.INFO,
        status=ScanStatus.INFO,
        recommendation="Manually verify SMBv1 in 'Turn Windows features on or off'.",
        evidence="PowerShell and registry checks returned no definitive result.",
        score_impact=0,
    )


def scan_remote_access() -> list[Finding]:
    """Run remote access security checks."""
    return [_check_rdp(), _check_smbv1()]
