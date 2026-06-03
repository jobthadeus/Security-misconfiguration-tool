"""
Windows security hardening checks.

Covers Defender AV status, Windows Update configuration, UAC, BitLocker,
local account security, and password policy — common CIS benchmark areas.
"""

from __future__ import annotations

import subprocess
from datetime import datetime

from utils.models import Finding, ScanStatus, Severity
from utils.registry_helper import read_registry_value

UAC_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
DEFENDER_KEY = r"SOFTWARE\Microsoft\Windows Defender"
UPDATE_KEY = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
ACCOUNT_POLICY_KEY = r"SYSTEM\CurrentControlSet\Control\Lsa"


def _check_defender() -> Finding:
    """Check Windows Defender real-time protection via registry and service."""
    disable_rt = read_registry_value(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
        "DisableRealtimeMonitoring",
        default=0,
    )
    antispyware = read_registry_value(
        "HKLM",
        DEFENDER_KEY,
        "DisableAntiSpyware",
        default=0,
    )

    disabled = int(disable_rt) == 1 or int(antispyware) == 1

    # Supplement with PowerShell status when available
    ps_evidence = ""
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-MpComputerStatus | Select-Object AMServiceEnabled,"
                "AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json -Compress",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.stdout.strip():
            ps_evidence = result.stdout.strip()[:400]
            if "false" in ps_evidence.lower() and "realtime" in ps_evidence.lower():
                disabled = True
    except (subprocess.TimeoutExpired, OSError):
        pass

    evidence_parts = [
        f"DisableRealtimeMonitoring={disable_rt}",
        f"DisableAntiSpyware={antispyware}",
    ]
    if ps_evidence:
        evidence_parts.append(ps_evidence)

    return Finding(
        category="Antivirus",
        check_id="defender_status",
        title="Windows Defender Antivirus",
        description=(
            "Windows Defender real-time protection appears disabled or incomplete."
            if disabled
            else "Windows Defender antivirus protection appears active."
        ),
        severity=Severity.HIGH if disabled else Severity.INFO,
        status=ScanStatus.FAIL if disabled else ScanStatus.PASS,
        recommendation=(
            "Enable Windows Defender and ensure real-time protection is on. "
            "Investigate if a third-party AV has replaced Defender."
            if disabled
            else "No action required."
        ),
        evidence=" | ".join(evidence_parts),
        score_impact=20 if disabled else 0,
    )


def _check_windows_update() -> Finding:
    """
    Check whether automatic Windows Updates are disabled via policy.

    AUOptions: 1=Never, 2=Notify before download, 3=Auto download notify install,
    4=Auto download schedule install, 5=Allow local admin to choose
    """
    au_options = read_registry_value("HKLM", UPDATE_KEY, "AUOptions", default=None)
    no_auto = read_registry_value("HKLM", UPDATE_KEY, "NoAutoUpdate", default=0)

    updates_disabled = int(no_auto) == 1 or (au_options is not None and int(au_options) == 1)

    # Check last update time via PowerShell when possible
    last_update = ""
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-HotFix | Sort-Object InstalledOn -Descending | "
                "Select-Object -First 1).InstalledOn",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        last_update = result.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        pass

    outdated = False
    if last_update:
        try:
            # PowerShell may return datetime string
            for fmt in ("%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d"):
                try:
                    dt = datetime.strptime(last_update.split()[0], fmt.split()[0])
                    days_old = (datetime.now() - dt).days
                    outdated = days_old > 60
                    break
                except ValueError:
                    continue
        except (ValueError, IndexError):
            pass

    if updates_disabled:
        status = ScanStatus.FAIL
        severity = Severity.MEDIUM
        score = 10
        desc = "Automatic Windows Updates appear to be disabled."
        rec = "Enable automatic updates via Settings > Windows Update or Group Policy."
    elif outdated:
        status = ScanStatus.WARNING
        severity = Severity.MEDIUM
        score = 10
        desc = f"System may be missing recent updates. Last hotfix: {last_update or 'unknown'}."
        rec = "Install pending Windows Updates and enable automatic patching."
    else:
        status = ScanStatus.PASS
        severity = Severity.INFO
        score = 0
        desc = "Windows Update configuration appears acceptable."
        rec = "No action required."

    evidence = f"NoAutoUpdate={no_auto}, AUOptions={au_options}"
    if last_update:
        evidence += f", LastHotfix={last_update}"

    return Finding(
        category="Windows Update",
        check_id="windows_update",
        title="Windows Update Status",
        description=desc,
        severity=severity,
        status=status,
        recommendation=rec,
        evidence=evidence,
        score_impact=score,
    )


def _check_uac() -> Finding:
    """User Account Control reduces privilege escalation from malware."""
    enable_lua = read_registry_value("HKLM", UAC_KEY, "EnableLUA", default=1)
    consent_prompt = read_registry_value("HKLM", UAC_KEY, "ConsentPromptBehaviorAdmin", default=5)

    uac_disabled = int(enable_lua) == 0
    weak_prompt = consent_prompt is not None and int(consent_prompt) == 0

    if uac_disabled:
        return Finding(
            category="System Hardening",
            check_id="uac_status",
            title="User Account Control (UAC)",
            description="UAC is disabled — admin actions run without elevation prompts.",
            severity=Severity.HIGH,
            status=ScanStatus.FAIL,
            recommendation="Enable UAC: set EnableLUA=1 in Group Policy or registry.",
            evidence=f"EnableLUA={enable_lua}, ConsentPromptBehaviorAdmin={consent_prompt}",
            score_impact=10,
        )

    if weak_prompt:
        return Finding(
            category="System Hardening",
            check_id="uac_status",
            title="User Account Control (UAC)",
            description="UAC is enabled but admin consent prompt behavior is permissive.",
            severity=Severity.MEDIUM,
            status=ScanStatus.WARNING,
            recommendation="Set ConsentPromptBehaviorAdmin to 2 (prompt on secure desktop).",
            evidence=f"EnableLUA={enable_lua}, ConsentPromptBehaviorAdmin={consent_prompt}",
            score_impact=5,
        )

    return Finding(
        category="System Hardening",
        check_id="uac_status",
        title="User Account Control (UAC)",
        description="UAC is enabled with standard prompt behavior.",
        severity=Severity.INFO,
        status=ScanStatus.PASS,
        recommendation="No action required.",
        evidence=f"EnableLUA={enable_lua}, ConsentPromptBehaviorAdmin={consent_prompt}",
        score_impact=0,
    )


def _check_bitlocker() -> Finding:
    """Check BitLocker drive encryption status via manage-bcd."""
    try:
        result = subprocess.run(
            ["manage-bde", "-status"],
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        output = result.stdout
    except (subprocess.TimeoutExpired, OSError) as exc:
        return Finding(
            category="System Hardening",
            check_id="bitlocker_status",
            title="BitLocker Drive Encryption",
            description="Could not query BitLocker status.",
            severity=Severity.INFO,
            status=ScanStatus.INFO,
            recommendation="Run 'manage-bde -status' manually or check Device encryption settings.",
            evidence=str(exc),
            score_impact=0,
        )

    fully_encrypted = "100.0%" in output and "Fully Encrypted" in output
    partially = "Encryption in Progress" in output or "Partially Encrypted" in output

    if fully_encrypted:
        return Finding(
            category="System Hardening",
            check_id="bitlocker_status",
            title="BitLocker Drive Encryption",
            description="System drive appears fully encrypted with BitLocker.",
            severity=Severity.INFO,
            status=ScanStatus.PASS,
            recommendation="No action required.",
            evidence=output.strip()[:400],
            score_impact=0,
        )

    if partially:
        return Finding(
            category="System Hardening",
            check_id="bitlocker_status",
            title="BitLocker Drive Encryption",
            description="BitLocker encryption is in progress or partial.",
            severity=Severity.LOW,
            status=ScanStatus.WARNING,
            recommendation="Allow encryption to complete; verify recovery keys are backed up.",
            evidence=output.strip()[:400],
            score_impact=5,
        )

    return Finding(
        category="System Hardening",
        check_id="bitlocker_status",
        title="BitLocker Drive Encryption",
        description="BitLocker does not appear enabled on the system drive.",
        severity=Severity.MEDIUM,
        status=ScanStatus.WARNING,
        recommendation=(
            "Enable BitLocker on fixed drives to protect data at rest, "
            "especially on laptops."
        ),
        evidence=output.strip()[:400] if output.strip() else "Protection Off or unavailable.",
        score_impact=8,
    )


def _check_guest_account() -> Finding:
    """Detect whether the built-in Guest account is active."""
    try:
        result = subprocess.run(
            ["net", "user", "Guest"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        output = result.stdout
        not_found = "not found" in output.lower() or result.returncode != 0

        active = False
        for line in output.splitlines():
            if "account active" in line.lower():
                active = "yes" in line.lower().split(":")[-1]
                break
    except (subprocess.TimeoutExpired, OSError) as exc:
        return Finding(
            category="User Accounts",
            check_id="guest_account",
            title="Guest Account",
            description="Could not query Guest account status.",
            severity=Severity.INFO,
            status=ScanStatus.ERROR,
            recommendation="Verify Guest account with 'net user Guest'.",
            evidence=str(exc),
            score_impact=0,
        )

    if not_found:
        return Finding(
            category="User Accounts",
            check_id="guest_account",
            title="Guest Account",
            description="Guest account not present or renamed.",
            severity=Severity.INFO,
            status=ScanStatus.PASS,
            recommendation="No action required.",
            evidence="net user Guest: account not found.",
            score_impact=0,
        )

    if active:
        return Finding(
            category="User Accounts",
            check_id="guest_account",
            title="Guest Account",
            description="The Guest account is enabled.",
            severity=Severity.MEDIUM,
            status=ScanStatus.FAIL,
            recommendation="Disable the Guest account: 'net user Guest /active:no'",
            evidence=result.stdout.strip()[:300],
            score_impact=8,
        )

    return Finding(
        category="User Accounts",
        check_id="guest_account",
        title="Guest Account",
        description="Guest account is disabled.",
        severity=Severity.INFO,
        status=ScanStatus.PASS,
        recommendation="No action required.",
        evidence=result.stdout.strip()[:300],
        score_impact=0,
    )


def _check_admin_accounts() -> Finding:
    """List members of the local Administrators group."""
    try:
        result = subprocess.run(
            ["net", "localgroup", "Administrators"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        output = result.stdout
    except (subprocess.TimeoutExpired, OSError) as exc:
        return Finding(
            category="User Accounts",
            check_id="admin_accounts",
            title="Local Administrator Accounts",
            description="Could not enumerate Administrators group.",
            severity=Severity.INFO,
            status=ScanStatus.ERROR,
            recommendation="Run 'net localgroup Administrators' manually.",
            evidence=str(exc),
            score_impact=0,
        )

    lines = output.splitlines()
    members = []
    capture = False
    for line in lines:
        if "----" in line:
            capture = True
            continue
        if capture and line.strip() and "command completed" not in line.lower():
            members.append(line.strip())

    # Flag if many human admin accounts (excluding built-in/SID entries heuristic)
    human_admins = [m for m in members if not m.startswith("S-1-") and "Administrator" not in m]

    many_admins = len(human_admins) > 3

    return Finding(
        category="User Accounts",
        check_id="admin_accounts",
        title="Local Administrator Accounts",
        description=(
            f"Found {len(members)} member(s) in the local Administrators group."
            + (" Multiple admin accounts increase risk." if many_admins else "")
        ),
        severity=Severity.MEDIUM if many_admins else Severity.INFO,
        status=ScanStatus.WARNING if many_admins else ScanStatus.INFO,
        recommendation=(
            "Apply least privilege — limit local admin membership and use separate admin accounts."
            if many_admins
            else "Review admin group membership periodically."
        ),
        evidence=", ".join(members) if members else "No members parsed.",
        score_impact=5 if many_admins else 0,
    )


def _check_password_policy() -> Finding:
    """
    Read local password policy via net accounts.

    Weak policies (short min length, no complexity) are common misconfigs.
    """
    try:
        result = subprocess.run(
            ["net", "accounts"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        output = result.stdout
    except (subprocess.TimeoutExpired, OSError) as exc:
        return Finding(
            category="User Accounts",
            check_id="password_policy",
            title="Password Policy",
            description="Could not read local password policy.",
            severity=Severity.INFO,
            status=ScanStatus.ERROR,
            recommendation="Review password policy in Local Security Policy (secpol.msc).",
            evidence=str(exc),
            score_impact=0,
        )

    weak = False
    details = []

    for line in output.splitlines():
        lower = line.lower()
        if "minimum password length" in lower:
            details.append(line.strip())
            try:
                length = int("".join(c for c in line if c.isdigit()) or "0")
                if length < 8:
                    weak = True
            except ValueError:
                pass
        if "password complexity" in lower:
            details.append(line.strip())
            if "no" in lower.split(":")[-1]:
                weak = True

    return Finding(
        category="User Accounts",
        check_id="password_policy",
        title="Password Policy",
        description=(
            "Local password policy may be weak (short minimum length or no complexity)."
            if weak
            else "Local password policy meets basic expectations."
        ),
        severity=Severity.MEDIUM if weak else Severity.INFO,
        status=ScanStatus.WARNING if weak else ScanStatus.PASS,
        recommendation=(
            "Enforce minimum 12+ character passwords with complexity via Group Policy."
            if weak
            else "No action required."
        ),
        evidence=" | ".join(details) if details else output.strip()[:300],
        score_impact=8 if weak else 0,
    )


def scan_windows_security() -> list[Finding]:
    """Run Windows security and hardening checks."""
    return [
        _check_defender(),
        _check_windows_update(),
        _check_uac(),
        _check_bitlocker(),
        _check_guest_account(),
        _check_admin_accounts(),
        _check_password_policy(),
    ]
