"""
Network exposure checks using psutil.

Identifies listening TCP/UDP ports and flags commonly abused services
(RDP 3389, SMB 445, Telnet 23, etc.) that expand the attack surface.
"""

from __future__ import annotations

import psutil

from utils.models import Finding, ScanStatus, Severity

# Ports associated with high-risk or commonly targeted services
RISKY_PORTS: dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
}


def scan_network() -> list[Finding]:
    """Enumerate listening ports and flag risky exposed services."""
    findings: list[Finding] = []

    listening: list[dict] = []
    risky_exposed: list[str] = []

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, psutil.Error) as exc:
        return [
            Finding(
                category="Network",
                check_id="network_connections",
                title="Open Ports & Listening Services",
                description="Unable to enumerate network connections.",
                severity=Severity.INFO,
                status=ScanStatus.ERROR,
                recommendation="Run SecureAudit as Administrator to inspect network listeners.",
                evidence=str(exc),
                score_impact=0,
            )
        ]

    seen: set[tuple] = set()
    for conn in connections:
        if conn.status != psutil.CONN_LISTEN:
            continue

        key = (conn.laddr.ip if conn.laddr else "", conn.laddr.port if conn.laddr else 0)
        if key in seen:
            continue
        seen.add(key)

        port = conn.laddr.port if conn.laddr else 0
        proc_name = "unknown"
        if conn.pid:
            try:
                proc_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        entry = {
            "port": port,
            "address": conn.laddr.ip if conn.laddr else "0.0.0.0",
            "protocol": "TCP" if conn.type.name == "SOCK_STREAM" else "UDP",
            "process": proc_name,
        }
        listening.append(entry)

        if port in RISKY_PORTS:
            service = RISKY_PORTS[port]
            risky_exposed.append(f"{service} ({port}/{entry['protocol']}) via {proc_name}")

    # Summary finding for open listeners
    if listening:
        port_list = ", ".join(
            sorted({str(e["port"]) for e in listening}, key=int)[:30]
        )
        if len(listening) > 30:
            port_list += f" ... (+{len(listening) - 30} more)"

        findings.append(
            Finding(
                category="Network",
                check_id="network_listeners",
                title="Listening Ports",
                description=f"Found {len(listening)} listening socket(s) on this system.",
                severity=Severity.INFO,
                status=ScanStatus.INFO,
                recommendation="Review listening ports and disable unnecessary services.",
                evidence=f"Ports: {port_list}",
                score_impact=0,
            )
        )
    else:
        findings.append(
            Finding(
                category="Network",
                check_id="network_listeners",
                title="Listening Ports",
                description="No listening ports detected (or insufficient privileges).",
                severity=Severity.INFO,
                status=ScanStatus.INFO,
                recommendation="Re-run with elevated privileges if results seem incomplete.",
                evidence="No LISTEN state connections found.",
                score_impact=0,
            )
        )

    # Risky exposed services
    if risky_exposed:
        findings.append(
            Finding(
                category="Network",
                check_id="network_risky_services",
                title="Risky Exposed Services",
                description=(
                    "One or more high-risk services are listening on network interfaces."
                ),
                severity=Severity.HIGH,
                status=ScanStatus.WARNING,
                recommendation=(
                    "Disable or restrict access to exposed services. "
                    "Use firewall rules to limit source IPs where possible."
                ),
                evidence="; ".join(risky_exposed),
                score_impact=10,
            )
        )
    else:
        findings.append(
            Finding(
                category="Network",
                check_id="network_risky_services",
                title="Risky Exposed Services",
                description="No commonly targeted risky services detected on listening ports.",
                severity=Severity.INFO,
                status=ScanStatus.PASS,
                recommendation="Continue periodic review of network listeners.",
                evidence="No matches for FTP, Telnet, SMB, RDP, WinRM on listening ports.",
                score_impact=0,
            )
        )

    return findings
