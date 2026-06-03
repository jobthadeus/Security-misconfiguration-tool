"""
SecureAudit — System Security Misconfiguration Scanner
Streamlit dashboard for local Windows security assessments.
"""

from __future__ import annotations

import platform
from datetime import datetime

import matplotlib.pyplot as plt
import streamlit as st

from reporting.json_report import export_json_report
from reporting.pdf_report import export_pdf_report
from scanner.orchestrator import run_full_scan
from utils.models import ScanStatus, Severity
from utils.storage import load_recent_scans, save_scan

# --- Page config ---
st.set_page_config(
    page_title="SecureAudit",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Custom styling ---
st.markdown(
    """
    <style>
    .main-header { font-size: 2rem; font-weight: 700; color: #0F172A; }
    .sub-header { color: #64748B; margin-bottom: 1.5rem; }
    div[data-testid="stMetricValue"] { font-size: 2rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

RISK_COLORS = {
    "Secure": "#16A34A",
    "Moderate Risk": "#CA8A04",
    "High Risk": "#EA580C",
    "Critical Risk": "#DC2626",
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "#DC2626",
    Severity.HIGH: "#EA580C",
    Severity.MEDIUM: "#CA8A04",
    Severity.LOW: "#2563EB",
    Severity.INFO: "#64748B",
}


def _score_gauge(score: int) -> None:
    """Render a simple matplotlib gauge for the security score."""
    fig, ax = plt.subplots(figsize=(4, 1.2))
    fig.patch.set_facecolor("#FFFFFF")
    ax.set_facecolor("#FFFFFF")

    color = "#16A34A" if score >= 80 else "#CA8A04" if score >= 60 else "#EA580C" if score >= 40 else "#DC2626"

    ax.barh([0], [score], color=color, height=0.4)
    ax.barh([0], [100 - score], left=[score], color="#E2E8F0", height=0.4)
    ax.set_xlim(0, 100)
    ax.set_yticks([])
    ax.set_xlabel("Security Score (0–100)")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_visible(False)

    st.pyplot(fig, clear_figure=True)


def _severity_chart(findings) -> None:
    """Bar chart of findings by severity."""
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1

    labels = list(counts.keys())
    values = list(counts.values())
    bar_colors = ["#DC2626", "#EA580C", "#CA8A04", "#2563EB", "#64748B"]

    fig, ax = plt.subplots(figsize=(5, 3))
    fig.patch.set_facecolor("#FFFFFF")
    ax.bar(labels, values, color=bar_colors)
    ax.set_ylabel("Count")
    ax.set_title("Findings by Severity")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    plt.xticks(rotation=15)
    st.pyplot(fig, clear_figure=True)


def _status_chart(findings) -> None:
    """Pie chart of check outcomes."""
    status_counts = {}
    for f in findings:
        key = f.status.value
        status_counts[key] = status_counts.get(key, 0) + 1

    if not status_counts:
        st.info("No findings to chart.")
        return

    fig, ax = plt.subplots(figsize=(4, 3))
    fig.patch.set_facecolor("#FFFFFF")
    colors_map = {
        "Pass": "#16A34A",
        "Fail": "#DC2626",
        "Warning": "#CA8A04",
        "Info": "#64748B",
        "Error": "#94A3B8",
    }
    labels = list(status_counts.keys())
    sizes = list(status_counts.values())
    pie_colors = [colors_map.get(l, "#CBD5E1") for l in labels]

    ax.pie(sizes, labels=labels, autopct="%1.0f%%", colors=pie_colors, startangle=90)
    ax.set_title("Check Outcomes")
    st.pyplot(fig, clear_figure=True)


def _render_finding_card(finding) -> None:
    """Display a single finding as a styled card."""
    border_color = SEVERITY_COLORS.get(finding.severity, "#64748B")
    status_icon = {
        ScanStatus.PASS: "✅",
        ScanStatus.FAIL: "❌",
        ScanStatus.WARNING: "⚠️",
        ScanStatus.INFO: "ℹ️",
        ScanStatus.ERROR: "🔧",
    }.get(finding.status, "•")

    st.markdown(
        f"""
        <div style="
            border-left: 4px solid {border_color};
            padding: 12px 16px;
            margin-bottom: 12px;
            background: #F8FAFC;
            border-radius: 0 8px 8px 0;
        ">
            <strong>{status_icon} {finding.title}</strong>
            <span style="float:right; color:{border_color}; font-size:0.85rem;">
                {finding.severity.value}
            </span>
            <p style="margin:8px 0; color:#334155;">{finding.description}</p>
            <p style="margin:0; font-size:0.85rem; color:#64748B;">
                <em>Category: {finding.category}</em>
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def main() -> None:
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/fluency/96/security-checked.png", width=64)
        st.title("SecureAudit")
        st.caption("Windows Security Misconfiguration Scanner")
        st.divider()

        if platform.system() != "Windows":
            st.error("This tool is designed for Windows systems.")
        else:
            st.success(f"Host: {platform.node()}")

        st.markdown("**Categories scanned:**")
        st.markdown(
            """
            - Firewall
            - Network exposure
            - Remote access (RDP/SMBv1)
            - Windows Defender & updates
            - UAC & BitLocker
            - User accounts
            - Startup persistence
            - Security services
            """
        )

        st.divider()
        st.caption("Run as Administrator for complete results.")

    # Header
    st.markdown('<p class="main-header">🛡️ SecureAudit</p>', unsafe_allow_html=True)
    st.markdown(
        '<p class="sub-header">Local Windows security misconfiguration scanner for blue-team auditing</p>',
        unsafe_allow_html=True,
    )

    # Scan controls
    col_btn, col_info = st.columns([1, 3])
    with col_btn:
        run_scan = st.button("🔍 Run Security Scan", type="primary", use_container_width=True)
    with col_info:
        st.caption("Scans registry, services, network listeners, and security policies on this machine.")

    if "scan_result" not in st.session_state:
        st.session_state.scan_result = None

    if run_scan:
        with st.spinner("Scanning system for misconfigurations..."):
            result = run_full_scan()
            save_scan(result)
            st.session_state.scan_result = result

    result = st.session_state.scan_result

    if result is None:
        st.info("Click **Run Security Scan** to start a local security assessment.")
        recent = load_recent_scans(limit=5)
        if recent:
            st.subheader("Recent Scans")
            st.dataframe(recent, use_container_width=True, hide_index=True)
        return

    # --- Score & metrics row ---
    risk_color = RISK_COLORS.get(result.risk_level, "#64748B")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Security Score", f"{result.score}/100")
    m2.metric("Risk Level", result.risk_level)
    m3.metric(
        "Failed Checks",
        sum(1 for f in result.findings if f.status == ScanStatus.FAIL),
    )
    m4.metric(
        "Warnings",
        sum(1 for f in result.findings if f.status == ScanStatus.WARNING),
    )

    st.markdown(
        f'<p style="color:{risk_color}; font-weight:600;">'
        f"Assessment: {result.risk_level} — scanned at {result.scanned_at}</p>",
        unsafe_allow_html=True,
    )

    # Charts row
    chart_col1, chart_col2, chart_col3 = st.columns([2, 2, 2])
    with chart_col1:
        _score_gauge(result.score)
    with chart_col2:
        _severity_chart(result.findings)
    with chart_col3:
        _status_chart(result.findings)

    st.divider()

    # Tabs: Findings | Recommendations | Export
    tab_findings, tab_recommendations, tab_export = st.tabs(
        ["📋 Findings", "💡 Recommendations", "📥 Export Report"]
    )

    with tab_findings:
        filter_col1, filter_col2 = st.columns(2)
        with filter_col1:
            severity_filter = st.multiselect(
                "Filter by severity",
                options=[s.value for s in Severity],
                default=[s.value for s in Severity],
            )
        with filter_col2:
            status_filter = st.multiselect(
                "Filter by status",
                options=[s.value for s in ScanStatus],
                default=[ScanStatus.FAIL.value, ScanStatus.WARNING.value, ScanStatus.INFO.value],
            )

        filtered = [
            f
            for f in result.findings
            if f.severity.value in severity_filter and f.status.value in status_filter
        ]

        # Group by category
        categories = sorted({f.category for f in filtered})
        for category in categories:
            cat_findings = [f for f in filtered if f.category == category]
            with st.expander(f"{category} ({len(cat_findings)})", expanded=True):
                for finding in cat_findings:
                    _render_finding_card(finding)
                    if finding.evidence:
                        with st.popover("View evidence"):
                            st.code(finding.evidence)

    with tab_recommendations:
        actionable = [
            f
            for f in result.findings
            if f.status in (ScanStatus.FAIL, ScanStatus.WARNING)
            and f.recommendation
            and f.recommendation.lower() != "no action required."
        ]

        if not actionable:
            st.success("No urgent recommendations — system checks look good!")
        else:
            st.warning(f"{len(actionable)} item(s) require attention.")
            for i, finding in enumerate(actionable, 1):
                st.markdown(f"**{i}. [{finding.severity.value}] {finding.title}**")
                st.markdown(finding.recommendation)
                st.divider()

    with tab_export:
        st.subheader("Download Reports")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hostname = result.hostname.replace(" ", "_")

        json_data = export_json_report(result)
        pdf_bytes = export_pdf_report(result)

        dl_col1, dl_col2 = st.columns(2)
        with dl_col1:
            st.download_button(
                label="⬇️ Download JSON Report",
                data=json_data,
                file_name=f"secureaudit_{hostname}_{timestamp}.json",
                mime="application/json",
                use_container_width=True,
            )
        with dl_col2:
            st.download_button(
                label="⬇️ Download PDF Report",
                data=pdf_bytes,
                file_name=f"secureaudit_{hostname}_{timestamp}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

        with st.expander("Preview JSON"):
            st.json(result.to_dict())


if __name__ == "__main__":
    main()
