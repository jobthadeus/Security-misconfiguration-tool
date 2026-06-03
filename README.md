# SecureAudit — System Security Misconfiguration Scanner

**SecureAudit** is a beginner-to-intermediate cybersecurity tool that scans a local **Windows** system for common security misconfigurations and generates a professional security report. Built for cybersecurity students targeting SOC analyst, blue-team, and security internship roles.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Features

| Category | Checks |
|----------|--------|
| **Firewall** | Profile status (Domain/Private/Public), mpssvc service |
| **Network** | Listening ports, risky exposed services (RDP, SMB, WinRM) |
| **Remote Access** | RDP enabled, SMBv1 protocol status |
| **Antivirus** | Windows Defender real-time protection |
| **Windows Update** | Auto-update policy, last hotfix age |
| **System Hardening** | UAC, BitLocker, critical security services |
| **User Accounts** | Guest account, admin group members, password policy |
| **Persistence** | Run/RunOnce registry keys, startup folder |

### Risk Scoring (0–100)

| Finding | Impact |
|---------|--------|
| Firewall disabled | −20 |
| Defender disabled | −20 |
| SMBv1 enabled | −15 |
| RDP enabled | −10 |
| Missing/outdated updates | −10 |
| UAC disabled | −10 |

**Risk tiers:** Secure (80+) · Moderate (60–79) · High (40–59) · Critical (0–39)

### Dashboard

- Streamlit web UI with scan button, score gauge, and severity charts
- Filterable finding cards with evidence popovers
- Prioritized recommendations
- **JSON** and **PDF** report downloads
- SQLite history for comparing scans over time

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     app.py (Streamlit UI)                   │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│              scanner/orchestrator.py                          │
│         Runs all modules, handles errors gracefully           │
└──┬──────────┬──────────┬──────────────┬──────────┬───────────┘
   │          │          │              │          │
 firewall  network  remote_access  windows_security  services
   │          │          │              │          │
   └──────────┴──────────┴──────────────┴──────────┘
                          │
              ┌───────────▼───────────┐
              │   utils/models.py     │  Finding, ScanResult
              │   utils/risk_scorer   │  0–100 score
              │   utils/registry_helper│ winreg wrapper
              │   utils/storage.py    │  SQLite history
              └───────────┬───────────┘
                          │
              ┌───────────▼───────────┐
              │  reporting/           │
              │  json_report.py       │
              │  pdf_report.py        │
              └───────────────────────┘
```

Each scanner module returns a list of `Finding` objects with real evidence from registry, services, or PowerShell — **no mock data**.

---

## Project Structure

```
secureaudit/
├── app.py                      # Streamlit dashboard
├── requirements.txt
├── README.md
├── scanner/
│   ├── __init__.py
│   ├── orchestrator.py         # Runs all scans
│   ├── firewall.py
│   ├── network.py
│   ├── remote_access.py
│   ├── windows_security.py
│   └── services.py
├── reporting/
│   ├── json_report.py
│   └── pdf_report.py
├── utils/
│   ├── models.py
│   ├── registry_helper.py
│   ├── risk_scorer.py
│   └── storage.py
└── data/                       # SQLite scan history (auto-created)
```

---

## Installation

### Prerequisites

- **Windows 10/11**
- **Python 3.10+** ([python.org](https://www.python.org/downloads/))
- Administrator privileges recommended for full registry/network visibility

### Setup

```powershell
cd "sec misconfig tool"
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### Run

```powershell
streamlit run app.py
```

Open the URL shown in the terminal (typically `http://localhost:8501`).

---

## Usage

1. Click **Run Security Scan**
2. Review the security score and risk level
3. Browse findings by category; expand evidence for audit details
4. Follow the **Recommendations** tab for remediation steps
5. Export **JSON** (for tooling/SIEM) or **PDF** (for reports)

---

## Resume / Portfolio Tips

- Screenshot the dashboard with a real scan on your VM
- Mention specific checks aligned with **CIS Benchmarks** and **MITRE ATT&CK** persistence (T1547)
- Highlight modular design, real Windows API usage, and structured reporting
- Optional next steps: scheduled scans, baseline diffing, export to STIX/CSV

---

## Security & Ethics

SecureAudit is intended for **authorized assessment of systems you own or have permission to test**. Do not deploy against systems without explicit authorization.

---

## License

MIT License — free to use, modify, and showcase in your portfolio.
