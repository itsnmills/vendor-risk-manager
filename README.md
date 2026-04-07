# Healthcare Third-Party Vendor Risk Manager

**The first open-source healthcare vendor risk management platform.** Manage the full vendor lifecycle — intake, risk assessment, BAA tracking, annual verification, and compliance reporting — mapped to HIPAA, NIST CSF, and HITRUST.

Built for healthcare organizations that can't afford $15k+/year commercial tools like Censinet RiskOps or CORL Technologies, but still need to meet the 2025 HIPAA Security Rule requirements for business associate management.

## Why This Exists

- **41% of healthcare breaches** come from third-party vendors ([Censinet](https://censinet.com))
- The **2025 HIPAA Security Rule update** requires annual written verification from every business associate
- **Zero open-source alternatives** exist — organizations either pay enterprise prices or track vendors in spreadsheets
- Healthcare breach frequency **doubled in 2025** ([Fortified Health Security](https://fortifiedhealthsecurity.com))

## Features

### Vendor Lifecycle Management
- Full vendor lifecycle tracking: Prospect → Onboarding → Active → Review → Offboarding → Terminated
- Auto-classification into risk tiers (Critical / High / Medium / Low) based on PHI access, data volume, and assessment scores
- Support for 15 healthcare vendor types (EHR, Telehealth, Billing, Lab, Pharmacy, Medical Device MFG, etc.)
- Vendor dashboards with risk scores, BAA status, findings, and verification status

### Risk Assessment Engine
- **125 assessment questions** across 10 security domains
- Triple-mapped to **HIPAA Security Rule** (specific CFR references), **NIST CSF**, and **HITRUST CSF**
- **60 questions flagged as critical** for the new HIPAA mandatory requirements (MFA, encryption, 24-hour notification, etc.)
- Weighted scoring: Likelihood × Impact × Weight with domain-level and overall scores
- Auto-generated findings with severity, HIPAA references, and specific remediation recommendations

### Scoring Model
- **Inherent Risk** — Based on vendor characteristics (PHI access, data sensitivity, integration type, data volume)
- **Control Effectiveness** — From assessment responses across 10 domains
- **Residual Risk** — Inherent risk adjusted by control effectiveness
- **Trend Analysis** — Compare current vs. previous assessments (Improving / Stable / Declining)
- **Auto Tier Classification** — Vendors auto-classified into risk tiers based on residual risk

### BAA (Business Associate Agreement) Tracking
- Full BAA lifecycle: Draft → Review → Signature → Active → Renewal → Expired → Terminated
- **24-hour breach notification compliance check** (new HIPAA requirement)
- **24-hour contingency plan notification compliance check** (new HIPAA requirement)
- Subcontractor flow-down verification
- Expiration alerts with configurable warning windows
- Missing BAA detection for active vendors with PHI access

### Annual Verification Workflow
Implements the new HIPAA requirement for annual BA verification:
1. **Written verification** from business associate confirming technical safeguards are deployed
2. **Professional analysis** from a qualified professional
3. **Authorized representative certification**

All three must be present for verification to pass. Tracks overdue verifications and generates attestation reports.

### Professional PDF Reports
Four report types, all branded with professional design:
- **Vendor Risk Card** — One-page executive summary per vendor with risk gauge, domain scores, top findings
- **Executive Portfolio Report** — Multi-page org-wide view with KPI dashboard, risk distribution, heatmap, and recommendations
- **Annual Attestation Report** — HIPAA-required documentation with verification checklist and signature blocks
- **Remediation Tracker** — All open findings across vendors, sorted by severity and due date

### Assessment Domains (10)

| Domain | Questions | Focus Areas |
|--------|-----------|-------------|
| Access Control & Authentication | 20 | MFA, RBAC, session management, access reviews |
| Encryption & Data Protection | 15 | AES-256 at rest, TLS 1.2+ in transit, key management, DLP |
| Audit & Monitoring | 15 | Audit trails, 6-year retention, SIEM, real-time alerting |
| Incident Response & Breach | 15 | IR plan, 24-hour notification, forensics, post-incident review |
| Business Continuity & DR | 10 | RPO/RTO, backup testing, geographic redundancy |
| Physical & Environmental | 10 | Facility access, media disposal (NIST 800-88), device inventory |
| Vendor & Subcontractor Mgmt | 10 | Fourth-party risk, BAA flow-down, termination procedures |
| Workforce Security & Training | 10 | Background checks, phishing testing, security awareness |
| Vulnerability Management | 10 | Semi-annual scanning, annual pen testing, SBOM, patch SLAs |
| Network Security & Segmentation | 5 | Network segmentation, firewall rules, VPN, wireless security |

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the demo (generates 8 realistic healthcare vendors)
python run_vrm.py demo

# View the org-wide dashboard
python run_vrm.py dashboard

# List all vendors by risk
python run_vrm.py vendor list

# Generate executive portfolio PDF
python run_vrm.py report executive

# Generate a vendor risk card
python run_vrm.py report risk-card <vendor_id>

# Check BAA compliance alerts
python run_vrm.py baa alerts

# View verification status across all vendors
python run_vrm.py verify status
```

## All Commands

```
Vendor Management:
  vendor add                    Interactive vendor onboarding
  vendor list                   List all vendors by risk score
  vendor dashboard <id>         Full vendor dashboard
  vendor offboard <id>          Offboard a vendor

BAA Tracking:
  baa create <vendor_id>        Create new BAA interactively
  baa list                      List all BAAs with status
  baa alerts                    Show BAA alerts (expiring, missing, non-compliant)
  baa check <baa_id>            Check specific BAA compliance

Risk Assessment:
  assess <vendor_id>            Run interactive assessment
  assess quick <vendor_id>      Quick assessment with demo responses

Verification:
  verify request <vendor_id>    Create verification request
  verify submit <id>            Submit verification
  verify status                 Org-wide verification status

Reports (PDF):
  report risk-card <vendor_id>  Vendor risk card (1 page)
  report executive              Executive portfolio report
  report attestation <vendor_id> Annual attestation report
  report remediation            Remediation tracker

General:
  demo                          Generate demo organization
  dashboard                     Org-wide text dashboard
  alerts                        All actionable alerts
  export                        Export all data as JSON
  import <file.json>            Import data from JSON
```

## Demo Organization

The `demo` command generates **Midwest Family Health Partners** — a realistic mid-size healthcare practice with 8 vendors spanning the full risk spectrum:

| Vendor | Type | Score | Tier | Key Issue |
|--------|------|-------|------|-----------|
| Epic Systems | EHR Provider | 95.6 | LOW | Near-perfect compliance |
| LabCorp | Lab System | 92.2 | LOW | Minor physical security docs gap |
| MedTech Shredding | Destruction Service | 90.3 | LOW | Certificate tracking improvement needed |
| SecureRx Pharmacy | Pharmacy System | 74.3 | HIGH | IR and business continuity gaps |
| CloudMD Telehealth | Telehealth | 72.9 | HIGH | 72-hour breach notification (needs 24h) |
| MedBill Pro | Billing Service | 45.2 | CRITICAL | No MFA, shared credentials, no audit logging |
| ClearPath SmartSchedule | Cloud Service | 38.8 | CRITICAL | BAA unsigned, data leaves US |
| ChatGPT (Shadow AI) | Other | 13.3 | CRITICAL | No BAA possible, PHI exposed |

## Architecture

```
vendor-risk-manager/
├── run_vrm.py              # CLI entry point (1,539 lines)
├── requirements.txt
├── config.yaml             # Organization configuration
├── vrm/
│   ├── models.py           # 9 dataclasses, 16 enums (808 lines)
│   ├── db.py               # JSON file-based storage (479 lines)
│   ├── controls.py         # 125 HIPAA/NIST/HITRUST questions (1,751 lines)
│   ├── scoring.py          # Multi-dimensional risk scoring (475 lines)
│   ├── risk_engine.py      # Assessment orchestration (626 lines)
│   ├── vendor_manager.py   # Vendor lifecycle management (675 lines)
│   ├── baa_tracker.py      # BAA lifecycle & compliance (587 lines)
│   ├── verification.py     # Annual verification workflow (537 lines)
│   └── reports.py          # Professional PDF generation (2,467 lines)
├── demo/
│   └── demo_org.py         # Demo data generator (885 lines)
└── data/                   # JSON data files (auto-created)
```

**~11,500 lines of Python** | Zero external API dependencies | Runs fully offline

## HIPAA Security Rule 2025 Alignment

This tool specifically addresses the upcoming HIPAA Security Rule changes:

- **Mandatory MFA** — Assessment questions verify MFA deployment across all ePHI systems
- **Encryption requirements** — Checks AES-256 at rest and TLS 1.2+ in transit (no longer "addressable")
- **24-hour breach notification** — BAA tracker flags non-compliant notification windows
- **24-hour contingency notification** — Tracks and verifies contingency plan activation requirements
- **Annual compliance audit** — Assessment framework supports the new annual audit requirement
- **Semi-annual vulnerability scanning** — Questions verify scanning frequency compliance
- **Annual penetration testing** — Checks pen test recency and remediation tracking
- **BA verification** — Complete workflow for the new annual written verification requirement
- **6-year documentation retention** — Audit trail and report generation supports retention requirements

## Dependencies

- Python 3.10+
- reportlab (PDF generation)
- pyyaml (configuration)
- colorama (CLI colors)
- tqdm (progress bars)

No cloud services. No API keys. No database servers. Everything runs locally with JSON file storage.


---

## System Requirements

| Requirement | Details |
|---|---|
| **Python** | 3.10 or higher ([python.org](https://www.python.org/downloads/)) |
| **pip** | Included with Python — used to install dependencies |
| **Operating System** | Windows, macOS, or Linux |
| **Disk Space** | ~30 MB (including dependencies) |
| **RAM** | 256 MB minimum |
| **Network** | Not required — runs entirely offline |

### Installation

```bash
git clone https://github.com/itsnmills/vendor-risk-manager.git
cd vendor-risk-manager
pip install -r requirements.txt
```

### Dependencies

All dependencies are standard, widely-used Python packages:

| Package | What It Does | Why It's Needed |
|---|---|---|
| `reportlab` | PDF generation | Creates professional vendor risk cards, executive reports, attestation documents, and remediation trackers |
| `pyyaml` | YAML parsing | Reads the 125-question assessment definitions and configuration files |
| `tqdm` | Progress bars | Shows progress during assessment processing and report generation |
| `colorama` | Terminal colors | Color-coded risk levels and status indicators in CLI output |

---

## What This Tool Accesses On Your System

This tool runs 100% locally on your machine. Here is exactly what it reads, writes, and accesses:

| What | Access Type | Details |
|---|---|---|
| **Local JSON data files** | Read/Write | Vendor profiles, assessment responses, and BAA records are stored as JSON files in the project directory. You own these files completely. |
| **Local filesystem** | Write | PDF reports are saved to the `reports/` directory inside the project folder. |
| **No external APIs** | None | This tool makes zero outbound network requests. No vendor data, assessment results, or risk scores are sent anywhere. |
| **No telemetry** | None | No analytics, tracking, crash reporting, or phone-home behavior of any kind. |
| **No database server** | None | Data is stored in flat JSON files — no MySQL, PostgreSQL, or other database installation required. |

**In demo mode:** The tool generates 8 realistic but entirely fictional healthcare vendor profiles (fake company names, fake assessment scores, fake BAA details). No real vendor or organizational data is involved.

---

## Privacy & Open Source Transparency

**This is open-source software. You download it, you run it, you own it.**

| Concern | Answer |
|---|---|
| **Can the developer see my data?** | No. This tool runs entirely on your machine. The developer (or anyone else) has zero access to your data, your results, or your system. |
| **Does it phone home?** | No. There are no analytics, telemetry, crash reporting, update checks, or network calls of any kind. |
| **Is my data stored in the cloud?** | No. All data stays on your local machine in files you can inspect, move, back up, or delete at any time. |
| **Can I audit the code?** | Yes. Every line of source code is available in this repository. The MIT license gives you the right to use, modify, and distribute it. |
| **Is it safe to use with real organizational data?** | Yes — but as with any tool, follow your organization's data handling policies. Since everything runs locally, your data never leaves your control. |

> **If you're evaluating this tool for your organization:** Download it, review the source code, run the demo mode first, and verify for yourself that it meets your security requirements. That's the entire point of open source.

## Keeping Threat Intelligence & Regulatory Data Current

The 125 assessment questions are triple-mapped to:
- **HIPAA Security Rule** (45 CFR §164, including 2025 NPRM amendments)
- **NIST Cybersecurity Framework (CSF)**
- **HITRUST CSF**

60 questions are flagged for the new 2025 HIPAA mandatory requirements (MFA, encryption, 24-hour notification, etc.). These regulatory mappings are embedded in the source code. When regulations are updated, the repository will be updated accordingly:

```bash
git pull origin main
```

---

## Security

If you discover a security vulnerability in this tool, please report it responsibly by opening a GitHub issue or contacting the maintainer directly. Do not submit PHI or real patient data in bug reports.

## License

MIT License — Free for personal, commercial, and institutional use.

## Author

**Nathan Mills** — [VerifAI Security](https://github.com/itsnmills)

Part of the VerifAI Security healthcare cybersecurity toolkit:
- [HIPAA Risk Assessment Tool](https://github.com/itsnmills/hipaa-risk-assessment)
- [AI Governance Auditor](https://github.com/itsnmills/ai-governance-auditor)
- [Threat Intelligence Aggregator](https://github.com/itsnmills/verifai-threat-intel)
- [SOAR Engine](https://github.com/itsnmills/verifai-soar)
