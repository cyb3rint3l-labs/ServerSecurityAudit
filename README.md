# 🛡️ Windows Server Security Audit (NIS2 Alignment)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-blue)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Server-lightgrey)](https://www.microsoft.com/en-us/windows-server)
[![NIS2 Ready](https://img.shields.io/badge/Compliance-NIS2%20EU-orange)](https://eur-lex.europa.eu/eli/dir/2022/2555/oj/eng)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-E62F25)](https://attack.mitre.org/)
[![CIS Controls](https://img.shields.io/badge/CIS%20Controls-v8-005D88)](https://www.cisecurity.org/controls/cis-controls-list)

## 📋 Overview

A modular PowerShell-based engine designed to perform deep security hygiene audits on Windows Server systems. It delivers actionable risk scoring mapped to **NIS2 Directive (Article 21)**, **MITRE ATT&CK**, and **CIS Controls v8**, generating forensic-ready HTML and JSON outputs.

The engine executes **30+ weighted checks** across 6 Strategic Domains covering 12 critical security disciplines to ensure a holistic defense-in-depth posture. 

It runs entirely offline, has no external dependencies or call home capabilities.

## ⚠️ Disclaimer

While designed to be non-intrusive, this script performs extensive WMI, Registry, and File System queries.
These operations may cause temporary CPU/Disk spikes or trigger EDR/Monitoring alerts.

## 🎯 Key Capabilities

* **🇪🇺 NIS2 Compliance Aligned:** Every check is mapped directly to Directive (EU) 2022/2555 articles (Vulnerability Handling, Risk Analysis, Basic Cyber Hygiene, Network Security, Access Control, Cryptography, Business Continuity).
* **📊 Risk-Based Scoring:** Prioritises vulnerabilities (Critical/Warning/Info) based on exploitability impact. Furthermore, findings are mapped to MITRE ATT&CK tactics and CIS Controls v8 practices.
* **🕵️ Sensitive Data Discovery:** Detects exposed credentials in user profiles and Inetpub locations in the form of filenames (e.g., "passwords.txt", "credentials.docx") across 15+ languages (🇬🇧 EN, 🇬🇷 GR, 🇩🇪 DE, 🇳🇱 DU, 🇫🇷 FR, 🇮🇹 IT, 🇪🇸 ES, 🇵🇹 PT, 🇵🇱 PL, 🇨🇿 CZ, 🇭🇺 HU, 🇷🇴 RO, 🇧🇬 BG & Nordic 🇸🇪🇳🇴🇩🇰🇫🇮🇮🇸) using Regex.
* **📝 Forensic-Ready Reporting:** Generates a self-contained HTML Dashboard and JSON datasets for ingestion with third-party toolset.
* **⚙️Compatibility**: Tested on Windows Server 2016, 2019, 2022, and 2025 (Desktop Experience), en-US Locale.

## 🖼️ Dashboard Overview

<p align="center">
<img src="https://github.com/user-attachments/assets/4d09add4-0a9e-4952-af5f-1f142a8e681a" width="100%" />
</p>

## 🖼️ Findings per domain

<p align="center">
<img src="https://github.com/user-attachments/assets/eee4f508-28f3-4a7c-80d6-30f7eff3e404" width="100%" />
</p>

## 🧩 Security Checks & Framework Mappings

**🚨 High-Impact Checks (Weight: 20 pts)**

Failure in these areas represents an **immediate compromise risk** (e.g., Ransomware, Data Breach, Man-in-the-Middle).

| # | Check Name | Security Impact / Rationale | Compliance Mapping |
| :--- | :--- | :--- | :--- |
| 01 | **OS Patching & Update Source** | Continuous Vulnerability Management | CIS Control 7 (IG1) |
| 02 | **RDP & NLA Status** | Ransomware Entry Vector | MITRE T1133 |
| 03 | **Credential Guard & LSA** | OS Credential Dumping Protection | MITRE T1003 |
| 04 | **Saved UNC Paths & Vault** | Lateral Movement Risk | MITRE T1552 |
| 05 | **Auth & Kerberos Hardening** | NTLM Relay / Kerberoasting Prevention | MITRE T1557/T1558 |
| 06 | **Firewall State & Logging** | Secure Network Configuration | CIS Control 4 (IG1) |
| 07 | **SMB Protocol Security** | Exploitation of Remote Services | MITRE T1210 |
| 08 | **LLMNR & mDNS Status** | Man-in-the-Middle / Responder | MITRE T1557 |
| 09 | **WPAD Status** | Traffic Interception Prevention | MITRE T1557 |
| 10 | **Endpoint Protection** | Malware Defenses (AV/EDR) | CIS Control 10 (IG1) |
| 11 | **Print Spooler Service** | Privilege Escalation (PrintNightmare) | MITRE T1068 |
| 12 | **Plaintext Password Files** | Unsecured Credentials Discovery | MITRE T1552 |
| 13 | **Drive Encryption (BitLocker)** | Data Protection at Rest | CIS Control 3 (IG1) |
| 14 | **Local Admin Group** | Least Privilege Enforcement | CIS Control 5 (IG1) |
| 15 | **Forensic Audit & Logging** | Defense Evasion Detection | MITRE T1562 |
| 16 | **VSS Writers Status** | Data Recovery & Ransomware Resilience | CIS Control 11 (IG1) |

📖 **Full Documentation:** For a complete list of all 30+ checks, weights, and technical details, please consult the **[Detailed Checks & Scoring Documentation](CHECKS.md)**.

## 🔐 Integrity Verification

Current Version (1.0.1) Hash (SHA-256):

6BCD6B9B821DC997A19F78D7B545EFFCCEACBEA9F66883BE4F47C716EDB3559D

Verify via PowerShell:

```powershell

(Get-FileHash .\ServerSecurityAudit.ps1 -Algorithm SHA256).Hash -eq "6BCD6B9B821DC997A19F78D7B545EFFCCEACBEA9F66883BE4F47C716EDB3559D"

```
---

**Author:** Konstantinos Xanthopoulos, Founder & Principal Consultant @ [Cyb3rint3l Labs](https://cyb3rint3l.tech)


