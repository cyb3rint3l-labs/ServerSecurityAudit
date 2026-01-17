# 📋 Audit Scope & Scoring Methodology

This document details the **30 security checks** performed by the **Cyb3rint3l Labs Security Hygiene Engine**.
Each check is assigned a specific **Weight** based on the risk it poses (Exploitability & Impact), aligned with **NIS2 Directive**, **MITRE ATT&CK**, and **CIS Controls v8**.

## ⚖️ Weighting System (Risk-Based)
Each check falls into one of three categories defining its maximum possible score:

| Impact Level | Weight | Description |
| :--- | :--- | :--- |
| **[!] HIGH IMPACT** | **20 pts** | **Immediate Compromise Risk.** Failure here indicates a high likelihood of Ransomware, Credential Theft, or Data Breach. |
| **[-] STANDARD** | **10 pts** | **Defense in Depth.** Essential hardening measures that reduce the attack surface but are not direct exploits. |
| **[/] LOWER IMPACT** | **5 pts** | **Optional Hardening.** Features that are optional by default but recommended (Specific to: SmartScreen Status). |

## 💯 Scoring Logic
The engine calculates the score based on compliance. The HTML report visualises non-compliance as a "point loss" to highlight the security impact.

| Status | Visual Impact | Backend Logic | Description |
| :--- | :--- | :--- | :--- |
| 🟢 **OK / Info** | **Full Score** | **100% Earned** | **Compliance verified**. Full weight added to score. |
| 🟠 **Warning** | **-50% Penalty** | **50% Earned** | **Partial compliance**. Only half the weight is awarded (e.g., -10 pts impact). |
| 🔴 **Critical** | **-100% Penalty** | **0% Earned** | **Security Gap.** The check fails completely. The full weight is forfeited (e.g., -20 pts displayed), significantly lowering the overall rating. |

**Final Score Calculation**: The total score is a percentage calculated by dividing the Total Points Earned by the Total Possible Points of all applicable checks. The result is normalised to a 0-100 scale. 

## 🔍 Detailed Checks by Domain

### 1. Patching & Maintenance
*NIS2 Alignment: Article 21(2)(e) - Security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure*

| Check Name | Weight | Compliance Mapping | Technical Check Logic |
| :--- | :--- | :--- | :--- |
| **OS Patching & Update Source** | 🔴 **20** | **CIS Control 7 (IG1)** | Checks patch age (<30 days OK, >90 Critical) and if Patch Management is used. |
| **Software Vulnerability (Winget)** | 🟠 10 | **CIS Control 2 + 7 (IG1)** | Uses `winget` to detect outdated third-party software and End-of-Life apps. |

### 2. Access Control & Identity Management
*NIS2 Alignment: Article 21(2)(i) - Human resources security, access control policies and asset management*

| Check Name | Weight | Compliance Mapping | Technical Check Logic |
| :--- | :--- | :--- | :--- |
| **RDP & NLA Status** | 🔴 **20** | **MITRE T1133** | Verifies if RDP is enabled and if Network Level Authentication (NLA) is enforced. |
| **Credential Guard & LSA** | 🔴 **20** | **MITRE T1003** | Checks for Credential Guard, LSA Protection (RunAsPPL), and WDigest status. |
| **Saved UNC Paths & Vault** | 🔴 **20** | **MITRE T1552** | Detects stored Windows Credentials (cmdkey) and mapped drive history. |
| **Auth & Kerberos Hardening** | 🔴 **20** | **MITRE T1557/T1558** | Checks `LmCompatibilityLevel` (NTLMv2) and Kerberos Encryption types (No RC4/DES). |
| **Local Admin Group Status** | 🔴 **20** | **CIS Control 5 (IG1)** | Alerts if excessive or unsafe users are members of the local `Administrators` group. |
| **Saved RDP Connections** | 🟠 10 | **MITRE T1021** | Scans user profiles for `.rdp` files with saved passwords or Registry MRU history. |
| **WinRM Security** | 🟠 10 | **CIS Control 4 (IG1)** | Checks if WinRM is running and if it uses secure listeners (HTTPS). |
| **User Account Control (UAC)** | 🟠 10 | **CIS Control 5 (IG1)** | Verifies `EnableLUA` is active and Admin Approval Mode is secure. |
| **LAPS Status** | 🟠 10 | **CIS Control 5 (IG1)** | Detects if Legacy or Modern LAPS (Local Admin Password Solution) is active. |
| **Local Admin Password Age** | 🟠 10 | **CIS Control 5 (IG1)** | Checks age of local admin password and "Password Never Expires" flag. |

### 3. Network Security & Attack Surface
*NIS2 Alignment: Article 21(2)(e) - Security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure*

| Check Name | Weight | Compliance Mapping | Technical Check Logic |
| :--- | :--- | :--- | :--- |
| **Firewall State & Logging** | 🔴 **20** | **CIS Control 4 (IG1)** | Ensures Firewall Profiles are active and `LogDroppedPackets` is enabled. |
| **SMB Protocol Security** | 🔴 **20** | **MITRE T1210** | Verifies that SMBv1 is strictly disabled to prevent EternalBlue exploits. |
| **LLMNR & mDNS Status** | 🔴 **20** | **MITRE T1557** | Checks if multicast name resolution protocols are disabled to prevent spoofing. |
| **WPAD Status** | 🔴 **20** | **MITRE T1557** | Checks if Web Proxy Auto-Discovery is disabled or mitigated (DNS/Hosts). |
| **NetBIOS over TCP/IP** | 🟠 10 | **MITRE T1557** | Checks if NetBIOS is explicitly disabled on network adapters. |
| **IPv6 Configuration** | 🟠 10 | **MITRE T1557** | Checks if IPv6 Router Advertisement (RA) is disabled to prevent SLAAC attacks. |
| **Remote Registry Status** | 🟠 10 | **CIS Control 4 (IG1)** | Verifies that the Remote Registry service is disabled. |

### 4. Endpoint & System Hardening
*NIS2 Alignment: Article 21(2)(g) - Basic cyber hygiene practices and cybersecurity training*

| Check Name | Weight | Compliance Mapping | Technical Check Logic |
| :--- | :--- | :--- | :--- |
| **Server Endpoint Protection** | 🔴 **20** | **CIS Control 10 (IG1)** | Checks for active Antivirus (Defender/3rd Party), Real-time protection, and signatures. |
| **Print Spooler Service** | 🔴 **20** | **MITRE T1068** | Alerts if Spooler is running on Domain Controllers (PrintNightmare risk). |
| **Unquoted Service Paths** | 🟠 10 | **MITRE T1574** | Detects services with spaces in their path that lack quotes (Privilege Escalation). |
| **PowerShell Execution Policy** | 🟠 10 | **MITRE T1059** | Verifies Policy is not `Unrestricted` or `Bypass`. Recommends `RemoteSigned`. |
| **SmartScreen Status** | 🔵 **5** | **CIS Control 9 (IG1)** | Checks if SmartScreen is enabled (Warn/Block). *Optional feature on Server OS.* |

### 5. Data Protection & Platform Integrity
*NIS2 Alignment: Article 21(2)(h) - Policies and procedures regarding the use of cryptography and, where appropriate, encryption*

| Check Name | Weight | Compliance Mapping | Technical Check Logic |
| :--- | :--- | :--- | :--- |
| **Drive Encryption Status** | 🔴 **20** | **CIS Control 3 (IG1)** | Checks if System Drive (C:) is encrypted (BitLocker or 3rd Party). |
| **Plaintext Password Files** | 🔴 **20** | **MITRE T1552** | Scans for filenames like `passwords.txt`, `credentials.docx` in 15+ languages. |
| **TPM & Secure Boot Status** | 🟠 10 | **MITRE T1542** | Verifies UEFI Secure Boot status and TPM chip presence/version. |

### 6. Business Continuity & Crisis Management
*NIS2 Alignment: Article 21(2)(c) - Business continuity, such as backup management and disaster recovery, and crisis management*

| Check Name | Weight | Compliance Mapping | Technical Check Logic |
| :--- | :--- | :--- | :--- |
| **Forensic Audit & Logging** | 🔴 **20** | **MITRE T1562 / CIS Control 8 (IG1)** | Checks for Process Creation, Command Line Auditing, and ScriptBlock logging. |
| **VSS Writers Status** | 🔴 **20** | **CIS Control 11 (IG1)** | Verifies VSS Writers are healthy and if a Backup (Event 2004) occurred recently. |
| **Time Synchronization (NTP)**| 🟠 10 | **CIS Control 8 (IG1)** | Checks `w32time` service, Stratum drift, and Time Source integrity. |
