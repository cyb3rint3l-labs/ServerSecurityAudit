# 🚦 Usage / Quick Start

1️⃣ Download the Script and save it to a folder of your choice.

2️⃣ Launch PowerShell as Administrator

3️⃣ Verify Script Integrity (Recommended)

```powershell

(Get-FileHash .\ServerSecurityAudit.ps1 -Algorithm SHA256).Hash -eq "AD30532F52BD4E1435228E9810452F49054F9EACAD660F2F2EEDDEF020463B6E"

```
4️⃣ Set Execution Policy (Recommended: RemoteSigned)

```powershell

Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

```
- Use RemoteSigned for standard execution on servers.

- Use Bypass only in restricted environments where policy modification is not permitted.

5️⃣ Run the Audit with its default settings

```powershell

.\ServerSecurityAudit.ps1

```
The script will create 3 files in this folder:

**"Server Security Audit Report-Cyb3rint3l Labs"**

- HTML (Dashboard)
- JSON (Machine-readable)
- TXT (Summary)

# **Troubleshooting**

❗**Cannot change Execution Policy**

(GPO‑locked or restricted environment)

You may see one of the following messages:

- “Execution Policy is set by Group Policy and cannot be changed.”

-  “The setting is overridden by a policy defined at a more specific scope.”

-  “Access to the registry key is denied.”

**Cause:**
The server’s Execution Policy is enforced (likely by Group Policy) and cannot be modified.

**Solution (one‑time execution):**

```powershell

powershell.exe -ExecutionPolicy Bypass -File .\ServerSecurityAudit.ps1

```

❗**Access denied**
 
Open PowerShell with "Run as Administrator".

❗**EDR alerts / CPU spikes**

The script performs intensive WMI, Registry, Event Log, and File System queries.
This is expected behavior in monitored environments.

Refer to the Disclaimer in the **[README](README.md)** file.
