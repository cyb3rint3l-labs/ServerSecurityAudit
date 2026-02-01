<#
.SYNOPSIS
	Windows Server Security Audit by Cyb3rint3l Labs.
	 
.DESCRIPTION
	A modular PowerShell-based engine designed to perform deep security hygiene audits on Windows Server systems. It delivers actionable risk scoring mapped to NIS2 Directive (Article 21), MITRE ATT&CK, and CIS Controls v8, generating forensic-ready HTML and JSON outputs.

	The engine executes 30+ weighted checks across 6 Strategic Domains covering 12 critical security disciplines to ensure a holistic defense-in-depth posture. It runs entirely offline, has no external dependencies or call home capabilities.

	1.Access Control & Identity Management
	2.Business Continuity & Crisis Management
	3.Data Protection & Platform Integrity
	4.Endpoint & System Hardening
	5.Network Security & Attack Surface Reduction
	6.Patching & Maintenance
	
	Key Features:
	- NIS2 Compliance Aligned: Every check is mapped directly to Directive (EU) 2022/2555 articles (Vulnerability Handling, Risk Analysis, Basic Cyber Hygiene, Network Security, Access Control, Cryptography, Business Continuity).
    - Risk-Based Scoring: Prioritises vulnerabilities (Critical/Warning/Info) based on exploitability impact. Additionally, findings are also mapped to MITRE ATT&CK tactics and CIS Controls v8 practices.
	- Sensitive Data Discovery: Detects exposed credentials in user profiles and Inetpub locations searching for filenames (e.g., "passwords.txt", "credentials.docx") across 15+ languages (EN, GR, DE, DU, FR, IT, ES, PT, PL, CZ, HU, RO, BG, and Nordic) using Regex.
    - Forensic-Ready Reporting: Generates detailed HTML dashboards and JSON datasets for ingestion with third-party toolset.
    - Compatibility: Tested on Windows Server 2016, 2019, 2022, and 2025 (Desktop Experience), en-US Locale.

    NIS2 Compliance Reference:
    All alignments are derived from the Official Journal of the European Union (Directive (EU) 2022/2555), published on 27 December 2022.

.PARAMETER ReportPath
	Target directory for report generation.
	Default is "C:\Server Security Audit Report-Cyb3rint3l Labs".
	
.PARAMETER SkipWinget
	Bypasses third-party software vulnerability checks.	
	
.PARAMETER JSONOnly
    Exports raw data only, skipping HTML generation.
	
.PARAMETER HTMLOnly
    Generates the dashboard report only, skipping the raw JSON data file.
	
.EXAMPLE
	# Run with default settings (Recommended)
	.\ServerSecurityAudit.ps1 
	
.EXAMPLE
    # Save report to a custom folder and skip Winget check
    .\ServerSecurityAudit.ps1 -ReportPath "C:\Audit\Q1-2026" -SkipWinget

.NOTES
    Name: ServerSecurityAudit.ps1
	Author: Konstantinos Xanthopoulos (Cyb3rint3l Labs)
	Role: Founder & Principal Consultant
	Web: https://cyb3rint3l.tech
    Version: 1.0.1
	LastUpdated: 2026-01-30
	License: Apache 2.0
  
	
	[!] DISCLAIMER: 
    While designed to be non-intrusive, this script executes extensive WMI, Registry, and 
    File System queries. These operations may cause temporary CPU/Disk spikes or trigger 
	EDR/Monitoring alerts.
	
   ----------------------------
   SCORING & RATING METHODOLOGY
   ----------------------------
    This engine utilises a "Weighted Risk Scoring" model aligned with CIS Controls v8 
    and the MITRE ATT&CK framework. It prioritises high‑impact vulnerabilities (Initial Access, 
    Credential Dumping, Lateral Movement) over general hardening items.

    1. WEIGHTING SYSTEM (Risk-Based Impact)
       Each check is assigned a weight based on its exploitability and potential impact:

       [!] HIGH IMPACT (Weight: 20 pts)
       Failure in these areas represent an immediate compromise risk 
	   (Ransomware, Man‑in‑the‑Middle, Data Breach).
       1.  OS Patching & Update Source ........ (CIS Control 7 (IG1): Continuous Vulnerability Management)
       2.  RDP & NLA Status ................... (MITRE T1133: Ransomware Entry Vector)
       3.  Credential Guard & LSA ............. (MITRE T1003: OS Credential Dumping)
       4.  Saved UNC Paths, Vault & Credentials (MITRE T1552: Lateral Movement Risk)
       5.  Authentication & Kerberos Hardening  (MITRE T1557/T1558: NTLM Relay / Kerberoasting)
       6.  Firewall State & Logging Status .... (CIS Control 4 (IG1): Secure Configuration)
       7.  SMB Protocol Security .............. (MITRE T1210: Exploitation of Remote Services)
       8.  LLMNR & mDNS Status ................ (MITRE T1557: Man-in-the-Middle / Responder)
       9.  WPAD Status ........................ (MITRE T1557: Traffic Interception)
       10. Server Endpoint Protection ......... (CIS Control 10 (IG1): Malware Defenses)
       11. Print Spooler Service .............. (MITRE T1068: Privilege Escalation / PrintNightmare)
       12. Plaintext Password Files ........... (MITRE T1552: Unsecured Credentials)
       13. Drive Encryption Status ............ (CIS Control 3 (IG1): Data Protection)
       14. Local Administrators Group Status .. (CIS Control 5 (IG1): Account Management)
       15. Forensic Audit & Logging ........... (MITRE T1562: Impair Defenses)
       16. VSS Writers Status (Data Recovery) . (CIS Control 11 (IG1): Data Recovery)

       [-] STANDARD IMPACT (Weight: 10 pts) - "Defense in Depth"
       Essential hardening measures that reduce the attack surface but are not direct exploits.
	   
	   [/] LOWER IMPACT (Weight: 5 pts) - "SmartScreen Status” check, as this feature is optional by default in Windows.

    2. SCORING LOGIC (Points Earned)
       - OK       : 100% of Weight (Full Compliance)
       - Info     : 100% of Weight (Neutral/Positive finding)
       - Warning  : 50%  of Weight (Partial Compliance / Mitigation required)
       - Critical : 0%   of Weight (Non-Compliant / Security Gap)
       - N/A      : Excluded from scoring (Does not dilute the score)

    3. GRADING SCALE
       A (90-100%) : COMPLIANT Hygiene (Aligned with Best Practices / NIS2 Compliant)
       B (80-89%)  : Good (Minor improvements recommended / NIS2 Compliant)
       C (65-79%)  : Average (Hardening required / NIS2 Partially Compliant)
       D (50-64%)  : Poor (Significant compliance drift / NIS2 Non-Compliant)
       F (0-49%)   : Critical Risk (Immediate remediation required / NIS2 Non-Compliant)
	   
	  Final Score Calculation: The total score is a percentage calculated by dividing the Total Points Earned by the Total Possible Points of all applicable checks. The result is normalised to a 0-100 scale.
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

#region 1. Configuration & Parameters

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, HelpMessage="The directory where reports will be saved.")]
    [ValidateNotNullOrEmpty()]
    [string]$ReportPath = "$env:SystemDrive\Server Security Audit Report-Cyb3rint3l Labs",

    [Parameter(Mandatory=$false, HelpMessage="Skip checking for software updates via Winget.")]
    [switch]$SkipWinget,
    
    [Parameter(Mandatory=$false, HelpMessage="Export ONLY the JSON data file (skips HTML generation).")]
    [switch]$JSONOnly,

    [Parameter(Mandatory=$false, HelpMessage="Export ONLY the HTML report (skips JSON generation).")]
    [switch]$HTMLOnly
)

$scriptVersion   = "1.0.1"  # Stable. Changed Firewall State & Logging Status check to correctly identify the "LogDroppedPackets" parameter. Changed the check for Local Admin Password Age to also consider custom local admins. Appended scoring to the JSON file as well.
$scriptStartTime = Get-Date
$timestamp = $scriptStartTime.ToString('yyyyMMdd_HHmm')

# --- CONFIGURATION & CONSTANTS ---
$NIS2RationaleMap = @{
    # Check 1, 29,
    "Patching & Maintenance"                          = 'Art. 21(2)(e) - Security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure.'

    # Check 5, 7, 9, 10, 11, 19, 2, 21, 23, 26
    "Access Control & Identity Management"            = 'Art. 21(2)(i) & (j) - Human resources security, access control policies and asset management & the use of multi-factor authentication or continuous authentication solutions, secured voice,
														video and text communications and secured emergency communication systems within the entity, where appropriate.'

    # Check 4, 6, 12, 13, 14, 24, 30
    "Network Security & Attack Surface Reduction"     = 'Art. 21(2)(a) & (g) - Policies on risk analysis and information system security & basic cyber hygiene practices and cybersecurity training.'

    # Check 3, 8, 15, 16, 20
    "Endpoint & System Hardening"					  = 'Art. 21(2)(g) - Basic cyber hygiene practices and cybersecurity training.'

    # Check 17, 18, 22
    "Data Protection & Platform Integrity"            = 'Art. 21(2)(h) - Policies and procedures regarding the use of cryptography and, where appropriate, encryption.'

    # Check 25, 27, 28
    "Business Continuity & Crisis Management"         = 'Art. 21(2)(c) - Business continuity, such as backup management and disaster recovery, and crisis management.'
}

#endregion

#region 2. Initialisation & Pre-flight Checks

if (-not (Test-Path $ReportPath)) { New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null }

$LogFile  = Join-Path $ReportPath "Audit_Log_$timestamp.txt"
$outHtml  = Join-Path $ReportPath "Audit_Report_$timestamp.html"
$outJson  = Join-Path $ReportPath "Audit_Data_$timestamp.json"

Start-Transcript -Path $LogFile -Append -IncludeInvocationHeader | Out-Null

$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning " [!] Administrator privileges required."
    Stop-Transcript | Out-Null; Break
}
#endregion

#region 3. Helper Functions

function New-Check {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Detail,
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string]$Fix,
        [Parameter(Mandatory)][string]$Category,
        [int]$Weight = 10
    )

    $maxPoints = $Weight
    $earned    = 0

    switch ($Status) {
        "OK"       { $earned = $maxPoints }
        "Info"     { $earned = $maxPoints }
        "Warning"  { $earned = $maxPoints / 2 }
        "Critical" { $earned = 0 }
        "N/A"      { $earned = 0; $maxPoints = 0 }
    }

    [PSCustomObject]@{
        Name        = $Name
        Result      = $Detail
        Status      = $Status
        Score       = $earned
        MaxScore    = $maxPoints
        Remediation = $Fix
        Category    = $Category
    }
}

function Get-UpdateSource {
    $WUSettings = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $props = Get-ItemProperty $WUSettings -ErrorAction SilentlyContinue
    
    $svcStart = (Get-Service -Name wuauserv -ErrorAction SilentlyContinue).StartType

    if ($props.WUServer) { 
        return "WSUS (Configured: $($props.WUServer))" 
    } 
    elseif ($props.DisableWindowsUpdateAccess -eq 1) { 
        return "Disabled (Group Policy)" 
    } 
    elseif ($svcStart -eq 'Disabled') { 
        return "Third-Party Agent (Service Disabled)" 
    } 
    
    return "Microsoft Update (Default)"
}

function Get-LastPatchInfo {
	
    try {
        $hf = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($hf) { 
            return [PSCustomObject]@{ Source='Get-HotFix'; Date=[datetime]$hf.InstalledOn; KB=$hf.HotFixID; Title=$hf.Description } 
        }
    } catch {}

    try {
        $session  = New-Object -ComObject 'Microsoft.Update.Session'
        $searcher = $session.CreateUpdateSearcher()
        $count    = $searcher.GetTotalHistoryCount()
        
        if ($count -gt 0) {
            $lastOK = $searcher.QueryHistory(0, [Math]::Min(50, $count)) | 
                      Where-Object { $_.Operation -eq 1 -and $_.ResultCode -eq 2 } | 
                      Sort-Object Date -Descending | Select-Object -First 1
            
            if ($lastOK) {
                $kb = if ($lastOK.Title -match '(KB\d+)') { $matches[1] } else { $null }
                return [PSCustomObject]@{ Source='WUA History'; Date=[datetime]$lastOK.Date; KB=$kb; Title=$lastOK.Title }
            }
        }
    } catch {}

    try {
        $ev = Get-WinEvent -LogName 'Microsoft-Windows-WindowsUpdateClient/Operational' -MaxEvents 200 -ErrorAction SilentlyContinue |
              Where-Object { $_.Id -eq 19 } | Sort-Object TimeCreated -Descending | Select-Object -First 1
        
        if ($ev) {
            $kb = if ($ev.Message -match '(KB\d+)') { $matches[1] } else { $null }
            return [PSCustomObject]@{ Source='Event Log'; Date=[datetime]$ev.TimeCreated; KB=$kb; Title="Update Installation" }
        }
    } catch {}

    return $null
}

#endregion

#region 4. Audit Execution

# Collect checks

$checks = @()

Write-Progress -Activity "Windows Server Security Audit" -Status " [1/6] Auditing Patching & Maintenance..." -PercentComplete 15

# =============================================================================
#region CATEGORY 1: PATCHING & MAINTENANCE
# =============================================================================

<#
# 1) OS Patching & Update Source Configuration
# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(e) - security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure.
# Mapped to: CIS Control 7 (Vulnerability Management)
# Risk: Unpatched OS vulnerabilities are the primary vector for Ransomware/Exploits.
# Logic:
# 1. Calculates 'Patch Age' by querying the latest installed HotFix or Windows Update Event.
# 2. Enforces Thresholds: OK (<30 days), Warning (30-90 days), Critical (>90 days).
# 3. Audits Update Source: Identifies if the server uses Managed Updates (WSUS/RMM) or Unmanaged (Default Microsoft).
# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
#>

try {
    $patchInfo = Get-LastPatchInfo
    $daysSincePatch = -1
    $recencyResult = "Could not determine last patch date (No WUA/HotFix/Event data)."
    $recencyStatus = "Warning"

    if ($patchInfo -and $patchInfo.Date) {
        $daysSincePatch = [int]((Get-Date) - $patchInfo.Date).TotalDays
        $recencyResult = "Last Patch: $($patchInfo.Date) (Age: $daysSincePatch days) | KB: $($patchInfo.KB)"
        
        if ($daysSincePatch -le 30) { $recencyStatus = "OK" }
        elseif ($daysSincePatch -le 90) { $recencyStatus = "Warning" }
        else { $recencyStatus = "Critical" }
    }

    $sourceResult = Get-UpdateSource
    $sourceStatus = if ($sourceResult -like "*WSUS*" -or $sourceResult -like "*Third-Party*") { "OK" } else { "Info" }
    
    $finalStatus = if ($recencyStatus -eq "Critical") { "Critical" } elseif ($recencyStatus -eq "Warning") { "Warning" } else { "OK" } 
    $finalDetail = "$recencyResult`nSource: $sourceResult"
    
    if ($finalStatus -eq "Critical") {
        $finalRemed = "URGENT: The OS hasn't been patched for over 90 days. This is a high-risk entry point for Ransomware and other threats. Execute emergency patching as a matter of priority."
    }
    elseif ($finalStatus -eq "Warning") {
        $finalRemed = "ATTENTION: System is falling behind on updates (30-90 days). Verify that the Windows Update service is running and apply pending updates."
    }
    else {
        if ($sourceStatus -eq "OK") {
            $finalRemed = "COMPLIANT: System is compliant and correctly managed via a centralized update source. Maintain this posture."
        } else {
            $finalRemed = "MAINTENANCE: The system is up-to-date; however, updates are delivered via the default, unmanaged update mechanism. Implementing centralised patch management would improve control, visibility, and reporting."
        }
    }

    $checks += New-Check "OS Patching & Update Source" $finalDetail $finalStatus $finalRemed "Patching & Maintenance" -Weight 20
} catch {
    $checks += New-Check "OS Patching & Update Source" "Error: $($_.Exception.Message)" "Critical" "Check permissions." "Patching & Maintenance" -Weight 20
}

<#
# 29) Software Vulnerability Status (Winget Audit)
# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(e) - security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure.
# Mapped to: CIS Control 2 (Software Inventory)
# Risk: Outdated third-party software is a common entry point for attackers.
# Logic:
# 1. Checks if 'Winget' (Windows Package Manager) is installed and available.
# 2. Runs 'winget list --upgrade-available' to detect installed software with pending security updates.
# 3. Flags Critical if high-risk / End-of-Life software is installed. Flags Warning if remote access tools or generic pending updates are detected.
# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
#>
try {
    $softwareIssues = @(); $riskCritical = $false; $riskRemote = $false; $updateCount = 0; $wingetStatus = "Not Installed"
    $critPatterns = "Adobe Flash|Java.*8|Python 2\.|uTorrent|BitTorrent|End of Life"
    $remotePatterns = "AnyDesk|TeamViewer|VNC|RealVNC|TightVNC|UltraVNC|TigerVNC"
    
    $installedApps = Get-ItemProperty @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion
    foreach ($app in $installedApps) {
        if ($app.DisplayName -match $critPatterns) {
            $softwareIssues += "[CRITICAL] $($app.DisplayName) (v$($app.DisplayVersion))"; $riskCritical = $true
        } elseif ($app.DisplayName -match $remotePatterns) {
            $softwareIssues += "[REMOTE-TOOL] $($app.DisplayName) (v$($app.DisplayVersion))"; $riskRemote = $true
        }
    }

    # Check Winget
    $hasWinget = (Get-Command "winget" -ErrorAction SilentlyContinue)
    if ($hasWinget -and -not $SkipWinget) {
        $wingetStatus = "Active"
        $wingetOutput = winget upgrade --include-unknown --accept-source-agreements 2>&1 | Out-String
        $lines = $wingetOutput -split "`n"
        $upgradableApps = $lines | Where-Object { $_ -match "\s+(\d+\.)+\d+\s+(\d+\.)+\d+" -and $_ -notmatch "ID|Name" }
        $updateCount = $upgradableApps.Count
        if ($updateCount -gt 0) { $softwareIssues += "Pending Updates via Winget: $updateCount" }
    } elseif ($SkipWinget) {
        $wingetStatus = "Skipped (User Request)"
    }

    $detail = "Winget: $wingetStatus"
    if ($riskCritical) { $status = "Critical"; $detail += " | ISSUES: " + ($softwareIssues -join ", ") }
    elseif ($riskRemote) { $status = "Warning"; $detail += " | DETECTED: " + ($softwareIssues -join ", ") }
    elseif ($updateCount -gt 0) { $status = "Warning"; $detail += " | Pending Updates: $updateCount" }
    elseif ($SkipWinget) { $status = "N/A"; $detail += " | Software Updates: Skipped via -SkipWinget" }
    elseif (-not $hasWinget) { $status = "N/A"; $detail += " | Software Updates: Unknown (Winget missing)" }
    else { $status = "OK"; $detail += " | System is clean and software appears to be updated." }

    if ($status -eq "Critical") { $finalRemed = "URGENT: High-risk or End-of-Life software detected. This violates security policies. Uninstall as a matter of priority to prevent exploitation." }
    elseif ($status -eq "Warning") {
        if ($riskRemote) { $finalRemed = "POLICY CHECK: Remote Access Tools detected (Shadow IT Risk). Verify if these tools are strictly authorised for business use." }
        else { $finalRemed = "MAINTENANCE: Third-party applications have pending updates. Execute a patching cycle via Winget or your Package Manager." }
    }
    elseif ($status -eq "Info" -or $status -eq "N/A") { $finalRemed = "ADVISORY: Winget is missing or skipped. Consider deploying a Package Manager for better visibility into third-party software risks." }
    else { $finalRemed = "COMPLIANT: No high-risk software or pending updates detected. Application inventory appears clean." }

    $checks += New-Check "Software Vulnerability Status" $detail $status $finalRemed "Patching & Maintenance"
} catch {
    $checks += New-Check "Software Vulnerability Status" "Error: $($_.Exception.Message)" "Info" "Check permissions." "Patching & Maintenance"
}
#endregion

Write-Progress -Activity "Windows Server Security Audit" -Status " [2/6] Auditing Access Control & Identity Management..." -PercentComplete 30

# =============================================================================
#region CATEGORY 2: ACCESS CONTROL & IDENTITY MANAGEMENT
# =============================================================================

<#
# 5) RDP Service & Network Level Authentication (NLA)
# --------------------------------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(i) - human resources security, access control policies and asset management.
# Mapped to: CIS Control 16 (Secure Remote Access) & MITRE T1133.
# Risk: RDP exposed without NLA is the most frequent initial access vector for Ransomware.
# Logic:
# 1. Checks 'fDenyTSConnections' registry key to see if RDP is Enabled/Disabled.
# 2. Checks 'UserAuthentication' registry key to verify if NLA is enforced.
# 3. Scoring: Weight 20 (Critical). Penalizes heavily if RDP is open without NLA.
# --------------------------------------------------------------------------------------------------------
#>
try {
    $rdpEnabled = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0
    $nlaEnabled = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication -eq 1
    $portCheck  = Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue

    if (-not $rdpEnabled) { $status = 'OK'; $detail = "RDP Service: Disabled" }
    elseif ($rdpEnabled -and -not $nlaEnabled) { $status = 'Critical'; $detail = "RDP: Enabled | NLA: Disabled (Insecure)" }
    else { $status = 'Warning'; $detail = "RDP: Enabled | NLA: Enabled (Secure Auth)" }
    
    if ($portCheck) { $detail += " | Port 3389: Listening" }

    if ($status -eq 'Critical') { $finalRemed = "URGENT: RDP is enabled without Network Level Authentication (NLA). This exposes the server to ransomware and brute-force attacks. Enable NLA as a matter of priority or disable RDP." }
    elseif ($status -eq 'Warning') { $finalRemed = "SECURITY NOTICE: RDP is enabled. While NLA is active, ensure Port 3389 is NOT exposed to the public Internet. Ideally, restrict access to specific management IPs or use a VPN." }
    else { $finalRemed = "COMPLIANT: Remote Desktop Service is disabled, significantly reducing the attack surface. Use alternative methods to connect such as console if needed." }

    $checks += New-Check 'RDP & NLA Status' $detail $status $finalRemed "Access Control & Identity Management" -Weight 20
} catch {
    $checks += New-Check 'RDP & NLA Status' "Error: $($_.Exception.Message)" 'Warning' 'Check Registry.' "Access Control & Identity Management" -Weight 20
}

<#
# 23) Saved RDP Connections (Files & History)
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(i) - human resources security, access control policies and asset management.
# Mapped to: NIS2 Art. 21(2)(g) - Basic cyber hygiene practices and cybersecurity training.
# Mapped to: MITRE T1021 (Remote Services) & T1082 (System Information Discovery).
# Risk: RDP history and .rdp files reveal critical targets (IPs) and usernames to attackers.
# Logic:
# 1. Scans Registry (Terminal Server Client\Default) for MRU (Most Recently Used) history.
# 2. Scans 'Documents' and 'Desktop' for .rdp files.
# 3. Flags Warning if connection history or configuration files are exposed.
# Note: Stored Credentials (cmdkey) are checked in Check 11 (Saved UNC Paths & Credentials (cmdkey)). This check focuses on files (.rdp) and History.
# ----------------------------------------------------------------------------------
#>
try {
    $rdpHits = @(); $targetPath = "$env:SystemDrive\Users"
    # Helper for byte matching (condensed)
    function Test-BytePattern { param($B,$P) if(!$B -or !$P -or $B.Length -lt $P.Length){return $false} for($i=0;$i-le $B.Length-$P.Length;$i++){$ok=$true;for($j=0;$j-lt$P.Length;$j++){if($B[$i+$j]-ne$P[$j]){$ok=$false;break}};if($ok){return $true}};$false }
    
    if (Test-Path $targetPath) {
        $files = Get-ChildItem -Path $targetPath -Recurse -Filter "*.rdp" -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\\AppData\\Local\\Temp\\' }
        foreach ($f in $files) {
            try { $b=[IO.File]::ReadAllBytes($f.FullName); $mk={param($e) @{P=$e.GetBytes("password 51:b:");U=$e.GetBytes("username:s:")}}; $a=&$mk([Text.Encoding]::ASCII); $l=&$mk([Text.Encoding]::Unicode)
            if((Test-BytePattern $b $a.P) -or (Test-BytePattern $b $l.P)) { $rdpHits += [PSCustomObject]@{FullName=$f.FullName;HasPwd=$true} }
            elseif((Test-BytePattern $b $a.U) -or (Test-BytePattern $b $l.U)) { $rdpHits += [PSCustomObject]@{FullName=$f.FullName;HasUser=$true} }
            } catch {}
        }
    }
    
    # Registry MRU check
    $mruUsers = (Get-ItemProperty "HKCU:\Software\Microsoft\Terminal Server Client\Default" -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object {$_.Name -match '^MRU\d+$'} | Select-Object -ExpandProperty Value

    $pwdFiles = $rdpHits | Where-Object HasPwd; $userFiles = $rdpHits | Where-Object HasUser
    
    if ($pwdFiles) {
        $status = "Critical"; $detail = "Critical: Found $($pwdFiles.Count) .rdp files with saved passwords: " + ($pwdFiles.FullName -join '; ')
        $finalRemed = "URGENT: .rdp files with embedded passwords detected. This allows unauthorised access without authentication. Delete these files as a matter of priority."
    } elseif ($userFiles -or $mruUsers) {
        $status = "Warning"; $detail = "RDP History found"
        if ($userFiles) { $detail += " | Files with Usernames: $($userFiles.Count)" }
        if ($mruUsers) { $detail += " | Registry MRU: " + ($mruUsers -join ', ') }
        $finalRemed = "SECURITY NOTICE: RDP connection history or files with saved usernames detected. This aids reconnaissance (Target Enumeration). Clear client history (MRU) and remove username references."
    } else {
        $status = "OK"; $detail = "No .rdp files with credentials or RDP history detected in User profiles."
        $finalRemed = "COMPLIANT: No saved RDP credentials or connection history found on this system. Client connection hygiene is maintained."
    }
    $checks += New-Check "Saved RDP Connections (Files)" $detail $status $finalRemed "Access Control & Identity Management"
} catch {
    $checks += New-Check "Saved RDP Connections (Files)" "Error: $($_.Exception.Message)" "Warning" "Check file access permissions." "Access Control & Identity Management"
}
<#
# 7) Windows Remote Management (WinRM) Security
# --------------------------------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(i) - human resources security, access control policies and asset management.
# Mapped to: CIS Control 4.
# Risk: Unencrypted remote management (HTTP) allows credential interception.
# Logic:
# 1. Detects if the WinRM Service is Running.
# 2. Inspects the WinRM Listener configuration to see if it listens on HTTP (5985) or HTTPS (5986).
# 3. Advises restricting access to management subnets if HTTP is detected.
# --------------------------------------------------------------------------------------------------------
#>
try {
    $svc = Get-Service WinRM -ErrorAction SilentlyContinue
    $listeners = if(Test-Path WSMan:\localhost\Listener){Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue} else {@()}
    $hasHTTP = ($listeners | Where-Object Keys -contains "Transport=HTTP"); $hasHTTPS = ($listeners | Where-Object Keys -contains "Transport=HTTPS")
    
    $detail = "Service: $($svc.Status)"; if ($hasHTTP) { $detail += " | Listener: HTTP" }; if ($hasHTTPS) { $detail += " | Listener: HTTPS" }
    
    if ($svc.Status -ne "Running") {
        $status = "OK"; $finalRemed = "COMPLIANT: WinRM service is not running, reducing the attack surface. Enable only if remote management is explicitly required."
    } elseif ($hasHTTP -and -not $hasHTTPS) {
        $status = "Warning"
        $finalRemed = "SECURITY NOTICE: Windows Remote Management (WinRM) is configured to accept connections over HTTP (TCP 5985) without transport-level encryption (default setting). This configuration increases exposure to credential relay, interception, and lateral movement attacks. Use HTTPS listeners and restrict access to authorised management IP ranges."
    } else {
        $status = "OK"
        $finalRemed = if ($hasHTTPS) { "SECURE: WinRM is configured with HTTPS. Ensure a valid certificate is maintained." } else { "MAINTENANCE: WinRM service is running. No insecure (HTTP) listeners were detected. Ensure HTTPS is configured if remote access is required." }
    }
    $checks += New-Check "Windows Remote Management (WinRM)" $detail $status $finalRemed "Access Control & Identity Management"
} catch {
    $checks += New-Check "Windows Remote Management (WinRM)" "Error: $_" "Info" "Check WinRM service." "Access Control & Identity Management"
}

<#
# 9) Credential Guard, LSA Protection & Wdigest
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(g) - Basic cyber hygiene practices and cybersecurity training.
# Mapped to: NIS2 Art. 21(2)(i) - human resources security, access control policies and asset management.
# Mapped to: MITRE T1003 (OS Credential Dumping)
# Risk: Prevents tools like Mimikatz from stealing cleartext secrets/hashes from LSASS memory.
# Logic:
# 1. Checks registry 'LsaCfgFlags' for RunAsPPL (LSA Protection).
# 2. Checks registry 'Lsa\DeviceGuard' for Credential Guard status (Virtualisation-based Security).
# 3. Also verifies if the insecure 'WDigest' protocol is disabled (preventing cleartext storage).
# ----------------------------------------------------------------------------------
#>
try {
    $cgRun = $false; try { $cgRun = (Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -Class Win32_DeviceGuard -ErrorAction Stop).SecurityServicesRunning -contains 1 } catch {}
    $lsaKey = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    $lsaStatus = if ($lsaKey.RunAsPPL -ge 1 -or $lsaKey.LsaCfgFlags -ge 1) { 'Enabled' } elseif ($lsaKey.LsaCfgFlags -eq 2) { 'Audit Mode' } else { 'Disabled' }
    $wdStatus = if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest' -ErrorAction SilentlyContinue).UseLogonCredential -eq 1) { 'Enabled (Insecure)' } else { 'Disabled (Secure)' }

    if ($wdStatus -like '*Insecure*') {
        $status = 'Critical'; $detail = "WDigest: ENABLED (Critical Risk) | LSA: $lsaStatus | CredGuard: $(if($cgRun){'On'}else{'Off'})"
        $finalRemed = "URGENT: WDigest is enabled! This allows tools like Mimikatz to extract cleartext passwords from memory. Set Registry 'UseLogonCredential' to 0 as a matter of priority."
    } elseif ($cgRun -and $lsaStatus -eq 'Enabled') {
        $status = 'OK'; $detail = "All Protections Active (CredGuard + LSA + WDigest Disabled)."
        $finalRemed = "COMPLIANT: OS credential dumping defenses are fully active. LSASS memory is hardened against extraction."
    } elseif ($lsaStatus -eq 'Disabled' -and -not $cgRun) {
        $status = 'Warning'; $detail = "LSA: Disabled | CredGuard: Off | WDigest: Disabled (OK)"
        $finalRemed = "SECURITY NOTICE: Modern credential protections are inactive. The LSASS process is exposed to dumping attacks. Enable LSA Protection (RunAsPPL) and Credential Guard via Group Policy."
    } else {
        $status = 'Info'; $detail = "WDigest: Disabled (OK) | LSA: $lsaStatus | CredGuard: $(if($cgRun){'On'}else{'Off'})"
        $missing = @(); if ($lsaStatus -ne 'Enabled') { $missing += "LSA Protection" }; if (-not $cgRun) { $missing += "Credential Guard" }
        $finalRemed = "ADVISORY: Partial protection detected. You are missing: $($missing -join ' & '). Consider enabling the full stack for defense-in-depth."
    }
    $checks += New-Check 'Credential Guard & LSA' $detail $status $finalRemed "Access Control & Identity Management" -Weight 20
} catch {
    $checks += New-Check 'Credential Guard & LSA' "Error: $($_.Exception.Message)" 'Warning' 'Verify admin privileges.' "Access Control & Identity Management" -Weight 20
}
<#
# 10) User Account Control (UAC) Configuration
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(i) - human resources security, access control policies and asset management.
# Mapped to: CIS Control 5.1 (Secure Configuration) & MITRE T1548.002 (Bypass UAC).
# Risk: UAC prevents unauthorised elevation of privileges by malware or users.
# Logic:
# 1. Checks 'EnableLUA' to verify if UAC is globally enabled.
# 2. Checks 'ConsentPromptBehaviorAdmin' to ensure administrators are prompted for consent (Level 2 or 5).
# 3. Flags Warning if UAC is disabled or set to auto-approve elevations.
# ----------------------------------------------------------------------------------
#>
try {
    $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    $ena = $uac.EnableLUA; $consent = $uac.ConsentPromptBehaviorAdmin
    
    if ($ena -eq 0) {
        $status = 'Critical'; $detail = "UAC Global: DISABLED (EnableLUA=0)"
        $finalRemed = "URGENT: User Account Control (UAC) is globally DISABLED. This allows malware to execute with administrative privileges silently. Set 'EnableLUA' to 1 as a matter of priority."
    } elseif ($consent -eq 0) {
        $status = 'Critical'; $detail = "UAC Global: Enabled | Admin Prompt: Silently Elevate (0)"
        $finalRemed = "URGENT: UAC is enabled but configured to 'Elevate without prompting'. This bypasses all protection. Configure Admin Consent Mode to 'Prompt on Secure Desktop'."
    } elseif ($consent -eq 2) {
        $status = 'OK'; $detail = "UAC Global: Enabled | Admin Prompt: Secure Desktop (2)"
        $finalRemed = "COMPLIANT: UAC is enabled and configured to 'Prompt on Secure Desktop'. This prevents unauthorised privilege escalation."
    } else {
        $status = 'Warning'; $detail = "UAC Global: Enabled | Admin Prompt: Custom/Default ($consent)"
        $finalRemed = "SECURITY NOTICE: UAC is active but not set to the highest security level (Prompt on Secure Desktop). Ensure this meets your organisation's hardening standards."
    }
    $checks += New-Check 'User Account Control (UAC)' $detail $status $finalRemed "Access Control & Identity Management"
} catch {
    $checks += New-Check 'User Account Control (UAC)' "Error: $($_.Exception.Message)" 'Warning' 'Check Registry.' "Access Control & Identity Management"
}
<#
# 11) Saved UNC Paths, Vault & Credentials (cmdkey/vaultcmd)
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(g) - Basic cyber hygiene practices and cybersecurity training.
# Mapped to: MITRE T1552 (Unsecured Credentials) & CIS Control 5.
# Risk: Stored Windows credentials allow attackers to move laterally without cracking passwords.
# Logic:
# 1. Runs 'cmdkey /list' to enumerate stored credentials in the current user's session.
# 2. Runs 'vaultcmd /list' to detect Web Credentials & Certificate Vaults.
# 3. Checks Registry/PSDrive for mapped drive history.
# 4. Critical if RDP credentials found; Warning if Web Creds or UNC history found
# ----------------------------------------------------------------------------------
#>
try {
    $cmdOutput = (cmdkey /list 2>$null | Out-String); $riskyCreds = @()
    if ($cmdOutput) { $cmdOutput -split "`n" | ForEach-Object { if ($_ -match "Target:\s*(.*)") { $t = $matches[1].Trim(); if ($t -match "TERMSRV|\\\\") { $riskyCreds += $t } } } }
    
    $uncPaths = @(); $drives = Get-PSDrive -PSProvider FileSystem -ErrorAction 0 | Where-Object DisplayRoot -like '\\*' | Select-Object -ExpandProperty DisplayRoot; if ($drives) { $uncPaths += $drives }
    if (Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU') { 
        $uncPaths += (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU' -EA 0).PSObject.Properties | Where-Object Name -match '^[a-z]$' | Select-Object -ExpandProperty Value 
    }
    
    $vaultsFound = @()
    $vRaw = (vaultcmd /list 2>$null | Out-String)
    if ($vRaw -and ($vRaw -split "Name:" | Where-Object { $_ -notmatch "MicrosoftAccount" -and $_ -match "Type:\s*(Windows Credential|Web Credential)" })) {
        $vaultsFound += "Generic/Web Vaults Detected"
    }

    $detailParts = @(); $status = 'OK'
    if ($riskyCreds) { $status = 'Critical'; $detailParts += "Stored CMD Credentials: [" + ($riskyCreds -join ", ") + "]" }
    if ($vaultsFound) { if ($status -eq 'OK') { $status = 'Warning' }; $detailParts += "Vaults Detected" }
    if ($uncPaths) { if ($status -eq 'OK') { $status = 'Warning' }; $detailParts += "UNC History: [" + ($uncPaths -join ", ") + "]" }
    
    $detail = if ($detailParts) { $detailParts -join " | " } else { "No stored credentials, dangerous vaults, or network map history found." }

    if ($status -eq 'Critical') { 
        $finalRemed = "URGENT: Stored Windows Credentials (RDP/SMB) detected! Attackers can use these to move laterally. Clear them as a matter of priority." 
    } elseif ($status -eq 'Warning') {
        if ($vaultsFound) { $finalRemed = "SECURITY NOTICE: Web/Windows Credentials found in Vault. This implies passwords saved in browsers/apps on this Server. Clear them using Credential Manager (control keymgr.dll)." }
        else { $finalRemed = "SECURITY NOTICE: Mapped drive history found. This reveals network structure to attackers. Clear mapped drive history via Registry to reduce the attack surface." }
    } else { 
        $finalRemed = "COMPLIANT: No stored credentials, web vaults, or network map history detected." 
    }

    $checks += New-Check 'Saved UNC Paths, Vault & Credentials' $detail $status $finalRemed "Access Control & Identity Management" -Weight 20
} catch {
    $checks += New-Check 'Saved UNC Paths, Vault & Credentials' "Error: $($_.Exception.Message)" 'Warning' 'Check cmdkey/registry access.' "Access Control & Identity Management" -Weight 20
}

<#
# 19) Local Administrator Password Solution (LAPS) Status
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(i) - human resources security, access control policies and asset management.
# Mapped to: CIS Control 5 & MITRE T1078 (Valid Accounts).
# Risk: LAPS prevents lateral movement by randomizing local admin passwords.
# Logic:
# 1. Detects Domain Controller role (Check Skipped/NA for DCs - handled differently).
# 2. Checks for Legacy LAPS (AdmPwd.dll).
# 3. Checks Modern Windows LAPS (Backup Target, Rotation, Encryption).
# 4. Flags Warning if LAPS is missing OR if Modern LAPS has weak config (No Encryption, >60 Days).
# ----------------------------------------------------------------------------------
#>
try {
    $hasLaps = $false; $details = @(); $weakConfig = $false
    
    if ((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -EA 0).AdmPwdEnabled -eq 1) { $hasLaps = $true; $details += "Classic LAPS: Enabled" }
    
    $winLaps = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS" -EA 0
    if ($winLaps.IsEnabled -eq 1) { 
        $hasLaps = $true; $details += "Modern LAPS: Enabled"
        if ($winLaps.PasswordAgeDays -gt 60) { $weakConfig = $true; $details += "[WEAK Rotation]" }
        if ($winLaps.PasswordEncryptionRequired -eq 0) { $weakConfig = $true; $details += "[WEAK Encryption]" }
    }

    $sys = Get-CimInstance Win32_ComputerSystem
    $isDC = ($sys.DomainRole -ge 4); $isDomain = $sys.PartOfDomain

    if ($hasLaps) {
        if ($weakConfig) { 
            $status = "Warning"
            $remed = "SECURITY NOTICE: Modern LAPS is enabled but configured weakly. Issues detected: Encryption is OFF or Rotation period is too long (>60 days). Review GPO settings." 
        } else { 
            $status = "OK"
            $remed = "COMPLIANT: Local Administrator Password Solution (LAPS) is active and securely configured. Local admin passwords are randomised." 
        }
    } else {
        if ($isDC) { 
            $status = "N/A"
            $remed = "INFO: System is a Domain Controller. Standard LAPS is generally used for Member Servers/Workstations. Ensure DSRM password is rotated regularly." 
        } elseif (-not $isDomain) {
            $status = "Info"
            $remed = "ADVISORY: System is in a Workgroup. LAPS requires an Active Directory or Intune environment. Ensure the local admin password is strong and unique."
        } else {
            $status = "Warning"
            $remed = "SECURITY NOTICE: LAPS is not detected on this domain-joined server. If local admin passwords are static and shared, attackers can move laterally easily. Deploy Windows LAPS via GPO."
        }
    }
    
    $finalDetail = if ($details) { $details -join " | " } else { "No LAPS detected." }
    if ($isDC -and -not $hasLaps) { $finalDetail += " (Domain Controller - Check N/A)" }

    $checks += New-Check "LAPS (Local Administrator Password Solution) Status" $finalDetail $status $remed "Access Control & Identity Management"
} catch {
    $checks += New-Check "LAPS (Local Administrator Password Solution) Status" "Error: $($_.Exception.Message)" "Info" "Verify registry." "Access Control & Identity Management"
}

<#
# 2) Local Administrator Password Age
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(i) - human resources security, access control policies and asset management.
# Mapped to: CIS Control 5.
# Risk: Static local admin passwords are a major security risk if not managed by LAPS.
# Logic:
# 1. Detects Domain Controller role (Check Skipped/NA for DCs).
# 2. Identifies Built-in Administrator via SID (Renaming/Disabled Check).
# 3. Detects LAPS presence
# 4. Flags Warning if:
#    - Password Age > 365 days,
#    - 'PasswordNeverExpires' flag is set (Serious Risk).
# 5. Highlights Account Expiration as a positive finding.
# ----------------------------------------------------------------------------------
#>
try {
    $isDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
    if ($isDC) { 
        $checks += New-Check "Local Administrator Password Age" "(Domain Controller - Check N/A)" "N/A" "INFO: System is a Domain Controller. Ensure DSRM password is rotated periodically." "Access Control & Identity Management" 
    } else {
        
        $laps = ((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -EA 0).AdmPwdEnabled -eq 1) -or ((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS" -EA 0).IsEnabled -eq 1)
        
        $users = Get-LocalUser -ErrorAction SilentlyContinue
        $risky = @()
        $activeAccounts = @()
        
        $builtInName = "Unknown"
        $builtInEnabled = $false

        foreach($u in $users) {
           
            if ($u.SID -match "-500$") { 
                $builtInName = $u.Name
                $builtInEnabled = $u.Enabled 
            }
           
            elseif ($u.Enabled) {
                $activeAccounts += $u.Name
            }

        
            if ($u.Enabled) {
                if ($u.PasswordNeverExpires) { 
                    $risky += "$($u.Name) [NEVER EXPIRES]" 
                }
                elseif ($u.PasswordLastSet -and ((Get-Date) - $u.PasswordLastSet).TotalDays -gt 365) { 
                    $risky += "$($u.Name) [>365d]" 
                }
            }
        }
        
  
        $detail = "Built-in: $builtInName (Enabled: $builtInEnabled)"
        
        if ($activeAccounts.Count -gt 0) {
            $detail += " | Other Active Users Checked: " + ($activeAccounts -join ", ")
        }
        
        if ($risky) { 
            $detail += " | RISKY ACCOUNTS: " + ($risky -join ", ") 
        }
        
   
        if ($detail -match "NEVER EXPIRES") { 
            $status = "Warning"
            $remed = "SECURITY NOTICE: Detected accounts configured with 'Password Never Expires'. Disable this flag immediately." 
        } elseif ($detail -match ">365d") { 
            $status = "Warning"
            $remed = "SECURITY NOTICE: Active accounts have stale passwords (>1 year). Rotate them or deploy LAPS."
        } else { 
            $status = "OK"
            if (-not $builtInEnabled) {
        
                $remed = "EXCELLENT: Built-in Administrator is Disabled. Active accounts ($($activeAccounts -join ', ')) adhere to rotation policies."
            } else {
                $remed = "MAINTENANCE: Built-in Administrator is enabled but password hygiene is good. Consider disabling it in favor of a custom admin."
            }
        }
        
        $checks += New-Check "Local Administrator Password Age" $detail $status $remed "Access Control & Identity Management"
    }
} catch {
    $checks += New-Check "Local Administrator Password Age" "Error checking users" "Info" "Verify permissions." "Access Control & Identity Management"
}
<#
# 21) Local Administrators Group Status (Principle of Least Privilege)
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(i) - human resources security, access control policies and asset management.
# Mapped to: CIS Control 5.4 (Restrict Administrator Privileges).
# Risk: Excessive members in the local 'Administrators' group increase the attack surface.
# Logic:
# 1. Detects Domain Controller role (Check Skipped/NA for DCs).
# 2. Enumerates members of the local 'Administrators' group.
# 3. Flags Warning/Critical if:
#    - No break-glass admin exists (lockout risk),
#    - Built-in admin is still enabled,
#    - Too many custom admins,
#    - AzureAD accounts are local admins in hybrid environments.
# ----------------------------------------------------------------------------------
#>
try {
    $isDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
    if ($isDC) {
        $checks += New-Check "Local Administrators Group Status (Principle of Least Privilege)" "(Domain Controller - Check N/A)" "N/A" "INFO: Privileged access on DCs controls the entire domain. Audit 'Domain Admins', 'Enterprise Admins', and 'Administrators' groups in AD." "Access Control & Identity Management" -Weight 20
    } else {
        $members = Get-LocalGroupMember -Name 'Administrators' -ErrorAction SilentlyContinue
        if (-not $members) { $members = @() }

        $adm500 = $members | Where-Object { $_.SID.Value -match "-500$" }
        $builtInEnabled = $false
        if ($adm500) { try { if ((Get-LocalUser -SID $adm500.SID.Value -EA 0).Enabled) { $builtInEnabled = $true } } catch {} }

        $exemptSids = "-500$|-501$|-512$|S-1-5-18|S-1-5-19|S-1-5-20"
        $riskyPrincipals = $members | Where-Object { 
            $_.SID.Value -notmatch $exemptSids -and 
            $_.Name -notmatch '\$$|^Window Manager' 
        }
        
        $azAdmins = $riskyPrincipals | Where-Object { $_.Name -match "^AzureAD\\" -or $_.SID.Value -match "^S-1-12-1-" }

        if ($riskyPrincipals.Count -eq 0) {
            if ($builtInEnabled) {
                $status = "Warning"; $detail = "Only the Built-in Administrator (SID -500) is present and ENABLED."
                $remed = "SECURITY NOTICE: You are relying on the generic Built-in Administrator. Best practice: 1) Create a named 'Break-glass' account. 2) Disable the Built-in Administrator."
            } else {
                $status = "Critical"; $detail = "LOCKOUT RISK: Built-in Administrator is Disabled and NO other local admins found."
                $remed = "URGENT: If domain trust fails, you have NO local access! The built-in admin is disabled and no other local admin exists. Create a 'Break-glass' local admin as a matter of priority."
            }
        } elseif ($riskyPrincipals.Count -eq 1) {
            $accName = $riskyPrincipals[0].Name
            if (-not $builtInEnabled) {
                $status = "OK"; $detail = "Secure Configuration: Built-in Admin Disabled. 1 Custom Break-glass account: [$accName]."
                $remed = "COMPLIANT: Local administrator configuration is optimal (1 Custom Break-glass account, Built-in Disabled)."
            } else {
                $status = "Warning"; $detail = "Redundant Access: Built-in Admin is ENABLED plus 1 custom admin: [$accName]."
                $remed = "MAINTENANCE: Disable the Built-in Administrator (SID -500) to reduce attack surface, relying solely on the custom break-glass account [$accName]."
            }
        } else {
            $status = "Critical"; $detail = "Excessive Privileges: Found $($riskyPrincipals.Count) custom admins: " + ($riskyPrincipals.Name -join ", ")
            $remed = "SECURITY NOTICE: Too many local administrators violated 'Least Privilege'. Reduce membership to exactly one well-controlled break-glass account."
        }

        if ($azAdmins) { 
            $azNames = ($azAdmins.Name -join ", ")
            $detail += " [Includes AzureAD: $azNames]"
            $remed += " NOTE: AzureAD accounts detected ($azNames). Review if these specific users truly require permanent local admin rights." 
        }

        $checks += New-Check "Local Administrators Group Status (Principle of Least Privilege)" $detail $status $remed "Access Control & Identity Management" -Weight 20
    }
} catch {
    $checks += New-Check "Local Administrators Group Status (Principle of Least Privilege)" "Error checking members" "Warning" "Check permissions." "Access Control & Identity Management" -Weight 20
}

<#
# 26) Authentication & Kerberos Hardening
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(i) - human resources security, access control policies and asset management,
# Mapped to: CIS Control 4 & MITRE T1558 (Steal or Forge Kerberos Tickets).
# Risk: Weak protocols (NTLMv1, RC4, DES) allow credential theft via Relay/Kerberoasting,
# - Long ticket lifetimes facilitate Replay Attacks.
# Logic:
# 1. NTLM: Checks 'LmCompatibilityLevel' (Must be 5) & 'AuditNTLMInDomain'.
# 2. Kerberos: Checks 'SupportedEncryptionTypes', 'AllowWeakCrypto', and Ticket Lifetimes.
# 3. KRBTGT: Checks password age on Domain Controllers.
# ----------------------------------------------------------------------------------
#>
try {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $lmComp = (Get-ItemProperty $lsa -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
    $ntlmTxt = if ($lmComp -eq 5) { "Hardened (Level 5)" } elseif ($lmComp -lt 5 -and $lmComp) { "Weak (Level $lmComp)" } else { "Default" }
    
    $aud = (Get-ItemProperty "$lsa\MSV1_0" -Name "AuditNTLMInDomain" -ErrorAction SilentlyContinue).AuditNTLMInDomain
    $audTxt = if ($aud) { "[Auditing: ON]" } else { "[Auditing: OFF]" }

    $kerbEnc = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name "SupportedEncryptionTypes" -ErrorAction SilentlyContinue).SupportedEncryptionTypes
    if ($null -eq $kerbEnc) { $kerbEnc = (Get-ItemProperty "$lsa\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -ErrorAction SilentlyContinue).SupportedEncryptionTypes }
    
    $weakCryp = (Get-ItemProperty "$lsa\Kerberos\Parameters" -Name "AllowWeakCrypto" -ErrorAction SilentlyContinue).AllowWeakCrypto

    $kerbTxt = "Default (RC4 Risk)"
    if ($kerbEnc -band 0x3) { $kerbTxt = "Critical (DES Enabled)" } elseif ($kerbEnc -band 0x4) { $kerbTxt = "Weak (RC4 Enabled)" } elseif ($kerbEnc -band 0x10) { $kerbTxt = "Hardened (AES Only)" }
    if ($weakCryp -eq 1) { $kerbTxt += " | AllowWeakCrypto: ON (Risk)" }

    $krbInfo = ""; if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { try { $res = ([adsisearcher]"(samaccountname=krbtgt)").FindOne(); if($res){ $d=[int]((Get-Date)-[datetime]::FromFileTime($res.Properties["pwdlastset"][0])).TotalDays; $krbInfo=" | KRBTGT Age: $d days" } } catch {} }

    $ntlmRisk = if ($lmComp -lt 5) { "Critical" } else { "OK" }

    $kerbRisk = if (($kerbEnc -band 0x1) -or ($kerbEnc -band 0x2) -or ($kerbEnc -band 0x4) -or ($weakCryp -eq 1)) { "Critical" } elseif ($null -eq $kerbEnc) { "Warning" } else { "OK" }
    
    $status = if ($ntlmRisk -eq 'Critical' -or $kerbRisk -eq 'Critical') { "Critical" } elseif ($ntlmRisk -eq 'Warning' -or $kerbRisk -eq 'Warning') { "Warning" } else { "OK" }
    $detail = "NTLM: $ntlmTxt $audTxt | Kerberos: [Enc: $kerbTxt]$krbInfo"
	
    if ($status -eq "Critical") { 
        $finalRemed = "URGENT: Critical authentication weakness detected! Actions required: Set LmCompatibilityLevel=5 and Disable RC4/DES for Kerberos. These vulnerabilities allow Credential Relay or Golden Ticket attacks." 
    }
    elseif ($status -eq "Warning") { 
        $finalRemed = "SECURITY NOTICE: Authentication settings rely on OS defaults (Likely RC4 allowed). Explicitly enforce NTLMv2-only and disable legacy ciphers (RC4/DES) via Group Policy." 
    }
    else { 
        $finalRemed = "COMPLIANT: Authentication is fully hardened. NTLMv2 is enforced, Kerberos uses AES encryption (No DES/RC4), and KRBTGT is fresh." 
    }

    $checks += New-Check "Authentication & Kerberos Hardening" $detail $status $finalRemed "Access Control & Identity Management" -Weight 20
} catch { 
    $checks += New-Check "Authentication & Kerberos Hardening" "Error reading policies" "Warning" "Check Registry permissions." "Access Control & Identity Management" -Weight 20 
}
#endregion

Write-Progress -Activity "Windows Server Security Audit" -Status " [3/6] Auditing Network Security & Attack Surface Reduction..." -PercentComplete 50

# =============================================================================
#region CATEGORY 3: NETWORK SECURITY & ATTACK SURFACE REDUCTION
# =============================================================================

<#
# 4) Windows Firewall Status & Logging Check (Context Aware)
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(e) - security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure.
# Mapped to: NIS2 Art. 21(2)(g) - Basic cyber hygiene practices and cybersecurity training.
# Mapped to: CIS Control 4 (Secure Configuration of Enterprise Assets and Software) + 13 ( Network Monitoring and Defense) & MITRE T1562 (Impair Defenses).
# Risk: A disabled firewall or disabled logging blinds security teams during an incident.
# Logic:
# 1. Inspects all 3 Firewall Profiles (Domain, Private, Public).
# 2. Verifies if the Firewall is 'Enabled'.
# 3. Verifies if 'LogDroppedPackets' is enabled (Crucial for forensics).
# 4. Flags Critical (Weight 20) if Firewall is OFF.
# ----------------------------------------------------------------------------------
#>
try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    $disabled = $profiles | ? { !$_.Enabled }
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
    $map = @{ Domain="DomainProfile"; Private="StandardProfile"; Public="PublicProfile" }

    $noLog = $map.Keys | ? {
        $key = "$regPath\$($map[$_])\Logging"
        $val = Get-ItemProperty $key -ErrorAction SilentlyContinue
        !$val -or $val.LogDroppedPackets -ne 1
    }

    if ($disabled) {
        $status, $detail = "Critical", "Firewall disabled on: $($disabled.Name -join ', ')"
        $remed = "URGENT: One or more firewall profiles are disabled. Enable all profiles via Group Policy or PowerShell."
    }
    elseif ($noLog) {
        $status, $detail = "Warning", "Dropped packet logging missing on: $($noLog -join ', ')"
        $remed = "NOTICE: Firewall is enabled but logging is disabled.Enable dropped packet logging for forensic and incident response visibility."
    }
    else {
        $status, $detail = "OK", "Firewall enabled and logging active on all profiles."
        $remed = "COMPLIANT: Host firewall and logging are correctly configured."
    }

 $checks += New-Check "Firewall State & Logging Status" $detail $status $remed "Network Security & Attack Surface Reduction" -Weight 20
} catch { 
    $checks += New-Check "Firewall State & Logging Status" "Error: $($_.Exception.Message)" "Info" "Check permissions." "Network Security & Attack Surface Reduction" -Weight 20 
}

<#
# 6) NetBIOS over TCP/IP Status
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(e) - security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure.
# Mapped to: NIS2 Art. 21(2)(g) - Basic cyber hygiene practices and cybersecurity training.
# Mapped to: MITRE T1187 (Forced Authentication).
# Risk: NetBIOS is a legacy protocol vulnerable to spoofing (NBT-NS) and poisoning.
# Logic:
# 1. Queries all network adapters via WMI/CIM (Win32_NetworkAdapterConfiguration).
# 2. Checks 'TcpipNetbiosOptions': Value '2' means Disabled (Secure).
# 3. Flags Warning if NetBIOS is enabled (0 or 1).
# ----------------------------------------------------------------------------------
#>
try {
    $risky = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" -ErrorAction Stop | Where-Object { $_.TcpipNetbiosOptions -ne 2 }
    
    if ($risky) {
        $status = "Warning"

        $names = $risky | ForEach-Object { $_.Description }
        $detail = "NetBIOS Enabled on $($risky.Count) adapters: " + ($names -join ", ")
        
        $finalRemed = "SECURITY NOTICE: NetBIOS over TCP/IP is enabled. This legacy name-resolution mechanism can be abused for NBT-NS poisoning attacks, potentially leading to credential interception. If internal DNS is in use, NetBIOS should be disabled on network adapters or centrally via DHCP options."
    } else {
        $status = "OK"; $detail = "NetBIOS Disabled"
        $finalRemed = "COMPLIANT: NetBIOS over TCP/IP is explicitly disabled. This eliminates the NBT-NS spoofing attack vector."
    }
    $checks += New-Check "NetBIOS over TCP/IP" $detail $status $finalRemed "Network Security & Attack Surface Reduction"
} catch {
    $checks += New-Check "NetBIOS over TCP/IP" "Error: $($_.Exception.Message)" "Warning" "Check CIM/WMI." "Network Security & Attack Surface Reduction"
}

<#
# 6) NetBIOS over TCP/IP Status
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(e) - security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure.
# Mapped to: NIS2 Art. 21(2)(g) - Basic cyber hygiene practices and cybersecurity training.
# Mapped to: MITRE T1187 (Forced Authentication).
# Risk: NetBIOS is a legacy protocol vulnerable to spoofing (NBT-NS) and poisoning.
# Logic:
# 1. Queries all network adapters via WMI/CIM (Win32_NetworkAdapterConfiguration).
# 2. Checks 'TcpipNetbiosOptions': Value '2' means Disabled (Secure).
# 3. Flags Warning if NetBIOS is enabled (0 or 1).
# ----------------------------------------------------------------------------------
#>
try {
    $risky = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" -ErrorAction Stop | Where-Object { $_.TcpipNetbiosOptions -ne 2 }
    
    if ($risky) {
        $status = "Warning"

        $names = $risky | ForEach-Object { $_.Description }
        $detail = "NetBIOS Enabled on $($risky.Count) adapters: " + ($names -join ", ")
        
        $finalRemed = "SECURITY NOTICE: NetBIOS over TCP/IP is enabled. This legacy name-resolution mechanism can be abused for NBT-NS poisoning attacks, potentially leading to credential interception. If internal DNS is in use, NetBIOS should be disabled on network adapters or centrally via DHCP options."
    } else {
        $status = "OK"; $detail = "NetBIOS Disabled"
        $finalRemed = "COMPLIANT: NetBIOS over TCP/IP is explicitly disabled. This eliminates the NBT-NS spoofing attack vector."
    }
    $checks += New-Check "NetBIOS over TCP/IP" $detail $status $finalRemed "Network Security & Attack Surface Reduction"
} catch {
    $checks += New-Check "NetBIOS over TCP/IP" "Error: $($_.Exception.Message)" "Warning" "Check CIM/WMI." "Network Security & Attack Surface Reduction"
}

<#
# 12) SMB Protocol Versions (SMBv1 Audit)
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(e) - security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure.
# Mapped to: NIS2 Art. 21(2)(g) - Basic cyber hygiene practices and cybersecurity training.
# Mapped to: MITRE T1210 (Exploitation of Remote Services) & CIS Control 4.8.
# Risk: SMBv1 is obsolete and famously vulnerable to EternalBlue (WannaCry).
# Logic:
# 1. Checks 'SMB1' Registry key in CurrentControlSet\Services\LanmanServer.
# 2. Verifies if SMBv2/v3 is enabled as the preferred protocol.
# 3. Flags Critical (Weight 20) if SMBv1 is found Active.
# ----------------------------------------------------------------------------------
#>
try {
    $c = Get-SmbServerConfiguration -ErrorAction Stop
    $s1 = $c.EnableSMB1Protocol; $s2 = $c.EnableSMB2Protocol
    
    $detail = "SMBv1: $(if($s1){'Enabled'}else{'Disabled'}) | SMBv2/v3: $(if($s2){'Enabled'}else{'Disabled'})"

    if ($s1) {
        $status = "Critical"
        $remed = "URGENT: SMBv1 is ENABLED. This obsolete protocol is the primary vector for ransomware like WannaCry (EternalBlue exploit). Disable it as a matter of priority using 'Set-SmbServerConfiguration -EnableSMB1Protocol `$false'."
    } elseif (-not $s2) {
        $status = "Warning"
        $remed = "MAINTENANCE: SMBv2/v3 protocol is disabled. While this prevents SMBv1 attacks, it breaks file sharing for modern clients. Enable SMBv2/v3 unless this is a hardened standalone system."
    } else {
        $status = "OK"
        $remed = "COMPLIANT: SMBv1 is disabled, eliminating the EternalBlue attack surface. SMBv2/v3 is active for secure communication."
    }
    
    $checks += New-Check "SMB Protocol Security" $detail $status $remed "Network Security & Attack Surface Reduction" -Weight 20
} catch {
    $checks += New-Check "SMB Protocol Security" "Error: Verify manually (Cmdlet failed)" "Warning" "Check SMBv1 Registry." "Network Security & Attack Surface Reduction" -Weight 20
}

<#
# 13) LLMNR & mDNS Status (Responder/Spoofing Risk)
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(e) - security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure.
# Mapped to: NIS2 Art. 21(2)(g) - Basic cyber hygiene practices and cybersecurity training.
# Mapped to: MITRE T1557 (Man-in-the-Middle) & CIS Control 4.
# Risk: Legacy name resolution protocols allow attackers to steal NTLM hashes via spoofing.
# Logic:
# 1. Checks 'EnableMulticast' (LLMNR) in HKLM\Software\Policies\Microsoft\Windows NT\DNSClient.
# 2. Checks 'EnableMulticast' (mDNS) in HKLM\Software\Policies\Microsoft\Windows NT\DNSClient.
# 3. Flags Critical (Weight 20) if these protocols are active on a Server OS.
# ----------------------------------------------------------------------------------
#>
try {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    
    $lVal = if ($props.EnableMulticast -ne 0) { 1 } else { 0 }
    $mVal = if ($props.EnableMdns -ne 0) { 1 } else { 0 }

    $lTxt = if ($lVal) { "Enabled (High Risk)" } else { "Disabled" }
    $mTxt = if ($mVal) { "Enabled (Med Risk)" } else { "Disabled" }

    $detail = "LLMNR: $lTxt | mDNS: $mTxt"
    
    if ($lVal -eq 0 -and $mVal -eq 0) {
        $status = "OK"
        $remed = "COMPLIANT: Both LLMNR and mDNS are explicitly disabled. The system is hardened against local multicast spoofing and poisoning attacks."
    } else {
        $status = "Warning"
        $actions = @()
		
        if ($lVal) { $actions += "Disable LLMNR (High Risk - Spoofing)" }
        if ($mVal) { $actions += "Disable mDNS (Medium Risk - Recon)" }
        
        $remed = "SECURITY NOTICE: Risky multicast protocols detected: [" + ($actions -join " & ") + "]. These allow local attackers to intercept traffic using tools like Responder. Disable them via GPO."
    }

    $checks += New-Check 'LLMNR & mDNS Status' $detail $status $remed "Network Security & Attack Surface Reduction" -Weight 20
} catch {
    $checks += New-Check 'LLMNR & mDNS Status' "Error reading registry" 'Warning' 'Verify registry access.' "Network Security & Attack Surface Reduction" -Weight 20
}

<#
# 14) DHCPv6 & IPv6 Router Advertisement
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(e) - security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure.
# Mapped to: MITRE T1557 – Adversary-in-the-Middle.
# Risk: Unmonitored IPv6 traffic can be used to bypass security controls or spoof DNS (SLAAC attacks).
# Logic:
# 1. Checks 'DisabledComponents' registry key for IPv6 configuration.
# 2. Verifies if IPv6 is completely disabled or if 'RouterDiscovery' is blocked.
# 3. Advises disabling IPv6 if not explicitly required for operations.
# ----------------------------------------------------------------------------------
#>
try {
    $reg = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name DisabledComponents -EA 0).DisabledComponents
    
    if ($reg -eq 0xff) { 
        $status = "Info"; $detail = "IPv6 Globally Disabled (Reg)"; $remed = "ADVISORY: IPv6 is disabled via Registry. Microsoft recommends keeping it enabled but hardened." 
    }
    else {

        $ifaces = Get-NetIPInterface -AddressFamily IPv6 -EA 0 | Where-Object { $_.ConnectionState -eq 'Connected' -and $_.InterfaceAlias -notmatch "Loopback|Pseudo" }
        
        if (-not $ifaces) {
            $status = "Info"; $detail = "IPv6 Enabled (Reg) but no active physical interfaces."; $remed = "INFO: IPv6 stack is active but unused on physical adapters."
        }
        else {

            $riskyRA = $ifaces | Where-Object RouterDiscovery -eq 'Enabled'
            $dhcpOn  = $ifaces | Where-Object Dhcp -eq 'Enabled'
            
            $raStatus = if ($riskyRA) { "Enabled [Risk: $($riskyRA.InterfaceAlias)]" } else { "Disabled" }
            $dhStatus = if ($dhcpOn)  { "Enabled" } else { "Disabled" }
            $detail = "IPv6 Active. Router Discovery (RA): $raStatus & DHCP: $dhStatus"

            if ($riskyRA) {
                $status = "Warning"
                $remed = "SECURITY NOTICE: IPv6 Router Discovery (RA) is enabled on: [$($riskyRA.InterfaceAlias)]. This allows attackers to perform DNS spoofing (MITM6). Disable 'RouterDiscovery' on these interfaces."
            } elseif ($dhcpOn) {
                $status = "OK"

                $remed = "MAINTENANCE: IPv6 is active with Router Discovery disabled. DHCPv6 is enabled; ensure this is intended."
            } else {
                $status = "OK"
                $remed = "COMPLIANT: IPv6 is enabled but hardened. Router Discovery is disabled, mitigating MITM6 attacks."
            }
        }
    }
    $checks += New-Check 'IPv6 Security & Configuration' $detail $status $remed "Network Security & Attack Surface Reduction"
} catch { 
    $checks += New-Check 'IPv6 Security & Configuration' "Error reading config" 'Warning' 'Check permissions.' "Network Security & Attack Surface Reduction" 
}
<#
# 24) WPAD (Web Proxy Auto-Discovery) Status
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(e) - security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure.
# Mapped to: MITRE T1557 – Adversary-in-the-Middle.
# Risk: WPAD allows attackers to register a fake proxy and intercept all HTTP/HTTPS traffic.
# Logic:
# 1. Checks if 'WinHttpAutoProxySvc' service is Running.
# 2. Checks registry 'DisableWpad' in Microsoft\Windows\CurrentVersion\Internet Settings.
# 3. Flags Critical (Weight 20) if WPAD is active without mitigation (DNS Sinkhole).
# ----------------------------------------------------------------------------------
#>
try {
    $svc = Get-Service WinHttpAutoProxySvc -ErrorAction SilentlyContinue
    $reg = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc\Parameters" -Name "DisableWpad" -ErrorAction 0).DisableWpad
    
    $mitigated = $false
    if ((Test-Path "$env:SystemRoot\System32\drivers\etc\hosts") -and ((Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -Raw) -match "127\.0\.0\.1\s+wpad")) { $mitigated = $true }
    if (-not $mitigated) { try { if ((Resolve-DnsName "wpad" -Type A -EA 0).IPAddress -in '127.0.0.1','0.0.0.0') { $mitigated = $true } } catch {} }

    $detail = "Service: $($svc.Status) ($($svc.StartType)) | Reg: $reg | Mitigated: $mitigated"

    if ($svc.StartType -eq 'Disabled' -or $reg -eq 1) {
        $status = "OK"
        $remed = "COMPLIANT: WPAD is securely disabled via Service configuration or Registry policy. The attack vector is completely closed."
    } elseif ($mitigated) {
        $status = "OK"
        $remed = "SECURE (MITIGATED): WPAD service is active, but neutralised via Hosts/DNS (Redirected to localhost). This effectively prevents external spoofing."
    } elseif ($svc.Status -eq 'Running') {
        $status = "Critical"
        $remed = "URGENT: WPAD service is RUNNING and unmitigated! This makes the server vulnerable to Proxy Auto-Config (PAC) poisoning and Man-in-the-Middle attacks. Disable WPAD if not used for operational purposes."
    } else {
        $status = "Warning"
        $remed = "SECURITY NOTICE: WPAD service is not explicitly disabled (Current Mode: $($svc.StartType)). Although currently stopped, it could be triggered automatically. Explicitly set the service Start Mode to 'Disabled' to close the attack vector."
    }

    $checks += New-Check "WPAD Status" $detail $status $remed "Network Security & Attack Surface Reduction" -Weight 20
} catch {
    $checks += New-Check "WPAD Status" "Error: $($_.Exception.Message)" "Info" "Verify permissions." "Network Security & Attack Surface Reduction" -Weight 20
}

<#
# 30) Remote Registry Service Status
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(g) - Basic cyber hygiene practices and cybersecurity training.
# Mapped to: CIS Control 4.8 (Disable Unnecessary Services).
# Risk: Remote Registry facilitates lateral movement and remote reconnaissance by attackers.
# Logic:
# 1. Checks the status of the 'RemoteRegistry' service.
# 2. Verifies the Start Mode (Should be Disabled, or at least Manual/Stopped).
# 3. Flags Warning if the service is Running or set to Automatic.
# ----------------------------------------------------------------------------------
#>
try {
    $rr = Get-Service "RemoteRegistry" -ErrorAction SilentlyContinue
    
    if (-not $rr) {
        $status = "OK"; $detail = "Service not installed"; $mode = "N/A"
        $remed = "COMPLIANT: Remote Registry service is not present on this system."
    } else {
        $mode = $rr.StartType
        $detail = "State: $($rr.Status) | StartType: $mode"
        
        if ($rr.Status -eq "Running") {
            $status = "Critical"
            $remed = "URGENT: Remote Registry service is running. This allows attackers to remotely query or modify system keys, facilitating lateral movement. Stop and Disable this service as a matter of priority."
        } elseif ($mode -ne "Disabled") {
            $status = "Warning"
            $remed = "SECURITY NOTICE: Remote Registry is not explicitly disabled (Current: $mode). Even if currently stopped, it can be started remotely by an attacker with credentials. Set Startup Type to 'Disabled' to close this vector."
        } else {
            $status = "OK"
            $remed = "COMPLIANT: Remote Registry service is securely disabled. This prevents remote adversaries from enumerating or modifying registry keys."
        }
    }
    $checks += New-Check "Remote Registry Status" $detail $status $remed "Network Security & Attack Surface Reduction"
} catch {
    $checks += New-Check "Remote Registry Status" "Error: $($_.Exception.Message)" "Info" "Check permissions." "Network Security & Attack Surface Reduction"
}

#endregion

Write-Progress -Activity "Windows Server Security Audit" -Status " [4/6] Auditing Endpoint & System Hardening..." -PercentComplete 65

# =============================================================================
#region CATEGORY 4: ENDPOINT & SYSTEM HARDENING
# =============================================================================

<#
# 3) PowerShell Execution Policy (Detailed Scope Analysis & Interpretation)
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(e) - security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure.
# Mapped to: MITRE T1059.001 (PowerShell) & CIS Control 2.
# Risk: Restricts the execution of accidental or malicious unverified scripts.
# Logic:
# 1. Reads the effective PowerShell Execution Policy (including GPO vs Local)..
# 2. Flags Critical if the policy is Unrestricted or Bypass'.
# 3. Treats RemoteSigned/AllSigned/Restricted as compliant and all other non-default states as Warnings with hardening guidance.
# ----------------------------------------------------------------------------------
#>
try {
    $eff = Get-ExecutionPolicy -ErrorAction Stop
    $list = Get-ExecutionPolicy -List | Where-Object {$_.ExecutionPolicy -ne 'Undefined'}
    $src = if ($list | Where-Object Scope -match 'Policy') { "GPO" } else { "Local" }
    
    $detail = "Effective: $eff ($src) | Scopes: " + (($list | ForEach-Object { "$($_.Scope)=$($_.ExecutionPolicy)" }) -join " ")

    if ($eff -eq 'RemoteSigned') {
        $status = "OK"
    
        if ($src -eq "GPO" -and ($list | Where-Object {$_.Scope -eq 'LocalMachine' -and $_.ExecutionPolicy -match 'Bypass|Unrestricted'})) {
             $remed = "COMPLIANT (GPO Enforced): Policy is '$eff' (Ideal for Servers). NOTE: LocalMachine is set to unsafe values but overridden by GPO. Run 'Set-ExecutionPolicy Undefined -Scope LocalMachine' to clean up."
        } else {
             $remed = "COMPLIANT: Execution Policy is '$eff'. This is the preferred configuration for servers, balancing security (blocks internet threats) with operability (allows local automation)."
        }
    } elseif ($eff -eq 'AllSigned') {
        $status = "OK"
        $remed = "SECURE (MAXIMUM): Policy is '$eff'. This provides the highest security level but requires a Code Signing Infrastructure (PKI). CAUTION: All scripts (including internal ones) must be digitally signed, otherwise automation will fail."
    } elseif ($eff -eq 'Restricted') {
        $status = "OK"
        $remed = "SECURE (STRICT): Policy is '$eff'. While technically secure, this prevents ALL scripts from running, which may break backups, monitoring agents, or automation tasks. If operational issues arise, switch to 'RemoteSigned'."
    } elseif ($eff -match 'Unrestricted|Bypass') {
        $status = "Critical"
        $remed = "URGENT: Execution Policy is set to '$eff'! This configuration reduces safeguards against accidental or unauthorised script execution. Set to 'RemoteSigned' as a matter of priority via GPO."
    } else {
        $status = "Warning"
        $remed = "SECURITY NOTICE: Policy is '$eff'. While not fully open, it is recommended to explicitly set 'RemoteSigned' for Servers to ensure only trusted local scripts or signed remote scripts can run."
    }

    $checks += New-Check "PowerShell Execution Policy" $detail $status $remed "Endpoint & System Hardening"
} catch {
    $checks += New-Check "PowerShell Execution Policy" "Error: $($_.Exception.Message)" "Warning" "Ensure PowerShell access." "Endpoint & System Hardening"
}

<#
# 8) Server Endpoint Protection (Antivirus) Status
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(g) - basic cyber hygiene practices and cybersecurity training.
# Mapped to: CIS Control 10 (Malware Defense).
# Risk: Essential defense against malware, ransomware, and non-malware attacks (Living off the Land).
# Logic:
# 1. Queries WMI (ROOT\SecurityCenter2) or 'Get-MpComputerStatus' (for Defender).
# 2. Verifies if Real-Time Protection is Enabled.
# 3. Checks if Virus Definitions (Signatures) are up to date (< 7 days).
# 4. Flags Critical (Weight 20) if AV is missing or disabled.
# ----------------------------------------------------------------------------------
#>
try {
	
    $defStat = Get-MpComputerStatus -ErrorAction 0; $defPref = Get-MpPreference -ErrorAction 0
    $sigAge = if ($defStat.AntivirusSignatureLastUpdated) { [int]((Get-Date) - $defStat.AntivirusSignatureLastUpdated).TotalDays } else { 999 }
    
    $vendors = "*CrowdStrike*","*Cisco*","*Falcon*","*Sentinel*","*Sophos*","*Symantec*","*McAfee*","*Trellix*","*Trend*","*CarbonBlack*","*Cylance*","*Eset*","*Bitdefender*","*Cortex*","*Traps*","*Huntress*"
    $agent = Get-Service | Where-Object { $_.Status -eq 'Running' -and ($_.DisplayName -like $vendors -or $_.Name -like $vendors) } | Select-Object -First 1
    $mde = Get-Service "Sense" -ErrorAction 0 | Where-Object Status -eq 'Running'

    $prod = "Unknown"; $mode = "Disabled"; $isDef = $false
    if ($defStat.AMServiceEnabled -and $defStat.AntivirusEnabled) { $prod = "Microsoft Defender"; $mode = "Active"; $isDef = $true }
    elseif ($agent) { $prod = $agent.DisplayName; $mode = "Active (3rd Party)" }
    elseif ($mde) { $prod = "Defender for Endpoint"; $mode = "EDR Only" }

    $hardInfo = ""; $missing = @()
    if ($isDef) {
        $rt = $defStat.RealTimeProtectionEnabled; if (-not $rt) { $missing += "Real-Time Protection" }
        $tp = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name TamperProtection -EA 0).TamperProtection
        if ($null -eq $tp) { $tp = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection' -Name TamperProtection -EA 0).TamperProtection }
        if ($tp -notin 1,5) { $missing += "Tamper Protection" }
        
        $cloud = switch($defPref.CloudBlockLevel) { 2 {"High"} 4 {"High+"} 6 {"ZeroTol"} Default {"Default"} }; if ($defPref.CloudBlockLevel -eq 0) { $missing += "Cloud Block (High)" }
        $asrCount = ($defPref.AttackSurfaceReductionRules_Ids).Count; if ($asrCount -eq 0) { $missing += "Attack Surface Reduction (ASR) Rules" }
        
        $hardInfo = " | Hardening: [RT:$rt | Cloud:$cloud | ASR:$asrCount | Tamper:$(if($tp -in 1,5){'On'}else{'Off'})]"
    }

    $detail = "Product: $prod | Mode: $mode"; if ($isDef) { $detail += " | Sigs: $sigAge days$hardInfo" }

    if ($mode -match "Disabled" -or $prod -eq "Unknown") {
        $status = "Critical"; $remed = "URGENT: No active Antivirus detected! We checked for Defender and common Enterprise Agents (CrowdStrike, Sophos, SentinelOne, etc.) but found no running services."
    } elseif ($isDef -and -not $defStat.RealTimeProtectionEnabled) {
        $status = "Critical"; $remed = "URGENT: Microsoft Defender is active but 'Real-Time Protection' is DISABLED. The server is scanning only on demand, leaving it exposed to executing malware. Enable Real-Time Protection as a matter of priority."
    } elseif ($isDef -and $sigAge -gt 7) {
        $status = "Critical"; $remed = "URGENT: Antivirus signatures are outdated ($sigAge days). Trigger an update as a matter of priority (Update-MpSignature)."
    } elseif ($isDef -and $sigAge -gt 3) {
        $status = "Warning"; $remed = "MAINTENANCE: Antivirus signatures are slightly outdated ($sigAge days > 3). Verify update connectivity."
    } elseif ($isDef -and $missing) {
        $status = "Warning"; $remed = "SECURITY NOTICE: Defender is active but has hardening gaps. Recommended: Enable [" + ($missing -join ", ") + "]. Attack Surface Reduction (ASR) Rules and Cloud Protection drastically reduce ransomware risk."
    } elseif ($mode -eq "EDR Only") {
        $status = "Warning"; $remed = "SECURITY NOTICE: Microsoft Defender for Endpoint (EDR) is running, but the primary AV service is undetected/passive. Ensure EDR is in 'Block Mode' or that your 3rd-party AV is listed in the check script."
    } else {
        $status = "OK"
        if ($isDef) { $remed = "COMPLIANT: Microsoft Defender is fully operational on this Server. Signatures are fresh ($sigAge days), Real-Time Protection is ON, and advanced hardening (Attack Surface Reduction (ASR)/Cloud/Tamper) is active." }
        else { $remed = "COMPLIANT: Third-party Enterprise Protection detected ($prod). Agent service is running." }
    }

    $checks += New-Check "Server Endpoint Protection" $detail $status $remed "Endpoint & System Hardening" -Weight 20
} catch {
    $checks += New-Check "Server Endpoint Protection" "Error checking AV" "Warning" "Check permissions." "Endpoint & System Hardening" -Weight 20
}

<#
# 15) Unquoted Service Paths
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(e) - security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure.
# Mapped to: MITRE T1574.009 (Path Interception)
# Risk: Privilege Escalation via path interception.
# Logic:
# 1. Queries WMI (Win32_Service) for services with spaces in their 'PathName'.
# 2. Filters out paths that are already enclosed in quotes (" ").
# 3. Flags Warning if vulnerable services are found.
# ----------------------------------------------------------------------------------
#>
try {
 
    $SafeUnquotedServices = @("COMSysApp", "msiserver", "WSearch", "palservice")
    $services = Get-CimInstance Win32_Service -Property Name, PathName, StartMode, DisplayName | 
                Where-Object { 
                    $_.PathName -ne $null -and 
                    $_.PathName -notmatch '^"' -and 
                    $_.PathName -match ' ' -and 
                    $_.StartMode -ne 'Disabled' 
                }

    $vulnerable = @()

    foreach ($svc in $services) {
       
        if ($SafeUnquotedServices -contains $svc.Name) { continue }

        $p = $svc.PathName
        $exePath = $p
        if ($p -match '^(.*?\.exe)') {
            $exePath = $matches[1]
        }
        if ($exePath -match ' ' -and $p -notmatch '^"') {
            $vulnerable += $svc.Name
        }
    }

    if ($vulnerable.Count -gt 0) {
        $status = "Warning" 
        $list = if ($vulnerable.Count -gt 5) { ($vulnerable[0..4] -join ", ") + "..." } else { $vulnerable -join ", " }
        $detail = "Found $($vulnerable.Count) unquoted service path(s): [$list]"
    }
    else {
        $status = "OK"
        $detail = "No unquoted service paths detected (Verified active services)."
    }
    if ($status -eq "Warning") {
        $finalRemed = "SECURITY NOTICE: Unquoted service paths detected for the following services: $list.
					  This misconfiguration may allow Windows to execute malicious binaries placed in higher-priority path locations (e.g. C:\Program.exe), 
					  leading to Local Privilege Escalation. All service executable paths must be properly quoted."
    }
    else {
        $finalRemed = "COMPLIANT: All active service executable paths are correctly quoted. This mitigates Unquoted Service Path exploitation and prevents related Privilege Escalation attacks."
    }

$checks += New-Check "Unquoted Service Paths" $detail $status $finalRemed "Endpoint & System Hardening" }
catch {
    $checks += New-Check "Unquoted Service Paths" "Error: $($_.Exception.Message)" "Warning" "Check WMI permissions." "Endpoint & System Hardening" }
<#
# 16) Microsoft SmartScreen Status
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(e) - security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure.
# Risk: Prevents execution of unrecognized/malicious files downloaded from the internet.
# Logic:
# 1. Checks Registry 'EnableSmartScreen' in HKLM\Software\Policies\Microsoft\Windows\System.
# 2. Flags OK if enabled (Warn/Block).
# 3. Flags Warning if disabled (Note: Less critical on Servers than Workstations).
# ----------------------------------------------------------------------------------
#>
try {
    $locVal = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -EA 0).SmartScreenEnabled
    $gpo    = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -EA 0
    $isGPO  = ($gpo.EnableSmartScreen -eq 1)
    $gpoLvl = if ($isGPO) { $gpo.ShellSmartScreenLevel } else { $null }

    if ($isGPO) {
        if ($gpoLvl -eq "Block") {
            $status = "OK"; $detail = "GPO Enforced: Block (Strict)"
            $remed = "SECURE (STRICT): SmartScreen is enforced via GPO to 'Prevent Bypass'. Users cannot run unrecognised applications even if they trust them. This provides maximum security."
        } elseif ($gpoLvl -eq "Warn") {
            $status = "OK"; $detail = "GPO Enforced: Warn (Standard)"
            $remed = "COMPLIANT: (GPO Enforced): SmartScreen is enforced to 'Warn'. This balances security with usability, alerting users about unrecognised apps while allowing overrides if necessary."
        } else {
            $status = "Warning"; $detail = "GPO Enforced: Disabled/Off"
            $remed = "SECURITY NOTICE: SmartScreen is explicitly DISABLED. Users are not protected against potentially malicious or unrecognised downloads."
        }
    } 
    elseif ($locVal -in "On","Warn","RequireAdmin") {
        $status = "OK"; $detail = "Local Setting: Active ($locVal)"
        $remed = "OK (LOCAL): SmartScreen is active locally. Recommendation: Use Group Policy (GPO) to enforce 'Warn' setting across the domain to prevent user tampering."
    } 
    elseif ($locVal -eq "Off") {
        $status = "Warning"; $detail = "Local Setting: Off"
        $remed = "SECURITY NOTICE: SmartScreen is explicitly DISABLED. Users are not protected against potentially malicious or unrecognised downloads."
    }
    else {
      
        $status = "Info"; $detail = "State: Not Configured (Defaults)"
        $remed = "ADVISORY: SmartScreen is using OS defaults (Not Configured). It is recommended to Enforce 'Warn' via GPO to ensure consistent protection."
    }

    $checks += New-Check "SmartScreen Status" $detail $status $remed "Endpoint & System Hardening" -Weight 5
} catch {
    $checks += New-Check "SmartScreen Status" "Error: $($_.Exception.Message)" "Info" "Check permissions." "Endpoint & System Hardening"
}

<#
# 20) Print Spooler Service State
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(e) - security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure.
# Mapped to: MITRE T1068 (Exploitation for Privilege Escalation) & CIS Control 4.8 (Disable Unnecessary Services).
# Risk: The Spooler service is a high-risk vector, especially on Domain Controllers (PrintNightmare (CVE-2021-34527)). Critical for Domain Controllers.
# Logic:
# 1. Checks 'Spooler' service status.
# 2. Identifies Server Role: If Domain Controller + Spooler Running = CRITICAL (Weight 20).
# 3. For Member Servers, it flags Warning if running but not required.
# ----------------------------------------------------------------------------------
#>
try {
    $svc = Get-Service Spooler -ErrorAction SilentlyContinue
    if (-not $svc) {
        $checks += New-Check "Print Spooler Service" "Service not found." "Info" "None" "Endpoint & System Hardening"
    } else {
        $sys = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $isDC = if ($sys) { $sys.DomainRole -ge 4 } else { $false }
        
        $state = $svc.Status; $mode = $svc.StartType
        
        $hasShares = $false
        if ($state -eq 'Running') {
            if (Get-Command "Get-Printer" -EA 0) { 
     
                if (Get-Printer -EA 0 | Where-Object { $_.Shared }) { $hasShares = $true } 
            } elseif (Get-CimInstance Win32_Printer -Filter "Shared='True'" -EA 0) { 
                $hasShares = $true 
            }
        }

        $detail = "State: $state | StartMode: $mode | Role: $(if($isDC){'DC'}else{'Member'})"

        if ($isDC) {
            if ($state -eq "Running") {
                $status = "Critical"
                $remed = "URGENT: Print Spooler is RUNNING on a Domain Controller! This exposes the DC to critical vulnerabilities (PrintNightmare). Disable the service as a matter of priority or plan its decommission."
            } elseif ($mode -ne "Disabled") {
                $status = "Warning"
                $remed = "SECURITY NOTICE: Print Spooler is stopped but not explicitly disabled (Mode: $mode). It poses a risk on DCs. Set Startup Type to 'Disabled'."
            } else {
                $status = "OK"
                $remed = "COMPLIANT: Print Spooler service is stopped/disabled. This mitigates PrintNightmare risks."
            }
        } else {
            if ($state -eq "Running") {
                if ($hasShares) {
                    $status = "Info"
                    $remed = "OPERATIONAL: Print Spooler is active and serving shared printers (Legitimate Print Server). Ensure patching is up to date."
                } else {
                    $status = "Warning"
                    $remed = "ADVISORY: Print Spooler is running, but no shared printers were detected. If this server does not need to print, disable the service."
                }
            } else {
                if ($mode -eq "Automatic") {
                    $status = "Warning"
                    $remed = "MAINTENANCE: Print Spooler is currently Stopped but set to 'Automatic'. It will restart on the next reboot. Set Startup Type to 'Disabled' to permanently reduce attack surface."
                } else {
                    $status = "OK"
                    $remed = "COMPLIANT: Print Spooler service is stopped/disabled. This mitigates PrintNightmare risks."
                }
            }
        }
        $checks += New-Check "Print Spooler Service" $detail $status $remed "Endpoint & System Hardening" -Weight 20
    }
} catch {
    $checks += New-Check "Print Spooler Service" "Error: $($_.Exception.Message)" "Info" "Check permissions." "Endpoint & System Hardening" -Weight 20
}
#endregion

Write-Progress -Activity "Windows Server Security Audit" -Status " [5/6] Auditing Data Protection & Platform Integrity..." -PercentComplete 80

# =============================================================================
#region CATEGORY 5: DATA PROTECTION & PLATFORM INTEGRITY
# =============================================================================

<#
# 17) Drive Encryption Status (System Drive (C:))
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(h) - policies and procedures regarding the use of cryptography and, where appropriate, encryption.
# Mapped to: CIS Control 3 (Data Protection)
# Risk: Protects data at rest against physical theft or improper disposal of drives.
# Logic:
# 1. Context-Aware Remediation (Physical vs VM).
# 2. 3rd Party Encryption Detection.
# 3. Granular BitLocker Check (Detects Missing Feature vs Disabled State).
# 4. Flags Warning if unencrypted (Note: On VMs, host-level encryption is also acceptable).
# ----------------------------------------------------------------------------------
#>
try {

    $sys = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $isVM = if ($sys) { $sys.Model -match "Virtual|KVM|Bochs|QEMU" -or $sys.Manufacturer -match "VMware|Microsoft|Xen|KVM|QEMU|Amazon|Google" } else { $false }
    $drive = if ($env:SystemDrive) { $env:SystemDrive } else { "C:" }

    $bit = Get-CimInstance -Namespace "root/CIMV2/Security/MicrosoftVolumeEncryption" -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$drive'" -ErrorAction SilentlyContinue
    
    $vendors = "*Symantec*","*PGP*","*Sophos*","*McAfee*","*MneService*","*Kaspersky*","*avp*","*VeraCrypt*","*TrueCrypt*","*BitDefender*","*CheckPoint*","*FDE*","*TrendMicro*","*eeDisk*","*mbam*"
    $agent = Get-Service | Where-Object { $_.Status -eq 'Running' -and ($_.DisplayName -like $vendors -or $_.Name -like $vendors) } | Select-Object -First 1

    $isEnc = $false; $method = "None"
    
    if ($bit -and $bit.ProtectionStatus -eq 1) {
        $isEnc = $true; $method = "BitLocker (Native)"
    } elseif ($agent) {
        $isEnc = $true; $method = "Third-Party Agent ($($agent.DisplayName))"
    } elseif ($bit) {
        $method = "BitLocker Installed but DISABLED"
    } else {
        $method = "None (BitLocker Feature Missing)"
    }

    $detail = "Type: $(if($isVM){'Virtual Machine'}else{'Physical Server'}) | System Drive ($drive) Encryption: $method"

    if ($isEnc) {
        $status = "OK"
        $remed = "COMPLIANT: System Drive ($drive) encryption is active via $method. This secures the OS and data at rest against physical theft."
    } elseif ($isVM) {
        $status = "Warning"; $detail += " (Guest Unencrypted)"
        $remed = "SECURITY NOTICE: Guest OS ($drive) is NOT encrypted. ACTION REQUIRED: 1) VERIFY that underlying Host/Storage encryption is active. 2) Enable Guest encryption for 'Defense in Depth'."
    } else {
        $status = "Critical"
        if ($method -match "Disabled") {
            $remed = "URGENT: Physical Server has NO encryption active on $drive, but BitLocker is installed. Enable protection as a matter of priority."
        } else {
            $remed = "URGENT: Physical Server has NO encryption detected on $drive and BitLocker feature is missing! This poses a critical risk. Install BitLocker Feature and encrypt the drive."
        }
    }

    $checks += New-Check "Drive Encryption Status" $detail $status $remed "Data Protection & Platform Integrity" -Weight 20
} catch {
    $checks += New-Check "Drive Encryption Status" "Error: $($_.Exception.Message)" "Info" "Check permissions." "Data Protection & Platform Integrity" -Weight 20
}

<#
# 18) TPM & Secure Boot Status
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(h) - policies and procedures regarding the use of cryptography and, where appropriate, encryption.
# Mapped to: MITRE T1542 (Pre-OS Boot).
# Risk: Ensures the boot loader is signed and prevents Rootkits/Bootkits.
# Logic:
# 1. Uses 'Confirm-SecureBootUEFI' to verify Secure Boot status.
# 2. Queries WMI/CIM for TPM chip presence and version (v1.2 or v2.0).
# 3. Context-Aware remediation for Physical vs Virtual
# 4. Essential for enabling features like Credential Guard and BitLocker.
# ----------------------------------------------------------------------------------
#>
try {

    $sys = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $isVM = if ($sys) { $sys.Model -match "Virtual|KVM|Bochs|QEMU" -or $sys.Manufacturer -match "VMware|Microsoft|Xen|KVM|QEMU|Amazon|Google|Oracle|Parallels|Virtuozzo|DigitalOcean" } else { $false }

    $fw = "Unknown"; $sb = "Unknown"
    try { 
        $sbStatus = Confirm-SecureBootUEFI -ErrorAction Stop
        $fw = "UEFI (Gen 2)"; $sb = if ($sbStatus) { "Enabled" } else { "Disabled" }
    } catch { 
        $fw = "Legacy BIOS (Gen 1)"; $sb = "Not Supported" 
    }

    $tpmObj = Get-CimInstance -Namespace "root\cimv2\security\microsofttpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue | Select-Object -First 1
    $tpm = if ($tpmObj) { $true } else { $false }
    $ver = if ($tpmObj -and $tpmObj.SpecVersion) { ($tpmObj.SpecVersion -join ", ").Trim() } else { "None" }

    $detail = "Type: $(if($isVM){'Virtual Machine'}else{'Physical Server'}) | FW: $fw | Secure Boot: $sb | TPM: $ver"

    if ($sb -eq "Enabled") {
        if ($tpm) {
            $status = "OK"
            $remed = "EXCELLENT: Platform integrity is fully secure (UEFI + Secure Boot + TPM $ver Active). Protects against Bootkits and enables Credential Guard."
        } else {
            $status = "OK"
            if ($isVM) { 
                $detail += " (Advisory: vTPM missing)"
                $remed = "COMPLIANT: Secure Boot is Active. NOTE: vTPM is missing. Consider enabling vTPM in Hypervisor settings to support BitLocker and Credential Guard." 
            } else { 
                $status = "Warning"; $remed = "SECURITY NOTICE: Secure Boot is active, but TPM is missing. Check BIOS settings to enable Firmware TPM (fTPM/PTT) if available."
            }
        }
    } elseif ($isVM) {
        if ($fw -match "Legacy") { 
            $status = "Info"; $remed = "ADVISORY: VM is running Legacy BIOS (Gen 1). This prevents using Secure Boot and advanced security features. For future deployments, use UEFI (Gen 2 / OVMF)." 
        } else { 
            $status = "Warning"; $remed = "SECURITY NOTICE: VM is configured with UEFI but Secure Boot is DISABLED. Enable Secure Boot in the Hypervisor settings to prevent unauthorised boot loaders." 
        }
    } else {
        if ($fw -match "Legacy") { 
            $status = "Warning"; $remed = "HARDWARE WARNING: Physical Server is running Legacy BIOS. Secure Boot is not supported. Plan for hardware refresh or BIOS-to-UEFI conversion." 
        } else { 
            $status = "Critical"; $remed = "URGENT: Physical Server supports Secure Boot (UEFI) but it is explicitly DISABLED! The system is vulnerable to Bootkits. Enable Secure Boot in BIOS as a matter of priority." 
        }
    }

    $checks += New-Check "TPM & Secure Boot Status" $detail $status $remed "Data Protection & Platform Integrity"
} catch {
    $checks += New-Check "TPM & Secure Boot Status" "Error: $($_.Exception.Message)" "Info" "Check permissions." "Data Protection & Platform Integrity"
}

<#
# 22) Plaintext Password Files (Filename Scan)
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(h) - policies and procedures regarding the use of cryptography and, where appropriate, encryption.
# Mapped to: MITRE T1552.001 (Unsecure Credentials/Credentials in Files).
# Risk: Users often save credentials in files named "passwords", "login", etc. in plain text.
# Logic:
# 1. Scans user profiles (Desktop, Documents, Downloads) and Inetpub locations using specific Regex patterns.
# 2. Patterns include: *password*, *secret*, *kwdikos*, *key*, etc. (in 15+ languages).
# 3. Strict exact filename matching (no substrings) for high-fidelity hits (less false-positives). 
# 4. Flags Critical (Weight 20) if such files are detected.
# ----------------------------------------------------------------------------------
#>
try {

    $exts = @('.txt','.doc','.docx','.xls','.xlsx','.csv','.pdf','.rtf','.json','.xml')
    $pat = 'password|passwords|passw|my_passwords|passwords_backup|credential|vpn_credentials|credentials|creds|secret|secrets|login|logins|signin|auth|admin|admins|key|keys|kwdikos|kwdikoi|κωδικός|κωδικος|κωδικοί|κωδικοι|passwort|kennwort|geheim|zugangsdaten|authentifizierung|schluessel|wachtwoord|wachtwoorden|codewoord|inloggegevens|authenticatie|aanmelding|motdepasse|mdp|identifiants|connexion|authentification|contrasena|codice|credenziali|autenticazione|contraseña|clave|codigo|inicio de sesión|autenticación|senha|palavra-passe|credencial|credenciais|haslo|hasło|hasla|hasła|poświadczenia|uwierzytelnianie|heslo|hesla|přihlašovací údaje|ověření|jelszo|jelszavak|hitelesítő adatok|hitelesítés|parola|parolă|parole|credențiale|autentificare|парола|пароли|идентификационни данни|удостоверяване|учетни данни|passord|innlogging|pålogging|autentisering|losenord|lösenord|autentisering|salasana|tunnusluku|avain|avaimet|salainen|kodeord|adgangskode|legitimationsoplysninger|godkendelse|lykilorð|innskráning|auðkenning'


    $paths = @(); if (Test-Path "$env:SystemDrive\Users") { $paths += "$env:SystemDrive\Users" }; if (Test-Path "$env:SystemDrive\Inetpub") { $paths += "$env:SystemDrive\Inetpub" }
    $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Where-Object DeviceID -ne $env:SystemDrive | Select -Expand DeviceID
    foreach ($d in $drives) { $paths += "$d\" }
    
    $skipList = @("AppData", "Program Files", "Program Files (x86)", "Windows", "node_modules", ".git", "Default", "Public", "All Users", "ZxcvbnData", "Microsoft\Edge", "Google\Chrome", "PingCastle","PurpleKnight", "Semperis", "BloodHound", "Mimikatz")

    $hits = @()
    foreach ($root in $paths) {
        if (-not (Test-Path $root)) { continue }
        $files = Get-ChildItem $root -Recurse -File -EA 0 -Attributes !ReparsePoint | Where-Object {
            if ($exts -contains $_.Extension.ToLower()) {
                $fp = $_.FullName; $ignore = $false
                foreach ($ex in $skipList) { if ($fp -match [regex]::Escape($ex)) { $ignore = $true; break } }
                if ($ignore) { return $false }
                
                if ($_.BaseName -match "^($pat)$") { return $true }
            }
            return $false
        }
        foreach ($f in $files) { $hits += [PSCustomObject]@{ Name=$f.Name; Path=$f.FullName; SizeKB=[math]::Round($f.Length/1KB, 2); Modified=$f.LastWriteTime } }
    }

    $count = $hits.Count; $msg = ""
    if ($count -gt 0) {
        $status = "Critical"
        $ex = ($hits | Select -First 3 | ForEach {$_.Name}) -join ", "
        $detail = "Found $count potentially sensitive files. Examples: [$ex]..."
        
        $dir = if ($ReportPath) { $ReportPath } else { "$env:SystemDrive\" }
        if (-not (Test-Path $dir)) { New-Item -Type Directory -Force -Path $dir | Out-Null }
        $csv = Join-Path $dir "SensitiveFiles_Found.csv"
        
        try { 
            $hits | Select Name, Path, SizeKB, Modified | Export-Csv $csv -NoType -Encoding UTF8 -Force
            $msg = "See CSV in report folder."
            $detail += " [Full list saved to CSV]"
            Write-Host "⚠️ ALERT: Found $count plaintext password files! List saved to: $csv" -ForegroundColor Red
        } catch { $detail += " [Could not save CSV]" }
        
        $remed = "URGENT: Detected $count files with names explicitly indicating stored credentials (e.g., $ex). This is a massive security risk. $msg Action: Inspect these files as a matter of priority and move valid credentials to a Password Manager."
    } else {
        $status = "OK"; $detail = "No files with exact sensitive names found (Exact Match Mode)."
        $remed = "COMPLIANT: No files explicitly named 'passwords', 'credentials', etc. were found in user profiles."
    }

    $checks += New-Check "Plaintext Password Files" $detail $status $remed "Data Protection & Platform Integrity" -Weight 20
} catch {
    $checks += New-Check "Plaintext Password Files" "Error: $($_.Exception.Message)" "Error" "Check permissions." "Data Protection & Platform Integrity" -Weight 20
}

#endregion

Write-Progress -Activity "Windows Server Security Audit" -Status " [6/6] Auditing Business Continuity & Crisis Management..." -PercentComplete 90

# =============================================================================
#region CATEGORY 6: BUSINESS CONTINUITY & CRISIS MANAGEMENT
# =============================================================================

<#
# 25) Forensic Audit Policy & Logging
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(b) - Incident Handling.
# Mapped to: NIS2 Art. 21(2)(c) - business continuity, such as backup management and disaster recovery, and crisis management.
# Mapped to: CIS Control 8 & MITRE T1562.
# Risk: Lack of logging hinders detection. "Process Creation" is vital for forensics.
# Logic:
# 1. robustly checks for 'auditpol.exe'.
# 2. Uses 'auditpol /r' skipping headers for clean CSV parsing.
# 3. Handle edge cases (duplicate policies) safely.
# 4. Criticality Logic: Missing "Process Creation" or "CmdLine" is always Critical.
# ----------------------------------------------------------------------------------
#>
try {
    if (-not (Get-Command "auditpol.exe" -EA 0)) { throw "auditpol.exe missing" }

    $csv = auditpol /get /category:* /r | Select -Skip 1 | ConvertFrom-Csv -Header "M","T","Sub","GUID","Inc","Exc"
    
    $req = @(
        @{N="Logon";E=3}, @{N="Logoff";E=1}, @{N="Account Lockout";E=1}, 
        @{N="Process Creation";E=1}, @{N="Credential Validation";E=2}
    )

    $miss = @(); $found = @()

    foreach ($r in $req) {
        $pol = $csv | Where Sub -eq $r.N | Select -First 1
        if ($pol) {
            $cur = 0; $v = $pol.Inc
            if ($v -match "Success.*Failure") { $cur=3 } elseif ($v -match "Success") { $cur=1 } elseif ($v -match "Failure") { $cur=2 }
            
            $ok = $false
            if ($r.E -eq 3 -and $cur -eq 3) { $ok=$true }
            elseif ($r.E -eq 1 -and ($cur -in 1,3)) { $ok=$true }
            elseif ($r.E -eq 2 -and ($cur -in 2,3)) { $ok=$true }
            
            if ($ok) { $found += $r.N } else { $miss += "$($r.N) ($v)" }
        } else { $miss += "$($r.N) (Not Set)" }
    }

    $ps = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -EA 0).EnableScriptBlockLogging
    if ($ps -eq 1) { $found += "PS ScriptBlock" } else { $miss += "PS ScriptBlock (Reg)" }

    $cmd = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -EA 0).ProcessCreationIncludeCmdLine_Enabled
    if ($cmd -eq 1) { $found += "CmdLine Args" } else { $miss += "CmdLine Args (Reg)" }

    $fStr = if ($found.Count -gt 5) { ($found[0..4] -join ", ") + "..." } else { $found -join ", " }
    $detail = "Enabled: [$fStr]"
    
    $critMiss = ($miss -match "Process Creation" -or $miss -match "CmdLine Args")
    
    if ($miss.Count -eq 0) {
        $status = "OK"
        $remed = "COMPLIANT: Forensic logging is fully configured. Advanced Audit Policies, PowerShell ScriptBlock logging, and Command Line auditing are active."
    } elseif ($miss.Count -lt 3 -and -not $critMiss) {
        $status = "Warning"
        $remed = "SECURITY NOTICE: Forensic logging is mostly configured, but some gaps exist: [" + ($miss -join ", ") + "]. Enable these to ensure complete visibility."
    } else {
        $status = "Critical"
        if ($critMiss) {
            $remed = "URGENT: Critical forensic visibility is missing! 'Process Creation' or 'Command Line Argument' auditing is disabled. Without these, you cannot trace attacker commands. Enable Audit Process Creation (Success) and Registry 'ProcessCreationIncludeCmdLine_Enabled=1'."
        } else {
            $remed = "URGENT: The system is blind to attacks! Multiple audit policies are missing: [" + ($miss -join ", ") + "]. Configure Advanced Audit Policies as a matter of priority."
        }
    }

    $checks += New-Check "Forensic Audit & Logging" $detail $status $remed "Business Continuity & Crisis Management" -Weight 20
} catch {
    $checks += New-Check "Forensic Audit & Logging" "Error: $($_.Exception.Message)" "Warning" "Check permissions (Admin required)." "Business Continuity & Crisis Management" -Weight 20
}

<#
# 28) Time Synchronization (NTP) (Log Integrity)
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(b) - incident handling.
# Mapped to: NIS2 Art. 21(2)(c) - business continuity, such as backup management and disaster recovery, and crisis management.
# Mapped to: CIS Control 8 & 13
# Risk: Time drift breaks Kerberos authentication and invalidates forensic timelines.
# Logic:
# 1. Null-Safe Service Check (Critical if missing).
# 2. Virtualisation Detection (VMware, Hyper-V, KVM/QEMU, Xen).
# 3. Stratum Visibility in output.
# 4. Role-Based Severity: 'Local CMOS Clock' is Critical for DCs, Warning for Members.
# 5. Best-practices guidance for PDC
# ----------------------------------------------------------------------------------
#>
try {
    $svc = Get-Service W32Time -ErrorAction SilentlyContinue
    
    if (-not $svc) {
        $checks += New-Check "Time Synchronization (NTP)" "Service: MISSING" "Critical" "URGENT: Windows Time Service (W32Time) is missing. Time synchronization is impossible." "Business Continuity & Crisis Management" -Weight 10
    } else {
        $isRunning = ($svc.Status -eq 'Running')
        
        $sys = Get-CimInstance Win32_ComputerSystem -EA 0
        $isVM = ($sys.Model -match "Virtual|KVM|Bochs|QEMU" -or $sys.Manufacturer -match "VMware|Microsoft|Xen|KVM|QEMU")
        $isDC = ($sys.DomainRole -ge 4)
        $isPDC = $false; if ($isDC) { try { if ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name -match $env:COMPUTERNAME) { $isPDC=$true } } catch {} }

        $timeSource = (w32tm /query /source 2>$null).Trim()
        $peersRaw = w32tm /query /peers 2>$null | Out-String
        $peerList = [regex]::Matches($peersRaw, "Peer:\s*(.*)") | ForEach-Object { $_.Groups[1].Value.Trim() }
        $peersStr = if ($peerList) { "[" + ($peerList -join ", ") + "]" } else { "[None Configured]" }
        $stratum = 0; if ((w32tm /query /status 2>$null) -match "Stratum:\s*(\d+)") { $stratum = [int]$matches[1] }

        $vmSyncRisk = $false
        if ($isDC) {
            $vmSvcs = Get-Service "VMTools","vmictimesync" -EA 0 | Where Status -eq Running
            if ($timeSource -match "VM IC|VMware|Hyper-V|Integration Services|Host Time" -or $vmSvcs) { $vmSyncRisk = $true }
        }

        $roleStr = if ($isPDC) { "DC (PDC Emulator)" } elseif ($isDC) { "Domain Controller" } else { "Member Server" }
        $detail = "Role: $roleStr | Source: $timeSource (Stratum: $stratum) | Peers: $peersStr"

        if (-not $isRunning) {
            $status = "Critical"
            $finalRemed = "URGENT: Windows Time Service is STOPPED. Kerberos requires time sync. Start the service as a matter of priority."
        } elseif ($isPDC) {
            if ($timeSource -match "Local CMOS|Free-running") {
                $status = "Critical"; $finalRemed = "URGENT (PDC Failure): This server is the PDC Emulator but is using '$timeSource'. The PDC MUST sync with a reliable external NTP source."
            } elseif ($vmSyncRisk) {
                $status = "Warning"; $finalRemed = "CONFIGURATION RISK: Virtual PDC Emulator is syncing time from the VM Host. This can cause 'Time Loops' during reboots. Disable Host Time Sync and configure an external NTP source."
            } elseif ($stratum -eq 0) {
                $status = "Critical"; $finalRemed = "URGENT (PDC Failure): This server is the PDC Emulator but is using '$timeSource'. The PDC MUST sync with a reliable external NTP source."
            } else {
                $status = "OK"; $finalRemed = "EXCELLENT: PDC Emulator is correctly synchronised with an external time source ($timeSource)."
            }
        } elseif ($isDC) {
            if ($timeSource -match "Local CMOS") {
                $status = "Critical"; $finalRemed = "URGENT: Domain Controller is using 'Local CMOS Clock'. It has lost sync with the PDC."
            } elseif ($peersStr -notmatch "None" -and $timeSource -notmatch "VM IC") {
                $status = "Info"; $finalRemed = "ADVISORY: Secondary DC has manually configured NTP peers $peersStr. Best practice is to allow NT5DS to manage sync automatically."
            } else {
                $status = "OK"; $finalRemed = "COMPLIANT: System is synchronized via $timeSource."
            }
        } else {
            if ($stratum -eq 0) {
                $status = "Warning"; $finalRemed = "MAINTENANCE: Service running but Stratum 0 (Time Service unsynchronised). Check connectivity to NTP Peers: $peersStr."
            } else {
                $status = "OK"; $finalRemed = "COMPLIANT: System is synchronized via $timeSource."
            }
        }

        $checks += New-Check "Time Synchronization (NTP)" $detail $status $finalRemed "Business Continuity & Crisis Management"
    }
} catch {
    $checks += New-Check "Time Synchronization (NTP)" "Error: $($_.Exception.Message)" "Info" "Check W32Time permissions." "Business Continuity & Crisis Management"
}
<#
# 27) VSS Writers Status (Data Recovery)
# ----------------------------------------------------------------------------------
# Mapped to: NIS2 Art. 21(2)(c) - business continuity, such as backup management and disaster recovery, and crisis management.
# Mapped to: CIS Control 1 (Data Recovery)
# Risk: Failed VSS writers mean backups are likely corrupt. Lack of Event 2004 means no backups run.
# Logic:
# 1. Runs 'vssadmin list writers' to check the state of system writers.
# 2. Checks Application Event Log for recent VSS Success Events (ID 2004) in the last 8 days.
Note: Always validate and test your backup sets even in case of VSS success events. We only have backups when we can restore them as neeeded.
# ----------------------------------------------------------------------------------
#>
try {
	
    $vss = vssadmin list writers 2>$null
    $failed = @(); $total = 0; $curWriter = ""
    
    foreach ($line in $vss) {
        if ($line -match "Writer name:\s*'(.*)'") { 
            $curWriter = $matches[1]; $total++ 
        } elseif ($line -match "State:\s*\[(\d+)\]") {
            if ([int]$matches[1] -ge 7 -and $curWriter) { $failed += "$curWriter (ID:$($matches[1]))" }
        }
    }

    $evt = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='VSS'; Id=2004; StartTime=(Get-Date).AddDays(-8)} -MaxEvents 1 -ErrorAction SilentlyContinue
    $lastBackup = if ($evt) { $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm") } else { "None (Last 8 Days)" }
    $hasBackup = [bool]$evt

    $detail = "Writers: $total | Failed: $($failed.Count) | Last Shadow Copy (Event 2004): $lastBackup"

    if ($total -eq 0) {
        $status = "Warning"
        $remed = "No VSS Writers detected. Ensure 'Volume Shadow Copy' service is enabled. Backups may fail."
    } elseif ($failed.Count -gt 0) {
        $status = "Critical"
        $detail += " [Broken: " + ($failed -join ", ") + "]"
        $remed = "URGENT: VSS Writers are in FAILED state. Application-consistent backups are likely failing. Restart 'Cryptographic Services' and 'Volume Shadow Copy' services, or reboot the server."
    } elseif (-not $hasBackup) {
        $status = "Warning"
        $remed = "VSS Writers appear healthy, but NO VSS Snapshot (Event ID 2004) was detected in the last 8 days. This confirms no VSS-aware backup has run recently. ACTION: Verify your Backup Agent is installed and running."
    } else {
        $status = "OK"
        $remed = "COMPLIANT: VSS infrastructure is healthy and Shadow Copy usage was detected recently ($lastBackup). NOTE: Always perform test restores to validate backup integrity."
    }

    $checks += New-Check "VSS Writers Status (Data Recovery)" $detail $status $remed "Business Continuity & Crisis Management" -Weight 20
} catch {
    $checks += New-Check "VSS Writers Status (Data Recovery)" "Error: $($_.Exception.Message)" "Info" "Check permissions." "Business Continuity & Crisis Management" -Weight 20
}

#endregion
#endregion
#region 5. Reporting & Export
# -----------------------------------------------------------------------------
# JSON OUTPUT
# -----------------------------------------------------------------------------
Write-Host "`n--- Audit Results ---"
$checks | Format-Table -AutoSize

$NIS2RationaleJSON = @{
    "Patching & Maintenance" = "Art. 21(2)(e) - Security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure."
    "Access Control & Identity Management" = "Art. 21(2)(i) & (j) - Human resources security, access control policies and asset management & the use of multi-factor authentication or
	 continuous authentication solutions, secured voice, video and text communications and secured emergency communication systems within the entity, where appropriate."
    "Network Security & Attack Surface Reduction" = "Art. 21(2)(a) - Policies on risk analysis and information system security; Art. 21(2)(g) - basic cyber hygiene practices and cybersecurity training."
    "Endpoint & System Hardening" = "Art. 21(2)(g) - Basic cyber hygiene practices and cybersecurity training."
    "Data Protection & Platform Integrity" = "Art. 21(2)(h) - Policies and procedures regarding the use of cryptography and, where appropriate, encryption."
	"Business Continuity & Crisis Management" = "Art. 21(2)(c) - business continuity, such as backup management and disaster recovery, and crisis management"
}

$activeChecks = $checks | Where-Object { $_.MaxScore -gt 0 }

$totalPossible = ($activeChecks | Measure-Object -Property MaxScore -Sum).Sum
$totalEarned   = ($activeChecks | Measure-Object -Property Score -Sum).Sum

if ($totalPossible -gt 0) {
    $rawScore = ($totalEarned / $totalPossible) * 100
} else {
    $rawScore = 0
}

$securityScore = [Math]::Round($rawScore)

$countCrit = ($checks | Where-Object { $_.Status -eq "Critical" }).Count
$countWarn = ($checks | Where-Object { $_.Status -eq "Warning" }).Count

if ($securityScore -ge 90) { 
    $grade = "A"
    $gradeColor = "#2ecc71" 
} 
elseif ($securityScore -ge 80) { 
    $grade = "B"
    $gradeColor = "#3498db" 
} 
elseif ($securityScore -ge 65) { 
    $grade = "C"
    $gradeColor = "#f1c40f" 
} 
elseif ($securityScore -ge 50) { 
    $grade = "D"
    $gradeColor = "#e67e22"
} 
else { 
    $grade = "F"
    $gradeColor = "#e74c3c"
}

$critCats = $checks | Where-Object { $_.Status -eq "Critical" } | Select-Object -ExpandProperty Category -Unique | Sort-Object
if ($grade -eq "A" -or $grade -eq "B") { $summaryText = "System demonstrates a <strong>strong security posture</strong> with high adherence to the NIS2 directive standards. Focus on resolving warning-level configurations" }
elseif ($grade -eq "C") {
    if ($critCats) { $catStr = "<strong>" + ($critCats -join "</strong>, <strong>") + "</strong>"; $summaryText = "System shows <strong>moderate compliance with the NIS2 directive</strong>, but critical gaps remain in: $catStr." }
    else { $summaryText = "System shows <strong>moderate compliance</strong>. Focus on first resolving critical then warning-level configurations." }
} else {
    if ($critCats) { $catStr = "<strong>" + ($critCats -join "</strong>, <strong>") + "</strong>"; $summaryText = "<strong>Critical gaps detected. Significant compliance drift from the NIS2 directive.</strong> Immediate remediation is required across: $catStr." }
    else { $summaryText = "<strong>Significant compliance drift detected.</strong> Accumulation of critical and warning-level issues require urgent attention." }
}

foreach ($check in $checks) {
    $r = $NIS2RationaleJSON[$check.Category]
    if (-not $r) { $r = "General Security Best Practice" }
    $check | Add-Member -MemberType NoteProperty -Name "NIS2_Alignment" -Value $r -Force
}

if (-not $HTMLOnly) {
    $finalJsonPayload = @{
        RiskScore = $securityScore
        RiskLevel = $grade
        Findings  = $checks
    }

    $finalJsonPayload | ConvertTo-Json -Depth 6 | Out-File -FilePath $outJson -Encoding UTF8
	Write-Host "`n[SUCCESS] Saved JSON report to: $outJson" -ForegroundColor Green

}
else {
    Write-Host "`n[INFO] JSON Export skipped (-HTMLOnly selected)." -ForegroundColor Gray
}

# -----------------------------------------------------------------------------
# HTML OUTPUT
# -----------------------------------------------------------------------------

if (-not $JSONOnly) {

try {
    $ipProps = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    if ($ipProps.DomainName) { $fqdn = "$($ipProps.HostName).$($ipProps.DomainName)" } else { $fqdn = $ipProps.HostName }
} catch { $fqdn = $env:COMPUTERNAME }

try {
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $osDetail = "$($osInfo.Caption) (Build $($osInfo.Version))"
} catch { $osDetail = "Unknown OS" }

try {
    $sysInfo = Get-CimInstance Win32_ComputerSystem; $manuf = $sysInfo.Manufacturer; $model = $sysInfo.Model
    if ($model -match 'Virtual' -or $manuf -match 'VMware|Microsoft Corporation|Xen|Red Hat|Amazon|QEMU') {
        $hwType = "Virtual"; if ($manuf -match 'VMware') { $tech = "VMware vSphere/ESXi" } elseif ($manuf -match 'Microsoft' -and $model -match 'Virtual') { $tech = "Microsoft Hyper-V" } else { $tech = "Hypervisor ($model)" }
        $hardwareInfo = "$hwType ($tech)"
    } else { $hwType = "Physical"; $hardwareInfo = "$hwType ($manuf $model)" }
} catch { $hardwareInfo = "Unknown Hardware" }

if ($scriptStartTime) {
    $span = New-TimeSpan -Start $scriptStartTime -End (Get-Date)
    $durationStr = "{0:00}m {1:00}s" -f $span.Minutes, $span.Seconds
} else { $durationStr = "N/A" }

$currentDate = Get-Date -Format "dd-MM-yyyy HH:mm"
$targetName = $env:COMPUTERNAME

#region logoBase64
$logoPath = Join-Path -Path $PSScriptRoot -ChildPath "assets\logo.txt"

if (Test-Path $logoPath) {
    $logoBase64 = Get-Content -Path $logoPath -Raw
    $logoBase64 = $logoBase64.Trim()
} else {
    Write-Warning "Logo file not found at $logoPath. Report will be generated without logo."
}
#endregion

$catHtml = ""

$priorityHtml = ""

$topRisks = $checks | Where-Object { $_.Status -eq "Critical" } | Sort-Object Weight -Descending | Select-Object -First 3

if ($topRisks) {
    $priorityHtml = @"
    <div style='margin-top:1.5rem; text-align:left; border-top:1px solid rgba(255,255,255,0.1); padding-top:1rem;'>
        <h4 style='color:var(--danger); font-size:0.85rem; margin-bottom:0.8rem; text-transform:uppercase; letter-spacing:1px;'>&#9888; Priority Fixes</h4>
        <ul style='list-style:none; padding:0; color:var(--text-muted); font-size:0.85rem;'>
"@
    foreach ($risk in $topRisks) {
        $priorityHtml += "<li style='margin-bottom:0.6rem; display:flex; align-items:start;'><span style='color:var(--danger); margin-right:8px; font-weight:bold;'>&rsaquo;</span><span>$($risk.Name)</span></li>"
    }
    $priorityHtml += "</ul></div>"
} else {

    $priorityHtml = "<div style='margin-top:1.5rem; text-align:center; color:var(--success); font-size:0.85rem; border-top:1px solid rgba(255,255,255,0.1); padding-top:1rem;'>&check; No critical priorities detected. Good job!</div>"
}


$categories = $checks | Select-Object -ExpandProperty Category -Unique | Sort-Object

foreach ($cat in $categories) {

    $catChecks = $checks | Where-Object { $_.Category -eq $cat -and $_.MaxScore -gt 0 }
    
    if ($catChecks) {
        $catMax    = ($catChecks | Measure-Object -Property MaxScore -Sum).Sum
        $catEarned = ($catChecks | Measure-Object -Property Score -Sum).Sum
        
        $catPct = 0
        if ($catMax -gt 0) { $catPct = [Math]::Round(($catEarned / $catMax) * 100) }

        $barColor = "var(--danger)"
        if ($catPct -ge 80) { $barColor = "var(--success)" }
        elseif ($catPct -ge 50) { $barColor = "var(--warning)" }

        $catHtml += @"
        <div class='cat-row'>
            <div class='cat-name' title='$cat'>$cat</div>
            <div class='progress-track'>
                <div class='progress-fill' style='width: $catPct%; background-color: $barColor;'></div>
            </div>
            <div class='cat-percent'>$catPct%</div>
        </div>
"@
    }
}

$jsonPayload = @($checks) | ConvertTo-Json -Depth 5 -Compress; 
$jsonNIS2 = $NIS2RationaleMap | ConvertTo-Json -Compress

$htmlTemplate = Get-Content "$PSScriptRoot\templates\report.html" -Raw

$finalHtml = $htmlTemplate
$finalHtml = $finalHtml.Replace('##FQDN##', $fqdn)
$finalHtml = $finalHtml.Replace('##OS_INFO##', $osDetail)
$finalHtml = $finalHtml.Replace('##HARDWARE##', $hardwareInfo)
$finalHtml = $finalHtml.Replace('##DURATION##', $durationStr)
$finalHtml = $finalHtml.Replace('##DATE##', $currentDate)
$finalHtml = $finalHtml.Replace('##GRADE##', $grade)
$finalHtml = $finalHtml.Replace('##SCORE##', "$securityScore")
$finalHtml = $finalHtml.Replace('##SUMMARY##', $summaryText)
$finalHtml = $finalHtml.Replace('##GRADE_COLOR##', $gradeColor)
$finalHtml = $finalHtml.Replace('##JSON_PAYLOAD##', $jsonPayload)
$finalHtml = $finalHtml.Replace('##NIS2_PAYLOAD##', $jsonNIS2)
$finalHtml = $finalHtml.Replace('##VERSION##', $scriptVersion)
$finalHtml = $finalHtml.Replace('##LOGO##', $logoBase64)
$finalHtml = $finalHtml.Replace('##CAT_BARS##', $catHtml)
$finalHtml = $finalHtml.Replace('##PRIORITY_FIXES##', $priorityHtml)

$finalHtml | Out-File $outHtml -Encoding UTF8

Write-Host "`n[SUCCESS] Dashboard Report generated: $outHtml" -ForegroundColor Green

}

else {
    Write-Host "`n[INFO] HTML Report generation skipped (-JSONOnly selected)." -ForegroundColor Gray
}

Stop-Transcript | Out-Null

Write-Progress -Activity "Windows Server Security Audit Script" -Completed

Write-Host "========================================"
Write-Host " WINDOWS SERVER SECURITY AUDIT COMPLETE" -ForegroundColor Cyan
Write-Host " Score: $securityScore / 100" -ForegroundColor $(if($securityScore -ge 80){'Green'}else{'Red'})
Write-Host " Critical Issues: $countCrit" -ForegroundColor Red
Write-Host " Warnings: $countWarn" -ForegroundColor Yellow
Write-Host " Successful completion!" -ForegroundColor White
Write-Host "======================================== `n"

#endregion
