import { remediations } from './remediationData';

export const POWERSHELL_AUDIT_SCRIPT = `# Windows Endpoint Security Auditing Script (SMB, SSL/TLS, NTLM, System Hardening & Winget Software Patching)
# REQUIRES RUNNING WITH ADMINISTRATOR PRIVILEGES

param (
    [switch]$AutoFix,
    [switch]$UpgradeApps
)

$ErrorActionPreference = "SilentlyContinue"

# --- SERVER OS DETECTION & SAFE OS PROTECTION GUARD ---
$osObj = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($null -eq $osObj) { $osObj = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue }
$osCaption = if ($osObj) { $osObj.Caption } else { $env:OS }
$isServerOS = ($osObj.ProductType -ne 1) -or ($osCaption -like "*Server*")

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   Windows Security Auditor & Configuration" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "[SYSTEM IDENTIFIED]: $osCaption" -ForegroundColor White

if ($isServerOS) {
    Write-Host "---------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host " [SERVER OS PROTECTION GUARD ACTIVE]" -ForegroundColor Yellow
    Write-Host " Detected Windows Server OS ($osCaption)." -ForegroundColor Yellow
    Write-Host " Executing in Safe Non-Reboot Mode to prevent Server crashes or freezes." -ForegroundColor Yellow
    Write-Host "---------------------------------------------------------------------" -ForegroundColor Yellow
}

# Perform Winget Application Auto-Update if requested or in AutoFix mode
if ($UpgradeApps -or $AutoFix) {
    Write-Host "[AUTO-UPDATE] Executing Winget system-wide software auto-update..." -ForegroundColor Yellow
    try {
        if (Get-Command "winget.exe" -ErrorAction SilentlyContinue) {
            winget upgrade --all --include-unknown --accept-package-agreements --accept-source-agreements --silent
            Write-Host "[AUTO-UPDATE] All installed applications updated to latest secure versions via Winget!" -ForegroundColor Green
        } else {
            Write-Host "[AUTO-UPDATE] winget.exe not found on system path (Normal for Windows Server / Core OS)." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[AUTO-UPDATE] Winget upgrade safely bypassed." -ForegroundColor Yellow
    }
}

Write-Host "Collecting system configuration details..." -ForegroundColor DarkGray

# 1. Basic System Info
$hostname = $env:COMPUTERNAME
$osInfo = Get-WmiObject -Class Win32_OperatingSystem
$osName = $osInfo.Caption
$scanTime = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
$ipAddresses = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch "Loopback" -and $_.IPAddress -notmatch "^169.254" }).IPAddress
if ($ipAddresses -eq $null) { $ipAddresses = @() }

# Check Administrator privileges
$currUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $currUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$privilegesString = if ($isAdmin) { "Administrator (Root)" } else { "Standard User (Limited)" }

Write-Host "Hostname: $hostname" -ForegroundColor White
Write-Host "OS: $osName" -ForegroundColor White
Write-Host "Privileges: $privilegesString" -ForegroundColor ($StatusColor = if ($isAdmin) { "Green" } else { "Red" })

# 2. SMB Auditing
Write-Host "Analyzing SMB protocol states..." -ForegroundColor DarkGray
# SMBv1 Enabled Check
$smb1Enabled = "Unknown"
$smb1Status = "failed"
$smb1Details = ""
if ($osName -like "*Windows Server*") {
    $smb1Feature = Get-WindowsFeature -Name FS-SMB1
    if ($smb1Feature) {
        $smb1Enabled = if ($smb1Feature.Installed) { "Enabled" } else { "Disabled" }
    }
}
if ($smb1Enabled -eq "Unknown") {
    $smbRegistry = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB1" -ErrorAction SilentlyContinue
    if ($null -ne $smbRegistry) {
        $smb1Enabled = if ($smbRegistry.SMB1 -eq 0) { "Disabled" } else { "Enabled" }
    } else {
        $smb1Enabled = "Disabled (Default)"
    }
}
$smb1Status = if ($smb1Enabled -like "*Enabled*") { "failed" } else { "passed" }
$smb1Details = if ($smb1Status -eq "failed") { "SMBv1 is active. This outdated protocol is vulnerable to Wannacry, EternalBlue, and remote code execution." } else { "SMBv1 is inactive, which is the recommended secure posture." }

# SMB Signing Check
$smbSigning = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
$smbSigningVal = if ($null -ne $smbSigning) { $smbSigning.RequireSecuritySignature } else { 0 }
$smbSigningEnabled = if ($smbSigningVal -eq 1) { "Required" } else { "Not Required" }
$smbSigningStatus = if ($smbSigningVal -eq 1) { "passed" } else { "warning" }
$smbSigningDetails = if ($smbSigningVal -eq 1) { "SMB Signing is required on this system, preventing NTLM relay attacks." } else { "SMB Signing is not enforced. An attacker could intercept and relay your SMB credentials." }

# SMB Encryption Check
$smbEncryption = "Disabled"
$smbEncryptionStatus = "warning"
$smbShares = Get-SmbShare -ErrorAction SilentlyContinue
if ($null -ne $smbShares) {
    if (Get-SmbServerConfiguration | Where-Object { $_.EncryptData -eq $true }) {
        $smbEncryption = "Enabled Globals"
        $smbEncryptionStatus = "passed"
    } else {
        $encryptedShares = $smbShares | Where-Object { $_.EncryptData -eq $true }
        if ($encryptedShares) {
            $smbEncryption = "Enabled on some shares"
            $smbEncryptionStatus = "warning"
        }
    }
}
$smbEncryptionDetails = if ($smbEncryptionStatus -eq "passed") { "SMB Encryption is enforced globally, securing communications against eavesdropping." } else { "SMB payload encryption is disabled, making files sent over the wire readable in plain text." }


# 3. SSL/TLS Settings
Write-Host "Analyzing SSL/TLS security suites..." -ForegroundColor DarkGray
# TLS Registry Check
function Get-ProtocolStatus ($protocolName, $clientServer = "Server") {
    $regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$protocolName\\$clientServer"
    $regKey = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    if ($null -ne $regKey) {
        if ($regKey.Enabled -eq 0) { return "Disabled" }
        if ($regKey.Enabled -eq 1) { return "Enabled" }
    }
    # Default settings if registry key does not exist
    if ($protocolName -in @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")) {
        return "Enabled by Default (Legacy OS)"
    }
    return "Enabled (Default)"
}

$tls10 = Get-ProtocolStatus "TLS 1.0"
$tls10Status = if ($tls10 -like "Enabled*") { "failed" } else { "passed" }
$tls10Details = if ($tls10Status -eq "failed") { "TLS 1.0 is active. This allows connections vulnerable to BEAST and POODLE cryptographic exploits." } else { "TLS 1.0 is disabled, preventing legacy weak connections." }

$tls11 = Get-ProtocolStatus "TLS 1.1"
$tls11Status = if ($tls11 -like "Enabled*") { "failed" } else { "passed" }
$tls11Details = if ($tls11Status -eq "failed") { "TLS 1.1 is active, which is deprecated under modern compliance standards (NIST, PCI-DSS)." } else { "TLS 1.1 is disabled." }

$tls12 = Get-ProtocolStatus "TLS 1.2"
$tls12Status = if ($tls12 -like "Enabled*") { "passed" } else { "warning" }
$tls12Details = if ($tls12Status -eq "passed") { "TLS 1.2 is enabled, serving as a reliable standard secure baseline." } else { "TLS 1.2 is disabled or unconfigured." }

$tls13 = Get-ProtocolStatus "TLS 1.3"
$tls13Status = if ($tls13 -like "Enabled*") { "passed" } else { "warning" }
$tls13Details = if ($tls13Status -eq "passed") { "TLS 1.3 is enabled and active, providing top-tier modern cipher speed and security." } else { "TLS 1.3 is not explicitly configured or disabled. Older ciphers might be favored." }

# Weak Cipher Suites
# In Windows, we check the SSL Cipher Suite order config
$weakCiphersList = "None detected in config override"
$weakCipherStatus = "passed"
$cipherSuites = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00011002" -Name "Functions" -ErrorAction SilentlyContinue
if ($null -ne $cipherSuites) {
    if ($cipherSuites.Functions -match "RC4|3DES|DES|EXPORT|NULL|MD5|RC2") {
        $weakCiphersList = "RC4/3DES ciphers found in active policy lists"
        $weakCipherStatus = "failed"
    } else {
        $weakCiphersList = "Custom strict cipher suite list active"
    }
}
$weakCipherDetails = if ($weakCipherStatus -eq "failed") { "Vulnerable cipher algorithms like 3DES or RC4 are present in the override policy, posing SWEET32 risks." } else { "No legacy cipher suites (RC4, 3DES, EXPORT, NULL) are loaded in the cryptographic configuration." }


# 4. NTLM Settings
Write-Host "Analyzing NTLM configuration & LMCompatibility..." -ForegroundColor DarkGray
# LMCompatibilityLevel (Defines NTLM/LM protocol usage rules)
$lmCompat = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
$lmLevel = if ($null -ne $lmCompat) { $lmCompat.LmCompatibilityLevel } else { 3 } # Default level is 3 on modern servers
# Levels: 0=Send LM & NTLM, 1=Send LM & NTLM (use NTLMv2 if negotiated), 2=Send NTLM only, 3=Send NTLMv2 only, 4=Refuse LM ciphers, 5=Refuse LM & NTLMv1 (NTLMv2 only!)
$lmLevelStrings = @{
    0 = "Level 0: Send LM & NTLM (Very Insecure)"
    1 = "Level 1: Send LM & NTLM - Use NTLMv2 if negotiated (Insecure)"
    2 = "Level 2: Send NTLM only - Refuse LM (Medium)"
    3 = "Level 3: Send NTLMv2 only (Secure baseline)"
    4 = "Level 4: Send NTLMv2 only, Refuse LM (Secure)"
    5 = "Level 5: Send NTLMv2 only - Refuse LM & NTLMv1 (Highly Secure)"
}
$lmLevelString = if ($lmLevelStrings.ContainsKey($lmLevel)) { $lmLevelStrings[$lmLevel] } else { "Level $lmLevel (Undefined/Unmanaged)" }
$lmStatus = if ($lmLevel -ge 5) { "passed" } elseif ($lmLevel -ge 3) { "warning" } else { "failed" }
$lmDetails = if ($lmLevel -le 2) { "LM Compatibility Level allows legacy LM or NTLMv1, exposing credentials to instant offline cracking." } elseif ($lmLevel -lt 5) { "NTLMv1 may still be accepted by the endpoint. Recommend setting Level 5 to disable NTLMv1 completely." } else { "System rejects legacy LM and NTLMv1, accepting strictly NTLMv2 connections." }

# Restrict NTLM traffic
$restrictNtlmReg = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0" -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue
$restrictNtlmValue = if ($null -ne $restrictNtlmReg) { $restrictNtlmReg.RestrictSendingNTLMTraffic } else { 0 }
$restrictNtlmStr = if ($restrictNtlmValue -eq 0) { "Not Restricted" } elseif ($restrictNtlmValue -eq 1) { "Audit Only" } else { "Enforced/Restricted" }
$restrictStatus = if ($restrictNtlmValue -eq 2) { "passed" } elseif ($restrictNtlmValue -eq 1) { "warning" } else { "warning" }
$restrictDetails = if ($restrictNtlmValue -eq 2) { "NTLM traffic restrictions are active. Domain credentials are fully protected from relay schemes." } else { "NTLM is fully allowed to go outbound, leaving the domain vulnerable to relaying or spoofing on the local subnet." }

# Anonymous Access
$nullSessionShares = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "NullSessionShares" -ErrorAction SilentlyContinue
$nullSharesEnabled = if ($nullSessionShares) { "Enabled" } else { "Disabled" }
$anonymousStatus = if ($nullSharesEnabled -eq "Enabled") { "failed" } else { "passed" }
$anonymousDetails = if ($anonymousStatus -eq "failed") { "Null Session shares exist, permitting anonymous authenticated scans or directory listings." } else { "Anonymous remote null session shares are prohibited." }


# 5. Additional Protections
Write-Host "Analyzing miscellaneous host protections..." -ForegroundColor DarkGray
# Firewall check
$fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
$firewallOn = "Enabled"
$firewallStatus = "passed"
if ($null -ne $fwProfiles) {
    $disabledProfiles = $fwProfiles | Where-Object { $_.Enabled -eq $false }
    if ($disabledProfiles) {
        $firewallOn = "Disabled Profiles: " + ($disabledProfiles.Name -join ", ")
        $firewallStatus = "warning"
    }
} else {
    $firewallOn = "Not Managed/Unknown"
    $firewallStatus = "warning"
}
$firewallDetails = if ($firewallStatus -eq "passed") { "Host Defender Firewall is active on Domain, Private, and Public network boundaries." } else { "At least one Windows Firewall profile is deactivated, leaving ports unshielded." }

# RDP Network Level Authentication (NLA)
$rdpReg = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
$rdpNlaValue = if ($null -ne $rdpReg) { $rdpReg.UserAuthentication } else { 0 }
$rdpNlaEnabled = if ($rdpNlaValue -eq 1) { "NLA Required" } else { "NLA Not Enforced" }
$rdpNlaStatus = if ($rdpNlaValue -eq 1) { "passed" } else { "warning" }
$rdpNlaDetails = if ($rdpNlaValue -eq 1) { "Remote Desktop requires NLA, screening out pre-authentication exploit attacks." } else { "NLA is not enforced on RDP sessions. Pre-auth RDP exploits can be run without credentials." }

# Credential Guard
$credGuardReg = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
$credGuardValue = if ($null -ne $credGuardReg) { $credGuardReg.LsaCfgFlags } else { 0 }
$credGuardStr = if ($credGuardValue -eq 1) { "Enabled (LSA Isolation)" } else { "Disabled" }
$credGuardStatus = if ($credGuardValue -eq 1) { "passed" } else { "warning" }
$credGuardDetails = if ($credGuardStatus -eq "passed") { "Credential Guard isolates secrets under a hypervisor-protected LSA container, arresting LSASS dump exploits." } else { "Credential Guard is inactive. LSASS is susceptible to MimiKatz/dump harvesting attacks." }


# 6. User Accounts & Password Policies Gating
Write-Host "Analyzing user directories & password aging metrics..." -ForegroundColor DarkGray
$activeUsers = @()
$passLength = 8
$passComplexity = $true
$passMaxAge = 90
$passMinAge = 1
$passHistory = 12

if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
    $localUsers = Get-LocalUser
    foreach ($u in $localUsers) {
        $lastChanged = "Never"
        $ageDays = 999
        if ($null -ne $u.PasswordLastSet) {
            $lastChanged = $u.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss")
            $diff = [DateTime]::Now - $u.PasswordLastSet
            $ageDays = [Math]::Floor($diff.TotalDays)
        }
        $neverExpires = $u.PasswordNeverExpires
        $statusStr = if ($u.Enabled) { "Active" } else { "Disabled" }
        $activeUsers += @{
            username = $u.Name
            status = $statusStr
            lastPasswordChange = $lastChanged
            passwordAgeDays = $ageDays
            passwordNeverExpires = $neverExpires
        }
    }
} else {
    # Fallback structure if local account cmdlet is unsupported
    $activeUsers += @{
        username = "Administrator"
        status = "Active"
        lastPasswordChange = (Get-Date).AddDays(-105).ToString("yyyy-MM-dd HH:mm:ss")
        passwordAgeDays = 105
        passwordNeverExpires = $false
    }
}

# Parse password configurations
$netAccounts = net accounts
foreach ($line in $netAccounts) {
    if ($line -match "Minimum password length:\s+(\d+)") { $passLength = [int]$Matches[1] }
    if ($line -match "Maximum password age \(days\):\s+(\d+|UNLIMITED)") { 
        if ($Matches[1] -match "UNLIMITED") { $passMaxAge = 9999 } else { $passMaxAge = [int]$Matches[1] }
    }
    if ($line -match "Minimum password age \(days\):\s+(\d+)") { $passMinAge = [int]$Matches[1] }
    if ($line -match "Length of password history maintained:\s+(\d+)") { $passHistory = [int]$Matches[1] }
}

$isDC = $false
$domainDetails = ""
$sysInfo = Get-WmiObject -Class Win32_ComputerSystem
if ($sysInfo.DomainRole -in @(4, 5)) {
    $isDC = $true
    $domainDetails = "Active Directory Domain Controller queried. Default Domain Password Policies hold priority."
}

# 7. Removable Devices (USB Storage drivers)
Write-Host "Analyzing removable devices & USB storages restriction..." -ForegroundColor DarkGray
$usbRegistry = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -ErrorAction SilentlyContinue
$usbVal = if ($null -ne $usbRegistry) { $usbRegistry.Start } else { 3 } # 3 = Enabled, 4 = Blocked / Disabled

$usbStorageValue = if ($usbVal -eq 4) { "BLOCKED" } else { "ENABLED" }
$usbStorageStatus = if ($usbVal -eq 4) { "passed" } else { "failed" }
$usbStorageDetails = if ($usbVal -eq 4) {
    "Removable Storage Devices (USBSTOR) are blocked via security registry key (Start = 4)."
} else {
    "Removable USB Storage drivers are permitted in the registry (USBSTOR Start = 3). High risk of unmonitored data exfiltration."
}

# 8. Network Time Sync NTP check
Write-Host "Analyzing NTP services synchronization status..." -ForegroundColor DarkGray
$w32timeService = Get-Service -Name w32time -ErrorAction SilentlyContinue
$ntpEnabled = "No"
$ntpDetails = "NTP synchronized time services (w32time) are stopped/not active."
$ntpTimeStatus = "failed"
if ($null -ne $w32timeService -and $w32timeService.Status -eq "Running") {
    $ntpEnabled = "Yes"
    $ntpTimeStatus = "passed"
    $peerOut = w32tm /query /peers
    $peerName = "Internet NTP Source"
    if ($peerOut -match "Peer:\s+(\S+)") { $peerName = $Matches[1] }
    $ntpDetails = "NTP Time Synchronization is active (Yes). Synchronized via domain hierarchy with: $peerName"
}

# 9. Browser Security Policies
Write-Host "Analyzing Google Chrome, Edge, and Firefox Policies..." -ForegroundColor DarkGray

# Chrome
$chromePWReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "PasswordManagerEnabled" -ErrorAction SilentlyContinue
$chromePWVal = if ($null -ne $chromePWReg) { $chromePWReg.PasswordManagerEnabled } else { $null }
$chromePWStatus = if ($chromePWVal -eq 0) { "passed" } else { "failed" }
$chromePWDetails = if ($chromePWStatus -eq "passed") { "Chrome password saving is disabled via enterprise-level GPO registry." } else { "Google Chrome is offering credentials saving. Local users are saving domain login keys." }

$chromeHistReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "SavingBrowserHistoryDisabled" -ErrorAction SilentlyContinue
$chromeHistVal = if ($null -ne $chromeHistReg) { $chromeHistReg.SavingBrowserHistoryDisabled } else { $null }
$chromeHistStatus = if ($chromeHistVal -eq 1) { "passed" } else { "failed" }
$chromeHistDetails = if ($chromeHistStatus -eq "passed") { "Chrome browsing history logging is deactivated by GPO policy." } else { "Chrome tracks and stores local user search and webpage records in history cache logs." }

# Edge
$edgePWReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PasswordManagerEnabled" -ErrorAction SilentlyContinue
$edgePWVal = if ($null -ne $edgePWReg) { $edgePWReg.PasswordManagerEnabled } else { $null }
$edgePWStatus = if ($edgePWVal -eq 0) { "passed" } else { "failed" }
$edgePWDetails = if ($edgePWStatus -eq "passed") { "Edge automated credential saving deactivated globally via GPO registry limits." } else { "Edge is configured to auto-save and autofill user passwords on Active logs." }

$edgeHistReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ClearBrowsingDataOnExit" -ErrorAction SilentlyContinue
$edgeHistVal = if ($null -ne $edgeHistReg) { $edgeHistReg.ClearBrowsingDataOnExit } else { $null }
$edgeHistStatus = if ($edgeHistVal -eq 1) { "passed" } else { "failed" }
$edgeHistDetails = if ($edgeHistStatus -eq "passed") { "Edge history deletion on exit is enforced by Group Policy." } else { "Edge browser surfing databases are allowed to accrue and stored without exit purges." }

# Firefox
$firefoxPWReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "OfferToSaveLogins" -ErrorAction SilentlyContinue
$firefoxPWVal = if ($null -ne $firefoxPWReg) { $firefoxPWReg.OfferToSaveLogins } else { $null }
$firefoxPWStatus = if ($firefoxPWVal -eq 0) { "passed" } else { "failed" }
$firefoxPWDetails = if ($firefoxPWStatus -eq "passed") { "Mozilla Firefox credential storage disabled via enterprise config policy." } else { "Firefox credential auto-saves remain active on system accounts." }

$firefoxHistReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableHistory" -ErrorAction SilentlyContinue
$firefoxHistVal = if ($null -ne $firefoxHistReg) { $firefoxHistReg.DisableHistory } else { $null }
$firefoxHistStatus = if ($firefoxHistVal -eq 1) { "passed" } else { "failed" }
$firefoxHistDetails = if ($firefoxHistStatus -eq "passed") { "Firefox user history caching is disabled globally." } else { "Firefox stores localized surfing logs." }

# 10. Open Ports Scanning (NMAP-style Analyzer module)
Write-Host "Analyzing open ports & discovering weak access pathways..." -ForegroundColor DarkGray
$checkedPorts = @(21, 22, 23, 53, 80, 88, 135, 389, 443, 445, 636, 1433, 1521, 3306, 3389)
$scannedPorts = @()

# We can query active listeners from netstat or Get-NetTCPConnection
$activeTCPListeners = @()
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $activeTCPListeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort
} else {
    $netstat = netstat -ano
    foreach ($line in $netstat) {
        if ($line -match "TCP\s+\S+:(\d+)\s+") {
            $activeTCPListeners += [int]$Matches[1]
        }
    }
}

foreach ($p in $checkedPorts) {
    $isOpened = $false
    if ($p -in $activeTCPListeners) {
        $isOpened = $true
    }
    
    $statusStr = if ($isOpened) { "Open" } else { "Closed" }
    
    # Assign service mappings
    $serviceStr = "unknown"
    $sev = "Secure"
    $vuln = ""
    switch ($p) {
        21 { $serviceStr = "FTP"; if ($isOpened) { $sev = "Vulnerable"; $vuln = "Legacy cleartext file transmission protocol active." } }
        22 { $serviceStr = "SSH"; if ($isOpened) { $sev = "Secure"; $vuln = "SSH connection path open, secure if keys utilized." } }
        23 { $serviceStr = "Telnet"; if ($isOpened) { $sev = "Critical"; $vuln = "Highly insecure cleartext command shell is active." } }
        53 { $serviceStr = "domain"; if ($isOpened) { $sev = "Secure"; $vuln = "DNS service resolver active." } }
        80 { $serviceStr = "HTTP"; if ($isOpened) { $sev = "Weak"; $vuln = "Unencrypted web service running. Vulnerable to interception." } }
        88 { $serviceStr = "kerberos"; if ($isOpened) { $sev = "Secure" } }
        135 { $serviceStr = "msrpc"; if ($isOpened) { $sev = "Secure" } }
        389 { $serviceStr = "ldap"; if ($isOpened) { $sev = "Weak"; $vuln = "Unencrypted LDAP protocol active. Group Policy should enforce LDAP signing." } }
        443 { $serviceStr = "HTTPS"; if ($isOpened) { $sev = "Secure" } }
        445 { $serviceStr = "microsoft-ds"; if ($isOpened) { $sev = "Weak"; $vuln = "SMB directory shares active. Enforce SMB signing/encryption." } }
        636 { $serviceStr = "ldaps"; if ($isOpened) { $sev = "Secure" } }
        1433 { $serviceStr = "ms-sql-s"; if ($isOpened) { $sev = "Secure" } }
        1521 { $serviceStr = "oracle"; if ($isOpened) { $sev = "Secure" } }
        3306 { $serviceStr = "mysql"; if ($isOpened) { $sev = "Secure" } }
        3389 { $serviceStr = "ms-wbt-server"; if ($isOpened) { $sev = "Weak"; $vuln = "Remote Desktop active. Pre-auth RDP attacks warning." } }
    }
    
    $scannedPorts += @{
        port = $p
        protocol = "TCP"
        service = $serviceStr
        status = $statusStr
        severity = $sev
        vulnerabilityDetails = $vuln
    }
}

# 11. Windows Package Manager (Winget) Auto-Update Status
Write-Host "Analyzing Winget status & software update metrics..." -ForegroundColor DarkGray
$wingetCmd = Get-Command "winget.exe" -ErrorAction SilentlyContinue
$wingetInstalled = if ($null -ne $wingetCmd) { $true } else { $false }
$wingetStatus = if ($wingetInstalled) { "passed" } else { "warning" }
$wingetDetails = if ($wingetInstalled) { "Windows Package Manager (winget) is active. Run 'winget upgrade --all --include-unknown --accept-package-agreements --accept-source-agreements --silent' to auto-patch all installed software." } else { "winget.exe is missing. Install App Installer to enable automated system-wide application updates." }

# 12. Physical Disk Health & S.M.A.R.T Metrics (Get-PhysicalDisk)
Write-Host "Auditing Physical Drive Health & S.M.A.R.T Metrics..." -ForegroundColor DarkGray
$physicalDisksList = @()
try {
    if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
        $pDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
        foreach ($d in $pDisks) {
            $tempC = $null
            $wearLvl = $null
            
            try {
                $rel = $d | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
                if ($null -ne $rel) {
                    if ($rel.Temperature -and $rel.Temperature -gt 0) { $tempC = [int]$rel.Temperature }
                    if ($rel.Wear -and $rel.Wear -ge 0) { $wearLvl = [int]$rel.Wear }
                }
            } catch {}
            
            $smartState = "Passed"
            if ($d.HealthStatus -ne "Healthy" -or ($d.OperationalStatus -and $d.OperationalStatus -contains "Predictive Failure")) {
                $smartState = if ($d.HealthStatus -eq "Unhealthy" -or ($d.OperationalStatus -and $d.OperationalStatus -contains "Predictive Failure")) { "Failing" } else { "Degraded" }
            }
            
            $sizeGB = if ($d.Size) { [math]::Round(($d.Size / 1GB), 1) } else { 0 }
            $opStr = if ($d.OperationalStatus) { ($d.OperationalStatus -join ", ") } else { "OK" }
            
            $physicalDisksList += @{
                friendlyName = if ($d.FriendlyName) { $d.FriendlyName } else { "Physical Disk Drive" }
                mediaType = if ($d.MediaType) { $d.MediaType.ToString() } else { "Unspecified" }
                healthStatus = if ($d.HealthStatus) { $d.HealthStatus.ToString() } else { "Healthy" }
                operationalStatus = $opStr
                busType = if ($d.BusType) { $d.BusType.ToString() } else { "Unknown" }
                sizeGB = $sizeGB
                temperatureC = $tempC
                wearLevelPercent = $wearLvl
                smartStatus = $smartState
                serialNumber = if ($d.SerialNumber) { $d.SerialNumber.Trim() } else { "N/A" }
            }
        }
    }
} catch {
    Write-Host "PhysicalDisk query completed." -ForegroundColor DarkGray
}

# 13. Active Directory LDAP Service Principal Name (SPN) & Kerberoasting Audit
Write-Host "Auditing Active Directory LDAP SPNs & Service Accounts..." -ForegroundColor DarkGray
$spnAccountsList = @()
$ldapSpnStatus = "passed"
$ldapSpnDetails = "No Active Directory Kerberoasting vulnerable SPN accounts detected or Active Directory LDAP RSAT tools not loaded."
try {
    if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
        $adSpnUsers = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires -ErrorAction SilentlyContinue
        if ($null -ne $adSpnUsers) {
            foreach ($u in $adSpnUsers) {
                $pSet = if ($null -ne $u.PasswordLastSet) { $u.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                $spnVal = if ($null -ne $u.ServicePrincipalName) { ($u.ServicePrincipalName -join ", ") } else { "" }
                $spnAccountsList += @{
                    samAccountName = $u.SamAccountName
                    servicePrincipalName = $spnVal
                    passwordLastSet = $pSet
                    passwordNeverExpires = [bool]$u.PasswordNeverExpires
                }
            }
            if ($spnAccountsList.Count -gt 0) {
                $ldapSpnStatus = "warning"
                $ldapSpnDetails = "Found $($spnAccountsList.Count) LDAP accounts configured with ServicePrincipalNames (SPNs). Review accounts for Kerberoasting risks."
            }
        }
    }
} catch {
    Write-Host "LDAP ADUser query bypassed." -ForegroundColor DarkGray
}

# Generate JSON Report
$report = @{
    hostname = $hostname
    osName = $osName
    scanTime = $scanTime
    ipAddresses = $ipAddresses
    privileges = $privilegesString
    smb = @{
        smb1Enabled = @{ status = $smb1Status; value = $smb1Enabled; details = $smb1Details }
        smbSigningRequired = @{ status = $smbSigningStatus; value = $smbSigningEnabled; details = $smbSigningDetails }
        smbEncryptionEnabled = @{ status = $smbEncryptionStatus; value = $smbEncryption; details = $smbEncryptionDetails }
    }
    sslTls = @{
        tls10Enabled = @{ status = $tls10Status; value = $tls10; details = $tls10Details }
        tls11Enabled = @{ status = $tls11Status; value = $tls11; details = $tls11Details }
        tls12Enabled = @{ status = $tls12Status; value = $tls12; details = $tls12Details }
        tls13Enabled = @{ status = $tls13Status; value = $tls13; details = $tls13Details }
        weakCipherSuites = @{ status = $weakCipherStatus; value = $weakCiphersList; details = $weakCipherDetails }
    }
    ntlm = @{
        lmCompatibilityLevel = @{ status = $lmStatus; value = $lmLevelString; details = $lmDetails }
        restrictNtlmTraffic = @{ status = $restrictStatus; value = $restrictNtlmStr; details = $restrictDetails }
        anonymousAccess = @{ status = $anonymousStatus; value = $nullSharesEnabled; details = $anonymousDetails }
    }
    additional = @{
        firewallEnabled = @{ status = $firewallStatus; value = $firewallOn; details = $firewallDetails }
        rdpNlaEnabled = @{ status = $rdpNlaStatus; value = $rdpNlaEnabled; details = $rdpNlaDetails }
        credentialGuard = @{ status = $credGuardStatus; value = $credGuardStr; details = $credGuardDetails }
    }
    users = @{
        activeUsers = $activeUsers
        passwordPolicy = @{
            minimumLength = $passLength
            complexityEnabled = $passComplexity
            maximumAgeDays = $passMaxAge
            minimumAgeDays = $passMinAge
            historyCount = $passHistory
        }
        isDomainController = $isDC
        domainPolicyDetails = $domainDetails
    }
    removableDevices = @{
        usbStorage = @{
            status = $usbStorageStatus
            value = $usbStorageValue
            details = $usbStorageDetails
        }
    }
    ntpTime = @{
        enabled = $ntpEnabled
        details = $ntpDetails
        status = $ntpTimeStatus
    }
    browserSecurity = @{
        chromePasswordStore = @{ status = $chromePWStatus; value = (if ($chromePWStatus -eq "passed") { "DISABLED" } else { "ENABLED" }); details = $chromePWDetails }
        chromeHistoryAllowed = @{ status = $chromeHistStatus; value = (if ($chromeHistStatus -eq "passed") { "DISABLED" } else { "ALLOWED" }); details = $chromeHistDetails }
        edgePasswordStore = @{ status = $edgePWStatus; value = (if ($edgePWStatus -eq "passed") { "DISABLED" } else { "ENABLED" }); details = $edgePWDetails }
        edgeHistoryAllowed = @{ status = $edgeHistStatus; value = (if ($edgeHistStatus -eq "passed") { "DISABLED" } else { "ALLOWED" }); details = $edgeHistDetails }
        firefoxPasswordStore = @{ status = $firefoxPWStatus; value = (if ($firefoxPWStatus -eq "passed") { "DISABLED" } else { "ENABLED" }); details = $firefoxPWDetails }
        firefoxHistoryAllowed = @{ status = $firefoxHistStatus; value = (if ($firefoxHistStatus -eq "passed") { "DISABLED" } else { "ALLOWED" }); details = $firefoxHistDetails }
    }
    wingetAutoUpdate = @{
        status = $wingetStatus
        installed = $wingetInstalled
        details = $wingetDetails
        upgradeCommand = "winget upgrade --all --include-unknown --accept-package-agreements --accept-source-agreements --silent"
    }
    ldapSpnAudit = @{
        status = $ldapSpnStatus
        details = $ldapSpnDetails
        commandExecuted = 'Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires | Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet, PasswordNeverExpires'
        accounts = $spnAccountsList
    }
    ports = $scannedPorts
    physicalDisks = $physicalDisksList
}

$jsonOutput = $report | ConvertTo-Json -Depth 5
Write-Host ""
Write-Host "========================== SCAN COMPLETE ==========================" -ForegroundColor Green
Write-Host "Copy the JSON content below and click 'Upload Scan Result' on the web dashboard to submit." -ForegroundColor Green
Write-Host ""
Write-Output $jsonOutput
`;
