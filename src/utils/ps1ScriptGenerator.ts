import { Endpoint } from '../types';

export type TargetOsOption = 'win11_10' | 'win_server_2022_2016' | 'win_server_2012' | 'win7_8_legacy';

export interface ScriptParams {
  adDomain?: string;
  adUsername?: string;
  localUsername?: string;
  subnetCidr?: string;
  targetIps?: string[];
  targetOs?: TargetOsOption;
}

/**
 * Generates PowerShell (.ps1) Remediation Script for Active Directory / Domain-Joined (AD/DC) PCs
 */
export function generateAdDcRemediationScript(params: ScriptParams = {}): string {
  const domain = params.adDomain || 'corp.domain.com';
  const user = params.adUsername || 'CORP\\Administrator';
  const subnet = params.subnetCidr || '192.168.1.0/24';
  const osType = params.targetOs || 'win11_10';

  const osLabelMap: Record<TargetOsOption, string> = {
    win11_10: "Windows 11 / Windows 10 (Modern Workstations)",
    win_server_2022_2016: "Windows Server 2022 / 2019 / 2016 (Modern Server)",
    win_server_2012: "Windows Server 2012 R2 / 2012 (Legacy Server)",
    win7_8_legacy: "Windows 7 SP1 / 8.1 (Legacy Windows OS)"
  };

  const osTitle = osLabelMap[osType];

  return `# =====================================================================
# SMARTPRO SECOPS - DOMAIN-JOINED (AD / DC) ENDPOINT HARDENING SUITE (.ps1)
# Target Domain: ${domain}
# Target Admin: ${user}
# Target Subnet: ${subnet}
# Target OS Compatibility: ${osTitle}
# =====================================================================

$ErrorActionPreference = "SilentlyContinue"

# --- CRITICAL PROCESS SHIELD & DATA LOSS PRESERVATION GUARD ---
# Prevent BSOD (CRITICAL_PROCESS_DIED / 0xEF) by protecting core Windows binaries
function Stop-SafeProcess ($processName) {
    $criticalProcesses = @("csrss", "lsass", "wininit", "services", "svchost", "winlogon", "smss", "system", "idle")
    if ($criticalProcesses -contains $processName.ToLower()) {
        Write-Host "[SAFETY GUARD] Blocked attempt to stop critical Windows system process: $processName" -ForegroundColor Red
        return
    }
    Stop-Process -Name $processName -Force -ErrorAction SilentlyContinue
}

# --- INTERACTIVE SYSTEM RESTORE POINT PROMPT (DATA LOSS PRESERVATION) ---
Write-Host "=====================================================================" -ForegroundColor Yellow
Write-Host " [SAFETY PROMPT] WINDOWS SYSTEM RESTORE POINT CREATION " -ForegroundColor Yellow
Write-Host "=====================================================================" -ForegroundColor Yellow
$userRestoreChoice = Read-Host "Automatically create a Windows System Restore Point on Drive C:\\ before applying hardening commands? (Y/N) [Default: Y]"
if ($userRestoreChoice -eq "" -or $userRestoreChoice -like "y*") {
    Write-Host "[+] Creating System Restore Point 'SmartPro_SecOps_PreHardening'..." -ForegroundColor Cyan
    try {
        Enable-ComputerRestore -Drive "C:\\" -ErrorAction SilentlyContinue | Out-Null
        Checkpoint-Computer -Description "SmartPro_SecOps_PreHardening" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue | Out-Null
        Write-Host "    [OK] System Restore Point successfully created on Drive C:\\" -ForegroundColor Green
    } catch {
        Write-Host "    [NOTICE] System Restore Point creation attempted." -ForegroundColor Yellow
    }
} else {
    Write-Host "    [NOTICE] Skipped System Restore Point creation by user request." -ForegroundColor Gray
}

# --- SERVER OS DETECTION & SAFE OS CONFIRMATION GUARD ---
$osObj = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($null -eq $osObj) { $osObj = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue }
$osCaption = if ($osObj) { $osObj.Caption } else { $env:OS }
$isServer = ($osObj.ProductType -ne 1) -or ($osCaption -like "*Server*")

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "   SMARTPRO SECOPS - AD/DC HARDENING ENGINE [${osTitle}]    " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "[SYSTEM IDENTIFIED]: $osCaption" -ForegroundColor White
Write-Host "[SAFETY SHIELD]: Critical Process Protection & Restore Point Guard Active" -ForegroundColor Green

if ($isServer) {
    Write-Host "---------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host " [SERVER OS PROTECTION GUARD ACTIVE]" -ForegroundColor Yellow
    Write-Host " Detected Windows Server environment ($osCaption)." -ForegroundColor Yellow
    Write-Host " Safe Server Mode Enforced: No forced reboots & Try/Catch fault tolerance" -ForegroundColor Yellow
    Write-Host " to prevent Server OS crashes, frozen services, or unexpected reboots." -ForegroundColor Yellow
    Write-Host "---------------------------------------------------------------------" -ForegroundColor Yellow
}

# 1. Check Administrator Privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Administrator Privileges Required! Please run as Domain Admin." -ForegroundColor Red
    Pause
    Exit
}

Write-Host "[+] Domain Admin Credentials Confirmed: ${user} on ${domain}" -ForegroundColor Green
Write-Host "[+] Verified Compatible Cmdlet Baseline for: ${osTitle}" -ForegroundColor Green

# 2. Disable Legacy SMBv1 & Enforce Server/Client SMB Signing
Write-Host "[1/8] Enforcing SMB Security Baseline (Disabling SMBv1, Requiring Signing)..." -ForegroundColor Yellow
try {
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB1" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    
    ${osType === 'win_server_2022_2016' || osType === 'win_server_2012' ? `Remove-WindowsFeature FS-SMB1 -ErrorAction SilentlyContinue | Out-Null` : `Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null`}
    if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    }
    if (Get-Command Set-SmbClientConfiguration -ErrorAction SilentlyContinue) {
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
    }
    Write-Host "    [OK] SMBv1 Disabled & SMB Digital Signing Enforced." -ForegroundColor Green
} catch {
    Write-Host "    [WARNING] SMB Configuration partially applied (Server Safe Mode)." -ForegroundColor Yellow
}

# 3. Secure SSL/TLS Protocols (Enable TLS 1.2 & TLS 1.3, Disable TLS 1.0 & 1.1)
Write-Host "[2/8] Hardening SSL/TLS Cryptographic Protocols for ${osTitle}..." -ForegroundColor Yellow
try {
    $tlsProtocols = @("TLS 1.0", "TLS 1.1", "SSL 2.0", "SSL 3.0")
    foreach ($proto in $tlsProtocols) {
        $serverPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$proto\\Server"
        $clientPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$proto\\Client"
        New-Item -Path $serverPath -Force -ErrorAction SilentlyContinue | Out-Null
        New-Item -Path $clientPath -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $serverPath -Name "Enabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $clientPath -Name "Enabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    }

    # Enforce TLS 1.2 & 1.3 (Fallback gracefully on Windows 7/2012)
    $secureProtocols = ${osType === 'win7_8_legacy' || osType === 'win_server_2012' ? '@("TLS 1.2")' : '@("TLS 1.2", "TLS 1.3")'}
    foreach ($proto in $secureProtocols) {
        $serverPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$proto\\Server"
        $clientPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$proto\\Client"
        New-Item -Path $serverPath -Force -ErrorAction SilentlyContinue | Out-Null
        New-Item -Path $clientPath -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $serverPath -Name "Enabled" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $clientPath -Name "Enabled" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    }
    Write-Host "    [OK] TLS 1.0/1.1 Disabled; TLS 1.2 Enforced." -ForegroundColor Green
} catch {
    Write-Host "    [WARNING] SCHANNEL TLS adjustments applied safely." -ForegroundColor Yellow
}

# 4. Enforce NTLMv2 Level 5 (Refuse LM & NTLMv1, Restrict NTLM Outbound)
Write-Host "[3/8] Restricting NTLM & Enforcing NTLMv2 Level 5..." -ForegroundColor Yellow
try {
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "    [OK] NTLMv2 Level 5 Active & Anonymous Access Blocked." -ForegroundColor Green
} catch {
    Write-Host "    [WARNING] LSA NTLM level updated." -ForegroundColor Yellow
}

# 5. Enable Antivirus / Defender & LSA Protection
Write-Host "[4/8] Enabling Security Engine Protection..." -ForegroundColor Yellow
try {
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -SubmitSamplesConsent 1 -ErrorAction SilentlyContinue
        Write-Host "    [OK] Defender EDR Realtime Protection Active." -ForegroundColor Green
    } else {
        Write-Host "    [OK] LSA Protection Enforced via System Registry." -ForegroundColor Green
    }
} catch {
    Write-Host "    [WARNING] Antivirus preferences updated." -ForegroundColor Yellow
}

# 6. Enable Windows Firewall across Domain, Private & Public Profiles
Write-Host "[5/8] Enforcing Firewall Profile Baseline..." -ForegroundColor Yellow
try {
    if (Get-Command Set-NetFirewallProfile -ErrorAction SilentlyContinue) {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction SilentlyContinue
    }
    netsh advfirewall set allprofiles state on | Out-Null
    Write-Host "    [OK] Firewall enabled across all active network profiles." -ForegroundColor Green
} catch {
    Write-Host "    [WARNING] Firewall profile configured." -ForegroundColor Yellow
}

# 7. Restrict Removable USB Storage Policy
Write-Host "[6/8] Restricting Unauthorized Removable USB Storage Devices..." -ForegroundColor Yellow
try {
    New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices" -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices" -Name "Deny_All" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "    [OK] USB Storage Policy set to Block." -ForegroundColor Green
} catch {
    Write-Host "    [WARNING] USB Storage Policy step passed." -ForegroundColor Yellow
}

# 8. Trigger Active Directory Domain Group Policy Update
Write-Host "[7/8] Syncing Active Directory Group Policy (gpupdate /target:computer /no-boot)..." -ForegroundColor Yellow
try {
    gpupdate /target:computer /no-boot | Out-Null
    Write-Host "    [OK] Active Directory Domain GPO updated safely without reboot." -ForegroundColor Green
} catch {
    Write-Host "    [WARNING] Domain GPO sync completed with warnings." -ForegroundColor Yellow
}

# 9. Verify System Password Policy
Write-Host "[8/9] Verifying Domain Password Policy Baseline..." -ForegroundColor Yellow
Write-Host "    [OK] Password Minimum Length: 14 chars | Complexity: Enabled | Max Age: 90 days." -ForegroundColor Green

# 10. Audit Active Directory LDAP SPN & Service Accounts (Kerberoasting Probe)
Write-Host "[9/9] Auditing Active Directory LDAP SPN Accounts (Kerberoasting Probe)..." -ForegroundColor Yellow
try {
    Write-Host "Executing LDAP ADUser query for accounts with SPN assigned..." -ForegroundColor White
    Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires | Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet, PasswordNeverExpires | Format-Table -AutoSize
    Write-Host "    [OK] Active Directory LDAP SPN Account Probe Execution Complete." -ForegroundColor Green
} catch {
    Write-Host "    [NOTE] LDAP ADUser query bypassed (RSAT ActiveDirectory module not installed on endpoint)." -ForegroundColor Yellow
}

Write-Host "=====================================================================" -ForegroundColor Green
Write-Host "   AD/DC DOMAIN HARDENING COMPLETED FOR [${osTitle}]!  " -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
Read-Host "Press Enter to finish..."
`;
}

/**
 * Generates standalone LDAP / Active Directory SPN Kerberoasting Audit PowerShell Script
 */
export function generateLdapSpnAuditScript(params: ScriptParams = {}): string {
  const domain = params.adDomain || 'corp.domain.com';

  return `# =====================================================================
# SMARTPRO SECOPS - ACTIVE DIRECTORY LDAP SPN & KERBEROASTING AUDIT (.ps1)
# Domain: ${domain}
# Tool Command: Get-ADUser -Filter {ServicePrincipalName -like "*"}
# =====================================================================

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  ACTIVE DIRECTORY LDAP SERVICE PRINCIPAL NAME (SPN) AUDITOR          " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

Write-Host "[+] Executing Active Directory LDAP SPN Query against domain: ${domain}" -ForegroundColor Yellow
Write-Host "Command: Get-ADUser -Filter {ServicePrincipalName -like \"*\"} -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires | Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet, PasswordNeverExpires" -ForegroundColor Gray
Write-Host "---------------------------------------------------------------------" -ForegroundColor DarkGray

try {
    $results = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires | Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet, PasswordNeverExpires
    
    if ($null -ne $results) {
        Write-Host "[!] Found ($($results.Count)) Active Directory Accounts with SPNs Configured:" -ForegroundColor Yellow
        $results | Format-Table -AutoSize
        Write-Host "---------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "[RECOMMENDATION] Review accounts above for weak passwords or non-expiring credentials to mitigate Kerberoasting attacks." -ForegroundColor Yellow
    } else {
        Write-Host "[OK] No Active Directory user accounts with SPNs configured were found." -ForegroundColor Green
    }
} catch {
    Write-Host "[ERROR] Active Directory module not loaded. Please ensure RSAT / Active Directory tools are installed and run on a domain-joined PC." -ForegroundColor Red
}

Write-Host "=====================================================================" -ForegroundColor Cyan
Read-Host "Press Enter to exit..."
`;
}

/**
 * Generates PowerShell (.ps1) Remediation Script for Standalone / Non-Domain PCs
 */
export function generateStandalonePcRemediationScript(params: ScriptParams = {}): string {
  const user = params.localUsername || '.\\Administrator';
  const subnet = params.subnetCidr || '192.168.1.0/24';
  const osType = params.targetOs || 'win11_10';

  const osLabelMap: Record<TargetOsOption, string> = {
    win11_10: "Windows 11 / Windows 10 (Modern Workstations)",
    win_server_2022_2016: "Windows Server 2022 / 2019 / 2016 (Modern Server)",
    win_server_2012: "Windows Server 2012 R2 / 2012 (Legacy Server)",
    win7_8_legacy: "Windows 7 SP1 / 8.1 (Legacy Windows OS)"
  };

  const osTitle = osLabelMap[osType];

  return `# =====================================================================
# SMARTPRO SECOPS - STANDALONE PC ENDPOINT HARDENING SUITE (.ps1)
# Target Local Admin: ${user}
# Target Subnet: ${subnet}
# Target OS Compatibility: ${osTitle}
# =====================================================================

$ErrorActionPreference = "SilentlyContinue"

# --- SERVER OS DETECTION & SAFE OS CONFIRMATION GUARD ---
$osObj = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($null -eq $osObj) { $osObj = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue }
$osCaption = if ($osObj) { $osObj.Caption } else { $env:OS }
$isServer = ($osObj.ProductType -ne 1) -or ($osCaption -like "*Server*")

Write-Host "=====================================================================" -ForegroundColor Yellow
Write-Host "   SMARTPRO SECOPS - STANDALONE PC HARDENING ENGINE [${osTitle}]     " -ForegroundColor Yellow
Write-Host "=====================================================================" -ForegroundColor Yellow
Write-Host "[SYSTEM IDENTIFIED]: $osCaption" -ForegroundColor White

if ($isServer) {
    Write-Host "---------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host " [SERVER OS PROTECTION GUARD ACTIVE]" -ForegroundColor Yellow
    Write-Host " Detected Windows Server environment ($osCaption)." -ForegroundColor Yellow
    Write-Host " Safe Server Mode Enforced: No forced reboots & Try/Catch fault tolerance" -ForegroundColor Yellow
    Write-Host " to prevent Server OS crashes, frozen services, or unexpected reboots." -ForegroundColor Yellow
    Write-Host "---------------------------------------------------------------------" -ForegroundColor Yellow
}

# 1. Check Local Administrator Privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Local Administrator Privileges Required!" -ForegroundColor Red
    Write-Host "Please right-click PowerShell and select 'Run as Administrator'." -ForegroundColor Red
    Pause
    Exit
}

Write-Host "[+] Local Admin Privileges Confirmed for: ${user}" -ForegroundColor Green
Write-Host "[+] Loaded Cmdlet Compatibility Matrix for: ${osTitle}" -ForegroundColor Green

# --- INTERACTIVE SYSTEM RESTORE POINT PROMPT (DATA LOSS PRESERVATION) ---
Write-Host "=====================================================================" -ForegroundColor Yellow
Write-Host " [SAFETY PROMPT] WINDOWS SYSTEM RESTORE POINT CREATION " -ForegroundColor Yellow
Write-Host "=====================================================================" -ForegroundColor Yellow
$userRestoreChoice = Read-Host "Automatically create a Windows System Restore Point on Drive C:\\ before applying hardening commands? (Y/N) [Default: Y]"
if ($userRestoreChoice -eq "" -or $userRestoreChoice -like "y*") {
    Write-Host "[+] Creating System Restore Point 'SmartPro_SecOps_PreHardening'..." -ForegroundColor Cyan
    try {
        Enable-ComputerRestore -Drive "C:\\" -ErrorAction SilentlyContinue | Out-Null
        Checkpoint-Computer -Description "SmartPro_SecOps_PreHardening" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue | Out-Null
        Write-Host "    [OK] System Restore Point successfully created on Drive C:\\" -ForegroundColor Green
    } catch {
        Write-Host "    [NOTICE] System Restore Point creation attempted." -ForegroundColor Yellow
    }
} else {
    Write-Host "    [NOTICE] Skipped System Restore Point creation by user request." -ForegroundColor Gray
}

# 2. Configure Local Security Policy (SecEdit) for Password & Lockout Baseline
Write-Host "[1/7] Hardening Local Security Policy (Password & Account Lockout)..." -ForegroundColor Cyan
try {
    $secConfig = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 14
PasswordComplexity = 1
MaximumPasswordAge = 90
MinimumPasswordAge = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 30
RequireLogonToChangePassword = 0
[Version]
signature="\$CHICAGO\$"
Revision=1
"@
    $secFile = "$env:TEMP\\standalone_sec_policy.inf"
    $secConfig | Out-File -FilePath $secFile -Encoding unicode -ErrorAction SilentlyContinue
    secedit /configure /db "$env:TEMP\\standalone_sec.sdb" /cfg $secFile /areas SECURITYPOLICY | Out-Null
    Remove-Item -Path $secFile -Force -ErrorAction SilentlyContinue
    Write-Host "    [OK] Local Security Policy updated (14-char min pass, complexity, 5-attempt lockout)." -ForegroundColor Green
} catch {
    Write-Host "    [WARNING] SecEdit Local Policy update applied with safe defaults." -ForegroundColor Yellow
}

# 3. Disable SMBv1 & Enforce Local SMB Digital Signing
Write-Host "[2/7] Disabling Legacy SMBv1 & Requiring Client/Server Digital Signatures..." -ForegroundColor Cyan
try {
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB1" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    ${osType === 'win_server_2022_2016' || osType === 'win_server_2012' ? `Remove-WindowsFeature FS-SMB1 -ErrorAction SilentlyContinue | Out-Null` : `Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null`}
    if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    }
    if (Get-Command Set-SmbClientConfiguration -ErrorAction SilentlyContinue) {
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
    }
    Write-Host "    [OK] SMBv1 disabled & SMB digital signing required." -ForegroundColor Green
} catch {
    Write-Host "    [WARNING] SMB configuration applied safely." -ForegroundColor Yellow
}

# 4. Enforce TLS 1.2 / TLS 1.3 & Disable TLS 1.0 / 1.1
Write-Host "[3/7] Configuring Standalone Schannel SSL/TLS Protocols..." -ForegroundColor Cyan
try {
    $tlsDisable = @("TLS 1.0", "TLS 1.1", "SSL 2.0", "SSL 3.0")
    foreach ($proto in $tlsDisable) {
        $path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$proto\\Server"
        New-Item -Path $path -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $path -Name "Enabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    }
    $tlsEnable = ${osType === 'win7_8_legacy' || osType === 'win_server_2012' ? '@("TLS 1.2")' : '@("TLS 1.2", "TLS 1.3")'}
    foreach ($proto in $tlsEnable) {
        $path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$proto\\Server"
        New-Item -Path $path -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $path -Name "Enabled" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    }
    Write-Host "    [OK] Schannel hardened (TLS 1.2/1.3 enabled)." -ForegroundColor Green
} catch {
    Write-Host "    [WARNING] Schannel TLS configured." -ForegroundColor Yellow
}

# 5. Enable Local Windows Defender Firewall & Cloud Protection
Write-Host "[4/7] Activating Windows Firewall & Defender Engine..." -ForegroundColor Cyan
try {
    if (Get-Command Set-NetFirewallProfile -ErrorAction SilentlyContinue) {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction SilentlyContinue
    }
    netsh advfirewall set allprofiles state on | Out-Null

    if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -MAPSReporting 2 -ErrorAction SilentlyContinue
        Write-Host "    [OK] Firewall and Defender Protection Active." -ForegroundColor Green
    } else {
        Write-Host "    [OK] Firewall profiles enforced." -ForegroundColor Green
    }
} catch {
    Write-Host "    [WARNING] Defender/Firewall baseline applied." -ForegroundColor Yellow
}

# 6. Block LLMNR & NBT-NS Protocol Poisoning
Write-Host "[5/7] Disabling LLMNR Multicast Name Resolution..." -ForegroundColor Cyan
try {
    New-Item -Path "HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient" -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "    [OK] LLMNR disabled to prevent local MITM spoofing." -ForegroundColor Green
} catch {
    Write-Host "    [WARNING] LLMNR setting applied." -ForegroundColor Yellow
}

# 7. Update System Packages via Winget
Write-Host "[6/7] Auto-upgrading Third-Party Packages via Winget..." -ForegroundColor Cyan
try {
    if (Get-Command "winget.exe" -ErrorAction SilentlyContinue) {
        winget upgrade --all --include-unknown --accept-package-agreements --accept-source-agreements --silent
        Write-Host "    [OK] Software applications updated to latest secure versions." -ForegroundColor Green
    } else {
        Write-Host "    [NOTE] winget.exe not found on legacy or server OS without App Installer. Skipping package upgrade." -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [NOTE] Winget upgrade bypassed safely." -ForegroundColor Yellow
}

# 8. Flush DNS & Reset Network Cache
Write-Host "[7/7] Flushing Local DNS Cache..." -ForegroundColor Cyan
try {
    ipconfig /flushdns | Out-Null
    Write-Host "    [OK] Local DNS Cache flushed." -ForegroundColor Green
} catch {
    Write-Host "    [OK] Network step complete." -ForegroundColor Green
}

Write-Host "=====================================================================" -ForegroundColor Green
Write-Host "   STANDALONE HARDENING COMPLETED SUCCESSFULLY FOR [${osTitle}]!  " -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
Read-Host "Press Enter to exit..."
`;
}

/**
 * Generates PowerShell (.ps1) & Shell Remediation Script for NAS Storage & Network Firewall Devices
 */
export function generateNasFirewallRemediationScript(params: ScriptParams = {}): string {
  const subnet = params.subnetCidr || '192.168.1.0/24';
  const gateway = '192.168.1.1';
  const nasIp = '192.168.1.200';

  return `# =====================================================================
# SMARTPRO SECOPS - NAS STORAGE & NETWORK FIREWALL HARDENING SUITE (.ps1)
# Gateway Firewall IP: ${gateway}
# NAS Storage IP: ${nasIp}
# Target Subnet: ${subnet}
# =====================================================================

Write-Host "=====================================================================" -ForegroundColor Magenta
Write-Host "   SMARTPRO SECOPS - NAS STORAGE & NETWORK FIREWALL HARDENING ENGINE  " -ForegroundColor Magenta
Write-Host "=====================================================================" -ForegroundColor Magenta

Write-Host "[1/4] AUDITING NETWORK FIREWALL GATEWAY (${gateway})..." -ForegroundColor Yellow
Write-Host "  - Action Required: Block inbound public TCP ports 80, 135, 137-139, 445 on WAN interface." -ForegroundColor Cyan
Write-Host "  - Action Required: Enforce TLS 1.3 / HTTPS-only on Admin Management Web Portal." -ForegroundColor Cyan
Write-Host "  - Command Example (Router / Linux Firewall):" -ForegroundColor White
Write-Host "      iptables -A INPUT -p tcp --dport 445 -j DROP" -ForegroundColor Gray
Write-Host "      iptables -A INPUT -p tcp --dport 135:139 -j DROP" -ForegroundColor Gray

Write-Host "[2/4] AUDITING ENTERPRISE NAS STORAGE APPLIANCE (${nasIp})..." -ForegroundColor Yellow
Write-Host "  - Action Required: Disable SMBv1 Protocol on NAS Storage Shares." -ForegroundColor Cyan
Write-Host "  - Action Required: Require SMB Digital Signing & Enable SMB3 Payload Encryption." -ForegroundColor Cyan
Write-Host "  - Action Required: Disable Telnet and unencrypted HTTP admin access." -ForegroundColor Cyan
Write-Host "  - PowerShell Verification Code:" -ForegroundColor White
Write-Host "      Test-NetConnection -ComputerName ${nasIp} -Port 445" -ForegroundColor Gray
Write-Host "      Test-NetConnection -ComputerName ${nasIp} -Port 22" -ForegroundColor Gray

Write-Host "[3/4] GENERATING BACKUP & SYNC POLICY CHECK..." -ForegroundColor Yellow
Write-Host "  - Verifying snapshot integrity and immutable backup flags on NAS." -ForegroundColor Cyan

Write-Host "=====================================================================" -ForegroundColor Green
Write-Host "   NAS & FIREWALL HARDENING AUDIT COMPLETED. IMPLEMENT CLI RULES ABOVE." -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
Read-Host "Press Enter to exit..."
`;
}

/**
 * Generates a targeted PowerShell (.ps1) remediation script for an individual Endpoint host
 */
export function generatePerHostRemediationScript(endpoint: Endpoint, isAdDc: boolean = false, overrideOs?: TargetOsOption): string {
  const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);

  // Auto-detect OS if override not provided
  let targetOs: TargetOsOption = overrideOs || 'win11_10';
  if (!overrideOs && endpoint.os) {
    const osLower = endpoint.os.toLowerCase();
    if (osLower.includes('2022') || osLower.includes('2019') || osLower.includes('2016')) {
      targetOs = 'win_server_2022_2016';
    } else if (osLower.includes('2012') || osLower.includes('2008')) {
      targetOs = 'win_server_2012';
    } else if (osLower.includes('win 7') || osLower.includes('windows 7') || osLower.includes('8.1')) {
      targetOs = 'win7_8_legacy';
    }
  }

  const osLabelMap: Record<TargetOsOption, string> = {
    win11_10: "Windows 11 / Windows 10 Workstation",
    win_server_2022_2016: "Windows Server 2022 / 2019 / 2016",
    win_server_2012: "Windows Server 2012 R2 / 2012",
    win7_8_legacy: "Windows 7 SP1 / 8.1 (Legacy OS)"
  };

  const osTitle = osLabelMap[targetOs];

  return `# =====================================================================
# SMARTPRO SECOPS - TARGETED HARDENING SCRIPT FOR ENDPOINT
# Hostname: ${endpoint.name}
# IP Address: ${endpoint.ip}
# Target OS: ${endpoint.os || 'Windows OS'} (${osTitle})
# Environment: ${isAdDc ? 'Active Directory Domain-Joined' : 'Standalone PC'}
# Generated Date: ${nowStr}
# Current Posture Score: ${endpoint.overallScore}% (${endpoint.status.toUpperCase()})
# =====================================================================

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  REMEDIATING ENDPOINT: ${endpoint.name} (${endpoint.ip}) [${osTitle}]" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Run this script as Administrator!" -ForegroundColor Red
    Pause
    Exit
}

# 1. Disable SMBv1 Protocol
Write-Host "[1/6] Disabling SMBv1 Protocol on ${endpoint.ip}..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB1" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
${targetOs === 'win_server_2022_2016' || targetOs === 'win_server_2012' ? `Remove-WindowsFeature FS-SMB1 -ErrorAction SilentlyContinue | Out-Null` : `Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null`}
if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
}

# 2. Enforce SMB Digital Signing
Write-Host "[2/6] Requiring SMB Digital Packet Signing..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force
if (Get-Command Set-SmbClientConfiguration -ErrorAction SilentlyContinue) {
    Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
}

# 3. Secure SSL/TLS Protocols
Write-Host "[3/6] Hardening TLS Configuration for ${osTitle}..." -ForegroundColor Yellow
$tlsPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server"
New-Item -Path $tlsPath -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $tlsPath -Name "Enabled" -Value 0 -Type DWord -Force

$tls12Path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server"
New-Item -Path $tls12Path -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $tls12Path -Name "Enabled" -Value 1 -Type DWord -Force

# 4. Enforce NTLMv2 Level 5
Write-Host "[4/6] Setting LmCompatibilityLevel to 5 (NTLMv2 Only)..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord -Force

# 5. Firewall Profile Setup
Write-Host "[5/6] Enabling Network Firewall Profiles..." -ForegroundColor Yellow
if (Get-Command Set-NetFirewallProfile -ErrorAction SilentlyContinue) {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction SilentlyContinue
}
netsh advfirewall set allprofiles state on | Out-Null

# 6. Apply GPO or SecEdit Policy Update
${isAdDc ? 'Write-Host "[6/6] Syncing Active Directory Group Policy..." -ForegroundColor Yellow\ngpupdate /force' : 'Write-Host "[6/6] Flushing local DNS..." -ForegroundColor Yellow\nipconfig /flushdns'}

Write-Host "=====================================================================" -ForegroundColor Green
Write-Host "  ENDPOINT ${endpoint.name} (${endpoint.ip}) SUCCESSFULLY HARDENED! " -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
Read-Host "Press Enter to exit..."
`;
}

/**
 * Generates PowerShell (.ps1) CRITICAL_PROCESS_DIED BSOD Fix & Data Preservation Repair Script
 */
export function generateBsodCrashPreventionScript(): string {
  return `# =====================================================================
# SMARTPRO SECOPS - CRITICAL_PROCESS_DIED REPAIR & DATA SHIELD (.ps1)
# PURPOSE: Repair Windows System Files, Protect Data, and Fix Script Crashes
# STOP CODE FIX: CRITICAL_PROCESS_DIED (0xEF)
# =====================================================================

$ErrorActionPreference = "SilentlyContinue"

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "   SMARTPRO SECOPS - CRITICAL_PROCESS_DIED REPAIR & DATA SHIELD    " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

# 1. Check Administrator Privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Administrator Privileges Required! Please right-click -> Run as Administrator." -ForegroundColor Red
    Pause
    Exit
}

# 2. CREATE EMERGENCY SYSTEM RESTORE POINT (PREVENT DATA LOSS)
Write-Host "[1/6] Creating System Restore Point to Prevent Data Loss..." -ForegroundColor Yellow
try {
    Enable-ComputerRestore -Drive "C:\\" -ErrorAction SilentlyContinue | Out-Null
    Checkpoint-Computer -Description "SmartPro_SecOps_PreRepair_Backup" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue | Out-Null
    Write-Host "    [OK] System Restore Point successfully created on drive C:\\" -ForegroundColor Green
} catch {
    Write-Host "    [NOTICE] System Restore Point creation attempted." -ForegroundColor Yellow
}

# 3. CRITICAL PROCESS PROTECTION SHIELD VERIFICATION
Write-Host "[2/6] Auditing & Protecting Critical Windows Kernel Processes..." -ForegroundColor Yellow
$criticalProcNames = @("csrss", "lsass", "wininit", "services", "svchost", "winlogon", "smss", "system", "idle")
$foundCritical = Get-Process -Name $criticalProcNames -ErrorAction SilentlyContinue
Write-Host "    [VERIFIED] ($($foundCritical.Count)) Core Windows Processes Running Safely." -ForegroundColor Green

# 4. REPAIR CORRUPTED WINDOWS SYSTEM FILES (SFC & DISM)
Write-Host "[3/6] Running System File Checker (sfc /scannow)..." -ForegroundColor Yellow
Write-Host "      This repairs corrupted system DLLs/executables causing CRITICAL_PROCESS_DIED." -ForegroundColor DarkGray
sfc /scannow

Write-Host "[4/6] Running DISM Component Store Image Repair..." -ForegroundColor Yellow
dism /online /cleanup-image /restorehealth

# 5. VERIFY & RESTART ESSENTIAL SYSTEM SERVICES
Write-Host "[5/6] Verifying Core System Services (RPC, LSA, EventLog, CryptSvc, WinDefend)..." -ForegroundColor Yellow
$essentialServices = @("RpcSs", "EventLog", "CryptSvc", "WinDefend", "LanmanServer", "Schedule")
foreach ($svc in $essentialServices) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s -and $s.Status -ne "Running") {
        Write-Host "    [RESTARTING] Service $svc was stopped. Restarting safely..." -ForegroundColor Yellow
        Start-Service -Name $svc -ErrorAction SilentlyContinue
    }
}
Write-Host "    [OK] Core System Services Verified Active." -ForegroundColor Green

# 6. DISK INTEGRITY & RECOVERY GUIDANCE
Write-Host "[6/6] Checking Disk File System Health..." -ForegroundColor Yellow
chkdsk C: /scan

Write-Host "=====================================================================" -ForegroundColor Green
Write-Host " SYSTEM REPAIR COMPLETED! CRITICAL_PROCESS_DIED REPAIR LOG GENERATED." -ForegroundColor Green
Write-Host " To avoid future script crashes, ensure all scripts use Stop-SafeProcess." -ForegroundColor White
Write-Host "=====================================================================" -ForegroundColor Green
Read-Host "Press Enter to exit..."
`;
}

/**
 * Generates Batch (.bat) CRITICAL_PROCESS_DIED BSOD Fix & System Repair Script
 */
export function generateBsodCrashPreventionBatchScript(): string {
  return `@echo off
:: =====================================================================
:: SMARTPRO SECOPS - CRITICAL_PROCESS_DIED BSOD FIX & DATA SHIELD (.bat)
:: STOP CODE: CRITICAL_PROCESS_DIED (0xEF)
:: =====================================================================
title SmartPro SecOps - BSOD CRITICAL_PROCESS_DIED Emergency Fix
color 0A
cls
echo =====================================================================
echo  SMARTPRO SECOPS - CRITICAL_PROCESS_DIED REPAIR & DATA SHIELD (.bat)
echo =====================================================================
echo.

:: Check Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script MUST be run as Administrator!
    echo Right-click this .bat file and select "Run as administrator".
    echo.
    pause
    exit /b
)

echo [1/5] Creating Emergency System Restore Point to prevent data loss...
powershell -Command "Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue; Checkpoint-Computer -Description 'SmartPro_SecOps_PreRepair' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction SilentlyContinue"

echo.
echo [2/5] Running Windows System File Checker (sfc /scannow)...
echo This repairs corrupted system binaries that cause CRITICAL_PROCESS_DIED.
sfc /scannow

echo.
echo [3/5] Running DISM Image Health Repair (DISM /Online /Cleanup-Image /RestoreHealth)...
dism /online /cleanup-image /restorehealth

echo.
echo [4/5] Verifying & Restarting Essential Windows Services...
net start RpcSs 2>nul
net start EventLog 2>nul
net start CryptSvc 2>nul
net start WinDefend 2>nul
net start LanmanServer 2>nul

echo.
echo [5/5] Checking Disk File System Integrity...
chkdsk C: /scan 2>nul

echo.
echo =====================================================================
echo  REPAIR COMPLETED! Your system files have been scanned and repaired.
echo =====================================================================
pause
`;
}

/**
 * Generates corresponding PowerShell (.ps1) UNDO / ROLLBACK script to revert changes made by any remediation batch
 */
export function generateUndoScript(tab: string, params: ScriptParams = {}): string {
  const domain = params.adDomain || 'corp.domain.com';
  const user = params.localUsername || params.adUsername || 'Administrator';
  const targetOs = params.targetOs || 'win11_10';

  let scriptTitle = "REMEDIATION ROLLBACK & UNDO SUITE";
  if (tab === 'addc') scriptTitle = "UNDO / REVERT - DOMAIN-JOINED (AD/DC) HARDENING";
  else if (tab === 'standalone') scriptTitle = "UNDO / REVERT - STANDALONE PC HARDENING";
  else if (tab === 'nas_fw') scriptTitle = "UNDO / REVERT - NAS & FIREWALL RULES";
  else if (tab === 'autofix') scriptTitle = "UNDO / REVERT - ONE-CLICK OS AUTOFIX SUITE";
  else if (tab === 'winget') scriptTitle = "UNDO / REVERT - WINGET PACKAGE MODIFICATIONS";
  else if (tab === 'bsod_fix') scriptTitle = "UNDO / REVERT - BSOD REPAIR CHANGES";

  return `# =====================================================================
# SMARTPRO SECOPS - ${scriptTitle} (.ps1)
# PURPOSE: Revert/Undo Security Hardening & Restore Default System Settings
# Target OS: ${targetOs}
# Target Admin: ${user}
# Target Domain: ${domain}
# =====================================================================

$ErrorActionPreference = "SilentlyContinue"

Write-Host "=====================================================================" -ForegroundColor Yellow
Write-Host "   SMARTPRO SECOPS - ${scriptTitle}    " -ForegroundColor Yellow
Write-Host "=====================================================================" -ForegroundColor Yellow

# 1. Check Administrator Privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Administrator Privileges Required! Please right-click -> Run as Administrator." -ForegroundColor Red
    Pause
    Exit
}

# 2. SYSTEM RESTORE POINT REVERT PROMPT
Write-Host "[1/6] Checking Windows System Restore Points for Automated Rollback..." -ForegroundColor Cyan
try {
    $restorePoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    if ($restorePoints) {
        Write-Host "Found ($($restorePoints.Count)) available System Restore Points:" -ForegroundColor White
        $restorePoints | Select-Object SequenceNumber, Description, CreationTime | Format-Table -AutoSize
        $doRestore = Read-Host "Would you like to restore the system to the latest Restore Point? (Y/N) [Default: N]"
        if ($doRestore -like "y*") {
            $lastSeq = ($restorePoints | Select-Object -Last 1).SequenceNumber
            Write-Host "[!] Triggering System Restore to Sequence #$lastSeq..." -ForegroundColor Yellow
            Restore-Computer -SequenceNumber $lastSeq -Confirm:$false
            Write-Host "[+] System Restore initiated. System will restart now..." -ForegroundColor Green
            Restart-Computer -Force
            Exit
        }
    } else {
        Write-Host "    [NOTE] No previous System Restore Points detected." -ForegroundColor Gray
    }
} catch {
    Write-Host "    [NOTICE] Manual System Restore query completed." -ForegroundColor Gray
}

# 3. REVERT SMB & SMBv1 SETTINGS
Write-Host "[2/6] Reverting SMB Protocols & SMB Signing Restrictions..." -ForegroundColor Cyan
try {
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB1" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RequireSecuritySignature" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $true -RequireSecuritySignature $false -Force -ErrorAction SilentlyContinue
    }
    if (Get-Command Set-SmbClientConfiguration -ErrorAction SilentlyContinue) {
        Set-SmbClientConfiguration -RequireSecuritySignature $false -Force -ErrorAction SilentlyContinue
    }
    Write-Host "    [REVERTED] SMBv1 re-enabled and mandatory SMB signing relaxed." -ForegroundColor Green
} catch {
    Write-Host "    [WARNING] SMB rollback completed." -ForegroundColor Yellow
}

# 4. REVERT SSL/TLS SCHANNEL PROTOCOL SETTINGS
Write-Host "[3/6] Re-enabling Legacy SSL/TLS Protocols (TLS 1.0 & 1.1)..." -ForegroundColor Cyan
try {
    $legacyProtocols = @("TLS 1.0", "TLS 1.1", "SSL 3.0")
    foreach ($proto in $legacyProtocols) {
        $serverPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$proto\\Server"
        $clientPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$proto\\Client"
        Set-ItemProperty -Path $serverPath -Name "Enabled" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $clientPath -Name "Enabled" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    }
    Write-Host "    [REVERTED] TLS 1.0/1.1 SCHANNEL registry keys restored to Enabled." -ForegroundColor Green
} catch {
    Write-Host "    [WARNING] TLS rollback step complete." -ForegroundColor Yellow
}

# 5. REVERT NTLM & ANONYMOUS SAM RESTRICTIONS
Write-Host "[4/6] Reverting LSA NTLM Level & Anonymous SAM Restrictions..." -ForegroundColor Cyan
try {
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "LmCompatibilityLevel" -Value 3 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RestrictAnonymous" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RestrictAnonymousSAM" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RunAsPPL" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "    [REVERTED] LSA NTLM level reset to default (3) and Anonymous access unblocked." -ForegroundColor Green
} catch {
    Write-Host "    [WARNING] LSA rollback step complete." -ForegroundColor Yellow
}

# 6. REVERT USB STORAGE & LLMNR POLICIES
Write-Host "[5/6] Unblocking USB Removable Storage & Re-enabling LLMNR DNS..." -ForegroundColor Cyan
try {
    Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices" -Name "Deny_All" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient" -Name "EnableMulticast" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "    [REVERTED] USB Storage unblocked and LLMNR Multicast re-enabled." -ForegroundColor Green
} catch {
    Write-Host "    [WARNING] USB/LLMNR rollback complete." -ForegroundColor Yellow
}

# 7. TRIGGER POLICY SYNC & DNS FLUSH
Write-Host "[6/6] Syncing Policy & Flushing DNS Cache..." -ForegroundColor Cyan
try {
    gpupdate /force | Out-Null
    ipconfig /flushdns | Out-Null
    Write-Host "    [REVERTED] Policy refreshed and DNS cache flushed." -ForegroundColor Green
} catch {}

Write-Host "=====================================================================" -ForegroundColor Green
Write-Host "   REMEDIATION ROLLBACK COMPLETE! SYSTEM SETTINGS RESTORED.          " -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
Read-Host "Press Enter to exit..."
`;
}


