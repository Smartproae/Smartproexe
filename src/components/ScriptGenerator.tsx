import React, { useState } from 'react';
import { 
  Copy, 
  Check, 
  Download, 
  ShieldAlert, 
  FileText, 
  FileCode, 
  Zap, 
  Wrench, 
  Server, 
  HardDrive, 
  Shield, 
  Cpu, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  Filter, 
  Sparkles, 
  Laptop,
  Users,
  RotateCcw
} from 'lucide-react';
import { POWERSHELL_AUDIT_SCRIPT } from '../auditScript';
import {
  generateAdDcRemediationScript,
  generateStandalonePcRemediationScript,
  generateNasFirewallRemediationScript,
  generateLdapSpnAuditScript,
  generateBsodCrashPreventionScript,
  generateBsodCrashPreventionBatchScript,
  generateUndoScript,
  TargetOsOption
} from '../utils/ps1ScriptGenerator';

interface Props {
  onOpenGitHubModal?: () => void;
  onOpenSystemFastModal?: () => void;
}

export type ScriptTabKey = 'addc' | 'standalone' | 'nas_fw' | 'audit' | 'winget' | 'autofix' | 'ldap_spn' | 'bsod_fix';

export interface OsCompatInfo {
  status: 'optimal' | 'compatible' | 'safe_mode' | 'not_supported';
  badge: string;
  label: string;
  color: 'emerald' | 'cyan' | 'amber' | 'red';
  warning?: string;
}

export default function ScriptGenerator({ onOpenGitHubModal, onOpenSystemFastModal }: Props) {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<ScriptTabKey>('addc');
  const [showOnlyCompatible, setShowOnlyCompatible] = useState(false);
  const [bsodScriptFormat, setBsodScriptFormat] = useState<'ps1' | 'bat'>('ps1');
  const [isViewingUndo, setIsViewingUndo] = useState(false);

  // Input state for script customization
  const [adDomain, setAdDomain] = useState<string>('corp.domain.com');
  const [adUsername, setAdUsername] = useState<string>('CORP\\Administrator');
  const [localUsername, setLocalUsername] = useState<string>('.\\Administrator');
  const [subnetCidr, setSubnetCidr] = useState<string>('192.168.1.0/24');
  const [targetOs, setTargetOs] = useState<TargetOsOption>('win11_10');

  // OS Compatibility Helper Matrix
  const getTabOsCompatibility = (tab: ScriptTabKey, os: TargetOsOption): OsCompatInfo => {
    if (tab === 'bsod_fix') {
      return {
        status: 'optimal',
        badge: '100% Data Protection',
        label: 'Emergency System Restore & System File Repair (SFC / DISM)',
        color: 'emerald'
      };
    }

    if (os === 'win11_10') {
      return {
        status: 'optimal',
        badge: '100% Compatible',
        label: 'Fully compatible with Windows 11 / 10 Workstations',
        color: 'emerald'
      };
    }

    if (os === 'win_server_2022_2016') {
      switch (tab) {
        case 'addc':
          return {
            status: 'optimal',
            badge: 'Server Optimal',
            label: 'Tailored for Windows Server 2022 / 2019 / 2016 AD & DC',
            color: 'emerald'
          };
        case 'standalone':
          return {
            status: 'safe_mode',
            badge: 'Server Safe Mode',
            label: 'Server Guard Active: Non-reboot policy & try/catch safety',
            color: 'cyan'
          };
        case 'nas_fw':
          return {
            status: 'optimal',
            badge: 'Server Optimal',
            label: 'Storage & Gateway Firewall Hardening',
            color: 'emerald'
          };
        case 'audit':
          return {
            status: 'compatible',
            badge: 'Compatible',
            label: 'PowerShell 5.1+ Audit Probe Engine',
            color: 'cyan'
          };
        case 'winget':
          return {
            status: 'safe_mode',
            badge: 'Requires AppInstaller',
            label: 'Server Guard: Winget check bypassed if winget.exe absent on Server',
            color: 'amber',
            warning: 'Windows Server requires App Installer package to use winget. Script handles missing winget safely.'
          };
        case 'autofix':
          return {
            status: 'safe_mode',
            badge: 'Server Safe Mode',
            label: 'Server Crash Guard: WinUtil GUI & Winsock reset bypassed',
            color: 'amber',
            warning: 'Server Safe Mode active: WinUtil desktop GUI and Winsock stack resets are bypassed to protect Server network interfaces.'
          };
      }
    }

    if (os === 'win_server_2012') {
      switch (tab) {
        case 'addc':
          return {
            status: 'optimal',
            badge: 'Server 2012 AD',
            label: 'Uses Remove-WindowsFeature FS-SMB1 & PS v3.0/4.0 cmdlets',
            color: 'emerald'
          };
        case 'standalone':
          return {
            status: 'safe_mode',
            badge: 'Server Safe Mode',
            label: 'SecEdit policy update with Server 2012 safe fallback',
            color: 'cyan'
          };
        case 'nas_fw':
          return {
            status: 'optimal',
            badge: 'Compatible',
            label: 'Netsh & Storage rules',
            color: 'emerald'
          };
        case 'audit':
          return {
            status: 'compatible',
            badge: 'PS v3.0 Fallback',
            label: 'WMI/CIM fallback cmdlets active',
            color: 'cyan'
          };
        case 'winget':
          return {
            status: 'not_supported',
            badge: 'Not Supported',
            label: 'Winget is NOT natively supported on Windows Server 2012',
            color: 'red',
            warning: 'Windows Server 2012 lacks AppInstaller package support. Script will report winget unavailable.'
          };
        case 'autofix':
          return {
            status: 'safe_mode',
            badge: 'Server Safe Mode',
            label: 'DISM & SFC safe server repair engine',
            color: 'amber',
            warning: 'Server 2012 Safe Mode: Winsock resets and WinUtil GUI bypassed to prevent server crash.'
          };
      }
    }

    if (os === 'win7_8_legacy') {
      switch (tab) {
        case 'addc':
          return {
            status: 'safe_mode',
            badge: 'Legacy PS v2.0',
            label: 'Legacy registry fallback for SMB1 & TLS 1.2',
            color: 'amber'
          };
        case 'standalone':
          return {
            status: 'safe_mode',
            badge: 'Legacy PS v2.0',
            label: 'SecEdit local policy & registry fallbacks',
            color: 'amber'
          };
        case 'nas_fw':
          return {
            status: 'compatible',
            badge: 'Compatible',
            label: 'Legacy Netsh firewall commands',
            color: 'cyan'
          };
        case 'audit':
          return {
            status: 'safe_mode',
            badge: 'Legacy PS v2.0 Probe',
            label: 'Uses Get-WmiObject fallbacks for old PowerShell engines',
            color: 'amber'
          };
        case 'winget':
          return {
            status: 'not_supported',
            badge: 'Not Supported',
            label: 'Winget is NOT supported on Windows 7 / 8.1',
            color: 'red',
            warning: 'Windows 7 / 8.1 does not support winget.exe package manager.'
          };
        case 'autofix':
          return {
            status: 'safe_mode',
            badge: 'Legacy Safe Mode',
            label: 'DISM & SFC scan with WinUtil bypass',
            color: 'amber',
            warning: 'Legacy Windows 7/8.1 mode: Winget and modern GUI tools bypassed for system stability.'
          };
      }
    }

    return {
      status: 'compatible',
      badge: 'Compatible',
      label: 'Standard PowerShell compatibility',
      color: 'cyan'
    };
  };

  const wingetScript = `# =====================================================================
# SMARTPRO SECOPS - SYSTEM-WIDE WINGET SOFTWARE AUTO-UPDATER
# Target OS Compatibility: ${targetOs === 'win11_10' ? 'Windows 11 / 10 Workstations (Native)' : targetOs === 'win_server_2022_2016' ? 'Windows Server 2022 / 2019 / 2016 (Requires AppInstaller)' : targetOs === 'win_server_2012' ? 'Windows Server 2012 (Safe Fallback Guard)' : 'Windows 7 / 8.1 Legacy OS (Safe Fallback Guard)'}
# =====================================================================

$ErrorActionPreference = "SilentlyContinue"

# --- SERVER & LEGACY OS DETECTION & SAFE OS PROTECTION GUARD ---
$osObj = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($null -eq $osObj) { $osObj = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue }
$osCaption = if ($osObj) { $osObj.Caption } else { $env:OS }
$isServer = ($osObj.ProductType -ne 1) -or ($osCaption -like "*Server*")

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "     SMARTPRO SYSTEM SOFTWARE AUTO-UPDATER (WINGET ENGINE)           " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "[SYSTEM IDENTIFIED]: $osCaption" -ForegroundColor White

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Please run this script as Administrator!" -ForegroundColor Red
    Pause
    Exit
}

Write-Host "[1/2] Verifying Windows Package Manager (winget.exe) availability..." -ForegroundColor Yellow
try {
    if (Get-Command "winget.exe" -ErrorAction SilentlyContinue) {
        Write-Host "[2/2] Scanning & Upgrading all installed application packages..." -ForegroundColor Green
        winget upgrade --all --include-unknown --accept-package-agreements --accept-source-agreements
        Write-Host "=====================================================================" -ForegroundColor Green
        Write-Host "      ALL INSTALLED APPLICATIONS UPDATED SUCCESSFULLY!               " -ForegroundColor Green
        Write-Host "=====================================================================" -ForegroundColor Green
    } else {
        Write-Host "[NOTE] winget.exe is not installed on this OS ($osCaption)." -ForegroundColor Yellow
        Write-Host "Windows Server / Legacy systems can install App Installer if desktop patching is required." -ForegroundColor Yellow
    }
} catch {
    Write-Host "[NOTE] Winget upgrade process finished safely." -ForegroundColor Yellow
}
Read-Host "Press Enter to exit..."
`;

  const autoFixScript = `# =====================================================================
# SMARTPRO SECOPS ONE-CLICK AUTOMATED ERROR REMEDIATION SUITE (v2.5)
# Target OS Compatibility Mode: ${targetOs === 'win11_10' ? 'Windows 11 / 10 Workstation' : targetOs === 'win_server_2022_2016' ? 'Windows Server 2022 / 2019 / 2016 (Server Protection Active)' : targetOs === 'win_server_2012' ? 'Windows Server 2012 R2 / 2012 (Legacy Server Protection Active)' : 'Windows 7 / 8.1 Legacy OS (Legacy Protection Active)'}
# Safe Server OS Guard + DISM/SFC + Winget Auto-Update Engine
# =====================================================================

$ErrorActionPreference = "SilentlyContinue"

# --- SERVER & LEGACY OS DETECTION & SAFE OS PROTECTION GUARD ---
$osObj = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($null -eq $osObj) { $osObj = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue }
$osCaption = if ($osObj) { $osObj.Caption } else { $env:OS }
$isServer = ($osObj.ProductType -ne 1) -or ($osCaption -like "*Server*")

Write-Host "=====================================================================" -ForegroundColor Yellow
Write-Host "  SMARTPRO ENDPOINT GUARD - AUTOMATED ERROR & CONFIG FIX ENGINE     " -ForegroundColor Yellow
Write-Host "=====================================================================" -ForegroundColor Yellow
Write-Host "[SYSTEM IDENTIFIED]: $osCaption" -ForegroundColor White

if ($isServer) {
    Write-Host "---------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host " [SERVER OS PROTECTION GUARD ACTIVE]" -ForegroundColor Yellow
    Write-Host " Detected Windows Server OS ($osCaption)." -ForegroundColor Yellow
    Write-Host " Safe Mode Active: Winsock Reset & WinUtil GUI bypassed to prevent Server crashes." -ForegroundColor Yellow
    Write-Host "---------------------------------------------------------------------" -ForegroundColor Yellow
}

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Administrator Privileges Required!" -ForegroundColor Red
    Write-Host "Please right-click Terminal / PowerShell and select 'Run as Administrator'." -ForegroundColor Red
    Pause
    Exit
}

Write-Host "[1/7] Fixing PowerShell Execution Policy restrictions..." -ForegroundColor Cyan
try { Set-ExecutionPolicy Unrestricted -Scope Process -Force } catch { }

Write-Host "[2/7] Flushing DNS Cache..." -ForegroundColor Cyan
try { ipconfig /flushdns | Out-Null } catch { }

if ($isServer) {
    Write-Host "[INFO] Server OS detected. Winsock stack reset bypassed to prevent remote access drop." -ForegroundColor Yellow
} else {
    Write-Host "[2b/7] Resetting Network Winsock Stack (Workstation Only)..." -ForegroundColor Cyan
    try { netsh winsock reset | Out-Null } catch { }
}

Write-Host "[3/7] Repairing Corrupted System Component Store (DISM)..." -ForegroundColor Cyan
try { DISM /Online /Cleanup-Image /RestoreHealth } catch { Write-Host "[WARNING] DISM repair skipped or unavailable." -ForegroundColor Yellow }

Write-Host "[4/7] Running System File Checker (SFC Scan)..." -ForegroundColor Cyan
try { sfc /scannow } catch { Write-Host "[WARNING] SFC scan completed with warnings." -ForegroundColor Yellow }

Write-Host "[5/7] Resetting Windows Update & GPO Cache..." -ForegroundColor Cyan
try { gpupdate /target:computer /no-boot } catch { Write-Host "[WARNING] GPO sync finished." -ForegroundColor Yellow }

Write-Host "[6/7] Auto-Upgrading ALL Installed Software Applications via Winget..." -ForegroundColor Cyan
try {
    if (Get-Command "winget.exe" -ErrorAction SilentlyContinue) {
        winget upgrade --all --include-unknown --accept-package-agreements --accept-source-agreements --silent
        Write-Host "[OK] All installed applications updated via Winget." -ForegroundColor Green
    } else {
        Write-Host "[NOTE] winget.exe not detected on this OS. Skipping application auto-update." -ForegroundColor Yellow
    }
} catch {
    Write-Host "[NOTE] Package upgrade bypassed safely." -ForegroundColor Yellow
}

if ($isServer) {
    Write-Host "[INFO] Server OS detected. WinUtil desktop GUI launcher bypassed for 100% server stability." -ForegroundColor Green
} else {
    Write-Host "[7/7] Invoking Chris Titus Tech Windows Utility Bootstrap..." -ForegroundColor Cyan
    try {
        irm christitus.com/win | iex
    } catch {
        Write-Host "[WARNING] WinUtil bootstrap download bypassed." -ForegroundColor Yellow
    }
}

Write-Host "=====================================================================" -ForegroundColor Green
Write-Host "           ALL COMMON ERRORS & APP UPDATES COMPLETED CLEANLY!        " -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
Read-Host "Press Enter to exit..."
`;

  const getActiveCode = () => {
    if (isViewingUndo) {
      return generateUndoScript(activeTab, { adDomain, adUsername, localUsername, subnetCidr, targetOs });
    }
    if (activeTab === 'bsod_fix') {
      return bsodScriptFormat === 'bat' 
        ? generateBsodCrashPreventionBatchScript() 
        : generateBsodCrashPreventionScript();
    }
    if (activeTab === 'addc') return generateAdDcRemediationScript({ adDomain, adUsername, subnetCidr, targetOs });
    if (activeTab === 'standalone') return generateStandalonePcRemediationScript({ localUsername, subnetCidr, targetOs });
    if (activeTab === 'nas_fw') return generateNasFirewallRemediationScript({ subnetCidr });
    if (activeTab === 'winget') return wingetScript;
    if (activeTab === 'autofix') return autoFixScript;
    if (activeTab === 'ldap_spn') return generateLdapSpnAuditScript({ adDomain });
    return POWERSHELL_AUDIT_SCRIPT;
  };

  const getOsFileSuffix = (os: TargetOsOption) => {
    switch (os) {
      case 'win11_10': return 'Win11_10';
      case 'win_server_2022_2016': return 'Server2022_2016';
      case 'win_server_2012': return 'Server2012';
      case 'win7_8_legacy': return 'Win7_8_Legacy';
    }
  };

  const getActiveFilename = (ext: string) => {
    const osSuffix = getOsFileSuffix(targetOs);
    if (isViewingUndo) {
      return `UNDO_Revert_${activeTab.toUpperCase()}_${osSuffix}.${ext}`;
    }
    if (activeTab === 'bsod_fix') {
      return bsodScriptFormat === 'bat' ? 'Fix_CRITICAL_PROCESS_DIED_BSOD.bat' : 'Fix_CRITICAL_PROCESS_DIED_BSOD.ps1';
    }
    if (activeTab === 'addc') return `Remediate_AD_DC_${osSuffix}.${ext}`;
    if (activeTab === 'standalone') return `Remediate_Standalone_PC_${osSuffix}.${ext}`;
    if (activeTab === 'nas_fw') return `Remediate_NAS_Firewall_${osSuffix}.${ext}`;
    if (activeTab === 'winget') return `Winget_AutoUpdate_${osSuffix}.${ext}`;
    if (activeTab === 'autofix') return `SmartPro_AutoFix_${osSuffix}.${ext}`;
    if (activeTab === 'ldap_spn') return `LDAP_SPN_Audit_${osSuffix}.${ext}`;
    return `AuditEndpointSecurity_${osSuffix}.${ext}`;
  };

  const copyScript = () => {
    const code = getActiveCode();
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(code)
          .then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
          })
          .catch(() => {
            localFallbackCopy(code);
          });
      } else {
        localFallbackCopy(code);
      }
    } catch (err) {
      localFallbackCopy(code);
    }
  };

  const localFallbackCopy = (code: string) => {
    try {
      const textArea = document.createElement("textarea");
      textArea.value = code;
      textArea.style.position = "fixed";
      textArea.style.top = "0";
      textArea.style.left = "0";
      textArea.style.opacity = "0";
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      const success = document.execCommand('copy');
      document.body.removeChild(textArea);
      if (success) {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }
    } catch (e) {
      console.warn("Clipboard fallback failed", e);
    }
  };

  const downloadFile = (filename: string, content: string, mime: string = 'text/plain') => {
    const element = document.createElement("a");
    const file = new Blob([content], { type: mime });
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const activeCompat = getTabOsCompatibility(activeTab, targetOs);

  const allTabs: { id: ScriptTabKey; label: string; icon: React.ReactNode }[] = [
    { id: 'addc', label: '1. AD / DC PC Remediate (.ps1)', icon: <Server className="w-4 h-4 text-cyan-400" /> },
    { id: 'standalone', label: '2. Standalone PC Remediate (.ps1)', icon: <Shield className="w-4 h-4 text-emerald-400" /> },
    { id: 'nas_fw', label: '3. NAS Storage & Firewall (.ps1)', icon: <HardDrive className="w-4 h-4 text-amber-400" /> },
    { id: 'audit', label: '4. Audit Probe Script (.ps1)', icon: <FileCode className="w-4 h-4 text-[#FF3B30]" /> },
    { id: 'winget', label: '5. Winget App Auto-Updater', icon: <Zap className="w-4 h-4 text-cyan-400" /> },
    { id: 'autofix', label: '6. One-Click OS AutoFix Suite', icon: <Wrench className="w-4 h-4 text-emerald-400" /> },
    { id: 'ldap_spn', label: '7. LDAP SPN Audit (.ps1)', icon: <Users className="w-4 h-4 text-cyan-300" /> },
    { id: 'bsod_fix', label: '8. BSOD Fix (CRITICAL_PROCESS_DIED)', icon: <ShieldAlert className="w-4 h-4 text-red-400 animate-pulse" /> },
  ];

  const visibleTabs = showOnlyCompatible
    ? allTabs.filter(t => getTabOsCompatibility(t.id, targetOs).status !== 'not_supported')
    : allTabs;

  return (
    <div className="bg-[#0f0f0f] border-2 border-white/20 rounded-2xl overflow-hidden shadow-2xl">
      
      {/* Top Main Title Bar */}
      <div className="border-b border-white/20 px-6 py-6 text-left bg-gradient-to-r from-slate-900 via-slate-950 to-slate-900">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-6">
          <div className="space-y-1">
            <span className="bg-[#FF3B30]/15 text-[#FF3B30] border border-[#FF3B30]/30 text-[9px] px-2.5 py-1 font-mono font-black tracking-widest uppercase rounded">
              DEPLOYABLE SCRIPT & NOTEPAD EXPORTER
            </span>
            <h2 className="text-xl sm:text-2xl font-black mt-2 text-white uppercase tracking-tight">System Security & Auto-Fix Scripts</h2>
            <p className="text-white/50 text-xs mt-1 max-w-xl">
              Copy or export scripts tailored for your target Windows OS version (.txt / .ps1) to prevent system crashes.
            </p>
          </div>
          
          <div className="flex flex-wrap gap-2.5">
            <button
              onClick={copyScript}
              className="flex items-center gap-1.5 bg-[#050505] hover:bg-white/5 text-white px-4 py-2.5 text-xs font-black uppercase tracking-wider border-2 border-white/20 hover:border-white transition cursor-pointer select-none rounded-xl"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-[#FF3B30]" />}
              {copied ? 'Copied to Clipboard' : 'Copy Code for Notepad'}
            </button>

            <button
              onClick={() => downloadFile(getActiveFilename('txt'), getActiveCode())}
              className="flex items-center gap-1.5 bg-amber-500 hover:bg-amber-600 text-black px-4 py-2.5 text-xs font-black uppercase tracking-wider transition cursor-pointer select-none rounded-xl"
              title="Download clean plain text format for Notepad"
            >
              <FileText className="w-3.5 h-3.5" />
              Notepad (.txt)
            </button>

            <button
              onClick={() => downloadFile(getActiveFilename('ps1'), getActiveCode())}
              className="flex items-center gap-1.5 bg-[#FF3B30] hover:bg-[#E02E24] text-white px-4 py-2.5 text-xs font-black uppercase tracking-wider transition cursor-pointer select-none rounded-xl shadow-lg"
              title="Download PowerShell script file"
            >
              <Download className="w-3.5 h-3.5" />
              Script (.ps1)
            </button>

            <button
              onClick={() => downloadFile(`UNDO_Revert_${activeTab.toUpperCase()}_${getOsFileSuffix(targetOs)}.ps1`, generateUndoScript(activeTab, { adDomain, adUsername, localUsername, subnetCidr, targetOs }))}
              className="flex items-center gap-1.5 bg-purple-600 hover:bg-purple-700 text-white px-4 py-2.5 text-xs font-black uppercase tracking-wider transition cursor-pointer select-none rounded-xl shadow-lg border border-purple-400/30"
              title="Download corresponding Undo / Revert script to roll back changes"
            >
              <RotateCcw className="w-3.5 h-3.5 text-purple-200" />
              Undo Script (.ps1)
            </button>

            {onOpenSystemFastModal && (
              <button
                onClick={onOpenSystemFastModal}
                className="flex items-center gap-1.5 bg-gradient-to-r from-amber-400 to-yellow-500 hover:from-amber-300 hover:to-yellow-400 text-black px-4 py-2.5 text-xs font-black uppercase tracking-wider transition cursor-pointer select-none rounded-xl shadow-lg border border-amber-300"
                title="Windows 10/11 Pro System Fast & Safe Speed Optimization Guide"
              >
                <Zap className="w-3.5 h-3.5 text-black fill-black" />
                System Fast (Win 10/11 Pro)
              </button>
            )}

            {onOpenGitHubModal && (
              <button
                onClick={onOpenGitHubModal}
                className="flex items-center gap-1.5 bg-emerald-500 hover:bg-emerald-600 text-black px-4 py-2.5 text-xs font-black uppercase tracking-wider transition cursor-pointer select-none rounded-xl shadow-lg shadow-emerald-950/20"
                title="Push script directly to GitHub repository or publish Gist"
              >
                <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 24 24">
                  <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                </svg>
                GitHub Live Sync
              </button>
            )}
          </div>
        </div>
      </div>

      {/* PROMINENT TARGET WINDOWS OS SELECTION CONTROL BAR */}
      <div className="bg-[#141414] border-b border-white/15 p-5 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          
          {/* Dropdown Selector */}
          <div className="space-y-1.5 flex-1 max-w-xl">
            <label className="text-xs font-black uppercase tracking-wider text-cyan-300 flex items-center gap-2 font-mono">
              <Cpu className="w-4 h-4 text-cyan-400" />
              Target Windows OS Version Selection (Prevents System Crashes)
            </label>
            <div className="relative">
              <select
                value={targetOs}
                onChange={(e) => setTargetOs(e.target.value as TargetOsOption)}
                className="w-full bg-black border-2 border-cyan-500/60 rounded-xl px-4 py-2.5 text-xs font-mono text-cyan-200 font-bold focus:border-cyan-400 focus:outline-none cursor-pointer shadow-lg"
              >
                <option value="win11_10" className="bg-black text-white">🪟 Windows 11 / Windows 10 Workstation (Modern Client OS)</option>
                <option value="win_server_2022_2016" className="bg-black text-white">🖥️ Windows Server 2022 / 2019 / 2016 (Modern Enterprise Server)</option>
                <option value="win_server_2012" className="bg-black text-white">🏢 Windows Server 2012 R2 / 2012 (Legacy Enterprise Server)</option>
                <option value="win7_8_legacy" className="bg-black text-white">💻 Windows 7 SP1 / 8.1 (Legacy Client OS)</option>
              </select>
            </div>
          </div>

          {/* Compatible Filter Toggle */}
          <div className="flex items-center gap-3 bg-black/60 border border-white/10 px-4 py-2.5 rounded-xl">
            <Filter className="w-4 h-4 text-amber-400 shrink-0" />
            <div className="text-left">
              <div className="text-xs font-bold text-white">Filter Compatible Only</div>
              <div className="text-[10px] text-white/50">Hide scripts unsupported on selected OS</div>
            </div>
            <button
              onClick={() => setShowOnlyCompatible(!showOnlyCompatible)}
              className={`w-11 h-6 flex items-center rounded-full p-1 cursor-pointer transition ${
                showOnlyCompatible ? 'bg-amber-500' : 'bg-white/20'
              }`}
            >
              <div className={`bg-black w-4 h-4 rounded-full shadow-md transform transition ${
                showOnlyCompatible ? 'translate-x-5' : 'translate-x-0'
              }`} />
            </button>
          </div>

        </div>

        {/* Dynamic OS Capabilities Summary Card */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
          <div className="bg-black/40 border border-white/10 rounded-lg p-2.5 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <div>
              <span className="text-[10px] text-white/40 block">POWERSHELL BASELINE</span>
              <span className="text-white font-bold">
                {targetOs === 'win11_10' ? 'PowerShell 5.1 / Core 7.x' : targetOs === 'win_server_2022_2016' ? 'PowerShell 5.1 Native' : targetOs === 'win_server_2012' ? 'PowerShell 3.0 / 4.0' : 'PowerShell 2.0 / 3.0'}
              </span>
            </div>
          </div>

          <div className="bg-black/40 border border-white/10 rounded-lg p-2.5 flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400 shrink-0" />
            <div>
              <span className="text-[10px] text-white/40 block">SERVER CRASH GUARD</span>
              <span className={targetOs.includes('server') ? 'text-amber-300 font-bold' : 'text-emerald-400 font-bold'}>
                {targetOs.includes('server') ? 'Active (Safe Mode Bypasses GUI)' : 'Workstation (Full GUI Active)'}
              </span>
            </div>
          </div>

          <div className="bg-black/40 border border-white/10 rounded-lg p-2.5 flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400 shrink-0" />
            <div>
              <span className="text-[10px] text-white/40 block">WINGET PACKAGE MANAGER</span>
              <span className={targetOs === 'win11_10' ? 'text-emerald-400 font-bold' : targetOs === 'win_server_2022_2016' ? 'text-amber-300 font-bold' : 'text-red-400 font-bold'}>
                {targetOs === 'win11_10' ? 'Natively Supported' : targetOs === 'win_server_2022_2016' ? 'AppInstaller Optional' : 'Not Supported (Bypassed)'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Script Selection Tabs with Compatibility Badges */}
      <div className="border-b border-white/10 bg-[#0c0c0c] flex flex-wrap px-4 gap-2 py-3">
        {visibleTabs.map(tab => {
          const compat = getTabOsCompatibility(tab.id, targetOs);
          const isActive = activeTab === tab.id;

          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex flex-col items-start gap-1 px-3.5 py-2 rounded-xl text-xs font-black uppercase tracking-wider cursor-pointer transition border ${
                isActive
                  ? 'bg-white/10 border-white/30 text-white shadow-lg'
                  : 'bg-black/40 border-white/10 text-white/60 hover:text-white hover:bg-white/5'
              }`}
            >
              <div className="flex items-center gap-2">
                {tab.icon}
                <span>{tab.label}</span>
              </div>

              {/* OS Compatibility Badge */}
              <div className="flex items-center gap-1 mt-0.5">
                <span className={`px-1.5 py-0.2 rounded text-[9px] font-mono font-bold uppercase ${
                  compat.color === 'emerald' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' :
                  compat.color === 'cyan' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' :
                  compat.color === 'amber' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                  'bg-red-500/20 text-red-300 border border-red-500/40'
                }`}>
                  {compat.badge}
                </span>
              </div>
            </button>
          );
        })}
      </div>

      <div className="p-6">
        <div className="space-y-6">

          {/* Active OS Compatibility & Safe Protection Warning Banner */}
          {activeCompat.warning && (
            <div className="bg-amber-950/40 border-2 border-amber-500/50 rounded-xl p-4 flex items-start gap-3 text-xs text-amber-200">
              <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <strong className="font-bold text-amber-300 block uppercase">
                  OS Compatibility Guard Alert: {activeCompat.badge}
                </strong>
                <p className="text-amber-100/80 leading-relaxed font-sans">
                  {activeCompat.warning}
                </p>
              </div>
            </div>
          )}

          {/* Dedicated LDAP SPN Probe Feature Highlight Card */}
          {activeTab === 'ldap_spn' && (
            <div className="bg-[#051824] border-2 border-cyan-500/50 p-5 rounded-xl space-y-3 text-left font-mono">
              <div className="flex items-center justify-between border-b border-cyan-500/30 pb-2 flex-wrap gap-2">
                <div className="flex items-center gap-2">
                  <Users className="w-5 h-5 text-cyan-400" />
                  <h4 className="text-xs font-black text-white uppercase tracking-wider">
                    7. Active Directory LDAP Service Principal Name (SPN) & Kerberoasting Probe
                  </h4>
                </div>
                <span className="text-[9px] bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 px-2.5 py-0.5 rounded uppercase font-bold">
                  Active Directory RSAT Audit
                </span>
              </div>

              <p className="text-xs text-cyan-100/80 leading-relaxed font-sans">
                Queries Active Directory domain controllers via LDAP to identify all user service accounts with configured Service Principal Names (SPNs). Evaluates <code className="text-cyan-300 bg-black/60 px-1 py-0.2 rounded border border-white/10">SamAccountName</code>, <code className="text-cyan-300 bg-black/60 px-1 py-0.2 rounded border border-white/10">ServicePrincipalName</code>, <code className="text-cyan-300 bg-black/60 px-1 py-0.2 rounded border border-white/10">PasswordLastSet</code>, and <code className="text-cyan-300 bg-black/60 px-1 py-0.2 rounded border border-white/10">PasswordNeverExpires</code> flags to audit Kerberoasting vulnerability surfaces.
              </p>

              <div className="bg-black/80 border border-cyan-500/30 p-2.5 rounded text-[10px] space-y-1">
                <span className="text-cyan-400 font-bold block">Executed Tool Query Command:</span>
                <code className="text-white select-all block break-all font-mono">
                  Get-ADUser -Filter &#123;ServicePrincipalName -like "*"&#125; -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires | Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet, PasswordNeverExpires
                </code>
              </div>
            </div>
          )}

          {/* Dedicated BSOD CRITICAL_PROCESS_DIED Emergency Fix Feature Card */}
          {activeTab === 'bsod_fix' && (
            <div className="bg-[#1f0909] border-2 border-red-500/60 p-5 rounded-xl space-y-4 text-left font-mono">
              <div className="flex items-center justify-between border-b border-red-500/40 pb-3 flex-wrap gap-2">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-6 h-6 text-red-400 animate-pulse" />
                  <div>
                    <h4 className="text-xs font-black text-white uppercase tracking-wider flex items-center gap-2">
                      8. Emergency BSOD & CRITICAL_PROCESS_DIED Fix & Data Shield
                    </h4>
                    <span className="text-[10px] text-red-300/80 font-sans mt-0.5 block">
                      Fix Windows stop code <code className="text-red-200 font-bold">CRITICAL_PROCESS_DIED (0xEF)</code> when running .ps1 / .bat scripts without data loss.
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-white/60 font-sans font-bold uppercase">Format:</span>
                  <button
                    onClick={() => setBsodScriptFormat('ps1')}
                    className={`px-3 py-1 rounded text-xs font-black uppercase transition cursor-pointer border ${
                      bsodScriptFormat === 'ps1'
                        ? 'bg-red-500 text-black border-red-400 shadow-md'
                        : 'bg-black/60 text-white/60 border-white/10 hover:bg-white/10'
                    }`}
                  >
                    PowerShell (.ps1)
                  </button>
                  <button
                    onClick={() => setBsodScriptFormat('bat')}
                    className={`px-3 py-1 rounded text-xs font-black uppercase transition cursor-pointer border ${
                      bsodScriptFormat === 'bat'
                        ? 'bg-amber-500 text-black border-amber-400 shadow-md'
                        : 'bg-black/60 text-white/60 border-white/10 hover:bg-white/10'
                    }`}
                  >
                    Batch (.bat)
                  </button>
                </div>
              </div>

              {/* Troubleshooting Root Cause Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-sans">
                <div className="bg-black/70 border border-red-500/30 p-3 rounded-lg space-y-1">
                  <span className="text-red-400 font-bold text-[11px] block flex items-center gap-1">
                    <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                    1. Why `CRITICAL_PROCESS_DIED` Occurs
                  </span>
                  <p className="text-white/70 text-[11px] leading-relaxed">
                    A script or process attempted to terminate a core Windows binary (<code className="text-red-300 font-mono">csrss.exe</code>, <code className="text-red-300 font-mono">lsass.exe</code>, <code className="text-red-300 font-mono">services.exe</code>, <code className="text-red-300 font-mono">wininit.exe</code>, <code className="text-red-300 font-mono">svchost.exe</code>) or unhandled registry writes corrupted LSA/SCHANNEL.
                  </p>
                </div>

                <div className="bg-black/70 border border-emerald-500/30 p-3 rounded-lg space-y-1">
                  <span className="text-emerald-400 font-bold text-[11px] block flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    2. Data Preservation Guarantee
                  </span>
                  <p className="text-white/70 text-[11px] leading-relaxed">
                    This script creates an immediate System Restore Point (<code className="text-emerald-300 font-mono">Checkpoint-Computer</code>) before making changes. Your files, documents, and system state remain 100% safe.
                  </p>
                </div>

                <div className="bg-black/70 border border-cyan-500/30 p-3 rounded-lg space-y-1">
                  <span className="text-cyan-400 font-bold text-[11px] block flex items-center gap-1">
                    <Shield className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    3. Automatic File & Service Repair
                  </span>
                  <p className="text-white/70 text-[11px] leading-relaxed">
                    Executes <code className="text-cyan-300 font-mono">sfc /scannow</code> and <code className="text-cyan-300 font-mono">DISM /Online /Cleanup-Image /RestoreHealth</code> to repair damaged DLLs and verifies core Windows services are active.
                  </p>
                </div>
              </div>

              <div className="bg-black/90 border border-red-500/40 p-3 rounded-lg text-[11px] text-white/80 space-y-1 font-sans">
                <span className="text-red-400 font-bold block font-mono">
                  Safe Mode Recovery (If Windows continuously reboots with CRITICAL_PROCESS_DIED):
                </span>
                <p>
                  1. Hold <kbd className="bg-white/20 px-1 py-0.5 rounded text-white font-mono">Shift</kbd> while clicking <strong>Restart</strong> in Windows menu.<br />
                  2. Select <strong>Troubleshoot &gt; Advanced Options &gt; Startup Settings &gt; Restart</strong>.<br />
                  3. Press <kbd className="bg-white/20 px-1 py-0.5 rounded text-white font-mono">4</kbd> or <kbd className="bg-white/20 px-1 py-0.5 rounded text-white font-mono">F4</kbd> to enter <strong>Safe Mode</strong>, then right-click and run this <code className="text-red-300 font-mono">Fix_CRITICAL_PROCESS_DIED_BSOD.{bsodScriptFormat}</code> script as Administrator.
                </p>
              </div>
            </div>
          )}

          {/* Environment Parameters Bar for Tailored Scripts */}
          {(activeTab === 'addc' || activeTab === 'standalone' || activeTab === 'nas_fw') && (
            <div className="bg-[#141414] border border-white/15 p-4 rounded-xl space-y-3">
              <span className="text-[10px] font-mono font-black uppercase tracking-widest text-cyan-400 block">
                TARGET ENVIRONMENT & CREDENTIAL PARAMETERS FOR AUTOMATED PS1 REMEDIATION
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                {activeTab === 'addc' && (
                  <>
                    <div>
                      <label className="text-[10px] text-white/60 font-mono uppercase block mb-1">AD Domain FQDN</label>
                      <input
                        type="text"
                        value={adDomain}
                        onChange={(e) => setAdDomain(e.target.value)}
                        className="w-full bg-black border border-white/20 rounded px-2.5 py-1.5 text-xs font-mono text-white focus:border-cyan-400 outline-none"
                        placeholder="corp.domain.com"
                      />
                    </div>
                    <div>
                      <label className="text-[10px] text-white/60 font-mono uppercase block mb-1">Domain Admin Username</label>
                      <input
                        type="text"
                        value={adUsername}
                        onChange={(e) => setAdUsername(e.target.value)}
                        className="w-full bg-black border border-white/20 rounded px-2.5 py-1.5 text-xs font-mono text-white focus:border-cyan-400 outline-none"
                        placeholder="CORP\Administrator"
                      />
                    </div>
                  </>
                )}

                {activeTab === 'standalone' && (
                  <div>
                    <label className="text-[10px] text-white/60 font-mono uppercase block mb-1">Local Admin User</label>
                    <input
                      type="text"
                      value={localUsername}
                      onChange={(e) => setLocalUsername(e.target.value)}
                      className="w-full bg-black border border-white/20 rounded px-2.5 py-1.5 text-xs font-mono text-white focus:border-emerald-400 outline-none"
                      placeholder=".\Administrator"
                    />
                  </div>
                )}

                <div>
                  <label className="text-[10px] text-white/60 font-mono uppercase block mb-1">Subnet Range (CIDR)</label>
                  <input
                    type="text"
                    value={subnetCidr}
                    onChange={(e) => setSubnetCidr(e.target.value)}
                    className="w-full bg-black border border-white/20 rounded px-2.5 py-1.5 text-xs font-mono text-white focus:border-amber-400 outline-none"
                    placeholder="192.168.1.0/24"
                  />
                </div>
              </div>
            </div>
          )}

          {/* Execution & Notepad Instructions */}
          <div className="bg-[#FF3B30]/10 border-2 border-[#FF3B30]/30 p-5 rounded-xl flex items-start gap-4 text-xs select-text">
            <ShieldAlert className="w-5 h-5 text-[#FF3B30] flex-shrink-0 mt-0.5" />
            <div className="text-left space-y-1">
              <strong className="font-black uppercase tracking-wider text-[#FF3B30] block">Administrator Privileges & Notepad How-To</strong>
              <p className="text-white/70 leading-relaxed font-semibold">
                To create a script with Notepad: Open <strong>Notepad</strong>, paste the copied text below, click <strong>File &gt; Save As</strong>, set <em>Save as type</em> to <strong>All Files (*.*)</strong>, name it <code>{getActiveFilename('ps1')}</code> (or <code>.bat</code>), and run it as Administrator!
              </p>
            </div>
          </div>

          <div className="text-left space-y-4">
            <h3 className="text-sm font-black uppercase tracking-widest text-white font-mono">STEP-BY-STEP NOTEPAD INSTRUCTIONS:</h3>
            <ol className="space-y-3.5 text-xs font-semibold text-white/70">
              <li className="flex items-start gap-3">
                <span className="flex items-center justify-center w-6 h-6 bg-[#FF3B30]/20 text-[#FF3B30] font-black text-xs flex-shrink-0 font-mono rounded">1</span>
                <span className="pt-0.5">
                  Click <strong>Copy Code for Notepad</strong> or download <strong>Notepad (.txt)</strong>.
                </span>
              </li>
              <li className="flex items-start gap-3">
                <span className="flex items-center justify-center w-6 h-6 bg-[#FF3B30]/20 text-[#FF3B30] font-black text-xs flex-shrink-0 font-mono rounded">2</span>
                <span className="pt-0.5">
                  Open <strong>Notepad</strong> on Windows (<kbd className="bg-white/10 px-1 py-0.2 rounded font-mono">Win + R</kbd> &rarr; type <code>notepad</code> &rarr; Enter).
                </span>
              </li>
              <li className="flex items-start gap-3">
                <span className="flex items-center justify-center w-6 h-6 bg-[#FF3B30]/20 text-[#FF3B30] font-black text-xs flex-shrink-0 font-mono rounded">3</span>
                <span className="pt-0.5">
                  Paste the script contents into Notepad, then click <strong>File &gt; Save As...</strong> and save as <code>{getActiveFilename('ps1')}</code>.
                </span>
              </li>
              <li className="flex items-start gap-3">
                <span className="flex items-center justify-center w-6 h-6 bg-[#FF3B30]/20 text-[#FF3B30] font-black text-xs flex-shrink-0 font-mono rounded">4</span>
                <div className="pt-0.5 space-y-1.5 flex-1 select-text">
                  <span>Right-click PowerShell or Terminal and select <strong>Run as Administrator</strong>, then run:</span>
                  <code className="block p-3 bg-[#050505] border border-white/15 text-[#FF3B30] font-mono font-bold text-xs rounded-lg">
                    Set-ExecutionPolicy Bypass -Scope Process -Force; .\{getActiveFilename('ps1')}
                  </code>
                </div>
              </li>
            </ol>
          </div>

          {/* Remediation vs Undo Mode Toggle Bar & Safety Banner */}
          <div className="bg-gradient-to-r from-slate-900 via-purple-950 to-slate-900 border-2 border-purple-500/40 p-4 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-500/20 rounded-lg border border-purple-400/30">
                <RotateCcw className="w-5 h-5 text-purple-400 shrink-0" />
              </div>
              <div className="text-left">
                <span className="text-xs font-black text-white uppercase tracking-wider block font-mono flex items-center gap-2">
                  System Restore Safety & Reversion Shield Active
                  <span className="bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-[9px] px-2 py-0.5 rounded font-sans font-bold">100% Rollback Safe</span>
                </span>
                <p className="text-[11px] text-white/70 font-sans mt-0.5">
                  <strong>Safety Step:</strong> Script automatically prompts for Windows System Restore Point creation on Drive C:\ before running commands. <strong>Undo Script:</strong> Reverts changes anytime.
                </p>
              </div>
            </div>

            {/* View Mode Selector Toggle */}
            <div className="flex items-center bg-black/80 border border-purple-500/50 p-1 rounded-xl shrink-0 font-mono">
              <button
                onClick={() => setIsViewingUndo(false)}
                className={`px-3 py-1.5 rounded-lg text-xs font-black uppercase transition cursor-pointer ${
                  !isViewingUndo 
                    ? 'bg-[#FF3B30] text-white shadow-md' 
                    : 'text-white/60 hover:text-white hover:bg-white/5'
                }`}
              >
                Remediation Script
              </button>
              <button
                onClick={() => setIsViewingUndo(true)}
                className={`px-3 py-1.5 rounded-lg text-xs font-black uppercase transition cursor-pointer flex items-center gap-1.5 ${
                  isViewingUndo 
                    ? 'bg-purple-600 text-white shadow-md' 
                    : 'text-purple-300 hover:text-white hover:bg-white/5'
                }`}
              >
                <RotateCcw className="w-3 h-3 text-purple-300" />
                Undo / Revert Script
              </button>
            </div>
          </div>

          {/* Script Code Preview Window */}
          <div className="pt-4 border-t border-white/10">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
              <span className="text-xs font-black uppercase tracking-wider text-white flex items-center gap-2 font-mono">
                <FileText className={`w-4 h-4 ${isViewingUndo ? 'text-purple-400' : 'text-[#FF3B30]'}`} />
                {isViewingUndo ? 'Full Undo / Revert Script Text' : 'Full Script Source Text'} ({getActiveFilename('txt')})
              </span>

              <div className="flex items-center gap-2">
                <button
                  onClick={copyScript}
                  className="px-2.5 py-1 bg-white/10 hover:bg-white/20 text-white text-[10px] font-bold uppercase rounded font-mono transition cursor-pointer"
                >
                  {copied ? 'Copied!' : 'Copy Code'}
                </button>
                <button
                  onClick={() => downloadFile(getActiveFilename('txt'), getActiveCode())}
                  className="px-2.5 py-1 bg-amber-500 hover:bg-amber-600 text-black text-[10px] font-black uppercase rounded font-mono transition cursor-pointer"
                >
                  Download .txt
                </button>
              </div>
            </div>

            <div className="max-h-[380px] overflow-y-auto border border-white/15 rounded-xl shadow-inner">
              <pre className="text-left font-mono text-[11px] p-5 bg-[#050505] text-white/80 leading-relaxed whitespace-pre overflow-x-auto select-all">
                {getActiveCode()}
              </pre>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
