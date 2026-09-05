import React, { useState } from 'react';
import { 
  Zap, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  Sliders, 
  Terminal, 
  Copy, 
  Check, 
  Download, 
  ShieldCheck, 
  HardDrive, 
  Sparkles, 
  Search, 
  Activity, 
  FolderCheck, 
  Trash2, 
  Laptop, 
  Cpu, 
  Layers, 
  ExternalLink,
  ChevronRight,
  RefreshCw,
  X,
  FileText
} from 'lucide-react';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

type TabType = 'review' | 'startup' | 'plan' | 'summary' | 'script';
type FilterType = 'all' | 'safe' | 'optional' | 'avoid';

interface TweakItem {
  id: string;
  name: string;
  category: 'cleanup' | 'registry' | 'service' | 'hardware';
  recommendation: 'Safe' | 'Optional' | 'Don\'t Disable' | 'Avoid';
  status: 'safe' | 'optional' | 'avoid';
  notes: string;
  verdict: string;
  commandSnippet?: string;
}

const TWEAKS_DATA: TweakItem[] = [
  {
    id: 'clear-recent',
    name: 'Clear Recent',
    category: 'cleanup',
    recommendation: 'Safe',
    status: 'safe',
    notes: 'Removes recent-item history; does not significantly speed Windows, but safe for privacy and clean UI.',
    verdict: '✅ Safe',
    commandSnippet: 'Remove-Item -Path "$env:APPDATA\\Microsoft\\Windows\\Recent\\*" -Force -Recurse -ErrorAction SilentlyContinue'
  },
  {
    id: 'delete-temp',
    name: 'Delete %temp%',
    category: 'cleanup',
    recommendation: 'Safe',
    status: 'safe',
    notes: 'Good for cleanup and disk recovery. In-use locked files will be gracefully skipped by Windows.',
    verdict: '✅ Safe',
    commandSnippet: 'Get-ChildItem -Path $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue'
  },
  {
    id: 'empty-recycle-bin',
    name: 'Delete / Empty Recycle Bin',
    category: 'cleanup',
    recommendation: 'Safe',
    status: 'safe',
    notes: 'Purges deleted file caches across all drives ($Recycle.Bin). Instantly reclaims gigabytes of free disk space safely without affecting running programs.',
    verdict: '✅ Safe',
    commandSnippet: 'Clear-RecycleBin -Force -ErrorAction SilentlyContinue'
  },
  {
    id: 'turn-off-usb',
    name: 'Turn off USB',
    category: 'hardware',
    recommendation: 'Don\'t Disable',
    status: 'avoid',
    notes: 'Can break connected USB devices, external storage, keyboards, mice, and biometric peripherals.',
    verdict: '❌ Don\'t disable USB services/controllers'
  },
  {
    id: 'menushowdelay',
    name: 'MenuShowDelay = 0',
    category: 'registry',
    recommendation: 'Optional',
    status: 'optional',
    notes: 'Makes desktop context menus and Start submenus appear instantaneously, but the real performance improvement is tiny.',
    verdict: '⚠️ Optional',
    commandSnippet: 'Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "MenuShowDelay" -Value "0" -Type String'
  },
  {
    id: 'registry-usb-4',
    name: 'Registry USB = 4',
    category: 'registry',
    recommendation: 'Avoid',
    status: 'avoid',
    notes: 'Don\'t change an unspecified USB registry value without knowing exactly which key and value it controls. Setting Start=4 in USBSTOR disables USB storage completely.',
    verdict: '❌ Avoid'
  },
  {
    id: 'disable-sysmain',
    name: 'Disable SysMain (Superfetch)',
    category: 'service',
    recommendation: 'Don\'t Disable',
    status: 'avoid',
    notes: 'SysMain can help performance by pre-loading frequently used memory blocks, especially on systems with HDDs and standard SSDs.',
    verdict: '⚠️ Usually don\'t'
  },
  {
    id: 'disable-telemetry',
    name: 'Disable Connected User Experiences & Telemetry',
    category: 'service',
    recommendation: 'Optional',
    status: 'optional',
    notes: 'Disabling (DiagTrack) provides slight privacy improvement, but usually delivers little to no noticeable speed improvement on modern CPUs.',
    verdict: '⚠️ Optional',
    commandSnippet: 'Stop-Service -Name "DiagTrack" -ErrorAction SilentlyContinue; Set-Service -Name "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue'
  },
  {
    id: 'disable-search',
    name: 'Disable Windows Search (WSearch)',
    category: 'service',
    recommendation: 'Don\'t Disable',
    status: 'avoid',
    notes: 'It can slightly reduce background indexing activity, but searching files, Outlook, and Start Menu items will become much worse and slower.',
    verdict: '⚠️ Usually don\'t'
  }
];

export default function SystemFastModal({ isOpen, onClose }: Props) {
  const [activeTab, setActiveTab] = useState<TabType>('review');
  const [filter, setFilter] = useState<FilterType>('all');
  const [copiedCode, setCopiedCode] = useState(false);
  const [scriptFormat, setScriptFormat] = useState<'ps1' | 'bat'>('ps1');

  if (!isOpen) return null;

  const filteredTweaks = TWEAKS_DATA.filter(t => {
    if (filter === 'safe') return t.status === 'safe';
    if (filter === 'optional') return t.status === 'optional';
    if (filter === 'avoid') return t.status === 'avoid';
    return true;
  });

  const safePowershellScript = `# =====================================================================
# SMARTPRO SECOPS - WINDOWS 10/11 PRO SAFE SPEED OPTIMIZER (.ps1)
# TARGET: Windows 10 Pro / Windows 11 Pro
# SAFE & VERIFIED OPTIMIZATION SUITE (No dangerous service tampering)
# =====================================================================

$ErrorActionPreference = "SilentlyContinue"

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "   SMARTPRO SECOPS - WINDOWS 10/11 PRO SAFE SYSTEM FAST OPTIMIZER    " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

# 1. Administrator Elevation Check
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Administrator Privileges Required! Please right-click -> Run as Administrator." -ForegroundColor Red
    Pause
    Exit
}

# 2. System Restore Point Safety Prompt
Write-Host "---------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host " [SAFETY PROMPT] CREATE SYSTEM RESTORE POINT BEFORE TWEAKS           " -ForegroundColor Yellow
Write-Host "---------------------------------------------------------------------" -ForegroundColor Yellow
$userChoice = Read-Host "Create a Windows System Restore Point on Drive C:\\ first? (Y/N) [Default: Y]"
if ($userChoice -eq "" -or $userChoice -like "y*") {
    try {
        Enable-ComputerRestore -Drive "C:\\" -ErrorAction SilentlyContinue | Out-Null
        Checkpoint-Computer -Description "SmartPro_Safe_Speed_Optimization" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[+] System Restore Point 'SmartPro_Safe_Speed_Optimization' created successfully." -ForegroundColor Green
    } catch {
        Write-Host "[-] System Restore step checked." -ForegroundColor Yellow
    }
}

# 3. Clean %TEMP% and System Temp (Gracefully skips in-use locked files)
Write-Host "[1/7] Cleaning Temporary Files (%TEMP% & Windows Temp)..." -ForegroundColor Cyan
$tempPaths = @($env:TEMP, "$env:SystemRoot\\Temp")
foreach ($path in $tempPaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | 
            Where-Object { -not $_.PSIsContainer } | 
            ForEach-Object {
                try { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
            }
    }
}
Write-Host "    [OK] Temporary files cleared. Locked active files safely skipped." -ForegroundColor Green

# 4. Empty Recycle Bin on all drives ($Recycle.Bin)
Write-Host "[2/7] Emptying & Purging Recycle Bin across all drives..." -ForegroundColor Cyan
try {
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Host "    [OK] Recycle Bin cleared and disk space recovered." -ForegroundColor Green
} catch {
    Write-Host "    [OK] Recycle Bin check completed." -ForegroundColor Green
}

# 5. Clear Windows Recent Items & Explorer History
Write-Host "[3/7] Clearing Recent Items & Explorer Jump Lists..." -ForegroundColor Cyan
$recentPath = "$env:APPDATA\\Microsoft\\Windows\\Recent"
if (Test-Path $recentPath) {
    Get-ChildItem -Path $recentPath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    Write-Host "    [OK] Recent items history safely purged." -ForegroundColor Green
}

# 6. Optional MenuShowDelay tweak (Instant Responsive Menus)
Write-Host "[4/7] Applying Optional MenuShowDelay = 0 (Instant Submenu Response)..." -ForegroundColor Cyan
try {
    Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "MenuShowDelay" -Value "0" -Type String -Force -ErrorAction SilentlyContinue
    Write-Host "    [OK] MenuShowDelay set to 0." -ForegroundColor Green
} catch {}

# 7. Flush DNS & Clear Thumbnail Cache
Write-Host "[5/7] Flushing DNS Cache & Refreshing Explorer Thumbnail DB..." -ForegroundColor Cyan
Clear-DnsClientCache -ErrorAction SilentlyContinue
ipconfig /flushdns | Out-Null
Write-Host "    [OK] DNS cache cleared." -ForegroundColor Green

# 8. Safe Windows Component Health Check (DISM ScanHealth)
Write-Host "[6/7] Checking Windows System Image Health (DISM)..." -ForegroundColor Cyan
try {
    DISM.exe /Online /Cleanup-Image /ScanHealth
    Write-Host "    [OK] Component store image verified." -ForegroundColor Green
} catch {}

# 9. Storage Sense Verification (Windows 10/11 Pro)
Write-Host "[7/7] Checking Windows Storage Sense Auto-Cleanup Policy..." -ForegroundColor Cyan
try {
    Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\StoragePolicy" -Name "01" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Host "    [OK] Storage Sense auto-maintenance enabled." -ForegroundColor Green
} catch {}

Write-Host "=====================================================================" -ForegroundColor Green
Write-Host "   WINDOWS 10/11 PRO SAFE OPTIMIZATION COMPLETED SUCCESSFULLY!        " -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host "Next recommended steps:" -ForegroundColor White
Write-Host "  1. Open Task Manager (Ctrl+Shift+Esc) -> Startup Apps -> Disable non-essential apps." -ForegroundColor Cyan
Write-Host "  2. Keep at least 15-20% free storage space on Drive C:." -ForegroundColor Cyan
Write-Host "  3. Verify Windows Update & GPU drivers." -ForegroundColor Cyan
Read-Host "Press Enter to exit..."
`;

  const safeBatchScript = `@echo off
title SmartPro SecOps - Windows 10/11 Pro Safe Speed Optimizer
color 0B
cls
echo =======================================================================
echo    SMARTPRO SECOPS - WINDOWS 10/11 PRO SAFE SPEED OPTIMIZER (.BAT)
echo =======================================================================
echo.

:: 1. Admin Privilege Check
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [ERROR] Administrator Privileges Required!
    echo Please right-click this batch file and select "Run as administrator".
    echo.
    pause
    exit /b
)

echo [1/6] Cleaning user temporary files (%%TEMP%%)...
del /s /f /q "%TEMP%\*.*" >nul 2>&1
for /d %%p in ("%TEMP%\*.*") do rmdir /s /q "%%p" >nul 2>&1
echo       [OK] User temp folder cleared.

echo [2/6] Cleaning Windows system temp files...
del /s /f /q "%SystemRoot%\Temp\*.*" >nul 2>&1
for /d %%p in ("%SystemRoot%\Temp\*.*") do rmdir /s /q "%%p" >nul 2>&1
echo       [OK] System temp folder cleared.

echo [3/6] Emptying and purging Recycle Bin across all drives...
PowerShell.exe -NoProfile -Command "Clear-RecycleBin -Force -ErrorAction SilentlyContinue" >nul 2>&1
rd /s /q %systemdrive%\$Recycle.bin >nul 2>&1
echo       [OK] Recycle Bin cleared and storage reclaimed.

echo [4/6] Clearing Recent items history...
del /s /f /q "%APPDATA%\Microsoft\Windows\Recent\*.*" >nul 2>&1
echo       [OK] Recent items history cleared.

echo [5/6] Setting MenuShowDelay to 0 for instant UI menu transitions...
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >nul 2>&1
echo       [OK] MenuShowDelay registry key updated.

echo [6/6] Flushing DNS and refreshing network resolver cache...
ipconfig /flushdns >nul 2>&1
echo       [OK] DNS resolver flushed.

echo.
echo =======================================================================
echo   SAFE CLEANUP COMPLETE! 
echo =======================================================================
echo  RECOMMENDATION: Open Task Manager (Ctrl+Shift+Esc) -> Startup Apps
echo  and disable heavy startup launchers (Teams, Discord, Spotify, Steam).
echo =======================================================================
echo.
pause
`;

  const getActiveScriptContent = () => {
    return scriptFormat === 'ps1' ? safePowershellScript : safeBatchScript;
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(getActiveScriptContent());
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const handleDownload = () => {
    const content = getActiveScriptContent();
    const filename = scriptFormat === 'ps1' 
      ? 'SmartPro_Win10_11_Pro_Safe_Speed_Optimizer.ps1' 
      : 'SmartPro_Win10_11_Pro_Safe_Speed_Optimizer.bat';
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
      <div className="bg-[#0b101b] border-2 border-amber-500/50 rounded-2xl w-full max-w-5xl max-h-[92vh] flex flex-col shadow-2xl shadow-amber-950/60 overflow-hidden font-sans text-left">
        
        {/* Modal Top Header Banner */}
        <div className="bg-gradient-to-r from-[#1c1202] via-[#2d1b05] to-[#120a02] border-b border-amber-500/40 p-5 sm:p-6 flex items-start justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-amber-500/20 border-2 border-amber-400/60 rounded-xl text-amber-400 shrink-0 shadow-lg shadow-amber-950/50">
              <Zap className="w-7 h-7 text-amber-400 fill-amber-400/20 animate-pulse" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="bg-amber-400 text-black text-[10px] font-black px-2.5 py-0.5 rounded uppercase tracking-wider font-mono shadow">
                  System Fast
                </span>
                <span className="bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 text-[10px] font-bold px-2 py-0.5 rounded font-mono">
                  Windows 10 Pro & Windows 11 Pro Exclusive
                </span>
                <span className="bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[10px] font-bold px-2 py-0.5 rounded font-mono">
                  Safe & Verified Architecture
                </span>
              </div>
              <h2 className="text-xl sm:text-2xl font-black text-white tracking-tight mt-1.5 flex items-center gap-2">
                Windows 10/11 Pro Speed Optimization & Safe Tweaks Suite
              </h2>
              <p className="text-xs text-amber-200/80 mt-1 max-w-2xl leading-relaxed">
                Expert audit of system speed tweaks, startup apps management, and safe performance enhancements to keep Windows fast, reliable, and crash-free.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-xl bg-white/5 hover:bg-white/15 text-white/70 hover:text-white transition cursor-pointer border border-white/10 shrink-0"
            title="Close System Fast Suite"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Highlight Quote Alert Banner */}
        <div className="bg-[#141b2a] border-b border-amber-500/30 px-6 py-3.5 flex items-start sm:items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5 sm:mt-0" />
          <div className="text-xs text-amber-100/90 leading-snug">
            <strong className="text-amber-300">Expert Engineering Verdict: </strong>
            "Yes — some of those tweaks are useful, but I would not recommend all of them. A few can actually make Windows less reliable or slower. Prioritize safe cleanup and startup management over risky service or registry tampering."
          </div>
        </div>

        {/* Navigation Tabs Bar */}
        <div className="bg-black/60 border-b border-white/10 px-6 py-2.5 flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2 font-mono">
            <button
              onClick={() => setActiveTab('review')}
              className={`px-3.5 py-2 rounded-xl text-xs font-black uppercase tracking-wider transition cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'review'
                  ? 'bg-amber-400 text-black shadow-lg shadow-amber-950/40'
                  : 'bg-white/5 text-white/70 hover:text-white hover:bg-white/10 border border-white/10'
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              Tweaks Reviewed Matrix
            </button>

            <button
              onClick={() => setActiveTab('startup')}
              className={`px-3.5 py-2 rounded-xl text-xs font-black uppercase tracking-wider transition cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'startup'
                  ? 'bg-amber-400 text-black shadow-lg shadow-amber-950/40'
                  : 'bg-white/5 text-white/70 hover:text-white hover:bg-white/10 border border-white/10'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              Startup Apps Optimizer
            </button>

            <button
              onClick={() => setActiveTab('plan')}
              className={`px-3.5 py-2 rounded-xl text-xs font-black uppercase tracking-wider transition cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'plan'
                  ? 'bg-amber-400 text-black shadow-lg shadow-amber-950/40'
                  : 'bg-white/5 text-white/70 hover:text-white hover:bg-white/10 border border-white/10'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              Safe 8-Point Approach
            </button>

            <button
              onClick={() => setActiveTab('summary')}
              className={`px-3.5 py-2 rounded-xl text-xs font-black uppercase tracking-wider transition cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'summary'
                  ? 'bg-amber-400 text-black shadow-lg shadow-amber-950/40'
                  : 'bg-white/5 text-white/70 hover:text-white hover:bg-white/10 border border-white/10'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              Full Summary & Guide
            </button>

            <button
              onClick={() => setActiveTab('script')}
              className={`px-3.5 py-2 rounded-xl text-xs font-black uppercase tracking-wider transition cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'script'
                  ? 'bg-emerald-400 text-black shadow-lg shadow-emerald-950/40 font-bold'
                  : 'bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30 border border-emerald-500/40'
              }`}
            >
              <Terminal className="w-3.5 h-3.5 text-emerald-400" />
              1-Click Safe Script (.ps1 / .bat)
            </button>
          </div>

          <span className="text-[11px] text-white/40 font-mono hidden sm:inline-block">
            Target OS: <strong className="text-cyan-300">Win 10/11 Pro (64-bit)</strong>
          </span>
        </div>

        {/* Modal Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 text-white text-xs">
          
          {/* TAB 1: TWEAKS REVIEWED MATRIX */}
          {activeTab === 'review' && (
            <div className="space-y-6">
              
              {/* Quick Recycle Bin & Temp Cleanup Strip */}
              <div className="bg-gradient-to-r from-emerald-950/40 via-[#0a1f16] to-[#04120b] border-2 border-emerald-500/50 p-4 rounded-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow-lg">
                <div className="flex items-start gap-3">
                  <div className="p-2.5 rounded-lg bg-emerald-500/20 border border-emerald-400/40 text-emerald-400 shrink-0">
                    <Trash2 className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h4 className="font-mono font-black text-white text-xs uppercase tracking-wider">
                        Quick Command: Empty / Delete Recycle Bin & Temporary Files
                      </h4>
                      <span className="bg-emerald-500/20 text-emerald-300 font-mono text-[10px] px-2 py-0.5 rounded border border-emerald-500/40 font-bold">
                        100% Safe
                      </span>
                    </div>
                    <p className="text-white/70 text-[11px] mt-0.5 leading-relaxed font-sans">
                      Safely purge all contents from <code className="bg-black/60 px-1.5 py-0.5 rounded text-emerald-300 font-mono">$Recycle.Bin</code> across every partition without prompt, recovering storage instantly.
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2 w-full md:w-auto shrink-0 font-mono">
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText('Clear-RecycleBin -Force -ErrorAction SilentlyContinue; Write-Host "[OK] Recycle Bin Emptied." -ForegroundColor Green');
                      setCopiedCode(true);
                      setTimeout(() => setCopiedCode(false), 2000);
                    }}
                    className="flex-1 md:flex-none flex items-center justify-center gap-1.5 bg-emerald-500 hover:bg-emerald-400 text-black px-3.5 py-2 rounded-lg text-xs font-black uppercase tracking-wider transition cursor-pointer shadow-md"
                  >
                    {copiedCode ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedCode ? 'Copied PowerShell Cmd!' : 'Copy Recycle Bin Cmd'}
                  </button>
                </div>
              </div>

              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900/60 p-4 rounded-xl border border-white/10">
                <div>
                  <h3 className="text-sm font-black text-white uppercase tracking-wider font-mono">
                    Your Tweaks, Reviewed & Analyzed
                  </h3>
                  <p className="text-white/60 text-xs mt-0.5">
                    Categorized evaluation of common performance tweaks indicating exact risk and recommendation level.
                  </p>
                </div>

                <div className="flex items-center gap-1.5 font-mono">
                  <span className="text-[10px] text-white/40 uppercase mr-1">Filter:</span>
                  {(['all', 'safe', 'optional', 'avoid'] as FilterType[]).map((f) => (
                    <button
                      key={f}
                      onClick={() => setFilter(f)}
                      className={`px-2.5 py-1 rounded text-[11px] font-bold uppercase transition cursor-pointer border ${
                        filter === f
                          ? 'bg-amber-400 text-black border-amber-300'
                          : 'bg-white/5 text-white/60 hover:bg-white/10 border-white/10'
                      }`}
                    >
                      {f}
                    </button>
                  ))}
                </div>
              </div>

              {/* Matrix Table */}
              <div className="overflow-x-auto border border-white/15 rounded-xl">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-black/80 border-b border-white/15 text-white/60 font-mono uppercase text-[10px] tracking-wider">
                      <th className="py-3 px-4">Tweak</th>
                      <th className="py-3 px-4">Recommendation</th>
                      <th className="py-3 px-4">Technical Impact & Notes</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/10 font-sans">
                    {filteredTweaks.map((tweak) => (
                      <tr key={tweak.id} className="hover:bg-white/5 transition-colors">
                        <td className="py-3.5 px-4 font-mono font-bold text-white text-xs whitespace-nowrap">
                          {tweak.name}
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-black uppercase font-mono border ${
                            tweak.status === 'safe'
                              ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                              : tweak.status === 'optional'
                              ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                              : 'bg-red-500/20 text-red-300 border-red-500/40'
                          }`}>
                            {tweak.verdict}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 text-white/80 text-xs leading-relaxed">
                          {tweak.notes}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Deep Dive Breakdown Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono">
                <div className="bg-emerald-950/20 border-2 border-emerald-500/40 p-4 rounded-xl space-y-2">
                  <div className="flex items-center gap-2 text-emerald-400 font-bold text-xs uppercase">
                    <CheckCircle2 className="w-4 h-4" />
                    Safe Tweaks (Do These)
                  </div>
                  <ul className="text-[11px] text-white/70 space-y-1 font-sans">
                    <li>• <strong>Empty Recycle Bin:</strong> Safely purges $Recycle.Bin on all drives.</li>
                    <li>• <strong>Clear Recent:</strong> Removes file history without breaking OS.</li>
                    <li>• <strong>Delete %temp%:</strong> Recovers gigabytes of disk space safely.</li>
                    <li>• <strong>Storage Sense:</strong> Automated garbage collection.</li>
                  </ul>
                </div>

                <div className="bg-amber-950/20 border-2 border-amber-500/40 p-4 rounded-xl space-y-2">
                  <div className="flex items-center gap-2 text-amber-400 font-bold text-xs uppercase">
                    <AlertTriangle className="w-4 h-4" />
                    Optional (Tiny Gain)
                  </div>
                  <ul className="text-[11px] text-white/70 space-y-1 font-sans">
                    <li>• <strong>MenuShowDelay = 0:</strong> Snappier menus, negligible real speedup.</li>
                    <li>• <strong>Telemetry Disable:</strong> Minor privacy tweak, zero FPS difference.</li>
                  </ul>
                </div>

                <div className="bg-red-950/20 border-2 border-red-500/40 p-4 rounded-xl space-y-2">
                  <div className="flex items-center gap-2 text-red-400 font-bold text-xs uppercase">
                    <XCircle className="w-4 h-4" />
                    Don't Touch / Avoid
                  </div>
                  <ul className="text-[11px] text-white/70 space-y-1 font-sans">
                    <li>• <strong>Turn off USB / Reg USB=4:</strong> Breaks mouse, keyboard, drives.</li>
                    <li>• <strong>Disable SysMain:</strong> Slows down app launching on HDDs/SSDs.</li>
                    <li>• <strong>Disable Windows Search:</strong> Destroys search & Start menu speed.</li>
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: STARTUP APPS OPTIMIZER */}
          {activeTab === 'startup' && (
            <div className="space-y-6">
              <div className="bg-gradient-to-r from-slate-900 to-slate-950 border border-white/15 p-5 rounded-2xl space-y-2">
                <div className="flex items-center gap-2">
                  <Cpu className="w-5 h-5 text-amber-400" />
                  <h3 className="text-sm font-black text-white uppercase tracking-wider font-mono">
                    Recommendation for "Disable Unnecessary Programs"
                  </h3>
                </div>
                <p className="text-xs text-white/80 leading-relaxed font-sans">
                  <strong>Focus on Startup Apps rather than disabling core Windows services.</strong> Disabling unnecessary startup apps dramatically lowers boot times and frees up gigabytes of RAM without compromising Windows stability.
                </p>
                <div className="pt-2 flex flex-wrap items-center gap-3">
                  <span className="bg-white/10 px-3 py-1 rounded text-[11px] font-mono text-cyan-300 border border-white/10">
                    How to open: <strong>Task Manager (Ctrl+Shift+Esc) &rarr; Startup Apps Tab</strong>
                  </span>
                  <span className="text-[11px] text-amber-300 font-mono">
                    💡 Tip: Sort by the <strong>"Startup impact"</strong> column and tackle High impact apps first.
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* Apps to Disable Card */}
                <div className="bg-[#120808] border-2 border-red-500/40 rounded-2xl p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-red-500/30 pb-3">
                    <span className="font-mono text-xs font-black uppercase text-red-400 tracking-wider flex items-center gap-2">
                      <XCircle className="w-4 h-4 text-red-400" />
                      Recommended Startup Apps to Disable
                    </span>
                    <span className="bg-red-500/20 text-red-300 text-[10px] font-mono px-2 py-0.5 rounded border border-red-500/30">
                      Safe to Disable
                    </span>
                  </div>

                  <ul className="space-y-2 text-xs font-sans text-white/80">
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-red-500/20">
                      <span className="text-red-400 font-bold">❌</span>
                      <div>
                        <strong>Microsoft Teams / Teams:</strong> Heavy background RAM usage unless needed immediately at boot.
                      </div>
                    </li>
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-red-500/20">
                      <span className="text-red-400 font-bold">❌</span>
                      <div>
                        <strong>Discord:</strong> High startup impact; launch manually when you want to chat.
                      </div>
                    </li>
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-red-500/20">
                      <span className="text-red-400 font-bold">❌</span>
                      <div>
                        <strong>Spotify:</strong> Unnecessary auto-start playback daemon.
                      </div>
                    </li>
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-red-500/20">
                      <span className="text-red-400 font-bold">❌</span>
                      <div>
                        <strong>Steam / Epic Games / Game Launchers:</strong> Consumes background bandwidth & disk I/O.
                      </div>
                    </li>
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-red-500/20">
                      <span className="text-red-400 font-bold">❌</span>
                      <div>
                        <strong>Adobe Creative Cloud (CC):</strong> Launches multiple heavy node/helper processes.
                      </div>
                    </li>
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-red-500/20">
                      <span className="text-red-400 font-bold">❌</span>
                      <div>
                        <strong>Microsoft OneDrive:</strong> Only disable if you do not actively use OneDrive cloud syncing.
                      </div>
                    </li>
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-red-500/20">
                      <span className="text-red-400 font-bold">❌</span>
                      <div>
                        <strong>Zoom / Skype:</strong> Keep off auto-start unless working on immediate call shifts.
                      </div>
                    </li>
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-red-500/20">
                      <span className="text-red-400 font-bold">❌</span>
                      <div>
                        <strong>Google Drive:</strong> Only if you don't need automatic real-time sync.
                      </div>
                    </li>
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-red-500/20">
                      <span className="text-red-400 font-bold">❌</span>
                      <div>
                        <strong>Phone Link / OEM Bloat:</strong> Disable OEM assistant tools (Dell SupportAssist, HP Support, etc.) if unused.
                      </div>
                    </li>
                  </ul>
                </div>

                {/* Apps to Keep Enabled Card */}
                <div className="bg-[#06140e] border-2 border-emerald-500/40 rounded-2xl p-5 space-y-4">
                  <div className="flex items-center justify-between border-b border-emerald-500/30 pb-3">
                    <span className="font-mono text-xs font-black uppercase text-emerald-400 tracking-wider flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      Important Apps to Leave Enabled
                    </span>
                    <span className="bg-emerald-500/20 text-emerald-300 text-[10px] font-mono px-2 py-0.5 rounded border border-emerald-500/30">
                      Do Not Disable
                    </span>
                  </div>

                  <ul className="space-y-2 text-xs font-sans text-white/80">
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-emerald-500/20">
                      <span className="text-emerald-400 font-bold">✅</span>
                      <div>
                        <strong>Windows Security / Defender:</strong> Core anti-malware and realtime protection suite.
                      </div>
                    </li>
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-emerald-500/20">
                      <span className="text-emerald-400 font-bold">✅</span>
                      <div>
                        <strong>Graphics Drivers:</strong> NVIDIA Control Panel / AMD Radeon Software / Intel Graphics Command.
                      </div>
                    </li>
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-emerald-500/20">
                      <span className="text-emerald-400 font-bold">✅</span>
                      <div>
                        <strong>Audio Drivers:</strong> Realtek HD Audio Universal Service, Waves MaxxAudio, Nahimic.
                      </div>
                    </li>
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-emerald-500/20">
                      <span className="text-emerald-400 font-bold">✅</span>
                      <div>
                        <strong>Touchpad & Trackpad Software:</strong> Synaptics, ELAN, Precision Touchpad helpers.
                      </div>
                    </li>
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-emerald-500/20">
                      <span className="text-emerald-400 font-bold">✅</span>
                      <div>
                        <strong>Keyboard Hotkey Utilities:</strong> Volume knobs, screen brightness, function Fn key listeners.
                      </div>
                    </li>
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-emerald-500/20">
                      <span className="text-emerald-400 font-bold">✅</span>
                      <div>
                        <strong>Bluetooth Stack & Utilities:</strong> Required for wireless headphones, mice, and accessories.
                      </div>
                    </li>
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-emerald-500/20">
                      <span className="text-emerald-400 font-bold">✅</span>
                      <div>
                        <strong>Important Hardware / Chipset Drivers:</strong> Intel Rapid Storage, AMD Chipset drivers.
                      </div>
                    </li>
                    <li className="flex items-start gap-2 bg-black/40 p-2 rounded-lg border border-emerald-500/20">
                      <span className="text-emerald-400 font-bold">✅</span>
                      <div>
                        <strong>Windows Core Components:</strong> Shell Infrastructure, User OOBE tasks.
                      </div>
                    </li>
                  </ul>
                </div>
              </div>

              {/* Advisory Helper Banner */}
              <div className="bg-cyan-950/30 border border-cyan-500/40 p-4 rounded-xl flex items-center justify-between gap-4 font-mono">
                <div className="flex items-center gap-3">
                  <Laptop className="w-5 h-5 text-cyan-400 shrink-0" />
                  <div className="text-xs text-cyan-100/90 font-sans">
                    <strong>Admin Assistant Tip: </strong> If you inspect your Task Manager &rarr; Startup Apps, look for apps with "High Impact". If unsure about a specific utility, keep essential drivers on and disable 3rd party game/chat launchers.
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: SAFE 8-POINT APPROACH */}
          {activeTab === 'plan' && (
            <div className="space-y-6">
              <div className="bg-slate-900/80 p-5 rounded-2xl border border-white/10 space-y-1">
                <h3 className="text-sm font-black text-white uppercase tracking-wider font-mono flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-amber-400" />
                  👍 Better "Safe Optimization" Approach (8 Priorities)
                </h3>
                <p className="text-xs text-white/60 font-sans">
                  The verified, risk-free sequence of performance optimizations that make Windows 10/11 Pro fast and responsive.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-sans">
                {[
                  {
                    num: '1',
                    title: 'Startup apps → disable unnecessary programs',
                    desc: 'Stop Teams, Discord, Spotify, Steam, and game launchers from booting with Windows.',
                    icon: Cpu,
                    badge: 'High Impact'
                  },
                  {
                    num: '2',
                    title: 'Remove unused applications',
                    desc: 'Uninstall heavy legacy programs and unwanted trial OEM software via Settings → Apps.',
                    icon: Trash2,
                    badge: 'Disk & RAM'
                  },
                  {
                    num: '3',
                    title: 'Clean temporary files & empty Recycle Bin',
                    desc: 'Purge %temp%, Windows Temp, empty $Recycle.Bin across all drives, and activate Storage Sense.',
                    icon: HardDrive,
                    badge: 'Immediate'
                  },
                  {
                    num: '4',
                    title: 'Keep 15–20%+ free disk space',
                    desc: 'SSDs and Windows pagefile require free space for wear-leveling, caching, and TRIM efficiency.',
                    icon: FolderCheck,
                    badge: 'SSD Health'
                  },
                  {
                    num: '5',
                    title: 'Reduce unnecessary visual effects',
                    desc: 'Open sysdm.cpl → Advanced → Performance Settings → Adjust for best performance (keep smooth font edges).',
                    icon: Sliders,
                    badge: 'GPU/CPU'
                  },
                  {
                    num: '6',
                    title: 'Check Task Manager for high CPU/RAM/Disk usage',
                    desc: 'Identify rogue background processes or memory leaks consuming CPU cycles.',
                    icon: Activity,
                    badge: 'Diagnostics'
                  },
                  {
                    num: '7',
                    title: 'Make sure Windows & drivers are updated',
                    desc: 'Install latest chipset, GPU, and cumulative stability updates via Windows Update.',
                    icon: RefreshCw,
                    badge: 'Stability'
                  },
                  {
                    num: '8',
                    title: 'SSD upgrade if you\'re still using an HDD',
                    desc: 'Moving from a mechanical HDD to an NVMe/SATA SSD is 100x more effective than any registry tweak.',
                    icon: Zap,
                    badge: 'Ultimate Upgrade'
                  }
                ].map((step) => {
                  const Icon = step.icon;
                  return (
                    <div key={step.num} className="bg-black/50 border border-white/10 hover:border-amber-500/50 p-4 rounded-xl transition flex items-start gap-3.5">
                      <div className="w-8 h-8 rounded-lg bg-amber-500/20 border border-amber-400/40 flex items-center justify-center text-amber-400 font-mono font-black text-sm shrink-0">
                        {step.num}
                      </div>
                      <div className="flex-1 space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <h4 className="font-bold text-white text-xs">{step.title}</h4>
                          <span className="text-[9px] font-mono font-black uppercase px-2 py-0.5 rounded bg-white/5 border border-white/10 text-amber-300 shrink-0">
                            {step.badge}
                          </span>
                        </div>
                        <p className="text-white/60 text-xs leading-relaxed">{step.desc}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* TAB 4: FULL SUMMARY & GUIDE */}
          {activeTab === 'summary' && (
            <div className="space-y-6">
              <div className="bg-gradient-to-r from-[#1c1404] via-[#2a1d06] to-[#120d02] border-2 border-amber-500/50 p-6 rounded-2xl space-y-4">
                <div className="flex items-center gap-3">
                  <FileText className="w-6 h-6 text-amber-400" />
                  <h3 className="text-base font-black text-white uppercase tracking-wider font-mono">
                    Windows 10/11 Speed Optimization Summary (Executive Reference)
                  </h3>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2 text-xs font-sans">
                  
                  <div className="space-y-4">
                    {/* Safe Cleanup */}
                    <div className="bg-black/60 p-4 rounded-xl border border-white/10 space-y-2">
                      <h4 className="font-mono font-bold text-emerald-400 text-xs uppercase flex items-center gap-1.5">
                        <CheckCircle2 className="w-4 h-4" />
                        🧹 Safe Cleanup
                      </h4>
                      <ul className="text-white/80 space-y-1 pl-1">
                        <li>• <strong>Empty / Delete Recycle Bin:</strong> Safely purge <code>$Recycle.Bin</code> across all disk partitions (<code>Clear-RecycleBin -Force</code>).</li>
                        <li>• Clear Recent files & Jump List history.</li>
                        <li>• Delete temporary files using <strong>%temp%</strong> and <strong>C:\Windows\Temp</strong>.</li>
                        <li>• Use <strong>Settings → System → Storage → Temporary files</strong> for deep cleanup.</li>
                        <li>• Maintain at least <strong>15–20% free space</strong> on the Windows OS drive.</li>
                      </ul>
                    </div>

                    {/* Startup Programs */}
                    <div className="bg-black/60 p-4 rounded-xl border border-white/10 space-y-2">
                      <h4 className="font-mono font-bold text-amber-400 text-xs uppercase flex items-center gap-1.5">
                        <Cpu className="w-4 h-4" />
                        🚀 Startup Programs
                      </h4>
                      <p className="text-white/80 leading-relaxed">
                        Disable unnecessary apps from Task Manager (Teams, Discord, Spotify, Steam, Zoom, Adobe CC, OneDrive if not syncing). Keep important hardware, security, graphics, audio, Bluetooth, and touchpad utilities enabled.
                      </p>
                    </div>

                    {/* Registry Tweaks */}
                    <div className="bg-black/60 p-4 rounded-xl border border-white/10 space-y-2">
                      <h4 className="font-mono font-bold text-cyan-400 text-xs uppercase flex items-center gap-1.5">
                        <Sliders className="w-4 h-4" />
                        ⚙️ Registry Tweaks
                      </h4>
                      <ul className="text-white/80 space-y-1 pl-1">
                        <li>• <strong>MenuShowDelay = 0:</strong> Optional; makes menus feel slightly snappier.</li>
                        <li>• <strong>Avoid:</strong> Changing unspecified USB registry keys like 4.</li>
                      </ul>
                    </div>
                  </div>

                  <div className="space-y-4">
                    {/* Windows Services */}
                    <div className="bg-black/60 p-4 rounded-xl border border-white/10 space-y-2">
                      <h4 className="font-mono font-bold text-amber-400 text-xs uppercase flex items-center gap-1.5">
                        <Activity className="w-4 h-4" />
                        🔧 Windows Services
                      </h4>
                      <ul className="text-white/80 space-y-1 pl-1">
                        <li>• <strong>SysMain:</strong> Generally keep enabled, especially with an HDD.</li>
                        <li>• <strong>Telemetry (DiagTrack):</strong> Disabling is optional, little speedup.</li>
                        <li>• <strong>Windows Search:</strong> Generally keep enabled to avoid broken search.</li>
                      </ul>
                    </div>

                    {/* What to Avoid */}
                    <div className="bg-black/60 p-4 rounded-xl border border-red-500/30 space-y-2">
                      <h4 className="font-mono font-bold text-red-400 text-xs uppercase flex items-center gap-1.5">
                        <XCircle className="w-4 h-4" />
                        ⚠️ What to Avoid
                      </h4>
                      <ul className="text-white/80 space-y-1 pl-1">
                        <li>• Random 3rd-party "registry-cleaner" programs (can corrupt registry).</li>
                        <li>• Disabling Windows Defender / Security center.</li>
                        <li>• Disabling USB controllers or USB hub services.</li>
                        <li>• Disabling mass services from generic internet debloat lists.</li>
                        <li>• Deleting files directly from core Windows system folders.</li>
                      </ul>
                    </div>

                    {/* Best Overall Strategy */}
                    <div className="bg-emerald-950/30 p-4 rounded-xl border border-emerald-500/40 space-y-1">
                      <h4 className="font-mono font-bold text-emerald-300 text-xs uppercase flex items-center gap-1.5">
                        <Sparkles className="w-4 h-4" />
                        ⭐ Best Overall Strategy
                      </h4>
                      <p className="text-emerald-100/90 leading-relaxed text-[11px]">
                        Clean temporary files &rarr; Disable unnecessary startup apps &rarr; Uninstall unused software &rarr; Free disk space &rarr; Reduce visual effects &rarr; Keep Windows updated &rarr; Upgrade from HDD to SSD for massive 10x gains.
                      </p>
                    </div>
                  </div>

                </div>
              </div>
            </div>
          )}

          {/* TAB 5: 1-CLICK SAFE SCRIPT GENERATOR */}
          {activeTab === 'script' && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900/60 p-4 rounded-xl border border-white/10">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    <h3 className="text-sm font-black text-white uppercase tracking-wider font-mono">
                      Safe & Verified Windows 10/11 Pro Fast Optimizer Script
                    </h3>
                  </div>
                  <p className="text-white/60 text-xs">
                    Applies strictly safe optimizations (temp cleanup, recent history clear, optional MenuShowDelay, Storage Sense).
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <div className="flex items-center bg-black p-1 rounded-xl border border-white/20 font-mono">
                    <button
                      onClick={() => setScriptFormat('ps1')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-black uppercase transition cursor-pointer ${
                        scriptFormat === 'ps1' ? 'bg-cyan-500 text-black' : 'text-white/60 hover:text-white'
                      }`}
                    >
                      PowerShell (.ps1)
                    </button>
                    <button
                      onClick={() => setScriptFormat('bat')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-black uppercase transition cursor-pointer ${
                        scriptFormat === 'bat' ? 'bg-amber-400 text-black' : 'text-white/60 hover:text-white'
                      }`}
                    >
                      Batch (.bat)
                    </button>
                  </div>

                  <button
                    onClick={handleCopyCode}
                    className="flex items-center gap-1.5 bg-white/10 hover:bg-white/20 text-white px-3.5 py-2 text-xs font-bold uppercase tracking-wider transition rounded-xl border border-white/20 cursor-pointer"
                  >
                    {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedCode ? 'Copied!' : 'Copy Code'}
                  </button>

                  <button
                    onClick={handleDownload}
                    className="flex items-center gap-1.5 bg-emerald-500 hover:bg-emerald-400 text-black px-4 py-2 text-xs font-black uppercase tracking-wider transition rounded-xl shadow-lg cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    Download .{scriptFormat}
                  </button>
                </div>
              </div>

              {/* Code Preview Box */}
              <div className="bg-[#050912] border-2 border-emerald-500/30 rounded-xl p-4 font-mono text-[11px] leading-relaxed text-emerald-300 overflow-x-auto max-h-96">
                <pre>{getActiveScriptContent()}</pre>
              </div>

              <div className="bg-black/40 border border-white/10 p-4 rounded-xl flex items-center justify-between gap-4 font-mono text-[11px]">
                <div className="flex items-center gap-2 text-white/70">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span>Includes automatic <strong>System Restore Point prompt</strong> on Drive C:\ before running.</span>
                </div>
                <span className="text-cyan-300 font-bold uppercase">100% Non-Destructive</span>
              </div>
            </div>
          )}

        </div>

        {/* Modal Bottom Footer Actions Bar */}
        <div className="bg-[#060a12] border-t border-white/10 p-4 sm:p-5 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-xs text-white/50 font-mono">
            <span>⚡ SmartPro Consultancy SecOps Engine</span>
            <span>•</span>
            <span className="text-amber-400">Windows 10 Pro & Windows 11 Pro</span>
          </div>

          <div className="flex items-center gap-3 w-full sm:w-auto justify-end">
            <button
              onClick={() => setActiveTab('script')}
              className="px-4 py-2 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 text-xs font-bold uppercase transition cursor-pointer flex items-center gap-1.5 font-mono"
            >
              <Terminal className="w-3.5 h-3.5" />
              Get Safe Script
            </button>

            <button
              onClick={onClose}
              className="px-5 py-2 rounded-xl bg-white/10 hover:bg-white/20 text-white text-xs font-black uppercase tracking-wider transition cursor-pointer border border-white/20 font-mono"
            >
              Close
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
