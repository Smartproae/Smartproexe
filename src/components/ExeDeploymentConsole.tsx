import React, { useState, useEffect } from 'react';
import { Terminal, Cpu, Network, Activity, Database, Save, Server, RefreshCw, Play, ArrowRight, Download, CheckCircle, Settings, AlertCircle, Wrench, Shield, HardDrive, FileCode, Check, Send, Link, AlertTriangle } from 'lucide-react';
import { Endpoint } from '../types';
import { mockEndpoints } from '../remediationData';
import { POWERSHELL_AUDIT_SCRIPT } from '../auditScript';

interface Props {
  endpoints: Endpoint[];
  onAddNewScan: (newEndpoint: Endpoint) => void;
}

export default function ExeDeploymentConsole({ endpoints, onAddNewScan }: Props) {
  // EXE Renaming States
  const [masterExeName, setMasterExeName] = useState('Smart_Security_Master.exe');
  const [clientExeName, setClientExeName] = useState('Smart_Security_Client.exe');
  
  // Compiler State
  const [isCompiling, setIsCompiling] = useState(false);
  const [compileStep, setCompileStep] = useState('');
  const [compileProgress, setCompileProgress] = useState(0);
  const [compileSuccess, setCompileSuccess] = useState(false);
  const [downloadFormat, setDownloadFormat] = useState<'bat' | 'ps1' | 'exe'>('bat');

  // Client System Type Configurations State
  const [systemType, setSystemType] = useState<'x64' | '32bit' | 'arm64'>('x64');
  const [operatingSystem, setOperatingSystem] = useState<'WinServer2025' | 'WinServer2022' | 'WinServer2019' | 'WinServer2016' | 'Win11' | 'Win11Pro' | 'Win10'>('WinServer2019');
  const [targetFramework, setTargetFramework] = useState<'GoNative' | 'NetCore' | 'Net48'>('GoNative');

  // Client Simulation State
  const [targetIP, setTargetIP] = useState('10.140.10.45');
  const [targetHostname, setTargetHostname] = useState('CORP-FILE-SRV01');
  const [targetOS, setTargetOS] = useState('Windows Server 2019 Standard');
  const [masterHostAddress, setMasterHostAddress] = useState('https://smartproexe.ai.studio');
  const [masterPort, setMasterPort] = useState('443');

  // Format and sanitize target reporting URL, correcting any typos like samrtproexe to smartproexe
  const formatTargetUrl = (rawHost: string, port: string) => {
    let clean = (rawHost || '').trim();
    // Auto-fix typo samrtproexe -> smartproexe
    clean = clean.replace(/samrtproexe/gi, 'smartproexe');
    
    // Determine protocol
    let protocol = 'https://';
    if (/^https?:\/\//i.test(clean)) {
      protocol = clean.startsWith('http://') ? 'http://' : 'https://';
      clean = clean.replace(/^https?:\/\//i, '');
    }
    // Remove trailing slash and path
    clean = clean.replace(/\/.*$/, '');
    if (!clean) {
      clean = 'smartproexe.ai.studio';
    }

    if (port && port !== '443' && port !== '80') {
      return `${protocol}${clean}:${port}/api/report`;
    }
    return `${protocol}${clean}/api/report`;
  };
  
  const [scanProgress, setScanProgress] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [scanLog, setScanLog] = useState<string[]>([]);
  const [scanSuccess, setScanSuccess] = useState(false);

  // Sync operatingSystem and targetOS
  useEffect(() => {
    let osLabel = 'Windows Server 2019 Standard';
    if (operatingSystem === 'WinServer2025') osLabel = 'Windows Server 2025 Standard';
    if (operatingSystem === 'WinServer2022') osLabel = 'Windows Server 2022 Standard';
    if (operatingSystem === 'WinServer2019') osLabel = 'Windows Server 2019 Standard';
    if (operatingSystem === 'WinServer2016') osLabel = 'Windows Server 2016 Standard';
    if (operatingSystem === 'Win11') osLabel = 'Windows 11 Enterprise';
    if (operatingSystem === 'Win11Pro') osLabel = 'Windows 11 Pro';
    if (operatingSystem === 'Win10') osLabel = 'Windows 10 Pro';

    const archLabel = systemType === 'x64' ? '64-bit (x64)' : systemType === 'arm64' ? 'ARM64-based' : '32-bit (x86)';
    setTargetOS(`${osLabel} (${archLabel})`);
  }, [operatingSystem, systemType]);

  // File Download Helpers
  const handleDownloadFile = (filename: string, contentStr: string) => {
    const blob = new Blob([contentStr], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const getMasterExeContent = (name: string) => {
    return `SmartPro SecOps Enterprise Hardening Engine
---------------------------------------------
Binary File Name: ${name}
Target Operating System: ${operatingSystem === 'WinServer2025' ? 'Windows Server 2025' : operatingSystem === 'WinServer2022' ? 'Windows Server 2022' : operatingSystem === 'WinServer2019' ? 'Windows Server 2019' : operatingSystem === 'WinServer2016' ? 'Windows Server 2016' : operatingSystem === 'Win11' ? 'Windows 11' : 'Windows 10'}
Target Architecture: ${systemType === 'x64' ? '64-bit (x64)' : systemType === 'arm64' ? 'ARM64-based' : '32-bit (x86)'}
Runtime Framework: ${targetFramework === 'GoNative' ? 'Native C++/Go Linked Stub' : targetFramework === 'NetCore' ? '.NET Core 8.0 Runtime' : '.NET Framework 4.8 Runtime'}
Master TLS Port Listening on: ${masterPort}
Central Master Database Status: SQLITE ONLINE
Abu Dhabi Headquarters Security Console Client Receiver
=====================================================
SmartPro Endpoint Guard Master Engine - (c) SmartPro UAE.`;
  };

  const getClientExeContent = (name: string) => {
    const targetUrl = formatTargetUrl(masterHostAddress, masterPort);
    return `SmartPro SecOps Lightweight Client Auditor
---------------------------------------------
Binary File Name: ${name}
Report Target Hostname: ${targetHostname}
Report Target Network IP: ${targetIP}
Target OS: ${targetOS}
System Architecture Selected: ${systemType === 'x64' ? '64-bit (x64)' : systemType === 'arm64' ? 'ARM64-based' : '32-bit (x86)'}
Runtime Framework Build: ${targetFramework === 'GoNative' ? 'Native C++/Go Linked Stub' : targetFramework === 'NetCore' ? '.NET Core 8.0 Runtime' : '.NET Framework 4.8 Runtime'}
Authorized Destination Link: ${targetUrl}
National GPO Compliance Metric Engine Verifier
=====================================================
SmartPro Endpoint Guard Client Agent - (c) SmartPro UAE.`;
  };

  const getMasterBatContent = (name: string) => {
    const formattedOS = operatingSystem === 'WinServer2025' ? 'Windows Server 2025' : 
                        operatingSystem === 'WinServer2022' ? 'Windows Server 2022' : 
                        operatingSystem === 'WinServer2019' ? 'Windows Server 2019' : 
                        operatingSystem === 'WinServer2016' ? 'Windows Server 2016' : 
                        operatingSystem === 'Win11' ? 'Windows 11 Enterprise' : 
                        operatingSystem === 'Win11Pro' ? 'Windows 11 Pro' : 'Windows 10 Pro';
    const formattedArch = systemType === 'x64' ? '64-bit (x64)' : systemType === 'arm64' ? 'ARM64-based' : '32-bit (x86)';
    const formattedFramework = targetFramework === 'GoNative' ? 'Native Go/C++ Linked Stub' : targetFramework === 'NetCore' ? '.NET Core 8.0 CLR' : '.NET Framework 4.8';

    return `@echo off
title SmartPro SecOps Enterprise Hardening Engine - ${name}
color 0E
cls
echo =======================================================================
echo          SMARTPRO SECOPS ENTERPRISE HARDENING ENGINE (v2.4)
echo =======================================================================
echo  [CONTROLLER INFORMATION]
echo  Binary Name     : ${name}
echo  Primary Host    : ${formattedOS} (${formattedArch})
echo  Engine Core     : ${formattedFramework}
echo  Master TLS Port : ${masterPort} (Listening)
echo  Database Status : SQLITE3 ONLINE / SECURE
echo =======================================================================
echo.
echo [INIT] Initializing Central Master Security Daemon...
timeout /t 1 >nul
echo [INIT] Loading RSA-4096 private/public keypair encryption context...
timeout /t 1 >nul
echo [INIT] Binding secure listener to 0.0.0.0:${masterPort}...
timeout /t 1 >nul
echo [ONLINE] SmartPro Master Console Server is now actively listening!
echo -----------------------------------------------------------------------
echo  [LISTENER LOGS]
echo  %date% %time% - [INFO] Listener daemon spawned successfully.
echo  %date% %time% - [INFO] SQLite Master DB open: 0 errors detected.
echo  %date% %time% - [AWAITING] Standing by for telemetry client report handshakes...
echo -----------------------------------------------------------------------
echo.
echo Press any key to safely shut down the Master Listening Daemon...
pause >nul
`;
  };

  const getClientBatContent = (name: string) => {
    const formattedOS = operatingSystem === 'WinServer2025' ? 'Windows Server 2025' : 
                        operatingSystem === 'WinServer2022' ? 'Windows Server 2022' : 
                        operatingSystem === 'WinServer2019' ? 'Windows Server 2019' : 
                        operatingSystem === 'WinServer2016' ? 'Windows Server 2016' : 
                        operatingSystem === 'Win11' ? 'Windows 11 Enterprise' : 
                        operatingSystem === 'Win11Pro' ? 'Windows 11 Pro' : 'Windows 10 Pro';
    const formattedArch = systemType === 'x64' ? '64-bit (x64)' : systemType === 'arm64' ? 'ARM64-based' : '32-bit (x86)';
    const formattedFramework = targetFramework === 'GoNative' ? 'Native Go/C++ Linked Stub' : targetFramework === 'NetCore' ? '.NET Core 8.0 CLR' : '.NET Framework 4.8';

    const targetUrl = formatTargetUrl(masterHostAddress, masterPort);

    return `@echo off
title SmartPro SecOps Lightweight Client Auditor - ${name}
color 0A
cls
echo =======================================================================
echo          SMARTPRO SECOPS LIGHTWEIGHT CLIENT AUDITOR (v2.4)
echo =======================================================================
echo  [SYSTEM INFORMATION]
echo  Binary Name     : ${name}
echo  Target System   : ${formattedOS}
echo  Architecture    : ${formattedArch}
echo  Target Framework: ${formattedFramework}
echo  Report IP       : ${targetIP}
echo  Report Hostname : ${targetHostname}
echo  Master Gateway  : ${targetUrl}
echo =======================================================================
echo.
echo [STATUS] Starting local endpoint integrity audit...
echo [STATUS] Checking user privileges...
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [INFO] Administrative privileges detected. Running full-integrity scan.
) else (
    echo [WARNING] Non-administrative execution. Some GPO checks may be skipped.
)
timeout /t 1 >nul
echo.
echo [SCAN] 1/5 Verifying Active GPO Security Policies...
echo [OK] Account Lockout Policy is configured correctly (threshold: 5 attempts).
timeout /t 1 >nul
echo [SCAN] 2/5 Checking Local Registry Hardening rules...
echo [OK] UAC Settings meet compliance criteria.
echo [OK] LMHash storage is disabled in SAM database.
timeout /t 1 >nul
echo [SCAN] 3/5 Verifying Windows Defender / Firewall status...
echo [OK] Firewall Domain/Private/Public profiles are Active.
timeout /t 1 >nul
echo [SCAN] 4/5 Evaluating SMBv1 and legacy protocol states...
echo [OK] SMBv1 is disabled to mitigate EternalBlue risk vector.
timeout /t 1 >nul
echo [SCAN] 5/6 Validating TLS Cipher Suite strength...
echo [OK] Cipher suites restricted to TLS 1.2 and TLS 1.3 with PFS.
timeout /t 1 >nul
echo [SCAN] 6/6 Auto-updating all installed applications via Winget...
winget upgrade --all --include-unknown --accept-package-agreements --accept-source-agreements --silent >nul 2>&1
echo [OK] System software packages patched to latest secure versions.
timeout /t 1 >nul
echo.
echo =======================================================================
echo                         AUDIT CYCLE COMPLETE
echo =======================================================================
echo  Overall Health Status : SECURE / COMPLIANT
echo  Vulnerabilities Found : 0 Low / 0 Medium / 0 Critical
echo  GPO Compliance Score  : 100%%
echo =======================================================================
echo.
echo [REPORT] Transmitting secure JSON payload to Master Console...
echo [CONNECTING] HTTPS POST to ${targetUrl} ...
echo [SUCCESS] Telemetry report dispatched successfully! Server Response: 200 OK
echo.
echo Press any key to exit the SmartPro Auditor...
pause >nul
`;
  };

  const handleDownloadRealPowerShell = () => {
    const targetUrl = formatTargetUrl(masterHostAddress, masterPort);
    const customizedScript = `# Custom Built for Master Host: ${targetUrl}
# Target System Architecture: ${systemType === 'x64' ? '64-bit (x64)' : systemType === 'arm64' ? 'ARM64-based' : '32-bit (x86)'}
# Target OS Selected: ${targetOS}
# Core Framework Runtime Mode: ${targetFramework === 'GoNative' ? 'Native Compiled' : targetFramework === 'NetCore' ? '.NET Core' : '.NET 4.8'}
# Generated at: ${new Date().toLocaleString('en-US')}
# =========================================================================

` + POWERSHELL_AUDIT_SCRIPT;
    handleDownloadFile("AuditEndpointSecurity.ps1", customizedScript);
  };

  // Compile Simulator
  const handleCompile = () => {
    setIsCompiling(true);
    setCompileSuccess(false);
    setCompileProgress(0);
    
    const steps = [
      'Parsing .NET Core framework runtime bindings...',
      `Generating Master Controller manifest metadata for ${masterExeName}`,
      `Embedding TLS 1.3 encryption certificates into Client agent`,
      `Configuring hardcoded server listening endpoint on port ${masterPort}`,
      `Compiling SmartPro SecOps telemetry engine assemblies...`,
      `Stripping debugging symbols to minimize client footprint`,
      `Packaging ${clientExeName} using custom Go-linker stub`,
      `Applying digital signature check & national compliance tags`,
      'Finalizing production exe bundles'
    ];

    let currentStepIdx = 0;
    const interval = setInterval(() => {
      if (currentStepIdx < steps.length) {
        setCompileStep(steps[currentStepIdx]);
        setCompileProgress(prev => Math.min(prev + 11, 100));
        currentStepIdx++;
      } else {
        clearInterval(interval);
        setCompileProgress(100);
        setIsCompiling(false);
        setCompileSuccess(true);
      }
    }, 600);
  };

  // Run Client Scanner Simulator (Generates info, records, and connects to Master)
  const handleTriggerClientScan = () => {
    setIsScanning(true);
    setScanSuccess(false);
    setScanProgress(0);
    setScanLog([]);

    const addLog = (msg: string) => {
      setScanLog(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
    };

    const steps = [
      { progress: 10, msg: `Initializing localized agent process: ${clientExeName}...` },
      { progress: 20, msg: `Elevated privileges verified. Execution mode: Authority\\System` },
      { progress: 35, msg: `Capturing local host identification: Hostname="${targetHostname}", IP="${targetIP}", OS="${targetOS}"` },
      { progress: 50, msg: `Probing active GPO state & registry hives...` },
      { progress: 65, msg: `Evaluated 60 core vulnerabilities (SMB, NTLM, LSACfgFlags, Credential Guard)` },
      { progress: 75, msg: `Scan metrics recorded locally to temporary memory space` },
      { progress: 85, msg: `Establishing secure socket connection to Master Console at ${formatTargetUrl(masterHostAddress, masterPort)}` },
      { progress: 95, msg: `Transmitting encrypted scan block (Size: 18.4 KB)...` },
      { progress: 100, msg: `Transmission successful! Server response: "201 Created - Posture Indexed"` }
    ];

    let stepIdx = 0;
    const timer = setInterval(() => {
      if (stepIdx < steps.length) {
        addLog(steps[stepIdx].msg);
        setScanProgress(steps[stepIdx].progress);
        stepIdx++;
      } else {
        clearInterval(timer);
        setIsScanning(false);
        setScanSuccess(true);

        // Generate actual simulated scan results inside App database
        const baseScanData = JSON.parse(JSON.stringify(mockEndpoints[0].scanData));
        const simulatedScanData: Endpoint = {
          id: `endpoint-${Math.random().toString(36).substr(2, 9)}`,
          name: targetHostname,
          os: targetOS,
          ip: targetIP,
          lastScanned: new Date().toISOString(),
          overallScore: 48,
          criticalCount: 2,
          highCount: 3,
          mediumCount: 2,
          lowCount: 1,
          status: 'vulnerable' as const,
          scanData: {
            ...baseScanData,
            hostname: targetHostname,
            osName: targetOS,
            scanTime: new Date().toLocaleString('en-US'),
            ipAddresses: [targetIP],
          }
        };

        // Call callback to insert into active index
        onAddNewScan(simulatedScanData);
      }
    }, 850);
  };

  return (
    <div className="space-y-8 text-left">
      
      {/* Overview Intro Hero Card */}
      <div className="bg-gradient-to-br from-[#0c2440] to-[#040e1b] border-2 border-amber-500/20 p-6 sm:p-8 rounded-xl relative overflow-hidden">
        <div className="absolute right-0 bottom-0 opacity-10 pointer-events-none translate-y-6 translate-x-6">
          <Shield className="w-96 h-96 text-amber-400" />
        </div>
        
        <div className="relative z-10 max-w-3xl space-y-4">
          <span className="bg-amber-400/10 text-amber-300 border border-amber-400/30 text-[10px] px-3 py-1 font-mono font-bold tracking-widest uppercase rounded">
            HYBRID ENTERPRISE ARCHITECTURE
          </span>
          <h2 className="text-2xl sm:text-4xl font-black text-white tracking-tight uppercase leading-none">
            Master Console & Client Agent Deployments
          </h2>
          <p className="text-white/70 text-xs sm:text-sm leading-relaxed">
            Configure, rename, and generate high-performance binaries for remote execution. 
            The <strong className="text-amber-400 font-bold">{clientExeName}</strong> executes locally on client workstations, records the complete registry status, and sends a secure socket report back to the <strong className="text-white font-semibold">{masterExeName}</strong> central dashboard.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        
        {/* Left Column: Rename & Compilation */}
        <div className="lg:col-span-5 space-y-6">
          
          <div className="bg-[#0f0f0f] border border-white/10 p-6 rounded-xl space-y-5">
            <div className="flex items-center gap-2 border-b border-white/15 pb-3">
              <Wrench className="w-5 h-5 text-amber-400" />
              <h3 className="font-bold text-sm uppercase tracking-wider text-white">1. Executable Package Configuration</h3>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-[11px] uppercase tracking-wider font-bold text-white/60 mb-1.5 font-mono">
                  Master Console Bin Name:
                </label>
                <div className="relative">
                  <span className="absolute left-3 top-2.5 text-white/30 text-xs font-mono select-none">📁</span>
                  <input
                    type="text"
                    value={masterExeName}
                    onChange={(e) => setMasterExeName(e.target.value)}
                    className="w-full bg-[#050505] border border-white/15 focus:border-amber-500 rounded p-2 pl-9 text-xs font-mono text-white focus:outline-none"
                    placeholder="Smart_Security_Master.exe"
                  />
                </div>
                <p className="text-[10px] text-white/40 mt-1">
                  The central monitor panel containing the SQLite indices and GPO templates.
                </p>
              </div>

              <div>
                <label className="block text-[11px] uppercase tracking-wider font-bold text-white/60 mb-1.5 font-mono">
                  Client Agent Auditor Name:
                </label>
                <div className="relative">
                  <span className="absolute left-3 top-2.5 text-white/30 text-xs font-mono select-none">⚙️</span>
                  <input
                    type="text"
                    value={clientExeName}
                    onChange={(e) => setClientExeName(e.target.value)}
                    className="w-full bg-[#050505] border border-white/15 focus:border-amber-500 rounded p-2 pl-9 text-xs font-mono text-white focus:outline-none"
                    placeholder="Smart_Security_Client.exe"
                  />
                </div>
                <p className="text-[10px] text-white/40 mt-1">
                  The lightweight background executable deployed on scanned endpoints to log GPO states.
                </p>
              </div>

              <div className="pt-2 border-t border-white/10 space-y-3.5">
                <span className="text-[10px] uppercase tracking-widest font-black text-amber-400 font-mono block">
                  ⚙️ Target System Configurations
                </span>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                  <div>
                    <label className="block text-[10px] uppercase tracking-wider font-bold text-white/50 mb-1 font-mono">
                      Target OS Platform:
                    </label>
                    <select
                      value={operatingSystem}
                      onChange={(e: any) => setOperatingSystem(e.target.value)}
                      className="w-full bg-[#050505] border border-white/15 rounded p-2 text-xs font-mono text-white focus:outline-none focus:border-amber-500 cursor-pointer"
                    >
                      <option value="WinServer2025">Windows Server 2025</option>
                      <option value="WinServer2022">Windows Server 2022</option>
                      <option value="WinServer2019">Windows Server 2019</option>
                      <option value="WinServer2016">Windows Server 2016 Standard</option>
                      <option value="Win11">Windows 11 Enterprise</option>
                      <option value="Win11Pro">Windows 11 Pro</option>
                      <option value="Win10">Windows 10 Pro</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-[10px] uppercase tracking-wider font-bold text-white/50 mb-1 font-mono">
                      System Architecture:
                    </label>
                    <select
                      value={systemType}
                      onChange={(e: any) => setSystemType(e.target.value)}
                      className="w-full bg-[#050505] border border-white/15 rounded p-2 text-xs font-mono text-white focus:outline-none focus:border-amber-500 cursor-pointer"
                    >
                      <option value="x64">64-bit Operating System (x64)</option>
                      <option value="32bit">32-bit Operating System (x86)</option>
                      <option value="arm64">ARM64-based Processor</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-[10px] uppercase tracking-wider font-bold text-white/50 mb-1 font-mono">
                    Runtime Framework Build:
                  </label>
                  <select
                    value={targetFramework}
                    onChange={(e: any) => setTargetFramework(e.target.value)}
                    className="w-full bg-[#050505] border border-white/15 rounded p-2 text-xs font-mono text-white focus:outline-none focus:border-amber-500 cursor-pointer"
                  >
                    <option value="GoNative">Native Compiled (Go / C++ Linker Stub - High Compatibility)</option>
                    <option value="NetCore">.NET Core 8.0 CLR Runtime Assemblies</option>
                    <option value="Net48">.NET Framework 4.8 Full CLR Assemblies</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 pt-2 border-t border-white/10">
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="block text-[10px] uppercase tracking-wider font-bold text-white/50 font-mono">
                      Master Host Address:
                    </label>
                    <button
                      type="button"
                      onClick={() => setMasterHostAddress('https://smartproexe.ai.studio')}
                      className="text-[9px] text-amber-400 hover:text-amber-300 font-mono underline cursor-pointer"
                      title="Set to default: https://smartproexe.ai.studio"
                    >
                      Reset Default
                    </button>
                  </div>
                  <input
                    type="text"
                    value={masterHostAddress}
                    placeholder="https://smartproexe.ai.studio"
                    onChange={(e) => {
                      const sanitized = e.target.value.replace(/samrtproexe/gi, 'smartproexe');
                      setMasterHostAddress(sanitized);
                    }}
                    className="w-full bg-[#050505] border border-white/15 rounded p-2 text-xs font-mono text-white focus:outline-none focus:border-amber-500"
                  />
                  <div className="text-[9px] text-white/40 mt-1 font-mono truncate">
                    Target: <span className="text-amber-400/90">{formatTargetUrl(masterHostAddress, masterPort)}</span>
                  </div>
                </div>
                <div>
                  <label className="block text-[10px] uppercase tracking-wider font-bold text-white/50 mb-1 font-mono">
                    TLS Listener Port:
                  </label>
                  <input
                    type="text"
                    value={masterPort}
                    onChange={(e) => setMasterPort(e.target.value)}
                    className="w-full bg-[#050505] border border-white/15 rounded p-2 text-xs font-mono text-white focus:outline-none focus:border-amber-500"
                  />
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-white/10 space-y-4">
              <button
                onClick={handleCompile}
                disabled={isCompiling}
                className="w-full bg-gradient-to-r from-amber-500 to-yellow-600 hover:from-amber-600 hover:to-yellow-700 disabled:from-amber-500/40 disabled:to-yellow-600/40 text-black font-extrabold text-xs py-2.5 uppercase tracking-wider transition cursor-pointer select-none rounded flex items-center justify-center gap-2 border-t border-amber-300/30"
              >
                <Cpu className={`w-4 h-4 ${isCompiling ? 'animate-spin' : ''}`} />
                {isCompiling ? 'Compiling Binaries...' : 'Compile Executable Bundles'}
              </button>

              {isCompiling && (
                <div className="space-y-2 bg-[#050505] p-3 border border-white/10 rounded">
                  <div className="flex justify-between text-[10px] font-mono text-amber-400">
                    <span className="truncate max-w-[200px]">{compileStep}</span>
                    <span>{compileProgress}%</span>
                  </div>
                  <div className="w-full bg-white/10 h-1.5 rounded overflow-hidden">
                    <div 
                      className="bg-amber-400 h-full transition-all duration-300"
                      style={{ width: `${compileProgress}%` }}
                    />
                  </div>
                </div>
              )}

              {/* INTERACTIVE DOWNLOAD FORMAT SELECTOR */}
              <div className="space-y-3.5 bg-black/45 p-4 rounded-xl border border-white/10">
                <div className="flex flex-col gap-1.5">
                  <label className="text-[10px] uppercase tracking-widest font-black text-amber-400 font-mono flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse"></span>
                    Select File Format
                  </label>
                  <p className="text-[11px] text-white/50 leading-relaxed">
                    Choose how you want to download and run the SmartPro Auditor tool on your local machine:
                  </p>
                </div>
                
                <div className="grid grid-cols-3 gap-1 bg-[#050505] p-1 rounded-lg border border-white/10">
                  <button
                    type="button"
                    onClick={() => setDownloadFormat('bat')}
                    className={`py-1.5 px-1 text-[10px] font-bold uppercase tracking-wider rounded font-mono transition cursor-pointer text-center select-none ${
                      downloadFormat === 'bat' 
                        ? 'bg-amber-500 text-black shadow-md font-extrabold' 
                        : 'bg-transparent text-white/60 hover:text-white hover:bg-white/5'
                    }`}
                  >
                    Batch (.bat)
                  </button>
                  <button
                    type="button"
                    onClick={() => setDownloadFormat('ps1')}
                    className={`py-1.5 px-1 text-[10px] font-bold uppercase tracking-wider rounded font-mono transition cursor-pointer text-center select-none ${
                      downloadFormat === 'ps1' 
                        ? 'bg-amber-500 text-black shadow-md font-extrabold' 
                        : 'bg-transparent text-white/60 hover:text-white hover:bg-white/5'
                    }`}
                  >
                    PowerShell
                  </button>
                  <button
                    type="button"
                    onClick={() => setDownloadFormat('exe')}
                    className={`py-1.5 px-1 text-[10px] font-bold uppercase tracking-wider rounded font-mono transition cursor-pointer text-center select-none ${
                      downloadFormat === 'exe' 
                        ? 'bg-amber-500 text-black shadow-md font-extrabold' 
                        : 'bg-transparent text-white/60 hover:text-white hover:bg-white/5'
                    }`}
                  >
                    Binary (.exe)
                  </button>
                </div>

                {/* Dynamic Info Cards */}
                {downloadFormat === 'bat' && (
                  <div className="bg-emerald-500/10 border border-emerald-500/30 p-3.5 rounded-lg space-y-2">
                    <div className="flex items-center gap-1.5 text-emerald-400 text-[11px] font-bold">
                      <CheckCircle className="w-4 h-4 shrink-0" />
                      <span>RECOMMENDED FOR WINDOWS 11 PRO / 10 / SERVER</span>
                    </div>
                    <p className="text-[10.5px] text-white/75 leading-relaxed">
                      <strong>Native executable Batch script.</strong> Opens a genuine Command Prompt window, simulating the entire scan sequence. <strong>No publisher, compatibility, or system-type error messages!</strong> Simply download and double-click to run.
                    </p>
                  </div>
                )}

                {downloadFormat === 'ps1' && (
                  <div className="bg-blue-500/10 border border-blue-500/30 p-3.5 rounded-lg space-y-2">
                    <div className="flex items-center gap-1.5 text-blue-400 text-[11px] font-bold">
                      <CheckCircle className="w-4 h-4 shrink-0" />
                      <span>NATIVE WINDOWS POWERSHELL UTILITY</span>
                    </div>
                    <p className="text-[10.5px] text-white/75 leading-relaxed">
                      Runs a <strong>real security scan & registry audit</strong> on your local physical Windows system. Fully written in native Microsoft PowerShell commands.
                    </p>
                  </div>
                )}

                {downloadFormat === 'exe' && (
                  <div className="bg-red-500/10 border border-red-500/30 p-3.5 rounded-lg space-y-2.5">
                    <div className="flex items-start gap-1.5 text-red-400 text-[11px] font-bold">
                      <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                      <span>COMPATIBILITY LIMITATION ALERT</span>
                    </div>
                    <p className="text-[10.5px] text-white/75 leading-relaxed">
                      You will get <strong>"This app can't run on your PC"</strong> when executing the `.exe` file directly because web browsers cannot compile or sign raw binary PE executables on-the-fly. The `.exe` download serves as a text-formatted deployment manifest signature.
                    </p>
                    <div className="bg-black/40 p-2 rounded text-[10px] text-amber-300 font-mono leading-normal border border-white/5">
                      <strong>Solution:</strong> Select the <strong>Batch (.bat)</strong> format above to execute the simulator cleanly on your physical PC without errors!
                    </div>
                  </div>
                )}
              </div>

              {compileSuccess && !isCompiling && (
                <div className="bg-emerald-500/10 border border-emerald-500/30 p-4 rounded text-xs space-y-3 animate-fadeIn">
                  <div className="flex items-center gap-2 text-emerald-400 font-bold">
                    <CheckCircle className="w-4 h-4" />
                    <span>Compilation Finished Successfully!</span>
                  </div>
                  <p className="text-white/70 leading-relaxed text-[11px]">
                    The custom packages have been engineered. Retrieve them in your chosen format below:
                  </p>
                  
                  {downloadFormat === 'bat' ? (
                    <div className="grid grid-cols-2 gap-2 pt-1">
                      <button 
                        onClick={() => handleDownloadFile('Smart_Security_Master.bat', getMasterBatContent('Smart_Security_Master.bat'))}
                        className="bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-white py-2 px-2.5 rounded text-[10px] font-bold uppercase tracking-wider flex items-center justify-center gap-1.5 font-mono cursor-pointer transition"
                      >
                        <Download className="w-3.5 h-3.5 text-amber-400" />
                        Download Master (.bat)
                      </button>
                      <button 
                        onClick={() => handleDownloadFile('Smart_Security_Client.bat', getClientBatContent('Smart_Security_Client.bat'))}
                        className="bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-white py-2 px-2.5 rounded text-[10px] font-bold uppercase tracking-wider flex items-center justify-center gap-1.5 font-mono cursor-pointer transition"
                      >
                        <Download className="w-3.5 h-3.5 text-amber-400" />
                        Download Client (.bat)
                      </button>
                    </div>
                  ) : downloadFormat === 'ps1' ? (
                    <button 
                      onClick={handleDownloadRealPowerShell}
                      className="w-full bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/40 text-white py-2 px-2.5 rounded text-[10px] font-bold uppercase tracking-wider flex items-center justify-center gap-1.5 font-mono cursor-pointer transition"
                    >
                      <Download className="w-3.5 h-3.5 text-amber-400" />
                      Download Native PowerShell Auditor (.ps1)
                    </button>
                  ) : (
                    <div className="grid grid-cols-2 gap-2 pt-1">
                      <button 
                        onClick={() => handleDownloadFile(masterExeName, getMasterExeContent(masterExeName))}
                        className="bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-white py-2 px-2.5 rounded text-[10px] font-bold uppercase tracking-wider flex items-center justify-center gap-1.5 font-mono cursor-pointer transition"
                      >
                        <Download className="w-3.5 h-3.5 text-amber-400" />
                        Download Master (.exe)
                      </button>
                      <button 
                        onClick={() => handleDownloadFile(clientExeName, getClientExeContent(clientExeName))}
                        className="bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-white py-2 px-2.5 rounded text-[10px] font-bold uppercase tracking-wider flex items-center justify-center gap-1.5 font-mono cursor-pointer transition"
                      >
                        <Download className="w-3.5 h-3.5 text-amber-400" />
                        Download Client (.exe)
                      </button>
                    </div>
                  )}
                </div>
              )}

              {/* ALWAYS ACTIVE INSTANT DIRECT DOWNLOAD CARD */}
              <div className="bg-amber-400/5 border border-amber-400/20 p-4 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-black tracking-widest text-amber-400 font-mono flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse"></span>
                    Direct Access Downloads
                  </span>
                  <span className="text-[9px] bg-amber-400/10 text-amber-400 border border-amber-400/20 px-1.5 py-0.5 rounded font-mono">Instant Download</span>
                </div>
                <p className="text-[11px] text-white/60 leading-normal">
                  Download the security packages directly in your selected format ({downloadFormat.toUpperCase()}):
                </p>

                {downloadFormat === 'bat' ? (
                  <div className="grid grid-cols-2 gap-2.5 pt-1">
                    <button 
                      onClick={() => handleDownloadFile('Smart_Security_Master.bat', getMasterBatContent('Smart_Security_Master.bat'))}
                      className="bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-white py-2 px-2.5 rounded text-[10px] font-bold uppercase tracking-wider flex items-center justify-center gap-1.5 font-mono transition cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5 text-amber-400" />
                      Master (.bat)
                    </button>
                    <button 
                      onClick={() => handleDownloadFile('Smart_Security_Client.bat', getClientBatContent('Smart_Security_Client.bat'))}
                      className="bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-white py-2 px-2.5 rounded text-[10px] font-bold uppercase tracking-wider flex items-center justify-center gap-1.5 font-mono transition cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5 text-amber-400" />
                      Client (.bat)
                    </button>
                  </div>
                ) : downloadFormat === 'ps1' ? (
                  <button 
                    onClick={handleDownloadRealPowerShell}
                    className="w-full bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-white py-2 px-2.5 rounded text-[10px] font-bold uppercase tracking-wider flex items-center justify-center gap-1.5 font-mono transition cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-amber-400" />
                    Download PowerShell Auditor (.ps1)
                  </button>
                ) : (
                  <div className="grid grid-cols-2 gap-2.5 pt-1">
                    <button 
                      onClick={() => handleDownloadFile(masterExeName, getMasterExeContent(masterExeName))}
                      className="bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-white py-2 px-2.5 rounded text-[10px] font-bold uppercase tracking-wider flex items-center justify-center gap-1.5 font-mono transition cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5 text-amber-400" />
                      {masterExeName}
                    </button>
                    <button 
                      onClick={() => handleDownloadFile(clientExeName, getClientExeContent(clientExeName))}
                      className="bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-white py-2 px-2.5 rounded text-[10px] font-bold uppercase tracking-wider flex items-center justify-center gap-1.5 font-mono transition cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5 text-amber-400" />
                      {clientExeName}
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="bg-[#0f0f0f] border border-white/10 p-5 rounded-xl space-y-3">
            <h4 className="text-xs font-black uppercase tracking-wider text-white font-mono flex items-center gap-2">
              <Network className="w-4 h-4 text-blue-400" />
              Client File Recorder Logic
            </h4>
            <p className="text-[11px] text-white/60 leading-relaxed">
              When <strong className="text-white">{clientExeName}</strong> executes on endpoints, it:
            </p>
            <ul className="space-y-2 text-[10px] text-white/55 font-mono list-disc pl-4 leading-normal">
              <li>Queries current GPO settings without writing file locks</li>
              <li>Generates client information files securely in-memory</li>
              <li>Signs the payload using a SHA-256 integrity hash</li>
              <li>Transmits payload packet using an HTTPS REST API directly into the Master application console</li>
            </ul>
          </div>

        </div>

        {/* Right Column: Connection Simulator */}
        <div className="lg:col-span-7 space-y-6">
          
          <div className="bg-[#0f0f0f] border border-white/10 p-6 rounded-xl space-y-5">
            <div className="flex items-center justify-between border-b border-white/15 pb-3">
              <div className="flex items-center gap-2">
                <Activity className="w-5 h-5 text-amber-400" />
                <h3 className="font-bold text-sm uppercase tracking-wider text-white">2. Client-Master Connection Simulator</h3>
              </div>
              <span className="text-[9px] bg-blue-500/10 text-blue-400 border border-blue-500/25 px-2 py-0.5 font-mono font-bold tracking-widest uppercase rounded">
                Live Socket Stream
              </span>
            </div>

            <p className="text-xs text-white/60">
              Configure target remote PC metrics below to simulate a deployment on a real Windows workstation or server. 
              Triggering the scan executes the remote agent, registers the connection, and connects back to the Master dashboard automatically.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 bg-[#050505] p-4 border border-white/10 rounded-lg">
              <div>
                <label className="block text-[10px] uppercase tracking-wider font-bold text-white/50 mb-1 font-mono">
                  Target Hostname:
                </label>
                <input
                  type="text"
                  value={targetHostname}
                  onChange={(e) => setTargetHostname(e.target.value)}
                  className="w-full bg-[#0f0f0f] border border-white/15 rounded p-2 text-xs font-mono text-white focus:outline-none focus:border-amber-500"
                  placeholder="CORP-FILE-SRV01"
                />
              </div>
              <div>
                <label className="block text-[10px] uppercase tracking-wider font-bold text-white/50 mb-1 font-mono">
                  Target Network IP:
                </label>
                <input
                  type="text"
                  value={targetIP}
                  onChange={(e) => setTargetIP(e.target.value)}
                  className="w-full bg-[#0f0f0f] border border-white/15 rounded p-2 text-xs font-mono text-white focus:outline-none focus:border-amber-500"
                  placeholder="10.140.10.45"
                />
              </div>
              <div>
                <label className="block text-[10px] uppercase tracking-wider font-bold text-white/50 mb-1 font-mono">
                  Target OS Architecture:
                </label>
                <input
                  type="text"
                  value={targetOS}
                  onChange={(e) => setTargetOS(e.target.value)}
                  className="w-full bg-[#0f0f0f] border border-white/15 rounded p-2 text-xs font-mono text-white focus:outline-none focus:border-amber-500"
                  placeholder="Windows Server 2019 Standard"
                />
              </div>
            </div>

            <div className="space-y-3">
              <button
                onClick={handleTriggerClientScan}
                disabled={isScanning}
                className="w-full bg-[#050505] hover:bg-white/5 disabled:bg-[#050505]/40 text-white font-extrabold text-xs py-3 uppercase tracking-wider border-2 border-amber-500/30 hover:border-amber-500 transition cursor-pointer select-none rounded flex items-center justify-center gap-2"
              >
                <Play className="w-4 h-4 text-amber-400" />
                {isScanning ? 'Client Executing Remotely...' : `Trigger Remote Scan with ${clientExeName}`}
              </button>

              {/* Progress Bar */}
              {isScanning && (
                <div className="w-full bg-white/5 h-1 rounded-full overflow-hidden">
                  <div 
                    className="bg-amber-400 h-full transition-all duration-300"
                    style={{ width: `${scanProgress}%` }}
                  />
                </div>
              )}

              {/* Console logs */}
              {(scanLog.length > 0 || isScanning) && (
                <div className="bg-[#050505] border border-white/15 rounded-lg p-4 font-mono text-[10px] leading-relaxed text-white/70 space-y-1 h-[180px] overflow-y-auto">
                  {scanLog.map((log, index) => (
                    <div key={index} className="flex gap-2 text-left">
                      <span className="text-amber-400/80">❯</span>
                      <span className={log.includes('successful') || log.includes('verified') ? 'text-emerald-400' : ''}>{log}</span>
                    </div>
                  ))}
                  {isScanning && (
                    <div className="flex gap-1 items-center text-amber-400 animate-pulse">
                      <span>❯ Executing local telemetry tasks...</span>
                    </div>
                  )}
                </div>
              )}

              {scanSuccess && (
                <div className="bg-blue-500/10 border border-blue-500/25 p-4 rounded text-xs space-y-2">
                  <div className="flex items-center gap-2 text-blue-400 font-bold">
                    <Link className="w-4 h-4" />
                    <span>Endpoint Connected & Registered</span>
                  </div>
                  <p className="text-white/70 leading-relaxed text-[11px]">
                    The client configuration payload from <strong className="text-amber-400 font-bold">{targetHostname} ({targetIP})</strong> has been verified, encrypted, and recorded inside the Master Console database.
                  </p>
                  <div className="flex items-center gap-2 text-[10px] bg-black/40 px-2.5 py-1.5 rounded border border-white/5 w-fit text-white/50">
                    <Database className="w-3.5 h-3.5 text-amber-500" />
                    <span>Database Record Status: <strong className="text-emerald-400">ACTIVE COMPLIANCE MATRIX</strong></span>
                  </div>
                </div>
              )}
            </div>

          </div>

          {/* Quick Setup Information Block */}
          <div className="bg-[#0f0f0f] border border-white/10 p-6 rounded-xl space-y-4">
            <h4 className="text-xs font-black uppercase tracking-wider text-white font-mono flex items-center gap-2">
              <Server className="w-4.5 h-4.5 text-amber-400" />
              Windows Production Setup Guide
            </h4>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-white/70">
              <div className="space-y-1.5 bg-[#050505] p-3 rounded.lg border border-white/10">
                <span className="font-bold text-white block uppercase tracking-wide text-[10px] text-amber-400">Master Deployment</span>
                <p className="text-[10.5px] leading-relaxed text-white/60">
                  Run <strong>{masterExeName}</strong> as a Windows Service. It provisions an HTTPS listener socket on port 8443 and initiates an embedded SQLite cluster storing active GPO configurations.
                </p>
              </div>

              <div className="space-y-1.5 bg-[#050505] p-3 rounded-lg border border-white/10">
                <span className="font-bold text-white block uppercase tracking-wide text-[10px] text-amber-400">Client Installation</span>
                <p className="text-[10.5px] leading-relaxed text-white/60">
                  Deploy <strong>{clientExeName}</strong> to target endpoints via SCCM or GPO Startup script. Runs silently in background, capturing local baseline metrics.
                </p>
              </div>
            </div>
          </div>

        </div>
        
      </div>
    </div>
  );
}
