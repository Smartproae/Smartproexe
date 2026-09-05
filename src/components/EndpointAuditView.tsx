import React from 'react';
import { SecurityAuditResult, AuditSection, Endpoint } from '../types';
import { ShieldCheck, ShieldAlert, AlertTriangle, ExternalLink, HelpCircle, Users, Key, Usb, Globe, Play, Terminal, Search, Activity, Sliders, Cpu, Bot, Sparkles } from 'lucide-react';
import CompareReportManager from './CompareReportManager';
import { generatePerHostRemediationScript } from '../utils/ps1ScriptGenerator';

interface Props {
  endpoint: Endpoint;
  onAutoFixEndpoint?: (id: string) => void;
  onRecaptureBaseline?: (id: string) => void;
  onToggleRemediation?: (id: string, vulnId: number) => void;
  onToggleExclusion?: (id: string, vulnId: number) => void;
  onOpenAiAutoFix?: (id: string) => void;
}

export default function EndpointAuditView({ 
  endpoint, 
  onAutoFixEndpoint, 
  onRecaptureBaseline,
  onToggleRemediation,
  onToggleExclusion,
  onOpenAiAutoFix
}: Props) {
  const endpointId = endpoint.id;
  const auditResult = endpoint.scanData;
  const overallScore = endpoint.overallScore;
  
  const browserPolicy = auditResult.browserSecurity || {
    chromePasswordStore: { status: 'failed' as const, value: 'ENABLED', details: 'No active Chrome audit trace found in GPO registry paths.' },
    chromeHistoryAllowed: { status: 'failed' as const, value: 'ALLOWED', details: 'No history auto-wipe configuration active on standard profiles.' },
    edgePasswordStore: { status: 'failed' as const, value: 'ENABLED', details: 'Edge Password Manager allowed without administrative constraint.' },
    edgeHistoryAllowed: { status: 'failed' as const, value: 'ALLOWED', details: 'Edge browsing history retained persistent local storage databases.' },
    firefoxPasswordStore: { status: 'failed' as const, value: 'ENABLED', details: 'Mozilla Firefox password saving remains enabled on user accounts.' },
    firefoxHistoryAllowed: { status: 'failed' as const, value: 'ALLOWED', details: 'Firefox stores search and page records indefinitely.' }
  };

  // NMAP state
  const [nmapTarget, setNmapTarget] = React.useState(auditResult.ipAddresses[0] || '127.0.0.1');
  const [scanType, setScanType] = React.useState('-sS -sV -O');
  const [scanSpeed, setScanSpeed] = React.useState('-T4');
  const [isScanning, setIsScanning] = React.useState(false);
  const [scanProgress, setScanProgress] = React.useState(0);
  const [scanTerminalLogs, setScanTerminalLogs] = React.useState<string[]>([]);
  const [scanCompleted, setScanCompleted] = React.useState(false);
  const [showOnlyWeak, setShowOnlyWeak] = React.useState(false);

  // Sync state if endpoint changes
  React.useEffect(() => {
    setNmapTarget(auditResult.ipAddresses[0] || '127.0.0.1');
    setScanTerminalLogs([]);
    setScanCompleted(false);
    setScanProgress(0);
    setIsScanning(false);
  }, [auditResult]);

  const handleNmapScan = () => {
    setIsScanning(true);
    setScanCompleted(false);
    setScanProgress(5);
    setScanTerminalLogs([
      `Starting Nmap 7.92 ( https://nmap.org ) at ${new Date().toISOString().replace('T', ' ').substring(0, 19)} UTC`,
      `Nmap scan report for ${auditResult.hostname} (${nmapTarget})`,
      `Host is up (0.00045s latency).`,
      `rDNS record for ${nmapTarget} resolved to local domain structure.`,
      `Initiating SYN Stealth Scan at ${new Date().toLocaleTimeString()} ...`
    ]);

    const logs = [
      { p: 20, l: "Scanning 1000 ports... [SYN Scan]" },
      { p: 40, l: "Discovered active services and protocol signatures..." },
      { p: 60, l: "Initiating Service scan (-sV) against potential open listeners..." },
      { p: 80, l: "Initiating OS detection (-O) via fingerprinted TCP window params..." },
      { p: 95, l: "Completed scan sequence. Analyzing vulnerabilities for CVE correlation..." },
      { p: 100, l: `Nmap done: 1 IP address (1 host up) scanned successfully in 2.34 seconds.` }
    ];

    logs.forEach((step, index) => {
      setTimeout(() => {
        setScanProgress(step.p);
        setScanTerminalLogs(prev => [...prev, `[+] ${step.l}`]);
        if (step.p === 100) {
          setIsScanning(false);
          setScanCompleted(true);
        }
      }, (index + 1) * 355);
    });
  };

  // Automated Administrative Fix states
  const [adminUser, setAdminUser] = React.useState('CORP\\administrator');
  const [adminPassword, setAdminPassword] = React.useState('');
  const [requireReboot, setRequireReboot] = React.useState(true);
  const [triggerRescan, setTriggerRescan] = React.useState(true);
  
  const [isFixing, setIsFixing] = React.useState(false);
  const [fixProgress, setFixProgress] = React.useState(0);
  const [fixTerminalLogs, setFixTerminalLogs] = React.useState<string[]>([]);
  const [fixCompleted, setFixCompleted] = React.useState(false);
  const [showFixConsole, setShowFixConsole] = React.useState(false);

  // Connection/Fix progress steps
  const handleAutoFixExecute = (e: React.FormEvent) => {
    e.preventDefault();
    if (!adminUser.trim() || !adminPassword.trim()) {
      setFixTerminalLogs([
        `[!] SYSTEM RECOGNITION FAILURE: REQUISITE PARAMETERS MISSING`,
        `[!] Please enter both Administrator Username and Password to authorize Remote PowerShell connectivity.`
      ]);
      setShowFixConsole(true);
      return;
    }

    setIsFixing(true);
    setFixCompleted(false);
    setShowFixConsole(true);
    setFixProgress(0);
    setFixTerminalLogs([
      `[!] INITIALIZING SECURITY COMPLIANCE REMEDIATION ORCHESTRATOR`,
      `[!] Target Host: ${auditResult.hostname} (${auditResult.ipAddresses[0] || '127.0.0.1'})`,
      `[*] Connecting over WinRM-HTTPS (Port 5986) using secure SSL encapsulation...`,
      `[*] Authenticating User: ${adminUser}`
    ]);

    const steps = [
      { p: 10, l: `[+] Connected! Session active. User: ${adminUser}. Token elevation: Admin High-Privilege Verified.` },
      { p: 20, l: `[+] Disable SMBv1: Registry key SMB1 set to 0. Disable-WindowsOptionalFeature executed.` },
      { p: 35, l: `[+] Enforce SMB Signing: RequireSecuritySignature set to 1 on LanmanServer. Enabled global Client requirement.` },
      { p: 50, l: `[+] Disable obsolete SSL/TLS: Server/Client registry trees for SSL 3.0, TLS 1.0, and TLS 1.1 created with Enabled = 0 / DisabledByDefault = 1.` },
      { p: 60, l: `[+] Raise LM/NTLM to secure levels: LmCompatibilityLevel registry configured as 5 (Refuse LM & NTLMv1).` },
      { p: 70, l: `[+] Secure Browser Policies (Chrome & Edge GPOs): Set PasswordManagerEnabled = 0 and SavingBrowserHistoryDisabled = 1 under both Policies\\Google\\Chrome and Policies\\Microsoft\\Edge.` },
      { p: 80, l: `[+] Firefox Enterprise Policy Lockdown: Deployed custom policies.json on Active Directory & local systems to force "PasswordManager": false and "SanitizeOnShutdown": true.` },
      { p: 90, l: `[+] Profile Sanitization Action: Deleted saved SQLite password database files and wiped browsing history tables for all Local and Domain user profiles (Chrome, Edge & Firefox caches).` },
      { p: 95, l: `[+] Hardening policies applied. Reset passwords never expires flags on local non-service accounts, maximum password age locked to 45 days.` }
    ];

    if (requireReboot) {
      steps.push({ p: 98, l: `[!] REBOOT COMMAND ISSUED: Restart-Computer -Force. Simulating server warm recycling reboot...` });
      steps.push({ p: 100, l: `[+] Host is ONLINE again. WinRM sockets listening.` });
    } else {
      steps.push({ p: 100, l: `[+] All compliance policies pushed. Device configuration synced.` });
    }

    if (triggerRescan) {
      steps.push({ p: 100, l: `[*] TRIGGERING DIAGNOSTIC COMPLIANCE RE-SCAN POSTURE CERTIFICATE...` });
      steps.push({ p: 100, l: `[+] RE-SCAN COMPLETE: Overall Host Security Posture raised to 100% SECURE.` });
    }

    steps.forEach((step, index) => {
      setTimeout(() => {
        setFixProgress(step.p);
        setFixTerminalLogs(prev => [...prev, step.l]);
        if (index === steps.length - 1) {
          setIsFixing(false);
          setFixCompleted(true);
          // Apply changes in parent!
          if (onAutoFixEndpoint) {
            onAutoFixEndpoint(endpointId);
          }
        }
      }, (index + 1) * 800);
    });
  };

  const getAuditRowStatusIcon = (status: AuditSection['status']) => {
    switch (status) {
      case 'passed':
        return <ShieldCheck className="w-5 h-5 text-emerald-400 flex-shrink-0" />;
      case 'failed':
        return <ShieldAlert className="w-5 h-5 text-[#FF3B30] flex-shrink-0" />;
      default:
        return <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0" />;
    }
  };

  const getStatusBadge = (status: AuditSection['status'], val: string) => {
    switch (status) {
      case 'passed':
        return <span className="text-[9px] font-black tracking-wider uppercase px-2 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-400/30 font-mono">{val}</span>;
      case 'failed':
        return <span className="text-[9px] font-black tracking-wider uppercase px-2 py-0.5 bg-[#FF3B30]/15 text-[#FF3B30] border border-[#FF3B30]/30 font-mono">{val}</span>;
      default:
        return <span className="text-[9px] font-black tracking-wider uppercase px-2 py-0.5 bg-amber-500/10 text-amber-500 border border-amber-500/30 font-mono">{val}</span>;
    }
  };

  const scoreColor = (score: number) => {
    if (score >= 80) return 'text-emerald-400 border-emerald-400/40 bg-emerald-500/15';
    if (score >= 60) return 'text-amber-500 border-amber-500/40 bg-amber-500/15';
    return 'text-[#FF3B30] border-[#FF3B30]/40 bg-[#FF3B30]/15';
  };

  return (
    <div id="endpoint-audit-view" className="space-y-8">
      
      {/* Target summary bar */}
      <div className="bg-[#0f0f0f] border-2 border-white/20 p-6 flex flex-col sm:flex-row items-center justify-between gap-6 text-left hover:border-white transition-all">
        <div className="space-y-2 flex-1 w-full sm:w-auto">
          <div className="flex items-center gap-2.5 flex-wrap">
            <span className="text-[9px] uppercase tracking-widest bg-white/10 text-white border border-white/20 font-black px-2.5 py-0.5 font-mono">
              AUDIT COMPLIANCE REPORT
            </span>
            <span className="text-[10px] text-white/50 uppercase font-mono font-bold">LAST SCAN: {auditResult.scanTime}</span>
          </div>
          <h2 className="text-2xl sm:text-4xl font-black text-white uppercase tracking-tight leading-none pt-1">{auditResult.hostname}</h2>
          <p className="text-xs text-white/50 uppercase font-mono tracking-wider">OS version: {auditResult.osName}</p>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[10px] uppercase font-mono text-white/40 pt-1 font-bold">
            <span>Privileges: <strong className="text-white bg-white/10 px-1 py-0.5">{auditResult.privileges}</strong></span>
            <span>Target IP: <strong className="text-white bg-[#FF3B30]/10 px-1 py-0.5 text-[#FF3B30]">{auditResult.ipAddresses.join(', ') || 'n/a'}</strong></span>
            <button
              onClick={() => {
                const isDc = Boolean(endpoint.scanData?.users?.isDomainController || endpoint.deviceType === 'Server');
                const scriptContent = generatePerHostRemediationScript(endpoint, isDc);
                const element = document.createElement("a");
                const file = new Blob([scriptContent], { type: 'text/plain' });
                element.href = URL.createObjectURL(file);
                element.download = `Remediate_${endpoint.name}_${endpoint.ip}.ps1`;
                document.body.appendChild(element);
                element.click();
                document.body.removeChild(element);
              }}
              className="bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 px-2.5 py-1 text-[10px] font-black uppercase tracking-wider rounded transition cursor-pointer flex items-center gap-1 font-mono"
              title="Download targeted PS1 script to execute directly on this endpoint"
            >
              <Terminal className="w-3 h-3 text-emerald-400" />
              Download Host PS1 Fix Script
            </button>
          </div>
        </div>

        <div className={`flex flex-col items-center justify-center p-4 border-2 w-28 h-28 flex-shrink-0 font-mono ${scoreColor(overallScore)}`}>
          <span className="text-[8px] uppercase font-black tracking-widest opacity-80">COMPLIANCE</span>
          <span className="text-4xl font-black mt-1 leading-none">{overallScore}</span>
          <span className="text-[9px] uppercase tracking-wider mt-1.5 font-bold opacity-60">SCORE</span>
        </div>
      </div>

      {/* Dynamic side-by-side comparison & reporting hub */}
      <CompareReportManager
        endpoint={endpoint}
        onAutoFix={() => {
          if (onAutoFixEndpoint) {
            onAutoFixEndpoint(endpointId);
          }
        }}
        onRecaptureBaseline={() => {
          if (onRecaptureBaseline) {
            onRecaptureBaseline(endpointId);
          }
        }}
        onToggleRemediation={onToggleRemediation}
        onToggleExclusion={onToggleExclusion}
      />

      {/* TARGET COMPLIANCE AUTO-FIX ENGINE */}
      <div className="bg-[#0b0b0b] border-2 border-[#FF3B30]/30 p-6 text-left space-y-6 rounded relative overflow-hidden">
        {/* Decorative corner accent */}
        <div className="absolute top-0 right-0 w-12 h-12 bg-gradient-to-br from-[#FF3B30]/20 to-transparent pointer-events-none" />

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-4">
          <div>
            <span className="text-xs font-mono text-[#FF3B30] font-black tracking-widest uppercase flex items-center gap-1.5">
              <span className="w-2 h-2 bg-[#FF3B30] animate-ping rounded-full inline-block"></span>
              Administrative Remote Self-Healing Core
            </span>
            <h3 className="text-xl sm:text-2xl font-black text-white uppercase tracking-tight mt-1">
              PowerShell Remediation & Compliance Injector
            </h3>
            <p className="text-[11px] text-white/40 uppercase font-mono mt-0.5">
              Remediate standard vulnerabilities (SMB1, cleartext SSL, unsigned LDAP, weak ports, user-policy expirations) natively.
            </p>
          </div>
          
          <div className="flex items-center gap-2.5 flex-wrap">
            {onOpenAiAutoFix && (
              <button
                type="button"
                onClick={() => onOpenAiAutoFix(endpoint.id)}
                className="flex items-center gap-1.5 bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-black px-4 py-2 rounded-xl text-xs font-black uppercase tracking-wider transition shadow-lg shadow-cyan-950/40 cursor-pointer select-none border border-cyan-300"
                title="Synthesize AI-powered PowerShell Auto-Fix Script via Gemini"
              >
                <Sparkles className="w-3.5 h-3.5 text-black animate-pulse" />
                🤖 AI Auto-Fix (Gemini)
              </button>
            )}
            {overallScore === 100 && (
              <span className="bg-emerald-500/15 text-emerald-400 border border-emerald-400/30 px-3 py-1 font-mono text-xs uppercase tracking-wide font-black">
                ✓ COMPLIANT & SECURED
              </span>
            )}
          </div>
        </div>

        {overallScore === 100 && !showFixConsole ? (
          <div className="bg-emerald-500/10 border border-emerald-400/20 p-5 rounded flex items-start gap-3.5">
            <ShieldCheck className="w-6 h-6 text-emerald-400 flex-shrink-0 mt-0.5" />
            <div>
              <h4 className="text-sm font-black text-white uppercase font-mono tracking-wide">Workstation Hardening Verified</h4>
              <p className="text-xs text-white/60 leading-relaxed mt-1">
                All security control objectives have been fully resolved. Deprecated protocols are disabled, local registry policies hold secure, and unencrypted default listener ports (FTP, Telnet) are closed.
              </p>
              <button
                onClick={() => setShowFixConsole(true)}
                className="mt-3.5 text-xs font-mono text-emerald-400 hover:text-emerald-300 underline uppercase font-bold flex items-center gap-1.5"
              >
                <Terminal className="w-3.5 h-3.5" />
                Inspect compliance execution logs history
              </button>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            
            <div className="lg:col-span-6 space-y-4">
              <form onSubmit={handleAutoFixExecute} className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <label className="text-white/55 uppercase text-[9px] font-black tracking-wider block font-mono">
                      Admin Domain \ Username
                    </label>
                    <input
                      type="text"
                      required
                      value={adminUser}
                      onChange={(e) => setAdminUser(e.target.value)}
                      placeholder="e.g. CORP\administrator"
                      className="w-full bg-[#050505] border border-white/15 text-white p-2.5 rounded font-mono text-xs focus:outline-none focus:border-white transition-all"
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="text-white/55 uppercase text-[9px] font-black tracking-wider block font-mono">
                      Domain Admin Password
                    </label>
                    <input
                      type="password"
                      required
                      value={adminPassword}
                      onChange={(e) => setAdminPassword(e.target.value)}
                      placeholder="••••••••••••"
                      className="w-full bg-[#050505] border border-white/15 text-white p-2.5 rounded font-mono text-xs focus:outline-none focus:border-white transition-all"
                    />
                  </div>
                </div>

                {/* Automation Toggles */}
                <div className="flex flex-wrap items-center gap-x-5 gap-y-3 pt-1 border-t border-white/5">
                  <label className="flex items-center gap-2 cursor-pointer text-xs text-white/70 select-none">
                    <input
                      type="checkbox"
                      checked={requireReboot}
                      onChange={(e) => setRequireReboot(e.target.checked)}
                      className="w-4 h-4 accent-[#FF3B30] bg-black border-white/25 rounded"
                    />
                    <span className="font-mono uppercase text-[10px]">Require System Reboot ({requireReboot ? "On" : "Off"})</span>
                  </label>

                  <label className="flex items-center gap-2 cursor-pointer text-xs text-white/70 select-none">
                    <input
                      type="checkbox"
                      checked={triggerRescan}
                      onChange={(e) => setTriggerRescan(e.target.checked)}
                      className="w-4 h-4 accent-[#FF3B30] bg-black border-white/25 rounded"
                    />
                    <span className="font-mono uppercase text-[10px]">Instant diagnostic Post-Rescan verify ({triggerRescan ? "On" : "Off"})</span>
                  </label>
                </div>

                <div className="pt-2">
                  <button
                    type="submit"
                    disabled={isFixing}
                    className="w-full bg-[#FF3B30] text-white hover:bg-[#E02E24] disabled:bg-white/10 disabled:text-white/30 font-black uppercase text-xs py-3 rounded tracking-widest flex items-center justify-center gap-2.5 transition select-none cursor-pointer"
                  >
                    <Sliders className="w-4 h-4" />
                    {isFixing ? `Applying Elevated Policies (${fixProgress}%) ...` : "Enforce Compliance Autofixes"}
                  </button>
                </div>
              </form>
            </div>

            {/* Simulated interactive Terminal logging */}
            <div className="lg:col-span-6 flex flex-col justify-between bg-black border border-white/10 rounded overflow-hidden">
              <div className="bg-white/5 py-1.5 px-3.5 border-b border-white/10 flex items-center justify-between">
                <span className="text-[10px] uppercase text-white/40 font-mono tracking-wider flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                  Remote compliance execution panel
                </span>
                <span className="inline-block w-2 w-2 rounded-full bg-[#FF3B30]" />
              </div>

              <div className="p-3 bg-black text-[#58b277] h-48 overflow-y-auto font-mono text-[9px] text-left select-all space-y-1 leading-normal">
                {fixTerminalLogs.length === 0 ? (
                  <div className="text-white/25 text-center flex flex-col items-center justify-center h-full space-y-2">
                    <Sliders className="w-6 h-6 opacity-30 text-white" />
                    <span>Enter active administrator credentials and click enforce to view secure remote deployment output.</span>
                  </div>
                ) : (
                  fixTerminalLogs.map((log, index) => (
                    <div key={index} className="whitespace-pre-wrap font-mono">
                      {log}
                    </div>
                  ))
                )}

                {isFixing && (
                  <div className="flex items-center gap-1.5 text-white pt-1">
                    <span className="inline-block w-1.5 h-3 bg-white animate-pulse"></span>
                    <span className="text-xs font-mono">DEPLOYING COMPLIANCE MATRIX ...</span>
                  </div>
                )}
              </div>
            </div>

          </div>
        )}
      </div>

      {/* Protocol details grids */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 text-left">
        
        {/* SMB */}
        <div className="bg-[#0f0f0f] border-2 border-white/20 p-6 flex flex-col justify-between hover:border-white transition-all">
          <div>
            <h3 className="text-xs font-black text-white uppercase tracking-[0.15em] border-b border-white/15 pb-3 mb-5 font-mono">
              SMB Hardening Suites
            </h3>
            
            <div className="space-y-6">
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-2.5">
                  <div className="flex items-start gap-2">
                    {getAuditRowStatusIcon(auditResult.smb.smb1Enabled.status)}
                    <div>
                      <h4 className="text-xs font-black text-white uppercase tracking-wide">SMBv1 Protocol</h4>
                      <p className="text-[9px] text-white/40 uppercase font-mono font-bold pt-0.5">Deprecated share active</p>
                    </div>
                  </div>
                  {getStatusBadge(auditResult.smb.smb1Enabled.status, auditResult.smb.smb1Enabled.value)}
                </div>
                <p className="text-[10px] text-white/50 leading-relaxed pl-7">
                  {auditResult.smb.smb1Enabled.details}
                </p>
              </div>

              <div className="space-y-2 border-t border-white/10 pt-4">
                <div className="flex items-start justify-between gap-2.5">
                  <div className="flex items-start gap-2">
                    {getAuditRowStatusIcon(auditResult.smb.smbSigningRequired.status)}
                    <div>
                      <h4 className="text-xs font-black text-white uppercase tracking-wide">Secure SMB Signing</h4>
                      <p className="text-[9px] text-white/40 uppercase font-mono font-bold pt-0.5">Integrity validations</p>
                    </div>
                  </div>
                  {getStatusBadge(auditResult.smb.smbSigningRequired.status, auditResult.smb.smbSigningRequired.value)}
                </div>
                <p className="text-[10px] text-white/50 leading-relaxed pl-7">
                  {auditResult.smb.smbSigningRequired.details}
                </p>
              </div>

              <div className="space-y-2 border-t border-white/10 pt-4">
                <div className="flex items-start justify-between gap-2.5">
                  <div className="flex items-start gap-2">
                    {getAuditRowStatusIcon(auditResult.smb.smbEncryptionEnabled.status)}
                    <div>
                      <h4 className="text-xs font-black text-white uppercase tracking-wide">Payload Encryption</h4>
                      <p className="text-[9px] text-white/40 uppercase font-mono font-bold pt-0.5">Packet payload scrambles</p>
                    </div>
                  </div>
                  {getStatusBadge(auditResult.smb.smbEncryptionEnabled.status, auditResult.smb.smbEncryptionEnabled.value)}
                </div>
                <p className="text-[10px] text-white/50 leading-relaxed pl-7">
                  {auditResult.smb.smbEncryptionEnabled.details}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* SSL & TLS */}
        <div className="bg-[#0f0f0f] border-2 border-white/20 p-6 flex flex-col justify-between hover:border-white transition-all">
          <div>
            <h3 className="text-xs font-black text-white uppercase tracking-[0.15em] border-b border-white/15 pb-3 mb-5 font-mono">
              Schannel SSL / TLS Ciphers
            </h3>
            
            <div className="space-y-6">
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-2.5">
                  <div className="flex items-start gap-2">
                    {getAuditRowStatusIcon(auditResult.sslTls.tls10Enabled.status)}
                    <div>
                      <h4 className="text-xs font-black text-white uppercase tracking-wide">TLS 1.0 State</h4>
                      <p className="text-[9px] text-white/40 uppercase font-mono font-bold pt-0.5">Obsolete protocols check</p>
                    </div>
                  </div>
                  {getStatusBadge(auditResult.sslTls.tls10Enabled.status, auditResult.sslTls.tls10Enabled.value)}
                </div>
                <p className="text-[10px] text-white/50 leading-relaxed pl-7">
                  {auditResult.sslTls.tls10Enabled.details}
                </p>
              </div>

              <div className="space-y-2 border-t border-white/10 pt-4">
                <div className="flex items-start justify-between gap-2.5">
                  <div className="flex items-start gap-2">
                    {getAuditRowStatusIcon(auditResult.sslTls.tls11Enabled.status)}
                    <div>
                      <h4 className="text-xs font-black text-white uppercase tracking-wide">TLS 1.1 State</h4>
                      <p className="text-[9px] text-white/40 uppercase font-mono font-bold pt-0.5">Unsafe protocol negotiation</p>
                    </div>
                  </div>
                  {getStatusBadge(auditResult.sslTls.tls11Enabled.status, auditResult.sslTls.tls11Enabled.value)}
                </div>
                <p className="text-[10px] text-white/50 leading-relaxed pl-7">
                  {auditResult.sslTls.tls11Enabled.details}
                </p>
              </div>

              <div className="space-y-2 border-t border-white/10 pt-4">
                <div className="flex items-start justify-between gap-2.5">
                  <div className="flex items-start gap-2">
                    {getAuditRowStatusIcon(auditResult.sslTls.tls12Enabled.status)}
                    <div>
                      <h4 className="text-xs font-black text-white uppercase tracking-wide">TLS 1.2 Suite</h4>
                      <p className="text-[9px] text-white/40 uppercase font-mono font-bold pt-0.5">Default transport layer</p>
                    </div>
                  </div>
                  {getStatusBadge(auditResult.sslTls.tls12Enabled.status, auditResult.sslTls.tls12Enabled.value)}
                </div>
                <p className="text-[10px] text-white/50 leading-relaxed pl-7">
                  {auditResult.sslTls.tls12Enabled.details}
                </p>
              </div>

              <div className="space-y-2 border-t border-white/10 pt-4">
                <div className="flex items-start justify-between gap-2.5">
                  <div className="flex items-start gap-2">
                    {getAuditRowStatusIcon(auditResult.sslTls.tls13Enabled.status)}
                    <div>
                      <h4 className="text-xs font-black text-white uppercase tracking-wide">TLS 1.3 Suite</h4>
                      <p className="text-[9px] text-white/40 uppercase font-mono font-bold pt-0.5">Secure cryptography edge</p>
                    </div>
                  </div>
                  {getStatusBadge(auditResult.sslTls.tls13Enabled.status, auditResult.sslTls.tls13Enabled.value)}
                </div>
                <p className="text-[10px] text-white/50 leading-relaxed pl-7">
                  {auditResult.sslTls.tls13Enabled.details}
                </p>
              </div>

              <div className="space-y-2 border-t border-white/10 pt-4">
                <div className="flex items-start justify-between gap-2.5">
                  <div className="flex items-start gap-2">
                    {getAuditRowStatusIcon(auditResult.sslTls.weakCipherSuites.status)}
                    <div>
                      <h4 className="text-xs font-black text-white uppercase tracking-wide">RC4 & DES Ciphers</h4>
                      <p className="text-[9px] text-white/40 uppercase font-mono font-bold pt-0.5">Obsolete cryptography hashes</p>
                    </div>
                  </div>
                  {getStatusBadge(auditResult.sslTls.weakCipherSuites.status, auditResult.sslTls.weakCipherSuites.value)}
                </div>
                <p className="text-[10px] text-white/50 leading-relaxed pl-7">
                  {auditResult.sslTls.weakCipherSuites.details}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* NTLM Settings */}
        <div className="bg-[#0f0f0f] border-2 border-white/20 p-6 flex flex-col justify-between hover:border-white transition-all">
          <div>
            <h3 className="text-xs font-black text-white uppercase tracking-[0.15em] border-b border-white/15 pb-3 mb-5 font-mono">
              LM & NTLM Integrity
            </h3>
            
            <div className="space-y-6">
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-2.5">
                  <div className="flex items-start gap-2">
                    {getAuditRowStatusIcon(auditResult.ntlm.lmCompatibilityLevel.status)}
                    <div>
                      <h4 className="text-xs font-black text-white uppercase tracking-wide">LM Compatibility</h4>
                      <p className="text-[9px] text-white/40 uppercase font-mono font-bold pt-0.5">Exchange hashing protocols</p>
                    </div>
                  </div>
                  {getStatusBadge(auditResult.ntlm.lmCompatibilityLevel.status, auditResult.ntlm.lmCompatibilityLevel.value)}
                </div>
                <p className="text-[10px] text-white/50 leading-relaxed pl-7">
                  {auditResult.ntlm.lmCompatibilityLevel.details}
                </p>
              </div>

              <div className="space-y-2 border-t border-white/10 pt-4">
                <div className="flex items-start justify-between gap-2.5">
                  <div className="flex items-start gap-2">
                    {getAuditRowStatusIcon(auditResult.ntlm.restrictNtlmTraffic.status)}
                    <div>
                      <h4 className="text-xs font-black text-white uppercase tracking-wide">NTLM Restrictions</h4>
                      <p className="text-[9px] text-white/40 uppercase font-mono font-bold pt-0.5">Relay hijack prevention</p>
                    </div>
                  </div>
                  {getStatusBadge(auditResult.ntlm.restrictNtlmTraffic.status, auditResult.ntlm.restrictNtlmTraffic.value)}
                </div>
                <p className="text-[10px] text-white/50 leading-relaxed pl-7">
                  {auditResult.ntlm.restrictNtlmTraffic.details}
                </p>
              </div>

              <div className="space-y-2 border-t border-white/10 pt-4">
                <div className="flex items-start justify-between gap-2.5">
                  <div className="flex items-start gap-2">
                    {getAuditRowStatusIcon(auditResult.ntlm.anonymousAccess.status)}
                    <div>
                      <h4 className="text-xs font-black text-white uppercase tracking-wide">Anonymous shares</h4>
                      <p className="text-[9px] text-white/40 uppercase font-mono font-bold pt-0.5">Null session registry bounds</p>
                    </div>
                  </div>
                  {getStatusBadge(auditResult.ntlm.anonymousAccess.status, auditResult.ntlm.anonymousAccess.value)}
                </div>
                <p className="text-[10px] text-white/50 leading-relaxed pl-7">
                  {auditResult.ntlm.anonymousAccess.details}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Browser Security Policy Hardening */}
        <div className="bg-[#0f0f0f] border-2 border-white/20 p-6 flex flex-col justify-between hover:border-white transition-all col-span-1">
          <div>
            <h3 className="text-xs font-black text-white uppercase tracking-[0.15em] border-b border-white/15 pb-3 mb-5 font-mono flex items-center gap-1.5">
              <Globe className="w-4 h-4 text-[#FF3B30]" />
              Enterprise Browser Policies
            </h3>
            
            <div className="space-y-6">
              {/* CHROME */}
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-2.5">
                  <div className="flex items-start gap-2">
                    {getAuditRowStatusIcon(browserPolicy.chromePasswordStore.status)}
                    <div>
                      <h4 className="text-xs font-black text-white uppercase tracking-wide">Chrome Credentials Vault</h4>
                      <p className="text-[9px] text-white/40 uppercase font-mono font-bold pt-0.5">Password auto-fill block</p>
                    </div>
                  </div>
                  {getStatusBadge(browserPolicy.chromePasswordStore.status, browserPolicy.chromePasswordStore.value)}
                </div>
                <p className="text-[10px] text-white/50 leading-relaxed pl-7">
                  {browserPolicy.chromePasswordStore.details}
                </p>
                <div className="flex items-start gap-2 pt-2 border-t border-white/5">
                  {getAuditRowStatusIcon(browserPolicy.chromeHistoryAllowed.status)}
                  <div>
                    <h4 className="text-[10px] font-bold text-white/80 uppercase">Chrome Surfing History</h4>
                    <p className="text-[9px] text-white/50 leading-relaxed font-mono mt-0.5">History cache restricted & domain session deletion policy.</p>
                    <p className="text-[9px] text-[#FF3B30]/90 font-mono font-bold uppercase">{browserPolicy.chromeHistoryAllowed.details}</p>
                  </div>
                </div>
              </div>

              {/* EDGE */}
              <div className="space-y-2 border-t border-white/10 pt-4">
                <div className="flex items-start justify-between gap-2.5">
                  <div className="flex items-start gap-2">
                    {getAuditRowStatusIcon(browserPolicy.edgePasswordStore.status)}
                    <div>
                      <h4 className="text-xs font-black text-white uppercase tracking-wide">Edge Credentials Vault</h4>
                      <p className="text-[9px] text-white/40 uppercase font-mono font-bold pt-0.5">Password store disable</p>
                    </div>
                  </div>
                  {getStatusBadge(browserPolicy.edgePasswordStore.status, browserPolicy.edgePasswordStore.value)}
                </div>
                <p className="text-[10px] text-white/50 leading-relaxed pl-7">
                  {browserPolicy.edgePasswordStore.details}
                </p>
                <div className="flex items-start gap-2 pt-2 border-t border-white/5">
                  {getAuditRowStatusIcon(browserPolicy.edgeHistoryAllowed.status)}
                  <div>
                    <h4 className="text-[10px] font-bold text-white/80 uppercase">Edge Surfing History</h4>
                    <p className="text-[9px] text-white/50 leading-relaxed font-mono mt-0.5">GPO history clear-on-exit or wipe limits on Active profiles.</p>
                    <p className="text-[9px] text-[#FF3B30]/90 font-mono font-bold uppercase">{browserPolicy.edgeHistoryAllowed.details}</p>
                  </div>
                </div>
              </div>

              {/* FIREFOX */}
              <div className="space-y-2 border-t border-white/10 pt-4">
                <div className="flex items-start justify-between gap-2.5">
                  <div className="flex items-start gap-2">
                    {getAuditRowStatusIcon(browserPolicy.firefoxPasswordStore.status)}
                    <div>
                      <h4 className="text-xs font-black text-white uppercase tracking-wide">Firefox Password Store</h4>
                      <p className="text-[9px] text-white/40 uppercase font-mono font-bold pt-0.5">Master save check</p>
                    </div>
                  </div>
                  {getStatusBadge(browserPolicy.firefoxPasswordStore.status, browserPolicy.firefoxPasswordStore.value)}
                </div>
                <p className="text-[10px] text-white/50 leading-relaxed pl-7">
                  {browserPolicy.firefoxPasswordStore.details}
                </p>
                <div className="flex items-start gap-2 pt-2 border-t border-white/5">
                  {getAuditRowStatusIcon(browserPolicy.firefoxHistoryAllowed.status)}
                  <div>
                    <h4 className="text-[10px] font-bold text-white/80 uppercase">Firefox Surfing History</h4>
                    <p className="text-[9px] text-white/50 leading-relaxed font-mono mt-0.5">Firefox enterprise profiles history purge control indicator.</p>
                    <p className="text-[9px] text-[#FF3B30]/90 font-mono font-bold uppercase">{browserPolicy.firefoxHistoryAllowed.details}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* SECTION: ACCOUNTS & CREDENTIAL AGING GATES */}
      <div className="bg-[#0f0f0f] border-2 border-white/20 p-6 text-left hover:border-white transition-all space-y-6">
        <div className="border-b border-white/15 pb-4">
          <span className="text-[#FF3B30] font-black text-[10px] uppercase tracking-[0.2em] font-mono flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 bg-[#FF3B30] inline-block"></span>
            Accounts & Credential Lifecycle Audit
          </span>
          <h3 className="text-xl sm:text-2xl font-black text-white uppercase tracking-tight mt-1">
            "Net User" Security & Active Directory Assessment
          </h3>
        </div>

        {/* DC Info Banner */}
        {auditResult.users?.isDomainController && (
          <div className="bg-emerald-500/15 border-2 border-emerald-400/40 p-4 font-mono text-xs text-emerald-400">
            <strong className="font-extrabold uppercase tracking-wider block mb-1">
              [SYSTEM NOTICE: ACTIVE DIRECTORY DOMAIN CONTROLLER SPECIAL AUDIT CORE]
            </strong>
            This endpoint has been authenticated as a Primary Active Directory Domain Controller. The account policies listed below are governed by the default domain policy GPOs and applied domain-wide across all systems.
            {auditResult.users.domainPolicyDetails && (
              <p className="mt-2 text-white/70 italic">{auditResult.users.domainPolicyDetails}</p>
            )}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          
          {/* List of Active System Users */}
          <div className="space-y-3">
            <h4 className="text-xs font-black text-white uppercase tracking-widest font-mono border-b border-white/10 pb-2 flex items-center gap-1.5">
              <Users className="w-4 h-4 text-[#FF3B30]" />
              1. Active Corporate Users Directory
            </h4>
            <div className="max-h-56 overflow-y-auto border border-white/10 bg-[#050505] p-3 space-y-2 font-mono">
              {auditResult.users?.activeUsers?.filter(u => u.status === 'Active').map(user => (
                <div key={user.username} className="flex justify-between items-center text-xs p-2.5 border border-white/5 hover:border-white/20 bg-white/2 transition">
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                    <span className="text-white font-bold">{user.username}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] text-white/40 uppercase">Last Change: {user.lastPasswordChange.split(' ')[0]}</span>
                    <span className="text-[9px] font-black tracking-wider uppercase px-2 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-400/20">Active</span>
                  </div>
                </div>
              ))}
              {(!auditResult.users || !auditResult.users.activeUsers || auditResult.users.activeUsers.filter(u => u.status === 'Active').length === 0) && (
                <div className="text-white/40 text-xs italic text-center py-4">No active user records identified.</div>
              )}
            </div>
          </div>

          {/* Local Password Config Details */}
          <div className="space-y-3">
            <h4 className="text-xs font-black text-white uppercase tracking-widest font-mono border-b border-white/10 pb-2 flex items-center gap-1.5">
              <Key className="w-4 h-4 text-[#FF3B30]" />
              2. {auditResult.users?.isDomainController ? 'AD Domain Password Policy Settings' : 'Local Host Password Setting Details'}
            </h4>
            {auditResult.users?.passwordPolicy ? (
              <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                <div className="bg-[#050505] p-3.5 border border-white/10">
                  <span className="text-white/40 uppercase block text-[9px] font-black tracking-wider">Min Password Length</span>
                  <span className="text-white font-black text-sm block mt-1">{auditResult.users.passwordPolicy.minimumLength} Characters</span>
                </div>
                <div className="bg-[#050505] p-3.5 border border-white/10">
                  <span className="text-white/40 uppercase block text-[9px] font-black tracking-wider">Complexity Filters</span>
                  <span className={`font-black text-sm block mt-1 ${auditResult.users.passwordPolicy.complexityEnabled ? 'text-emerald-400' : 'text-amber-500'}`}>
                    {auditResult.users.passwordPolicy.complexityEnabled ? 'ENABLED (Yes)' : 'DISABLED (No)'}
                  </span>
                </div>
                <div className="bg-[#050505] p-3.5 border border-white/10">
                  <span className="text-white/40 uppercase block text-[9px] font-black tracking-wider">Max Password Age</span>
                  <span className="text-white font-black text-sm block mt-1">{auditResult.users.passwordPolicy.maximumAgeDays} Days</span>
                </div>
                <div className="bg-[#050505] p-3.5 border border-white/10">
                  <span className="text-white/40 uppercase block text-[9px] font-black tracking-wider">History Depth Limit</span>
                  <span className="text-white font-black text-sm block mt-1">{auditResult.users.passwordPolicy.historyCount} Keep-Count</span>
                </div>
              </div>
            ) : (
              <div className="text-white/40 text-xs italic font-mono p-4 border border-white/10">Password configuration metrics unavailable.</div>
            )}
          </div>

        </div>

        {/* Filtered outputs strictly based on criteria rules */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-3">
          
          {/* Overdue password warning (>90 days) - if less than 90 days, no need to show! */}
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-white/10 pb-2">
              <h4 className="text-xs font-black text-white uppercase tracking-widest font-mono flex items-center gap-1.5">
                <span className="w-2 h-2 bg-[#FF3B30] inline-block rounded-full"></span>
                3. Password Changed &gt; 90 Days Warnings
              </h4>
              <span className="text-[9px] uppercase tracking-wider bg-[#FF3B30]/15 text-[#FF3B30] px-2 py-0.5 border border-[#FF3B30]/30 font-mono font-black">
                90-DAY VIOLATORS List
              </span>
            </div>
            <div className="space-y-2">
              {auditResult.users?.activeUsers
                ?.filter(u => u.status === 'Active' && u.passwordAgeDays > 90)
                .map(user => (
                  <div key={user.username} className="bg-[#FF3B30]/5 border border-[#FF3B30]/30 p-3.5 flex justify-between items-start font-mono text-xs hover:bg-[#FF3B30]/10 transition-colors">
                    <div>
                      <div className="font-extrabold text-white leading-tight uppercase tracking-wider">{user.username}</div>
                      <div className="text-[10px] text-[#FF3B30] uppercase font-black mt-2">
                        Age: {user.passwordAgeDays} Days Old (&gt; 90 days criteria)
                      </div>
                    </div>
                    <div className="text-right">
                      <span className="text-white/40 block text-[9px] uppercase tracking-wider font-bold">Last Modified</span>
                      <span className="text-[#FF3B30] font-black block mt-1 text-[10px]">{user.lastPasswordChange.split(' ')[0]}</span>
                    </div>
                  </div>
                ))}
              {(!auditResult.users || !auditResult.users.activeUsers || auditResult.users.activeUsers.filter(u => u.status === 'Active' && u.passwordAgeDays > 90).length === 0) && (
                <div className="border border-emerald-500/20 bg-emerald-500/5 p-5 text-center font-mono text-xs text-emerald-400 font-semibold uppercase">
                  ✔ Safe: All active passwords were changed in less than 90 days (no warnings to display).
                </div>
              )}
            </div>
          </div>

          {/* Password Never Expires checkbox status - we must identify and show names */}
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-white/10 pb-2">
              <h4 className="text-xs font-black text-white uppercase tracking-widest font-mono flex items-center gap-1.5">
                <span className="w-2 h-2 bg-amber-500 inline-block rounded-full"></span>
                4. "Password Never Expires" Flagged Accounts
              </h4>
              <span className="text-[9px] uppercase tracking-wider bg-amber-500/15 text-amber-500 px-2 py-0.5 border border-amber-500/30 font-mono font-black">
                User EXPIRY BYPASS
              </span>
            </div>
            <div className="space-y-2">
              {auditResult.users?.activeUsers
                ?.filter(u => u.passwordNeverExpires)
                .map(user => (
                  <div key={user.username} className="bg-amber-500/5 border border-amber-500/30 p-3.5 flex justify-between items-center font-mono text-xs hover:bg-amber-500/10 transition-all">
                    <div>
                      <div className="font-extrabold text-white leading-tight uppercase tracking-wider">{user.username}</div>
                      <span className="text-[9px] text-amber-500 uppercase font-black block mt-2">
                        [✔ SYSTEM ALARM] passwordneverexpires flag is configured
                      </span>
                    </div>
                    <div className="text-[9px] font-black text-amber-500 border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 uppercase tracking-wider font-mono">
                      Security Exception
                    </div>
                  </div>
                ))}
              {(!auditResult.users || !auditResult.users.activeUsers || auditResult.users.activeUsers.filter(u => u.passwordNeverExpires).length === 0) && (
                <div className="border border-emerald-500/20 bg-emerald-500/5 p-5 text-center font-mono text-xs text-emerald-400 font-semibold uppercase">
                  ✔ Safe: No accounts detected with "Password Never Expires" option check.
                </div>
              )}
            </div>
          </div>

        </div>

        {/* 5. LDAP Active Directory SPN Service Principal Name Audit */}
        <div className="pt-4 border-t border-white/10 space-y-3">
          <div className="flex items-center justify-between border-b border-white/10 pb-2 flex-wrap gap-2">
            <div>
              <h4 className="text-xs font-black text-white uppercase tracking-widest font-mono flex items-center gap-1.5">
                <span className="w-2 h-2 bg-cyan-400 inline-block rounded-full"></span>
                5. Active Directory LDAP SPN & Kerberoasting Configuration
              </h4>
              <p className="text-[9px] text-white/40 font-mono mt-0.5">
                LDAP ADUser SPN Probe Results for Selected Endpoint
              </p>
            </div>
            <span className="text-[9px] uppercase tracking-wider bg-cyan-500/15 text-cyan-300 px-2.5 py-0.5 border border-cyan-500/30 font-mono font-black">
              LDAP / Kerberoasting Probe
            </span>
          </div>

          <div className="bg-[#050505] border border-white/10 p-3.5 font-mono text-xs space-y-3 rounded-lg">
            <div className="text-[10px] text-white/70 bg-black/80 p-2.5 border border-white/10 rounded flex items-center justify-between flex-wrap gap-2 overflow-hidden">
              <span className="text-cyan-400 font-bold shrink-0">Command Executed:</span>
              <code className="text-white/90 text-[9px] font-mono select-all truncate max-w-full bg-white/5 px-2 py-0.5 rounded border border-white/10">
                Get-ADUser -Filter &#123;ServicePrincipalName -like "*"&#125; -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires | Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet, PasswordNeverExpires
              </code>
            </div>

            {auditResult.ldapSpnAudit?.accounts && auditResult.ldapSpnAudit.accounts.length > 0 ? (
              <div className="space-y-2 pt-1">
                <div className="flex items-center justify-between">
                  <p className="text-[10px] text-amber-400 font-bold uppercase flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span>
                    Discovered ({auditResult.ldapSpnAudit.accounts.length}) LDAP accounts with ServicePrincipalName (SPN) set:
                  </p>
                  <span className="text-[9px] text-white/50">Kerberoasting Exposure Surface</span>
                </div>

                {/* Structured Table */}
                <div className="border border-white/10 rounded overflow-x-auto">
                  <table className="w-full text-left font-mono text-[10px]">
                    <thead className="bg-white/10 text-cyan-300 uppercase font-black text-[9px] border-b border-white/10">
                      <tr>
                        <th className="p-2 border-r border-white/10">SamAccountName</th>
                        <th className="p-2 border-r border-white/10">ServicePrincipalName (SPN)</th>
                        <th className="p-2 border-r border-white/10">PasswordLastSet</th>
                        <th className="p-2">PasswordNeverExpires</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                      {auditResult.ldapSpnAudit.accounts.map((acct, idx) => (
                        <tr key={idx} className={idx % 2 === 0 ? 'bg-black/40' : 'bg-white/[0.02]'}>
                          <td className="p-2 font-bold text-white border-r border-white/10 font-mono">
                            <span className="text-cyan-300">👤 {acct.samAccountName}</span>
                          </td>
                          <td className="p-2 text-white/90 border-r border-white/10 font-mono break-all max-w-xs">
                            {acct.servicePrincipalName}
                          </td>
                          <td className="p-2 text-cyan-200 border-r border-white/10 whitespace-nowrap">
                            {acct.passwordLastSet}
                          </td>
                          <td className="p-2 whitespace-nowrap">
                            {acct.passwordNeverExpires ? (
                              <span className="text-amber-300 bg-amber-500/20 border border-amber-500/40 px-1.5 py-0.5 rounded font-bold uppercase text-[8px]">
                                TRUE (Risk)
                              </span>
                            ) : (
                              <span className="text-emerald-400 bg-emerald-500/20 border border-emerald-500/40 px-1.5 py-0.5 rounded font-bold uppercase text-[8px]">
                                FALSE
                              </span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="p-3 text-center text-emerald-400 border border-emerald-500/20 bg-emerald-500/5 font-mono text-xs uppercase font-semibold rounded">
                ✔ Safe: No ServicePrincipalName (SPN) accounts detected via Active Directory LDAP query.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* SECTION: REMOVABLE DEVICES & NTP STATE */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* USB Peripheral Auditor */}
        <div className="bg-[#0f0f0f] border-2 border-white/20 p-6 text-left hover:border-white transition-all flex flex-col justify-between space-y-4">
          <div>
            <span className="text-[9px] uppercase tracking-widest bg-white/10 text-white border border-white/20 font-black px-2.5 py-0.5 font-mono inline-block">
              PERIPHERAL BUS INTEGRITY
            </span>
            <div className="flex items-center gap-2 mt-4 pb-2 border-b border-white/15">
              <Usb className="w-5 h-5 text-[#FF3B30]" />
              <h4 className="text-lg font-black text-white uppercase tracking-tight">
                USB Removable Storage Devices
              </h4>
            </div>
            
            <p className="text-[9px] uppercase font-mono font-bold text-white/40 mt-4">
              Registry Protection State:
            </p>
            <div className="flex items-center gap-2.5 mt-1.5">
              {auditResult.removableDevices ? getAuditRowStatusIcon(auditResult.removableDevices.usbStorage.status) : <AlertTriangle className="w-5 h-5 text-amber-500" />}
              <span className="font-mono text-xs font-black uppercase text-white bg-white/5 border border-white/15 px-3 py-1">
                {auditResult.removableDevices?.usbStorage.value || 'NOT CONFIGURED'}
              </span>
            </div>
            <p className="text-xs text-white/60 leading-relaxed font-semibold mt-3.5">
              {auditResult.removableDevices?.usbStorage.details || 'USB peripheral status audit records could not be fetched.'}
            </p>
          </div>
          <div className="pt-3 border-t border-white/10 text-[9px] uppercase font-mono text-white/40 flex justify-between items-center">
            <span>Core: Services\USBSTOR\Start Hive</span>
            <span className="font-black text-amber-500">{auditResult.removableDevices?.usbStorage.status === 'failed' ? 'UNRESTRICTED' : 'SECURE'}</span>
          </div>
        </div>

        {/* NTP Synchronization */}
        <div className="bg-[#0f0f0f] border-2 border-white/20 p-6 text-left hover:border-white transition-all flex flex-col justify-between space-y-4">
          <div>
            <span className="text-[9px] uppercase tracking-widest bg-white/10 text-white border border-white/20 font-black px-2.5 py-0.5 font-mono inline-block">
              NETWORK TIME PROTOCOL INTEGRITY
            </span>
            <div className="flex items-center gap-2 mt-4 pb-2 border-b border-white/15">
              <Globe className="w-5 h-5 text-[#FF3B30]" />
              <h4 className="text-lg font-black text-white uppercase tracking-tight">
                NTP SERVER TIMESTAMPS SYNC
              </h4>
            </div>

            <p className="text-[10px] uppercase font-mono font-bold text-white/40 mt-4">
              NTP Time Sync Enabled Status:
            </p>
            <div className="mt-2">
              <span className={`text-sm font-black font-mono px-3.5 py-1.5 border ${
                auditResult.ntpTime?.enabled === 'Yes' 
                  ? 'text-emerald-400 bg-emerald-500/10 border-emerald-400/30' 
                  : 'text-[#FF3B30] bg-[#FF3B30]/10 border-[#FF3B30]/30'
              }`}>
                NTP ENABLED: {auditResult.ntpTime?.enabled || 'No'}
              </span>
            </div>
            <p className="text-xs text-white/60 leading-relaxed mt-4 font-semibold">
              {auditResult.ntpTime?.details || 'NTP service sync flags could not be scanned.'}
            </p>
          </div>
          <div className="pt-3 border-t border-white/10 text-[9px] uppercase font-mono text-white/40 flex justify-between items-center">
            <span>System: Windows Time Daemon (w32time)</span>
            <span className={`font-black uppercase ${auditResult.ntpTime?.enabled === 'Yes' ? 'text-emerald-400' : 'text-[#FF3B30]'}`}>
              {auditResult.ntpTime?.enabled === 'Yes' ? 'YES' : 'NO'}
            </span>
          </div>
        </div>

      </div>

      {/* SECTION: NETWORK PORT INTEGRITY & NMAP SUITE */}
      <div className="bg-[#0f0f0f] border-2 border-white/20 p-6 text-left hover:border-white transition-all space-y-6">
        <div className="border-b border-white/15 pb-4 flex flex-col sm:flex-row justify-between sm:items-center gap-4">
          <div>
            <span className="text-[#FF3B30] font-black text-[10px] uppercase tracking-[0.2em] font-mono flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 bg-[#FF3B30] inline-block mb-[1px]"></span>
              Port Audit & Nmap Discovery Module
            </span>
            <h3 className="text-xl sm:text-2xl font-black text-white uppercase tracking-tight mt-1">
              Active Network Listeners & Socket Scan
            </h3>
          </div>
          
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setShowOnlyWeak(!showOnlyWeak)}
              className={`px-3 py-1.5 font-mono text-xs uppercase tracking-wider border transition-all font-black flex items-center gap-1.5 ${
                showOnlyWeak 
                  ? 'bg-[#FF3B30]/15 text-[#FF3B30] border-[#FF3B30]' 
                  : 'bg-white/5 text-white/60 border-white/10 hover:border-white/30'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              {showOnlyWeak ? 'Displaying: Weak/Vulnerable Only' : 'Display Status: All Ports'}
            </button>
          </div>
        </div>

        {/* Port Status List Table */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          
          <div className="lg:col-span-7 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-black text-white uppercase tracking-widest font-mono flex items-center gap-1.5">
                <Cpu className="w-4 h-4 text-[#FF3B30]" />
                1. Scanned System Ports Index
              </h4>
              <span className="text-[10px] font-mono text-white/40 uppercase">
                {auditResult.ports?.length || 0} TCP/UDP Ports Scanned
              </span>
            </div>

            <div className="border border-white/10 bg-[#050505] overflow-hidden rounded">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="bg-white/5 border-b border-white/10 text-white/40 uppercase text-[9px] font-black tracking-wider">
                    <th className="p-3">Port</th>
                    <th className="p-3">Protocol</th>
                    <th className="p-3">Service</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Security Risk</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {(auditResult.ports || [])
                    .filter(p => !showOnlyWeak || p.severity !== 'Secure')
                    .map((p, idx) => (
                      <React.Fragment key={idx}>
                        <tr className="hover:bg-white/[0.02] transition-colors">
                          <td className="p-3 font-bold text-white">{p.port}</td>
                          <td className="p-3 text-white/60">{p.protocol}</td>
                          <td className="p-3">
                            <span className="bg-white/5 text-white border border-white/10 px-1.5 py-0.5 rounded text-[10px] uppercase">
                              {p.service}
                            </span>
                          </td>
                          <td className="p-3">
                            <span className={`inline-flex items-center gap-1 font-black ${
                              p.status === 'Open' ? 'text-emerald-400' : 'text-white/30'
                            }`}>
                              <span className={`w-1.5 h-1.5 rounded-full ${p.status === 'Open' ? 'bg-emerald-400 animate-pulse' : 'bg-white/30'}`}></span>
                              {p.status}
                            </span>
                          </td>
                          <td className="p-3">
                            <span className={`text-[10px] font-black uppercase px-2 py-0.5 border ${
                              p.severity === 'Critical' 
                                ? 'bg-[#FF3B30]/15 text-[#FF3B30] border-[#FF3B30]' 
                                : p.severity === 'Vulnerable'
                                ? 'bg-[#FF3B30]/10 text-[#FF3B30] border-[#FF3B30]/30'
                                : p.severity === 'Weak'
                                ? 'bg-amber-500/10 text-amber-500 border-amber-500/30'
                                : 'bg-emerald-500/10 text-emerald-400 border-emerald-400/20'
                            }`}>
                              {p.severity}
                            </span>
                          </td>
                        </tr>
                        {p.vulnerabilityDetails && (
                          <tr className="bg-[#FF3B30]/2">
                            <td colSpan={5} className="p-2.5 px-3 border-t border-dashed border-[#FF3B30]/20 text-[10px] text-[#FF3B30]/80">
                              <span className="font-extrabold uppercase mr-1">[VULN FLAG]:</span>
                              {p.vulnerabilityDetails}
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                </tbody>
              </table>
              {(!auditResult.ports || auditResult.ports.length === 0) && (
                <div className="text-center py-6 text-white/40 italic">
                  No scan result database parsed for ports. Generate metrics via the powershell run wrapper.
                </div>
              )}
            </div>
          </div>

          {/* Interactive NMAP terminal simulator */}
          <div className="lg:col-span-5 flex flex-col justify-between bg-[#050505] border border-white/10 p-5 rounded space-y-4">
            <div>
              <div className="flex items-center justify-between border-b border-white/10 pb-2.5 mb-3.5">
                <span className="text-xs font-black text-white uppercase tracking-widest font-mono flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-emerald-400" />
                  NMAP Port Scanner Engine
                </span>
                <span className="text-[9px] bg-emerald-500/10 text-emerald-400 border border-emerald-400/20 font-mono px-2 py-0.5 uppercase tracking-wide">
                  INTEGRATED v7.92
                </span>
              </div>

              <div className="text-xs font-mono space-y-3">
                <div className="space-y-1">
                  <label className="text-white/40 uppercase text-[9px] font-black tracking-wider block">Target Host IP</label>
                  <input 
                    type="text" 
                    value={nmapTarget}
                    onChange={(e) => setNmapTarget(e.target.value)}
                    placeholder="e.g. 10.140.10.82"
                    className="w-full bg-[#0a0a0a] border border-white/15 text-white p-2.5 rounded font-mono text-xs focus:outline-none focus:border-white transition-all animate-none"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="text-white/40 uppercase text-[9px] font-black tracking-wider block">Scan Arguments</label>
                    <select
                      value={scanType}
                      onChange={(e) => setScanType(e.target.value)}
                      className="w-full bg-[#0a0a0a] border border-white/15 text-white p-2.5 rounded font-mono text-xs focus:outline-none focus:border-white"
                    >
                      <option value="-sS -sV -O">-sS -sV (Syn + Service + OS)</option>
                      <option value="-sT -sV">-sT -sV (Full TCP Connect)</option>
                      <option value="-p- -sV">-p- (Scan All 65535 Ports)</option>
                      <option value="-sU">-sU (UDP Scan Mode)</option>
                    </select>
                  </div>

                  <div className="space-y-1">
                    <label className="text-white/40 uppercase text-[9px] font-black tracking-wider block">Timing Template</label>
                    <select
                      value={scanSpeed}
                      onChange={(e) => setScanSpeed(e.target.value)}
                      className="w-full bg-[#0a0a0a] border border-white/15 text-white p-2.5 rounded font-mono text-xs focus:outline-none focus:border-white"
                    >
                      <option value="-T4">-T4 (Aggressive Timing)</option>
                      <option value="-T3">-T3 (Normal Timing)</option>
                      <option value="-T5">-T5 (Insane Speed limit)</option>
                      <option value="-T2">-T2 (Polite / Stealth)</option>
                    </select>
                  </div>
                </div>

                <div className="pt-2">
                  <button
                    onClick={handleNmapScan}
                    disabled={isScanning}
                    className="w-full bg-white hover:bg-white/90 disabled:bg-white/20 disabled:text-white/40 text-black font-black uppercase text-xs py-3 tracking-widest flex items-center justify-center gap-2 transition"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    {isScanning ? 'Scanner Running...' : 'Execute Live NMAP Scan'}
                  </button>
                </div>
              </div>
            </div>

            {/* Terminal output box */}
            <div className="border border-white/10 rounded overflow-hidden">
              <div className="bg-white/5 px-3 py-1.5 flex items-center justify-between border-b border-white/10">
                <span className="text-[10px] font-mono uppercase text-white/50 tracking-wider">Shell terminal Console</span>
                <span className="inline-block w-2.5 h-2.5 rounded-full bg-[#FF3B30]" />
              </div>
              
              <div className="h-44 bg-black text-[#58b277] p-3 overflow-y-auto font-mono text-[10px] space-y-1 text-left select-all leading-normal">
                {scanTerminalLogs.length === 0 && !isScanning && (
                  <div className="text-white/30 text-center flex flex-col items-center justify-center h-full space-y-2">
                    <Terminal className="w-5 h-5 opacity-40 text-white" />
                    <span>Nmap engine online. Ready to probe network path {nmapTarget}.</span>
                  </div>
                )}
                {scanTerminalLogs.map((log, index) => (
                  <div key={index} className="whitespace-pre-wrap font-mono">
                    {log}
                  </div>
                ))}
                {isScanning && (
                  <div className="flex items-center gap-1.5 text-white pt-1">
                    <span className="inline-block w-1.5 h-3 bg-white animate-pulse"></span>
                    <span className="text-xs">SCANNING: {scanProgress}% complete...</span>
                  </div>
                )}
              </div>
            </div>

          </div>
        </div>
      </div>

      {/* Additional Endpoint Hardening details banner */}
      <div className="bg-[#0f0f0f] border-2 border-white/20 p-6 text-left hover:border-white transition-all">
        <h3 className="text-xs font-black text-white uppercase tracking-[0.15em] border-b border-white/15 pb-3 mb-5 font-mono">
          System Guard Registry Extensions
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
          <div className="bg-[#050505] p-5 border border-white/10 space-y-2">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <span className="text-xs font-black text-white uppercase tracking-wide">Host Firewall State</span>
              {getStatusBadge(auditResult.additional.firewallEnabled.status, auditResult.additional.firewallEnabled.value)}
            </div>
            <p className="text-[10px] text-white/50 leading-relaxed pt-1">
              {auditResult.additional.firewallEnabled.details}
            </p>
          </div>

          <div className="bg-[#050505] p-5 border border-white/10 space-y-2">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <span className="text-xs font-black text-white uppercase tracking-wide">RDP Protection (NLA)</span>
              {getStatusBadge(auditResult.additional.rdpNlaEnabled.status, auditResult.additional.rdpNlaEnabled.value)}
            </div>
            <p className="text-[10px] text-white/50 leading-relaxed pt-1">
              {auditResult.additional.rdpNlaEnabled.details}
            </p>
          </div>

          <div className="bg-[#050505] p-5 border border-white/10 space-y-2">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <span className="text-xs font-black text-white uppercase tracking-wide">LSA Credential Isolation</span>
              {getStatusBadge(auditResult.additional.credentialGuard.status, auditResult.additional.credentialGuard.value)}
            </div>
            <p className="text-[10px] text-white/50 leading-relaxed pt-1">
              {auditResult.additional.credentialGuard.details}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

