import React, { useState, useEffect } from 'react';
import { Shield, LayoutDashboard, Terminal, Settings, Upload, CheckCircle, Flame, AlertCircle, HelpCircle, HardDrive, RefreshCw, Clock, Database, Wrench, Users, UserCheck, ShieldCheck, Lock, LogIn, LogOut, Stethoscope, Heart, CheckCircle2, ArrowRight, Sparkles, Laptop, FileText, Layers, Zap, Palette, Globe } from 'lucide-react';
import { mockEndpoints, remediations } from './remediationData';
import { Endpoint, AppTheme } from './types';
import EndpointList from './components/EndpointList';
import EndpointAuditView from './components/EndpointAuditView';
import EndpointInventoryTable from './components/EndpointInventoryTable';
import ScriptGenerator from './components/ScriptGenerator';
import UploadCenter from './components/UploadCenter';
import SecurityOverviewStats from './components/SecurityOverviewStats';
import RemediationGuides from './components/RemediationGuides';
import CsvWeaknessExplorer from './components/CsvWeaknessExplorer';
import ExeDeploymentConsole from './components/ExeDeploymentConsole';
import BulkRemediationConsole from './components/BulkRemediationConsole';
import WinUtilAutoFixModal from './components/WinUtilAutoFixModal';
import SystemFastModal from './components/SystemFastModal';
import DashboardConfigExportModal from './components/DashboardConfigExportModal';
import GitHubSyncModal from './components/GitHubSyncModal';
import LoginModal from './components/LoginModal';
import UserManagementModal from './components/UserManagementModal';
import AccessRestrictedModal from './components/AccessRestrictedModal';
import ResultsView from './components/ResultsView';
import AiThinkingSecOpsAssistant from './components/AiThinkingSecOpsAssistant';
import AiAutoFixModal from './components/AiAutoFixModal';
import { StaffUser } from './types/userManagement';
import { getCurrentSessionUser, INITIAL_DEFAULT_USERS, logoutUser } from './utils/userManagementStore';
import { get60VulnerabilitiesForEndpoint, calculate60DynamicScore } from './data/vulnerabilities60';

export default function App() {
  // Staff User Management & Auth States
  const [currentUser, setCurrentUser] = useState<StaffUser>(() => {
    return getCurrentSessionUser() || INITIAL_DEFAULT_USERS[0];
  });
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(true);
  const [isUserMgmtModalOpen, setIsUserMgmtModalOpen] = useState(false);
  const [isRestrictedModalOpen, setIsRestrictedModalOpen] = useState(false);
  const [restrictedInfo, setRestrictedInfo] = useState<{ requiredRole: 'superadmin' | 'admin'; actionName: string }>({
    requiredRole: 'superadmin',
    actionName: 'Action Execution'
  });

  const handleLogout = () => {
    logoutUser();
    const guestUser = INITIAL_DEFAULT_USERS.find(u => u.role === 'enduser') || INITIAL_DEFAULT_USERS[2] || INITIAL_DEFAULT_USERS[0];
    setCurrentUser(guestUser);
    setIsLoginModalOpen(true);
  };

  const checkPrivilegeAndRun = (requiredRole: 'superadmin' | 'admin', actionName: string, callback: () => void) => {
    if (!currentUser) {
      setIsLoginModalOpen(true);
      return;
    }
    if (currentUser.role === 'superadmin') {
      callback();
      return;
    }
    if (requiredRole === 'admin' && currentUser.role === 'admin') {
      callback();
      return;
    }
    setRestrictedInfo({ requiredRole, actionName });
    setIsRestrictedModalOpen(true);
  };
  const generateDefaultEndpoints = (): Endpoint[] => {
    return mockEndpoints.map(e => {
      const initialEndpointObj: Endpoint = {
        ...e,
        remediatedVulnerabilities: [],
        excludedVulnerabilities: []
      };
      
      const baselineScore = calculate60DynamicScore(initialEndpointObj);
      const list = get60VulnerabilitiesForEndpoint(initialEndpointObj);
      let crit = 0, high = 0, med = 0, low = 0;
      list.forEach(item => {
        if (item.status === 'failed') {
          if (item.vulnerability.severity === 'Critical') crit++;
          else if (item.vulnerability.severity === 'High') high++;
          else if (item.vulnerability.severity === 'Medium') med++;
          else low++;
        }
      });

      return {
        ...initialEndpointObj,
        overallScore: baselineScore,
        criticalCount: crit,
        highCount: high,
        mediumCount: med,
        lowCount: low,
        status: baselineScore > 85 ? 'secure' as const : baselineScore > 60 ? 'warning' as const : 'vulnerable' as const,
        firstScanData: JSON.parse(JSON.stringify(e.scanData)),
        firstScanScore: baselineScore
      };
    });
  };

  const [endpoints, setEndpoints] = useState<Endpoint[]>(() => {
    // Clear saved inventory data as requested by user
    const hasCleared = localStorage.getItem('inventory_saved_data_cleared');
    if (!hasCleared) {
      localStorage.removeItem('endpoint_postures');
      localStorage.setItem('inventory_saved_data_cleared', 'true');
      localStorage.setItem('endpoint_postures', '[]');
      return [];
    }

    const stored = localStorage.getItem('endpoint_postures');
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed)) {
          return parsed;
        }
      } catch (e) {
        console.warn("Could not load stored database postures", e);
      }
    }
    return [];
  });

  const [selectedEndpointId, setSelectedEndpointId] = useState<string>(endpoints[0]?.id || '');

  const handleClearAllEndpoints = () => {
    localStorage.removeItem('endpoint_postures');
    localStorage.setItem('endpoint_postures', '[]');
    localStorage.setItem('inventory_saved_data_cleared', 'true');
    setEndpoints([]);
    setSelectedEndpointId('');
  };

  const handleRestoreDefaultEndpoints = () => {
    const defaults = generateDefaultEndpoints();
    localStorage.removeItem('inventory_saved_data_cleared');
    localStorage.setItem('endpoint_postures', JSON.stringify(defaults));
    setEndpoints(defaults);
    if (defaults.length > 0) {
      setSelectedEndpointId(defaults[0].id);
    }
  };
  
  // Alert Threshold Configuration State (endpoints below this score are automatically flagged for urgent manual review)
  const [alertThreshold, setAlertThreshold] = useState<number>(() => {
    const saved = localStorage.getItem('alert_threshold');
    return saved ? Number(saved) : 75;
  });

  useEffect(() => {
    localStorage.setItem('alert_threshold', String(alertThreshold));
  }, [alertThreshold]);

  // 3-Step Program Lifecycle Navigation State
  const [programStep, setProgramStep] = useState<'diagnose' | 'improve' | 'results'>('diagnose');
  const [diagnoseSubTab, setDiagnoseSubTab] = useState<'inventory' | 'upload'>('inventory');
  const [improveSubTab, setImproveSubTab] = useState<'script' | 'winutil' | 'exe-deploy' | 'guides' | 'cve-catalog' | 'bulk-remediate'>('script');

  const [currentTime, setCurrentTime] = useState<string>('08:42:15');
  const [isWinUtilModalOpen, setIsWinUtilModalOpen] = useState(false);
  const [isSystemFastModalOpen, setIsSystemFastModalOpen] = useState(false);
  const [isExportConfigModalOpen, setIsExportConfigModalOpen] = useState(false);
  const [isGitHubModalOpen, setIsGitHubModalOpen] = useState(false);
  const [isAiThinkingModalOpen, setIsAiThinkingModalOpen] = useState(false);
  const [isAiAutoFixModalOpen, setIsAiAutoFixModalOpen] = useState(false);

  // Global Theme & Classic View state
  const [appTheme, setAppTheme] = useState<AppTheme>(() => {
    return (localStorage.getItem('secops_app_theme') as AppTheme) || 'cyber-dark';
  });

  useEffect(() => {
    localStorage.setItem('secops_app_theme', appTheme);
  }, [appTheme]);

  // Persist endpoints posture state changes
  useEffect(() => {
    localStorage.setItem('endpoint_postures', JSON.stringify(endpoints));
  }, [endpoints]);

  // Real-time ticking clock for premium feeling
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.toTimeString().split(' ')[0]);
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const selectedEndpoint = endpoints.find(e => e.id === selectedEndpointId) || endpoints[0];

  const handleAutoFixEndpoint = (endpointId: string) => {
    setEndpoints(prev => prev.map(e => {
      if (e.id === endpointId) {
        const list = get60VulnerabilitiesForEndpoint(e);
        const excludeList = e.excludedVulnerabilities || [];
        
        // Remediate all items that are NOT excluded
        const allUnresolvedNonExcluded = list
          .filter(item => item.baselineStatus !== 'passed' && !excludeList.includes(item.vulnerability.id))
          .map(item => item.vulnerability.id);

        const updatedRemediated = Array.from(new Set([
          ...(e.remediatedVulnerabilities || []),
          ...allUnresolvedNonExcluded
        ]));

        const tempEndpoint = {
          ...e,
          remediatedVulnerabilities: updatedRemediated
        };

        const score = calculate60DynamicScore(tempEndpoint);
        const updatedList = get60VulnerabilitiesForEndpoint(tempEndpoint);
        let crit = 0, high = 0, med = 0, low = 0;
        updatedList.forEach(item => {
          if (item.status === 'failed') {
            if (item.vulnerability.severity === 'Critical') crit++;
            else if (item.vulnerability.severity === 'High') high++;
            else if (item.vulnerability.severity === 'Medium') med++;
            else low++;
          }
        });

        // Also update standard scanData for retroactive compat
        const updatedScanData = {
          ...e.scanData,
          smb: {
            ...e.scanData.smb,
            smb1Enabled: { ...e.scanData.smb.smb1Enabled, status: 'passed' as const, value: 'Disabled / Safe', details: 'SMBv1 is verified as fully disabled on the system.' },
            smbSigningRequired: { ...e.scanData.smb.smbSigningRequired, status: 'passed' as const, value: 'CONFIGURED', details: 'SMB digital signing is enforced on all Server and Client sessions.' },
            smbEncryptionEnabled: { ...e.scanData.smb.smbEncryptionEnabled, status: 'passed' as const, value: 'ENABLED', details: 'SMB Transport payload encryption is active.' }
          }
        };

        return {
          ...tempEndpoint,
          overallScore: score,
          criticalCount: crit,
          highCount: high,
          mediumCount: med,
          lowCount: low,
          status: score > 85 ? 'secure' as const : score > 60 ? 'warning' as const : 'vulnerable' as const,
          scanData: updatedScanData
        };
      }
      return e;
    }));
  };

  const handleToggleVulnerabilityRemediation = (endpointId: string, vulnId: number) => {
    setEndpoints(prev => prev.map(e => {
      if (e.id === endpointId) {
        const remediated = e.remediatedVulnerabilities || [];
        const isRemediated = remediated.includes(vulnId);
        const updatedRemediated = isRemediated
          ? remediated.filter(id => id !== vulnId)
          : [...remediated, vulnId];

        const updatedExcluded = (e.excludedVulnerabilities || []).filter(id => id !== vulnId);

        const tempEndpoint = {
          ...e,
          remediatedVulnerabilities: updatedRemediated,
          excludedVulnerabilities: updatedExcluded
        };

        const score = calculate60DynamicScore(tempEndpoint);
        const list = get60VulnerabilitiesForEndpoint(tempEndpoint);
        let crit = 0, high = 0, med = 0, low = 0;
        list.forEach(item => {
          if (item.status === 'failed') {
            if (item.vulnerability.severity === 'Critical') crit++;
            else if (item.vulnerability.severity === 'High') high++;
            else if (item.vulnerability.severity === 'Medium') med++;
            else low++;
          }
        });

        return {
          ...tempEndpoint,
          overallScore: score,
          criticalCount: crit,
          highCount: high,
          mediumCount: med,
          lowCount: low,
          status: score > 85 ? 'secure' as const : score > 60 ? 'warning' as const : 'vulnerable' as const
        };
      }
      return e;
    }));
  };

  const handleToggleVulnerabilityExclusion = (endpointId: string, vulnId: number) => {
    setEndpoints(prev => prev.map(e => {
      if (e.id === endpointId) {
        const excluded = e.excludedVulnerabilities || [];
        const isExcluded = excluded.includes(vulnId);
        const updatedExcluded = isExcluded
          ? excluded.filter(id => id !== vulnId)
          : [...excluded, vulnId];

        const updatedRemediated = (e.remediatedVulnerabilities || []).filter(id => id !== vulnId);

        const tempEndpoint = {
          ...e,
          remediatedVulnerabilities: updatedRemediated,
          excludedVulnerabilities: updatedExcluded
        };

        const score = calculate60DynamicScore(tempEndpoint);
        const list = get60VulnerabilitiesForEndpoint(tempEndpoint);
        let crit = 0, high = 0, med = 0, low = 0;
        list.forEach(item => {
          if (item.status === 'failed') {
            if (item.vulnerability.severity === 'Critical') crit++;
            else if (item.vulnerability.severity === 'High') high++;
            else if (item.vulnerability.severity === 'Medium') med++;
            else low++;
          }
        });

        return {
          ...tempEndpoint,
          overallScore: score,
          criticalCount: crit,
          highCount: high,
          mediumCount: med,
          lowCount: low,
          status: score > 85 ? 'secure' as const : score > 60 ? 'warning' as const : 'vulnerable' as const
        };
      }
      return e;
    }));
  };

  const handleRecaptureBaseline = (endpointId: string) => {
    setEndpoints(prev => prev.map(e => {
      if (e.id === endpointId) {
        return {
          ...e,
          firstScanData: JSON.parse(JSON.stringify(e.scanData)),
          firstScanScore: e.overallScore
        };
      }
      return e;
    }));
  };

  const handleNewUpload = (newEndpoint: Endpoint) => {
    // Ensure baseline holds first scanned details
    const formatted: Endpoint = {
      ...newEndpoint,
      firstScanData: newEndpoint.firstScanData || JSON.parse(JSON.stringify(newEndpoint.scanData)),
      firstScanScore: newEndpoint.firstScanScore || newEndpoint.overallScore
    };

    // Add new scanned endpoint or overwrite if hostname matches
    setEndpoints(prev => {
      const existsIdx = prev.findIndex(item => item.name.toLowerCase() === formatted.name.toLowerCase());
      if (existsIdx >= 0) {
        const copy = [...prev];
        copy[existsIdx] = formatted;
        return copy;
      }
      return [formatted, ...prev];
    });
    setSelectedEndpointId(formatted.id);
    setProgramStep('diagnose');
    setDiagnoseSubTab('inventory');
  };

  const resetMockCollections = () => {
    localStorage.removeItem('endpoint_postures');
    const defaults = mockEndpoints.map(e => ({
      ...e,
      firstScanData: JSON.parse(JSON.stringify(e.scanData)),
      firstScanScore: e.overallScore
    }));
    setEndpoints(defaults);
    setSelectedEndpointId(defaults[0].id);
  };

  return (
    <div className={`min-h-screen flex flex-col font-sans antialiased selection:bg-amber-400 selection:text-black transition-colors duration-500 ${
      (appTheme === 'clean-light' || appTheme === 'classic-light')
        ? 'bg-[#f8fafc] text-slate-900'
        : (appTheme === 'enterprise-navy' || appTheme === 'classic-sysadmin')
        ? 'bg-[#071322] text-[#f1f5f9]'
        : appTheme === 'terminal-emerald'
        ? 'bg-[#040806] text-[#e2e8f0]'
        : programStep === 'diagnose'
        ? 'bg-[#030d1a] text-[#F5F5F5]'
        : programStep === 'improve'
        ? 'bg-[#1a0c02] text-[#F5F5F5]'
        : 'bg-[#02180e] text-[#F5F5F5]'
    }`}>
      
      {/* Header Banner - SmartPro Consultancy Premium Branding */}
      <header className={`border-b transition-colors duration-500 pt-7 pb-5 relative overflow-hidden ${
        (appTheme === 'clean-light' || appTheme === 'classic-light')
          ? 'bg-white border-slate-200 shadow-sm text-slate-900'
          : (appTheme === 'enterprise-navy' || appTheme === 'classic-sysadmin')
          ? 'bg-gradient-to-r from-[#0a1c33] via-[#102a4c] to-[#0a1c33] border-blue-500/30 shadow-lg shadow-blue-950/40 text-white'
          : appTheme === 'terminal-emerald'
          ? 'bg-gradient-to-r from-[#06120b] via-[#0b1f13] to-[#06120b] border-emerald-500/40 shadow-lg shadow-emerald-950/40 text-emerald-100'
          : programStep === 'diagnose'
          ? 'bg-gradient-to-r from-[#031525] via-[#082238] to-[#04111f] border-cyan-500/40 shadow-lg shadow-cyan-950/50 text-white'
          : programStep === 'improve'
          ? 'bg-gradient-to-r from-[#1c1203] via-[#2d1b05] to-[#170e02] border-amber-500/40 shadow-lg shadow-amber-950/50 text-white'
          : 'bg-gradient-to-r from-[#021810] via-[#05261a] to-[#02130c] border-emerald-500/40 shadow-lg shadow-emerald-950/50 text-white'
      }`}>
        {/* Subtle decorative elements */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row md:items-center justify-between gap-6 relative z-10">
          
          {/* Logo and Brand Title block */}
          <div className="flex flex-col sm:flex-row items-center sm:items-start gap-4 text-center sm:text-left">
            
            {/* Custom High-Fidelity SVG Shield matching the user's uploaded metallic shield */}
            <div className="relative w-18 h-18 flex-shrink-0 bg-gradient-to-br from-[#0c2440] to-[#1a4473] p-1 rounded-xl border border-amber-400/40 shadow-xl shadow-blue-950/40 group">
              <div className="absolute inset-0 bg-gradient-to-r from-amber-400/10 to-transparent rounded-xl animate-pulse" />
              <svg viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full drop-shadow-[0_2px_8px_rgba(234,179,8,0.2)]">
                {/* Shield background */}
                <path d="M50 5 L85 18 V45 C85 70 50 90 50 90 C50 90 15 70 15 45 V18 L50 5 Z" fill="#0d1b2a" stroke="#eab308" strokeWidth="4" strokeLinejoin="round" />
                {/* Nested gold accent path */}
                <path d="M50 12 L78 22 V45 C78 65 50 81 50 81 C50 81 22 65 22 45 V22 L50 12 Z" stroke="#c5a059" strokeWidth="2" strokeDasharray="3 2" strokeLinejoin="round" />
                {/* Metallic Inner 'S' shape */}
                <path d="M60 30 C60 25 40 25 40 32 C40 40 60 40 60 48 C60 55 40 55 40 50" stroke="#f1f5f9" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" />
                <path d="M60 30 C60 25 40 25 40 32 C40 40 60 40 60 48 C60 55 40 55 40 50" stroke="#eab308" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                {/* Shield core badge icon */}
                <circle cx="50" cy="50" r="10" fill="#0c2440" stroke="#eab308" strokeWidth="1.5" />
                <path d="M47 50 L49 52 L53 48" stroke="#eab308" strokeWidth="1.5" strokeLinecap="round" />
              </svg>
            </div>

            <div className="flex flex-col">
              <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2">
                <span className="text-amber-400 font-extrabold text-[10px] uppercase tracking-[0.25em] bg-amber-400/10 border border-amber-400/30 px-2 py-0.5 rounded flex items-center gap-1.5 font-mono">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-ping"></span>
                  SecOps Enterprise Hardening Engine
                </span>
                <span className="text-blue-400 font-bold text-[10px] uppercase tracking-[0.2em] bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 rounded">
                  National GPO Verification
                </span>
              </div>
              
              <h1 className="leading-none mt-2 text-white font-sans tracking-tight">
                <span className="font-bold text-[34px]">Smartpro</span>{" "}
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-amber-400 via-yellow-200 to-amber-500 text-[24px] font-medium tracking-wide">ENDPOINT GUARD</span>
              </h1>
              
              <p className="text-white/60 text-[11px] sm:text-xs uppercase tracking-widest font-semibold mt-1.5">
                CORPORATE HARDENING CONSOLE & AUDITING SUITE
              </p>
              
              {/* Contact Information block precisely integrated */}
              <div className="flex flex-wrap items-center justify-center sm:justify-start gap-x-3 gap-y-1 text-white/40 text-[10px] font-mono mt-2 bg-black/30 border border-white/5 rounded px-2.5 py-1 w-fit">
                <span className="text-amber-400/70 font-semibold">📍 Abu Dhabi, UAE</span>
                <span className="text-white/20">|</span>
                <span>📧 <a href="mailto:info@smartpro.ae" className="hover:text-amber-300 transition">info@smartpro.ae</a></span>
                <span className="text-white/20">|</span>
                <span>📞 <a href="tel:+971524846770" className="hover:text-amber-300 transition">+971 52 484 6770</a></span>
              </div>
            </div>

          </div>

          {/* Right side utilities: Staff Profile, Clock, post-remediation reset, and corporate sign-off */}
          <div className="flex flex-col items-center md:items-end justify-between md:justify-end gap-y-2.5 w-full md:w-auto">
            
            {/* Staff User Level Profile Badge */}
            <div className="flex items-center gap-2.5 bg-slate-900/90 border border-cyan-500/40 rounded-xl px-3.5 py-1.5 shadow-xl font-mono">
              <div className="p-1.5 rounded-lg bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <div className="text-left">
                <div className="text-xs font-bold text-slate-100 flex items-center gap-1.5">
                  <span>{currentUser.fullName}</span>
                  <span className={`text-[9px] font-black uppercase px-1.5 py-0.2 rounded border tracking-wider ${
                    currentUser.role === 'superadmin' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' :
                    currentUser.role === 'admin' ? 'bg-blue-500/20 text-blue-300 border-blue-500/40' :
                    'bg-amber-500/20 text-amber-300 border-amber-500/40'
                  }`}>
                    {currentUser.role}
                  </span>
                </div>
                <div className="text-[10px] text-cyan-400">
                  Login Runs: <strong className="text-white">{currentUser.loginCount}</strong> • Level: <strong className="text-cyan-200 uppercase">{currentUser.role}</strong>
                </div>
              </div>

              <div className="flex items-center gap-1.5 ml-1 border-l border-slate-700 pl-2">
                <button
                  onClick={() => setIsUserMgmtModalOpen(true)}
                  className="px-2 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-[10px] font-bold uppercase transition cursor-pointer flex items-center gap-1"
                  title="Open Staff Directory & 3-Tier Privilege Setup"
                >
                  <Users className="w-3 h-3" />
                  Staff & Privileges
                </button>
                <button
                  onClick={() => setIsLoginModalOpen(true)}
                  className="px-2 py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 text-[10px] font-bold uppercase transition cursor-pointer flex items-center gap-1"
                  title="Log In or Switch Staff Account"
                >
                  <LogIn className="w-3 h-3 text-emerald-400" />
                  Log In / Switch
                </button>
                <button
                  onClick={handleLogout}
                  className="px-2 py-1 rounded bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 text-[10px] font-bold uppercase transition cursor-pointer flex items-center gap-1"
                  title="Log out current session user"
                >
                  <LogOut className="w-3 h-3 text-red-400" />
                  Log Out
                </button>
              </div>
            </div>

            <div className="text-center md:text-right">
              <div className="text-2xl sm:text-3.5xl font-black tracking-tight flex items-center justify-center md:justify-end gap-2 font-mono text-[#F5F5F5]">
                <Clock className="w-5 h-5 text-amber-400" />
                {currentTime}
              </div>
              <div className="text-[9px] uppercase tracking-widest text-white/50 font-bold mt-0.5">
                Active System Scan Time
              </div>
            </div>
            
            {/* Global Visual Theme Switcher */}
            <div className="flex items-center gap-1 bg-black/60 border border-white/20 rounded-lg p-1 font-mono text-xs shadow-md">
              <span className="text-[10px] text-white/70 font-bold px-1.5 flex items-center gap-1">
                <Palette className="w-3 h-3 text-cyan-400" />
                Theme:
              </span>
              <button
                type="button"
                onClick={() => setAppTheme('cyber-dark')}
                className={`px-2 py-1 rounded text-[10px] font-bold transition cursor-pointer flex items-center gap-1 ${
                  appTheme === 'cyber-dark'
                    ? 'bg-cyan-500/30 text-cyan-300 border border-cyan-500/50 shadow-sm'
                    : 'text-white/60 hover:text-white'
                }`}
                title="Deep Charcoal & Cyan Cyber Dark Theme"
              >
                <Zap className="w-2.5 h-2.5 text-cyan-400" />
                Cyber Dark
              </button>
              <button
                type="button"
                onClick={() => setAppTheme('enterprise-navy')}
                className={`px-2 py-1 rounded text-[10px] font-bold transition cursor-pointer flex items-center gap-1 ${
                  appTheme === 'enterprise-navy' || appTheme === 'classic-sysadmin'
                    ? 'bg-blue-600 text-white border border-blue-400 font-black shadow-sm'
                    : 'text-white/60 hover:text-white'
                }`}
                title="Corporate Enterprise Active Directory / Navy Blue Console"
              >
                <Laptop className="w-2.5 h-2.5 text-blue-300" />
                Enterprise Navy
              </button>
              <button
                type="button"
                onClick={() => setAppTheme('clean-light')}
                className={`px-2 py-1 rounded text-[10px] font-bold transition cursor-pointer flex items-center gap-1 ${
                  appTheme === 'clean-light' || appTheme === 'classic-light'
                    ? 'bg-white text-slate-900 border border-slate-300 font-black shadow-sm'
                    : 'text-white/60 hover:text-white'
                }`}
                title="Clean High-Contrast Daylight Enterprise Mode"
              >
                <Layers className="w-2.5 h-2.5 text-amber-500" />
                Clean Daylight
              </button>
              <button
                type="button"
                onClick={() => setAppTheme('terminal-emerald')}
                className={`px-2 py-1 rounded text-[10px] font-bold transition cursor-pointer flex items-center gap-1 ${
                  appTheme === 'terminal-emerald'
                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-500 font-black shadow-sm'
                    : 'text-white/60 hover:text-white'
                }`}
                title="Retro SysAdmin Terminal Phosphor Green Mode"
              >
                <Terminal className="w-2.5 h-2.5 text-emerald-400" />
                Terminal
              </button>
            </div>

            <div className="flex flex-wrap items-center justify-center md:justify-end gap-2">
              <button
                onClick={() => setIsSystemFastModalOpen(true)}
                className="flex items-center gap-1.5 bg-gradient-to-r from-amber-400 via-amber-300 to-yellow-400 hover:from-amber-300 hover:to-yellow-300 text-black px-3.5 py-2 text-xs font-black uppercase tracking-wider transition rounded shadow-lg shadow-amber-950/40 cursor-pointer select-none border border-amber-300"
                title="Windows 10/11 Pro System Fast & Safe Speed Optimization Suite"
              >
                <Zap className="w-3.5 h-3.5 text-black fill-black" />
                ⚡ System Fast
              </button>

              <button
                onClick={() => setIsAiThinkingModalOpen(true)}
                className="flex items-center gap-1.5 bg-gradient-to-r from-cyan-400 to-cyan-500 hover:from-cyan-300 hover:to-cyan-400 text-black px-3.5 py-2 text-xs font-black uppercase tracking-wider transition rounded shadow-lg shadow-cyan-950/40 cursor-pointer select-none border border-cyan-300"
                title="Launch Gemini 3.1 Pro High-Thinking Reasoning Architect"
              >
                <Sparkles className="w-3.5 h-3.5 text-black animate-pulse" />
                AI SecOps Co-Pilot
              </button>

              <button
                onClick={() => checkPrivilegeAndRun('admin', 'GitHub Repository Live Sync', () => setIsGitHubModalOpen(true))}
                className="flex items-center gap-1.5 bg-emerald-500 hover:bg-emerald-600 text-black px-3.5 py-2 text-xs font-black uppercase tracking-wider transition rounded shadow-lg shadow-emerald-950/20 cursor-pointer select-none"
                title="GitHub Repository Upload & Live Auto-Sync Options"
              >
                <svg className="w-3.5 h-3.5 fill-current text-black" viewBox="0 0 24 24">
                  <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                </svg>
                GitHub Live Sync
              </button>

              <button
                onClick={() => setIsExportConfigModalOpen(true)}
                className="flex items-center gap-1.5 bg-amber-500 hover:bg-amber-600 text-black px-3.5 py-2 text-xs font-black uppercase tracking-wider transition rounded shadow-lg shadow-amber-950/20 cursor-pointer select-none"
                title="Export or Copy Full Dashboard Configuration & Script Settings"
              >
                <Database className="w-3.5 h-3.5 text-black" />
                Export Dashboard Config
              </button>

              <button
                onClick={() => checkPrivilegeAndRun('superadmin', 'Launch WinUtil System AutoFix', () => setIsWinUtilModalOpen(true))}
                className="flex items-center gap-1.5 bg-emerald-500 hover:bg-emerald-600 text-black px-3.5 py-2 text-xs font-black uppercase tracking-wider transition rounded shadow-lg shadow-emerald-950/20 cursor-pointer select-none"
                title="Launch Chris Titus WinUtil & Auto Fix Common Errors"
              >
                <Wrench className="w-3.5 h-3.5 text-black" />
                WinUtil Auto-Fix
              </button>

              <button
                onClick={() => checkPrivilegeAndRun('superadmin', 'Reset Posture Database Baseline', resetMockCollections)}
                className="flex items-center gap-1 bg-white/10 hover:bg-white/20 text-white px-3 py-2 text-xs font-black uppercase tracking-wider transition rounded cursor-pointer select-none border border-white/15"
                title="Reset posture baselines"
              >
                <RefreshCw className="w-3.5 h-3.5 text-amber-400" />
                Reset
              </button>
            </div>
          </div>
          
        </div>
      </header>

      {/* Main 3-Step Program Lifecycle Navigation Header */}
      <nav className={`border-b sticky top-0 z-40 shadow-2xl transition-colors duration-700 ${
        programStep === 'diagnose'
          ? 'bg-[#021124]/95 border-cyan-500/40 shadow-cyan-950/80'
          : programStep === 'improve'
          ? 'bg-[#241203]/95 border-amber-500/40 shadow-amber-950/80'
          : 'bg-[#032114]/95 border-emerald-500/40 shadow-emerald-950/80'
      }`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          
          {/* Primary Program Stage Stepper Buttons */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 py-3.5 border-b border-white/10">
            
            {/* Step 1 – Diagnose */}
            <button
              onClick={() => setProgramStep('diagnose')}
              className={`p-3.5 rounded-xl border text-left transition-all duration-300 cursor-pointer select-none relative group ${
                programStep === 'diagnose'
                  ? 'bg-gradient-to-r from-cyan-950 via-cyan-900 to-slate-900 border-2 border-cyan-400 text-white shadow-xl shadow-cyan-950/80 ring-2 ring-cyan-400/80 scale-[1.01]'
                  : 'bg-slate-950/60 border-cyan-900/30 text-cyan-200/60 hover:text-cyan-200 hover:bg-cyan-950/30 hover:border-cyan-500/40'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className={`font-mono text-xs font-black uppercase tracking-wider flex items-center gap-2 ${
                  programStep === 'diagnose' ? 'text-cyan-300 font-extrabold' : 'text-cyan-400/80'
                }`}>
                  <Stethoscope className="w-4 h-4 text-cyan-400 animate-pulse" />
                  🩺 Step 1 – Diagnose Page
                </span>
                {programStep === 'diagnose' && (
                  <span className="bg-cyan-400 text-black px-2 py-0.5 rounded text-[9px] font-black uppercase tracking-widest animate-pulse">
                    ACTIVE PAGE
                  </span>
                )}
              </div>
              <div className="text-[11px] text-cyan-100/70 mt-1.5 font-medium line-clamp-1">
                Cyan Theme • Network & Single PC Inspector
              </div>
            </button>

            {/* Step 2 – Improve */}
            <button
              onClick={() => setProgramStep('improve')}
              className={`p-3.5 rounded-xl border text-left transition-all duration-300 cursor-pointer select-none relative group ${
                programStep === 'improve'
                  ? 'bg-gradient-to-r from-amber-950 via-amber-900 to-stone-900 border-2 border-amber-400 text-white shadow-xl shadow-amber-950/80 ring-2 ring-amber-400/80 scale-[1.01]'
                  : 'bg-stone-950/60 border-amber-900/30 text-amber-200/60 hover:text-amber-200 hover:bg-amber-950/30 hover:border-amber-500/40'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className={`font-mono text-xs font-black uppercase tracking-wider flex items-center gap-2 ${
                  programStep === 'improve' ? 'text-amber-300 font-extrabold' : 'text-amber-400/80'
                }`}>
                  <Heart className="w-4 h-4 text-amber-400 fill-amber-400/30" />
                  ❤️ Step 2 – Improve Page
                </span>
                {programStep === 'improve' && (
                  <span className="bg-amber-400 text-black px-2 py-0.5 rounded text-[9px] font-black uppercase tracking-widest animate-pulse">
                    ACTIVE PAGE
                  </span>
                )}
              </div>
              <div className="text-[11px] text-amber-100/70 mt-1.5 font-medium line-clamp-1">
                Amber Theme • Hardening Tools & Auto-Fixes
              </div>
            </button>

            {/* Step 3 – Results */}
            <button
              onClick={() => setProgramStep('results')}
              className={`p-3.5 rounded-xl border text-left transition-all duration-300 cursor-pointer select-none relative group ${
                programStep === 'results'
                  ? 'bg-gradient-to-r from-emerald-950 via-emerald-900 to-zinc-900 border-2 border-emerald-400 text-white shadow-xl shadow-emerald-950/80 ring-2 ring-emerald-400/80 scale-[1.01]'
                  : 'bg-zinc-950/60 border-emerald-900/30 text-emerald-200/60 hover:text-emerald-200 hover:bg-emerald-950/30 hover:border-emerald-500/40'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className={`font-mono text-xs font-black uppercase tracking-wider flex items-center gap-2 ${
                  programStep === 'results' ? 'text-emerald-300 font-extrabold' : 'text-emerald-400/80'
                }`}>
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ✅ Step 3 – Results Page
                </span>
                {programStep === 'results' && (
                  <span className="bg-emerald-400 text-black px-2 py-0.5 rounded text-[9px] font-black uppercase tracking-widest animate-pulse">
                    ACTIVE PAGE
                  </span>
                )}
              </div>
              <div className="text-[11px] text-emerald-100/70 mt-1.5 font-medium line-clamp-1">
                Emerald Theme • Posture Verification & PDF Export
              </div>
            </button>

          </div>

          {/* Secondary Loaded Tools Bar depending on Program Step */}
          {programStep === 'diagnose' && (
            <div className="flex flex-wrap gap-2 py-2.5">
              <button
                onClick={() => setDiagnoseSubTab('inventory')}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-black uppercase tracking-wider flex items-center gap-2 transition cursor-pointer ${
                  diagnoseSubTab === 'inventory'
                    ? 'bg-cyan-500 text-black shadow font-bold'
                    : 'bg-white/5 text-white/70 hover:text-white hover:bg-white/10 border border-white/10'
                }`}
              >
                <Laptop className="w-3.5 h-3.5" />
                Network Devices & Single PC Inspector
              </button>
              <button
                onClick={() => setDiagnoseSubTab('upload')}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-black uppercase tracking-wider flex items-center gap-2 transition cursor-pointer ${
                  diagnoseSubTab === 'upload'
                    ? 'bg-cyan-500 text-black shadow font-bold'
                    : 'bg-white/5 text-white/70 hover:text-white hover:bg-white/10 border border-white/10'
                }`}
              >
                <Upload className="w-3.5 h-3.5" />
                Audit Report Upload Hub
              </button>
            </div>
          )}

          {programStep === 'improve' && (
            <div className="flex flex-wrap gap-2 py-2.5">
              <button
                onClick={() => setImproveSubTab('bulk-remediate')}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-black uppercase tracking-wider flex items-center gap-2 transition cursor-pointer ${
                  improveSubTab === 'bulk-remediate'
                    ? 'bg-amber-400 text-black font-bold shadow'
                    : 'bg-amber-500/10 text-amber-300 hover:bg-amber-500/20 border border-amber-500/40'
                }`}
              >
                <Layers className="w-3.5 h-3.5 text-amber-400" />
                Bulk Sequenced Remediation
                <span className="bg-amber-500/20 text-amber-300 px-1.5 py-0.2 rounded text-[9px] font-mono border border-amber-500/40">NEW</span>
              </button>

              <button
                onClick={() => setImproveSubTab('script')}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-black uppercase tracking-wider flex items-center gap-2 transition cursor-pointer ${
                  improveSubTab === 'script'
                    ? 'bg-amber-400 text-black font-bold shadow'
                    : 'bg-white/5 text-white/70 hover:text-white hover:bg-white/10 border border-white/10'
                }`}
              >
                <Terminal className="w-3.5 h-3.5" />
                PowerShell Fix Script Generator
              </button>

              <button
                onClick={() => {
                  setImproveSubTab('winutil');
                  checkPrivilegeAndRun('superadmin', 'Launch WinUtil System AutoFix', () => setIsWinUtilModalOpen(true));
                }}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-black uppercase tracking-wider flex items-center gap-2 transition cursor-pointer ${
                  improveSubTab === 'winutil'
                    ? 'bg-emerald-400 text-black font-bold shadow'
                    : 'bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30 border border-emerald-500/40'
                }`}
              >
                <Wrench className="w-3.5 h-3.5 text-emerald-400" />
                WinUtil Auto-Fix Suite
              </button>

              <button
                onClick={() => setImproveSubTab('exe-deploy')}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-black uppercase tracking-wider flex items-center gap-2 transition cursor-pointer ${
                  improveSubTab === 'exe-deploy'
                    ? 'bg-amber-400 text-black font-bold shadow'
                    : 'bg-white/5 text-white/70 hover:text-white hover:bg-white/10 border border-white/10'
                }`}
              >
                <Shield className="w-3.5 h-3.5" />
                EXE Software & Patch Deployments
              </button>

              <button
                onClick={() => setImproveSubTab('guides')}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-black uppercase tracking-wider flex items-center gap-2 transition cursor-pointer ${
                  improveSubTab === 'guides'
                    ? 'bg-amber-400 text-black font-bold shadow'
                    : 'bg-white/5 text-white/70 hover:text-white hover:bg-white/10 border border-white/10'
                }`}
              >
                <Settings className="w-3.5 h-3.5" />
                Remediations Hardening Manuals
              </button>

              <button
                onClick={() => setImproveSubTab('cve-catalog')}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-black uppercase tracking-wider flex items-center gap-2 transition cursor-pointer ${
                  improveSubTab === 'cve-catalog'
                    ? 'bg-amber-400 text-black font-bold shadow'
                    : 'bg-white/5 text-white/70 hover:text-white hover:bg-white/10 border border-white/10'
                }`}
              >
                <Database className="w-3.5 h-3.5" />
                CVE / CSV Weakness Catalog
              </button>

              <button
                onClick={() => setIsSystemFastModalOpen(true)}
                className="px-3.5 py-1.5 rounded-lg text-xs font-black uppercase tracking-wider flex items-center gap-2 transition cursor-pointer bg-gradient-to-r from-amber-400/20 to-yellow-500/20 text-amber-300 hover:bg-amber-500/30 border border-amber-400/50 shadow-sm"
              >
                <Zap className="w-3.5 h-3.5 text-amber-400 fill-amber-400" />
                ⚡ System Fast (Win 10/11 Pro)
              </button>
            </div>
          )}

        </div>
      </nav>

      {/* Primary Program View Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">

        {/* STEP 1: DIAGNOSE */}
        {programStep === 'diagnose' && (
          <div className="space-y-8 animate-fadeIn">
            
            {/* Step 1 Hero Header Banner */}
            <div className="bg-gradient-to-r from-[#031d36] via-[#082a4d] to-[#041528] border-2 border-cyan-400/60 rounded-2xl p-6 shadow-2xl shadow-cyan-950/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="bg-cyan-400 text-black font-black px-3 py-1 rounded-md text-xs uppercase tracking-widest flex items-center gap-1.5 font-mono shadow">
                    <Stethoscope className="w-4 h-4 text-black" />
                    STEP 1 PAGE – CYAN DIAGNOSTICS & AUDITING
                  </span>
                  <span className="text-cyan-300/80 text-xs font-mono font-bold">• Active Network & Host Inspector</span>
                </div>
                <h2 className="text-xl sm:text-2xl font-black text-white tracking-tight">
                  Diagnose Network & Host Device Hardening Posture
                </h2>
                <p className="text-xs text-cyan-100/80 max-w-2xl leading-relaxed">
                  Inspect active network endpoints, test RDP port 3389 connectivity, check physical disk SMART metrics, and analyze 60 security posture audit rules for each machine.
                </p>
              </div>

              <button
                onClick={() => setProgramStep('improve')}
                className="px-5 py-3 rounded-xl bg-gradient-to-r from-amber-400 to-amber-500 hover:from-amber-300 hover:to-amber-400 text-black font-black text-xs uppercase tracking-wider transition shadow-2xl shadow-amber-950/80 flex items-center gap-2 shrink-0 cursor-pointer border border-amber-300"
              >
                Proceed to Step 2 – Improve & Fix &rarr;
              </button>
            </div>

            {diagnoseSubTab === 'inventory' ? (
              <div className="space-y-8">
                {/* Global summary stats row */}
                <SecurityOverviewStats 
                  endpoints={endpoints} 
                  alertThreshold={alertThreshold}
                  onAlertThresholdChange={setAlertThreshold}
                />

                {/* Windows Endpoint Hardening Inventory Table */}
                <EndpointInventoryTable
                  endpoints={endpoints}
                  selectedEndpointId={selectedEndpointId}
                  onSelectEndpoint={(id) => setSelectedEndpointId(id)}
                  alertThreshold={alertThreshold}
                  onAlertThresholdChange={setAlertThreshold}
                  onClearAllEndpoints={handleClearAllEndpoints}
                  onRestoreDefaultEndpoints={handleRestoreDefaultEndpoints}
                  appTheme={appTheme}
                  onThemeChange={setAppTheme}
                  onBatchAddEndpoints={(batch) => {
                    setEndpoints(prev => {
                      const existingIps = new Set(prev.map(e => e.ip));
                      const toAdd = batch.filter(b => !existingIps.has(b.ip));
                      const updated = prev.map(e => {
                        const match = batch.find(b => b.ip === e.ip);
                        return match || e;
                      });
                      const combined = [...toAdd, ...updated];
                      if (combined.length > 0) {
                        setSelectedEndpointId(combined[0].id);
                      }
                      return combined;
                    });
                  }}
                  onDeleteEndpoint={(id) => {
                    setEndpoints(prev => {
                      const remaining = prev.filter(e => e.id !== id);
                      if (selectedEndpointId === id && remaining.length > 0) {
                        setSelectedEndpointId(remaining[0].id);
                      }
                      return remaining;
                    });
                  }}
                  onAddOrUpdateEndpoint={(newEp) => {
                    setEndpoints(prev => {
                      const exists = prev.some(e => e.id === newEp.id || e.ip === newEp.ip);
                      if (exists) {
                        return prev.map(e => (e.id === newEp.id || e.ip === newEp.ip) ? newEp : e);
                      }
                      return [newEp, ...prev];
                    });
                    setSelectedEndpointId(newEp.id);
                  }}
                  onAiAuditClick={(id) => {
                    setSelectedEndpointId(id);
                    const el = document.getElementById('endpoint-audit-view');
                    if (el) {
                      el.scrollIntoView({ behavior: 'smooth' });
                    }
                  }}
                />

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                  
                  {/* Sidebar Endpoint List Selector */}
                  <div className="lg:col-span-4">
                    <EndpointList
                      endpoints={endpoints}
                      selectedEndpointId={selectedEndpointId}
                      onSelectEndpoint={setSelectedEndpointId}
                    />
                  </div>

                  {/* Main Configuration Details Audit Checklist wrapper */}
                  <div className="lg:col-span-8 space-y-8">
                    {selectedEndpoint ? (
                      <EndpointAuditView
                        endpoint={selectedEndpoint}
                        onAutoFixEndpoint={(id) => checkPrivilegeAndRun('admin', 'Vulnerability AutoFix', () => handleAutoFixEndpoint(id))}
                        onRecaptureBaseline={(id) => checkPrivilegeAndRun('admin', 'Recapture Baseline Posture', () => handleRecaptureBaseline(id))}
                        onToggleRemediation={(id, vulnId) => checkPrivilegeAndRun('admin', 'Toggle Remediation Status', () => handleToggleVulnerabilityRemediation(id, vulnId))}
                        onToggleExclusion={(id, vulnId) => checkPrivilegeAndRun('admin', 'Toggle Exception Exclusion', () => handleToggleVulnerabilityExclusion(id, vulnId))}
                        onOpenAiAutoFix={(id) => {
                          if (id) setSelectedEndpointId(id);
                          setIsAiAutoFixModalOpen(true);
                        }}
                      />
                    ) : (
                      <div className="bg-[#0f0f0f] border border-white/10 p-12 text-center text-white/60 rounded-2xl space-y-3">
                        <HelpCircle className="w-10 h-10 text-white/20 mx-auto" />
                        <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                          {endpoints.length === 0 ? 'Saved Inventory Data Cleared (0 Host Devices)' : 'No host selected'}
                        </h3>
                        <p className="text-xs text-white/40 max-w-md mx-auto leading-relaxed">
                          {endpoints.length === 0 
                            ? 'All previous endpoint posture records have been cleared from local storage. Add a host in the inventory table above, scan an IP address, or restore the 5 sample demo machines.'
                            : 'Choose one computer from the sidebar to inspect its configuration.'}
                        </p>
                        {endpoints.length === 0 && (
                          <div className="pt-2 flex items-center justify-center gap-2">
                            <button
                              onClick={handleRestoreDefaultEndpoints}
                              className="px-3 py-1.5 rounded bg-white/10 hover:bg-white/20 text-white text-xs font-mono font-bold border border-white/20 transition cursor-pointer"
                            >
                              ↺ Restore Demo 5 Hosts
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>

                {/* Bottom Callout Banner */}
                <div className="bg-gradient-to-r from-amber-950/40 via-black to-slate-900 border border-amber-500/40 rounded-2xl p-6 flex flex-col sm:flex-row items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <Heart className="w-8 h-8 text-amber-400 shrink-0" />
                    <div>
                      <h4 className="font-bold text-white text-sm">Diagnosis Complete for Audited Hosts?</h4>
                      <p className="text-xs text-white/60">Move to Step 2 to generate PowerShell fix scripts, run WinUtil auto-remediation, or deploy patches.</p>
                    </div>
                  </div>

                  <button
                    onClick={() => setProgramStep('improve')}
                    className="px-5 py-2.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-black font-black text-xs uppercase tracking-wider transition shadow-lg flex items-center gap-2 cursor-pointer shrink-0"
                  >
                    Proceed to Step 2 – Improve & Fix Vulnerabilities &rarr;
                  </button>
                </div>
              </div>
            ) : (
              <UploadCenter onUploadSuccess={(newEndpoint) => checkPrivilegeAndRun('admin', 'Upload Audit Findings', () => handleNewUpload(newEndpoint))} />
            )}

          </div>
        )}

        {/* STEP 2: IMPROVE */}
        {programStep === 'improve' && (
          <div className="space-y-8 animate-fadeIn">
            
            {/* Step 2 Hero Header Banner */}
            <div className="bg-gradient-to-r from-[#381a03] via-[#4d2605] to-[#281102] border-2 border-amber-400/60 rounded-2xl p-6 shadow-2xl shadow-amber-950/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="bg-amber-400 text-black font-black px-3 py-1 rounded-md text-xs uppercase tracking-widest flex items-center gap-1.5 font-mono shadow">
                    <Heart className="w-4 h-4 text-black fill-black" />
                    STEP 2 PAGE – AMBER REMEDIATION & HARDENING CONSOLE
                  </span>
                  <span className="text-amber-300/80 text-xs font-mono font-bold">• Hardening Tools Loaded</span>
                </div>
                <h2 className="text-xl sm:text-2xl font-black text-white tracking-tight">
                  Remediate & Fix All Discovered Vulnerabilities
                </h2>
                <p className="text-xs text-amber-100/80 max-w-2xl leading-relaxed">
                  Select any loaded tool below to generate active PowerShell scripts, launch WinUtil system debloat & auto-repair, deploy software patches, or consult hardening manuals.
                </p>
              </div>

              <button
                onClick={() => setProgramStep('results')}
                className="px-5 py-3 rounded-xl bg-gradient-to-r from-emerald-400 to-emerald-500 hover:from-emerald-300 hover:to-emerald-400 text-black font-black text-xs uppercase tracking-wider transition shadow-2xl shadow-emerald-950/80 flex items-center gap-2 shrink-0 cursor-pointer border border-emerald-300"
              >
                Proceed to Step 3 – Results & Report &rarr;
              </button>
            </div>

            {/* Quick 1-Click Endpoint Auto-Fix Banner */}
            <div className="bg-black/60 border border-white/10 rounded-2xl p-4 flex flex-col sm:flex-row items-center justify-between gap-4 font-mono">
              <div className="flex items-center gap-3">
                <Sparkles className="w-6 h-6 text-amber-400 shrink-0" />
                <div className="text-xs">
                  <span className="text-white font-bold">Target Host PC: </span>
                  <span className="text-cyan-400 font-bold">{selectedEndpoint ? `${selectedEndpoint.name} (${selectedEndpoint.ip})` : 'No Host Selected'}</span>
                  <div className="text-[10px] text-white/50">Current Posture Score: {selectedEndpoint ? `${selectedEndpoint.overallScore}%` : 'N/A (Inventory Empty)'}</div>
                </div>
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={() => setIsAiAutoFixModalOpen(true)}
                  className="px-3.5 py-2 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-black font-black text-xs uppercase tracking-wider transition shadow cursor-pointer flex items-center gap-1.5 border border-cyan-300 shadow-cyan-950/40"
                  title="Synthesize AI-powered PowerShell Auto-Fix Script via Gemini"
                >
                  <Sparkles className="w-3.5 h-3.5 text-black animate-pulse" />
                  🤖 AI Auto-Fix (Gemini)
                </button>

                <button
                  onClick={() => selectedEndpoint && checkPrivilegeAndRun('admin', 'Vulnerability AutoFix', () => handleAutoFixEndpoint(selectedEndpoint.id))}
                  disabled={!selectedEndpoint}
                  className="px-3.5 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-black font-black text-xs uppercase tracking-wider transition shadow cursor-pointer flex items-center gap-1.5 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Wrench className="w-3.5 h-3.5 text-black" />
                  1-Click Auto-Fix Selected Host
                </button>

                <button
                  onClick={() => checkPrivilegeAndRun('superadmin', 'Launch WinUtil System AutoFix', () => setIsWinUtilModalOpen(true))}
                  className="px-3.5 py-2 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-bold uppercase transition cursor-pointer flex items-center gap-1.5"
                >
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  Launch WinUtil Modal
                </button>
              </div>
            </div>

            {/* Sub-tab Tool Content Loader */}
            {improveSubTab === 'bulk-remediate' && (
              <BulkRemediationConsole
                endpoints={endpoints}
                onUpdateEndpoints={(updated) => setEndpoints(updated)}
                onCheckPrivilegeAndRun={(role, action, fn) => checkPrivilegeAndRun(role as any, action, fn)}
                onOpenAiAutoFix={(id) => {
                  if (id) setSelectedEndpointId(id);
                  setIsAiAutoFixModalOpen(true);
                }}
              />
            )}

            {improveSubTab === 'script' && (
              <ScriptGenerator 
                onOpenGitHubModal={() => setIsGitHubModalOpen(true)} 
                onOpenSystemFastModal={() => setIsSystemFastModalOpen(true)}
              />
            )}

            {improveSubTab === 'winutil' && (
              <div className="bg-[#0f0f0f] border border-emerald-500/40 rounded-2xl p-8 text-center space-y-6">
                <div className="w-16 h-16 rounded-full bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center mx-auto text-emerald-400">
                  <Wrench className="w-8 h-8" />
                </div>
                <div className="space-y-2 max-w-xl mx-auto">
                  <h3 className="text-xl font-black text-white">Chris Titus WinUtil System Auto-Fix Suite</h3>
                  <p className="text-xs text-white/70 leading-relaxed">
                    Automated Windows debloat, security hardening, GPO policy enforcement, and 1-click execution script generator.
                  </p>
                </div>
                <button
                  onClick={() => checkPrivilegeAndRun('superadmin', 'Launch WinUtil System AutoFix', () => setIsWinUtilModalOpen(true))}
                  className="px-6 py-3 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-black font-black text-xs uppercase tracking-wider transition shadow-2xl inline-flex items-center gap-2 cursor-pointer"
                >
                  <Wrench className="w-4 h-4 text-black" />
                  Launch WinUtil Full Console Modal
                </button>
              </div>
            )}

            {improveSubTab === 'exe-deploy' && (
              <ExeDeploymentConsole endpoints={endpoints} onAddNewScan={handleNewUpload} />
            )}

            {improveSubTab === 'guides' && (
              <RemediationGuides remediations={remediations} />
            )}

            {improveSubTab === 'cve-catalog' && (
              <CsvWeaknessExplorer />
            )}

            {/* Bottom Callout Banner */}
            <div className="bg-gradient-to-r from-emerald-950/40 via-black to-slate-900 border border-emerald-500/40 rounded-2xl p-6 flex flex-col sm:flex-row items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 shrink-0" />
                <div>
                  <h4 className="font-bold text-white text-sm">Finished Executing Remediation Fixes?</h4>
                  <p className="text-xs text-white/60">Switch to Step 3 to view updated compliance scores, residual risk logs, and export the official PDF audit report.</p>
                </div>
              </div>

              <button
                onClick={() => setProgramStep('results')}
                className="px-5 py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-black font-black text-xs uppercase tracking-wider transition shadow-lg flex items-center gap-2 cursor-pointer shrink-0"
              >
                Proceed to Step 3 – Results & PDF Report &rarr;
              </button>
            </div>

          </div>
        )}

        {/* STEP 3: RESULTS */}
        {programStep === 'results' && (
          <ResultsView
            endpoints={endpoints}
            onOpenExportModal={() => setIsExportConfigModalOpen(true)}
            onOpenGitHubModal={() => setIsGitHubModalOpen(true)}
            onOpenWinUtilModal={() => checkPrivilegeAndRun('superadmin', 'Launch WinUtil System AutoFix', () => setIsWinUtilModalOpen(true))}
            onRecaptureBaseline={(id) => checkPrivilegeAndRun('admin', 'Recapture Baseline Posture', () => handleRecaptureBaseline(id))}
          />
        )}

        <WinUtilAutoFixModal
          isOpen={isWinUtilModalOpen}
          onClose={() => setIsWinUtilModalOpen(false)}
        />

        <SystemFastModal
          isOpen={isSystemFastModalOpen}
          onClose={() => setIsSystemFastModalOpen(false)}
        />

        <DashboardConfigExportModal
          isOpen={isExportConfigModalOpen}
          onClose={() => setIsExportConfigModalOpen(false)}
          endpoints={endpoints}
          onImportConfig={(importedEndpoints) => setEndpoints(importedEndpoints)}
          onOpenGitHubModal={() => setIsGitHubModalOpen(true)}
        />

        <GitHubSyncModal
          isOpen={isGitHubModalOpen}
          onClose={() => setIsGitHubModalOpen(false)}
          endpoints={endpoints}
        />

        <LoginModal
          isOpen={isLoginModalOpen}
          currentUser={currentUser}
          onLogout={handleLogout}
          onClose={() => setIsLoginModalOpen(false)}
          onLoginSuccess={(user) => {
            setCurrentUser(user);
            setIsLoginModalOpen(false);
          }}
        />

        <UserManagementModal
          isOpen={isUserMgmtModalOpen}
          currentUser={currentUser}
          onClose={() => setIsUserMgmtModalOpen(false)}
          onUpdateCurrentUser={(updated) => setCurrentUser(updated)}
          onOpenLogin={() => {
            setIsUserMgmtModalOpen(false);
            setIsLoginModalOpen(true);
          }}
          onLogout={handleLogout}
        />

        <AccessRestrictedModal
          isOpen={isRestrictedModalOpen}
          requiredRole={restrictedInfo.requiredRole}
          actionName={restrictedInfo.actionName}
          currentUser={currentUser}
          onClose={() => setIsRestrictedModalOpen(false)}
          onOpenLogin={() => {
            setIsRestrictedModalOpen(false);
            setIsLoginModalOpen(true);
          }}
        />

        <AiThinkingSecOpsAssistant
          endpoints={endpoints}
          selectedEndpoint={selectedEndpoint}
          isOpen={isAiThinkingModalOpen}
          onClose={() => setIsAiThinkingModalOpen(false)}
        />

        <AiAutoFixModal
          isOpen={isAiAutoFixModalOpen}
          onClose={() => setIsAiAutoFixModalOpen(false)}
          endpoints={endpoints}
          selectedEndpointId={selectedEndpointId}
          onSelectEndpoint={(id) => setSelectedEndpointId(id)}
          onApplyAutoFix={(endpointId) => handleAutoFixEndpoint(endpointId)}
        />
      </main>

      {/* Global informational guide banner */}
      <footer className="mt-auto border-t border-white/15 bg-[#0c0c0c] py-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-4 text-xs text-white/40 font-mono">
          <p>© Windows Endpoint Security Audit Tool. Robust configuration auditing.</p>
          <div className="flex flex-wrap gap-4 justify-center">
            <span className="hover:text-white cursor-help transition" title="Checks SMB1 override registry parameter">SMB1 MODULE</span>
            <span className="hover:text-white cursor-help transition" title="Checks secure protocols in SCHANNEL SecurityProviders registry">SCHANNEL SSL/TLS</span>
            <span className="hover:text-white cursor-help transition" title="Audits LmCompatibilityLevel configuration setting">NTLM HARDENING</span>
            <span className="hover:text-white cursor-help transition" title="Audits LSACfgFlags virtualization setting">LSA ISOLATION</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

