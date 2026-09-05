import React from 'react';
import { Endpoint } from '../types';
import { Shield, ShieldAlert, AlertCircle, Sparkles, Sliders, AlertTriangle } from 'lucide-react';

interface Props {
  endpoints: Endpoint[];
  alertThreshold?: number;
  onAlertThresholdChange?: (threshold: number) => void;
}

export default function SecurityOverviewStats({ 
  endpoints, 
  alertThreshold = 75, 
  onAlertThresholdChange 
}: Props) {
  const total = endpoints.length;
  
  // Averages and aggregated counts
  const averageScore = Math.round(
    endpoints.reduce((sum, item) => sum + item.overallScore, 0) / (total || 1)
  );

  const vulnerableCount = endpoints.filter(e => e.status === 'vulnerable').length;
  const warningCount = endpoints.filter(e => e.status === 'warning').length;
  
  // Count endpoints automatically flagged for urgent manual review (overallScore < alertThreshold)
  const flaggedEndpoints = endpoints.filter(e => e.overallScore < alertThreshold);
  const flaggedCount = flaggedEndpoints.length;

  const totalCritical = endpoints.reduce((sum, item) => sum + item.criticalCount, 0);
  const totalHigh = endpoints.reduce((sum, item) => sum + item.highCount, 0);
  const totalMedium = endpoints.reduce((sum, item) => sum + item.mediumCount, 0);

  // Remediation actions recommendation counts
  const smbv1Active = endpoints.filter(e => e.scanData.smb.smb1Enabled.status === 'failed').length;
  const weakSigning = endpoints.filter(e => e.scanData.smb.smbSigningRequired.status === 'warning').length;
  const obsoleteTls = endpoints.filter(e => e.scanData.sslTls.tls10Enabled.status === 'failed').length;
  const legacyLm = endpoints.filter(e => e.scanData.ntlm.lmCompatibilityLevel.status === 'failed' || e.scanData.ntlm.lmCompatibilityLevel.status === 'warning').length;
  const browserVuln = endpoints.filter(e => {
    if (!e.scanData.browserSecurity) return false;
    const b = e.scanData.browserSecurity;
    return b.chromePasswordStore.status === 'failed' || b.edgePasswordStore.status === 'failed' || b.firefoxPasswordStore.status === 'failed';
  }).length;

  return (
    <div className="space-y-6 text-left">
      {/* Top 4 Fleet Overview Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        
        {/* Average Fleet Score Card */}
        <div className="bg-[#0f0f0f] border-2 border-white/20 p-6 flex items-center justify-between hover:border-white transition-all">
          <div className="space-y-1">
            <span className="text-[10px] sm:text-xs uppercase font-black text-white/50 tracking-widest font-mono">Fleet Score</span>
            <div className="flex items-baseline gap-1.5 pt-1.5">
              <span className={`text-4xl sm:text-5xl font-black font-mono leading-none ${averageScore < alertThreshold ? 'text-[#FF3B30]' : 'text-emerald-400'}`}>{averageScore}</span>
              <span className="text-xs uppercase text-white/40 font-mono">/ 100</span>
            </div>
            <span className="text-[10px] text-white/40 block pt-2 uppercase font-bold tracking-wider leading-relaxed">
              Registry threat audit factor
            </span>
          </div>
          <div className={`p-3 border-2 border-current font-bold ${averageScore < alertThreshold ? 'text-[#FF3B30]' : 'text-emerald-400'}`}>
            <Shield className="w-6 h-6" />
          </div>
        </div>

        {/* Flagged Endpoints Below Threshold Card */}
        <div className={`bg-[#0f0f0f] border-2 p-6 flex items-center justify-between hover:border-white transition-all ${
          flaggedCount > 0 ? 'border-red-500/80 bg-red-950/20' : 'border-white/20'
        }`}>
          <div className="space-y-1">
            <span className="text-[10px] sm:text-xs uppercase font-black text-red-400 tracking-widest font-mono flex items-center gap-1">
              <AlertTriangle className="w-3.5 h-3.5" />
              Flagged Below {alertThreshold}
            </span>
            <div className="flex items-baseline gap-2 pt-1.5 font-mono leading-none">
              <span className={`text-4xl sm:text-5xl font-black ${flaggedCount > 0 ? 'text-[#FF3B30] animate-pulse' : 'text-emerald-400'}`}>{flaggedCount}</span>
              <span className="text-xs uppercase text-white/40">HOSTS</span>
            </div>
            <span className="text-[10px] text-red-300/80 block pt-2 uppercase font-bold tracking-wider leading-relaxed">
              Urgent manual review required
            </span>
          </div>
          <div className={`p-3 border-2 ${flaggedCount > 0 ? 'border-[#FF3B30] text-[#FF3B30]' : 'border-emerald-400 text-emerald-400'}`}>
            <ShieldAlert className="w-6 h-6" />
          </div>
        </div>

        {/* Critical Vulnerabilities Aggregations */}
        <div className="bg-[#0f0f0f] border-2 border-white/20 p-6 flex flex-col justify-between hover:border-white transition-all">
          <div className="space-y-1">
            <span className="text-[10px] sm:text-xs uppercase font-black text-white/50 tracking-widest font-mono">Identified Security Risks</span>
            <div className="flex gap-4 pt-2 font-mono">
              <div>
                <span className="text-2xl sm:text-3xl font-black text-[#FF3B30] block">{totalCritical}</span>
                <span className="text-[8px] sm:text-[9px] uppercase font-bold text-[#FF3B30] bg-[#FF3B30]/10 px-1 py-0.5 border border-[#FF3B30]/20 font-mono">CRITICAL</span>
              </div>
              <div>
                <span className="text-2xl sm:text-3xl font-black text-amber-500 block">{totalHigh}</span>
                <span className="text-[8px] sm:text-[9px] uppercase font-bold text-amber-500 bg-amber-500/10 px-1 py-0.5 border border-amber-500/20 font-mono">HIGH</span>
              </div>
              <div>
                <span className="text-2xl sm:text-3xl font-black text-white block">{totalMedium}</span>
                <span className="text-[8px] sm:text-[9px] uppercase font-bold text-white/60 bg-white/10 px-1 py-0.5 border border-white/20 font-mono">MEDIUM</span>
              </div>
            </div>
          </div>
        </div>

        {/* Priority Action Trigger */}
        <div className="bg-[#FF3B30] text-white border-2 border-[#FF3B30] p-6 flex flex-col justify-between transition-all">
          <div className="space-y-1">
            <span className="text-[11px] uppercase font-black tracking-widest flex items-center gap-1 font-mono">
              <Sparkles className="w-3.5 h-3.5" />
              Top remediation vector
            </span>
            <div className="pt-2 text-xs uppercase font-black leading-tight tracking-wider font-mono">
              {smbv1Active > 0 ? (
                <span>CRITICAL: DISABLE SMBV1 ON {smbv1Active} ENDPOINT(S). HIGH WANNACRY RISKS.</span>
              ) : browserVuln > 0 ? (
                <span>BROWSER SECURITY RISK: PASSWORD STORING & HISTORY CLEARANCE NOT CONFIGURED ON {browserVuln} HOST(S).</span>
              ) : obsoleteTls > 0 ? (
                <span>WARNING: DEPRECATE TLS 1.0/1.1 ON {obsoleteTls} ENDPOINT(S) NOW.</span>
              ) : weakSigning > 0 ? (
                <span>SCHANNEL: REQUIRE SMB SECURE CHANNELS ON {weakSigning} SYSTEMS.</span>
              ) : legacyLm > 0 ? (
                <span>NTLM: ENROLL LMCOMPATIBILITYLEVEL HARDENING TO PREVENT SESSION SPOOFING.</span>
              ) : total === 0 ? (
                <span className="flex items-center gap-1 text-white">INVENTORY IS EMPTY. ADD OR SCAN AN ENDPOINT TO AUDIT.</span>
              ) : (
                <span className="flex items-center gap-1 text-white">ALL TARGET HOSTS SAFE. SCHEDULE AUDIT.</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Dedicated Alert Threshold Configuration Bar */}
      {onAlertThresholdChange && (
        <div className="bg-[#0b131f] border-2 border-cyan-500/40 p-4 sm:p-5 rounded-2xl flex flex-col md:flex-row md:items-center justify-between gap-4 font-mono shadow-xl">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Sliders className="w-5 h-5 text-cyan-400" />
              <h4 className="text-sm font-black text-white uppercase tracking-wider">
                Alert Threshold Configuration
              </h4>
              <span className="bg-red-500/20 text-red-300 border border-red-500/40 px-2 py-0.5 rounded text-[10px] font-bold">
                Auto-Flagging Active
              </span>
            </div>
            <p className="text-xs text-cyan-100/70 font-sans">
              Endpoints with an overall security score below <strong className="text-amber-300 font-mono">{alertThreshold} / 100</strong> are automatically flagged with an <span className="text-red-400 font-bold">URGENT MANUAL REVIEW</span> alert across all views.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 bg-black/60 p-3 rounded-xl border border-white/10 shrink-0">
            <div className="flex items-center gap-3">
              <span className="text-xs text-white/60 font-bold uppercase">Threshold Score:</span>
              <input
                type="range"
                min="30"
                max="95"
                step="5"
                value={alertThreshold}
                onChange={(e) => onAlertThresholdChange(Number(e.target.value))}
                className="w-32 accent-cyan-400 cursor-pointer"
              />
              <div className="flex items-center gap-1 bg-cyan-950 border border-cyan-500/50 px-2.5 py-1 rounded text-sm font-black text-cyan-300">
                <span>{alertThreshold}</span>
                <span className="text-[10px] text-white/40">/100</span>
              </div>
            </div>

            {/* Presets */}
            <div className="flex items-center gap-1.5 border-t sm:border-t-0 sm:border-l border-white/10 pt-2 sm:pt-0 sm:pl-3">
              <span className="text-[10px] text-white/40 font-bold uppercase">Presets:</span>
              {[60, 70, 75, 80, 85].map((preset) => (
                <button
                  key={preset}
                  onClick={() => onAlertThresholdChange(preset)}
                  className={`px-2 py-0.5 text-[10px] font-bold rounded transition cursor-pointer border ${
                    alertThreshold === preset
                      ? 'bg-cyan-500 text-black border-cyan-300'
                      : 'bg-white/5 text-white/70 hover:bg-white/10 border-white/10'
                  }`}
                >
                  {preset}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


