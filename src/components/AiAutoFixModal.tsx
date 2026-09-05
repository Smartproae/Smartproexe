import React, { useState, useEffect } from 'react';
import { Endpoint } from '../types';
import { get60VulnerabilitiesForEndpoint, Vulnerability60 } from '../data/vulnerabilities60';
import { 
  Bot, 
  Sparkles, 
  Terminal, 
  ShieldAlert, 
  ShieldCheck, 
  CheckCircle2, 
  Copy, 
  Download, 
  RefreshCw, 
  AlertTriangle, 
  Play, 
  Undo2, 
  ExternalLink, 
  Cpu, 
  Check, 
  Layers,
  Wrench,
  Sliders,
  ChevronRight
} from 'lucide-react';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  endpoints: Endpoint[];
  selectedEndpointId: string;
  onSelectEndpoint: (id: string) => void;
  onApplyAutoFix: (endpointId: string) => void;
}

interface AutoFixResponse {
  summary: string;
  vulnerabilitiesDetected: string[];
  vulnerabilitiesFixed: string[];
  powershellScript: string;
  rollbackScript: string;
  verificationCommands: string;
  riskAssessment: {
    rebootRequired: boolean;
    breakingChangeRisk: 'Low' | 'Medium' | 'High';
    legacyImpact: string;
    servicesAffected: string[];
  };
  modelUsed: string;
  engineType: string;
  timestamp: string;
}

export default function AiAutoFixModal({
  isOpen,
  onClose,
  endpoints,
  selectedEndpointId,
  onSelectEndpoint,
  onApplyAutoFix
}: Props) {
  const [activeTab, setActiveTab] = useState<'script' | 'rollback' | 'verify' | 'risk'>('script');
  const [mode, setMode] = useState<'full' | 'no_reboot' | 'legacy_compat'>('full');
  const [customInstructions, setCustomInstructions] = useState('');
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [autoFixResult, setAutoFixResult] = useState<AutoFixResponse | null>(null);
  const [appliedSuccessfully, setAppliedSuccessfully] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const endpoint = endpoints.find(e => e.id === selectedEndpointId) || endpoints[0];

  // Get detected failed vulnerabilities for selected endpoint
  const failedVulns = React.useMemo(() => {
    if (!endpoint) return [];
    const list = get60VulnerabilitiesForEndpoint(endpoint);
    return list.filter(item => (item.status === 'failed' || item.status === 'warning') && !item.remediated && !item.excluded);
  }, [endpoint]);

  // Trigger AI auto-fix synthesis
  const handleGenerateAutoFix = async () => {
    if (!endpoint) return;
    setLoading(true);
    setError(null);
    setAppliedSuccessfully(false);

    try {
      const res = await fetch('/api/ai/auto-fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          endpoint: endpoint,
          mode: mode,
          customInstructions: customInstructions
        })
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `Server responded with status ${res.status}`);
      }

      const data = await res.json();
      setAutoFixResult(data);
    } catch (err: any) {
      console.error('Failed to generate AI auto-fix:', err);
      setError(err.message || 'Error generating AI Auto-Fix solution.');
    } finally {
      setLoading(false);
    }
  };

  // Auto-generate on modal open if not generated yet for this host
  useEffect(() => {
    if (isOpen && endpoint && !autoFixResult) {
      handleGenerateAutoFix();
    }
  }, [isOpen, selectedEndpointId]);

  if (!isOpen) return null;

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleDownloadPs1 = (content: string, filename: string) => {
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

  const handleExecuteToDashboard = () => {
    if (!endpoint) return;
    onApplyAutoFix(endpoint.id);
    setAppliedSuccessfully(true);
    setTimeout(() => {
      setAppliedSuccessfully(false);
    }, 4000);
  };

  return (
    <div className="fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4">
      <div className="bg-[#030d17] border-2 border-cyan-500/60 rounded-2xl max-w-5xl w-full max-h-[94vh] flex flex-col shadow-2xl shadow-cyan-950/90 font-mono text-left relative overflow-hidden">
        
        {/* Header */}
        <div className="p-5 bg-gradient-to-r from-[#061d2d] via-[#041624] to-[#020b12] border-b border-cyan-500/30 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-cyan-400/30 to-blue-600/30 border border-cyan-400/60 flex items-center justify-center shadow-lg">
              <Bot className="w-6 h-6 text-cyan-300 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-black text-white uppercase tracking-wider flex items-center gap-2">
                  AI Auto-Fix & Remediation Synthesizer
                </h3>
                <span className="text-[10px] bg-cyan-500/20 text-cyan-300 border border-cyan-400/40 px-2 py-0.5 rounded font-mono font-bold uppercase flex items-center gap-1">
                  <Sparkles className="w-3 h-3 text-cyan-300" />
                  Gemini-Powered
                </span>
              </div>
              <p className="text-xs text-cyan-100/70 font-sans mt-0.5">
                Automatically analyzes scanned vulnerabilities and synthesizes tailored, zero-trust PowerShell auto-fix scripts with safety rollbacks.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-white/50 hover:text-white bg-white/5 hover:bg-white/10 p-2 rounded-lg transition cursor-pointer"
          >
            ✕
          </button>
        </div>

        {/* Top Control Bar: Endpoint selector & Mode */}
        <div className="p-4 bg-black/40 border-b border-white/10 flex flex-wrap items-center justify-between gap-3 text-xs">
          
          {/* Target Host dropdown */}
          <div className="flex items-center gap-2">
            <span className="text-white/70 font-bold flex items-center gap-1.5">
              <Cpu className="w-4 h-4 text-cyan-400" />
              Target Host:
            </span>
            <select
              value={selectedEndpointId}
              onChange={(e) => {
                onSelectEndpoint(e.target.value);
                setAutoFixResult(null);
              }}
              disabled={endpoints.length === 0}
              className="bg-slate-900 border border-cyan-500/40 text-cyan-200 text-xs rounded-lg px-2.5 py-1.5 font-bold focus:outline-none focus:border-cyan-300 disabled:opacity-40"
            >
              {endpoints.length === 0 ? (
                <option value="">No Hosts Available</option>
              ) : (
                endpoints.map(ep => (
                  <option key={ep.id} value={ep.id}>
                    {ep.name} ({ep.ip}) — Score: {ep.overallScore}%
                  </option>
                ))
              )}
            </select>
          </div>

          {/* Hardening Mode */}
          <div className="flex items-center gap-2">
            <span className="text-white/70 font-bold">Hardening Mode:</span>
            <div className="flex bg-slate-900/80 rounded-lg p-0.5 border border-white/10">
              <button
                onClick={() => setMode('full')}
                className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase transition ${
                  mode === 'full' ? 'bg-cyan-500 text-black' : 'text-white/60 hover:text-white'
                }`}
              >
                Full Zero-Trust
              </button>
              <button
                onClick={() => setMode('no_reboot')}
                className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase transition ${
                  mode === 'no_reboot' ? 'bg-cyan-500 text-black' : 'text-white/60 hover:text-white'
                }`}
              >
                Zero-Downtime
              </button>
              <button
                onClick={() => setMode('legacy_compat')}
                className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase transition ${
                  mode === 'legacy_compat' ? 'bg-cyan-500 text-black' : 'text-white/60 hover:text-white'
                }`}
              >
                Legacy Compat
              </button>
            </div>
          </div>

          {/* Re-generate button */}
          <button
            onClick={handleGenerateAutoFix}
            disabled={loading || !endpoint}
            className="px-3 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-black font-black text-xs uppercase tracking-wider rounded-lg transition flex items-center gap-1.5 disabled:opacity-50 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            {loading ? 'Synthesizing...' : 'Regenerate Solution'}
          </button>
        </div>

        {/* Content Body */}
        {!endpoint ? (
          <div className="p-12 text-center space-y-3 font-mono">
            <Cpu className="w-10 h-10 text-cyan-400/40 mx-auto" />
            <h4 className="text-sm font-bold text-white uppercase">No Endpoint Host in Inventory</h4>
            <p className="text-xs text-white/50 max-w-md mx-auto">
              Inventory is currently empty. Add or scan an IP host or restore sample hosts in Step 1 (Diagnose) to synthesize AI Auto-Fix scripts.
            </p>
          </div>
        ) : (
        <div className="p-5 overflow-y-auto space-y-5 flex-1 text-xs">
          
          {/* Detected Vulnerabilities Alert Banner */}
          <div className="bg-gradient-to-r from-red-950/40 via-black to-slate-900 border border-red-500/40 rounded-xl p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-500/20 text-red-400 shrink-0">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div>
                <div className="text-white font-bold flex items-center gap-2">
                  <span>Detected Issues on {endpoint?.name}:</span>
                  <span className="bg-red-500/20 text-red-300 border border-red-500/40 px-2 py-0.5 rounded text-[10px] font-mono">
                    {failedVulns.length} Open Vulnerabilities
                  </span>
                </div>
                <div className="text-[11px] text-white/60 font-sans mt-0.5 flex flex-wrap gap-2">
                  {failedVulns.slice(0, 4).map((v, i) => (
                    <span key={i} className="bg-black/50 border border-white/10 px-2 py-0.5 rounded text-[10px] text-white/70">
                      • {v.vulnerability.name}
                    </span>
                  ))}
                  {failedVulns.length > 4 && (
                    <span className="text-white/40 text-[10px] self-center">
                      +{failedVulns.length - 4} more
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Instant Apply Button */}
            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={handleExecuteToDashboard}
                className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-black font-black text-xs uppercase tracking-wider rounded-xl transition shadow-lg flex items-center gap-1.5 cursor-pointer"
              >
                <CheckCircle2 className="w-4 h-4 text-black" />
                Apply Auto-Fix to Dashboard
              </button>
            </div>
          </div>

          {appliedSuccessfully && (
            <div className="bg-emerald-950/80 border border-emerald-500/60 text-emerald-200 p-3 rounded-xl flex items-center gap-2 animate-fadeIn">
              <Check className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>
                <strong>Remediation Registered!</strong> All open vulnerabilities on <strong>{endpoint?.name}</strong> have been marked as resolved and posture score recalculated.
              </span>
            </div>
          )}

          {error && (
            <div className="bg-red-950/80 border border-red-500/60 text-red-200 p-3 rounded-xl flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* AI Solution View */}
          {loading ? (
            <div className="bg-black/60 border border-cyan-500/30 rounded-2xl p-12 text-center space-y-4">
              <div className="w-12 h-12 rounded-full border-4 border-cyan-400 border-t-transparent animate-spin mx-auto" />
              <div className="space-y-1">
                <p className="text-white font-bold">Gemini AI is analyzing host scan findings...</p>
                <p className="text-cyan-200/60 text-[11px] font-sans">
                  Synthesizing exact PowerShell registry keys, SCHANNEL ciphers, and rollback procedures.
                </p>
              </div>
            </div>
          ) : autoFixResult ? (
            <div className="space-y-4">
              
              {/* Summary Card */}
              <div className="bg-[#051824] border border-cyan-500/30 rounded-xl p-4 space-y-2">
                <div className="flex items-center justify-between text-[11px] text-cyan-300 font-bold uppercase tracking-wider">
                  <span className="flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                    AI Remediation Blueprint
                  </span>
                  <span className="text-white/40 font-mono text-[10px]">
                    Engine: {autoFixResult.engineType} ({autoFixResult.modelUsed})
                  </span>
                </div>
                <p className="text-cyan-100/90 font-sans text-xs leading-relaxed">
                  {autoFixResult.summary}
                </p>
              </div>

              {/* Subtabs for PowerShell, Rollback, Verification, Risk */}
              <div className="border-b border-white/10 flex items-center gap-2">
                <button
                  onClick={() => setActiveTab('script')}
                  className={`px-3 py-2 text-xs font-bold uppercase tracking-wider border-b-2 transition flex items-center gap-1.5 ${
                    activeTab === 'script'
                      ? 'border-cyan-400 text-cyan-300'
                      : 'border-transparent text-white/50 hover:text-white'
                  }`}
                >
                  <Terminal className="w-3.5 h-3.5" />
                  PowerShell Auto-Fix Script (.ps1)
                </button>
                <button
                  onClick={() => setActiveTab('rollback')}
                  className={`px-3 py-2 text-xs font-bold uppercase tracking-wider border-b-2 transition flex items-center gap-1.5 ${
                    activeTab === 'rollback'
                      ? 'border-amber-400 text-amber-300'
                      : 'border-transparent text-white/50 hover:text-white'
                  }`}
                >
                  <Undo2 className="w-3.5 h-3.5" />
                  Safety Rollback Script
                </button>
                <button
                  onClick={() => setActiveTab('verify')}
                  className={`px-3 py-2 text-xs font-bold uppercase tracking-wider border-b-2 transition flex items-center gap-1.5 ${
                    activeTab === 'verify'
                      ? 'border-emerald-400 text-emerald-300'
                      : 'border-transparent text-white/50 hover:text-white'
                  }`}
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Post-Fix Verification
                </button>
                <button
                  onClick={() => setActiveTab('risk')}
                  className={`px-3 py-2 text-xs font-bold uppercase tracking-wider border-b-2 transition flex items-center gap-1.5 ${
                    activeTab === 'risk'
                      ? 'border-purple-400 text-purple-300'
                      : 'border-transparent text-white/50 hover:text-white'
                  }`}
                >
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Impact & Risk Review
                </button>
              </div>

              {/* Tab 1: PowerShell Script */}
              {activeTab === 'script' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-white/60 font-mono">
                      Run this script in Administrator PowerShell on <strong>{endpoint?.name}</strong>:
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleCopy(autoFixResult.powershellScript, 'script')}
                        className="px-2.5 py-1 bg-white/10 hover:bg-white/20 text-white rounded text-[11px] flex items-center gap-1 transition cursor-pointer"
                      >
                        <Copy className="w-3 h-3" />
                        {copied === 'script' ? 'Copied!' : 'Copy Script'}
                      </button>
                      <button
                        onClick={() => handleDownloadPs1(autoFixResult.powershellScript, `AI_AutoFix_${endpoint?.name}.ps1`)}
                        className="px-2.5 py-1 bg-cyan-500 hover:bg-cyan-400 text-black font-bold rounded text-[11px] flex items-center gap-1 transition cursor-pointer"
                      >
                        <Download className="w-3 h-3" />
                        Download .ps1
                      </button>
                    </div>
                  </div>

                  {/* 1-Liner command box */}
                  <div className="bg-black/90 border border-cyan-500/30 rounded-lg p-2.5 flex items-center justify-between gap-2 font-mono text-[11px]">
                    <span className="text-cyan-400 truncate select-all">
                      powershell -ExecutionPolicy Bypass -File .\AI_AutoFix_{endpoint?.name}.ps1
                    </span>
                    <button
                      onClick={() => handleCopy(`powershell -ExecutionPolicy Bypass -File .\\AI_AutoFix_${endpoint?.name}.ps1`, 'cmd')}
                      className="text-white/50 hover:text-white px-2 py-0.5 rounded bg-white/5"
                    >
                      {copied === 'cmd' ? 'Copied' : 'Copy'}
                    </button>
                  </div>

                  <div className="bg-[#020912] border border-white/10 rounded-xl p-4 overflow-x-auto max-h-[320px] font-mono text-xs text-cyan-200/90 leading-relaxed whitespace-pre selection:bg-cyan-500 selection:text-black">
                    {autoFixResult.powershellScript}
                  </div>
                </div>
              )}

              {/* Tab 2: Rollback Script */}
              {activeTab === 'rollback' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-amber-300 font-mono flex items-center gap-1.5">
                      <Undo2 className="w-3.5 h-3.5" />
                      Zero-Trust Rollback Script: Reverts settings if needed
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleCopy(autoFixResult.rollbackScript, 'rollback')}
                        className="px-2.5 py-1 bg-white/10 hover:bg-white/20 text-white rounded text-[11px] flex items-center gap-1 transition cursor-pointer"
                      >
                        <Copy className="w-3 h-3" />
                        {copied === 'rollback' ? 'Copied!' : 'Copy Rollback'}
                      </button>
                      <button
                        onClick={() => handleDownloadPs1(autoFixResult.rollbackScript, `Rollback_${endpoint?.name}.ps1`)}
                        className="px-2.5 py-1 bg-amber-500 hover:bg-amber-400 text-black font-bold rounded text-[11px] flex items-center gap-1 transition cursor-pointer"
                      >
                        <Download className="w-3 h-3" />
                        Download Rollback .ps1
                      </button>
                    </div>
                  </div>

                  <div className="bg-[#0e0701] border border-amber-500/30 rounded-xl p-4 overflow-x-auto max-h-[320px] font-mono text-xs text-amber-200/90 leading-relaxed whitespace-pre">
                    {autoFixResult.rollbackScript}
                  </div>
                </div>
              )}

              {/* Tab 3: Verification Commands */}
              {activeTab === 'verify' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-emerald-300 font-mono flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Run Verification in PowerShell to confirm compliance:
                    </span>
                    <button
                      onClick={() => handleCopy(autoFixResult.verificationCommands, 'verify')}
                      className="px-2.5 py-1 bg-white/10 hover:bg-white/20 text-white rounded text-[11px] flex items-center gap-1 transition cursor-pointer"
                    >
                      <Copy className="w-3 h-3" />
                      {copied === 'verify' ? 'Copied!' : 'Copy Commands'}
                    </button>
                  </div>

                  <div className="bg-[#021008] border border-emerald-500/30 rounded-xl p-4 overflow-x-auto max-h-[320px] font-mono text-xs text-emerald-200/90 leading-relaxed whitespace-pre">
                    {autoFixResult.verificationCommands}
                  </div>
                </div>
              )}

              {/* Tab 4: Risk Review */}
              {activeTab === 'risk' && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-black/40 border border-white/10 rounded-xl p-4 space-y-2">
                      <div className="text-[11px] text-white/50 uppercase font-bold">Breaking Change Risk</div>
                      <div className={`text-base font-black uppercase ${
                        autoFixResult.riskAssessment.breakingChangeRisk === 'Low' ? 'text-emerald-400' :
                        autoFixResult.riskAssessment.breakingChangeRisk === 'Medium' ? 'text-amber-400' : 'text-red-400'
                      }`}>
                        {autoFixResult.riskAssessment.breakingChangeRisk} Risk
                      </div>
                      <p className="text-[11px] text-white/70 font-sans">
                        {autoFixResult.riskAssessment.legacyImpact}
                      </p>
                    </div>

                    <div className="bg-black/40 border border-white/10 rounded-xl p-4 space-y-2">
                      <div className="text-[11px] text-white/50 uppercase font-bold">Reboot Requirement</div>
                      <div className={`text-base font-black uppercase ${
                        autoFixResult.riskAssessment.rebootRequired ? 'text-amber-400' : 'text-emerald-400'
                      }`}>
                        {autoFixResult.riskAssessment.rebootRequired ? 'Reboot Recommended' : 'No Reboot Required'}
                      </div>
                      <p className="text-[11px] text-white/70 font-sans">
                        SCHANNEL TLS cipher changes take full effect upon OS restart. SMB and firewall changes apply immediately.
                      </p>
                    </div>
                  </div>

                  <div className="bg-black/40 border border-white/10 rounded-xl p-4 space-y-2">
                    <div className="text-[11px] text-white/50 uppercase font-bold">Affected Services</div>
                    <div className="flex flex-wrap gap-2">
                      {autoFixResult.riskAssessment.servicesAffected.map((srv, idx) => (
                        <span key={idx} className="bg-white/5 border border-white/10 px-2.5 py-1 rounded text-cyan-300 font-mono text-xs">
                          {srv}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              )}

            </div>
          ) : (
            <div className="p-8 text-center text-white/40">
              Click 'Regenerate Solution' to synthesize your AI Auto-Fix package.
            </div>
          )}

        </div>
        )}

        {/* Footer */}
        <div className="p-4 bg-[#020b12] border-t border-white/10 flex items-center justify-between shrink-0">
          <div className="text-[11px] text-white/50 font-sans flex items-center gap-1.5">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            Zero-Trust Pre-flight checks and rollback procedures included.
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-white/10 hover:bg-white/20 text-white rounded-lg text-xs font-bold uppercase transition cursor-pointer"
            >
              Close
            </button>
            <button
              onClick={handleExecuteToDashboard}
              disabled={!endpoint}
              className="px-5 py-2 bg-gradient-to-r from-emerald-500 to-emerald-400 hover:from-emerald-400 hover:to-emerald-300 text-black font-black rounded-lg text-xs uppercase tracking-wider transition shadow-lg flex items-center gap-1.5 cursor-pointer disabled:opacity-40"
            >
              <CheckCircle2 className="w-4 h-4 text-black" />
              Apply Auto-Fix & Recalculate Posture
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
