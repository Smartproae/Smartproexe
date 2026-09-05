import React, { useState } from 'react';
import { Sparkles, Brain, Shield, Send, Copy, Check, RefreshCw, Terminal, AlertTriangle, Layers, Cpu } from 'lucide-react';
import { Endpoint } from '../types';

interface AiThinkingSecOpsAssistantProps {
  endpoints: Endpoint[];
  selectedEndpoint?: Endpoint;
  isOpen: boolean;
  onClose: () => void;
}

export default function AiThinkingSecOpsAssistant({
  endpoints,
  selectedEndpoint,
  isOpen,
  onClose
}: AiThinkingSecOpsAssistantProps) {
  const [prompt, setPrompt] = useState('');
  const [contextMode, setContextMode] = useState<'selected' | 'all' | 'none'>('selected');
  const [userApiKey, setUserApiKey] = useState('');
  const [showApiKeyInput, setShowApiKeyInput] = useState(false);
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<string | null>(null);
  const [engineTypeUsed, setEngineTypeUsed] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const presetQueries = [
    {
      title: "Active Directory LDAP SPN & Kerberoasting Mitigation",
      query: "Analyze the discovered LDAP Service Principal Name (SPN) accounts and evaluate the Kerberoasting exposure risk. Provide step-by-step mitigation commands, Group Policy configurations, and gMSA service account conversion instructions."
    },
    {
      title: "Cross-Endpoint SMBv1 & NTLM Security Hardening",
      query: "Provide a comprehensive enterprise remediation roadmap to completely disable SMBv1 and enforce NTLMv2 session security across all monitored Windows domain endpoints without breaking legacy business application connectivity."
    },
    {
      title: "GPO Baseline Strategy for Zero Trust Endpoints",
      query: "Construct a hardened Active Directory Group Policy Object (GPO) configuration baseline targeting TLS 1.2+, Credential Guard, BitLocker, and WinGet auto-updating for enterprise domain controllers and workstations."
    },
    {
      title: "NIST 800-53 & ISO 27001 Audit Compliance Strategy",
      query: "Review our current security posture scores and host vulnerability findings against NIST SP 800-53 Rev 5 and ISO/IEC 27001:2022 standards. Highlight critical compliance gaps and produce an executive-level remediation plan."
    },
    {
      title: "🤖 Synthesize PowerShell Auto-Fix Script for Scan Findings",
      query: "Analyze all failed security controls, open ports, and weak protocols discovered on this endpoint. Synthesize a production-ready, elevated PowerShell auto-fix script with pre-flight checks, exact registry fixes, verification commands, and a rollback script."
    }
  ];

  const handleAnalyze = async (queryToUse?: string) => {
    const finalQuery = queryToUse || prompt;
    if (!finalQuery.trim()) return;

    setLoading(true);
    setError(null);
    setAnalysisResult(null);

    let contextData: any = null;
    if (contextMode === 'selected' && selectedEndpoint) {
      contextData = {
        endpointName: selectedEndpoint.name,
        ip: selectedEndpoint.ip,
        os: selectedEndpoint.os,
        overallScore: selectedEndpoint.overallScore,
        ldapSpnAudit: selectedEndpoint.scanData?.ldapSpnAudit || null,
        ports: selectedEndpoint.scanData?.ports || null,
        smbStatus: selectedEndpoint.scanData?.smb || null,
        sslTlsStatus: selectedEndpoint.scanData?.sslTls || null
      };
    } else if (contextMode === 'all') {
      contextData = endpoints.map(ep => ({
        hostname: ep.name,
        ip: ep.ip,
        os: ep.os,
        score: ep.overallScore,
        ldapSpnAccounts: ep.scanData?.ldapSpnAudit?.accounts || [],
        failedChecks: ep.criticalCount + ep.highCount
      }));
    }

    try {
      const response = await fetch('/api/gemini/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prompt: finalQuery,
          context: contextData,
          userApiKey: userApiKey.trim() || undefined,
          systemInstruction: "You are a Principal Cyber Security Architect & Enterprise Active Directory SecOps Specialist. Use step-by-step deep reasoning to analyze complex security posture queries, Kerberoasting risks, GPO policies, SMB/NTLM vulnerability surfaces, and endpoint health."
        })
      });

      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Failed to complete AI reasoning analysis');
      }

      setAnalysisResult(data.analysis);
      setEngineTypeUsed(data.engineType || 'builtin_fallback');
    } catch (err: any) {
      console.error("Gemini thinking analysis error:", err);
      setError(err.message || 'Error executing Gemini 3.1 Pro High-Thinking analysis');
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (analysisResult) {
      navigator.clipboard.writeText(analysisResult);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4">
      <div className="bg-[#030d14] border-2 border-cyan-500/60 rounded-2xl max-w-4xl w-full max-h-[92vh] flex flex-col shadow-2xl shadow-cyan-950/90 font-mono text-left relative overflow-hidden">
        
        {/* Header */}
        <div className="p-5 bg-gradient-to-r from-[#051824] to-[#020b12] border-b border-cyan-500/30 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/20 border border-cyan-400/50 flex items-center justify-center shadow-inner">
              <Brain className="w-6 h-6 text-cyan-300 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-black text-white uppercase tracking-wider flex items-center gap-2">
                  Gemini SecOps High-Thinking Reasoning Architect
                </h3>
                <span className="text-[9px] bg-cyan-500/20 text-cyan-300 border border-cyan-400/40 px-2 py-0.5 rounded font-mono font-bold uppercase flex items-center gap-1">
                  <Sparkles className="w-3 h-3 text-cyan-300" />
                  Gemini 3.8 Flash
                </span>
              </div>
              <p className="text-[11px] text-cyan-100/70 font-sans mt-0.5">
                Deep reasoning engine powered by <code className="text-cyan-300 font-mono font-bold">gemini-3.8-flash</code> with automated fallback for complex security analysis & Active Directory hardening strategy.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-white/50 hover:text-white bg-white/5 hover:bg-white/10 p-2 rounded-lg transition"
          >
            ✕
          </button>
        </div>

        {/* Content Body */}
        <div className="p-5 overflow-y-auto space-y-5 flex-1">
          
          {/* Preset Prompts Grid */}
          <div className="space-y-2">
            <label className="text-[10px] text-cyan-300 uppercase font-black tracking-widest flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-cyan-400" />
              Complex Query Templates (High Reasoning):
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {presetQueries.map((item, idx) => (
                <button
                  key={idx}
                  onClick={() => {
                    setPrompt(item.query);
                    handleAnalyze(item.query);
                  }}
                  className="p-3 bg-white/[0.03] hover:bg-cyan-500/10 border border-white/10 hover:border-cyan-500/40 rounded-xl text-left transition group cursor-pointer space-y-1"
                >
                  <div className="text-xs font-bold text-white group-hover:text-cyan-300 flex items-center justify-between">
                    <span>{item.title}</span>
                    <Sparkles className="w-3 h-3 text-cyan-400 opacity-0 group-hover:opacity-100 transition" />
                  </div>
                  <p className="text-[10px] text-white/50 line-clamp-2 font-sans">
                    {item.query}
                  </p>
                </button>
              ))}
            </div>
          </div>

          {/* Optional API Key Collapsible Configuration */}
          <div className="bg-black/40 border border-cyan-500/20 rounded-xl p-3 text-xs space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-cyan-200/90 font-sans flex items-center gap-1.5 font-bold">
                <Shield className="w-4 h-4 text-cyan-400" />
                AI API Key Options:
                <span className="text-[9px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 px-2 py-0.5 rounded uppercase font-bold ml-1">
                  100% Free Built-in Mode Active
                </span>
              </span>
              <button
                onClick={() => setShowApiKeyInput(!showApiKeyInput)}
                className="text-[10px] text-cyan-400 hover:text-cyan-300 underline font-mono cursor-pointer"
              >
                {showApiKeyInput ? 'Hide API Key Field' : 'Optional: Enter Custom Gemini API Key'}
              </button>
            </div>

            {showApiKeyInput && (
              <div className="pt-2 border-t border-cyan-500/20 space-y-1.5 animate-fadeIn">
                <p className="text-[10px] text-white/60 font-sans">
                  No paid key required! If left empty, the co-pilot uses SmartPro SecOps built-in high-reasoning SecOps expert engine.
                </p>
                <input
                  type="password"
                  value={userApiKey}
                  onChange={(e) => setUserApiKey(e.target.value)}
                  placeholder="Optional: Enter AI Studio / Gemini API key (e.g. AIzaSy...)"
                  className="w-full bg-black/90 border border-cyan-500/40 rounded-lg p-2 text-xs text-cyan-200 placeholder-white/30 font-mono focus:outline-none focus:border-cyan-300"
                />
              </div>
            )}
          </div>

          {/* Context Target Selection */}
          <div className="bg-black/60 border border-white/10 p-3 rounded-xl flex items-center justify-between flex-wrap gap-3 text-xs">
            <span className="text-white/70 font-bold flex items-center gap-1.5">
              <Cpu className="w-4 h-4 text-cyan-400" />
              Security Context Included in Prompt:
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setContextMode('selected')}
                className={`px-3 py-1 rounded text-[10px] uppercase font-bold transition cursor-pointer border ${
                  contextMode === 'selected'
                    ? 'bg-cyan-500 text-black border-cyan-400'
                    : 'bg-white/5 text-white/60 border-white/10 hover:bg-white/10'
                }`}
              >
                Selected Endpoint ({selectedEndpoint?.name || 'Host'})
              </button>
              <button
                onClick={() => setContextMode('all')}
                className={`px-3 py-1 rounded text-[10px] uppercase font-bold transition cursor-pointer border ${
                  contextMode === 'all'
                    ? 'bg-cyan-500 text-black border-cyan-400'
                    : 'bg-white/5 text-white/60 border-white/10 hover:bg-white/10'
                }`}
              >
                All Network Hosts ({endpoints.length})
              </button>
              <button
                onClick={() => setContextMode('none')}
                className={`px-3 py-1 rounded text-[10px] uppercase font-bold transition cursor-pointer border ${
                  contextMode === 'none'
                    ? 'bg-cyan-500 text-black border-cyan-400'
                    : 'bg-white/5 text-white/60 border-white/10 hover:bg-white/10'
                }`}
              >
                No Host Data (General Query)
              </button>
            </div>
          </div>

          {/* Custom Prompt Box */}
          <div className="space-y-2">
            <textarea
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              placeholder="Ask a complex security question (e.g., 'How to execute a domain-wide kerberoasting audit & implement gMSA service accounts while enforcing GPO LDAP signing?')..."
              className="w-full h-28 bg-black/80 border border-cyan-500/30 rounded-xl p-3 text-xs text-white placeholder-white/40 focus:outline-none focus:border-cyan-400 transition font-mono resize-none"
            />
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-white/40 font-sans">
                Model: <code className="text-cyan-300 font-mono">gemini-3.8-flash</code> | Fallback: <code className="text-cyan-300 font-mono">Active (Zero-Fail)</code>
              </span>
              <button
                onClick={() => handleAnalyze()}
                disabled={loading || !prompt.trim()}
                className="px-5 py-2 bg-gradient-to-r from-cyan-500 to-cyan-400 hover:from-cyan-400 hover:to-cyan-300 disabled:opacity-50 text-black font-black text-xs uppercase tracking-wider rounded-xl transition shadow-lg shadow-cyan-950 flex items-center gap-2 cursor-pointer"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-4 h-4 text-black animate-spin" />
                    Deep Reasoning Thinking...
                  </>
                ) : (
                  <>
                    <Send className="w-4 h-4 text-black" />
                    Execute High-Thinking Analysis
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Error Message */}
          {error && (
            <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-red-300 text-xs flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
              <div>
                <p className="font-bold">Gemini Analysis Error:</p>
                <p className="text-[11px] text-red-200/80 font-sans mt-0.5">{error}</p>
              </div>
            </div>
          )}

          {/* Reasoning Results Box */}
          {analysisResult && (
            <div className="bg-[#051622] border-2 border-cyan-500/40 rounded-xl p-5 space-y-4 shadow-xl">
              <div className="flex items-center justify-between border-b border-cyan-500/30 pb-3 flex-wrap gap-2">
                <div className="flex items-center gap-2">
                  <Brain className="w-5 h-5 text-cyan-400" />
                  <h4 className="text-xs font-black text-white uppercase tracking-wider flex items-center gap-2">
                    SecOps Reasoning Output
                    {engineTypeUsed === 'gemini_api' ? (
                      <span className="text-[9px] bg-cyan-500/20 text-cyan-300 border border-cyan-400/40 px-2 py-0.5 rounded font-mono font-bold uppercase">
                        Gemini AI Live
                      </span>
                    ) : (
                      <span className="text-[9px] bg-emerald-500/20 text-emerald-300 border border-emerald-400/40 px-2 py-0.5 rounded font-mono font-bold uppercase">
                        Built-In SecOps Engine (Free)
                      </span>
                    )}
                  </h4>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleCopy}
                    className="px-3 py-1 bg-white/10 hover:bg-white/20 text-white rounded text-[10px] uppercase font-bold flex items-center gap-1.5 transition cursor-pointer border border-white/10"
                  >
                    {copied ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        Copied!
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5 text-cyan-300" />
                        Copy Result
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Formatted Output Text */}
              <div className="bg-black/80 border border-white/10 rounded-lg p-4 text-xs text-cyan-50/90 whitespace-pre-wrap font-sans leading-relaxed max-h-96 overflow-y-auto font-mono text-left">
                {analysisResult}
              </div>
            </div>
          )}

        </div>

        {/* Footer info */}
        <div className="p-3 bg-black/80 border-t border-cyan-500/20 text-[10px] text-white/50 flex items-center justify-between shrink-0 font-sans">
          <span>SmartPro SecOps Enterprise AI Engine</span>
          <span>Configured: gemini-3.8-flash with automatic offline failover</span>
        </div>

      </div>
    </div>
  );
}
