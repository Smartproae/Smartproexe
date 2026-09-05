import React, { useState } from 'react';
import { Download, Copy, Check, X, FileText, Database, Code, Upload, CheckCircle2, Shield, Layout, ShieldAlert } from 'lucide-react';
import { Endpoint } from '../types';
import { remediations } from '../remediationData';
import { POWERSHELL_AUDIT_SCRIPT } from '../auditScript';
import { VULNERABILITIES_60_DATABASE } from '../data/vulnerabilities60';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  endpoints: Endpoint[];
  onImportConfig?: (importedEndpoints: Endpoint[]) => void;
  onOpenGitHubModal?: () => void;
}

export default function DashboardConfigExportModal({ isOpen, onClose, endpoints, onImportConfig, onOpenGitHubModal }: Props) {
  const [copiedJson, setCopiedJson] = useState(false);
  const [copiedScriptConfig, setCopiedScriptConfig] = useState(false);
  const [copiedReactCode, setCopiedReactCode] = useState(false);
  const [importText, setImportText] = useState('');
  const [importStatus, setImportStatus] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [activeTab, setActiveTab] = useState<'export' | 'script' | 'react' | 'import' | 'github'>('export');

  if (!isOpen) return null;

  // System Posture Stats
  const totalEndpoints = endpoints.length;
  const avgScore = Math.round(endpoints.reduce((acc, ep) => acc + (ep.overallScore || 0), 0) / (totalEndpoints || 1));
  const criticalCount = endpoints.filter(ep => ep.status === 'vulnerable').length;
  const warningCount = endpoints.filter(ep => ep.status === 'warning').length;
  const secureCount = endpoints.filter(ep => ep.status === 'secure').length;

  // Complete dashboard configuration package
  const fullDashboardConfig = {
    appName: "SmartPro SecOps Security Auditor & Endpoint Guard",
    version: "2.5.0",
    exportedAt: new Date().toISOString(),
    systemSummary: {
      totalEndpoints,
      averageScore: avgScore,
      criticalCount,
      warningCount,
      secureCount,
      healthStatus: avgScore >= 80 ? "HEALTHY" : avgScore >= 60 ? "WARNING" : "CRITICAL"
    },
    endpoints: endpoints,
    vulnerabilitiesCatalog60: VULNERABILITIES_60_DATABASE,
    remediationsRules: remediations,
    powerShellAuditScript: POWERSHELL_AUDIT_SCRIPT,
    wingetAutoUpdateCommand: "winget upgrade --all --include-unknown --accept-package-agreements --accept-source-agreements --silent",
    winUtilBootstrapCommand: "irm christitus.com/win | iex"
  };

  const jsonString = JSON.stringify(fullDashboardConfig, null, 2);

  // Standalone React Component Template snippet to recreate identical dashboard in another page
  const reactDashboardCodeTemplate = `// SmartPro SecOps - Security Auditor Dashboard Component
// Paste this component into your new application page to replicate the identical dashboard design

import React from 'react';
import { Shield, Server, AlertTriangle, CheckCircle2, Zap, Database } from 'lucide-react';

const DASHBOARD_CONFIG = ${jsonString};

export default function ReplicatedSecurityDashboard() {
  const { systemSummary, endpoints } = DASHBOARD_CONFIG;

  return (
    <div className="min-h-screen bg-[#050505] text-white p-6 font-sans">
      {/* Header Banner */}
      <div className="border-2 border-[#FF3B30] bg-[#0A0A0A] p-6 rounded-xl shadow-2xl mb-8 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <span className="bg-[#FF3B30] text-black text-[10px] font-black uppercase px-2 py-0.5 tracking-widest font-mono">
            SMARTPRO SECOPS V2.5
          </span>
          <h1 className="text-2xl md:text-3xl font-black uppercase tracking-tight mt-2 text-white">
            Security Auditor & Endpoint Dashboard
          </h1>
          <p className="text-white/60 text-xs mt-1">
            Replicated SecOps Engine - Monitored Endpoints: {systemSummary.totalEndpoints} | Overall Security Score: {systemSummary.averageScore}/100
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="bg-[#111111] border border-white/20 px-4 py-2 rounded-lg text-center font-mono">
            <span className="text-[10px] text-white/50 block font-bold">AVG SCORE</span>
            <span className="text-xl font-black text-amber-400">{systemSummary.averageScore} / 100</span>
          </div>
          <div className="bg-[#FF3B30]/20 border border-[#FF3B30] px-4 py-2 rounded-lg text-center font-mono">
            <span className="text-[10px] text-[#FF3B30] block font-bold">CRITICAL RISK</span>
            <span className="text-xl font-black text-[#FF3B30]">{systemSummary.criticalCount} UNITS</span>
          </div>
        </div>
      </div>

      {/* Endpoints Posture Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {endpoints.map((ep: any) => (
          <div key={ep.id} className="bg-[#0C0C0C] border border-white/15 p-5 rounded-xl hover:border-[#FF3B30] transition space-y-4">
            <div className="flex justify-between items-start">
              <div>
                <h3 className="font-bold text-base text-white font-mono">{ep.name || ep.scanData?.hostname}</h3>
                <span className="text-xs text-white/50">{ep.ip} &bull; {ep.os}</span>
              </div>
              <span className={\`px-2.5 py-1 text-[10px] font-black uppercase rounded font-mono \${
                ep.status === 'vulnerable' ? 'bg-[#FF3B30] text-white' : ep.status === 'warning' ? 'bg-amber-500 text-black' : 'bg-emerald-500 text-black'
              }\`}>
                {ep.status} ({ep.overallScore}/100)
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
`;

  const copyToClipboard = (text: string, setCopiedState: (v: boolean) => void) => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
          setCopiedState(true);
          setTimeout(() => setCopiedState(false), 2000);
        });
      } else {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.position = "fixed";
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand("copy");
        document.body.removeChild(textArea);
        setCopiedState(true);
        setTimeout(() => setCopiedState(false), 2000);
      }
    } catch (e) {
      console.error("Copy failed", e);
    }
  };

  const downloadFile = (filename: string, content: string, mimeType: string = 'application/json') => {
    const element = document.createElement("a");
    const file = new Blob([content], { type: mimeType });
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const handleImport = () => {
    setImportStatus(null);
    if (!importText.trim()) {
      setImportStatus({ type: 'error', text: 'Please paste valid dashboard JSON configuration.' });
      return;
    }

    try {
      const parsed = JSON.parse(importText);
      if (parsed.endpoints && Array.isArray(parsed.endpoints) && parsed.endpoints.length > 0) {
        if (onImportConfig) {
          onImportConfig(parsed.endpoints);
        }
        setImportStatus({
          type: 'success',
          text: `Successfully imported ${parsed.endpoints.length} endpoint configurations into dashboard!`
        });
      } else {
        setImportStatus({ type: 'error', text: 'Invalid JSON format. Missing "endpoints" array.' });
      }
    } catch (err: any) {
      setImportStatus({ type: 'error', text: `JSON Parse Error: ${err.message}` });
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-md p-4 font-sans animate-fadeIn">
      <div className="bg-[#080808] border-2 border-[#FF3B30]/60 rounded-2xl max-w-5xl w-full overflow-hidden shadow-2xl flex flex-col max-h-[94vh]">
        
        {/* Header - Identical High-Contrast Dashboard Aesthetic */}
        <div className="bg-[#0D0D0D] border-b-2 border-[#FF3B30] p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-[#FF3B30]/15 border border-[#FF3B30] rounded-xl text-[#FF3B30]">
              <Database className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="bg-[#FF3B30] text-black text-[9px] font-black uppercase px-2 py-0.5 tracking-widest font-mono">
                  EXPORT CONFIG ENGINE
                </span>
                <span className="text-[10px] font-mono text-amber-400 font-bold uppercase">
                  DASHBOARD LOOK & STATE PACKAGE
                </span>
              </div>
              <h3 className="text-xl font-black text-white uppercase tracking-tight mt-1">
                Dashboard Design & Settings Export
              </h3>
            </div>
          </div>

          {/* Posture Metrics Mirror */}
          <div className="flex items-center gap-2.5 font-mono">
            <div className="bg-[#141414] border border-white/15 px-3 py-1.5 rounded-lg text-center">
              <span className="text-[9px] text-white/50 block font-bold">POSTURE</span>
              <span className="text-xs font-black text-amber-400">{avgScore} / 100</span>
            </div>
            <div className="bg-[#FF3B30]/20 border border-[#FF3B30]/50 px-3 py-1.5 rounded-lg text-center">
              <span className="text-[9px] text-[#FF3B30] block font-bold">UNITS</span>
              <span className="text-xs font-black text-[#FF3B30]">{totalEndpoints} ENDPOINTS</span>
            </div>
            <button
              onClick={onClose}
              className="p-2 text-white/50 hover:text-white hover:bg-white/10 rounded-lg transition cursor-pointer"
            >
              <X className="w-6 h-6 text-[#FF3B30]" />
            </button>
          </div>
        </div>

        {/* Identical Dashboard View Card Preview */}
        <div className="bg-[#111111] border-b border-white/10 p-4 font-mono text-xs text-white/70 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Layout className="w-4 h-4 text-cyan-400" />
            <span>Dashboard Layout Target: <strong className="text-white">SmartPro SecOps Red-Line Dark Canvas</strong></span>
          </div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 rounded text-[10px] font-bold">
              {secureCount} SECURE
            </span>
            <span className="px-2 py-0.5 bg-amber-500/20 text-amber-400 border border-amber-500/40 rounded text-[10px] font-bold">
              {warningCount} WARNINGS
            </span>
            <span className="px-2 py-0.5 bg-[#FF3B30]/20 text-[#FF3B30] border border-[#FF3B30]/40 rounded text-[10px] font-bold">
              {criticalCount} CRITICAL
            </span>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="bg-[#0A0A0A] border-b border-white/10 flex flex-wrap px-4 gap-2 pt-2">
          <button
            onClick={() => setActiveTab('export')}
            className={`px-4 py-2.5 text-xs font-black uppercase tracking-wider flex items-center gap-2 cursor-pointer transition ${
              activeTab === 'export'
                ? 'border-b-2 border-amber-400 text-white bg-amber-500/10'
                : 'text-white/50 hover:text-white hover:bg-white/5'
            }`}
          >
            <Database className="w-4 h-4 text-amber-400" />
            1. Full Config JSON
          </button>

          <button
            onClick={() => setActiveTab('script')}
            className={`px-4 py-2.5 text-xs font-black uppercase tracking-wider flex items-center gap-2 cursor-pointer transition ${
              activeTab === 'script'
                ? 'border-b-2 border-cyan-400 text-white bg-cyan-500/10'
                : 'text-white/50 hover:text-white hover:bg-white/5'
            }`}
          >
            <FileText className="w-4 h-4 text-cyan-400" />
            2. Notepad / PowerShell Text
          </button>

          <button
            onClick={() => setActiveTab('react')}
            className={`px-4 py-2.5 text-xs font-black uppercase tracking-wider flex items-center gap-2 cursor-pointer transition ${
              activeTab === 'react'
                ? 'border-b-2 border-[#FF3B30] text-white bg-[#FF3B30]/10'
                : 'text-white/50 hover:text-white hover:bg-white/5'
            }`}
          >
            <Code className="w-4 h-4 text-[#FF3B30]" />
            3. React Layout Code (.tsx)
          </button>

          <button
            onClick={() => setActiveTab('import')}
            className={`px-4 py-2.5 text-xs font-black uppercase tracking-wider flex items-center gap-2 cursor-pointer transition ${
              activeTab === 'import'
                ? 'border-b-2 border-emerald-400 text-white bg-emerald-500/10'
                : 'text-white/50 hover:text-white hover:bg-white/5'
            }`}
          >
            <Upload className="w-4 h-4 text-emerald-400" />
            4. Import Config
          </button>

          <button
            onClick={() => {
              if (onOpenGitHubModal) {
                onClose();
                onOpenGitHubModal();
              } else {
                setActiveTab('github');
              }
            }}
            className={`px-4 py-2.5 text-xs font-black uppercase tracking-wider flex items-center gap-2 cursor-pointer transition ${
              activeTab === 'github'
                ? 'border-b-2 border-amber-400 text-white bg-amber-500/10'
                : 'text-white/50 hover:text-white hover:bg-white/5'
            }`}
          >
            <svg className="w-4 h-4 fill-amber-400" viewBox="0 0 24 24">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
            </svg>
            5. GitHub Direct Sync
          </button>
        </div>

        {/* Modal Content Area */}
        <div className="p-6 overflow-y-auto space-y-5 text-left font-sans">
          
          {activeTab === 'export' && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-amber-500/10 border border-amber-500/30 p-4 rounded-xl">
                <div>
                  <h4 className="text-sm font-black text-white uppercase tracking-wide flex items-center gap-2 font-mono">
                    <Database className="w-4 h-4 text-amber-400" />
                    Complete Dashboard State & Config Schema
                  </h4>
                  <p className="text-xs text-white/70 mt-1">
                    Contains all endpoint postures, 60 vulnerability criteria, remediation data, and Winget auto-update configs for another app.
                  </p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => copyToClipboard(jsonString, setCopiedJson)}
                    className="px-4 py-2.5 bg-amber-500 hover:bg-amber-600 text-black text-xs font-black uppercase tracking-wider rounded-lg transition flex items-center gap-2 cursor-pointer shadow-lg shadow-amber-950/40"
                  >
                    {copiedJson ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                    {copiedJson ? 'Copied JSON!' : 'Copy Config JSON'}
                  </button>

                  <button
                    onClick={() => downloadFile('SmartPro_Dashboard_Config.json', jsonString, 'application/json')}
                    className="px-4 py-2.5 bg-white/10 hover:bg-white/20 text-white text-xs font-black uppercase tracking-wider rounded-lg border border-white/20 transition flex items-center gap-2 cursor-pointer"
                  >
                    <Download className="w-4 h-4 text-amber-400" />
                    Export .json
                  </button>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs text-white/50 font-mono">
                  <span>Dashboard State JSON (Version 2.5)</span>
                  <span>{Math.round(jsonString.length / 1024)} KB</span>
                </div>
                <div className="bg-[#050505] border border-white/15 rounded-xl p-4 max-h-[380px] overflow-y-auto">
                  <pre className="font-mono text-[11px] text-amber-300/90 leading-relaxed whitespace-pre overflow-x-auto select-all">
                    {jsonString}
                  </pre>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'script' && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-cyan-500/10 border border-cyan-500/30 p-4 rounded-xl">
                <div>
                  <h4 className="text-sm font-black text-white uppercase tracking-wide flex items-center gap-2 font-mono">
                    <FileText className="w-4 h-4 text-cyan-400" />
                    Notepad & PowerShell Execution Script Text
                  </h4>
                  <p className="text-xs text-white/70 mt-1">
                    Copy or save directly as Notepad text (.txt), PowerShell script (.ps1), or Batch (.bat) to run on local or network endpoints.
                  </p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => copyToClipboard(POWERSHELL_AUDIT_SCRIPT, setCopiedScriptConfig)}
                    className="px-4 py-2.5 bg-cyan-400 hover:bg-cyan-500 text-black text-xs font-black uppercase tracking-wider rounded-lg transition flex items-center gap-2 cursor-pointer shadow-lg shadow-cyan-950/40"
                  >
                    {copiedScriptConfig ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                    {copiedScriptConfig ? 'Copied Text!' : 'Copy Script Text'}
                  </button>

                  <button
                    onClick={() => downloadFile('SmartPro_AuditScript.txt', POWERSHELL_AUDIT_SCRIPT, 'text/plain')}
                    className="px-4 py-2.5 bg-white/10 hover:bg-white/20 text-white text-xs font-black uppercase tracking-wider rounded-lg border border-white/20 transition flex items-center gap-2 cursor-pointer"
                  >
                    <Download className="w-4 h-4 text-cyan-400" />
                    Notepad (.txt)
                  </button>
                </div>
              </div>

              <div className="bg-[#050505] border border-white/15 rounded-xl p-4 max-h-[380px] overflow-y-auto">
                <pre className="font-mono text-[11px] text-cyan-300/90 leading-relaxed whitespace-pre overflow-x-auto select-all">
                  {POWERSHELL_AUDIT_SCRIPT}
                </pre>
              </div>
            </div>
          )}

          {activeTab === 'react' && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#FF3B30]/10 border border-[#FF3B30]/30 p-4 rounded-xl">
                <div>
                  <h4 className="text-sm font-black text-white uppercase tracking-wide flex items-center gap-2 font-mono">
                    <Code className="w-4 h-4 text-[#FF3B30]" />
                    Dashboard React/Tailwind Standalone Component
                  </h4>
                  <p className="text-xs text-white/70 mt-1">
                    Copy this entire React TypeScript component to paste into your new application or page to render the exact same dashboard layout!
                  </p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => copyToClipboard(reactDashboardCodeTemplate, setCopiedReactCode)}
                    className="px-4 py-2.5 bg-[#FF3B30] hover:bg-[#E02E24] text-white text-xs font-black uppercase tracking-wider rounded-lg transition flex items-center gap-2 cursor-pointer shadow-lg shadow-red-950/40"
                  >
                    {copiedReactCode ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    {copiedReactCode ? 'Copied TSX Code!' : 'Copy Component TSX'}
                  </button>

                  <button
                    onClick={() => downloadFile('ReplicatedSecurityDashboard.tsx', reactDashboardCodeTemplate, 'text/typescript')}
                    className="px-4 py-2.5 bg-white/10 hover:bg-white/20 text-white text-xs font-black uppercase tracking-wider rounded-lg border border-white/20 transition flex items-center gap-2 cursor-pointer"
                  >
                    <Download className="w-4 h-4 text-[#FF3B30]" />
                    Export (.tsx)
                  </button>
                </div>
              </div>

              <div className="bg-[#050505] border border-white/15 rounded-xl p-4 max-h-[380px] overflow-y-auto">
                <pre className="font-mono text-[11px] text-red-300/90 leading-relaxed whitespace-pre overflow-x-auto select-all">
                  {reactDashboardCodeTemplate}
                </pre>
              </div>
            </div>
          )}

          {activeTab === 'import' && (
            <div className="space-y-4">
              <div className="bg-emerald-500/10 border border-emerald-500/30 p-4 rounded-xl">
                <h4 className="text-sm font-black text-white uppercase tracking-wide flex items-center gap-2 font-mono">
                  <Upload className="w-4 h-4 text-emerald-400" />
                  Import Configuration & Attach to Dashboard
                </h4>
                <p className="text-xs text-white/70 mt-1">
                  Paste the JSON configuration exported from another page or application to attach and restore all system endpoints and vulnerability settings into this dashboard instantly.
                </p>
              </div>

              <textarea
                value={importText}
                onChange={(e) => setImportText(e.target.value)}
                placeholder="Paste Dashboard Config JSON here..."
                className="w-full h-52 bg-[#050505] border border-white/20 rounded-xl p-4 text-xs font-mono text-emerald-300 focus:outline-none focus:border-emerald-500 resize-none"
              />

              {importStatus && (
                <div className={`p-3 rounded-lg text-xs font-bold flex items-center gap-2 ${
                  importStatus.type === 'success' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'bg-red-500/20 text-red-300 border border-red-500/40'
                }`}>
                  {importStatus.type === 'success' ? <CheckCircle2 className="w-4 h-4 shrink-0" /> : <ShieldAlert className="w-4 h-4 shrink-0" />}
                  <span>{importStatus.text}</span>
                </div>
              )}

              <div className="flex justify-end gap-2">
                <button
                  onClick={handleImport}
                  className="px-5 py-2.5 bg-emerald-500 hover:bg-emerald-600 text-black text-xs font-black uppercase tracking-wider rounded-lg transition flex items-center gap-2 cursor-pointer shadow-lg shadow-emerald-950/30"
                >
                  <Upload className="w-4 h-4" />
                  Apply & Attach Configuration
                </button>
              </div>
            </div>
          )}

        </div>

        {/* Footer */}
        <div className="bg-[#0D0D0D] border-t border-white/10 p-4 flex justify-between items-center text-xs text-white/50 font-mono">
          <span>SmartPro SecOps Config Manager v2.5</span>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-white/10 hover:bg-white/20 text-white rounded font-bold uppercase transition cursor-pointer"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
}
