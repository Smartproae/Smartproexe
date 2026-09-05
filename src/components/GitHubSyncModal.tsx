import React, { useState, useEffect } from 'react';
import { 
  X, Check, Copy, Download, RefreshCw, Upload, Shield, 
  CheckCircle2, AlertTriangle, ExternalLink, Key, Database, 
  GitBranch, GitCommit, Play, Clock, Sparkles, Server, FileCode,
  Lock, Globe, ShieldAlert, Cpu, ArrowUpRight
} from 'lucide-react';
import { Endpoint } from '../types';
import { POWERSHELL_AUDIT_SCRIPT } from '../auditScript';
import { remediations } from '../remediationData';
import { VULNERABILITIES_60_DATABASE } from '../data/vulnerabilities60';
import { 
  GitHubSyncConfig, 
  loadGitHubConfig, 
  saveGitHubConfig, 
  verifyGitHubToken, 
  commitFileToGitHub, 
  createGitHubGist, 
  loadSyncHistory, 
  SyncHistoryItem 
} from '../lib/githubSyncService';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  endpoints: Endpoint[];
}

export default function GitHubSyncModal({ isOpen, onClose, endpoints }: Props) {
  const [config, setConfig] = useState<GitHubSyncConfig>(loadGitHubConfig());
  const [history, setHistory] = useState<SyncHistoryItem[]>(loadSyncHistory());
  const [activeTab, setActiveTab] = useState<'upload' | 'gist' | 'autosync' | 'history'>('upload');
  
  // Auth state
  const [verifying, setVerifying] = useState(false);
  const [userInfo, setUserInfo] = useState<{ username?: string; avatarUrl?: string; valid: boolean } | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);

  // Upload state
  const [selectedUploadTarget, setSelectedUploadTarget] = useState<'audit_ps1' | 'dashboard_json' | 'remediations_json' | 'vulnerabilities_json'>('audit_ps1');
  const [customPath, setCustomPath] = useState('secops/AuditEndpointSecurity.ps1');
  const [commitMsg, setCommitMsg] = useState('feat(secops): Update SmartPro Endpoint Guard audit script & rules');
  const [isUploading, setIsUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<{ success: boolean; commitSha?: string; htmlUrl?: string; error?: string } | null>(null);

  // Gist state
  const [gistDescription, setGistDescription] = useState('SmartPro SecOps - Endpoint Security Audit & Hardening Script');
  const [gistFilename, setGistFilename] = useState('AuditEndpointSecurity.ps1');
  const [gistIsPublic, setGistIsPublic] = useState(false);
  const [isCreatingGist, setIsCreatingGist] = useState(false);
  const [gistResult, setGistResult] = useState<{ success: boolean; gistUrl?: string; rawUrl?: string; error?: string } | null>(null);
  const [copiedRawGist, setCopiedRawGist] = useState(false);

  // Auto sync state
  const [autoSyncStatusMsg, setAutoSyncStatusMsg] = useState<string | null>(null);

  // On mount or token update when open, test token if provided
  useEffect(() => {
    if (isOpen && config.token.trim()) {
      handleVerifyToken(config.token);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  // Update default file path when target changes
  const handleTargetChange = (target: 'audit_ps1' | 'dashboard_json' | 'remediations_json' | 'vulnerabilities_json') => {
    setSelectedUploadTarget(target);
    if (target === 'audit_ps1') setCustomPath('secops/AuditEndpointSecurity.ps1');
    else if (target === 'dashboard_json') setCustomPath('secops/SmartPro_Dashboard_Config.json');
    else if (target === 'remediations_json') setCustomPath('secops/remediation-rules.json');
    else if (target === 'vulnerabilities_json') setCustomPath('secops/vulnerabilities-60-db.json');
  };

  const handleVerifyToken = async (tokenToTest: string) => {
    if (!tokenToTest.trim()) {
      setUserInfo(null);
      setAuthError('Please enter a GitHub Personal Access Token (PAT).');
      return;
    }

    setVerifying(true);
    setAuthError(null);
    const result = await verifyGitHubToken(tokenToTest);
    setVerifying(false);

    if (result.valid) {
      setUserInfo({ username: result.username, avatarUrl: result.avatarUrl, valid: true });
    } else {
      setUserInfo({ valid: false });
      setAuthError(result.error || 'Token verification failed.');
    }
  };

  const handleSaveConfig = (newCfg: GitHubSyncConfig) => {
    setConfig(newCfg);
    saveGitHubConfig(newCfg);
  };

  const getContentForTarget = (target: string): string => {
    if (target === 'audit_ps1') {
      return POWERSHELL_AUDIT_SCRIPT;
    }
    if (target === 'dashboard_json') {
      const fullConfig = {
        appName: "SmartPro SecOps Security Auditor & Endpoint Guard",
        version: "2.5.0",
        exportedAt: new Date().toISOString(),
        systemSummary: {
          totalEndpoints: endpoints.length,
          avgScore: Math.round(endpoints.reduce((acc, ep) => acc + (ep.overallScore || 0), 0) / (endpoints.length || 1)),
          criticalCount: endpoints.filter(ep => ep.status === 'vulnerable').length,
          warningCount: endpoints.filter(ep => ep.status === 'warning').length,
          secureCount: endpoints.filter(ep => ep.status === 'secure').length
        },
        endpoints: endpoints,
        vulnerabilitiesCatalog60: VULNERABILITIES_60_DATABASE,
        remediationsRules: remediations
      };
      return JSON.stringify(fullConfig, null, 2);
    }
    if (target === 'remediations_json') {
      return JSON.stringify(remediations, null, 2);
    }
    return JSON.stringify(VULNERABILITIES_60_DATABASE, null, 2);
  };

  const handleExecuteUpload = async () => {
    setIsUploading(true);
    setUploadResult(null);

    const content = getContentForTarget(selectedUploadTarget);

    const result = await commitFileToGitHub({
      token: config.token,
      owner: config.owner || 'SmartPro-SecOps',
      repo: config.repo || 'endpoint-guard-scripts',
      branch: config.branch || 'main',
      filePath: customPath,
      content,
      commitMessage: commitMsg
    });

    setIsUploading(false);
    setUploadResult(result);
    setHistory(loadSyncHistory());

    if (result.success) {
      const now = new Date().toISOString();
      handleSaveConfig({ ...config, lastSyncedAt: now });
    }
  };

  const handleCreateGist = async () => {
    setIsCreatingGist(true);
    setGistResult(null);

    const content = getContentForTarget(selectedUploadTarget);

    const result = await createGitHubGist({
      token: config.token,
      description: gistDescription,
      filename: gistFilename,
      content,
      isPublic: gistIsPublic
    });

    setIsCreatingGist(false);
    setGistResult(result);
    setHistory(loadSyncHistory());
  };

  const copyToClipboard = (text: string, setCopied: (v: boolean) => void) => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        });
      } else {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.position = "fixed";
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand("copy");
        document.body.removeChild(textArea);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }
    } catch (e) {
      console.error("Copy failed", e);
    }
  };

  const handleDemoPreset = () => {
    const demoCfg: GitHubSyncConfig = {
      ...config,
      owner: 'SmartPro-SecOps',
      repo: 'endpoint-guard-live',
      branch: 'main'
    };
    handleSaveConfig(demoCfg);
    if (!config.token) {
      setUserInfo({ username: 'SmartPro-SecOps-Bot', valid: true });
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-md p-4 font-sans animate-fadeIn">
      <div className="bg-[#080808] border-2 border-[#FF3B30]/60 rounded-2xl max-w-5xl w-full overflow-hidden shadow-2xl flex flex-col max-h-[94vh]">
        
        {/* Header - Identical Dark Canvas Styling */}
        <div className="bg-[#0D0D0D] border-b-2 border-[#FF3B30] p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-[#FF3B30]/15 border border-[#FF3B30] rounded-xl text-[#FF3B30]">
              <svg className="w-6 h-6 fill-current" viewBox="0 0 24 24">
                <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
              </svg>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="bg-[#FF3B30] text-black text-[9px] font-black uppercase px-2 py-0.5 tracking-widest font-mono">
                  GITHUB LIVE SYNC ENGINE
                </span>
                <span className="text-[10px] font-mono text-amber-400 font-bold uppercase">
                  DIRECT REPO COMMIT & GIST PUBLISHER
                </span>
              </div>
              <h3 className="text-xl font-black text-white uppercase tracking-tight mt-1">
                GitHub Repository & Script Sync
              </h3>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {userInfo?.valid ? (
              <div className="flex items-center gap-2 bg-emerald-500/15 border border-emerald-500/40 px-3 py-1.5 rounded-lg text-emerald-400 text-xs font-mono font-bold">
                {userInfo.avatarUrl && <img src={userInfo.avatarUrl} alt="Avatar" className="w-5 h-5 rounded-full border border-emerald-400" />}
                <span>@{userInfo.username}</span>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              </div>
            ) : (
              <div className="bg-amber-500/15 border border-amber-500/40 px-3 py-1.5 rounded-lg text-amber-400 text-xs font-mono font-bold flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>OFFLINE / SIMULATION MODE</span>
              </div>
            )}

            <button
              onClick={onClose}
              className="p-2 text-white/50 hover:text-white hover:bg-white/10 rounded-lg transition cursor-pointer"
            >
              <X className="w-6 h-6 text-[#FF3B30]" />
            </button>
          </div>
        </div>

        {/* GitHub Credentials & Connection Bar */}
        <div className="bg-[#121212] border-b border-white/10 p-4 font-mono text-xs text-white/80 space-y-3">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
            <div className="flex-1 w-full flex flex-col sm:flex-row items-center gap-2">
              <div className="relative flex-1 w-full">
                <Key className="w-4 h-4 text-amber-400 absolute left-3 top-2.5" />
                <input
                  type="password"
                  value={config.token}
                  onChange={(e) => {
                    const val = e.target.value;
                    handleSaveConfig({ ...config, token: val });
                  }}
                  placeholder="Paste GitHub Personal Access Token (PAT ghp_...)"
                  className="w-full bg-[#050505] border border-white/20 rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-amber-300 focus:outline-none focus:border-amber-400"
                />
              </div>

              <button
                onClick={() => handleVerifyToken(config.token)}
                disabled={verifying}
                className="px-4 py-2 bg-amber-500 hover:bg-amber-600 text-black font-black uppercase text-xs rounded-lg transition flex items-center gap-1.5 shrink-0 cursor-pointer disabled:opacity-50"
              >
                {verifying ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Key className="w-3.5 h-3.5" />}
                {verifying ? 'Verifying...' : 'Verify PAT'}
              </button>

              <button
                onClick={handleDemoPreset}
                className="px-3 py-2 bg-white/10 hover:bg-white/20 text-white text-xs font-bold uppercase rounded-lg border border-white/20 transition flex items-center gap-1 shrink-0 cursor-pointer"
                title="Fill demo repository defaults"
              >
                <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                Preset Repo
              </button>
            </div>
          </div>

          {authError && (
            <div className="text-[11px] text-red-400 bg-red-500/10 border border-red-500/30 p-2 rounded flex items-center gap-2">
              <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0" />
              <span>{authError} - (Note: You can still use Direct Upload simulation mode!)</span>
            </div>
          )}
        </div>

        {/* Tab Navigation */}
        <div className="bg-[#0A0A0A] border-b border-white/10 flex flex-wrap px-4 gap-2 pt-2">
          <button
            onClick={() => setActiveTab('upload')}
            className={`px-4 py-2.5 text-xs font-black uppercase tracking-wider flex items-center gap-2 cursor-pointer transition ${
              activeTab === 'upload'
                ? 'border-b-2 border-amber-400 text-white bg-amber-500/10'
                : 'text-white/50 hover:text-white hover:bg-white/5'
            }`}
          >
            <Upload className="w-4 h-4 text-amber-400" />
            1. Commit & Upload to Repo
          </button>

          <button
            onClick={() => setActiveTab('gist')}
            className={`px-4 py-2.5 text-xs font-black uppercase tracking-wider flex items-center gap-2 cursor-pointer transition ${
              activeTab === 'gist'
                ? 'border-b-2 border-cyan-400 text-white bg-cyan-500/10'
                : 'text-white/50 hover:text-white hover:bg-white/5'
            }`}
          >
            <FileCode className="w-4 h-4 text-cyan-400" />
            2. Publish GitHub Gist
          </button>

          <button
            onClick={() => setActiveTab('autosync')}
            className={`px-4 py-2.5 text-xs font-black uppercase tracking-wider flex items-center gap-2 cursor-pointer transition ${
              activeTab === 'autosync'
                ? 'border-b-2 border-[#FF3B30] text-white bg-[#FF3B30]/10'
                : 'text-white/50 hover:text-white hover:bg-white/5'
            }`}
          >
            <RefreshCw className="w-4 h-4 text-[#FF3B30]" />
            3. Auto Live-Sync Settings
          </button>

          <button
            onClick={() => setActiveTab('history')}
            className={`px-4 py-2.5 text-xs font-black uppercase tracking-wider flex items-center gap-2 cursor-pointer transition ${
              activeTab === 'history'
                ? 'border-b-2 border-emerald-400 text-white bg-emerald-500/10'
                : 'text-white/50 hover:text-white hover:bg-white/5'
            }`}
          >
            <Clock className="w-4 h-4 text-emerald-400" />
            4. Sync History ({history.length})
          </button>
        </div>

        {/* Modal Main Content Area */}
        <div className="p-6 overflow-y-auto space-y-6 text-left font-sans">

          {activeTab === 'upload' && (
            <div className="space-y-5">
              
              {/* Target File Selection */}
              <div className="space-y-2">
                <label className="text-xs font-black text-white uppercase tracking-wider font-mono flex items-center gap-2">
                  <Database className="w-4 h-4 text-amber-400" />
                  Select Component to Push to GitHub:
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 font-mono">
                  <button
                    onClick={() => handleTargetChange('audit_ps1')}
                    className={`p-3 rounded-xl border text-left transition cursor-pointer flex flex-col justify-between ${
                      selectedUploadTarget === 'audit_ps1'
                        ? 'bg-amber-500/15 border-amber-400 text-white shadow-lg shadow-amber-950/30'
                        : 'bg-[#0D0D0D] border-white/15 text-white/60 hover:border-white/30'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase font-bold text-amber-400">PowerShell Script</span>
                      <FileCode className="w-4 h-4 text-amber-400" />
                    </div>
                    <span className="font-bold text-xs mt-2 text-white">AuditEndpointSecurity.ps1</span>
                    <span className="text-[10px] text-white/50 mt-1">Full 60-vulnerability auditor script</span>
                  </button>

                  <button
                    onClick={() => handleTargetChange('dashboard_json')}
                    className={`p-3 rounded-xl border text-left transition cursor-pointer flex flex-col justify-between ${
                      selectedUploadTarget === 'dashboard_json'
                        ? 'bg-cyan-500/15 border-cyan-400 text-white shadow-lg shadow-cyan-950/30'
                        : 'bg-[#0D0D0D] border-white/15 text-white/60 hover:border-white/30'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase font-bold text-cyan-400">Dashboard Config</span>
                      <Database className="w-4 h-4 text-cyan-400" />
                    </div>
                    <span className="font-bold text-xs mt-2 text-white">SmartPro_Dashboard_Config.json</span>
                    <span className="text-[10px] text-white/50 mt-1">Entire endpoints posture & layout state</span>
                  </button>

                  <button
                    onClick={() => handleTargetChange('remediations_json')}
                    className={`p-3 rounded-xl border text-left transition cursor-pointer flex flex-col justify-between ${
                      selectedUploadTarget === 'remediations_json'
                        ? 'bg-emerald-500/15 border-emerald-400 text-white shadow-lg shadow-emerald-950/30'
                        : 'bg-[#0D0D0D] border-white/15 text-white/60 hover:border-white/30'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase font-bold text-emerald-400">Remediation Rules</span>
                      <Shield className="w-4 h-4 text-emerald-400" />
                    </div>
                    <span className="font-bold text-xs mt-2 text-white">remediation-rules.json</span>
                    <span className="text-[10px] text-white/50 mt-1">Custom registry & GPO remediation steps</span>
                  </button>

                  <button
                    onClick={() => handleTargetChange('vulnerabilities_json')}
                    className={`p-3 rounded-xl border text-left transition cursor-pointer flex flex-col justify-between ${
                      selectedUploadTarget === 'vulnerabilities_json'
                        ? 'bg-[#FF3B30]/15 border-[#FF3B30] text-white shadow-lg shadow-red-950/30'
                        : 'bg-[#0D0D0D] border-white/15 text-white/60 hover:border-white/30'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase font-bold text-[#FF3B30]">CVE Database</span>
                      <ShieldAlert className="w-4 h-4 text-[#FF3B30]" />
                    </div>
                    <span className="font-bold text-xs mt-2 text-white">vulnerabilities-60-db.json</span>
                    <span className="text-[10px] text-white/50 mt-1">Catalog of 60 security checks</span>
                  </button>
                </div>
              </div>

              {/* Repository & Branch Parameters */}
              <div className="bg-[#0C0C0C] border border-white/15 rounded-xl p-4 space-y-4 font-mono text-xs">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="block text-white/60 text-[11px] font-bold uppercase mb-1">
                      Repository Owner / Org
                    </label>
                    <input
                      type="text"
                      value={config.owner}
                      onChange={(e) => handleSaveConfig({ ...config, owner: e.target.value })}
                      placeholder="e.g. SmartPro-SecOps"
                      className="w-full bg-[#050505] border border-white/20 rounded-lg p-2 text-white focus:outline-none focus:border-amber-400"
                    />
                  </div>

                  <div>
                    <label className="block text-white/60 text-[11px] font-bold uppercase mb-1">
                      Repository Name
                    </label>
                    <input
                      type="text"
                      value={config.repo}
                      onChange={(e) => handleSaveConfig({ ...config, repo: e.target.value })}
                      placeholder="e.g. endpoint-guard-scripts"
                      className="w-full bg-[#050505] border border-white/20 rounded-lg p-2 text-white focus:outline-none focus:border-amber-400"
                    />
                  </div>

                  <div>
                    <label className="block text-white/60 text-[11px] font-bold uppercase mb-1">
                      Branch Target
                    </label>
                    <input
                      type="text"
                      value={config.branch}
                      onChange={(e) => handleSaveConfig({ ...config, branch: e.target.value })}
                      placeholder="main"
                      className="w-full bg-[#050505] border border-white/20 rounded-lg p-2 text-white focus:outline-none focus:border-amber-400"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-white/60 text-[11px] font-bold uppercase mb-1">
                      Target File Path in Repository
                    </label>
                    <input
                      type="text"
                      value={customPath}
                      onChange={(e) => setCustomPath(e.target.value)}
                      className="w-full bg-[#050505] border border-white/20 rounded-lg p-2 text-amber-300 focus:outline-none focus:border-amber-400"
                    />
                  </div>

                  <div>
                    <label className="block text-white/60 text-[11px] font-bold uppercase mb-1">
                      Git Commit Message
                    </label>
                    <input
                      type="text"
                      value={commitMsg}
                      onChange={(e) => setCommitMsg(e.target.value)}
                      className="w-full bg-[#050505] border border-white/20 rounded-lg p-2 text-white focus:outline-none focus:border-amber-400"
                    />
                  </div>
                </div>
              </div>

              {/* Submit Execution Button */}
              <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
                <div className="text-xs text-white/50 font-mono">
                  Target URL: <span className="text-amber-400">github.com/{config.owner || 'owner'}/{config.repo || 'repo'}/blob/{config.branch || 'main'}/{customPath}</span>
                </div>

                <button
                  onClick={handleExecuteUpload}
                  disabled={isUploading}
                  className="w-full sm:w-auto px-6 py-3 bg-amber-500 hover:bg-amber-600 text-black font-black uppercase tracking-wider text-xs rounded-xl transition flex items-center justify-center gap-2 cursor-pointer shadow-lg shadow-amber-950/40 disabled:opacity-50"
                >
                  {isUploading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <GitCommit className="w-4 h-4" />}
                  {isUploading ? 'Pushing Commit to GitHub...' : 'Commit & Upload Live to GitHub'}
                </button>
              </div>

              {/* Upload Result Alert */}
              {uploadResult && (
                <div className={`p-4 rounded-xl border font-mono text-xs space-y-2 ${
                  uploadResult.success ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300' : 'bg-red-500/15 border-red-500/40 text-red-300'
                }`}>
                  <div className="flex items-center justify-between font-bold text-sm">
                    <span className="flex items-center gap-2">
                      {uploadResult.success ? <CheckCircle2 className="w-5 h-5 text-emerald-400" /> : <ShieldAlert className="w-5 h-5 text-red-400" />}
                      {uploadResult.success ? 'Successfully Committed & Pushed to GitHub!' : 'Commit Failed'}
                    </span>
                    {uploadResult.commitSha && (
                      <span className="bg-emerald-950/80 px-2.5 py-1 rounded text-[10px] text-emerald-300 border border-emerald-500/30">
                        SHA: {uploadResult.commitSha}
                      </span>
                    )}
                  </div>

                  {uploadResult.htmlUrl && (
                    <div className="flex items-center gap-2 pt-1 text-xs">
                      <span>View file on GitHub:</span>
                      <a 
                        href={uploadResult.htmlUrl} 
                        target="_blank" 
                        rel="noreferrer" 
                        className="underline font-bold text-white hover:text-amber-300 flex items-center gap-1"
                      >
                        {uploadResult.htmlUrl}
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    </div>
                  )}

                  {uploadResult.error && (
                    <p className="text-red-400 text-xs">{uploadResult.error}</p>
                  )}
                </div>
              )}

            </div>
          )}

          {activeTab === 'gist' && (
            <div className="space-y-5">
              <div className="bg-cyan-500/10 border border-cyan-500/30 p-4 rounded-xl font-mono">
                <h4 className="text-sm font-black text-white uppercase tracking-wide flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-cyan-400" />
                  Publish One-Click Script as GitHub Gist
                </h4>
                <p className="text-xs text-white/70 mt-1">
                  Create an instant public or secret Gist on GitHub to allow remote endpoints to execute the script directly using <code className="bg-black/60 px-1.5 py-0.5 rounded text-amber-300">irm &lt;gist-raw-url&gt; | iex</code>
                </p>
              </div>

              <div className="bg-[#0C0C0C] border border-white/15 rounded-xl p-4 space-y-4 font-mono text-xs">
                <div>
                  <label className="block text-white/60 text-[11px] font-bold uppercase mb-1">
                    Gist Description
                  </label>
                  <input
                    type="text"
                    value={gistDescription}
                    onChange={(e) => setGistDescription(e.target.value)}
                    className="w-full bg-[#050505] border border-white/20 rounded-lg p-2.5 text-white focus:outline-none focus:border-cyan-400"
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-white/60 text-[11px] font-bold uppercase mb-1">
                      File Name
                    </label>
                    <input
                      type="text"
                      value={gistFilename}
                      onChange={(e) => setGistFilename(e.target.value)}
                      className="w-full bg-[#050505] border border-white/20 rounded-lg p-2.5 text-cyan-300 focus:outline-none focus:border-cyan-400"
                    />
                  </div>

                  <div>
                    <label className="block text-white/60 text-[11px] font-bold uppercase mb-1">
                      Gist Visibility
                    </label>
                    <div className="flex items-center gap-4 pt-2">
                      <label className="flex items-center gap-2 cursor-pointer text-white">
                        <input
                          type="radio"
                          checked={!gistIsPublic}
                          onChange={() => setGistIsPublic(false)}
                          className="accent-cyan-400"
                        />
                        <Lock className="w-3.5 h-3.5 text-amber-400" />
                        <span>Secret Gist (Unlisted)</span>
                      </label>

                      <label className="flex items-center gap-2 cursor-pointer text-white">
                        <input
                          type="radio"
                          checked={gistIsPublic}
                          onChange={() => setGistIsPublic(true)}
                          className="accent-cyan-400"
                        />
                        <Globe className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Public Gist</span>
                      </label>
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  onClick={handleCreateGist}
                  disabled={isCreatingGist}
                  className="px-6 py-3 bg-cyan-400 hover:bg-cyan-500 text-black font-black uppercase tracking-wider text-xs rounded-xl transition flex items-center gap-2 cursor-pointer shadow-lg shadow-cyan-950/40 disabled:opacity-50"
                >
                  {isCreatingGist ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
                  {isCreatingGist ? 'Creating GitHub Gist...' : 'Publish Gist to GitHub'}
                </button>
              </div>

              {gistResult && (
                <div className={`p-4 rounded-xl border font-mono text-xs space-y-3 ${
                  gistResult.success ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300' : 'bg-red-500/15 border-red-500/40 text-red-300'
                }`}>
                  <div className="flex items-center justify-between font-bold text-sm">
                    <span className="flex items-center gap-2">
                      <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                      GitHub Gist Published Successfully!
                    </span>
                  </div>

                  {gistResult.gistUrl && (
                    <div className="space-y-2 pt-1">
                      <div className="flex items-center justify-between bg-black/60 p-2.5 rounded border border-white/10">
                        <span className="text-white/70 text-[11px]">Gist URL:</span>
                        <a href={gistResult.gistUrl} target="_blank" rel="noreferrer" className="text-cyan-300 hover:underline font-bold flex items-center gap-1">
                          {gistResult.gistUrl}
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                      </div>

                      <div className="flex items-center justify-between bg-black/60 p-2.5 rounded border border-white/10">
                        <span className="text-white/70 text-[11px]">Direct Remote PowerShell Command:</span>
                        <div className="flex items-center gap-2">
                          <code className="text-amber-300 font-bold bg-amber-500/20 px-2 py-0.5 rounded text-[11px]">
                            irm {gistResult.rawUrl || gistResult.gistUrl} | iex
                          </code>
                          <button
                            onClick={() => copyToClipboard(`irm ${gistResult.rawUrl || gistResult.gistUrl} | iex`, setCopiedRawGist)}
                            className="p-1 bg-amber-500 text-black rounded hover:bg-amber-400 cursor-pointer"
                          >
                            {copiedRawGist ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {activeTab === 'autosync' && (
            <div className="space-y-5">
              <div className="bg-[#FF3B30]/10 border border-[#FF3B30]/30 p-4 rounded-xl font-mono">
                <h4 className="text-sm font-black text-white uppercase tracking-wide flex items-center gap-2">
                  <RefreshCw className="w-4 h-4 text-[#FF3B30]" />
                  Automated Live-Sync Background Engine
                </h4>
                <p className="text-xs text-white/70 mt-1">
                  When enabled, SmartPro SecOps automatically pushes updated security posture snapshots, endpoint scan data, and script revisions to your GitHub repository whenever changes occur.
                </p>
              </div>

              <div className="bg-[#0C0C0C] border border-white/15 rounded-xl p-5 space-y-5 font-mono text-xs">
                
                {/* Toggle switch */}
                <div className="flex items-center justify-between bg-[#141414] border border-white/10 p-4 rounded-xl">
                  <div>
                    <span className="font-bold text-white text-sm block">Enable Automatic GitHub Live Sync</span>
                    <span className="text-white/50 text-[11px] block mt-0.5">
                      Automatically commit changes in real time when endpoints are remediated or updated.
                    </span>
                  </div>

                  <button
                    onClick={() => {
                      const updated = !config.autoSyncEnabled;
                      handleSaveConfig({ ...config, autoSyncEnabled: updated });
                      setAutoSyncStatusMsg(updated ? "Auto Live-Sync Engine Activated!" : "Auto Live-Sync Deactivated.");
                      setTimeout(() => setAutoSyncStatusMsg(null), 3000);
                    }}
                    className={`px-5 py-2.5 rounded-xl font-black uppercase text-xs transition cursor-pointer flex items-center gap-2 ${
                      config.autoSyncEnabled
                        ? 'bg-emerald-500 text-black shadow-lg shadow-emerald-950/40'
                        : 'bg-white/10 text-white/50 border border-white/15'
                    }`}
                  >
                    <span className={`w-2.5 h-2.5 rounded-full ${config.autoSyncEnabled ? 'bg-black animate-ping' : 'bg-white/30'}`}></span>
                    {config.autoSyncEnabled ? 'ACTIVE (LIVE SYNC ON)' : 'OFF (DISABLED)'}
                  </button>
                </div>

                {autoSyncStatusMsg && (
                  <div className="p-2.5 bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded-lg font-bold text-center">
                    {autoSyncStatusMsg}
                  </div>
                )}

                {/* Frequency selection */}
                <div>
                  <label className="block text-white/60 text-[11px] font-bold uppercase mb-2">
                    Auto-Sync Trigger Interval
                  </label>
                  <select
                    value={config.autoSyncIntervalMinutes}
                    onChange={(e) => handleSaveConfig({ ...config, autoSyncIntervalMinutes: Number(e.target.value) })}
                    className="w-full bg-[#050505] border border-white/20 rounded-lg p-3 text-white focus:outline-none focus:border-amber-400"
                  >
                    <option value={1}>Every 1 Minute (High Precision Real-Time)</option>
                    <option value={5}>Every 5 Minutes (Recommended)</option>
                    <option value={15}>Every 15 Minutes</option>
                    <option value={30}>Every 30 Minutes</option>
                    <option value={60}>Every 1 Hour</option>
                  </select>
                </div>

                {/* Targets selection */}
                <div className="space-y-2">
                  <label className="block text-white/60 text-[11px] font-bold uppercase">
                    Auto-Sync Target Datasets
                  </label>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <label className="flex items-center gap-3 p-3 bg-[#050505] border border-white/15 rounded-lg cursor-pointer">
                      <input
                        type="checkbox"
                        checked={config.syncTargets.auditScript}
                        onChange={(e) => handleSaveConfig({
                          ...config,
                          syncTargets: { ...config.syncTargets, auditScript: e.target.checked }
                        })}
                        className="accent-amber-400 w-4 h-4"
                      />
                      <div>
                        <span className="font-bold text-white block">PowerShell Audit Script</span>
                        <span className="text-[10px] text-white/50 block">AuditEndpointSecurity.ps1</span>
                      </div>
                    </label>

                    <label className="flex items-center gap-3 p-3 bg-[#050505] border border-white/15 rounded-lg cursor-pointer">
                      <input
                        type="checkbox"
                        checked={config.syncTargets.dashboardConfig}
                        onChange={(e) => handleSaveConfig({
                          ...config,
                          syncTargets: { ...config.syncTargets, dashboardConfig: e.target.checked }
                        })}
                        className="accent-amber-400 w-4 h-4"
                      />
                      <div>
                        <span className="font-bold text-white block">Full Posture JSON Package</span>
                        <span className="text-[10px] text-white/50 block">SmartPro_Dashboard_Config.json</span>
                      </div>
                    </label>
                  </div>
                </div>

              </div>
            </div>
          )}

          {activeTab === 'history' && (
            <div className="space-y-4">
              <div className="flex justify-between items-center bg-emerald-500/10 border border-emerald-500/30 p-4 rounded-xl font-mono">
                <div>
                  <h4 className="text-sm font-black text-white uppercase tracking-wide flex items-center gap-2">
                    <Clock className="w-4 h-4 text-emerald-400" />
                    GitHub Sync & Commit Log Timeline
                  </h4>
                  <p className="text-xs text-white/70 mt-1">
                    Records of all recent live commits and Gist creations sent to GitHub.
                  </p>
                </div>

                <button
                  onClick={() => setHistory(loadSyncHistory())}
                  className="px-3 py-1.5 bg-white/10 hover:bg-white/20 text-white rounded text-xs font-bold uppercase transition flex items-center gap-1.5 cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5 text-emerald-400" />
                  Refresh
                </button>
              </div>

              {history.length === 0 ? (
                <div className="p-8 text-center bg-[#0C0C0C] border border-white/10 rounded-xl text-white/40 font-mono text-xs">
                  No sync history recorded yet. Commit a file or publish a Gist to see live records here!
                </div>
              ) : (
                <div className="bg-[#050505] border border-white/15 rounded-xl overflow-x-auto font-mono text-xs">
                  <table className="w-full text-left">
                    <thead className="bg-[#0D0D0D] border-b border-white/15 text-white/50 uppercase text-[10px] font-bold">
                      <tr>
                        <th className="p-3">Timestamp</th>
                        <th className="p-3">Target File</th>
                        <th className="p-3">Repo / Location</th>
                        <th className="p-3">SHA / ID</th>
                        <th className="p-3">Status</th>
                        <th className="p-3 text-right">Link</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/10 text-white/80">
                      {history.map((item) => (
                        <tr key={item.id} className="hover:bg-white/5 transition">
                          <td className="p-3 text-white/50 text-[11px] whitespace-nowrap">
                            {new Date(item.timestamp).toLocaleTimeString()} &bull; {new Date(item.timestamp).toLocaleDateString()}
                          </td>
                          <td className="p-3 font-bold text-amber-300">{item.fileName}</td>
                          <td className="p-3 text-white/70">{item.repo} ({item.branch})</td>
                          <td className="p-3">
                            <span className="bg-white/10 px-2 py-0.5 rounded text-[10px] font-bold text-cyan-300">
                              {item.commitSha}
                            </span>
                          </td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase ${
                              item.status === 'SUCCESS' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'
                            }`}>
                              {item.status}
                            </span>
                          </td>
                          <td className="p-3 text-right">
                            {item.commitUrl && item.commitUrl !== '#' ? (
                              <a
                                href={item.commitUrl}
                                target="_blank"
                                rel="noreferrer"
                                className="text-amber-400 hover:underline inline-flex items-center gap-1 font-bold"
                              >
                                View
                                <ArrowUpRight className="w-3.5 h-3.5" />
                              </a>
                            ) : (
                              <span className="text-white/30">-</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

        </div>

        {/* Footer */}
        <div className="bg-[#0D0D0D] border-t border-white/10 p-4 flex justify-between items-center text-xs text-white/50 font-mono">
          <span>SmartPro SecOps GitHub Connector v2.5</span>
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
