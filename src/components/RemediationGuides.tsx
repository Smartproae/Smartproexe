import React, { useState } from 'react';
import { RemediationGuide } from '../types';
import { Code, Check, Copy, Terminal, ExternalLink, HelpCircle } from 'lucide-react';

interface Props {
  remediations: RemediationGuide[];
}

export default function RemediationGuides({ remediations }: Props) {
  const [selectedCategory, setSelectedCategory] = useState<'All' | 'SMB' | 'SSL/TLS' | 'NTLM' | 'General'>('All');
  const [selectedSeverity, setSelectedSeverity] = useState<'All' | 'Critical' | 'High' | 'Medium' | 'Low'>('All');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const categories: ('All' | 'SMB' | 'SSL/TLS' | 'NTLM' | 'General')[] = ['All', 'SMB', 'SSL/TLS', 'NTLM', 'General'];
  const severities: ('All' | 'Critical' | 'High' | 'Medium' | 'Low')[] = ['All', 'Critical', 'High', 'Medium', 'Low'];

  const filteredRemediations = remediations.filter(item => {
    const matchCat = selectedCategory === 'All' || item.category === selectedCategory;
    const matchSev = selectedSeverity === 'All' || item.severity === selectedSeverity;
    return matchCat && matchSev;
  });

  const copyCode = (id: string, code: string) => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(code)
          .then(() => {
            setCopiedId(id);
            setTimeout(() => setCopiedId(null), 2000);
          })
          .catch(() => {
            localFallbackCopy(id, code);
          });
      } else {
        localFallbackCopy(id, code);
      }
    } catch (err) {
      localFallbackCopy(id, code);
    }
  };

  const localFallbackCopy = (id: string, code: string) => {
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
        setCopiedId(id);
        setTimeout(() => setCopiedId(null), 2000);
      }
    } catch (e) {
      console.warn("Clipboard fallback failed", e);
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return <span className="text-xxs px-2 py-0.5 rounded-full font-bold bg-rose-100 text-rose-800 border border-rose-200">Critical</span>;
      case 'High':
        return <span className="text-xxs px-2 py-0.5 rounded-full font-bold bg-amber-100 text-amber-800 border border-amber-200">High</span>;
      case 'Medium':
        return <span className="text-xxs px-2 py-0.5 rounded-full font-bold bg-indigo-100 text-indigo-800 border border-indigo-200">Medium</span>;
      default:
        return <span className="text-xxs px-2 py-0.5 rounded-full font-bold bg-slate-100 text-slate-800 border border-slate-200">Low</span>;
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white border border-slate-200 p-5 rounded-xl shadow-xs text-left">
        <h2 className="text-lg font-bold text-slate-900 tracking-tight">Hardening guides & Active Fixes</h2>
        <p className="text-xs text-slate-500 mt-1">
          Select vulnerabilities to copy remediative group policies or immediate PowerShell registry configurations.
        </p>

        {/* Filter Toolbar */}
        <div className="flex flex-wrap items-center mt-4 gap-4">
          <div className="flex flex-col gap-1.5">
            <span className="text-xxs uppercase tracking-wider text-slate-400 font-bold">Protocol Category</span>
            <div className="flex bg-slate-100 p-1 rounded-lg gap-0.5">
              {categories.map(cat => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-3 py-1 text-[11px] font-semibold rounded-md transition cursor-pointer ${
                    selectedCategory === cat ? 'bg-white shadow-xs text-slate-900' : 'text-slate-500 hover:text-slate-900'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <span className="text-xxs uppercase tracking-wider text-slate-400 font-bold">Threat Severity</span>
            <div className="flex bg-slate-100 p-1 rounded-lg gap-0.5">
              {severities.map(sev => (
                <button
                  key={sev}
                  onClick={() => setSelectedSeverity(sev)}
                  className={`px-3 py-1 text-[11px] font-semibold rounded-md transition cursor-pointer ${
                    selectedSeverity === sev ? 'bg-white shadow-xs text-slate-900' : 'text-slate-500 hover:text-slate-900'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* List of remediation steps */}
      <div className="space-y-5">
        {filteredRemediations.length === 0 ? (
          <div className="bg-white border border-slate-200 p-12 rounded-xl text-center">
            <HelpCircle className="w-10 h-10 text-slate-300 mx-auto" />
            <h3 className="text-sm font-bold text-slate-700 mt-3">No Guides Match Current Selector</h3>
            <p className="text-xs text-slate-400 mt-1">Try resetting the protocol category or severity selectors.</p>
          </div>
        ) : (
          filteredRemediations.map(guide => (
            <div
              key={guide.id}
              className="bg-white rounded-xl border border-slate-200 shadow-xxs p-6 text-left hover:border-slate-300/90 transition flex flex-col md:flex-row gap-6"
            >
              <div className="flex-1 space-y-4">
                <div className="flex items-start justify-between gap-2.5">
                  <div>
                    <div className="flex items-center gap-2">
                      {getSeverityBadge(guide.severity)}
                      <span className="text-xxs uppercase tracking-wider font-semibold text-slate-400">
                        {guide.category} PROTOCOL Fix
                      </span>
                    </div>
                    <h3 className="text-base font-bold text-slate-900 mt-1.5 tracking-tight">{guide.title}</h3>
                  </div>
                </div>

                <p className="text-xs text-slate-600 leading-relaxed leading-6">{guide.description}</p>

                {/* technical properties info */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 bg-slate-50 p-3 text-xxs font-mono rounded-lg border border-slate-150">
                  {guide.registryPath && (
                    <div>
                      <span className="text-[10px] text-slate-400 block font-sans">Active Target Registry Key:</span>
                      <span className="text-slate-700 font-medium select-all block break-all font-semibold">{guide.registryPath}</span>
                    </div>
                  )}
                  {guide.registryKey && (
                    <div>
                      <span className="text-[10px] text-slate-400 block font-sans">DWORD Attribute Name & Target Value:</span>
                      <span className="text-slate-700 font-semibold select-all block break-all">
                        {guide.registryKey}: {guide.registryValue}
                      </span>
                    </div>
                  )}
                  {guide.gpoPath && (
                    <div className="sm:col-span-2 border-t border-slate-150 pt-2 mt-1">
                      <span className="text-[10px] text-slate-400 block font-sans">GPO Hardening Directive Path:</span>
                      <span className="text-slate-600 block leading-normal font-sans text-xs pt-0.5">{guide.gpoPath}</span>
                    </div>
                  )}
                </div>

                <div className="border-t border-slate-100 pt-3 flex flex-col gap-1">
                  <span className="text-xxs uppercase font-bold text-rose-500 tracking-wider">Business Impact Risk Assessment:</span>
                  <p className="text-xs text-slate-500 leading-relaxed font-sans">{guide.impactAssessment}</p>
                </div>
              </div>

              {/* powershell fix component box */}
              <div className="w-full md:w-[350px] flex-shrink-0 bg-slate-900 text-slate-300 rounded-xl p-4.5 border border-slate-800 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between gap-2 border-b border-slate-800 pb-2.5 mb-3">
                    <span className="text-xxs font-mono flex items-center gap-1 text-slate-400 font-bold">
                      <Terminal className="w-3.5 h-3.5 text-teal-400" />
                      ADMIN FIX SCRIPT
                    </span>
                    <button
                      onClick={() => copyCode(guide.id, guide.powershellFix)}
                      className="bg-slate-800 hover:bg-slate-700 active:scale-97 text-slate-200 h-6 px-2.5 rounded-lg text-xxs font-semibold flex items-center gap-1 border border-slate-700 transition cursor-pointer"
                    >
                      {copiedId === guide.id ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3 text-slate-400" />}
                      {copiedId === guide.id ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <pre className="text-left font-mono text-[10.5px] leading-relaxed overflow-x-auto whitespace-pre h-[150px] scrollbar-thin select-all text-teal-300">
                    {guide.powershellFix}
                  </pre>
                </div>
                <div className="text-[10px] text-slate-400 mt-2 hover:text-slate-300 flex items-center gap-1.5 border-t border-slate-800 pt-2.5">
                  <span>Usage: Launch an elevated system console and paste executing command parameters.</span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
