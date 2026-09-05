import React, { useState, useEffect } from 'react';
import { 
  Server, 
  ShieldCheck, 
  Play, 
  CheckCircle2, 
  AlertTriangle, 
  RefreshCw, 
  Download, 
  Copy, 
  Check, 
  Search, 
  Sliders, 
  Layers, 
  Terminal, 
  Cpu, 
  Wrench, 
  Sparkles, 
  X, 
  ChevronRight, 
  Filter, 
  ListOrdered, 
  Clock, 
  ShieldAlert,
  Laptop,
  Pause,
  Zap,
  CheckSquare,
  Square,
  Bot
} from 'lucide-react';
import { Endpoint } from '../types';
import { VULNERABILITIES_60_DATABASE, Vulnerability60, get60VulnerabilitiesForEndpoint, calculate60DynamicScore } from '../data/vulnerabilities60';

interface Props {
  endpoints: Endpoint[];
  onUpdateEndpoints: (updatedEndpoints: Endpoint[]) => void;
  onCheckPrivilegeAndRun?: (requiredRole: string, actionName: string, actionFn: () => void) => void;
  onOpenAiAutoFix?: (endpointId?: string) => void;
}

export interface SequencedTask {
  vulnerabilityId: number;
  name: string;
  category: string;
  severity: 'Medium' | 'Low' | 'High' | 'Critical';
  powershellFix: string;
  impactWarning: string;
  order: number;
  selected: boolean;
  affectedEndpointCount: number;
}

export interface ExecutionLog {
  id: string;
  timestamp: string;
  type: 'info' | 'success' | 'warn' | 'error' | 'step';
  endpointName?: string;
  message: string;
}

export default function BulkRemediationConsole({ endpoints, onUpdateEndpoints, onCheckPrivilegeAndRun, onOpenAiAutoFix }: Props) {
  // Selection state
  const [selectedEndpointIds, setSelectedEndpointIds] = useState<string[]>(() => endpoints.map(e => e.id));
  const [deviceFilter, setDeviceFilter] = useState<'all' | 'Server' | 'Workstation' | 'Laptop'>('all');
  const [searchTerm, setSearchTerm] = useState('');

  // 'Select All and Auto-Fix' master state
  const [selectAllAutoFix, setSelectAllAutoFix] = useState(false);

  // Vulnerability selection state
  const [selectedSeverities, setSelectedSeverities] = useState<{ Critical: boolean; High: boolean; Medium: boolean; Low: boolean }>({
    Critical: false,
    High: false,
    Medium: true,
    Low: true
  });

  const [customTaskSelection, setCustomTaskSelection] = useState<Record<number, boolean>>({});

  // Execution state
  const [isExecuting, setIsExecuting] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [executionProgress, setExecutionProgress] = useState(0);
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [currentEndpointIndex, setCurrentEndpointIndex] = useState(0);
  const [executionLogs, setExecutionLogs] = useState<ExecutionLog[]>([]);
  const [executionComplete, setExecutionComplete] = useState(false);
  const [copiedLog, setCopiedLog] = useState(false);

  // Summary result state
  const [summaryStats, setSummaryStats] = useState<{
    endpointsFixed: number;
    vulnsFixedTotal: number;
    initialAvgScore: number;
    finalAvgScore: number;
  } | null>(null);

  // Filter endpoints by tab / search
  const filteredEndpoints = endpoints.filter(ep => {
    const matchesSearch = ep.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          ep.ip.includes(searchTerm) || 
                          (ep.os && ep.os.toLowerCase().includes(searchTerm.toLowerCase()));
    
    if (deviceFilter === 'all') return matchesSearch;
    if (deviceFilter === 'Server') return matchesSearch && (ep.deviceType === 'Server' || ep.os.toLowerCase().includes('server'));
    return matchesSearch && (ep.deviceType === deviceFilter || (!ep.deviceType && !ep.os.toLowerCase().includes('server')));
  });

  // Toggle selection for all or individual endpoints
  const toggleSelectAllEndpoints = () => {
    if (selectedEndpointIds.length === filteredEndpoints.length) {
      setSelectedEndpointIds([]);
    } else {
      setSelectedEndpointIds(filteredEndpoints.map(e => e.id));
    }
  };

  const toggleEndpointSelect = (id: string) => {
    setSelectedEndpointIds(prev => 
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  // Extract non-critical vulnerabilities present on selected endpoints
  const selectedEndpointsList = endpoints.filter(e => selectedEndpointIds.includes(e.id));

  // Collect all vulnerabilities that need remediation on selected endpoints (excluding marked exclusions)
  const nonCriticalTasks: SequencedTask[] = React.useMemo(() => {
    const taskMap = new Map<number, { vuln: Vulnerability60; affectedCount: number }>();

    selectedEndpointsList.forEach(ep => {
      const epVulns = get60VulnerabilitiesForEndpoint(ep);
      epVulns.forEach(item => {
        // Find failed or warning status items that are non-remediated and not excluded
        if ((item.status === 'failed' || item.status === 'warning') && !item.remediated && !item.excluded) {
          const v = item.vulnerability;
          const existing = taskMap.get(v.id);
          if (existing) {
            existing.affectedCount += 1;
          } else {
            taskMap.set(v.id, { vuln: v, affectedCount: 1 });
          }
        }
      });
    });

    const tasks: SequencedTask[] = Array.from(taskMap.values()).map(({ vuln, affectedCount }, idx) => {
      const isSelected = selectAllAutoFix
        ? true
        : (customTaskSelection[vuln.id] !== undefined 
          ? customTaskSelection[vuln.id] 
          : selectedSeverities[vuln.severity as keyof typeof selectedSeverities] ?? true);

      return {
        vulnerabilityId: vuln.id,
        name: vuln.name,
        category: vuln.category,
        severity: vuln.severity as any,
        powershellFix: vuln.powershellFix,
        impactWarning: vuln.impactWarning,
        order: idx + 1,
        selected: isSelected,
        affectedEndpointCount: affectedCount
      };
    });

    // Sequence order: Category & Severity priority (Critical -> High -> Medium -> Low)
    return tasks.sort((a, b) => {
      const sevOrder = { Critical: 1, High: 2, Medium: 3, Low: 4 };
      return (sevOrder[a.severity] || 5) - (sevOrder[b.severity] || 5);
    });
  }, [selectedEndpointsList, selectedSeverities, customTaskSelection, selectAllAutoFix]);

  const activeSelectedTasks = nonCriticalTasks.filter(t => t.selected);

  // Total non-excluded open vulnerability occurrences across all selected endpoints
  const totalNonExcludedOccurrences = React.useMemo(() => {
    let count = 0;
    selectedEndpointsList.forEach(ep => {
      const epVulns = get60VulnerabilitiesForEndpoint(ep);
      epVulns.forEach(item => {
        if ((item.status === 'failed' || item.status === 'warning') && !item.remediated && !item.excluded) {
          count++;
        }
      });
    });
    return count;
  }, [selectedEndpointsList]);

  // Handler for master "Select All and Auto-Fix" checkbox
  const handleToggleSelectAllAutoFix = (checked: boolean) => {
    setSelectAllAutoFix(checked);
    if (checked) {
      setSelectedSeverities({ Critical: true, High: true, Medium: true, Low: true });
      const allSelected: Record<number, boolean> = {};
      nonCriticalTasks.forEach(t => {
        allSelected[t.vulnerabilityId] = true;
      });
      setCustomTaskSelection(allSelected);
    }
  };

  // Instant 1-Action Auto-Fix all non-excluded vulnerabilities across all selected endpoints
  const handleInstantAutoFixAll = () => {
    const runFn = () => {
      if (selectedEndpointsList.length === 0) return;

      const initialAvg = Math.round(
        selectedEndpointsList.reduce((acc, curr) => acc + curr.overallScore, 0) / (selectedEndpointsList.length || 1)
      );

      let totalRemediatedCount = 0;
      const updatedEndpoints = endpoints.map(ep => {
        if (!selectedEndpointIds.includes(ep.id)) return ep;

        const epVulns = get60VulnerabilitiesForEndpoint(ep);
        const excludeList = ep.excludedVulnerabilities || [];
        
        // Remediate all items that are NOT excluded and not yet passed
        const nonExcludedToRemediate = epVulns
          .filter(item => item.baselineStatus !== 'passed' && !excludeList.includes(item.vulnerability.id))
          .map(item => item.vulnerability.id);

        totalRemediatedCount += nonExcludedToRemediate.length;

        const updatedRemediated = Array.from(new Set([
          ...(ep.remediatedVulnerabilities || []),
          ...nonExcludedToRemediate
        ]));

        const tempEndpoint: Endpoint = {
          ...ep,
          remediatedVulnerabilities: updatedRemediated
        };

        const newScore = calculate60DynamicScore(tempEndpoint);
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

        // Also update standard scanData for legacy audits
        const updatedScanData = {
          ...ep.scanData,
          smb: {
            ...ep.scanData.smb,
            smb1Enabled: { ...ep.scanData.smb.smb1Enabled, status: 'passed' as const, value: 'Disabled / Safe', details: 'SMBv1 is verified as fully disabled on the system.' },
            smbSigningRequired: { ...ep.scanData.smb.smbSigningRequired, status: 'passed' as const, value: 'CONFIGURED', details: 'SMB digital signing is enforced on all Server and Client sessions.' },
            smbEncryptionEnabled: { ...ep.scanData.smb.smbEncryptionEnabled, status: 'passed' as const, value: 'ENABLED', details: 'SMB Transport payload encryption is active.' }
          }
        };

        return {
          ...tempEndpoint,
          overallScore: newScore,
          criticalCount: crit,
          highCount: high,
          mediumCount: med,
          lowCount: low,
          status: newScore > 85 ? 'secure' as const : newScore > 60 ? 'warning' as const : 'vulnerable' as const,
          scanData: updatedScanData
        };
      });

      const finalSelected = updatedEndpoints.filter(e => selectedEndpointIds.includes(e.id));
      const finalAvg = Math.round(
        finalSelected.reduce((acc, curr) => acc + curr.overallScore, 0) / (finalSelected.length || 1)
      );

      setSummaryStats({
        endpointsFixed: selectedEndpointsList.length,
        vulnsFixedTotal: totalRemediatedCount,
        initialAvgScore: initialAvg,
        finalAvgScore: finalAvg
      });

      const logs: ExecutionLog[] = [
        {
          id: `instant-init-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          type: 'info',
          message: `⚡ EXECUTING 1-ACTION AUTO-FIX: Remediating all non-excluded vulnerabilities across ${selectedEndpointsList.length} selected hosts`
        },
        ...selectedEndpointsList.map((ep, idx) => ({
          id: `instant-ep-${ep.id}-${Date.now()}-${idx}`,
          timestamp: new Date().toLocaleTimeString(),
          type: 'step' as const,
          endpointName: ep.name,
          message: `[${ep.name} @ ${ep.ip}] Auto-remediated all non-excluded vulnerabilities. Posture score recalculated.`
        })),
        {
          id: `instant-finish-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          type: 'success',
          message: `🎉 1-ACTION AUTO-FIX COMPLETE: ${totalRemediatedCount} non-excluded vulnerabilities remediated across ${selectedEndpointsList.length} endpoints! Excluded vulnerabilities preserved intact.`
        }
      ];

      setExecutionLogs(logs);
      setExecutionProgress(100);
      setExecutionComplete(true);
      setIsExecuting(false);
      onUpdateEndpoints(updatedEndpoints);
    };

    if (onCheckPrivilegeAndRun) {
      onCheckPrivilegeAndRun('admin', 'Select All and Auto-Fix (All Non-Excluded Vulnerabilities)', runFn);
    } else {
      runFn();
    }
  };

  // Start Bulk Sequenced Remediation Execution
  const handleStartExecution = () => {
    const runFn = () => {
      if (selectedEndpointIds.length === 0) return;
      if (activeSelectedTasks.length === 0) return;

      setIsExecuting(true);
      setIsPaused(false);
      setExecutionProgress(0);
      setCurrentStepIndex(0);
      setCurrentEndpointIndex(0);
      setExecutionComplete(false);
      
      const initialAvg = Math.round(
        selectedEndpointsList.reduce((acc, curr) => acc + curr.overallScore, 0) / (selectedEndpointsList.length || 1)
      );

      const logs: ExecutionLog[] = [
        {
          id: 'log-1',
          timestamp: new Date().toLocaleTimeString(),
          type: 'info',
          message: `🚀 INITIALIZING BULK SEQUENCED REMEDIATION BATCH`
        },
        {
          id: 'log-2',
          timestamp: new Date().toLocaleTimeString(),
          type: 'info',
          message: `Target Endpoints (${selectedEndpointsList.length}): ${selectedEndpointsList.map(e => e.name).join(', ')}`
        },
        {
          id: 'log-3',
          timestamp: new Date().toLocaleTimeString(),
          type: 'info',
          message: `Sequenced Tasks Selected (${activeSelectedTasks.length}): ${activeSelectedTasks.map(t => t.name).join(', ')}`
        }
      ];

      setExecutionLogs(logs);

      // Trigger sequenced execution loop
      executeSequenceStep(0, 0, selectedEndpointsList, activeSelectedTasks, [...endpoints], logs, initialAvg);
    };

    if (onCheckPrivilegeAndRun) {
      onCheckPrivilegeAndRun('admin', 'Bulk Sequenced Remediation', runFn);
    } else {
      runFn();
    }
  };

  const executeSequenceStep = (
    epIdx: number, 
    taskIdx: number, 
    targets: Endpoint[], 
    tasks: SequencedTask[], 
    workingEndpoints: Endpoint[],
    logs: ExecutionLog[],
    initialAvg: number
  ) => {
    if (epIdx >= targets.length) {
      // Completed all endpoints!
      setIsExecuting(false);
      setExecutionComplete(true);
      setExecutionProgress(100);

      const finalSelected = workingEndpoints.filter(e => selectedEndpointIds.includes(e.id));
      const finalAvg = Math.round(
        finalSelected.reduce((acc, curr) => acc + curr.overallScore, 0) / (finalSelected.length || 1)
      );

      const totalFixed = tasks.length * targets.length;

      setSummaryStats({
        endpointsFixed: targets.length,
        vulnsFixedTotal: totalFixed,
        initialAvgScore: initialAvg,
        finalAvgScore: finalAvg
      });

      const finishLog: ExecutionLog = {
        id: `finish-${Date.now()}`,
        timestamp: new Date().toLocaleTimeString(),
        type: 'success',
        message: `🎉 BULK SEQUENCED REMEDIATION COMPLETE! Updated posture scores across all ${targets.length} target endpoints.`
      };

      setExecutionLogs(prev => [...prev, finishLog]);
      onUpdateEndpoints(workingEndpoints);
      return;
    }

    const currentEp = targets[epIdx];
    const currentTask = tasks[taskIdx];

    const totalSteps = targets.length * tasks.length;
    const currentStepNum = epIdx * tasks.length + taskIdx + 1;
    const progressPct = Math.round((currentStepNum / totalSteps) * 100);

    setExecutionProgress(progressPct);
    setCurrentEndpointIndex(epIdx);
    setCurrentStepIndex(taskIdx);

    // Update endpoint state to apply this remediated vulnerability
    const targetEndpointInState = workingEndpoints.find(e => e.id === currentEp.id);
    if (targetEndpointInState) {
      const existingRemediated = targetEndpointInState.remediatedVulnerabilities || [];
      if (!existingRemediated.includes(currentTask.vulnerabilityId)) {
        targetEndpointInState.remediatedVulnerabilities = [...existingRemediated, currentTask.vulnerabilityId];
      }

      // Recalculate dynamic score
      const newScore = calculate60DynamicScore(targetEndpointInState);
      const list = get60VulnerabilitiesForEndpoint(targetEndpointInState);
      let crit = 0, high = 0, med = 0, low = 0;
      list.forEach(item => {
        if (item.status === 'failed' || item.status === 'warning') {
          if (item.vulnerability.severity === 'Critical') crit++;
          else if (item.vulnerability.severity === 'High') high++;
          else if (item.vulnerability.severity === 'Medium') med++;
          else low++;
        }
      });

      targetEndpointInState.overallScore = newScore;
      targetEndpointInState.criticalCount = crit;
      targetEndpointInState.highCount = high;
      targetEndpointInState.mediumCount = med;
      targetEndpointInState.lowCount = low;
      targetEndpointInState.status = newScore > 85 ? 'secure' : newScore > 60 ? 'warning' : 'vulnerable';
    }

    const stepLog: ExecutionLog = {
      id: `log-${epIdx}-${taskIdx}-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString(),
      type: 'step',
      endpointName: currentEp.name,
      message: `[${currentEp.name} @ ${currentEp.ip}] Step ${taskIdx + 1}/${tasks.length}: Remediating '${currentTask.name}' (${currentTask.severity})`
    };

    setExecutionLogs(prev => [...prev, stepLog]);

    // Schedule next step after simulated execution delay
    setTimeout(() => {
      let nextEpIdx = epIdx;
      let nextTaskIdx = taskIdx + 1;

      if (nextTaskIdx >= tasks.length) {
        nextTaskIdx = 0;
        nextEpIdx = epIdx + 1;
      }

      executeSequenceStep(nextEpIdx, nextTaskIdx, targets, tasks, workingEndpoints, logs, initialAvg);
    }, 400);
  };

  const copyExecutionLogs = () => {
    const text = executionLogs.map(l => `[${l.timestamp}] ${l.endpointName ? `[${l.endpointName}] ` : ''}${l.message}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopiedLog(true);
    setTimeout(() => setCopiedLog(false), 2000);
  };

  const downloadExecutionReport = () => {
    const text = `# SMARTPRO SECOPS - BULK SEQUENCED REMEDIATION AUDIT LOG
# Generated: ${new Date().toLocaleString()}
# Target Endpoints (${selectedEndpointsList.length}): ${selectedEndpointsList.map(e => `${e.name} (${e.ip})`).join(', ')}
# Sequenced Tasks Executed (${activeSelectedTasks.length}):
${activeSelectedTasks.map((t, i) => `${i + 1}. [${t.severity}] ${t.name} (CVE/GPO ID)`).join('\n')}

=====================================================================
EXECUTION LOG OUTPUT
=====================================================================
${executionLogs.map(l => `[${l.timestamp}] ${l.endpointName ? `[${l.endpointName}] ` : ''}${l.message}`).join('\n')}
`;

    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Bulk_Remediation_Audit_${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-[#0f0f0f] border-2 border-amber-500/30 rounded-2xl overflow-hidden shadow-2xl space-y-6">
      
      {/* Top Banner Header */}
      <div className="bg-gradient-to-r from-slate-950 via-amber-950/40 to-slate-950 border-b border-white/10 p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <span className="bg-amber-500/20 text-amber-300 border border-amber-500/40 text-[10px] px-2.5 py-1 font-mono font-black tracking-widest uppercase rounded inline-flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-amber-400" />
              BULK ENDPOINT OPERATION CONSOLE
            </span>
            <h2 className="text-xl sm:text-2xl font-black text-white uppercase tracking-tight mt-1">
              Multi-Endpoint Sequenced Remediation Engine
            </h2>
            <p className="text-white/60 text-xs max-w-2xl">
              Select multiple Windows hosts and execute non-disruptive remediation batches across common non-critical and all non-excluded vulnerabilities with zero service downtime.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0 font-mono">
            <div className="bg-black/60 border border-white/15 px-3.5 py-2 rounded-xl text-xs text-left">
              <div className="text-[10px] text-white/50 uppercase">Selected Target Endpoints</div>
              <div className="text-amber-400 font-bold text-sm">{selectedEndpointIds.length} of {endpoints.length} Hosts</div>
            </div>

            <div className="bg-black/60 border border-white/15 px-3.5 py-2 rounded-xl text-xs text-left">
              <div className="text-[10px] text-white/50 uppercase">Queued Fix Tasks</div>
              <div className="text-emerald-400 font-bold text-sm">{activeSelectedTasks.length} Fixes Queued</div>
            </div>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-8">

        {/* FEATURE HIGHLIGHT: 'SELECT ALL AND AUTO-FIX' MASTER BANNER */}
        <div className="bg-gradient-to-r from-emerald-950/50 via-slate-950 to-amber-950/40 border-2 border-emerald-500/50 p-4 sm:p-5 rounded-2xl shadow-xl flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div className="flex items-start gap-3.5 flex-1">
            <div className="p-2.5 rounded-xl bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 shrink-0 mt-0.5">
              <Zap className="w-6 h-6 fill-emerald-400/20" />
            </div>

            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <label 
                  htmlFor="master-select-all-autofix"
                  className="font-mono font-black text-white text-sm sm:text-base uppercase tracking-wider flex items-center gap-2 cursor-pointer select-none"
                >
                  <input
                    id="master-select-all-autofix"
                    type="checkbox"
                    checked={selectAllAutoFix}
                    onChange={(e) => handleToggleSelectAllAutoFix(e.target.checked)}
                    className="w-5 h-5 accent-emerald-500 rounded cursor-pointer"
                  />
                  Select All and Auto-Fix
                </label>
                <span className="bg-emerald-500/20 text-emerald-300 font-mono text-[10px] px-2.5 py-0.5 rounded border border-emerald-500/40 font-bold">
                  All Non-Excluded Vulnerabilities
                </span>
                <span className="bg-blue-500/20 text-blue-300 font-mono text-[10px] px-2.5 py-0.5 rounded border border-blue-500/40 font-bold">
                  {selectedEndpointsList.length} Hosts Target
                </span>
              </div>
              
              <p className="text-white/70 text-xs leading-relaxed font-sans max-w-2xl">
                Check this box to automatically encompass and remediate <strong>all non-excluded vulnerabilities</strong> across all {selectedEndpointsList.length} selected endpoints in one single action. Any specifically excluded vulnerabilities are safeguarded and skipped.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 w-full lg:w-auto shrink-0 font-mono">
            {onOpenAiAutoFix && (
              <button
                onClick={() => onOpenAiAutoFix(selectedEndpointIds[0])}
                disabled={selectedEndpointsList.length === 0}
                className="flex-1 lg:flex-none flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-black px-4 py-2.5 rounded-xl text-xs font-black uppercase tracking-wider transition cursor-pointer shadow-lg shadow-cyan-950/50 disabled:opacity-50 disabled:cursor-not-allowed border border-cyan-300"
                title="Synthesize AI-powered PowerShell Auto-Fix Script via Gemini"
              >
                <Sparkles className="w-4 h-4 text-black animate-pulse" />
                🤖 AI Smart Auto-Fix (Gemini)
              </button>
            )}

            <button
              onClick={handleInstantAutoFixAll}
              disabled={selectedEndpointsList.length === 0 || totalNonExcludedOccurrences === 0 || isExecuting}
              className="flex-1 lg:flex-none flex items-center justify-center gap-2 bg-gradient-to-r from-emerald-500 via-emerald-400 to-teal-400 hover:from-emerald-400 hover:to-teal-300 text-black px-5 py-2.5 rounded-xl text-xs font-black uppercase tracking-wider transition cursor-pointer shadow-lg shadow-emerald-950/50 disabled:opacity-50 disabled:cursor-not-allowed"
              title="Execute immediate 1-action auto-fix on all non-excluded items across selected hosts"
            >
              <Wrench className="w-4 h-4 text-black" />
              ⚡ 1-Action Auto-Fix All ({totalNonExcludedOccurrences} Gaps)
            </button>
          </div>
        </div>

        {/* STEP 1: TARGET ENDPOINT SELECTION GRID */}
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-3">
            <div className="flex items-center gap-2">
              <span className="w-6 h-6 rounded-full bg-amber-500/20 border border-amber-500/40 text-amber-400 flex items-center justify-center font-mono font-bold text-xs">
                1
              </span>
              <h3 className="text-sm font-black uppercase text-white font-mono tracking-wider">
                Select Target Windows Endpoints for Bulk Batch
              </h3>
            </div>

            {/* Filter & Search Bar */}
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-white/40 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Search hostname or IP..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="bg-black border border-white/20 rounded-xl pl-8 pr-3 py-1.5 text-white text-xs focus:border-amber-400 outline-none w-48 font-mono"
                />
              </div>

              {/* Device Type Tabs */}
              <div className="bg-black border border-white/15 rounded-xl p-1 flex items-center gap-1">
                {(['all', 'Server', 'Workstation', 'Laptop'] as const).map(type => (
                  <button
                    key={type}
                    onClick={() => setDeviceFilter(type)}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-bold uppercase transition cursor-pointer ${
                      deviceFilter === type ? 'bg-amber-400 text-black shadow' : 'text-white/60 hover:text-white'
                    }`}
                  >
                    {type}
                  </button>
                ))}
              </div>

              <button
                onClick={toggleSelectAllEndpoints}
                className="px-3 py-1.5 bg-white/10 hover:bg-white/20 text-white rounded-xl text-xs font-bold uppercase transition cursor-pointer font-mono"
              >
                {selectedEndpointIds.length === filteredEndpoints.length ? 'Deselect All' : 'Select All'}
              </button>
            </div>
          </div>

          {/* Endpoints Selection Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredEndpoints.map(ep => {
              const isSelected = selectedEndpointIds.includes(ep.id);
              const scoreColor = ep.overallScore > 85 ? 'text-emerald-400' : ep.overallScore > 60 ? 'text-amber-400' : 'text-red-400';

              return (
                <div
                  key={ep.id}
                  onClick={() => toggleEndpointSelect(ep.id)}
                  className={`border-2 rounded-xl p-4 transition cursor-pointer select-none relative overflow-hidden ${
                    isSelected
                      ? 'bg-amber-950/20 border-amber-500 shadow-lg shadow-amber-950/30'
                      : 'bg-black/50 border-white/10 hover:border-white/30'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => {}} // Handled by parent div
                        className="w-4 h-4 accent-amber-500 rounded cursor-pointer"
                      />
                      <div>
                        <div className="font-bold text-white text-sm flex items-center gap-1.5 font-mono">
                          {ep.deviceType === 'Server' ? (
                            <Server className="w-3.5 h-3.5 text-cyan-400" />
                          ) : (
                            <Laptop className="w-3.5 h-3.5 text-emerald-400" />
                          )}
                          {ep.name}
                        </div>
                        <div className="text-[10px] text-white/50 font-mono mt-0.5">{ep.ip} • {ep.os}</div>
                      </div>
                    </div>

                    {/* Posture Score Badge */}
                    <div className="text-right font-mono">
                      <div className={`text-sm font-black ${scoreColor}`}>{ep.overallScore}%</div>
                      <div className="text-[9px] text-white/40 uppercase">Score</div>
                    </div>
                  </div>

                  {/* Open Vulnerability Counts summary */}
                  <div className="mt-3 pt-2.5 border-t border-white/10 flex items-center justify-between text-[10px] font-mono">
                    <span className="text-white/50">Open Gaps:</span>
                    <div className="flex items-center gap-2">
                      <span className="text-red-400 bg-red-500/20 px-1.5 py-0.5 rounded border border-red-500/30">
                        {ep.criticalCount + ep.highCount} Crit/High
                      </span>
                      <span className="text-amber-300 bg-amber-500/20 px-1.5 py-0.5 rounded border border-amber-500/30">
                        {ep.mediumCount} Med
                      </span>
                      <span className="text-blue-300 bg-blue-500/20 px-1.5 py-0.5 rounded border border-blue-500/30">
                        {ep.lowCount} Low
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* STEP 2: SEQUENCED NON-CRITICAL VULNERABILITY TASK SCOPE */}
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-3">
            <div className="flex items-center gap-2">
              <span className="w-6 h-6 rounded-full bg-amber-500/20 border border-amber-500/40 text-amber-400 flex items-center justify-center font-mono font-bold text-xs">
                2
              </span>
              <h3 className="text-sm font-black uppercase text-white font-mono tracking-wider">
                Vulnerability Remediation Task Pipeline & Scope
              </h3>
            </div>

            {/* Severity Level Filter Toggles & Select All */}
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <label 
                htmlFor="sub-select-all-autofix"
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold text-[10px] uppercase cursor-pointer hover:bg-emerald-500/30 transition"
              >
                <input
                  id="sub-select-all-autofix"
                  type="checkbox"
                  checked={selectAllAutoFix}
                  onChange={(e) => handleToggleSelectAllAutoFix(e.target.checked)}
                  className="w-3.5 h-3.5 accent-emerald-500 rounded cursor-pointer"
                />
                Select All & Auto-Fix
              </label>

              <span className="text-white/50 text-[10px] uppercase ml-1">Severities:</span>
              
              <button
                onClick={() => {
                  setSelectAllAutoFix(false);
                  setSelectedSeverities(prev => ({ ...prev, Critical: !prev.Critical }));
                }}
                className={`px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase transition cursor-pointer border ${
                  selectedSeverities.Critical 
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/50' 
                    : 'bg-black/40 text-white/40 border-white/10'
                }`}
              >
                Critical
              </button>

              <button
                onClick={() => {
                  setSelectAllAutoFix(false);
                  setSelectedSeverities(prev => ({ ...prev, High: !prev.High }));
                }}
                className={`px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase transition cursor-pointer border ${
                  selectedSeverities.High 
                    ? 'bg-red-500/20 text-red-300 border-red-500/50' 
                    : 'bg-black/40 text-white/40 border-white/10'
                }`}
              >
                High
              </button>

              <button
                onClick={() => {
                  setSelectAllAutoFix(false);
                  setSelectedSeverities(prev => ({ ...prev, Medium: !prev.Medium }));
                }}
                className={`px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase transition cursor-pointer border ${
                  selectedSeverities.Medium 
                    ? 'bg-amber-500/20 text-amber-300 border-amber-500/50' 
                    : 'bg-black/40 text-white/40 border-white/10'
                }`}
              >
                Medium
              </button>

              <button
                onClick={() => {
                  setSelectAllAutoFix(false);
                  setSelectedSeverities(prev => ({ ...prev, Low: !prev.Low }));
                }}
                className={`px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase transition cursor-pointer border ${
                  selectedSeverities.Low 
                    ? 'bg-blue-500/20 text-blue-300 border-blue-500/50' 
                    : 'bg-black/40 text-white/40 border-white/10'
                }`}
              >
                Low
              </button>
            </div>
          </div>

          {/* Sequenced Task List Preview */}
          <div className="space-y-2.5">
            {nonCriticalTasks.length === 0 ? (
              <div className="bg-black/40 border border-white/10 p-8 rounded-xl text-center text-white/50 text-xs">
                No open vulnerabilities detected on selected target endpoints or all have been remediated!
              </div>
            ) : (
              nonCriticalTasks.map((task) => {
                const isChecked = task.selected;

                return (
                  <div
                    key={task.vulnerabilityId}
                    className={`border rounded-xl p-3.5 transition flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                      isChecked
                        ? 'bg-black/80 border-amber-500/40 shadow-sm'
                        : 'bg-black/30 border-white/10 opacity-60'
                    }`}
                  >
                    <div className="flex items-start gap-3 flex-1">
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={(e) => {
                          if (selectAllAutoFix && !e.target.checked) {
                            setSelectAllAutoFix(false);
                          }
                          setCustomTaskSelection(prev => ({
                            ...prev,
                            [task.vulnerabilityId]: e.target.checked
                          }));
                        }}
                        className="w-4 h-4 accent-amber-500 rounded cursor-pointer mt-0.5"
                      />

                      <div className="space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-xs font-bold text-amber-400">
                            Sequence #{task.order}
                          </span>
                          <span className="font-bold text-white text-xs">{task.name}</span>
                          <span className={`text-[9px] px-2 py-0.2 rounded font-mono font-bold uppercase ${
                            task.severity === 'Critical' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                            task.severity === 'High' ? 'bg-red-500/20 text-red-300 border border-red-500/30' :
                            task.severity === 'Medium' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                            'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                          }`}>
                            {task.severity}
                          </span>
                          <span className="text-[10px] text-cyan-300 bg-cyan-950/60 px-2 py-0.2 rounded font-mono border border-cyan-800/40">
                            {task.category}
                          </span>
                        </div>

                        <p className="text-[11px] text-white/60 font-sans">
                          {task.impactWarning}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 shrink-0 font-mono text-xs">
                      <div className="text-right">
                        <span className="text-emerald-400 font-bold block">{task.affectedEndpointCount} Hosts</span>
                        <span className="text-[9px] text-white/40 block uppercase">Needs Fix</span>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* STEP 3: SEQUENCED REMEDIATION EXECUTION TRIGGER & ENGINE */}
        <div className="bg-black/60 border-2 border-amber-500/40 rounded-2xl p-6 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <h3 className="text-base font-black text-white uppercase tracking-tight flex items-center gap-2 font-mono">
                <Play className="w-4 h-4 text-emerald-400 fill-emerald-400" />
                Batch Execution Controller
              </h3>
              <p className="text-xs text-white/60">
                Ready to execute {activeSelectedTasks.length} queued remediation commands across {selectedEndpointsList.length} target endpoints.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              {!isExecuting && !executionComplete && (
                <>
                  <button
                    onClick={handleInstantAutoFixAll}
                    disabled={selectedEndpointsList.length === 0 || totalNonExcludedOccurrences === 0}
                    className="px-5 py-3 rounded-xl bg-gradient-to-r from-emerald-500 via-teal-400 to-cyan-400 hover:from-emerald-400 hover:to-cyan-300 text-black font-black text-xs uppercase tracking-wider transition shadow-xl cursor-pointer flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                    title="Remediate all non-excluded vulnerabilities across all selected endpoints in one single action"
                  >
                    <Zap className="w-4 h-4 fill-black text-black" />
                    1-Action Auto-Fix ({totalNonExcludedOccurrences} Gaps)
                  </button>

                  <button
                    onClick={handleStartExecution}
                    disabled={selectedEndpointsList.length === 0 || activeSelectedTasks.length === 0}
                    className="px-5 py-3 rounded-xl bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-black font-black text-xs uppercase tracking-wider transition shadow-xl cursor-pointer flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Play className="w-4 h-4 fill-black" />
                    Sequenced Batch Step Runner
                  </button>
                </>
              )}

              {isExecuting && (
                <div className="flex items-center gap-2">
                  <span className="flex items-center gap-2 text-xs text-amber-400 font-mono font-bold animate-pulse">
                    <RefreshCw className="w-4 h-4 animate-spin text-amber-400" />
                    Executing Batch Sequence... ({executionProgress}%)
                  </span>
                </div>
              )}

              {executionComplete && (
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleInstantAutoFixAll}
                    className="px-4 py-2.5 rounded-xl bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 text-xs font-bold uppercase transition cursor-pointer font-mono flex items-center gap-2"
                  >
                    <Zap className="w-3.5 h-3.5 text-emerald-400" />
                    Re-Run 1-Action Auto-Fix
                  </button>
                  <button
                    onClick={handleStartExecution}
                    className="px-4 py-2.5 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-bold uppercase transition cursor-pointer font-mono flex items-center gap-2"
                  >
                    <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
                    Re-Run Sequenced Batch
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Real-time Execution Progress Bar */}
          {(isExecuting || executionComplete) && (
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-white/70">
                  {executionComplete 
                    ? '✅ Remediation Batch Executed Successfully' 
                    : `Active Endpoint [${currentEndpointIndex + 1}/${selectedEndpointsList.length}]: ${selectedEndpointsList[currentEndpointIndex]?.name}`}
                </span>
                <span className="text-amber-400 font-bold">{executionProgress}%</span>
              </div>

              <div className="w-full h-3 bg-black rounded-full border border-white/20 overflow-hidden p-0.5">
                <div 
                  className="h-full bg-gradient-to-r from-amber-500 via-emerald-400 to-cyan-400 rounded-full transition-all duration-300"
                  style={{ width: `${executionProgress}%` }}
                />
              </div>
            </div>
          )}

          {/* Live Terminal & Execution Console Output */}
          {executionLogs.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-white/60 flex items-center gap-2">
                  <Terminal className="w-3.5 h-3.5 text-amber-400" />
                  Live Execution Console Output Log
                </span>

                <div className="flex items-center gap-2">
                  <button
                    onClick={copyExecutionLogs}
                    className="px-2.5 py-1 bg-white/10 hover:bg-white/20 text-white rounded text-[10px] font-bold uppercase transition cursor-pointer font-mono flex items-center gap-1"
                  >
                    {copiedLog ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-amber-400" />}
                    {copiedLog ? 'Copied Log' : 'Copy Log'}
                  </button>

                  <button
                    onClick={downloadExecutionReport}
                    className="px-2.5 py-1 bg-amber-500 hover:bg-amber-600 text-black rounded text-[10px] font-black uppercase transition cursor-pointer font-mono flex items-center gap-1"
                  >
                    <Download className="w-3 h-3" />
                    Export Log
                  </button>
                </div>
              </div>

              <div className="bg-[#050505] border border-white/15 rounded-xl p-4 font-mono text-[11px] max-h-60 overflow-y-auto space-y-1.5 shadow-inner">
                {executionLogs.map((log) => (
                  <div key={log.id} className="flex items-start gap-2 leading-relaxed">
                    <span className="text-white/40 shrink-0">[{log.timestamp}]</span>
                    <span className={
                      log.type === 'success' ? 'text-emerald-400 font-bold' :
                      log.type === 'step' ? 'text-cyan-300' :
                      log.type === 'warn' ? 'text-amber-300' :
                      'text-amber-400 font-bold'
                    }>
                      {log.message}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Post-Execution Summary Stats Card */}
          {executionComplete && summaryStats && (
            <div className="bg-emerald-950/30 border-2 border-emerald-500/50 rounded-xl p-5 space-y-4 animate-fadeIn">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                <h4 className="font-bold text-white text-sm uppercase tracking-wider font-mono">
                  Bulk Remediation Impact Summary
                </h4>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
                <div className="bg-black/50 border border-white/10 rounded-lg p-3">
                  <div className="text-[10px] text-white/50 uppercase">Updated Hosts</div>
                  <div className="text-lg font-black text-white">{summaryStats.endpointsFixed} Endpoints</div>
                </div>

                <div className="bg-black/50 border border-white/10 rounded-lg p-3">
                  <div className="text-[10px] text-white/50 uppercase">Remediated Gaps</div>
                  <div className="text-lg font-black text-emerald-400">+{summaryStats.vulnsFixedTotal} Fixed</div>
                </div>

                <div className="bg-black/50 border border-white/10 rounded-lg p-3">
                  <div className="text-[10px] text-white/50 uppercase">Initial Avg Score</div>
                  <div className="text-lg font-black text-amber-400">{summaryStats.initialAvgScore}%</div>
                </div>

                <div className="bg-black/50 border border-white/10 rounded-lg p-3">
                  <div className="text-[10px] text-white/50 uppercase">Improved Avg Score</div>
                  <div className="text-lg font-black text-emerald-400">{summaryStats.finalAvgScore}%</div>
                </div>
              </div>
            </div>
          )}

        </div>

      </div>
    </div>
  );
}

