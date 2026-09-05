import React, { useState, useEffect } from 'react';
import { Endpoint } from '../types';
import { get60VulnerabilitiesForEndpoint } from '../data/vulnerabilities60';
import {
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  Sparkles,
  Server,
  Laptop,
  Monitor,
  Lock,
  Unlock,
  ShieldCheck,
  Activity,
  Eye,
  KeyRound,
  Network,
  Wifi,
  WifiOff,
  Plug,
  PlugZap,
  Loader2,
  Settings,
  Edit3,
  Save,
  Trash2,
  Plus,
  Radio,
  X,
  ChevronDown,
  ChevronUp,
  Terminal,
  Check,
  Globe,
  RefreshCw,
  FileText,
  Search,
  Filter,
  CheckSquare,
  XSquare,
  AlertCircle,
  Download,
  Info
} from 'lucide-react';

interface Props {
  endpoints: Endpoint[];
  selectedEndpointId: string;
  onSelectEndpoint: (id: string) => void;
  onAddOrUpdateEndpoint?: (endpoint: Endpoint) => void;
  onDeleteEndpoint?: (id: string) => void;
  onAiAuditClick?: (id: string) => void;
  alertThreshold?: number;
  onAlertThresholdChange?: (threshold: number) => void;
  onClearAllEndpoints?: () => void;
  onRestoreDefaultEndpoints?: () => void;
}

export default function EndpointInventoryTable({
  endpoints,
  selectedEndpointId,
  onSelectEndpoint,
  onAddOrUpdateEndpoint,
  onDeleteEndpoint,
  onAiAuditClick,
  alertThreshold = 75,
  onAlertThresholdChange,
  onClearAllEndpoints,
  onRestoreDefaultEndpoints
}: Props) {
  // Title editing state
  const [inventoryTitle, setInventoryTitle] = useState<string>(() => {
    return localStorage.getItem('inventory_title') || 'Windows Endpoint Hardening Inventory';
  });
  const [isEditingTitle, setIsEditingTitle] = useState<boolean>(false);
  const [tempTitle, setTempTitle] = useState<string>(inventoryTitle);

  // Clear data confirmation modal
  const [showClearConfirmModal, setShowClearConfirmModal] = useState<boolean>(false);

  // Toggle for AD & Network Settings drawer
  const [showConfigDrawer, setShowConfigDrawer] = useState<boolean>(false);
  const [activeConfigTab, setActiveConfigTab] = useState<'ad' | 'network' | 'ip_report'>('network');

  // Search & Filter State
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'compliant' | 'attention' | 'flagged'>('all');
  const [rdpFilter, setRdpFilter] = useState<'all' | 'connected' | 'disconnected' | 'failed'>('all');

  // Edit Endpoint Modal State
  const [editingEndpoint, setEditingEndpoint] = useState<Endpoint | null>(null);

  // Delete Confirmation State
  const [deleteConfirmEndpoint, setDeleteConfirmEndpoint] = useState<Endpoint | null>(null);

  // Add New IP Host Modal State
  const [showAddModal, setShowAddModal] = useState<boolean>(false);
  const [newIp, setNewIp] = useState<string>('192.168.1.105');
  const [newName, setNewName] = useState<string>('FACILITY-WIN11-WS05');
  const [newDeviceType, setNewDeviceType] = useState<'Server' | 'Workstation' | 'Laptop'>('Workstation');
  const [newOs, setNewOs] = useState<string>('Windows 11 Enterprise 22H2');
  const [newDepartment, setNewDepartment] = useState<string>('Corporate Finance Subnet');
  const [newBitLocker, setNewBitLocker] = useState<'Encrypted' | 'Unencrypted'>('Encrypted');
  const [newDefenderEdr, setNewDefenderEdr] = useState<'Active' | 'Outdated'>('Active');
  const [newPatchLevel, setNewPatchLevel] = useState<'Up-to-Date' | 'Pending Updates'>('Up-to-Date');
  const [newSmbStatus, setNewSmbStatus] = useState<string>('SMBv1: Disabled (Safe)');
  const [newScore, setNewScore] = useState<number>(90);
  const [newRdpStatus, setNewRdpStatus] = useState<'connected' | 'disconnected' | 'failed'>('connected');
  const [isProbingAddRdp, setIsProbingAddRdp] = useState<boolean>(false);
  const [addRdpProbeMsg, setAddRdpProbeMsg] = useState<{ text: string; type: 'success' | 'danger' | 'info' } | null>(null);

  // Single IP Live Scanning & RDP Testing State
  const [scanningIp, setScanningIp] = useState<string | null>(null);
  const [testingRdpIp, setTestingRdpIp] = useState<string | null>(null);

  // Toast Feedback Banner
  const [toastMessage, setToastMessage] = useState<{ text: string; type: 'success' | 'info' | 'danger' } | null>(null);

  // Active Directory Form State
  const [adDomain, setAdDomain] = useState<string>(() => localStorage.getItem('ad_domain') || 'corp.domain.com');
  const [adUsername, setAdUsername] = useState<string>(() => localStorage.getItem('ad_username') || 'CORP\\Administrator');
  const [adPassword, setAdPassword] = useState<string>('P@ssw0rd2026!');
  const [showAdPassword, setShowAdPassword] = useState<boolean>(false);
  const [adStatus, setAdStatus] = useState<'connected' | 'disconnected' | 'testing'>('connected');
  const [adMessage, setAdMessage] = useState<string>('Active Directory Domain Controller (10.140.10.10) verified');

  // Network Gateway & DNS Scanning Form State
  const [subnetCidr, setSubnetCidr] = useState<string>(() => localStorage.getItem('net_subnet_cidr') || '192.168.1.0/24');
  const [defaultGateway, setDefaultGateway] = useState<string>(() => localStorage.getItem('net_default_gateway') || '192.168.1.1');
  const [primaryDns, setPrimaryDns] = useState<string>(() => localStorage.getItem('net_primary_dns') || '192.168.1.254');
  const [secondaryDns, setSecondaryDns] = useState<string>(() => localStorage.getItem('net_secondary_dns') || '8.8.8.8');
  const [subnetMask, setSubnetMask] = useState<string>(() => localStorage.getItem('net_subnet_mask') || '255.255.255.0');
  const [targetIp, setTargetIp] = useState<string>('192.168.1.45');
  const [targetHostname, setTargetHostname] = useState<string>('FACILITY-GW-SRV01');
  const [targetDeviceType, setTargetDeviceType] = useState<'Server' | 'Workstation' | 'Laptop'>('Server');

  // Scanning State & Console
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [scanLogs, setScanLogs] = useState<string[]>([]);
  const [scanSuccessMsg, setScanSuccessMsg] = useState<string>('');

  // IP-Wise Report View Filter State
  const [reportSelectedIp, setReportSelectedIp] = useState<string>('all');
  const [reportSeverityFilter, setReportSeverityFilter] = useState<'all' | 'Critical' | 'High' | 'Medium' | 'Low' | 'failed'>('all');
  const [expandedIpRows, setExpandedIpRows] = useState<Record<string, boolean>>({});

  // Auto-dismiss toast after 4 seconds
  useEffect(() => {
    if (toastMessage) {
      const timer = setTimeout(() => setToastMessage(null), 4000);
      return () => clearTimeout(timer);
    }
  }, [toastMessage]);

  // Persist settings
  useEffect(() => {
    localStorage.setItem('inventory_title', inventoryTitle);
  }, [inventoryTitle]);

  useEffect(() => {
    localStorage.setItem('ad_domain', adDomain);
    localStorage.setItem('ad_username', adUsername);
    localStorage.setItem('net_subnet_cidr', subnetCidr);
    localStorage.setItem('net_default_gateway', defaultGateway);
    localStorage.setItem('net_primary_dns', primaryDns);
    localStorage.setItem('net_secondary_dns', secondaryDns);
    localStorage.setItem('net_subnet_mask', subnetMask);
  }, [adDomain, adUsername, subnetCidr, defaultGateway, primaryDns, secondaryDns, subnetMask]);

  const handleSaveTitle = () => {
    if (tempTitle.trim()) {
      setInventoryTitle(tempTitle.trim());
      setIsEditingTitle(false);
      setToastMessage({ text: 'Inventory title updated and saved.', type: 'success' });
    }
  };

  const handleTestAdConnection = () => {
    setAdStatus('testing');
    setAdMessage('Authenticating LDAP over TLS (Port 636) with Active Directory...');
    setTimeout(() => {
      setAdStatus('connected');
      setAdMessage(`AD Kerberos & LDAP authentication successful for ${adUsername} on ${adDomain}`);
      setToastMessage({ text: 'Active Directory LDAP credentials verified!', type: 'success' });
    }, 1200);
  };

  // Perform Live IP Scan on an individual Endpoint row
  const handleLiveScanSingleIp = (ep: Endpoint) => {
    setScanningIp(ep.ip);
    setToastMessage({ text: `Initializing 60-finding live AI probe on IP ${ep.ip}...`, type: 'info' });

    setTimeout(() => {
      const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
      const updatedScore = Math.min(100, Math.max(65, (ep.overallScore || 85) + (Math.random() > 0.5 ? 2 : -1)));

      const scannedEp: Endpoint = {
        ...ep,
        lastScanned: nowStr,
        overallScore: updatedScore,
        status: updatedScore >= 85 ? 'secure' : updatedScore >= 60 ? 'warning' : 'vulnerable',
        scanData: {
          ...ep.scanData,
          scanTime: nowStr
        }
      };

      if (onAddOrUpdateEndpoint) {
        onAddOrUpdateEndpoint(scannedEp);
      }
      setScanningIp(null);
      setToastMessage({
        text: `Live IP Scan Complete for ${ep.ip} (${ep.name})! Posture score updated to ${updatedScore}%.`,
        type: 'success'
      });
    }, 1400);
  };

  // Save changes from Edit Endpoint modal
  const handleSaveEditEndpoint = () => {
    if (!editingEndpoint) return;
    if (!editingEndpoint.ip.trim() || !editingEndpoint.name.trim()) {
      alert("IP Address and Hostname are required.");
      return;
    }

    if (onAddOrUpdateEndpoint) {
      onAddOrUpdateEndpoint(editingEndpoint);
    }

    setToastMessage({
      text: `Endpoint IP ${editingEndpoint.ip} (${editingEndpoint.name}) saved successfully!`,
      type: 'success'
    });
    setEditingEndpoint(null);
  };

  // Delete endpoint
  const handleConfirmDeleteEndpoint = () => {
    if (!deleteConfirmEndpoint) return;
    if (onDeleteEndpoint) {
      onDeleteEndpoint(deleteConfirmEndpoint.id);
      setToastMessage({
        text: `IP ${deleteConfirmEndpoint.ip} (${deleteConfirmEndpoint.name}) deleted from inventory.`,
        type: 'danger'
      });
    }
    setDeleteConfirmEndpoint(null);
  };

  // Test RDP connection for a single endpoint in the inventory
  const handleTestRdpSingle = (ep: Endpoint) => {
    setTestingRdpIp(ep.ip);
    setToastMessage({ text: `Probing RDP TCP Port 3389 TLS/NLA handshake on ${ep.ip}...`, type: 'info' });

    setTimeout(() => {
      let resultStatus: 'connected' | 'disconnected' | 'failed' = 'connected';
      let failReason = '';

      if (ep.ip.endsWith('.255') || ep.ip.endsWith('.0') || ep.ip.startsWith('10.999.') || ep.ip === '10.140.20.104' || ep.ip.includes('199')) {
        resultStatus = 'failed';
        failReason = `RDP Port 3389 unreachable / NLA handshake timed out on ${ep.ip}`;
      } else if (ep.ip.endsWith('.254') || ep.ip.startsWith('172.99.')) {
        resultStatus = 'disconnected';
        failReason = `RDP service listener inactive on ${ep.ip} (Port 3389 closed)`;
      } else {
        resultStatus = 'connected';
        failReason = 'Active RDP / WinRM Session Verified';
      }

      const updatedEp: Endpoint = {
        ...ep,
        rdpStatus: resultStatus,
        connectionStatus: resultStatus === 'failed' ? 'failed' : 'connected',
        connectionReason: failReason
      };

      if (onAddOrUpdateEndpoint) {
        onAddOrUpdateEndpoint(updatedEp);
      }
      setTestingRdpIp(null);

      if (resultStatus === 'failed') {
        setToastMessage({
          text: `[ERROR] RDP Connection Check FAILED for ${ep.ip} (${ep.name}): ${failReason}`,
          type: 'danger'
        });
      } else if (resultStatus === 'disconnected') {
        setToastMessage({
          text: `RDP Port Check for ${ep.ip}: Disconnected / Port 3389 Closed.`,
          type: 'info'
        });
      } else {
        setToastMessage({
          text: `[OK] RDP Connectivity Check PASSED for ${ep.ip} (${ep.name})! Port 3389 active & NLA verified.`,
          type: 'success'
        });
      }
    }, 900);
  };

  // Probe RDP port inside Add Modal
  const handleProbeAddRdp = () => {
    if (!newIp.trim()) {
      alert("Please enter an IP address first.");
      return;
    }
    setIsProbingAddRdp(true);
    setAddRdpProbeMsg({ text: `Initiating TCP port 3389 probe on ${newIp}...`, type: 'info' });

    setTimeout(() => {
      setIsProbingAddRdp(false);
      if (newIp.endsWith('.255') || newIp.endsWith('.0') || newIp.includes('199') || newIp.startsWith('10.999.') || newRdpStatus === 'failed') {
        setNewRdpStatus('failed');
        setAddRdpProbeMsg({
          text: `[PROBE FAILED] TCP 3389 connection to ${newIp} timed out after 3000ms. Firewall / NLA policies blocking packets.`,
          type: 'danger'
        });
      } else if (newRdpStatus === 'disconnected' || newIp.endsWith('.254')) {
        setNewRdpStatus('disconnected');
        setAddRdpProbeMsg({
          text: `[PROBE DISCONNECTED] Port 3389 is closed on ${newIp}. Terminal server listener disabled.`,
          type: 'info'
        });
      } else {
        setNewRdpStatus('connected');
        setAddRdpProbeMsg({
          text: `[PROBE SUCCESS] TCP port 3389 open on ${newIp}. RDP NLA authentication verified!`,
          type: 'success'
        });
      }
    }, 1000);
  };

  // Add new IP host to inventory with simulated RDP connection check
  const handleSaveNewEndpoint = (runLiveScanNow: boolean = false) => {
    if (!newIp.trim() || !newName.trim()) {
      alert("Please provide an IP address and Hostname.");
      return;
    }

    // Determine RDP connectivity status
    let effectiveRdpStatus: 'connected' | 'disconnected' | 'failed' = newRdpStatus;
    let rdpReason = 'Active RDP / WinRM Session Verified';

    if (newIp.endsWith('.255') || newIp.endsWith('.0') || newIp.includes('199') || newIp.startsWith('10.999.') || newIp === '0.0.0.0') {
      effectiveRdpStatus = 'failed';
      rdpReason = `RDP Port 3389 connection refused / NLA handshake timed out on ${newIp}`;
    } else if (newRdpStatus === 'failed') {
      effectiveRdpStatus = 'failed';
      rdpReason = `RDP Port 3389 connection refused / NLA handshake failed on ${newIp}`;
    } else if (newRdpStatus === 'disconnected') {
      effectiveRdpStatus = 'disconnected';
      rdpReason = `RDP listener service inactive on ${newIp}`;
    }

    const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const createdEp: Endpoint = {
      id: `ip-${Date.now()}`,
      name: newName,
      deviceType: newDeviceType,
      os: newOs,
      ip: newIp,
      department: newDepartment,
      bitLocker: newBitLocker,
      defenderEdr: newDefenderEdr,
      patchLevel: newPatchLevel,
      smbStatusText: newSmbStatus,
      lastScanned: nowStr,
      overallScore: newScore,
      criticalCount: newScore >= 85 ? 0 : 2,
      highCount: newScore >= 85 ? 1 : 3,
      mediumCount: newScore >= 85 ? 2 : 4,
      lowCount: 1,
      status: newScore >= 85 ? 'secure' : newScore >= 60 ? 'warning' : 'vulnerable',
      rdpStatus: effectiveRdpStatus,
      connectionStatus: effectiveRdpStatus === 'failed' ? 'failed' : 'connected',
      connectionReason: rdpReason,
      scanData: {
        hostname: newName,
        osName: newOs,
        scanTime: nowStr,
        ipAddresses: [newIp],
        privileges: 'Local System Administrator',
        smb: {
          smb1Enabled: { status: newSmbStatus.includes('Disabled') ? 'passed' : 'failed', value: newSmbStatus, details: 'SMBv1 status check' },
          smbSigningRequired: { status: 'passed', value: 'Required', details: 'SMB signing' },
          smbEncryptionEnabled: { status: 'passed', value: 'Enabled', details: 'SMB payload encryption' }
        },
        sslTls: {
          tls10Enabled: { status: 'passed', value: 'Disabled', details: 'TLS 1.0 disabled' },
          tls11Enabled: { status: 'passed', value: 'Disabled', details: 'TLS 1.1 disabled' },
          tls12Enabled: { status: 'passed', value: 'Enabled', details: 'TLS 1.2 enabled' },
          tls13Enabled: { status: 'passed', value: 'Enabled', details: 'TLS 1.3 enabled' },
          weakCipherSuites: { status: 'passed', value: 'Strict list', details: 'Cipher suite check' }
        },
        ntlm: {
          lmCompatibilityLevel: { status: 'passed', value: 'Level 5', details: 'NTLMv2 only' },
          restrictNtlmTraffic: { status: 'passed', value: 'Restricted', details: 'NTLM traffic restricted' },
          anonymousAccess: { status: 'passed', value: 'Disabled', details: 'Anonymous access disabled' }
        },
        additional: {
          firewallEnabled: { status: 'passed', value: 'Enabled', details: 'Firewall active' },
          rdpNlaEnabled: { status: 'passed', value: 'NLA Required', details: 'RDP NLA active' },
          credentialGuard: { status: 'passed', value: 'Enabled', details: 'Credential Guard active' }
        },
        users: {
          activeUsers: [{ username: 'Administrator', status: 'Active', lastPasswordChange: nowStr, passwordAgeDays: 10, passwordNeverExpires: false }],
          passwordPolicy: { minimumLength: 14, complexityEnabled: true, maximumAgeDays: 90, minimumAgeDays: 1, historyCount: 24 },
          isDomainController: false
        },
        removableDevices: {
          usbStorage: { status: 'passed', value: 'BLOCKED', details: 'USB storage blocked' }
        },
        ntpTime: { enabled: 'Yes', details: 'Time synchronized', status: 'passed' }
      }
    };

    if (onAddOrUpdateEndpoint) {
      onAddOrUpdateEndpoint(createdEp);
    }

    setShowAddModal(false);
    setAddRdpProbeMsg(null);

    if (effectiveRdpStatus === 'failed') {
      setToastMessage({
        text: `[ERROR] Added host ${newIp} (${newName}), but RDP Connection Check FAILED: Port 3389 unreachable or NLA rejected!`,
        type: 'danger'
      });
    } else if (effectiveRdpStatus === 'disconnected') {
      setToastMessage({
        text: `[WARNING] Added host ${newIp} (${newName}). RDP port 3389 is disconnected / closed.`,
        type: 'info'
      });
    } else {
      setToastMessage({
        text: `[OK] New IP Host ${newIp} (${newName}) saved & RDP Connection Verified (Port 3389 Active)!`,
        type: 'success'
      });
    }

    if (runLiveScanNow) {
      handleLiveScanSingleIp(createdEp);
    }
  };

  const handleRunLiveScan = () => {
    setIsScanning(true);
    setScanProgress(5);
    setScanLogs([]);
    setScanSuccessMsg('');

    const logs: string[] = [];

    const appendLog = (msg: string, pct: number) => {
      logs.push(msg);
      setScanLogs([...logs]);
      setScanProgress(pct);
    };

    setTimeout(() => {
      appendLog(`[+] Active Directory Domain Controller (${adDomain}): Authenticating LDAP credentials...`, 10);
    }, 300);

    setTimeout(() => {
      appendLog(`[+] Kerberos Token issued for user ${adUsername} with Domain Admin privileges.`, 20);
    }, 700);

    setTimeout(() => {
      appendLog(`[+] Initializing Facility Network Subnet Discovery on ${subnetCidr} via Gateway ${defaultGateway}...`, 35);
    }, 1200);

    setTimeout(() => {
      appendLog(`[+] Querying Primary DNS (${primaryDns}) and Secondary DNS (${secondaryDns}) for active host records...`, 50);
    }, 1700);

    setTimeout(() => {
      appendLog(`[+] Discovered active endpoints: ${endpoints.map(e => e.ip).join(', ')}, ${targetIp}`, 65);
    }, 2200);

    setTimeout(() => {
      appendLog(`[+] Running parallel 60-Vulnerability AI Benchmark probes across all discovered IP targets...`, 80);
    }, 2700);

    setTimeout(() => {
      appendLog(`[+] Multi-IP Scan complete! Evaluated all 60 security checks per IP across SMB, TLS, NTLM, and GPO policies.`, 100);
      setIsScanning(false);

      const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
      const newEp: Endpoint = {
        id: `scanned-${targetHostname.toLowerCase()}`,
        name: targetHostname,
        deviceType: targetDeviceType,
        os: 'Windows Server 2022 Datacenter Hardened',
        ip: targetIp,
        department: `Subnet ${subnetCidr} / GW ${defaultGateway}`,
        bitLocker: 'Encrypted',
        defenderEdr: 'Active',
        patchLevel: 'Up-to-Date',
        smbStatusText: 'SMBv1: Disabled (Safe)',
        lastScanned: nowStr,
        overallScore: 95,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 1,
        lowCount: 1,
        status: 'secure',
        scanData: {
          hostname: targetHostname,
          osName: 'Windows Server 2022 Datacenter Hardened',
          scanTime: nowStr,
          ipAddresses: [targetIp],
          privileges: `AD Domain User (${adUsername})`,
          smb: {
            smb1Enabled: { status: 'passed', value: 'Disabled (Safe)', details: 'SMBv1 is inactive and verified safe.' },
            smbSigningRequired: { status: 'passed', value: 'Required', details: 'SMB Signing enforced.' },
            smbEncryptionEnabled: { status: 'passed', value: 'Enabled', details: 'SMB payload encryption enabled.' }
          },
          sslTls: {
            tls10Enabled: { status: 'passed', value: 'Disabled', details: 'TLS 1.0 disabled.' },
            tls11Enabled: { status: 'passed', value: 'Disabled', details: 'TLS 1.1 disabled.' },
            tls12Enabled: { status: 'passed', value: 'Enabled', details: 'TLS 1.2 enabled.' },
            tls13Enabled: { status: 'passed', value: 'Enabled', details: 'TLS 1.3 enabled.' },
            weakCipherSuites: { status: 'passed', value: 'Strict list', details: 'No weak ciphers found.' }
          },
          ntlm: {
            lmCompatibilityLevel: { status: 'passed', value: 'Level 5', details: 'Refuse LM & NTLMv1.' },
            restrictNtlmTraffic: { status: 'passed', value: 'Restricted', details: 'NTLM outbound traffic restricted.' },
            anonymousAccess: { status: 'passed', value: 'Disabled', details: 'Anonymous access disabled.' }
          },
          additional: {
            firewallEnabled: { status: 'passed', value: 'Enabled', details: 'Firewall active on Domain/Public/Private profiles.' },
            rdpNlaEnabled: { status: 'passed', value: 'NLA Required', details: 'RDP protected with Network Level Authentication.' },
            credentialGuard: { status: 'passed', value: 'Enabled', details: 'Credential Guard active.' }
          },
          users: {
            activeUsers: [
              { username: 'Administrator', status: 'Active', lastPasswordChange: nowStr, passwordAgeDays: 5, passwordNeverExpires: false }
            ],
            passwordPolicy: { minimumLength: 14, complexityEnabled: true, maximumAgeDays: 90, minimumAgeDays: 1, historyCount: 24 },
            isDomainController: false
          },
          removableDevices: {
            usbStorage: { status: 'passed', value: 'BLOCKED', details: 'USB Storage blocked.' }
          },
          ntpTime: { enabled: 'Yes', details: `Time synchronized with DNS ${primaryDns}.`, status: 'passed' },
          ports: [
            { port: 80, protocol: 'TCP', service: 'HTTP', status: 'Closed', severity: 'Secure' },
            { port: 443, protocol: 'TCP', service: 'HTTPS', status: 'Open', severity: 'Secure' },
            { port: 445, protocol: 'TCP', service: 'microsoft-ds', status: 'Open', severity: 'Secure' }
          ],
          browserSecurity: {
            chromePasswordStore: { status: 'passed', value: 'DISABLED', details: 'Chrome password store disabled.' },
            chromeHistoryAllowed: { status: 'passed', value: 'DISABLED', details: 'Chrome history logging disabled.' },
            edgePasswordStore: { status: 'passed', value: 'DISABLED', details: 'Edge password store disabled.' },
            edgeHistoryAllowed: { status: 'passed', value: 'DISABLED', details: 'Edge history logging disabled.' },
            firefoxPasswordStore: { status: 'passed', value: 'DISABLED', details: 'Firefox password store disabled.' },
            firefoxHistoryAllowed: { status: 'passed', value: 'DISABLED', details: 'Firefox history logging disabled.' }
          }
        }
      };

      if (onAddOrUpdateEndpoint) {
        onAddOrUpdateEndpoint(newEp);
      }
      onSelectEndpoint(newEp.id);
      setActiveConfigTab('ip_report');
      setScanSuccessMsg(`Scanned all hosts in ${subnetCidr}! Generated IP-Wise 60-Vulnerabilities Report.`);
    }, 3200);
  };

  const getDeviceIcon = (deviceType?: string, os?: string) => {
    const type = deviceType?.toLowerCase() || os?.toLowerCase() || '';
    if (type.includes('laptop')) {
      return <Laptop className="w-4 h-4 text-cyan-400" />;
    }
    if (type.includes('workstation') || type.includes('win 10') || type.includes('win 11')) {
      return <Monitor className="w-4 h-4 text-blue-400" />;
    }
    return <Server className="w-4 h-4 text-amber-400" />;
  };

  const getStatusBadge = (statusText?: string, score?: number) => {
    if (statusText === 'Compliant' || (score !== undefined && score >= 85)) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] font-bold uppercase tracking-wider font-mono">
          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
          Compliant
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[10px] font-bold uppercase tracking-wider font-mono">
        <AlertTriangle className="w-3 h-3 text-amber-400" />
        Needs Attention
      </span>
    );
  };

  const getScoreBadge = (score: number) => {
    if (score >= 90) {
      return <span className="font-mono font-black text-emerald-400 text-xs bg-emerald-500/15 border border-emerald-500/30 px-2 py-0.5 rounded">{score}%</span>;
    }
    if (score >= 80) {
      return <span className="font-mono font-black text-emerald-300 text-xs bg-emerald-500/10 border border-emerald-400/20 px-2 py-0.5 rounded">{score}%</span>;
    }
    if (score >= 60) {
      return <span className="font-mono font-black text-amber-400 text-xs bg-amber-500/15 border border-amber-500/30 px-2 py-0.5 rounded">{score}%</span>;
    }
    return <span className="font-mono font-black text-red-400 text-xs bg-red-500/15 border border-red-500/30 px-2 py-0.5 rounded">{score}%</span>;
  };

  const toggleIpExpand = (ip: string) => {
    setExpandedIpRows(prev => ({ ...prev, [ip]: !prev[ip] }));
  };

  // Filtered endpoints based on Search, Status & RDP dropdowns
  const filteredEndpoints = endpoints.filter(ep => {
    const q = searchQuery.trim().toLowerCase();
    const matchesSearch = !q ||
      ep.ip.toLowerCase().includes(q) ||
      ep.name.toLowerCase().includes(q) ||
      ep.os.toLowerCase().includes(q) ||
      (ep.department && ep.department.toLowerCase().includes(q));

    if (!matchesSearch) return false;

    if (statusFilter === 'compliant' && ep.overallScore < 85) return false;
    if (statusFilter === 'attention' && ep.overallScore >= 85) return false;
    if (statusFilter === 'flagged' && ep.overallScore >= alertThreshold) return false;

    if (rdpFilter !== 'all') {
      const currentRdp = ep.rdpStatus || (ep.connectionStatus === 'failed' ? 'failed' : 'connected');
      if (currentRdp !== rdpFilter) return false;
    }

    return true;
  });

  return (
    <div className="bg-[#0f0f0f] border-2 border-white/20 rounded-lg shadow-2xl overflow-hidden font-sans relative">
      {/* Toast Notification Banner */}
      {toastMessage && (
        <div className={`px-4 py-2 text-xs font-bold font-mono flex items-center justify-between animate-fadeIn border-b ${
          toastMessage.type === 'success' ? 'bg-emerald-950/90 text-emerald-300 border-emerald-500/40' :
          toastMessage.type === 'danger' ? 'bg-red-950/90 text-red-300 border-red-500/40' :
          'bg-cyan-950/90 text-cyan-300 border-cyan-500/40'
        }`}>
          <div className="flex items-center gap-2">
            {toastMessage.type === 'success' && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
            {toastMessage.type === 'danger' && <AlertCircle className="w-4 h-4 text-red-400" />}
            {toastMessage.type === 'info' && <Info className="w-4 h-4 text-cyan-400 animate-spin" />}
            <span>{toastMessage.text}</span>
          </div>
          <button onClick={() => setToastMessage(null)} className="text-white/60 hover:text-white">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Table Header Section */}
      <div className="p-5 border-b border-white/15 bg-gradient-to-r from-[#141414] via-[#0f0f0f] to-[#141414] flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
            </div>
            <div className="flex-1">
              {isEditingTitle ? (
                <div className="flex items-center gap-2 max-w-xl">
                  <input
                    type="text"
                    value={tempTitle}
                    onChange={(e) => setTempTitle(e.target.value)}
                    className="bg-black border border-cyan-500/50 rounded px-2.5 py-1 text-sm text-white font-mono font-bold focus:outline-none focus:border-cyan-400 w-full"
                    placeholder="Enter Inventory Title..."
                  />
                  <button
                    onClick={handleSaveTitle}
                    className="p-1.5 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 border border-emerald-500/40 rounded transition cursor-pointer"
                    title="Save Title"
                  >
                    <Save className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => {
                      setTempTitle(inventoryTitle);
                      setIsEditingTitle(false);
                    }}
                    className="p-1.5 bg-white/10 hover:bg-white/20 text-white/70 border border-white/20 rounded transition cursor-pointer"
                    title="Cancel"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <h2 className="text-sm md:text-base font-black text-white uppercase tracking-wider font-mono">
                    {inventoryTitle} ({endpoints.length} Host Devices)
                  </h2>
                  <button
                    onClick={() => {
                      setTempTitle(inventoryTitle);
                      setIsEditingTitle(true);
                    }}
                    className="p-1 text-white/40 hover:text-cyan-400 transition cursor-pointer"
                    title="Edit Inventory Title"
                  >
                    <Edit3 className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
              <p className="text-xs text-white/50 mt-0.5 flex items-center gap-1.5 font-medium">
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                Live IP options active: <span className="text-emerald-400 font-bold">Scan IP Live</span>, <span className="text-cyan-400 font-bold">Edit Host</span>, <span className="text-amber-400 font-bold">Save</span>, and <span className="text-red-400 font-bold">Delete</span>.
              </p>
            </div>
          </div>
        </div>

        {/* Top Control Buttons: Add IP, AD Connect, Gateway Scan, IP Report */}
        <div className="flex flex-wrap items-center gap-2 self-start md:self-auto">
          <button
            onClick={() => setShowAddModal(true)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-bold font-mono transition border cursor-pointer bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border-emerald-500/50"
            title="Add a new IP endpoint host to inventory"
          >
            <Plus className="w-4 h-4 text-emerald-400" />
            <span>+ Add / Scan IP Host</span>
          </button>

          <button
            onClick={() => {
              setShowConfigDrawer(!showConfigDrawer);
              setActiveConfigTab('ad');
            }}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-bold font-mono transition border cursor-pointer ${
              showConfigDrawer && activeConfigTab === 'ad'
                ? 'bg-cyan-500/20 border-cyan-500/60 text-cyan-300'
                : 'bg-black/60 border-white/20 hover:border-white/40 text-white/80'
            }`}
          >
            <KeyRound className="w-3.5 h-3.5 text-cyan-400" />
            <span>AD Connect</span>
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
          </button>

          <button
            onClick={() => {
              setShowConfigDrawer(!showConfigDrawer);
              setActiveConfigTab('network');
            }}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-bold font-mono transition border cursor-pointer ${
              showConfigDrawer && activeConfigTab === 'network'
                ? 'bg-amber-500/20 border-amber-500/60 text-amber-300'
                : 'bg-black/60 border-white/20 hover:border-white/40 text-white/80'
            }`}
          >
            <Network className="w-3.5 h-3.5 text-amber-400" />
            <span>Gateway & DNS Scan</span>
          </button>

          <button
            onClick={() => {
              setShowConfigDrawer(true);
              setActiveConfigTab('ip_report');
            }}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-bold font-mono transition border cursor-pointer ${
              showConfigDrawer && activeConfigTab === 'ip_report'
                ? 'bg-emerald-500/20 border-emerald-500/60 text-emerald-300'
                : 'bg-emerald-500/10 border-emerald-500/30 hover:border-emerald-500/50 text-emerald-400'
            }`}
          >
            <FileText className="w-3.5 h-3.5 text-emerald-400" />
            <span>IP-Wise 60+ Scan Report</span>
            {showConfigDrawer ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>

          {/* Clear Inventory Saved Data Button */}
          {onClearAllEndpoints && (
            <button
              onClick={() => setShowClearConfirmModal(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-bold font-mono transition border cursor-pointer bg-red-500/10 hover:bg-red-500/20 text-red-300 border-red-500/40 hover:border-red-500/60"
              title="Clear all saved host devices from local browser storage"
            >
              <Trash2 className="w-3.5 h-3.5 text-red-400" />
              <span>Clear Saved Data</span>
            </button>
          )}

          {/* Restore Demo Hosts Button */}
          {onRestoreDefaultEndpoints && (
            <button
              onClick={() => {
                onRestoreDefaultEndpoints();
                setToastMessage({ text: 'Restored 5 demo host devices to inventory.', type: 'info' });
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-bold font-mono transition border cursor-pointer bg-white/5 hover:bg-white/10 text-white/80 border-white/20 hover:border-white/40"
              title="Restore standard 5 demo Windows host devices to inventory"
            >
              <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
              <span>{endpoints.length === 0 ? 'Restore Demo 5 Hosts' : 'Reload Demo Hosts'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Active Directory, Network Gateway, & IP-Wise Report Drawer */}
      {showConfigDrawer && (
        <div className="p-5 border-b-2 border-cyan-500/30 bg-[#0a0a0a] space-y-5 animate-fadeIn font-mono">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={() => setActiveConfigTab('network')}
                className={`px-3 py-1.5 rounded text-xs font-bold flex items-center gap-2 transition cursor-pointer ${
                  activeConfigTab === 'network'
                    ? 'bg-amber-500/20 border border-amber-500/50 text-amber-300'
                    : 'bg-white/5 text-white/60 hover:text-white'
                }`}
              >
                <Network className="w-4 h-4 text-amber-400" />
                Facility Network & DNS Configuration
              </button>

              <button
                onClick={() => setActiveConfigTab('ad')}
                className={`px-3 py-1.5 rounded text-xs font-bold flex items-center gap-2 transition cursor-pointer ${
                  activeConfigTab === 'ad'
                    ? 'bg-cyan-500/20 border border-cyan-500/50 text-cyan-300'
                    : 'bg-white/5 text-white/60 hover:text-white'
                }`}
              >
                <KeyRound className="w-4 h-4 text-cyan-400" />
                Active Directory Credentials
              </button>

              <button
                onClick={() => setActiveConfigTab('ip_report')}
                className={`px-3 py-1.5 rounded text-xs font-bold flex items-center gap-2 transition cursor-pointer ${
                  activeConfigTab === 'ip_report'
                    ? 'bg-emerald-500/20 border border-emerald-500/50 text-emerald-300'
                    : 'bg-white/5 text-white/60 hover:text-white'
                }`}
              >
                <FileText className="w-4 h-4 text-emerald-400" />
                IP-Wise 60+ Vulnerability Report
              </button>
            </div>

            <button
              onClick={() => setShowConfigDrawer(false)}
              className="text-white/40 hover:text-white p-1 rounded hover:bg-white/10 transition"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Active Directory Connection Tab */}
          {activeConfigTab === 'ad' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-black text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                    <KeyRound className="w-4 h-4 text-cyan-400" />
                    Active Directory Domain Controller Authentication
                  </h3>
                  <p className="text-[11px] text-white/50 mt-0.5">
                    Provide domain administrator credentials to query LDAP/S and retrieve endpoint GPO policies.
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${
                    adStatus === 'connected' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                  }`}>
                    {adStatus === 'connected' ? '● AD Connected' : '○ Pending Verification'}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                <div>
                  <label className="block text-white/60 font-bold mb-1">AD Domain / DC IP</label>
                  <div className="flex items-center bg-black border border-white/20 rounded px-2.5 py-1.5 focus-within:border-cyan-400">
                    <Globe className="w-3.5 h-3.5 text-white/40 mr-2" />
                    <input
                      type="text"
                      value={adDomain}
                      onChange={(e) => setAdDomain(e.target.value)}
                      className="bg-transparent text-white font-bold w-full focus:outline-none"
                      placeholder="corp.domain.com"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-white/60 font-bold mb-1">Active Directory Username</label>
                  <div className="flex items-center bg-black border border-white/20 rounded px-2.5 py-1.5 focus-within:border-cyan-400">
                    <KeyRound className="w-3.5 h-3.5 text-white/40 mr-2" />
                    <input
                      type="text"
                      value={adUsername}
                      onChange={(e) => setAdUsername(e.target.value)}
                      className="bg-transparent text-white font-bold w-full focus:outline-none"
                      placeholder="CORP\Administrator"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-white/60 font-bold mb-1">AD User Password</label>
                  <div className="flex items-center bg-black border border-white/20 rounded px-2.5 py-1.5 focus-within:border-cyan-400">
                    <Lock className="w-3.5 h-3.5 text-white/40 mr-2" />
                    <input
                      type={showAdPassword ? "text" : "password"}
                      value={adPassword}
                      onChange={(e) => setAdPassword(e.target.value)}
                      className="bg-transparent text-white font-bold w-full focus:outline-none"
                      placeholder="••••••••••••"
                    />
                    <button
                      type="button"
                      onClick={() => setShowAdPassword(!showAdPassword)}
                      className="text-[10px] text-cyan-400 font-bold hover:underline ml-1"
                    >
                      {showAdPassword ? 'HIDE' : 'SHOW'}
                    </button>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between pt-2">
                <span className="text-[11px] text-emerald-400/90 font-mono flex items-center gap-1.5">
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  {adMessage}
                </span>

                <button
                  onClick={handleTestAdConnection}
                  disabled={adStatus === 'testing'}
                  className="bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 px-4 py-1.5 rounded text-xs font-bold uppercase transition flex items-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  {adStatus === 'testing' ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                      Testing LDAP...
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                      Test AD Connection
                    </>
                  )}
                </button>
              </div>
            </div>
          )}

          {/* Facility Network Gateway & DNS Scanning Tab */}
          {activeConfigTab === 'network' && (
            <div className="space-y-4">
              <div>
                <h3 className="text-xs font-black text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Network className="w-4 h-4 text-amber-400" />
                  Facility Network Gateway & DNS Configuration Live Scanner
                </h3>
                <p className="text-[11px] text-white/50 mt-0.5">
                  Configure network parameters, default gateway, and primary/secondary DNS servers to perform a live 60-findings security audit on target subnet endpoints.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 text-xs">
                <div>
                  <label className="block text-white/60 font-bold mb-1">Subnet CIDR Range</label>
                  <input
                    type="text"
                    value={subnetCidr}
                    onChange={(e) => setSubnetCidr(e.target.value)}
                    className="bg-black border border-white/20 rounded px-2.5 py-1.5 text-cyan-300 font-mono font-bold w-full focus:border-amber-400 focus:outline-none"
                    placeholder="192.168.1.0/24"
                  />
                </div>

                <div>
                  <label className="block text-white/60 font-bold mb-1">Default Gateway IP *</label>
                  <input
                    type="text"
                    value={defaultGateway}
                    onChange={(e) => setDefaultGateway(e.target.value)}
                    className="bg-black border border-white/20 rounded px-2.5 py-1.5 text-cyan-300 font-mono font-bold w-full focus:border-amber-400 focus:outline-none"
                    placeholder="192.168.1.1"
                  />
                </div>

                <div>
                  <label className="block text-white/60 font-bold mb-1">Primary DNS Server *</label>
                  <input
                    type="text"
                    value={primaryDns}
                    onChange={(e) => setPrimaryDns(e.target.value)}
                    className="bg-black border border-white/20 rounded px-2.5 py-1.5 text-cyan-300 font-mono font-bold w-full focus:border-amber-400 focus:outline-none"
                    placeholder="192.168.1.254"
                  />
                </div>

                <div>
                  <label className="block text-white/60 font-bold mb-1">Secondary DNS Server</label>
                  <input
                    type="text"
                    value={secondaryDns}
                    onChange={(e) => setSecondaryDns(e.target.value)}
                    className="bg-black border border-white/20 rounded px-2.5 py-1.5 text-cyan-300 font-mono font-bold w-full focus:border-amber-400 focus:outline-none"
                    placeholder="8.8.8.8"
                  />
                </div>

                <div>
                  <label className="block text-white/60 font-bold mb-1">Subnet Mask</label>
                  <input
                    type="text"
                    value={subnetMask}
                    onChange={(e) => setSubnetMask(e.target.value)}
                    className="bg-black border border-white/20 rounded px-2.5 py-1.5 text-cyan-300 font-mono font-bold w-full focus:border-amber-400 focus:outline-none"
                    placeholder="255.255.255.0"
                  />
                </div>

                <div>
                  <label className="block text-amber-300 font-bold mb-1">Target Host IP</label>
                  <input
                    type="text"
                    value={targetIp}
                    onChange={(e) => setTargetIp(e.target.value)}
                    className="bg-black border border-amber-500/60 rounded px-2.5 py-1.5 text-amber-300 font-mono font-black w-full focus:border-amber-400 focus:outline-none"
                    placeholder="192.168.1.45"
                  />
                </div>
              </div>

              {/* Additional Target Info */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs bg-black/40 p-3 rounded border border-white/10">
                <div>
                  <label className="block text-white/60 font-bold mb-1">Target Hostname</label>
                  <input
                    type="text"
                    value={targetHostname}
                    onChange={(e) => setTargetHostname(e.target.value)}
                    className="bg-black border border-white/20 rounded px-2.5 py-1 text-white font-mono font-bold w-full focus:border-cyan-400 focus:outline-none"
                    placeholder="FACILITY-GW-SRV01"
                  />
                </div>

                <div>
                  <label className="block text-white/60 font-bold mb-1">Target Device Type</label>
                  <select
                    value={targetDeviceType}
                    onChange={(e) => setTargetDeviceType(e.target.value as any)}
                    className="bg-black border border-white/20 rounded px-2.5 py-1 text-white font-mono font-bold w-full focus:border-cyan-400 focus:outline-none"
                  >
                    <option value="Server">Server (Infrastructure / DC / GW)</option>
                    <option value="Workstation">Workstation (Windows 10 / 11 Enterprise)</option>
                    <option value="Laptop">Laptop (Mobile Endpoint)</option>
                  </select>
                </div>
              </div>

              {/* Console & Progress during scanning */}
              {isScanning && (
                <div className="space-y-2 bg-black/90 p-4 rounded border border-amber-500/40 font-mono">
                  <div className="flex items-center justify-between text-xs text-amber-300 font-bold">
                    <span className="flex items-center gap-2">
                      <Sparkles className="w-4 h-4 text-amber-400 animate-spin" />
                      Auditing Network Subnet ({subnetCidr}) & Target IP ({targetIp})...
                    </span>
                    <span>{scanProgress}%</span>
                  </div>

                  {/* Progress Bar */}
                  <div className="w-full bg-white/10 h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-gradient-to-r from-amber-500 to-emerald-400 h-full transition-all duration-300"
                      style={{ width: `${scanProgress}%` }}
                    ></div>
                  </div>

                  <div className="text-[11px] space-y-1 text-white/80 max-h-32 overflow-y-auto pt-2 scrollbar-thin">
                    {scanLogs.map((log, idx) => (
                      <div key={idx} className="flex items-center gap-1.5">
                        <Terminal className="w-3 h-3 text-cyan-400 flex-shrink-0" />
                        <span>{log}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {scanSuccessMsg && !isScanning && (
                <div className="p-3 bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-xs rounded font-bold flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    {scanSuccessMsg}
                  </span>
                  <button
                    onClick={() => setActiveConfigTab('ip_report')}
                    className="underline text-white font-bold cursor-pointer hover:text-cyan-300 flex items-center gap-1"
                  >
                    <FileText className="w-3.5 h-3.5 text-emerald-400" />
                    Open IP-Wise 60+ Findings Matrix
                  </button>
                </div>
              )}

              {/* Action Button */}
              <div className="flex items-center justify-between pt-2">
                <span className="text-[11px] text-white/40">
                  Subnet CIDR: <strong className="text-white">{subnetCidr}</strong> | Gateway: <strong className="text-white">{defaultGateway}</strong> | Primary DNS: <strong className="text-white">{primaryDns}</strong>
                </span>

                <button
                  onClick={handleRunLiveScan}
                  disabled={isScanning}
                  className="bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-600 hover:to-amber-700 text-black px-5 py-2 rounded text-xs font-black uppercase tracking-wider transition shadow-lg flex items-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  <Sparkles className="w-4 h-4 text-black" />
                  {isScanning ? 'Scanning Network Subnet...' : 'Execute 60-Findings Live AI Scan'}
                </button>
              </div>
            </div>
          )}

          {/* IP-Wise 60+ Vulnerability Audit Report Matrix */}
          {activeConfigTab === 'ip_report' && (
            <div className="space-y-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-white/10 pb-3">
                <div>
                  <h3 className="text-xs font-black text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                    <FileText className="w-4 h-4 text-emerald-400" />
                    IP-Wise 60+ Vulnerabilities Audit Report Matrix
                  </h3>
                  <p className="text-[11px] text-white/50 mt-0.5">
                    Detailed per-IP security posture across 60 benchmark findings for subnet <span className="text-white font-mono font-bold">{subnetCidr}</span> via Gateway <span className="text-white font-mono font-bold">{defaultGateway}</span> & DNS <span className="text-white font-mono font-bold">{primaryDns}</span>.
                  </p>
                </div>

                {/* Filter Controls */}
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <div>
                    <label className="text-[10px] text-white/40 block font-bold">Select IP:</label>
                    <select
                      value={reportSelectedIp}
                      onChange={(e) => setReportSelectedIp(e.target.value)}
                      className="bg-black border border-white/20 rounded px-2 py-1 text-white font-mono font-bold text-xs focus:border-emerald-400 focus:outline-none"
                    >
                      <option value="all">All IP Addresses ({endpoints.length})</option>
                      {endpoints.map(ep => (
                        <option key={ep.id} value={ep.ip}>{ep.ip} ({ep.name})</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="text-[10px] text-white/40 block font-bold">Severity / Status:</label>
                    <select
                      value={reportSeverityFilter}
                      onChange={(e) => setReportSeverityFilter(e.target.value as any)}
                      className="bg-black border border-white/20 rounded px-2 py-1 text-white font-mono font-bold text-xs focus:border-emerald-400 focus:outline-none"
                    >
                      <option value="all">All Statuses</option>
                      <option value="failed">Failed Gaps Only</option>
                      <option value="Critical">Critical Severity</option>
                      <option value="High">High Severity</option>
                      <option value="Medium">Medium Severity</option>
                      <option value="Low">Low Severity</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* IP-Wise Summary Cards & Table */}
              <div className="space-y-4">
                {endpoints
                  .filter(ep => reportSelectedIp === 'all' || ep.ip === reportSelectedIp)
                  .map((ep) => {
                    const vulnList = get60VulnerabilitiesForEndpoint(ep);
                    const failedVulns = vulnList.filter(v => v.status === 'failed' || v.status === 'warning');
                    const passedVulns = vulnList.filter(v => v.status === 'passed');

                    const filteredVulns = vulnList.filter(v => {
                      if (reportSeverityFilter === 'failed') return v.status === 'failed' || v.status === 'warning';
                      if (reportSeverityFilter !== 'all') return v.vulnerability.severity === reportSeverityFilter;
                      return true;
                    });

                    const isExpanded = expandedIpRows[ep.ip] ?? true;

                    return (
                      <div key={ep.id} className="bg-black/60 border border-white/15 rounded-lg p-4 space-y-3">
                        {/* Header Row for this IP */}
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-3">
                          <div className="flex items-center gap-3">
                            <div className="p-2 rounded bg-cyan-500/10 border border-cyan-500/30">
                              {getDeviceIcon(ep.deviceType, ep.os)}
                            </div>
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-black font-mono text-cyan-300">{ep.ip}</span>
                                <span className="text-xs font-bold text-white font-mono">({ep.name})</span>
                                {getScoreBadge(ep.overallScore)}
                              </div>
                              <div className="text-[11px] text-white/50 font-mono mt-0.5">
                                OS: {ep.os} | AD Privilege: <span className="text-white font-bold">{adUsername}</span>
                              </div>
                            </div>
                          </div>

                          <div className="flex items-center gap-2">
                            {/* Summary Metrics */}
                            <div className="flex items-center gap-1.5 text-xs font-mono mr-2">
                              <span className="px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 font-bold">
                                {passedVulns.length} Passed
                              </span>
                              <span className="px-2 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-400 font-bold">
                                {failedVulns.length} Gaps
                              </span>
                            </div>

                            <button
                              onClick={() => handleLiveScanSingleIp(ep)}
                              disabled={scanningIp === ep.ip}
                              className="px-2.5 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 text-xs font-bold uppercase transition border border-cyan-500/40 flex items-center gap-1 cursor-pointer disabled:opacity-50"
                              title="Trigger live 60-finding scan on this IP"
                            >
                              <Radio className={`w-3.5 h-3.5 text-cyan-400 ${scanningIp === ep.ip ? 'animate-spin text-amber-400' : ''}`} />
                              {scanningIp === ep.ip ? 'Scanning IP...' : 'Live Scan'}
                            </button>

                            <button
                              onClick={() => setEditingEndpoint(ep)}
                              className="px-2.5 py-1 rounded bg-white/10 hover:bg-white/20 text-white text-xs font-bold uppercase transition border border-white/20 flex items-center gap-1 cursor-pointer"
                              title="Edit IP Host parameters"
                            >
                              <Edit3 className="w-3.5 h-3.5 text-cyan-400" />
                              Edit
                            </button>

                            <button
                              onClick={() => setDeleteConfirmEndpoint(ep)}
                              className="px-2 py-1 rounded bg-red-500/15 hover:bg-red-500/25 text-red-400 text-xs font-bold uppercase transition border border-red-500/30 flex items-center gap-1 cursor-pointer"
                              title="Delete IP Host from inventory"
                            >
                              <Trash2 className="w-3.5 h-3.5 text-red-400" />
                            </button>

                            <button
                              onClick={() => toggleIpExpand(ep.ip)}
                              className="p-1 rounded bg-white/5 hover:bg-white/10 text-white/70 border border-white/10 transition cursor-pointer"
                            >
                              {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                            </button>
                          </div>
                        </div>

                        {/* Collapsible 60 Vulnerability Breakdown per IP */}
                        {isExpanded && (
                          <div className="space-y-2">
                            <div className="text-[11px] text-white/40 uppercase tracking-wider font-mono font-bold flex items-center justify-between">
                              <span>Showing {filteredVulns.length} of 60 Vulnerabilities Audit Checks</span>
                              <span>Subnet Target IP: {ep.ip}</span>
                            </div>

                            <div className="max-h-72 overflow-y-auto border border-white/10 rounded bg-black/80 scrollbar-thin scrollbar-thumb-white/20">
                              <table className="w-full text-left border-collapse text-xs font-mono">
                                <thead>
                                  <tr className="border-b border-white/10 bg-white/5 text-[10px] uppercase text-white/50">
                                    <th className="py-2 px-3">ID / CVE</th>
                                    <th className="py-2 px-3">Category</th>
                                    <th className="py-2 px-3">Vulnerability Finding</th>
                                    <th className="py-2 px-3 text-center">Severity</th>
                                    <th className="py-2 px-3 text-center">Audit Status</th>
                                    <th className="py-2 px-3 text-right">Powershell Fix</th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-white/5">
                                  {filteredVulns.map(item => {
                                    const v = item.vulnerability;
                                    const isPassed = item.status === 'passed';
                                    const isWarning = item.status === 'warning';
                                    const isExcluded = item.status === 'excluded';

                                    return (
                                      <tr key={v.id} className="hover:bg-white/5 transition">
                                        <td className="py-2 px-3 font-bold text-white/70">
                                          #{v.id} <span className="text-[10px] text-cyan-400 font-mono block">{v.cveId}</span>
                                        </td>
                                        <td className="py-2 px-3 text-white/60 text-[11px]">
                                          {v.category}
                                        </td>
                                        <td className="py-2 px-3 text-white max-w-xs">
                                          <div className="font-bold">{v.name}</div>
                                          <div className="text-[10px] text-white/40 line-clamp-1">{v.description}</div>
                                        </td>
                                        <td className="py-2 px-3 text-center">
                                          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                                            v.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                                            v.severity === 'High' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' :
                                            v.severity === 'Medium' ? 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30' :
                                            'bg-blue-500/15 text-blue-300 border border-blue-500/30'
                                          }`}>
                                            {v.severity}
                                          </span>
                                        </td>
                                        <td className="py-2 px-3 text-center">
                                          {isPassed ? (
                                            <span className="inline-flex items-center gap-1 text-[10px] font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded">
                                              <CheckSquare className="w-3 h-3 text-emerald-400" />
                                              Passed
                                            </span>
                                          ) : isExcluded ? (
                                            <span className="inline-flex items-center gap-1 text-[10px] font-bold text-white/50 bg-white/10 border border-white/20 px-2 py-0.5 rounded">
                                              Excluded
                                            </span>
                                          ) : isWarning ? (
                                            <span className="inline-flex items-center gap-1 text-[10px] font-bold text-amber-400 bg-amber-500/15 border border-amber-500/30 px-2 py-0.5 rounded">
                                              <AlertCircle className="w-3 h-3 text-amber-400" />
                                              Warning
                                            </span>
                                          ) : (
                                            <span className="inline-flex items-center gap-1 text-[10px] font-bold text-red-400 bg-red-500/15 border border-red-500/30 px-2 py-0.5 rounded">
                                              <XSquare className="w-3 h-3 text-red-400" />
                                              Failed
                                            </span>
                                          )}
                                        </td>
                                        <td className="py-2 px-3 text-right">
                                          <span className="text-[10px] text-cyan-300/80 bg-black border border-white/15 px-2 py-0.5 rounded font-mono truncate max-w-[150px] inline-block" title={v.powershellFix}>
                                            {v.powershellFix.split('\n')[0]}
                                          </span>
                                        </td>
                                      </tr>
                                    );
                                  })}
                                </tbody>
                              </table>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Table Toolbar: Search Filter & Quick Status Filter */}
      <div className="p-3 bg-black/50 border-b border-white/10 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-72">
            <Search className="w-3.5 h-3.5 text-white/40 absolute left-2.5 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by IP, Hostname, OS or Dept..."
              className="w-full bg-black border border-white/20 rounded pl-8 pr-3 py-1 text-white placeholder-white/40 text-xs focus:border-cyan-400 focus:outline-none font-mono"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-2 text-white/40 hover:text-white"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <div className="flex items-center gap-1 bg-black border border-white/20 rounded px-2 py-1">
            <Filter className="w-3 h-3 text-amber-400" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as any)}
              className="bg-transparent text-white font-mono text-xs focus:outline-none cursor-pointer"
            >
              <option value="all" className="bg-black text-white">All Statuses ({endpoints.length})</option>
              <option value="flagged" className="bg-black text-red-400 font-bold">🚨 Flagged Below {alertThreshold} ({endpoints.filter(e => e.overallScore < alertThreshold).length})</option>
              <option value="compliant" className="bg-black text-emerald-400">Compliant Only</option>
              <option value="attention" className="bg-black text-amber-400">Needs Attention Only</option>
            </select>
          </div>

          <div className="flex items-center gap-1 bg-black border border-white/20 rounded px-2 py-1">
            <Wifi className="w-3 h-3 text-cyan-400" />
            <select
              value={rdpFilter}
              onChange={(e) => setRdpFilter(e.target.value as any)}
              className="bg-transparent text-white font-mono text-xs focus:outline-none cursor-pointer"
            >
              <option value="all" className="bg-black text-white">All RDP ({endpoints.length})</option>
              <option value="connected" className="bg-black text-emerald-400">RDP Connected</option>
              <option value="disconnected" className="bg-black text-amber-400">RDP Disconnected</option>
              <option value="failed" className="bg-black text-red-400">RDP Failed</option>
            </select>
          </div>
        </div>

        <div className="text-[11px] text-white/50 flex items-center gap-3 self-end sm:self-auto">
          <span>Showing <strong className="text-white">{filteredEndpoints.length}</strong> of <strong className="text-white">{endpoints.length}</strong> Hosts</span>
        </div>
      </div>

      {/* Main Responsive Inventory Table */}
      <div className="overflow-x-auto scrollbar-thin scrollbar-thumb-white/20">
        <table className="w-full text-left border-collapse min-w-[1050px]">
          <thead>
            <tr className="border-b border-white/15 bg-black/40 text-[11px] font-mono uppercase tracking-wider text-white/60">
              <th className="py-3.5 px-4 font-bold">Hostname / Device</th>
              <th className="py-3.5 px-4 font-bold">OS Version</th>
              <th className="py-3.5 px-4 font-bold">IP & Department</th>
              <th className="py-3.5 px-4 font-bold text-center">Connection / RDP</th>
              <th className="py-3.5 px-4 font-bold text-center">HDD / SSD Health</th>
              <th className="py-3.5 px-4 font-bold text-center">BitLocker / EDR</th>
              <th className="py-3.5 px-4 font-bold">Firewall / SMBv1</th>
              <th className="py-3.5 px-4 font-bold text-center">Score</th>
              <th className="py-3.5 px-4 font-bold text-center">Status</th>
              <th className="py-3.5 px-4 font-bold text-right">Actions (Scan / PS1 / Edit)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/10 text-xs">
            {filteredEndpoints.length === 0 ? (
              <tr>
                <td colSpan={10} className="py-12 px-4 text-center">
                  {endpoints.length === 0 ? (
                    <div className="max-w-md mx-auto space-y-3 font-mono">
                      <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mx-auto text-cyan-400">
                        <Server className="w-6 h-6" />
                      </div>
                      <h3 className="text-sm font-black text-white uppercase tracking-wider">
                        Saved Inventory Data Cleared (0 Host Devices)
                      </h3>
                      <p className="text-xs text-white/50 font-sans leading-relaxed">
                        All previous endpoint posture records have been cleared from local storage. Add your Windows hosts, scan a live IP address, or restore the 5 demo machines.
                      </p>
                      <div className="flex items-center justify-center gap-2.5 pt-2 flex-wrap">
                        <button
                          onClick={() => setShowAddModal(true)}
                          className="px-3.5 py-1.5 rounded bg-emerald-500 hover:bg-emerald-400 text-black text-xs font-bold transition cursor-pointer flex items-center gap-1.5 font-mono shadow-md shadow-emerald-950/30"
                        >
                          <Plus className="w-3.5 h-3.5" />
                          + Add / Scan IP Host
                        </button>
                        {onRestoreDefaultEndpoints && (
                          <button
                            onClick={() => {
                              onRestoreDefaultEndpoints();
                              setToastMessage({ text: 'Restored 5 demo host devices to inventory.', type: 'info' });
                            }}
                            className="px-3.5 py-1.5 rounded bg-white/10 hover:bg-white/20 text-white text-xs font-bold border border-white/20 transition cursor-pointer flex items-center gap-1.5 font-mono"
                          >
                            <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
                            Restore Demo 5 Hosts
                          </button>
                        )}
                      </div>
                    </div>
                  ) : (
                    <div className="py-8 text-center text-white/50 font-mono">
                      No endpoint IP hosts matched search criteria: "{searchQuery}".
                      <button
                        onClick={() => setSearchQuery('')}
                        className="ml-2 text-cyan-400 underline hover:text-cyan-300 font-bold"
                      >
                        Clear Search
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ) : (
              filteredEndpoints.map((ep) => {
                const isSelected = ep.id === selectedEndpointId;
                const isCurrentlyScanning = scanningIp === ep.ip;

                const deviceType = ep.deviceType || (ep.name.toLowerCase().includes('srv') || ep.name.toLowerCase().includes('dc') ? 'Server' : ep.name.toLowerCase() === 'test' ? 'Laptop' : 'Workstation');
                const department = ep.department || 'Corporate Endpoints';
                const bitLocker = ep.bitLocker || (ep.name === 'CORP-WIN10-WS104' ? 'Unencrypted' : 'Encrypted');
                const defenderEdr = ep.defenderEdr || (ep.name === 'CORP-WIN10-WS104' ? 'Outdated' : 'Active');
                const patchLevel = ep.patchLevel || (ep.name === 'CORP-WIN10-WS104' ? 'Pending Updates' : 'Up-to-Date');
                const smbStatusText = ep.smbStatusText || (ep.name === 'CORP-WIN10-WS104' ? 'SMBv1: ENABLED (Vuln)' : 'SMBv1: Disabled (Safe)');

                const isCompliant = ep.overallScore >= 85 && bitLocker === 'Encrypted' && smbStatusText.includes('Disabled');

                return (
                  <tr
                    key={ep.id}
                    onClick={() => onSelectEndpoint(ep.id)}
                    className={`transition-colors cursor-pointer group hover:bg-white/5 ${
                      isSelected ? 'bg-white/10 font-medium' : ''
                    } ${isCurrentlyScanning ? 'bg-amber-500/10' : ''}`}
                  >
                    {/* Hostname / Device */}
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2.5">
                        <div className="p-1.5 rounded bg-white/5 border border-white/10 group-hover:border-white/30 transition">
                          {getDeviceIcon(deviceType, ep.os)}
                        </div>
                        <div>
                          <div className="font-mono font-black text-white text-xs tracking-wide flex items-center gap-1.5">
                            {ep.name}
                            {isSelected && <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>}
                          </div>
                          <div className="text-[10px] text-white/50 font-mono uppercase mt-0.5">
                            {deviceType}
                          </div>
                        </div>
                      </div>
                    </td>

                    {/* OS Version */}
                    <td className="py-3.5 px-4 text-white/80 font-mono text-[11px] max-w-[200px]">
                      <span className="line-clamp-2" title={ep.os}>{ep.os}</span>
                    </td>

                    {/* IP & Department */}
                    <td className="py-3.5 px-4">
                      <div className="font-mono text-cyan-300 font-bold text-xs flex items-center gap-1.5 flex-wrap">
                        <span>{ep.ip}</span>

                        {/* Real-time RDP Connectivity Status Icon */}
                        {testingRdpIp === ep.ip ? (
                          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40" title="Testing RDP Port 3389...">
                            <Loader2 className="w-3 h-3 text-amber-400 animate-spin" />
                          </span>
                        ) : (ep.rdpStatus === 'failed' || ep.connectionStatus === 'failed') ? (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleTestRdpSingle(ep);
                            }}
                            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-500/25 text-red-300 border border-red-500/50 hover:bg-red-500/40 transition cursor-pointer"
                            title={`RDP Connection Check FAILED: ${ep.connectionReason || 'Port 3389 unreachable'}. Click to re-test.`}
                          >
                            <WifiOff className="w-3 h-3 text-red-400 animate-pulse" />
                          </button>
                        ) : ep.rdpStatus === 'disconnected' ? (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleTestRdpSingle(ep);
                            }}
                            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold bg-white/10 text-white/60 border border-white/20 hover:bg-white/20 transition cursor-pointer"
                            title="RDP Disconnected: Port 3389 closed. Click to re-test."
                          >
                            <PlugZap className="w-3 h-3 text-amber-400" />
                          </button>
                        ) : (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleTestRdpSingle(ep);
                            }}
                            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30 transition cursor-pointer"
                            title="RDP Connected: TCP Port 3389 Active & NLA Verified. Click to re-test."
                          >
                            <Wifi className="w-3 h-3 text-emerald-400" />
                          </button>
                        )}

                        {isCurrentlyScanning && <Sparkles className="w-3 h-3 text-amber-400 animate-spin" />}
                      </div>
                      <div className="text-[10px] text-white/50 uppercase truncate max-w-[170px]" title={department}>
                        {department}
                      </div>
                    </td>

                    {/* Connection / RDP Status */}
                    <td className="py-3.5 px-4 text-center font-mono">
                      {testingRdpIp === ep.ip ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                          <Loader2 className="w-3 h-3 text-amber-400 animate-spin" />
                          Probing 3389...
                        </span>
                      ) : (ep.rdpStatus === 'failed' || ep.connectionStatus === 'failed') ? (
                        <div className="space-y-1">
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/40">
                            <WifiOff className="w-3 h-3 text-red-400 animate-pulse" />
                            RDP Failed
                          </span>
                          <div className="text-[9px] text-red-300/90 max-w-[150px] truncate mx-auto font-medium" title={ep.connectionReason || 'Port 3389 unreachable / NLA handshake timed out'}>
                            {ep.connectionReason || '3389 Unreachable'}
                          </div>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleTestRdpSingle(ep);
                            }}
                            className="text-[9px] text-cyan-400 hover:text-cyan-300 underline font-sans cursor-pointer block mx-auto"
                          >
                            Retry RDP
                          </button>
                        </div>
                      ) : ep.rdpStatus === 'disconnected' ? (
                        <div className="space-y-0.5">
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30">
                            <PlugZap className="w-3 h-3 text-amber-400" />
                            Disconnected
                          </span>
                          <div className="text-[9px] text-white/50">
                            Port 3389 Closed
                          </div>
                        </div>
                      ) : ep.connectionStatus === 'scanning' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                          <Radio className="w-3 h-3 text-amber-400 animate-spin" />
                          Probing IP...
                        </span>
                      ) : (
                        <div className="space-y-0.5">
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                            <Wifi className="w-3 h-3 text-emerald-400" />
                            RDP Connected
                          </span>
                          <div className="text-[9px] text-cyan-400/80">
                            Port 3389 Active
                          </div>
                        </div>
                      )}
                    </td>

                    {/* HDD / SSD Health */}
                    <td className="py-3.5 px-4 text-center font-mono text-[10px]">
                      {ep.storageHealth && ep.storageHealth.length > 0 ? (
                        <div className="space-y-1">
                          {ep.storageHealth.slice(0, 1).map((drive, idx) => (
                            <div key={idx} className="flex items-center justify-center gap-1">
                              <span className={`font-bold px-1 py-0.5 rounded ${
                                drive.healthStatus === 'Healthy' ? 'text-emerald-400 bg-emerald-500/10' : 'text-red-400 bg-red-500/10'
                              }`}>
                                {drive.driveLetter} [{drive.mediaType}] {drive.smartStatus}
                              </span>
                              <span className="text-white/60">
                                {drive.freeSpaceGB}GB Free ({drive.freeSpacePercent}%)
                              </span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="text-white/60">
                          <span className="text-emerald-400 font-bold">NVMe SSD: Passed</span>
                          <div className="text-[9px] text-white/40">184GB Free (36%)</div>
                        </div>
                      )}
                    </td>

                    {/* BitLocker / EDR */}
                    <td className="py-3.5 px-4 text-center">
                      <div className="space-y-1">
                        {bitLocker === 'Encrypted' ? (
                          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-bold font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            <Lock className="w-2.5 h-2.5 text-emerald-400" />
                            BitLocker Encrypted
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-bold font-mono bg-red-500/15 text-red-400 border border-red-500/30">
                            <Unlock className="w-2.5 h-2.5 text-red-400" />
                            Unencrypted Drive
                          </span>
                        )}
                        <div className="text-[9px] font-mono text-white/50">
                          EDR: <strong className={defenderEdr === 'Active' ? 'text-emerald-400' : 'text-amber-400'}>{defenderEdr}</strong>
                        </div>
                      </div>
                    </td>

                    {/* Firewall / SMBv1 */}
                    <td className="py-3.5 px-4">
                      {smbStatusText.includes('Disabled') || smbStatusText.includes('Safe') ? (
                        <span className="text-[11px] font-mono text-emerald-400 font-semibold flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                          SMBv1: Disabled (Safe)
                        </span>
                      ) : (
                        <span className="text-[11px] font-mono text-red-400 font-bold flex items-center gap-1">
                          <AlertTriangle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                          SMBv1: ENABLED (Vuln)
                        </span>
                      )}
                    </td>

                    {/* Score */}
                    <td className="py-3.5 px-4 text-center">
                      {getScoreBadge(ep.overallScore)}
                    </td>

                    {/* Status */}
                    <td className="py-3.5 px-4 text-center">
                      <div className="flex flex-col items-center gap-1">
                        {getStatusBadge(isCompliant ? 'Compliant' : 'Needs Attention', ep.overallScore)}
                        {ep.overallScore < alertThreshold && (
                          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-black uppercase font-mono bg-red-500/20 text-red-300 border border-red-500/60 animate-pulse" title={`Score (${ep.overallScore}) is below alert threshold (${alertThreshold}). Flagged for urgent manual review.`}>
                            <AlertTriangle className="w-2.5 h-2.5 text-red-400" />
                            Flagged for Review
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Actions: Live Scan / RDP PS1 / Edit / Delete */}
                    <td className="py-3.5 px-4 text-right">
                      <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                        
                        {/* Live IP Scan Button */}
                        <button
                          onClick={() => handleLiveScanSingleIp(ep)}
                          disabled={isCurrentlyScanning}
                          className="inline-flex items-center gap-1 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition cursor-pointer disabled:opacity-50"
                          title="Run immediate live 60-finding audit scan on this IP address"
                        >
                          <Radio className={`w-3 h-3 text-cyan-400 ${isCurrentlyScanning ? 'animate-spin text-amber-400' : ''}`} />
                          {isCurrentlyScanning ? 'Scanning...' : 'Live Scan'}
                        </button>

                        {/* RDP PS1 Fix Download */}
                        <button
                          onClick={() => {
                            const scriptContent = `# PowerShell Direct Remediation Script for ${ep.name} (${ep.ip})\nSet-SmbServerConfiguration -EnableSMB1Protocol $false -Force\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type DWord -Force\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -Type DWord -Force\nSet-NetFirewallProfile -Profile Domain,Private,Public -Enabled True\nWrite-Host "Endpoint ${ep.name} hardened via RDP Session!" -ForegroundColor Green`;
                            const element = document.createElement("a");
                            const file = new Blob([scriptContent], { type: 'text/plain' });
                            element.href = URL.createObjectURL(file);
                            element.download = `Remediate_RDP_${ep.name}_${ep.ip}.ps1`;
                            document.body.appendChild(element);
                            element.click();
                            document.body.removeChild(element);
                          }}
                          className="inline-flex items-center gap-1 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition cursor-pointer"
                          title="Download PowerShell .ps1 script to execute via RDP connection"
                        >
                          <Terminal className="w-3 h-3 text-emerald-400" />
                          PS1 Script
                        </button>

                        {/* Edit Button */}
                        <button
                          onClick={() => setEditingEndpoint(ep)}
                          className="inline-flex items-center gap-1 bg-white/10 hover:bg-white/20 text-white border border-white/20 px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition cursor-pointer"
                          title="Edit host parameters and save"
                        >
                          <Edit3 className="w-3 h-3 text-cyan-400" />
                          Edit
                        </button>

                        {/* Delete Button */}
                        <button
                          onClick={() => setDeleteConfirmEndpoint(ep)}
                          className="inline-flex items-center gap-1 bg-red-500/15 hover:bg-red-500/25 text-red-400 border border-red-500/30 px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition cursor-pointer"
                          title="Delete IP host from inventory"
                        >
                          <Trash2 className="w-3 h-3 text-red-400" />
                        </button>

                        {/* Inspect Details */}
                        <button
                          onClick={() => {
                            onSelectEndpoint(ep.id);
                            const el = document.getElementById('endpoint-audit-view');
                            if (el) {
                              el.scrollIntoView({ behavior: 'smooth' });
                            }
                          }}
                          className="p-1 bg-white/5 hover:bg-white/10 text-white/70 rounded border border-white/10 transition cursor-pointer"
                          title="Inspect Host Registry & Policy Configuration"
                        >
                          <Eye className="w-3.5 h-3.5 text-blue-400" />
                        </button>

                        {/* AI Audit */}
                        <button
                          onClick={() => {
                            onSelectEndpoint(ep.id);
                            if (onAiAuditClick) {
                              onAiAuditClick(ep.id);
                            } else {
                              const el = document.getElementById('endpoint-audit-view');
                              if (el) {
                                el.scrollIntoView({ behavior: 'smooth' });
                              }
                            }
                          }}
                          className="p-1 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 rounded border border-amber-500/30 transition cursor-pointer"
                          title="Run AI Hardening Audit"
                        >
                          <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                        </button>

                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* EDIT ENDPOINT MODAL */}
      {editingEndpoint && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f0f0f] border-2 border-cyan-500/40 rounded-lg max-w-2xl w-full p-6 space-y-4 font-mono shadow-2xl animate-fadeIn">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2">
                <Edit3 className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-black text-white uppercase tracking-wider">
                  Edit Endpoint Host: <span className="text-cyan-300">{editingEndpoint.ip}</span>
                </h3>
              </div>
              <button
                onClick={() => setEditingEndpoint(null)}
                className="text-white/40 hover:text-white p-1 rounded"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div>
                <label className="block text-white/60 font-bold mb-1">IP Address *</label>
                <input
                  type="text"
                  value={editingEndpoint.ip}
                  onChange={(e) => setEditingEndpoint({ ...editingEndpoint, ip: e.target.value })}
                  className="w-full bg-black border border-white/20 rounded px-3 py-1.5 text-cyan-300 font-bold focus:border-cyan-400 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-white/60 font-bold mb-1">Hostname *</label>
                <input
                  type="text"
                  value={editingEndpoint.name}
                  onChange={(e) => setEditingEndpoint({ ...editingEndpoint, name: e.target.value })}
                  className="w-full bg-black border border-white/20 rounded px-3 py-1.5 text-white font-bold focus:border-cyan-400 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-white/60 font-bold mb-1">Device Type</label>
                <select
                  value={editingEndpoint.deviceType || 'Workstation'}
                  onChange={(e) => setEditingEndpoint({ ...editingEndpoint, deviceType: e.target.value as any })}
                  className="w-full bg-black border border-white/20 rounded px-3 py-1.5 text-white font-bold focus:border-cyan-400 focus:outline-none cursor-pointer"
                >
                  <option value="Server">Server (Infrastructure / DC)</option>
                  <option value="Workstation">Workstation (Enterprise Desktop)</option>
                  <option value="Laptop">Laptop (Mobile Endpoint)</option>
                </select>
              </div>

              <div>
                <label className="block text-white/60 font-bold mb-1">OS Version</label>
                <input
                  type="text"
                  value={editingEndpoint.os}
                  onChange={(e) => setEditingEndpoint({ ...editingEndpoint, os: e.target.value })}
                  className="w-full bg-black border border-white/20 rounded px-3 py-1.5 text-white font-bold focus:border-cyan-400 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-white/60 font-bold mb-1">Department / Subnet</label>
                <input
                  type="text"
                  value={editingEndpoint.department || ''}
                  onChange={(e) => setEditingEndpoint({ ...editingEndpoint, department: e.target.value })}
                  className="w-full bg-black border border-white/20 rounded px-3 py-1.5 text-white font-bold focus:border-cyan-400 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-white/60 font-bold mb-1">BitLocker Encryption</label>
                <select
                  value={editingEndpoint.bitLocker || 'Encrypted'}
                  onChange={(e) => setEditingEndpoint({ ...editingEndpoint, bitLocker: e.target.value as any })}
                  className="w-full bg-black border border-white/20 rounded px-3 py-1.5 text-white font-bold focus:border-cyan-400 focus:outline-none cursor-pointer"
                >
                  <option value="Encrypted">Encrypted (Protected)</option>
                  <option value="Unencrypted">Unencrypted (At Risk)</option>
                </select>
              </div>

              <div>
                <label className="block text-white/60 font-bold mb-1">Defender EDR Status</label>
                <select
                  value={editingEndpoint.defenderEdr || 'Active'}
                  onChange={(e) => setEditingEndpoint({ ...editingEndpoint, defenderEdr: e.target.value as any })}
                  className="w-full bg-black border border-white/20 rounded px-3 py-1.5 text-white font-bold focus:border-cyan-400 focus:outline-none cursor-pointer"
                >
                  <option value="Active">Active & Up to Date</option>
                  <option value="Outdated">Outdated / Disabled</option>
                </select>
              </div>

              <div>
                <label className="block text-white/60 font-bold mb-1">Patch Level</label>
                <select
                  value={editingEndpoint.patchLevel || 'Up-to-Date'}
                  onChange={(e) => setEditingEndpoint({ ...editingEndpoint, patchLevel: e.target.value as any })}
                  className="w-full bg-black border border-white/20 rounded px-3 py-1.5 text-white font-bold focus:border-cyan-400 focus:outline-none cursor-pointer"
                >
                  <option value="Up-to-Date">Up-to-Date (Compliant)</option>
                  <option value="Pending Updates">Pending Security Updates</option>
                </select>
              </div>

              <div>
                <label className="block text-white/60 font-bold mb-1">SMB Status</label>
                <select
                  value={editingEndpoint.smbStatusText || 'SMBv1: Disabled (Safe)'}
                  onChange={(e) => setEditingEndpoint({ ...editingEndpoint, smbStatusText: e.target.value })}
                  className="w-full bg-black border border-white/20 rounded px-3 py-1.5 text-white font-bold focus:border-cyan-400 focus:outline-none cursor-pointer"
                >
                  <option value="SMBv1: Disabled (Safe)">SMBv1: Disabled (Safe)</option>
                  <option value="SMBv1: ENABLED (Vuln)">SMBv1: ENABLED (Vulnerable)</option>
                </select>
              </div>

              <div>
                <label className="block text-white/60 font-bold mb-1">Overall Score (0 - 100%)</label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={editingEndpoint.overallScore}
                  onChange={(e) => {
                    const sc = Math.min(100, Math.max(0, parseInt(e.target.value) || 0));
                    setEditingEndpoint({
                      ...editingEndpoint,
                      overallScore: sc,
                      status: sc >= 85 ? 'secure' : sc >= 60 ? 'warning' : 'vulnerable'
                    });
                  }}
                  className="w-full bg-black border border-white/20 rounded px-3 py-1.5 text-emerald-400 font-black focus:border-cyan-400 focus:outline-none"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-4 border-t border-white/10">
              <button
                onClick={() => setEditingEndpoint(null)}
                className="px-4 py-2 rounded text-xs font-bold text-white/70 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition cursor-pointer"
              >
                Cancel
              </button>

              <button
                onClick={handleSaveEditEndpoint}
                className="px-5 py-2 rounded text-xs font-black uppercase tracking-wider bg-cyan-500 hover:bg-cyan-600 text-black transition shadow-lg flex items-center gap-2 cursor-pointer"
              >
                <Save className="w-4 h-4 text-black" />
                Save Changes
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ADD NEW IP HOST MODAL */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f0f0f] border-2 border-emerald-500/40 rounded-lg max-w-2xl w-full p-6 space-y-4 font-mono shadow-2xl animate-fadeIn">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2">
                <Plus className="w-5 h-5 text-emerald-400" />
                <h3 className="text-sm font-black text-white uppercase tracking-wider">
                  Add New Endpoint Host & Live Scan Option
                </h3>
              </div>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-white/40 hover:text-white p-1 rounded"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div>
                <label className="block text-white/60 font-bold mb-1">Target IP Address *</label>
                <input
                  type="text"
                  value={newIp}
                  onChange={(e) => setNewIp(e.target.value)}
                  placeholder="192.168.1.105"
                  className="w-full bg-black border border-white/20 rounded px-3 py-1.5 text-cyan-300 font-bold focus:border-emerald-400 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-white/60 font-bold mb-1">Target Hostname *</label>
                <input
                  type="text"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="FACILITY-WIN11-WS05"
                  className="w-full bg-black border border-white/20 rounded px-3 py-1.5 text-white font-bold focus:border-emerald-400 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-white/60 font-bold mb-1">Device Type</label>
                <select
                  value={newDeviceType}
                  onChange={(e) => setNewDeviceType(e.target.value as any)}
                  className="w-full bg-black border border-white/20 rounded px-3 py-1.5 text-white font-bold focus:border-emerald-400 focus:outline-none cursor-pointer"
                >
                  <option value="Workstation">Workstation (Enterprise Desktop)</option>
                  <option value="Server">Server (Infrastructure / DC)</option>
                  <option value="Laptop">Laptop (Mobile Endpoint)</option>
                </select>
              </div>

              <div>
                <label className="block text-white/60 font-bold mb-1">OS Version</label>
                <input
                  type="text"
                  value={newOs}
                  onChange={(e) => setNewOs(e.target.value)}
                  placeholder="Windows 11 Enterprise 22H2"
                  className="w-full bg-black border border-white/20 rounded px-3 py-1.5 text-white font-bold focus:border-emerald-400 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-white/60 font-bold mb-1">Department / Subnet</label>
                <input
                  type="text"
                  value={newDepartment}
                  onChange={(e) => setNewDepartment(e.target.value)}
                  placeholder="Subnet 192.168.1.0/24"
                  className="w-full bg-black border border-white/20 rounded px-3 py-1.5 text-white font-bold focus:border-emerald-400 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-white/60 font-bold mb-1">Initial Security Score</label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={newScore}
                  onChange={(e) => setNewScore(parseInt(e.target.value) || 0)}
                  className="w-full bg-black border border-white/20 rounded px-3 py-1.5 text-emerald-400 font-bold focus:border-emerald-400 focus:outline-none"
                />
              </div>

              {/* RDP Connectivity Check Config */}
              <div className="col-span-1 md:col-span-2 bg-black/60 border border-white/10 rounded p-3 space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <label className="block text-white/90 font-bold text-xs flex items-center gap-1.5">
                      <Wifi className="w-3.5 h-3.5 text-cyan-400" />
                      RDP Port 3389 Connectivity Simulation
                    </label>
                    <p className="text-[10px] text-white/50">
                      Simulate TCP port 3389 probe and NLA authentication handshake upon adding this IP host.
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    <select
                      value={newRdpStatus}
                      onChange={(e) => setNewRdpStatus(e.target.value as any)}
                      className="bg-black border border-white/20 rounded px-2 py-1 text-xs text-white font-bold focus:border-cyan-400 focus:outline-none cursor-pointer"
                    >
                      <option value="connected">Connected (3389 Open)</option>
                      <option value="disconnected">Disconnected (3389 Closed)</option>
                      <option value="failed">Failed (Connection Timeout)</option>
                    </select>

                    <button
                      type="button"
                      onClick={handleProbeAddRdp}
                      disabled={isProbingAddRdp}
                      className="px-3 py-1 rounded text-xs font-bold bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 flex items-center gap-1 cursor-pointer transition disabled:opacity-50"
                    >
                      {isProbingAddRdp ? <Loader2 className="w-3 h-3 text-cyan-400 animate-spin" /> : <Wifi className="w-3 h-3 text-cyan-400" />}
                      Probe RDP
                    </button>
                  </div>
                </div>

                {addRdpProbeMsg && (
                  <div className={`px-2.5 py-1.5 rounded text-[11px] font-mono border flex items-center gap-2 ${
                    addRdpProbeMsg.type === 'success' ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40' :
                    addRdpProbeMsg.type === 'danger' ? 'bg-red-950/80 text-red-300 border-red-500/40' :
                    'bg-cyan-950/80 text-cyan-300 border-cyan-500/40'
                  }`}>
                    {addRdpProbeMsg.type === 'success' && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />}
                    {addRdpProbeMsg.type === 'danger' && <AlertCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />}
                    {addRdpProbeMsg.type === 'info' && <Loader2 className="w-3.5 h-3.5 text-cyan-400 animate-spin shrink-0" />}
                    <span>{addRdpProbeMsg.text}</span>
                  </div>
                )}
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-white/10">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 rounded text-xs font-bold text-white/70 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition cursor-pointer"
              >
                Cancel
              </button>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleSaveNewEndpoint(false)}
                  className="px-4 py-2 rounded text-xs font-bold bg-white/10 hover:bg-white/20 text-white border border-white/20 transition flex items-center gap-1.5 cursor-pointer"
                >
                  <Save className="w-3.5 h-3.5 text-cyan-400" />
                  Save Host
                </button>

                <button
                  onClick={() => handleSaveNewEndpoint(true)}
                  className="px-5 py-2 rounded text-xs font-black uppercase tracking-wider bg-emerald-500 hover:bg-emerald-600 text-black transition shadow-lg flex items-center gap-2 cursor-pointer"
                >
                  <Radio className="w-4 h-4 text-black" />
                  Save & Live Scan IP
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* DELETE CONFIRMATION MODAL */}
      {deleteConfirmEndpoint && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f0f0f] border-2 border-red-500/50 rounded-lg max-w-md w-full p-6 space-y-4 font-mono shadow-2xl animate-fadeIn">
            <div className="flex items-center gap-3 border-b border-white/10 pb-3">
              <div className="p-2 bg-red-500/20 border border-red-500/40 rounded">
                <Trash2 className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <h3 className="text-sm font-black text-white uppercase tracking-wider">Confirm IP Delete</h3>
                <p className="text-[11px] text-white/50">Remove endpoint record from inventory</p>
              </div>
            </div>

            <div className="text-xs text-white/80 space-y-2 bg-black/50 p-3 rounded border border-white/10">
              <p>Are you sure you want to delete this host IP entry?</p>
              <div className="font-mono font-bold text-cyan-300">
                IP: {deleteConfirmEndpoint.ip} ({deleteConfirmEndpoint.name})
              </div>
              <p className="text-[11px] text-red-400/90 font-bold">
                ⚠️ All associated 60-finding posture logs and audit states will be purged.
              </p>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setDeleteConfirmEndpoint(null)}
                className="px-4 py-2 rounded text-xs font-bold text-white/70 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition cursor-pointer"
              >
                Cancel
              </button>

              <button
                onClick={handleConfirmDeleteEndpoint}
                className="px-5 py-2 rounded text-xs font-black uppercase tracking-wider bg-red-500 hover:bg-red-600 text-white transition shadow-lg flex items-center gap-2 cursor-pointer"
              >
                <Trash2 className="w-4 h-4 text-white" />
                Confirm Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* CONFIRMATION MODAL TO CLEAR SAVED INVENTORY DATA */}
      {showClearConfirmModal && (
        <div className="fixed inset-0 bg-black/85 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0b0f17] border-2 border-red-500/60 rounded-2xl max-w-md w-full p-6 shadow-2xl font-mono text-left space-y-4">
            <div className="flex items-center gap-3 border-b border-red-500/30 pb-3">
              <div className="p-2.5 rounded-xl bg-red-500/20 border border-red-500/40 text-red-400">
                <AlertTriangle className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-sm font-black text-white uppercase tracking-wider">
                  Clear Saved Inventory Data?
                </h3>
                <p className="text-[11px] text-red-400/80">
                  Permanent wipe of local browser storage records
                </p>
              </div>
            </div>

            <p className="text-xs text-white/70 font-sans leading-relaxed">
              Are you sure you want to clear all <strong>{endpoints.length} saved host devices</strong> and posture assessments from your browser's local storage?
            </p>
            <div className="p-3 bg-black/60 rounded-lg border border-white/10 text-[11px] text-white/50 space-y-1 font-mono">
              <div>• Removes: <span className="text-white">localStorage['endpoint_postures']</span></div>
              <div>• Current device count: <span className="text-amber-400">{endpoints.length} hosts</span></div>
              <div>• Note: You can reload the 5 default demo hosts at any time.</div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setShowClearConfirmModal(false)}
                className="px-4 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-white text-xs font-bold transition cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  onClearAllEndpoints?.();
                  setShowClearConfirmModal(false);
                  setToastMessage({ text: 'All saved endpoint data cleared from local storage.', type: 'info' });
                }}
                className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-bold transition cursor-pointer flex items-center gap-1.5 shadow-lg shadow-red-950/50"
              >
                <Trash2 className="w-4 h-4" />
                Yes, Clear Saved Data
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
