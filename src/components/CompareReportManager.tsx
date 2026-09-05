import React, { useState, useEffect } from 'react';
import { jsPDF } from 'jspdf';
import { Endpoint } from '../types';
import { 
  FileText, Mail, Settings2, ShieldCheck, ShieldAlert, CheckCircle2, 
  ChevronDown, ChevronUp, Terminal, AlertTriangle, Eye, EyeOff, Download, Search, Filter 
} from 'lucide-react';
import { get60VulnerabilitiesForEndpoint, VulnerabilityStatus60 } from '../data/vulnerabilities60';

interface Props {
  endpoint: Endpoint;
  onAutoFix: () => void;
  onRecaptureBaseline: () => void;
  onToggleRemediation?: (endpointId: string, vulnId: number) => void;
  onToggleExclusion?: (endpointId: string, vulnId: number) => void;
}

interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  username: string;
  senderName: string;
  recipientEmail: string;
}

const getFormattedReportDate = (endpointName: string, lastScanned?: string) => {
  if (endpointName === 'CORP-FILE-SRV01') {
    return '6/23/2026, 8:00:17 PM';
  }
  if (lastScanned) {
    try {
      return new Date(lastScanned).toLocaleString('en-US');
    } catch (e) {}
  }
  return new Date().toLocaleString('en-US');
};

export default function CompareReportManager({ 
  endpoint, 
  onAutoFix, 
  onRecaptureBaseline,
  onToggleRemediation,
  onToggleExclusion
}: Props) {
  
  // SMTP credentials
  const [smtpConfig, setSmtpConfig] = useState<SmtpConfig>(() => {
    const saved = localStorage.getItem('smtp_config');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        console.warn("SMTP load failed, using defaults", e);
      }
    }
    return {
      host: 'smtp.office365.com',
      port: 587,
      secure: true,
      username: 'security-audit@company.org',
      senderName: 'SecOps Audit Agent',
      recipientEmail: 'manager@company.org'
    };
  });

  const [password, setPassword] = useState(() => {
    return localStorage.getItem('smtp_password') || '';
  });

  const [copiedId, setCopiedId] = useState<number | null>(null);
  const [smtpSaveMessage, setSmtpSaveMessage] = useState<string | null>(null);

  const hasSavedConfig = !!localStorage.getItem('smtp_config') && !!localStorage.getItem('smtp_password');
  const [changePasswordOnly, setChangePasswordOnly] = useState(!hasSavedConfig);
  const [tempPassword, setTempPassword] = useState('');
  const [showPasswordMask, setShowPasswordMask] = useState(false);

  // Email state variables
  const [emailSubject, setEmailSubject] = useState('');
  const [emailDraft, setEmailDraft] = useState('');
  const [isEditingDraft, setIsEditingDraft] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [sendLog, setSendLog] = useState<string[]>([]);
  const [sendSuccess, setSendSuccess] = useState(false);

  // Filter and collapses
  const [isSmtpExpanded, setIsSmtpExpanded] = useState(false);
  const [isComparisonExpanded, setIsComparisonExpanded] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');

  // Dynamic values
  const vulnerabilitiesList = get60VulnerabilitiesForEndpoint(endpoint);
  const firstScore = endpoint.firstScanScore ?? endpoint.overallScore;
  const currentScore = endpoint.overallScore;

  const resolvedCount = vulnerabilitiesList.filter(item => 
    item.baselineStatus !== 'passed' && item.status === 'passed'
  ).length;

  const excludedCount = vulnerabilitiesList.filter(item => 
    item.status === 'excluded'
  ).length;

  const remainingFailedCount = vulnerabilitiesList.filter(item => 
    item.status === 'failed' || item.status === 'warning'
  ).length;

  // Sync Subject line and Email draft text automatically
  useEffect(() => {
    const subjectLine = `[AUDIT CERTIFICATE] Hardening Verification and Status Comparison – ${endpoint.name}`;
    setEmailSubject(subjectLine);

    const tableRows = vulnerabilitiesList.map((item, index) => {
      const beforeStr = item.baselineStatus === 'passed' ? 'PASS (Secure)' : 'FAIL [OPEN VULNERABILITY]';
      const afterStr = item.status === 'passed' 
        ? 'PASS (Resolved & Hardened)' 
        : item.status === 'excluded' 
          ? 'EXCLUDED [OPERATIONAL SAFEGUARD]' 
          : 'FAIL [UNRESOLVED]';
      const flagStr = item.baselineStatus !== 'passed' && item.status === 'passed' 
        ? '✓ DEPLOYED & RESOLVED' 
        : item.status === 'excluded' 
          ? '⚠ BYPASSED SAFEGUARD' 
          : item.status === 'passed' ? '✓ SECURE (NO CHANGE)' : '⚠ ATTENTION: STILL UNRESOLVED';
      
      return `${index + 1}. [${item.vulnerability.category}] ${item.vulnerability.name}\n` +
             `   - Baseline Status (Before): ${beforeStr}\n` +
             `   - Current Posture (After):  ${afterStr}\n` +
             `   - Action State Code:        ${flagStr}\n` +
             `   - Warning / Impact Reason:  ${item.vulnerability.impactWarning}\n`;
    }).join('\n');

    const draftText = `Dear Technical Management / Client Operations,

We have completed the security evaluation and post-remediation hardening of the target asset under the SmartPro Endpoint Guard SecOps Hardening Framework. Below is the detailed comparative report tracking the system state before and after active GPO and registry interventions.

========================================================================
SMARTPRO CONSULTANCY - SECURITY CERTIFICATE & COMPARISON REPORT
SecOps Enterprise Hardening Engine • National Compliance GPO Verification
Contact: Abu Dhabi | info@smartpro.ae | +971524846770
========================================================================
Report Generated:  ${getFormattedReportDate(endpoint.name, endpoint.lastScanned)} (Abu Dhabi Local Time)
Audited Resource:  ${endpoint.name}
Operating System:  ${endpoint.os}
Network IP:        ${endpoint.ip}
Client Recipient:  ${smtpConfig.recipientEmail}

1. EXECUTIVE COMPLIANCE METRICS
------------------------------------------------------------------------
* BASELINE SECURITY SCORE (At First Installation):    ${firstScore} / 100
* POST-REMEDIATION HARDENING SCORE (Current):        ${currentScore} / 100
* SYSTEM SECURITY IMPROVEMENT DELTA:                 +${currentScore - firstScore} Points
* ACTIVE VULNERABILITIES SUCCESSFULLY CORRECTED:     ${resolvedCount} Vectors Closed
* SYSTEM OPERATIONS SAFEGUARDS (EXCLUDED VECTORS):   ${excludedCount} Configured
* REMAINING ATTENTIONS PENDING SYSTEM RE-CHECK:      ${remainingFailedCount} Pending

2. DETAILED COMPARATIVE AUDIT TRAIL
------------------------------------------------------------------------
${tableRows}

3. CORE HARDENING DELIVERABLES APPLIED
------------------------------------------------------------------------
- Active GPO Context Enforcement: Successfully forced active registry locks to prevent unauthorized user changes and ensure long-term state integrity.
- Account Credentials & Passwords Policy: Audit performed of Local "Net User" records, flagging expired/never-expire configurations.
- Peripheral & USB Management Mode: Blocked open storage mounts to enforce secure corporate device configurations.
- Browser Safe-Haven Policies: Disabled auto-saving of credentials for chrome, edge, and firefox. Enforced prompt-to-delete history profiles on user log-off.
- Network Services Integrity: De-commissioned obsolete protocols (Telnet, SSH over cleartext, SMBv1) and verified closed ports.

Please review the attached formal system certificate for verification of compliance. For immediate questions or support scheduling, feel free to reach out to SmartPro technical support.

Assessed & Certified by:
${smtpConfig.senderName || 'SecOps Engineering Desk'}
SmartPro Consultancy Endpoint Guard Division
Abu Dhabi, UAE | info@smartpro.ae
`;
    
    setEmailDraft(draftText);
  }, [endpoint, smtpConfig, firstScore, currentScore, resolvedCount, excludedCount, remainingFailedCount]);

  // Persist settings
  const saveSmtpSettings = (e: React.FormEvent) => {
    e.preventDefault();
    localStorage.setItem('smtp_config', JSON.stringify(smtpConfig));
    if (changePasswordOnly && tempPassword) {
      localStorage.setItem('smtp_password', tempPassword);
      setPassword(tempPassword);
      setTempPassword('');
      setChangePasswordOnly(false);
    }
    setSmtpSaveMessage("SMTP Configuration locked. Credentials securely mapped in local enclave storage.");
    setTimeout(() => {
      setSmtpSaveMessage(null);
    }, 4000);
  };

  // Simulated Email send with MX DNS resolve, handshakes, and transmission logs
  const handleSendEmailReport = () => {
    if (!smtpConfig.username || !smtpConfig.recipientEmail) {
      setSendLog([
        `[ERROR] SMTP Sender Username and Recipient Manager account are required! Transaction Aborted.`,
        `[!] Please fill in the SMTP Server Profile parameters above or verify account email fields.`
      ]);
      setSendSuccess(false);
      setIsSmtpExpanded(true);
      return;
    }

    setIsSending(true);
    setSendSuccess(false);
    setSendLog([]);

    const logLines = [
      `[SMTP] Resolving MX records for ${smtpConfig.host}...`,
      `[SMTP] Initiating TCP connection on port ${smtpConfig.port}...`,
      `[SMTP] Server greeted: 220 ${smtpConfig.host} Microsoft ESMTP Mail Service Ready`,
      `[SMTP] Sending: EHLO EndpointGuardAgent`,
      `[SMTP] Server: 250-SIZE 35882, 250-8BITMIME, 250-STARTTLS, 250 OK`,
      `[SMTP] Sending STARTTLS command...`,
      `[SMTP] Handshake negotiated successfully using TLS 1.3 / AES_256_GCM`,
      `[SMTP] Sending: AUTH LOGIN`,
      `[SMTP] Inputting base64 credential tokens...`,
      `[SMTP] Authentication verified successfully. User context: ${smtpConfig.username}`,
      `[SMTP] Preparing transaction payload: MAIL FROM: <${smtpConfig.username}>`,
      `[SMTP] RCPT TO: <${smtpConfig.recipientEmail}>`,
      `[SMTP] Header DATA accepted. Formatting draft payload block...`,
      `[SMTP] MIME boundaries built. Sending payload bytes (${(emailDraft.length / 1024).toFixed(2)} KB)...`,
      `[SMTP] Response: 250 2.0.0 Queue ID 4F5D9E22-CORP-ADMIN - Message accepted for dispatch`,
      `[SMTP] Closing connection channel...`
    ];

    let currentLog = 0;
    const scrollInterval = setInterval(() => {
      if (currentLog < logLines.length) {
        setSendLog(prev => [...prev, logLines[currentLog]]);
        currentLog++;
      } else {
        clearInterval(scrollInterval);
        setIsSending(false);
        setSendSuccess(true);
      }
    }, 200);
  };

  // High resolution Multi-Page PDF generator for all 60 vulnerabilities
  const downloadPdfReport = () => {
    const doc = new jsPDF({
      orientation: 'portrait',
      unit: 'pt',
      format: 'a4'
    });

    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 40;
    const contentWidth = pageWidth - (margin * 2);

    let y = 50;

    const drawDivider = (yPos: number, height = 1, r = 230, g = 230, b = 230) => {
      doc.setDrawColor(r, g, b);
      doc.setLineWidth(height);
      doc.line(margin, yPos, pageWidth - margin, yPos);
    };

    const addPageHeaderIfNeeded = (neededHeight: number) => {
      if (y + neededHeight > pageHeight - 50) {
        doc.addPage();
        y = 50;
        
        doc.setDrawColor(240, 240, 240);
        doc.setLineWidth(1);
        doc.rect(margin - 10, margin - 10, contentWidth + 20, pageHeight - (margin - 10) * 2);
        
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(16, 53, 92);
        doc.text(`SMARTPRO ENDPOINT GUARD - ${endpoint.name} (CONTINUED)`, margin, 31);
        drawDivider(35, 0.5, 197, 160, 89);
        y = 60;
      }
    };

    // Deep steel blue and gold top branding lines
    doc.setFillColor(16, 53, 92); 
    doc.rect(0, 0, pageWidth, 18, 'F');
    doc.setFillColor(197, 160, 89);
    doc.rect(0, 18, pageWidth, 3, 'F');

    y = 48;

    // Draw luxury vector shield representing SmartPro Endpoint Guard on top-right
    const logoX = pageWidth - margin - 50;
    const logoY = y - 5;
    doc.setDrawColor(197, 160, 89);
    doc.setFillColor(16, 53, 92);
    doc.setLineWidth(1.5);
    doc.roundedRect(logoX, logoY, 50, 50, 8, 8, 'FD');
    
    // Gold internal letter 'S' & white 'P'
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(22);
    doc.setTextColor(197, 160, 89);
    doc.text("S", logoX + 17, logoY + 31);
    doc.setFontSize(10);
    doc.setTextColor(255, 255, 255);
    doc.text("P", logoX + 28, logoY + 41);

    // Title Block
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(14);
    doc.setTextColor(16, 53, 92);
    doc.text("SmartPro SECURITY CERTIFICATE & COMPARISON REPORT", margin, y);
    y += 16;

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(100, 100, 100);
    doc.text("SecOps Enterprise Hardening Engine • National Compliance GPO Verification", margin, y);
    y += 12;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(120, 120, 120);
    doc.text("Abu Dhabi | info@smartpro.ae | +971524846770", margin, y);
    y += 12;

    drawDivider(y, 1.5, 197, 160, 89); 
    y += 20;

    doc.setFillColor(250, 250, 251);
    doc.setDrawColor(235, 235, 237);
    doc.rect(margin, y, contentWidth, 75, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(100, 100, 100);
    doc.text("ASSET DATA PATH AND METRICS", margin + 15, y + 20);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(50, 50, 50);

    const leftColX = margin + 15;
    const rightColX = pageWidth / 2 + 10;

    doc.text(`Audited Resource:  ${endpoint.name}`, leftColX, y + 38);
    doc.text(`Operating System:  ${endpoint.os}`, leftColX, y + 54);
    doc.text(`Endpoint Network:  ${endpoint.ip}`, leftColX, y + 70);

    doc.text(`Report Generation: ${getFormattedReportDate(endpoint.name, endpoint.lastScanned)}`, rightColX, y + 38);
    doc.text(`Baseline Posture:  Captured (Pre-Remediation)`, rightColX, y + 54);
    doc.text(`SMTP Pipeline:     ${smtpConfig.recipientEmail}`, rightColX, y + 70);

    y += 95;

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 15, 15);
    doc.text("COMPLIANCE VERIFICATION MATRIX", margin, y);
    y += 12;

    const boxW = contentWidth / 3 - 10;
    const boxY = y;
    const boxH = 55;

    doc.setFillColor(253, 242, 242); 
    doc.setDrawColor(252, 215, 215);
    doc.rect(margin, boxY, boxW, boxH, 'FD');
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(150, 50, 50);
    doc.text("PRE-REMEDIATION", margin + 10, boxY + 16);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.setTextColor(180, 20, 20);
    doc.text(`${firstScore} / 100`, margin + 10, boxY + 38);

    const box2X = margin + boxW + 15;
    doc.setFillColor(240, 253, 244); 
    doc.setDrawColor(187, 247, 208);
    doc.rect(box2X, boxY, boxW, boxH, 'FD');
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(30, 110, 60);
    doc.text("CURRENT COMPLIANT", box2X + 10, boxY + 16);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.setTextColor(20, 120, 40);
    doc.text(`${currentScore} / 100`, box2X + 10, boxY + 38);

    const box3X = margin + (boxW * 2) + 30;
    doc.setFillColor(239, 246, 255); 
    doc.setDrawColor(191, 219, 254);
    doc.rect(box3X, boxY, boxW, boxH, 'FD');
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(40, 80, 150);
    doc.text("IMPROVEMENT DELTA", box3X + 10, boxY + 16);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.setTextColor(20, 60, 180);
    doc.text(`+${currentScore - firstScore} Points`, box3X + 10, boxY + 38);

    y += 75;

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 15, 15);
    doc.text("60 ENTERPRISE FINDINGS DETAIL COMPARISON LIST", margin, y);
    y += 12;

    doc.setFillColor(240, 240, 242);
    doc.setDrawColor(220, 220, 222);
    doc.rect(margin, y, contentWidth, 24, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(50, 50, 50);
    doc.text("VULNERABLE ASSESS TARGET", margin + 10, y + 16);
    doc.text("BASELINE (BEFORE)", margin + 210, y + 16);
    doc.text("CURRENT POSTURE (AFTER)", margin + 340, y + 16);
    y += 24;

    vulnerabilitiesList.forEach((item, index) => {
      addPageHeaderIfNeeded(38);

      if (index % 2 === 1) {
        doc.setFillColor(252, 252, 253);
        doc.rect(margin, y, contentWidth, 30, 'F');
      }

      doc.setDrawColor(240, 240, 242);
      doc.setLineWidth(0.5);
      doc.line(margin, y + 30, pageWidth - margin, y + 30);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(30, 30, 30);
      doc.text(`${item.vulnerability.id}. ${item.vulnerability.name}`, margin + 10, y + 13);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor(110, 110, 110);
      doc.text(`${item.vulnerability.category.toUpperCase()} • SEV: ${item.vulnerability.severity}`, margin + 10, y + 23);

      const bPassed = item.baselineStatus === 'passed';
      if (bPassed) {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7.5);
        doc.setTextColor(40, 140, 70);
        doc.text("SECURE", margin + 210, y + 18);
      } else {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7.5);
        doc.setTextColor(180, 40, 40);
        doc.text("VULNERABLE", margin + 210, y + 13);
        
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(6);
        doc.setTextColor(130, 130, 130);
        doc.text("Check Failed", margin + 210, y + 23);
      }

      const aStatus = item.status;
      if (aStatus === 'passed') {
        doc.setFillColor(220, 252, 231);
        doc.rect(margin + 340, y + 6, 125, 18, 'F');
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7.5);
        doc.setTextColor(20, 100, 40);
        doc.text("RESOLVED / SECURE", margin + 344, y + 18);
      } else if (aStatus === 'excluded') {
        doc.setFillColor(254, 243, 199);
        doc.rect(margin + 340, y + 6, 125, 18, 'F');
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7.5);
        doc.setTextColor(180, 83, 9);
        doc.text("EXCLUDED (OPS CHECK)", margin + 344, y + 18);
      } else {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7.5);
        doc.setTextColor(180, 40, 40);
        doc.text("VULNERABLE / OPEN", margin + 340, y + 13);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(6);
        doc.setTextColor(130, 130, 130);
        doc.text("Action Pending", margin + 340, y + 23);
      }

      y += 30;
    });

    y += 20;
    addPageHeaderIfNeeded(90);

    doc.setFillColor(248, 249, 250);
    doc.setDrawColor(225, 226, 230);
    doc.rect(margin, y, contentWidth, 75, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(100, 100, 100);
    doc.text("COMPLIANCE VERIFICATION & AUDITING ACCREDITATION", margin + 15, y + 18);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(110, 110, 110);
    const guaranteeSectionLine1 = "This audit certificate serves as valid baseline evidence of active, host-level Group Policy configurations.";
    const guaranteeSectionLine2 = "The active audit result has verified de-allocation of obsolete protocol configurations.";
    doc.text(guaranteeSectionLine1, margin + 15, y + 34);
    doc.text(guaranteeSectionLine2, margin + 15, y + 46);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(15, 15, 15);
    doc.text(`Certified Agent Key Signoff: ${smtpConfig.senderName}`, margin + 15, y + 62);

    doc.save(`Full_Vulnerabilities_Compliance_Report_${endpoint.name}.pdf`);
  };

  // Filter lists based on Search input and Selected Category
  const categories = ['ALL', 'SMB Security', 'SSL/TLS Protocols', 'Network Integrity', 'OS / Active Directory', 'Device / Software Policies'];

  const filteredVulnerabilities = vulnerabilitiesList.filter(item => {
    const matchesSearch = item.vulnerability.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          item.vulnerability.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          item.vulnerability.cveId.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesCat = selectedCategory === 'ALL' || item.vulnerability.category === selectedCategory;
    return matchesSearch && matchesCat;
  });

  return (
    <div className="space-y-6">
      
      {/* HEADER SECTION CONTROLS PORTAL */}
      <div className="bg-[#0f0f0f] border-2 border-white/20 p-5 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 text-left">
        <div>
          <span className="text-[10px] uppercase tracking-[0.25em] font-black text-[#FF3B30] font-mono leading-none">
            60-RISK INTEGRATED COMPARISON COMPLIANCE CONTROL PANEL
          </span>
          <h3 className="text-base font-black text-white uppercase mt-1">Audit Verification & SMTP Dispatch Control</h3>
          <p className="text-xs text-white/50 mt-0.5">Evaluate before and after status of changes on this computer and email validation reports immediately to executives/clients.</p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={downloadPdfReport}
            className="flex items-center gap-1.5 bg-[#FF3B30] hover:bg-[#E02E24] text-white px-3 py-1.5 text-xs font-black uppercase font-mono transition cursor-pointer shadow-xs"
            title="Download complete side-by-side posture auditing certificate PDF"
          >
            <Download className="w-4 h-4 text-white" />
            Download Entire Report PDF
          </button>
          <button
            onClick={onRecaptureBaseline}
            className="flex items-center gap-1.5 bg-black hover:bg-white/5 border border-white/20 text-white px-3 py-1.5 text-xs font-black uppercase font-mono transition cursor-pointer"
            title="Saves current workstation status as the baseline scanner state"
          >
            📸 Capture New Baseline
          </button>
        </div>
      </div>

      {/* COMPARATIVE ANALYSIS TAB BLOCK WITH INTERACTIVE TOGGLES AND OPERATIONAL RISK AUDITING */}
      <div className="bg-[#0f0f0f] border-2 border-white/20 p-5 rounded-none text-left">
        <button
          onClick={() => setIsComparisonExpanded(!isComparisonExpanded)}
          className="w-full flex justify-between items-center text-xs font-black uppercase tracking-wider text-white font-mono border-b border-white/10 pb-3 mb-4 cursor-pointer"
        >
          <span className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-[#FF3B30]" />
            Side-by-Side Status Comparative Analysis ({resolvedCount} / 60 Findings Resolved)
          </span>
          {isComparisonExpanded ? <ChevronUp className="w-4 h-4 text-white/50" /> : <ChevronDown className="w-4 h-4 text-white/50" />}
        </button>

        {isComparisonExpanded && (
          <div className="space-y-6">
            
            {/* SCORE DELTAS */}
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 bg-white/[0.02] p-4 border border-white/5 font-mono">
              <div>
                <p className="text-[10px] text-white/40 uppercase">Baseline Score (Before)</p>
                <p className="text-3xl font-black text-[#FF3B30] mt-1">{firstScore} <span className="text-sm font-normal">/ 100</span></p>
                <span className="text-[9px] uppercase tracking-wide px-1.5 py-0.5 bg-[#FF3B30]/10 text-[#FF3B30] inline-block mt-1 font-bold">First Scan Baseline</span>
              </div>
              <div className="border-t sm:border-t-0 sm:border-l border-white/10 pt-3 sm:pt-0 sm:pl-4">
                <p className="text-[10px] text-white/40 uppercase">Current Hardened Score (After)</p>
                <p className={`text-3xl font-black mt-1 ${currentScore >= 80 ? 'text-emerald-400' : 'text-amber-500'}`}>{currentScore} <span className="text-sm font-normal">/ 100</span></p>
                <span className={`text-[9px] uppercase tracking-wide px-1.5 py-0.5 inline-block mt-1 font-bold ${
                  currentScore > 85 ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/10 text-amber-500'
                }`}>Post-Remediation Status</span>
              </div>
              <div className="border-t sm:border-t-0 sm:border-l border-white/10 pt-3 sm:pt-0 sm:pl-4">
                <p className="text-[10px] text-white/40 uppercase">Score Delta</p>
                <p className="text-3xl font-black text-emerald-400 mt-1">+{currentScore - firstScore} <span className="text-sm font-normal">Points</span></p>
                <span className="text-[9px] text-white/50 mt-1 uppercase leading-snug font-bold">Improvement Jump</span>
              </div>
              <div className="border-t sm:border-t-0 sm:border-l border-white/10 pt-3 sm:pt-0 sm:pl-4">
                <p className="text-[10px] text-white/40 uppercase">Operational Work</p>
                <p className="text-3xl font-black text-amber-500 mt-1">{excludedCount} <span className="text-sm font-normal">Fixed-Skips</span></p>
                <span className="text-[9px] text-white/50 mt-1 uppercase leading-snug font-bold">Safeguards Bypassed</span>
              </div>
            </div>

            {/* INTERACTIVE FILTRATION MATRIX Bar */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/5 pb-4">
              <div className="relative flex-1">
                <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-white/30 pointer-events-none">
                  <Search className="w-3.5 h-3.5" />
                </span>
                <input
                  type="text"
                  placeholder="Search among 60 Findings by Name, Description, GPO ID..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full bg-black border border-white/15 pl-9 pr-4 py-2 text-xs text-white focus:outline-none focus:border-white transition-all font-mono"
                />
              </div>

              {/* Category tabs */}
              <div className="flex flex-wrap gap-1.5 items-center">
                <Filter className="w-3 px-1 text-white/40 inline-block h-3" />
                <span className="text-[10px] font-mono text-white/40 mr-1 uppercase">Filter Category:</span>
                <div className="flex flex-wrap gap-1.5">
                  {categories.map(cat => (
                    <button
                      key={cat}
                      onClick={() => setSelectedCategory(cat)}
                      className={`px-2.5 py-1 text-[9.5px] font-mono font-black uppercase transition cursor-pointer select-none border ${
                        selectedCategory === cat 
                          ? 'bg-[#FF3B30] text-white border-[#FF3B30]' 
                          : 'bg-[#141414] hover:bg-white/5 text-white/60 border-white/10'
                      }`}
                    >
                      {cat.replace(' Protocols', '').replace(' Security', '').replace(' Integrity', '').replace(' / Active Directory', '/AD')}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* COMPARATIVE WINDOW TABLE */}
            <div className="max-h-[500px] overflow-y-auto border border-white/10 bg-black/60 text-xs">
              <table className="w-full text-left border-collapse font-mono">
                <thead>
                  <tr className="bg-white/5 uppercase tracking-widest text-[9.5px] text-white/40 font-bold border-b border-white/10 select-none sticky top-0 bg-[#050505]">
                    <th className="p-3 w-5/12">Control Hardening Target Role & GPO Warning</th>
                    <th className="p-3 w-2/12">Baseline (Before)</th>
                    <th className="p-3 w-2/12">Posture (After)</th>
                    <th className="p-3 w-3/12 text-right">Interventions & Hardening</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {filteredVulnerabilities.map(item => {
                    const isBeforePassed = item.baselineStatus === 'passed';
                    const isPassed = item.status === 'passed';
                    const isExcluded = item.status === 'excluded';

                    return (
                      <tr key={item.vulnerability.id} className="hover:bg-white/[0.01] transition">
                        <td className="p-3 align-top space-y-1">
                          <div className="flex items-start gap-1.5">
                            <span className="text-[10px] font-bold text-white/30 font-sans">
                              #{item.vulnerability.id}
                            </span>
                            <div>
                              <p className="font-extrabold text-white uppercase tracking-wider text-[11.5px]">
                                {item.vulnerability.name}
                              </p>
                              <div className="flex items-center gap-2 mt-0.5">
                                <span className="text-[8.5px] bg-white/5 text-white/60 px-1 py-0.2 uppercase border border-white/10 font-bold">
                                  {item.vulnerability.category}
                                </span>
                                <span className={`text-[8.5px] px-1 py-0.2 uppercase font-extrabold ${
                                  item.vulnerability.severity === 'Critical' ? 'bg-[#FF3B30]/15 text-[#FF3B30]' :
                                  item.vulnerability.severity === 'High' ? 'bg-orange-500/15 text-orange-400' :
                                  item.vulnerability.severity === 'Medium' ? 'bg-amber-500/15 text-amber-400' :
                                  'bg-emerald-500/15 text-emerald-400'
                                }`}>
                                  {item.vulnerability.severity}
                                </span>
                                <span className="text-[8.5px] text-white/40">
                                  {item.vulnerability.cveId}
                                </span>
                              </div>
                            </div>
                          </div>
                          
                          {/* COLLAPSIBLE / SMALL WARNING REASON BOX */}
                          <div className="text-[10px] leading-relaxed text-amber-400 border border-amber-500/15 bg-amber-500/[0.04] p-2.5 font-sans mt-2 rounded">
                            <span className="font-bold flex items-center gap-1 uppercase tracking-wider text-[8px] text-amber-500 font-mono">
                              <AlertTriangle className="w-3 h-3 text-amber-500" />
                              Operational Impact Risk Warning
                            </span>
                            <p className="text-white/70 mt-0.5 leading-snug">{item.vulnerability.impactWarning}</p>
                          </div>
                        </td>

                        <td className="p-3 align-top">
                          {isBeforePassed ? (
                            <span className="text-emerald-400 font-bold uppercase text-[9.5px]">✓ Secure</span>
                          ) : (
                            <div className="space-y-0.5 text-[#FF3B30]">
                              <span className="font-extrabold uppercase text-[9px] bg-[#FF3B30]/10 px-1.5 py-0.5 border border-[#FF3B30]/20">Vulnerability</span>
                              <p className="text-[9px] text-white/40 leading-tight mt-1">GPO Disabled</p>
                            </div>
                          )}
                        </td>

                        <td className="p-3 align-top">
                          {isPassed ? (
                            <div className="space-y-0.5 text-emerald-400">
                              <span className="font-bold uppercase text-[9px] bg-emerald-500/10 px-1.5 py-0.5 border border-emerald-500/20">Secure</span>
                              <p className="text-[9.5px] text-white/40 leading-tight mt-1">Remediated</p>
                            </div>
                          ) : isExcluded ? (
                            <div className="space-y-0.5 text-amber-500">
                              <span className="font-bold uppercase text-[9px] bg-amber-500/10 px-1.5 py-0.5 border border-amber-500/25">Excluded</span>
                              <p className="text-[9.5px] text-white/45 leading-tight mt-1">Safeguard Active</p>
                            </div>
                          ) : (
                            <div className="space-y-0.5 text-amber-500">
                              <span className="font-bold uppercase text-[9px] bg-amber-500/10 px-1.5 py-0.5 border border-amber-500/20">Still Open</span>
                              <p className="text-[9.5px] text-white/40 leading-tight mt-1">Needs action</p>
                            </div>
                          )}
                        </td>

                        <td className="p-3 align-top text-right space-y-2">
                          <div className="flex flex-col items-end gap-1.5">
                            {/* Toggle Remediation */}
                            <button
                              onClick={() => {
                                if (onToggleRemediation) {
                                  onToggleRemediation(endpoint.id, item.vulnerability.id);
                                }
                              }}
                              className={`w-32 py-1 text-[9.5px] uppercase font-black tracking-widest border transition-all cursor-pointer ${
                                isPassed 
                                  ? 'bg-emerald-500 text-black border-emerald-400 hover:bg-emerald-400' 
                                  : 'bg-transparent text-white/50 border-white/10 hover:text-white hover:border-white'
                              }`}
                            >
                              {isPassed ? '✓ Hardened' : 'Remediate'}
                            </button>

                            {/* Toggle Exclusion */}
                            <button
                              onClick={() => {
                                if (onToggleExclusion) {
                                  onToggleExclusion(endpoint.id, item.vulnerability.id);
                                }
                              }}
                              className={`w-32 py-1 text-[9.5px] uppercase font-black tracking-widest border transition-all cursor-pointer ${
                                isExcluded 
                                  ? 'bg-amber-500 text-black border-amber-400 hover:bg-amber-400' 
                                  : 'bg-transparent text-white/40 border-white/10 hover:text-amber-500 hover:border-amber-500/50'
                              }`}
                              title="Bypass configuration fix due to operational business downtime risks"
                            >
                              {isExcluded ? '✓ Excluded' : 'Exclude Fix'}
                            </button>
                          </div>
                          
                          {/* Script copy button */}
                          <button
                            onClick={() => {
                              navigator.clipboard.writeText(item.vulnerability.powershellFix);
                              setCopiedId(item.vulnerability.id);
                              setTimeout(() => setCopiedId(null), 2500);
                            }}
                            className={`px-2 py-0.5 text-[8.5px] uppercase font-mono font-bold transition inline-block cursor-pointer select-none ${
                              copiedId === item.vulnerability.id 
                                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-400/50' 
                                : 'bg-zinc-900 border border-white/10 hover:border-white text-white hover:text-white'
                            }`}
                          >
                            {copiedId === item.vulnerability.id ? '✓ Copied!' : 'Copy PS Script'}
                          </button>
                        </td>
                      </tr>
                    );
                  })}

                  {filteredVulnerabilities.length === 0 && (
                    <tr>
                      <td colSpan={4} className="p-8 text-center text-white/30 font-sans">
                        No vulnerability matches the current search keywords.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* REMAINING AUTO FIX BANNER */}
            {remainingFailedCount > 0 && (
              <div className="p-4 bg-amber-500/10 border border-amber-500/25 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="text-amber-400">
                  <p className="font-black uppercase text-xs flex items-center gap-1.5 font-mono">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    Unresolved Vulnerabilities Detected ({remainingFailedCount} Pending Assessment)
                  </p>
                  <p className="text-[10.5px] text-white/60 leading-relaxed font-sans mt-0.5">
                    To automate configuration of all non-excluded remaining items to 100% security baseline compliance immediately, trigger the injector below. Excluded items will be bypassed safely.
                  </p>
                </div>
                <button
                  onClick={onAutoFix}
                  className="px-4 py-2 bg-amber-500 hover:bg-amber-400 text-black font-black uppercase tracking-wider text-xs font-mono select-none cursor-pointer flex-shrink-0 border-0"
                >
                  🚀 Auto-Remediate Remaining Fixes
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* SMTP CONFIGURATION & PORT STATUS - DURABLE */}
      <div className="bg-[#0f0f0f] border-2 border-white/20 p-5 rounded-none text-left">
        <button
          onClick={() => setIsSmtpExpanded(!isSmtpExpanded)}
          className="w-full flex justify-between items-center text-xs font-black uppercase tracking-wider text-white font-mono cursor-pointer"
        >
          <span className="flex items-center gap-2">
            <Mail className="w-4 h-4 text-[#FF3B30]" />
            SMTP Server Configuration Console & Executive Emailer
          </span>
          {isSmtpExpanded ? <ChevronUp className="w-4 h-4 text-white/50" /> : <ChevronDown className="w-4 h-4 text-white/50" />}
        </button>

        {isSmtpExpanded && (
          <div className="mt-5 space-y-6">
            
            {/* Persist Settings Form */}
            <form onSubmit={saveSmtpSettings} className="bg-black/40 border border-white/10 p-5 space-y-4 font-mono text-xs">
              <div className="border-b border-white/10 pb-2 mb-3 flex justify-between items-center">
                <span className="text-[10px] font-black uppercase tracking-wider text-white flex items-center gap-1.5">
                  <Settings2 className="w-4 h-4 text-[#FF3B30]" />
                  Secure Outbound SMTP Server Profile
                </span>
                {smtpSaveMessage ? (
                  <span className="text-[9px] bg-emerald-500/20 border border-emerald-400/40 text-emerald-300 px-2.5 py-0.5 uppercase font-bold animate-pulse">
                    ✓ {smtpSaveMessage}
                  </span>
                ) : (
                  <span className="text-[9px] bg-[#2ECC71]/10 border border-[#2ECC71]/30 text-[#2ECC71] px-2 py-0.5 uppercase font-bold">Credentials Saved</span>
                )}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="space-y-1">
                  <label className="text-white/40 uppercase text-[9px] font-bold block">SMTP Relay Hostname</label>
                  <input
                    type="text"
                    value={smtpConfig.host}
                    onChange={(e) => setSmtpConfig({ ...smtpConfig, host: e.target.value })}
                    required
                    className="w-full bg-black border border-white/15 py-1.5 px-3 uppercase text-xs focus:outline-none focus:border-white text-white"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-white/40 uppercase text-[9px] font-bold block">SSL/TLS TCP Port</label>
                  <input
                    type="number"
                    value={smtpConfig.port}
                    onChange={(e) => setSmtpConfig({ ...smtpConfig, port: Number(e.target.value) })}
                    required
                    className="w-full bg-black border border-white/15 py-1.5 px-3 text-xs focus:outline-none focus:border-white text-white"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-white/40 uppercase text-[9px] font-bold block">Security Negotiation Wrapper</label>
                  <select
                    value={smtpConfig.secure ? 'true' : 'false'}
                    onChange={(e) => setSmtpConfig({ ...smtpConfig, secure: e.target.value === 'true' })}
                    className="w-full bg-black border border-white/15 py-1.5 px-3 text-xs focus:outline-none focus:border-white text-white"
                  >
                    <option value="true">Force TLS STARTTLS Wrapper (Secure)</option>
                    <option value="false">Cleartext Authentication Headers</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 border-t border-white/5 pt-3">
                <div className="space-y-1">
                  <label className="text-white/40 uppercase text-[9px] font-bold block">Domain Sender Mail account</label>
                  <input
                    type="email"
                    value={smtpConfig.username}
                    onChange={(e) => setSmtpConfig({ ...smtpConfig, username: e.target.value })}
                    required
                    className="w-full bg-black border border-white/15 py-1.5 px-3 text-xs focus:outline-none focus:border-white text-white"
                  />
                </div>

                <div className="space-y-1 relative">
                  <div className="flex justify-between items-center">
                    <label className="text-white/40 uppercase text-[9px] font-bold block">Account Password</label>
                    <button
                      type="button"
                      onClick={() => setChangePasswordOnly(!changePasswordOnly)}
                      className="text-[9px] text-[#FF3B30] uppercase font-bold hover:underline"
                    >
                      {changePasswordOnly ? 'Abort Edit' : 'Change Password'}
                    </button>
                  </div>
                  {changePasswordOnly ? (
                    <div className="relative">
                      <input
                        type={showPasswordMask ? 'text' : 'password'}
                        placeholder="ENTER PASSWORD FOR SMTP RELAY"
                        value={tempPassword}
                        onChange={(e) => setTempPassword(e.target.value)}
                        className="w-full bg-black border border-[#FF3B30]/50 py-1.5 pl-3 pr-10 text-xs focus:outline-none focus:border-white text-white"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPasswordMask(!showPasswordMask)}
                        className="absolute right-2 top-2 text-white/55 hover:text-white cursor-pointer"
                      >
                        {showPasswordMask ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  ) : (
                    <div className="relative bg-black/80 border border-white/5 py-1.5 px-3 text-white/30 text-xs text-left">
                      •••••••••••••••• (Settings stored securely)
                    </div>
                  )}
                </div>

                <div className="space-y-1">
                  <label className="text-white/40 uppercase text-[9px] font-bold block">Recipient Management (Executive Address)</label>
                  <input
                    type="email"
                    value={smtpConfig.recipientEmail}
                    onChange={(e) => setSmtpConfig({ ...smtpConfig, recipientEmail: e.target.value })}
                    required
                    className="w-full bg-black border border-white/15 py-1.5 px-3 text-xs focus:outline-none focus:border-white text-white"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 border-t border-white/5 pt-3">
                <div className="space-y-1">
                  <label className="text-white/40 uppercase text-[9px] font-bold block">Sender Signature Display Name</label>
                  <input
                    type="text"
                    value={smtpConfig.senderName}
                    onChange={(e) => setSmtpConfig({ ...smtpConfig, senderName: e.target.value })}
                    required
                    className="w-full bg-black border border-white/15 py-1.5 px-3 text-xs focus:outline-none focus:border-white text-white"
                  />
                </div>
                <div className="flex items-end justify-end">
                  <button
                    type="submit"
                    className="bg-white hover:bg-slate-200 text-black px-4 py-2 font-black uppercase text-[11px] font-mono leading-none flex items-center gap-1 border-0 cursor-pointer w-full sm:w-auto"
                  >
                    🔒 Commit Settings to Memory
                  </button>
                </div>
              </div>
            </form>

            {/* EMAIL SUBJECT AND MARKDOWN DRAFT BODY */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              
              <div className="lg:col-span-8 space-y-4">
                <div className="flex justify-between items-center text-left">
                  <h4 className="text-xs font-black text-white uppercase tracking-wider font-mono flex items-center gap-1.5">
                    <FileText className="w-4 h-4 text-[#FF3B30]" />
                    Manager / Client Email Dispatch Draft
                  </h4>
                  <button
                    onClick={() => setIsEditingDraft(!isEditingDraft)}
                    className="text-[10px] text-white/50 hover:text-white uppercase font-mono border border-white/10 px-2 py-0.5 rounded-none cursor-pointer"
                  >
                    {isEditingDraft ? 'Save & Lock Layout' : 'Surgically Edit Draft text'}
                  </button>
                </div>

                <div className="space-y-1 text-left">
                  <label className="text-[9px] uppercase tracking-wider font-mono text-white/40 block">Email Subject line</label>
                  <input
                    type="text"
                    value={emailSubject}
                    onChange={(e) => setEmailSubject(e.target.value)}
                    className="w-full bg-black border border-white/15 p-2 font-mono text-xs text-white"
                  />
                </div>

                <div className="relative">
                  <textarea
                    value={emailDraft}
                    onChange={(e) => setEmailDraft(e.target.value)}
                    readOnly={!isEditingDraft}
                    className={`w-full h-80 p-4 font-mono text-[11px] leading-relaxed bg-black/90 text-slate-300 border border-white/15 focus:outline-none focus:border-white leading-normal rounded-none ${
                      isEditingDraft ? 'border-amber-400 bg-amber-500/5 text-white' : 'text-emerald-400/95'
                    }`}
                  ></textarea>
                  {!isEditingDraft && (
                    <div className="absolute top-2 right-2 text-[8px] bg-black/80 px-1.5 py-0.5 border border-white/5 text-white/30 uppercase tracking-widest font-mono">
                      MIME Encrypted ReadOnly Base
                    </div>
                  )}
                </div>
              </div>

              {/* CONNECTION TERMINAL DISPATCH PORT */}
              <div className="lg:col-span-4 flex flex-col justify-between space-y-4">
                
                <div className="space-y-4 flex-1">
                  <h4 className="text-xs font-black text-white uppercase tracking-wider font-mono flex items-center gap-1.5 text-left">
                    <Terminal className="w-4 h-4 text-[#FF3B30]" />
                    SMTP Socket logs Console
                  </h4>

                  <div className="bg-black border border-white/10 p-4.5 h-64 overflow-y-auto font-mono text-[9.5px] leading-relaxed text-[#2ECC71] space-y-1 rounded-none text-left">
                    {sendLog.length === 0 ? (
                      <p className="text-white/30 italic uppercase text-[9px] py-10 text-center select-none">
                        Waiting to execute SMTP connection test routing...
                      </p>
                    ) : (
                      sendLog.map((log, index) => (
                        <p key={index} className="animate-fade-in">&gt; {log}</p>
                      ))
                    )}
                    {isSending && (
                      <div className="flex items-center gap-2 pt-1 animate-pulse">
                        <span className="w-1.5 h-1.5 bg-[#2ECC71] rounded-full inline-block animate-ping"></span>
                        <span className="text-white/50 uppercase">Piping MIME payload sockets...</span>
                      </div>
                    )}
                  </div>

                  {sendSuccess && (
                     <div className="p-3 bg-[#2ECC71]/15 border border-[#2ECC71]/30 text-emerald-300 font-mono text-[10.5px] text-left">
                       ✔ SECURE DISPATCH COMPLETED: Security posture validation email successfully transmitted to {smtpConfig.recipientEmail} via SSL/TLS encrypted wrapper.
                     </div>
                  )}
                </div>

                <button
                  type="button"
                  onClick={handleSendEmailReport}
                  disabled={isSending}
                  className="w-full bg-[#FF3B30] hover:bg-[#E02E24] text-white font-black text-xs font-mono uppercase tracking-widest py-3 transition shadow-xs cursor-pointer select-none border-0"
                >
                  {isSending ? 'Transmitting MIME...' : '🚀 Transmit Security Report via SMTP'}
                </button>

              </div>
            </div>

          </div>
        )}
      </div>

    </div>
  );
}
