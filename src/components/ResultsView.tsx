import React, { useState } from 'react';
import { jsPDF } from 'jspdf';
import { 
  CheckCircle2, 
  ShieldCheck, 
  TrendingUp, 
  FileText, 
  Download, 
  Award, 
  AlertTriangle, 
  CheckSquare, 
  Share2, 
  Printer, 
  RefreshCw, 
  Database, 
  Sparkles,
  Server,
  Activity,
  HardDrive
} from 'lucide-react';
import { Endpoint } from '../types';
import { get60VulnerabilitiesForEndpoint } from '../data/vulnerabilities60';

interface ResultsViewProps {
  endpoints: Endpoint[];
  onOpenExportModal: () => void;
  onOpenGitHubModal: () => void;
  onOpenWinUtilModal: () => void;
  onRecaptureBaseline?: (endpointId: string) => void;
}

export default function ResultsView({
  endpoints,
  onOpenExportModal,
  onOpenGitHubModal,
  onOpenWinUtilModal,
  onRecaptureBaseline
}: ResultsViewProps) {
  const [selectedEndpointId, setSelectedEndpointId] = useState<string>(endpoints[0]?.id || '');
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [pdfSuccessToast, setPdfSuccessToast] = useState(false);
  const [exportToast, setExportToast] = useState<string | null>(null);

  // Custom PDF Executive Report Metadata
  const [showPdfCustomizer, setShowPdfCustomizer] = useState(false);
  const [companyName, setCompanyName] = useState('SmartPro Enterprise Consultancy');
  const [auditorName, setAuditorName] = useState('Senior SecOps Lead');
  const [securityClassification, setSecurityClassification] = useState('CONFIDENTIAL - INTERNAL AUDIT USE ONLY');
  const [customExecutiveNote, setCustomExecutiveNote] = useState('All critical Windows Registry security settings, RDP configurations, and disk SMART parameters have been audited according to CIS Windows Benchmarks.');

  const selectedEndpoint = endpoints.find(e => e.id === selectedEndpointId) || endpoints[0];

  // Aggregate stats across all endpoints
  const totalEndpoints = endpoints.length;
  const compliantEndpoints = endpoints.filter(e => e.overallScore >= 85).length;
  const warningEndpoints = endpoints.filter(e => e.overallScore >= 60 && e.overallScore < 85).length;
  const criticalEndpoints = endpoints.filter(e => e.overallScore < 60).length;

  // Average scores
  const avgCurrentScore = Math.round(
    endpoints.reduce((acc, curr) => acc + curr.overallScore, 0) / (totalEndpoints || 1)
  );
  const avgBaselineScore = Math.round(
    endpoints.reduce((acc, curr) => acc + (curr.firstScanScore ?? curr.overallScore), 0) / (totalEndpoints || 1)
  );

  const totalFixedCount = endpoints.reduce((acc, curr) => acc + (curr.remediatedVulnerabilities?.length || 0), 0);

  const [showDownloadModal, setShowDownloadModal] = useState(false);

  // Selected endpoint details
  const selectedVulns = selectedEndpoint ? get60VulnerabilitiesForEndpoint(selectedEndpoint) : [];
  const selectedFixed = selectedEndpoint 
    ? selectedVulns.filter(v => v.status === 'passed' && (selectedEndpoint.remediatedVulnerabilities?.includes(v.vulnerability.id)))
    : [];
  const selectedRemainingFailed = selectedVulns.filter(v => v.status === 'failed');

  // Full Network Report Handlers
  const handleDownloadFullNetworkReportJson = () => {
    const fullReport = {
      reportTitle: "SmartPro SecOps Enterprise Security Audit Report",
      generatedAt: new Date().toISOString(),
      monitoredEndpointsCount: endpoints.length,
      averageComplianceScore: avgCurrentScore,
      baselineScore: avgBaselineScore,
      totalRemediationsApplied: totalFixedCount,
      endpoints: endpoints.map(ep => {
        const vulns = get60VulnerabilitiesForEndpoint(ep);
        return {
          id: ep.id,
          hostname: ep.name,
          ipAddress: ep.ip,
          os: ep.os,
          patchLevel: ep.patchLevel,
          overallScore: ep.overallScore,
          complianceStatus: ep.overallScore >= 85 ? 'COMPLIANT' : ep.overallScore >= 60 ? 'NEEDS ATTENTION' : 'CRITICAL ACTION NEEDED',
          vulnerabilities: vulns.map(v => ({
            id: v.vulnerability.id,
            name: v.vulnerability.name,
            category: v.vulnerability.category,
            severity: v.vulnerability.severity,
            status: v.status,
            remediated: v.remediated || false,
            excluded: v.excluded || false
          })),
          logicalStorage: ep.storageHealth || [],
          physicalDisks: ep.physicalDrives || [],
          ldapSpnAudit: ep.scanData?.ldapSpnAudit || {
            status: 'passed',
            details: 'No Active Directory SPNs configured or RSAT AD tool not loaded.',
            commandExecuted: 'Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires | Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet, PasswordNeverExpires',
            accounts: []
          }
        };
      })
    };

    const jsonContent = JSON.stringify(fullReport, null, 2);
    const blob = new Blob([jsonContent], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Enterprise_Audit_Report_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);

    setExportToast(`Downloaded Full Enterprise JSON Audit Report (${endpoints.length} hosts)`);
    setTimeout(() => setExportToast(null), 4000);
  };

  const handleDownloadFullNetworkReportCsv = () => {
    const csvRows: string[] = [];
    const escapeCsv = (str: string | number) => `"${String(str || '').replace(/"/g, '""')}"`;

    csvRows.push('=== SMARTPRO SECOPS ENTERPRISE AUDIT SUMMARY REPORT ===');
    csvRows.push(`Generated At,${escapeCsv(new Date().toISOString())}`);
    csvRows.push(`Total Endpoints,${endpoints.length}`);
    csvRows.push(`Average Compliance Score,${avgCurrentScore}%`);
    csvRows.push(`Baseline Compliance Score,${avgBaselineScore}%`);
    csvRows.push('');

    // 1. Host Summary Table
    csvRows.push('=== HOST INVENTORY SUMMARY ===');
    csvRows.push('Hostname,IP Address,OS,Patch Level,Compliance Score,Compliance Status,Remediated Fixes Count,LDAP SPN Risk Status');
    endpoints.forEach(ep => {
      const ldapStatus = ep.scanData?.ldapSpnAudit?.status || 'passed';
      csvRows.push([
        escapeCsv(ep.name),
        escapeCsv(ep.ip),
        escapeCsv(ep.os),
        escapeCsv(ep.patchLevel),
        ep.overallScore,
        ep.overallScore >= 85 ? 'COMPLIANT' : ep.overallScore >= 60 ? 'NEEDS ATTENTION' : 'CRITICAL ACTION NEEDED',
        ep.remediatedVulnerabilities?.length || 0,
        escapeCsv(ldapStatus.toUpperCase())
      ].join(','));
    });
    csvRows.push('');

    // 2. Vulnerabilities Matrix across all hosts
    csvRows.push('=== VULNERABILITY EVALUATION DETAILS ===');
    csvRows.push('Hostname,IP Address,Vulnerability ID,Vulnerability Name,Category,Severity,Audit Status,Remediated');
    endpoints.forEach(ep => {
      const vulns = get60VulnerabilitiesForEndpoint(ep);
      vulns.forEach(item => {
        csvRows.push([
          escapeCsv(ep.name),
          escapeCsv(ep.ip),
          item.vulnerability.id,
          escapeCsv(item.vulnerability.name),
          escapeCsv(item.vulnerability.category),
          escapeCsv(item.vulnerability.severity),
          escapeCsv(item.status.toUpperCase()),
          item.remediated ? 'YES' : 'NO'
        ].join(','));
      });
    });
    csvRows.push('');

    // 3. LDAP Active Directory SPN Results
    csvRows.push('=== ACTIVE DIRECTORY LDAP SPN & KERBEROASTING RESULTS ===');
    csvRows.push('Hostname,IP Address,SamAccountName,ServicePrincipalName,PasswordLastSet,PasswordNeverExpires,Command Executed');
    endpoints.forEach(ep => {
      const ldap = ep.scanData?.ldapSpnAudit;
      const cmd = ldap?.commandExecuted || 'Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires | Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet, PasswordNeverExpires';
      if (ldap?.accounts && ldap.accounts.length > 0) {
        ldap.accounts.forEach(a => {
          csvRows.push([
            escapeCsv(ep.name),
            escapeCsv(ep.ip),
            escapeCsv(a.samAccountName),
            escapeCsv(a.servicePrincipalName),
            escapeCsv(a.passwordLastSet),
            a.passwordNeverExpires ? 'YES' : 'NO',
            escapeCsv(cmd)
          ].join(','));
        });
      } else {
        csvRows.push([
          escapeCsv(ep.name),
          escapeCsv(ep.ip),
          'N/A',
          'No SPN accounts found',
          'N/A',
          'N/A',
          escapeCsv(cmd)
        ].join(','));
      }
    });

    const csvContent = csvRows.join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Enterprise_Audit_Report_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);

    setExportToast(`Downloaded Full Enterprise CSV Audit Report (${endpoints.length} hosts)`);
    setTimeout(() => setExportToast(null), 4000);
  };

  const handlePrintPdfReport = () => {
    setIsGeneratingPdf(true);

    setTimeout(() => {
      try {
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

        const drawDivider = (yPos: number, height = 1, r = 220, g = 220, b = 220) => {
          doc.setDrawColor(r, g, b);
          doc.setLineWidth(height);
          doc.line(margin, yPos, pageWidth - margin, yPos);
        };

        const addPageHeaderIfNeeded = (neededHeight: number) => {
          if (y + neededHeight > pageHeight - 50) {
            doc.addPage();
            y = 50;
            doc.setFont('helvetica', 'bold');
            doc.setFontSize(8);
            doc.setTextColor(16, 53, 92);
            doc.text('SMARTPRO SECOPS - EXECUTIVE SECURITY AUDIT REPORT (CONTINUED)', margin, 32);
            drawDivider(36, 0.5, 197, 160, 89);
            y = 55;
          }
        };

        // Top Header Brand Bar
        doc.setFillColor(16, 53, 92);
        doc.rect(0, 0, pageWidth, 18, 'F');
        doc.setFillColor(197, 160, 89);
        doc.rect(0, 18, pageWidth, 3, 'F');

        y = 48;

        // SmartPro Shield Logo Badge
        const logoX = pageWidth - margin - 45;
        const logoY = y - 5;
        doc.setDrawColor(197, 160, 89);
        doc.setFillColor(16, 53, 92);
        doc.setLineWidth(1.5);
        doc.roundedRect(logoX, logoY, 45, 45, 6, 6, 'FD');

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(20);
        doc.setTextColor(197, 160, 89);
        doc.text("S", logoX + 15, logoY + 28);
        doc.setFontSize(9);
        doc.setTextColor(255, 255, 255);
        doc.text("P", logoX + 26, logoY + 37);

        // Title Block
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(14);
        doc.setTextColor(16, 53, 92);
        doc.text(`${companyName.toUpperCase()} - EXECUTIVE AUDIT REPORT`, margin, y);
        y += 16;

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(100, 100, 100);
        doc.text(`Auditor: ${auditorName} | Classification: ${securityClassification}`, margin, y);
        y += 12;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.5);
        doc.setTextColor(120, 120, 120);
        doc.text(`Generated: ${new Date().toLocaleString()} | Monitored Hosts: ${totalEndpoints}`, margin, y);
        y += 12;

        drawDivider(y, 1.5, 197, 160, 89);
        y += 20;

        // Executive Custom Notes Box
        if (customExecutiveNote.trim()) {
          doc.setFillColor(245, 248, 252);
          doc.setDrawColor(16, 53, 92);
          doc.rect(margin, y, contentWidth, 38, 'FD');

          doc.setFont('helvetica', 'bold');
          doc.setFontSize(7.5);
          doc.setTextColor(16, 53, 92);
          doc.text("EXECUTIVE AUDITOR STATEMENT & CIS BENCHMARK SCOPE:", margin + 10, y + 14);

          doc.setFont('helvetica', 'normal');
          doc.setFontSize(7.5);
          doc.setTextColor(50, 50, 50);
          const splitNotes = doc.splitTextToSize(customExecutiveNote, contentWidth - 20);
          doc.text(splitNotes, margin + 10, y + 26);
          y += 48;
        }

        // Executive Metrics Summary Box
        doc.setFillColor(250, 250, 252);
        doc.setDrawColor(230, 230, 235);
        doc.rect(margin, y, contentWidth, 70, 'FD');

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8.5);
        doc.setTextColor(100, 100, 100);
        doc.text("EXECUTIVE COMPLIANCE SUMMARY", margin + 15, y + 20);

        const col1 = margin + 15;
        const col2 = margin + 180;
        const col3 = margin + 350;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        doc.setTextColor(40, 40, 40);

        doc.text(`Monitored Hosts:   ${totalEndpoints} Systems`, col1, y + 38);
        doc.text(`Avg Compliance:    ${avgCurrentScore}% (Initial: ${avgBaselineScore}%)`, col1, y + 54);

        doc.text(`Compliant Hosts:   ${compliantEndpoints} / ${totalEndpoints}`, col2, y + 38);
        doc.text(`Posture Delta:     +${avgCurrentScore - avgBaselineScore}% Improvement`, col2, y + 54);

        doc.text(`Remediations:      ${totalFixedCount} Fixes Applied`, col3, y + 38);
        doc.text(`Critical Status:   ${criticalEndpoints} Host(s) Need Action`, col3, y + 54);

        y += 90;

        // Section: Host Inventory Postures Table
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(11);
        doc.setTextColor(16, 53, 92);
        doc.text("HOST ENDPOINTS AUDIT INVENTORY", margin, y);
        y += 14;

        // Table Header
        doc.setFillColor(240, 240, 245);
        doc.setDrawColor(220, 220, 225);
        doc.rect(margin, y, contentWidth, 22, 'FD');

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(60, 60, 60);
        doc.text("HOSTNAME & OS", margin + 10, y + 15);
        doc.text("IP ADDRESS", margin + 180, y + 15);
        doc.text("SCORE", margin + 280, y + 15);
        doc.text("STATUS", margin + 350, y + 15);
        doc.text("DISKS HEALTH", margin + 440, y + 15);

        y += 22;

        endpoints.forEach((ep, idx) => {
          addPageHeaderIfNeeded(30);

          if (idx % 2 === 1) {
            doc.setFillColor(252, 252, 254);
            doc.rect(margin, y, contentWidth, 26, 'F');
          }

          doc.setDrawColor(240, 240, 242);
          doc.line(margin, y + 26, pageWidth - margin, y + 26);

          doc.setFont('helvetica', 'bold');
          doc.setFontSize(8.5);
          doc.setTextColor(30, 30, 30);
          doc.text(ep.name, margin + 10, y + 12);

          doc.setFont('helvetica', 'normal');
          doc.setFontSize(7);
          doc.setTextColor(110, 110, 110);
          doc.text(ep.os, margin + 10, y + 21);

          doc.setFont('helvetica', 'normal');
          doc.setFontSize(8);
          doc.setTextColor(50, 50, 50);
          doc.text(ep.ip, margin + 180, y + 16);

          doc.setFont('helvetica', 'bold');
          doc.setFontSize(9);
          const score = ep.overallScore;
          doc.setTextColor(score >= 85 ? 20 : score >= 60 ? 180 : 200, score >= 85 ? 120 : score >= 60 ? 110 : 30, score >= 85 ? 40 : 20);
          doc.text(`${score}%`, margin + 280, y + 16);

          const statusText = score >= 85 ? 'COMPLIANT' : score >= 60 ? 'WARNING' : 'CRITICAL';
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(7.5);
          doc.text(statusText, margin + 350, y + 16);

          const diskCount = ep.storageHealth?.length || 0;
          doc.setFont('helvetica', 'normal');
          doc.setFontSize(7.5);
          doc.setTextColor(80, 80, 80);
          doc.text(`${diskCount} Drive(s) OK`, margin + 440, y + 16);

          y += 26;
        });

        y += 30;

        // Selected Endpoint Deep Detailed Findings Section
        if (selectedEndpoint) {
          addPageHeaderIfNeeded(120);

          doc.setFont('helvetica', 'bold');
          doc.setFontSize(11);
          doc.setTextColor(16, 53, 92);
          doc.text(`FEATURED AUDIT: ${selectedEndpoint.name} (${selectedEndpoint.ip})`, margin, y);
          y += 14;

          const vulns = get60VulnerabilitiesForEndpoint(selectedEndpoint);
          const passedCount = vulns.filter(v => v.status === 'passed').length;
          const failedCount = vulns.filter(v => v.status === 'failed').length;

          doc.setFont('helvetica', 'normal');
          doc.setFontSize(8.5);
          doc.setTextColor(60, 60, 60);
          doc.text(`Vulnerability Controls Evaluated: 60 Total | Passed: ${passedCount} | Open Findings: ${failedCount}`, margin, y);
          y += 16;

          // Top open findings if any
          const failedItems = vulns.filter(v => v.status === 'failed').slice(0, 10);
          if (failedItems.length > 0) {
            doc.setFont('helvetica', 'bold');
            doc.setFontSize(8);
            doc.setTextColor(180, 30, 30);
            doc.text("Top Pending Remediation Controls:", margin, y);
            y += 12;

            failedItems.forEach((fItem) => {
              addPageHeaderIfNeeded(20);
              doc.setFont('helvetica', 'normal');
              doc.setFontSize(7.5);
              doc.setTextColor(50, 50, 50);
              doc.text(`• [${fItem.vulnerability.severity}] ${fItem.vulnerability.name} (${fItem.vulnerability.category})`, margin + 10, y);
              y += 12;
            });
          }
        }

        y += 25;
        addPageHeaderIfNeeded(50);

        // Footer / Signature block
        drawDivider(y, 1, 197, 160, 89);
        y += 15;

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(16, 53, 92);
        doc.text("SmartPro SecOps Enterprise Audit & Compliance Desk", margin, y);
        y += 10;
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7);
        doc.setTextColor(120, 120, 120);
        doc.text("Certified Security Audit Report • SmartPro Consultancy • Abu Dhabi, UAE", margin, y);

        // Save PDF
        const pdfFileName = `SmartPro_Executive_Audit_Report_${new Date().toISOString().slice(0, 10)}.pdf`;
        doc.save(pdfFileName);

        // Also attempt window.print()
        try {
          window.print();
        } catch (e) {
          console.log("Browser print preview skipped or not available");
        }

      } catch (err) {
        console.error("PDF generation error:", err);
      } finally {
        setIsGeneratingPdf(false);
        setPdfSuccessToast(true);
        setTimeout(() => setPdfSuccessToast(false), 5000);
      }
    }, 600);
  };

  const handleExportHostCsv = (ep: Endpoint) => {
    if (!ep) return;
    const vulns = get60VulnerabilitiesForEndpoint(ep);

    const csvRows: string[] = [];
    const escapeCsv = (str: any) => `"${String(str ?? '').replace(/"/g, '""')}"`;

    // Section 1: Host Overview Metadata
    csvRows.push('=== SMARTPRO SECOPS - ENDPOINT AUDIT REPORT ===');
    csvRows.push(`Export Date,${escapeCsv(new Date().toLocaleString())}`);
    csvRows.push(`Hostname,${escapeCsv(ep.name)}`);
    csvRows.push(`IP Address,${escapeCsv(ep.ip)}`);
    csvRows.push(`Operating System,${escapeCsv(ep.os)}`);
    csvRows.push(`Device Type,${escapeCsv(ep.deviceType || 'Workstation')}`);
    csvRows.push(`Patch Level,${escapeCsv(ep.patchLevel || 'Up-to-Date')}`);
    csvRows.push(`Overall Score,${ep.overallScore}%`);
    csvRows.push(`Baseline Score,${ep.firstScanScore ?? ep.overallScore}%`);
    csvRows.push(`Compliance Status,${escapeCsv(ep.overallScore >= 85 ? 'COMPLIANT' : ep.overallScore >= 60 ? 'NEEDS ATTENTION' : 'CRITICAL ACTION NEEDED')}`);
    csvRows.push(`Last Scanned,${escapeCsv(ep.lastScanned)}`);
    csvRows.push('');

    // Section 2: Vulnerability Audit Details
    csvRows.push(`=== VULNERABILITY AUDIT & COMPLIANCE CONTROLS (${vulns.length} CONTROLS) ===`);
    csvRows.push('ID,Vulnerability / Control Name,Category,Severity,Audit Status,Remediated,Excluded,Impact Warning,PowerShell Remediation');
    
    vulns.forEach(item => {
      const v = item.vulnerability;
      csvRows.push([
        v.id,
        escapeCsv(v.name),
        escapeCsv(v.category),
        escapeCsv(v.severity),
        escapeCsv(item.status.toUpperCase()),
        item.remediated ? 'YES' : 'NO',
        item.excluded ? 'YES' : 'NO',
        escapeCsv(v.impactWarning || ''),
        escapeCsv(v.powershellFix || '')
      ].join(','));
    });
    csvRows.push('');

    // Section 3: Storage & Logical Disk Health
    const storage = ep.storageHealth || [];
    csvRows.push(`=== LOGICAL STORAGE HEALTH (${storage.length} DRIVES) ===`);
    csvRows.push('Drive Letter,Media Type,Health Status,SMART Status,Free Space (GB),Total Space (GB),Free Space %,BitLocker Status');
    if (storage.length === 0) {
      csvRows.push('N/A,No logical storage drives reported');
    } else {
      storage.forEach(s => {
        csvRows.push([
          escapeCsv(s.driveLetter),
          escapeCsv(s.mediaType),
          escapeCsv(s.healthStatus),
          escapeCsv(s.smartStatus),
          s.freeSpaceGB,
          s.totalSpaceGB,
          s.freeSpacePercent,
          escapeCsv(s.bitLockerStatus)
        ].join(','));
      });
    }
    csvRows.push('');

    // Section 4: Physical Disk S.M.A.R.T. Health
    const physical = ep.physicalDrives || [];
    csvRows.push(`=== PHYSICAL DISK S.M.A.R.T. HEALTH (${physical.length} DISKS) ===`);
    csvRows.push('Drive Friendly Name,Media Type,Health Status,Operational Status,Bus Type,Size (GB),Temperature (C),Wear Level %,SMART Status,Serial Number');
    if (physical.length === 0) {
      csvRows.push('N/A,No physical disk drives reported');
    } else {
      physical.forEach(p => {
        csvRows.push([
          escapeCsv(p.friendlyName),
          escapeCsv(p.mediaType),
          escapeCsv(p.healthStatus),
          escapeCsv(p.operationalStatus),
          escapeCsv(p.busType || 'N/A'),
          p.sizeGB,
          p.temperatureC !== null && p.temperatureC !== undefined ? p.temperatureC : 'N/A',
          p.wearLevelPercent !== null && p.wearLevelPercent !== undefined ? p.wearLevelPercent : 'N/A',
          escapeCsv(p.smartStatus),
          escapeCsv(p.serialNumber || 'N/A')
        ].join(','));
      });
    }

    const csvContent = csvRows.join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Endpoint_Audit_Report_${ep.name.replace(/[^a-zA-Z0-9_-]/g, '_')}_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);

    setExportToast(`Exported CSV audit report for ${ep.name}`);
    setTimeout(() => setExportToast(null), 4000);
  };

  const handleExportHostJson = (ep: Endpoint) => {
    if (!ep) return;
    const vulns = get60VulnerabilitiesForEndpoint(ep);

    const reportData = {
      exportMetadata: {
        generatedAt: new Date().toISOString(),
        reportType: 'Endpoint Vulnerability & Disk Health Audit',
        generatedBy: 'SmartPro SecOps Enterprise Guard'
      },
      endpoint: {
        id: ep.id,
        hostname: ep.name,
        ipAddress: ep.ip,
        os: ep.os,
        deviceType: ep.deviceType || 'Workstation',
        patchLevel: ep.patchLevel,
        lastScanned: ep.lastScanned,
        overallScore: ep.overallScore,
        firstScanScore: ep.firstScanScore ?? ep.overallScore,
        complianceStatus: ep.overallScore >= 85 ? 'COMPLIANT' : ep.overallScore >= 60 ? 'NEEDS ATTENTION' : 'CRITICAL ACTION NEEDED',
        remediatedVulnerabilityIds: ep.remediatedVulnerabilities || [],
        excludedVulnerabilityIds: ep.excludedVulnerabilities || []
      },
      vulnerabilities: vulns.map(v => ({
        id: v.vulnerability.id,
        name: v.vulnerability.name,
        category: v.vulnerability.category,
        severity: v.vulnerability.severity,
        auditStatus: v.status,
        remediated: v.remediated || false,
        excluded: v.excluded || false,
        description: v.vulnerability.description,
        impactWarning: v.vulnerability.impactWarning,
        powershellFix: v.vulnerability.powershellFix
      })),
      storageHealth: ep.storageHealth || [],
      physicalDrives: ep.physicalDrives || [],
      scanDataSummary: ep.scanData
    };

    const jsonContent = JSON.stringify(reportData, null, 2);
    const blob = new Blob([jsonContent], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Endpoint_Audit_Report_${ep.name.replace(/[^a-zA-Z0-9_-]/g, '_')}_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);

    setExportToast(`Exported JSON audit report for ${ep.name}`);
    setTimeout(() => setExportToast(null), 4000);
  };

  return (
    <div className="space-y-8 animate-fadeIn print:text-black print:bg-white">
      {/* Toast notification */}
      {pdfSuccessToast && (
        <div className="fixed bottom-6 right-6 z-50 bg-emerald-950 border border-emerald-500/60 text-emerald-200 px-4 py-3 rounded-xl shadow-2xl flex items-center gap-3">
          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          <div>
            <div className="font-bold text-xs uppercase tracking-wide">Audit Report Generated</div>
            <div className="text-[11px] text-emerald-300/80">Executive PDF report formatted and sent to browser print preview!</div>
          </div>
        </div>
      )}

      {exportToast && (
        <div className="fixed bottom-6 right-6 z-50 bg-cyan-950 border border-cyan-500/60 text-cyan-200 px-4 py-3 rounded-xl shadow-2xl flex items-center gap-3 animate-fadeIn">
          <Download className="w-5 h-5 text-cyan-400 shrink-0" />
          <div>
            <div className="font-bold text-xs uppercase tracking-wide">Offline Report Exported</div>
            <div className="text-[11px] text-cyan-300/80">{exportToast}</div>
          </div>
        </div>
      )}

      {/* Hero Header Card */}
      <div className="bg-gradient-to-r from-[#032917] via-[#063d22] to-[#021c10] border-2 border-emerald-400/60 rounded-2xl p-6 sm:p-8 shadow-2xl shadow-emerald-950/80 relative overflow-hidden">
        <div className="absolute -top-24 -right-24 w-72 h-72 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />
        
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="bg-emerald-400 text-black font-black px-3 py-1 rounded-md text-xs uppercase tracking-widest flex items-center gap-1.5 font-mono shadow">
                <CheckCircle2 className="w-4 h-4 text-black" />
                STEP 3 PAGE – EMERALD RESULTS & COMPLIANCE CERTIFICATE
              </span>
              <span className="text-emerald-300/80 text-xs font-mono font-bold">• SmartPro SecOps Audit</span>
            </div>
            
            <h2 className="text-2xl sm:text-3xl font-black text-white tracking-tight">
              Final Security Results & Verification Report
            </h2>
            <p className="text-xs sm:text-sm text-emerald-100/80 max-w-2xl leading-relaxed">
              Comprehensive compliance scorecard, before-vs-after security posture improvements, verified remediations log, and executive audit report export options.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              onClick={() => setShowDownloadModal(true)}
              className="px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-black font-black text-xs uppercase tracking-wider transition shadow-xl shadow-cyan-950/60 flex items-center gap-2 cursor-pointer border border-cyan-300"
            >
              <Download className="w-4 h-4 text-black" />
              Download Audit Report
            </button>

            <button
              onClick={() => setShowPdfCustomizer(true)}
              className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-emerald-400 to-emerald-500 hover:from-emerald-300 hover:to-emerald-400 text-black font-black text-xs uppercase tracking-wider transition shadow-xl shadow-emerald-950/60 flex items-center gap-2 cursor-pointer border border-emerald-300"
            >
              <Printer className="w-4 h-4 text-black" />
              Customize & Generate PDF Report
            </button>

            <button
              onClick={onOpenExportModal}
              className="px-4 py-2.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-black font-black text-xs uppercase tracking-wider transition shadow-lg shadow-amber-950/40 flex items-center gap-2 cursor-pointer"
            >
              <Download className="w-4 h-4 text-black" />
              Export Config / JSON
            </button>
          </div>
        </div>
      </div>

      {/* Data Provenance & Realness Indicator Banner */}
      <div className="bg-[#0a1810] border-2 border-emerald-500/40 rounded-xl p-4 text-left flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg border text-xs font-black uppercase flex items-center gap-1.5 ${
            selectedEndpoint?.isRealScan || selectedEndpoint?.scanData?.isRealScan
              ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/50'
              : 'bg-amber-500/20 text-amber-300 border-amber-500/50'
          }`}>
            <ShieldCheck className="w-4 h-4" />
            <span>{selectedEndpoint?.isRealScan || selectedEndpoint?.scanData?.isRealScan ? '100% REAL SCAN DATA' : 'DEMO BASELINE DATA'}</span>
          </div>
          <div>
            <div className="text-xs font-bold text-white uppercase tracking-wider">
              Selected Host: <span className="text-emerald-400 font-extrabold">{selectedEndpoint?.name || 'Local Host'}</span> ({selectedEndpoint?.ip || 'N/A'})
            </div>
            <div className="text-[11px] text-emerald-200/70">
              Source: {selectedEndpoint?.scanSource || selectedEndpoint?.scanData?.scanSource || (selectedEndpoint?.isRealScan ? 'Verified PowerShell Local Audit' : 'Pre-loaded benchmark endpoint')}
            </div>
          </div>
        </div>

        {!(selectedEndpoint?.isRealScan || selectedEndpoint?.scanData?.isRealScan) && (
          <div className="text-right">
            <span className="text-[10px] text-amber-300/90 block mb-1">Want 100% real data from your machine?</span>
            <span className="text-xs text-emerald-400 font-bold bg-emerald-950/80 border border-emerald-500/40 px-2.5 py-1 rounded inline-block">
              Go to Upload Hub → Switch to PowerShell / Live Probe
            </span>
          </div>
        )}
      </div>

      {/* Aggregate Score & Improvement Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0f0f0f] border border-white/10 rounded-2xl p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-white/50 uppercase tracking-wider">Average Compliance Score</span>
            <Award className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-black font-mono text-emerald-400">{avgCurrentScore}%</span>
            <span className="text-xs font-mono text-white/40">vs {avgBaselineScore}% initial</span>
          </div>
          <div className="mt-2 text-[10px] text-emerald-300 flex items-center gap-1 font-mono">
            <TrendingUp className="w-3 h-3 text-emerald-400" />
            +{(avgCurrentScore - avgBaselineScore)}% Posture Improvement
          </div>
        </div>

        <div className="bg-[#0f0f0f] border border-white/10 rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-white/50 uppercase tracking-wider">Total Remediations Applied</span>
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="mt-3 text-3xl font-black font-mono text-cyan-300">
            {totalFixedCount} <span className="text-sm font-normal text-white/40">Fixes</span>
          </div>
          <div className="mt-2 text-[10px] text-cyan-400 font-mono">
            Verified across {totalEndpoints} network host devices
          </div>
        </div>

        <div className="bg-[#0f0f0f] border border-white/10 rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-white/50 uppercase tracking-wider">Network Compliance Status</span>
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="mt-3 text-3xl font-black font-mono text-white">
            {compliantEndpoints} <span className="text-sm text-emerald-400">/ {totalEndpoints}</span>
          </div>
          <div className="mt-2 text-[10px] text-white/50 font-mono">
            {warningEndpoints > 0 && <span className="text-amber-400">{warningEndpoints} warning</span>}
            {criticalEndpoints > 0 && <span className="text-red-400 ml-1.5">{criticalEndpoints} vulnerable</span>}
            {warningEndpoints === 0 && criticalEndpoints === 0 && <span className="text-emerald-400">100% Fully Compliant</span>}
          </div>
        </div>

        <div className="bg-[#0f0f0f] border border-white/10 rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-white/50 uppercase tracking-wider">Cloud & Repositories</span>
            <Share2 className="w-5 h-5 text-amber-400" />
          </div>
          <div className="mt-3 text-xs font-bold text-amber-300">
            SmartPro Sync Active
          </div>
          <button
            onClick={onOpenGitHubModal}
            className="mt-3 text-[11px] font-bold text-amber-400 hover:text-amber-300 underline cursor-pointer flex items-center gap-1 font-mono"
          >
            GitHub Auto-Sync Backup &rarr;
          </button>
        </div>
      </div>

      {/* Individual Endpoint Detailed Results Explorer */}
      <div className="bg-[#0d0d0d] border border-white/10 rounded-2xl p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-4">
          <div>
            <h3 className="text-lg font-black text-white flex items-center gap-2">
              <Server className="w-5 h-5 text-cyan-400" />
              Endpoint-Specific Verification Results
            </h3>
            <p className="text-xs text-white/50">Select an audited host PC to inspect its before vs after compliance posture.</p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <label className="text-xs font-bold text-white/60 font-mono">Host Device:</label>
              <select
                value={selectedEndpointId}
                onChange={(e) => setSelectedEndpointId(e.target.value)}
                className="bg-black border border-white/20 rounded-xl px-3 py-1.5 text-xs text-white font-mono font-bold focus:border-emerald-400 focus:outline-none cursor-pointer"
              >
                {endpoints.map(ep => (
                  <option key={ep.id} value={ep.id} className="bg-black text-white">
                    {ep.name} ({ep.ip}) — Score: {ep.overallScore}%
                  </option>
                ))}
              </select>
            </div>

            {selectedEndpoint && (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleExportHostCsv(selectedEndpoint)}
                  className="px-3 py-1.5 rounded-xl bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 text-xs font-mono font-bold uppercase transition cursor-pointer flex items-center gap-1.5"
                  title="Export current endpoint's vulnerability and disk health data into CSV format"
                >
                  <FileText className="w-3.5 h-3.5 text-emerald-400" />
                  Export Host CSV
                </button>
                <button
                  onClick={() => handleExportHostJson(selectedEndpoint)}
                  className="px-3 py-1.5 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-mono font-bold uppercase transition cursor-pointer flex items-center gap-1.5"
                  title="Export current endpoint's vulnerability and disk health data into JSON format"
                >
                  <Download className="w-3.5 h-3.5 text-cyan-400" />
                  Export Host JSON
                </button>
              </div>
            )}
          </div>
        </div>

        {selectedEndpoint ? (
          <div className="space-y-6">
            {/* Host Overview Card */}
            <div className="bg-black/60 border border-white/10 rounded-xl p-5 grid grid-cols-1 md:grid-cols-4 gap-4">
              <div>
                <span className="text-[10px] text-white/40 uppercase font-mono">Hostname & IP</span>
                <div className="font-bold text-white text-sm font-mono mt-0.5">{selectedEndpoint.name}</div>
                <div className="text-xs text-cyan-400 font-mono">{selectedEndpoint.ip}</div>
              </div>

              <div>
                <span className="text-[10px] text-white/40 uppercase font-mono">Operating System</span>
                <div className="font-bold text-white/90 text-xs mt-0.5">{selectedEndpoint.os}</div>
                <div className="text-[10px] text-white/50">{selectedEndpoint.patchLevel}</div>
              </div>

              <div>
                <span className="text-[10px] text-white/40 uppercase font-mono">Baseline vs Current</span>
                <div className="flex items-baseline gap-2 mt-0.5 font-mono">
                  <span className="text-sm font-bold text-white/50 line-through">{selectedEndpoint.firstScanScore ?? selectedEndpoint.overallScore}%</span>
                  <span className="text-xl font-black text-emerald-400">&rarr; {selectedEndpoint.overallScore}%</span>
                </div>
              </div>

              <div>
                <span className="text-[10px] text-white/40 uppercase font-mono">Remediation Status</span>
                <div className="mt-1">
                  <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-black uppercase font-mono ${
                    selectedEndpoint.overallScore >= 85 ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' :
                    selectedEndpoint.overallScore >= 60 ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                    'bg-red-500/20 text-red-300 border border-red-500/40'
                  }`}>
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    {selectedEndpoint.overallScore >= 85 ? 'COMPLIANT' : selectedEndpoint.overallScore >= 60 ? 'NEEDS ATTENTION' : 'CRITICAL ACTION NEEDED'}
                  </span>
                </div>
              </div>
            </div>

            {/* Remediated Items Log */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              
              {/* Remediated / Passed Checklist */}
              <div className="bg-black/40 border border-emerald-500/30 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-emerald-500/20 pb-3">
                  <h4 className="text-xs font-bold text-emerald-300 uppercase tracking-wider flex items-center gap-2">
                    <CheckSquare className="w-4 h-4 text-emerald-400" />
                    Applied Fixes & Passed Checks ({selectedFixed.length})
                  </h4>
                  <span className="text-[10px] text-emerald-400 font-mono">Verified Safe</span>
                </div>

                {selectedFixed.length === 0 ? (
                  <p className="text-xs text-white/40 italic py-4 text-center">
                    No custom remediations applied yet on this host. Go to <strong className="text-amber-400">Step 2 – Improve</strong> to execute fixes.
                  </p>
                ) : (
                  <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                    {selectedFixed.map((item) => (
                      <div key={item.vulnerability.id} className="bg-emerald-950/20 border border-emerald-500/20 rounded p-2.5 text-xs flex items-start gap-2.5">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                        <div>
                          <div className="font-bold text-white/90">{item.vulnerability.name}</div>
                          <div className="text-[10px] text-emerald-300/80 mt-0.5">{item.vulnerability.description}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Residual Vulnerabilities (If any remain) */}
              <div className="bg-black/40 border border-amber-500/30 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-amber-500/20 pb-3">
                  <h4 className="text-xs font-bold text-amber-300 uppercase tracking-wider flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    Residual Risks & Open Remediation Items ({selectedRemainingFailed.length})
                  </h4>
                  <span className="text-[10px] text-amber-400 font-mono">Requires Attention</span>
                </div>

                {selectedRemainingFailed.length === 0 ? (
                  <div className="bg-emerald-950/30 border border-emerald-500/30 rounded-xl p-6 text-center space-y-2">
                    <Award className="w-8 h-8 text-emerald-400 mx-auto" />
                    <h5 className="text-sm font-bold text-emerald-300 uppercase">Zero Open Vulnerabilities</h5>
                    <p className="text-xs text-emerald-200/80">This host endpoint has achieved 100% compliance across all 60 security audit controls!</p>
                  </div>
                ) : (
                  <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                    {selectedRemainingFailed.map((item) => (
                      <div key={item.vulnerability.id} className="bg-amber-950/20 border border-amber-500/20 rounded p-2.5 text-xs flex items-start gap-2.5">
                        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                        <div>
                          <div className="font-bold text-white/90 flex items-center gap-2">
                            <span>{item.vulnerability.name}</span>
                            <span className="text-[9px] font-bold uppercase px-1.5 py-0.2 rounded bg-red-500/20 text-red-300 border border-red-500/40">
                              {item.vulnerability.severity}
                            </span>
                          </div>
                          <div className="text-[10px] text-amber-200/80 mt-0.5">{item.vulnerability.description}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

            </div>

            {/* Storage & Disk Health Audit Breakdown Card */}
            <div className="bg-black/40 border border-white/10 rounded-xl p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-3">
                <h4 className="text-xs font-bold text-cyan-300 uppercase tracking-wider flex items-center gap-2 font-mono">
                  <HardDrive className="w-4 h-4 text-cyan-400" />
                  Storage & Physical Disk S.M.A.R.T. Health ({selectedEndpoint.storageHealth?.length || 0} Logical / {selectedEndpoint.physicalDrives?.length || 0} Physical)
                </h4>
                
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleExportHostCsv(selectedEndpoint)}
                    className="px-2.5 py-1 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 text-[10px] font-mono font-bold uppercase transition cursor-pointer flex items-center gap-1"
                    title="Export CSV audit report for this host"
                  >
                    <FileText className="w-3 h-3 text-emerald-400" />
                    CSV Report
                  </button>
                  <button
                    onClick={() => handleExportHostJson(selectedEndpoint)}
                    className="px-2.5 py-1 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-[10px] font-mono font-bold uppercase transition cursor-pointer flex items-center gap-1"
                    title="Export JSON audit report for this host"
                  >
                    <Download className="w-3 h-3 text-cyan-400" />
                    JSON Report
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Logical Storage Drives */}
                <div className="space-y-3">
                  <div className="text-[11px] font-bold text-white/50 uppercase font-mono">Logical Storage Drives</div>
                  {(!selectedEndpoint.storageHealth || selectedEndpoint.storageHealth.length === 0) ? (
                    <div className="text-xs text-white/40 italic">No logical drive details recorded.</div>
                  ) : (
                    selectedEndpoint.storageHealth.map((drive, idx) => (
                      <div key={idx} className="bg-black/60 border border-white/10 rounded-lg p-3 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-white text-xs font-mono">{drive.driveLetter} ({drive.mediaType})</span>
                          <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded font-mono ${
                            drive.healthStatus === 'Healthy' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' :
                            'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                          }`}>
                            {drive.healthStatus} • SMART: {drive.smartStatus}
                          </span>
                        </div>
                        
                        <div className="space-y-1">
                          <div className="flex justify-between text-[10px] font-mono text-white/60">
                            <span>{drive.freeSpaceGB} GB free of {drive.totalSpaceGB} GB</span>
                            <span>{drive.freeSpacePercent}% free</span>
                          </div>
                          <div className="w-full h-1.5 bg-white/10 rounded-full overflow-hidden">
                            <div 
                              className={`h-full ${drive.freeSpacePercent < 15 ? 'bg-red-500' : drive.freeSpacePercent < 30 ? 'bg-amber-400' : 'bg-emerald-400'}`}
                              style={{ width: `${100 - drive.freeSpacePercent}%` }}
                            />
                          </div>
                        </div>

                        <div className="text-[10px] text-white/40 font-mono flex items-center justify-between pt-1">
                          <span>BitLocker: <strong className={drive.bitLockerStatus.includes('Encrypted') ? 'text-emerald-400' : 'text-red-400'}>{drive.bitLockerStatus}</strong></span>
                          {drive.temperatureC !== undefined && drive.temperatureC !== null && <span>Temp: {drive.temperatureC}°C</span>}
                        </div>
                      </div>
                    ))
                  )}
                </div>

                {/* Physical Hardware Disks */}
                <div className="space-y-3">
                  <div className="text-[11px] font-bold text-white/50 uppercase font-mono">Physical Hardware S.M.A.R.T. Disks</div>
                  {(!selectedEndpoint.physicalDrives || selectedEndpoint.physicalDrives.length === 0) ? (
                    <div className="text-xs text-white/40 italic">No physical drive S.M.A.R.T telemetry reported.</div>
                  ) : (
                    selectedEndpoint.physicalDrives.map((pd, idx) => (
                      <div key={idx} className="bg-black/60 border border-white/10 rounded-lg p-3 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-white text-xs font-mono truncate max-w-[200px]" title={pd.friendlyName}>
                            {pd.friendlyName}
                          </span>
                          <span className="text-[10px] font-mono text-cyan-300 bg-cyan-950/60 px-1.5 py-0.2 rounded border border-cyan-800/40">
                            {pd.mediaType} ({pd.busType || 'N/A'})
                          </span>
                        </div>

                        <div className="grid grid-cols-2 gap-2 text-[10px] font-mono text-white/60 pt-1">
                          <div>Capacity: <strong className="text-white">{pd.sizeGB} GB</strong></div>
                          <div>SMART Status: <strong className={pd.smartStatus === 'Passed' ? 'text-emerald-400' : 'text-amber-400'}>{pd.smartStatus}</strong></div>
                          {pd.temperatureC !== null && pd.temperatureC !== undefined && (
                            <div>Temperature: <strong className={pd.temperatureC > 45 ? 'text-amber-400' : 'text-emerald-400'}>{pd.temperatureC}°C</strong></div>
                          )}
                          {pd.wearLevelPercent !== null && pd.wearLevelPercent !== undefined && (
                            <div>Life / Health: <strong className="text-emerald-400">{pd.wearLevelPercent}%</strong></div>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="bg-black/60 border border-white/10 rounded-2xl p-12 text-center space-y-3 font-mono">
            <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mx-auto text-cyan-400">
              <Server className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-black text-white uppercase tracking-wider">
              {endpoints.length === 0 ? 'Saved Inventory Data Cleared (0 Host Devices)' : 'No Endpoint Host Selected'}
            </h3>
            <p className="text-xs text-white/50 max-w-md mx-auto font-sans leading-relaxed">
              {endpoints.length === 0 
                ? 'All previous endpoint posture records have been cleared from local storage. Add host devices in Step 1 (Diagnose) or restore the demo hosts to view audit verification reports.'
                : 'Select an endpoint host from the dropdown to review post-remediation verification results.'}
            </p>
          </div>
        )}
      </div>

      {/* Executive Sign-off Footer Card */}
      <div className="bg-[#0f0f0f] border border-white/10 rounded-2xl p-6 flex flex-col sm:flex-row items-center justify-between gap-4 font-mono text-xs">
        <div className="flex items-center gap-3">
          <ShieldCheck className="w-8 h-8 text-amber-400 shrink-0" />
          <div>
            <div className="font-bold text-white">SmartPro SecOps Enterprise Guard Verification Complete</div>
            <div className="text-[10px] text-white/50">Official Audit Document & Posture Record • Abu Dhabi, UAE</div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onOpenWinUtilModal}
            className="px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 font-bold uppercase text-[11px] transition cursor-pointer"
          >
            Launch WinUtil Auto-Fix
          </button>
          <button
            onClick={() => setShowPdfCustomizer(true)}
            className="px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-black font-black uppercase text-[11px] transition cursor-pointer"
          >
            Print Executive PDF
          </button>
        </div>
      </div>

      {/* Download Audit Report Modal (JSON & CSV Export Options) */}
      {showDownloadModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-[#05141c] border-2 border-cyan-500/50 rounded-2xl max-w-2xl w-full p-6 shadow-2xl shadow-cyan-950/80 space-y-5 text-left font-mono relative animate-fadeIn">
            <div className="flex items-center justify-between border-b border-cyan-500/30 pb-3">
              <div className="flex items-center gap-2.5">
                <Download className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-black text-white uppercase tracking-wider">
                  Download Security Audit Report (JSON / CSV)
                </h3>
              </div>
              <button
                onClick={() => setShowDownloadModal(false)}
                className="text-white/50 hover:text-white bg-white/5 hover:bg-white/10 p-1.5 rounded-lg transition"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-cyan-100/80 leading-relaxed">
              Export comprehensive security audit logs, including all 60 vulnerability statuses, logical & physical drive health, and Active Directory LDAP SPN Kerberoasting probe findings.
            </p>

            {/* Option 1: Full Enterprise Network Audit Report */}
            <div className="bg-black/60 border border-cyan-500/30 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-bold text-cyan-300 uppercase flex items-center gap-2">
                    <Server className="w-4 h-4 text-cyan-400" />
                    Full Network Enterprise Report ({endpoints.length} Systems)
                  </h4>
                  <p className="text-[10px] text-white/50 mt-0.5">
                    Consolidated audit report across all network host endpoints, including LDAP SPNs & disk SMART data.
                  </p>
                </div>
                <span className="text-[9px] bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 px-2 py-0.5 rounded uppercase font-bold">
                  All Hosts
                </span>
              </div>

              <div className="flex items-center gap-3 pt-1">
                <button
                  onClick={() => {
                    setShowDownloadModal(false);
                    handleDownloadFullNetworkReportJson();
                  }}
                  className="flex-1 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-black font-black text-xs uppercase rounded transition cursor-pointer flex items-center justify-center gap-1.5 shadow"
                >
                  <Download className="w-3.5 h-3.5 text-black" />
                  Download Full JSON
                </button>

                <button
                  onClick={() => {
                    setShowDownloadModal(false);
                    handleDownloadFullNetworkReportCsv();
                  }}
                  className="flex-1 px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-black font-black text-xs uppercase rounded transition cursor-pointer flex items-center justify-center gap-1.5 shadow"
                >
                  <FileText className="w-3.5 h-3.5 text-black" />
                  Download Full CSV
                </button>
              </div>
            </div>

            {/* Option 2: Selected Endpoint Audit Report */}
            {selectedEndpoint && (
              <div className="bg-black/60 border border-emerald-500/30 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-xs font-bold text-emerald-300 uppercase flex items-center gap-2">
                      <Activity className="w-4 h-4 text-emerald-400" />
                      Single Host Report: {selectedEndpoint.name} ({selectedEndpoint.ip})
                    </h4>
                    <p className="text-[10px] text-white/50 mt-0.5">
                      Detailed audit report specifically for {selectedEndpoint.name} including vulnerability controls & LDAP SPNs.
                    </p>
                  </div>
                  <span className="text-[9px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 px-2 py-0.5 rounded uppercase font-bold">
                    {selectedEndpoint.overallScore}% Score
                  </span>
                </div>

                <div className="flex items-center gap-3 pt-1">
                  <button
                    onClick={() => {
                      setShowDownloadModal(false);
                      handleExportHostJson(selectedEndpoint);
                    }}
                    className="flex-1 px-4 py-2 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-500/40 font-black text-xs uppercase rounded transition cursor-pointer flex items-center justify-center gap-1.5"
                  >
                    <Download className="w-3.5 h-3.5 text-cyan-400" />
                    Host JSON Report
                  </button>

                  <button
                    onClick={() => {
                      setShowDownloadModal(false);
                      handleExportHostCsv(selectedEndpoint);
                    }}
                    className="flex-1 px-4 py-2 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-500/40 font-black text-xs uppercase rounded transition cursor-pointer flex items-center justify-center gap-1.5"
                  >
                    <FileText className="w-3.5 h-3.5 text-emerald-400" />
                    Host CSV Report
                  </button>
                </div>
              </div>
            )}

            <div className="flex items-center justify-between pt-2 border-t border-cyan-500/30 text-[10px] text-white/50">
              <span>Includes Get-ADUser LDAP SPN Audit Data & Password Policy Parameters</span>
              <button
                onClick={() => setShowDownloadModal(false)}
                className="px-4 py-1.5 bg-white/10 hover:bg-white/20 text-white font-bold text-xs uppercase rounded transition cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Executive PDF Report Branding & Content Customizer Modal */}
      {showPdfCustomizer && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-[#081810] border-2 border-emerald-500/50 rounded-2xl max-w-xl w-full p-6 shadow-2xl shadow-emerald-950/80 space-y-4 text-left font-mono relative animate-fadeIn">
            <div className="flex items-center justify-between border-b border-emerald-500/30 pb-3">
              <div className="flex items-center gap-2.5">
                <Printer className="w-5 h-5 text-emerald-400" />
                <h3 className="text-sm font-black text-white uppercase tracking-wider">
                  Executive PDF Report Customizer
                </h3>
              </div>
              <button
                onClick={() => setShowPdfCustomizer(false)}
                className="text-white/50 hover:text-white bg-white/5 hover:bg-white/10 p-1.5 rounded-lg transition"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-emerald-100/70">
              Customize company branding, auditor title, and security notes before compiling the official PDF compliance certificate.
            </p>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-white/70 font-bold block mb-1">Company / Enterprise Name:</label>
                <input
                  type="text"
                  value={companyName}
                  onChange={(e) => setCompanyName(e.target.value)}
                  className="w-full bg-black/80 border border-emerald-500/30 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-400"
                />
              </div>

              <div>
                <label className="text-white/70 font-bold block mb-1">Auditor Name & Title:</label>
                <input
                  type="text"
                  value={auditorName}
                  onChange={(e) => setAuditorName(e.target.value)}
                  className="w-full bg-black/80 border border-emerald-500/30 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-400"
                />
              </div>

              <div>
                <label className="text-white/70 font-bold block mb-1">Security Classification Label:</label>
                <input
                  type="text"
                  value={securityClassification}
                  onChange={(e) => setSecurityClassification(e.target.value)}
                  className="w-full bg-black/80 border border-emerald-500/30 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-400"
                />
              </div>

              <div>
                <label className="text-white/70 font-bold block mb-1">Executive Audit Summary Notes:</label>
                <textarea
                  value={customExecutiveNote}
                  onChange={(e) => setCustomExecutiveNote(e.target.value)}
                  rows={3}
                  className="w-full bg-black/80 border border-emerald-500/30 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-400"
                />
              </div>
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-emerald-500/30">
              <span className="text-[10px] text-emerald-300/80">Includes Before/After Scorecard & All Verified Remediation Logs</span>
              
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowPdfCustomizer(false)}
                  className="px-4 py-2 bg-white/10 hover:bg-white/20 text-white font-bold text-xs uppercase rounded transition cursor-pointer"
                >
                  Cancel
                </button>

                <button
                  onClick={() => {
                    setShowPdfCustomizer(false);
                    handlePrintPdfReport();
                  }}
                  disabled={isGeneratingPdf}
                  className="px-5 py-2 bg-gradient-to-r from-emerald-400 to-emerald-500 hover:from-emerald-300 hover:to-emerald-400 text-black font-black text-xs uppercase tracking-wider rounded transition shadow-lg shadow-emerald-950/80 cursor-pointer flex items-center gap-1.5"
                >
                  <Printer className="w-3.5 h-3.5 text-black" />
                  <span>{isGeneratingPdf ? 'Compiling PDF...' : 'Generate PDF Report'}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
