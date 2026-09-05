export interface AuditSection {
  status: 'passed' | 'failed' | 'warning';
  value: string;
  details: string;
}

export interface UserStatus {
  username: string;
  status: 'Active' | 'Disabled';
  lastPasswordChange: string;
  passwordAgeDays: number;
  passwordNeverExpires: boolean; // Is Password Never Expires 'tik'-ed / optioned
}

export interface PortInfo {
  port: number;
  protocol: 'TCP' | 'UDP';
  service: string;
  status: 'Open' | 'Closed' | 'Filtered';
  severity: 'Secure' | 'Weak' | 'Vulnerable' | 'Critical';
  vulnerabilityDetails?: string;
}

export interface PasswordPolicy {
  minimumLength: number;
  complexityEnabled: boolean;
  maximumAgeDays: number;
  minimumAgeDays: number;
  historyCount: number;
}

export interface BrowserSecurityCheck {
  chromePasswordStore: AuditSection;
  chromeHistoryAllowed: AuditSection;
  edgePasswordStore: AuditSection;
  edgeHistoryAllowed: AuditSection;
  firefoxPasswordStore: AuditSection;
  firefoxHistoryAllowed: AuditSection;
}

export interface PhysicalDriveHealth {
  friendlyName: string;
  mediaType: 'SSD' | 'HDD' | 'NVMe' | 'Unspecified' | string;
  healthStatus: 'Healthy' | 'Warning' | 'Unhealthy' | 'Critical' | 'Unknown' | string;
  operationalStatus: string; // e.g., 'OK', 'Degraded', 'Predictive Failure'
  busType?: string; // e.g. 'NVMe', 'SATA', 'SAS', 'USB'
  sizeGB: number;
  temperatureC?: number | null; // Temperature in Celsius (e.g. 34, 42)
  wearLevelPercent?: number | null; // Remaining wear level / Life percentage (0-100%)
  smartStatus: 'Passed' | 'Degraded' | 'Failing' | 'Unknown' | string;
  serialNumber?: string;
}

export interface LdapSpnAccount {
  samAccountName: string;
  servicePrincipalName: string;
  passwordLastSet: string;
  passwordNeverExpires: boolean;
}

export interface LdapAuditResult {
  status: 'passed' | 'failed' | 'warning';
  details: string;
  commandExecuted?: string;
  accounts?: LdapSpnAccount[];
}

export interface SecurityAuditResult {
  hostname: string;
  osName: string;
  scanTime: string;
  ipAddresses: string[];
  privileges: string;
  isRealScan?: boolean;
  verifiedScanType?: 'POWERSHELL_LOCAL_AUDIT' | 'LIVE_NETWORK_PROBE' | 'LOCAL_LAN_SWEEP' | 'DEMO_BASELINE';
  scanSource?: string;
  smb: {
    smb1Enabled: AuditSection;
    smbSigningRequired: AuditSection;
    smbEncryptionEnabled: AuditSection;
  };
  sslTls: {
    tls10Enabled: AuditSection;
    tls11Enabled: AuditSection;
    tls12Enabled: AuditSection;
    tls13Enabled: AuditSection;
    weakCipherSuites: AuditSection;
  };
  ntlm: {
    lmCompatibilityLevel: AuditSection;
    restrictNtlmTraffic: AuditSection;
    anonymousAccess: AuditSection;
  };
  additional: {
    firewallEnabled: AuditSection;
    rdpNlaEnabled: AuditSection;
    credentialGuard: AuditSection;
  };
  users: {
    activeUsers: UserStatus[];
    passwordPolicy: PasswordPolicy;
    isDomainController: boolean;
    domainPolicyDetails?: string;
  };
  removableDevices: {
    usbStorage: AuditSection;
  };
  ntpTime: {
    enabled: 'Yes' | 'No';
    details: string;
    status: 'passed' | 'failed' | 'warning';
  };
  ports?: PortInfo[];
  browserSecurity?: BrowserSecurityCheck;
  physicalDisks?: PhysicalDriveHealth[];
  ldapSpnAudit?: LdapAuditResult;
  wingetAutoUpdate?: {
    status: 'passed' | 'failed' | 'warning';
    installed: boolean;
    details: string;
    upgradeCommand?: string;
  };
}

export interface StorageHealth {
  driveLetter: string;
  mediaType: 'SSD' | 'HDD' | 'NVMe' | string;
  healthStatus: 'Healthy' | 'Warning' | 'Critical' | 'Unknown' | string;
  smartStatus: 'Passed' | 'Degraded' | 'Failing' | string;
  freeSpaceGB: number;
  totalSpaceGB: number;
  freeSpacePercent: number;
  bitLockerStatus: 'Fully Encrypted' | 'Protection Off' | 'Decrypting' | 'Unencrypted' | string;
  // Physical drive S.M.A.R.T Metrics extensions
  friendlyName?: string;
  operationalStatus?: string;
  temperatureC?: number | null;
  wearLevelPercent?: number | null;
  busType?: string;
  serialNumber?: string;
}

export interface Endpoint {
  id: string;
  name: string;
  deviceType?: 'Server' | 'Laptop' | 'Workstation';
  os: string;
  ip: string;
  department?: string;
  bitLocker?: 'Encrypted' | 'Unencrypted';
  defenderEdr?: 'Active' | 'Outdated';
  patchLevel?: 'Up-to-Date' | 'Pending Updates';
  smbStatusText?: string;
  lastScanned: string;
  overallScore: number; // 0 to 100
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  status: 'secure' | 'warning' | 'vulnerable';
  connectionStatus?: 'connected' | 'failed' | 'scanning' | 'unpaired';
  connectionReason?: string;
  rdpPortStatus?: 'Open (3389)' | 'Closed / Blocked';
  winRmStatus?: 'Active' | 'Inactive / Refused';
  rdpStatus?: 'connected' | 'disconnected' | 'failed';
  rdpLatencyHistory?: number[]; // Latency values in ms for last 5 checks (e.g., [18, 22, 19, 25, 20])
  storageHealth?: StorageHealth[];
  physicalDrives?: PhysicalDriveHealth[];
  isRealScan?: boolean;
  verifiedScanType?: 'POWERSHELL_LOCAL_AUDIT' | 'LIVE_NETWORK_PROBE' | 'LOCAL_LAN_SWEEP' | 'DEMO_BASELINE';
  scanSource?: string;
  scanData: SecurityAuditResult;
  firstScanData?: SecurityAuditResult;
  firstScanScore?: number;
  remediatedVulnerabilities?: number[];
  excludedVulnerabilities?: number[];
}

export interface RemediationGuide {
  id: string;
  title: string;
  category: 'SMB' | 'SSL/TLS' | 'NTLM' | 'General';
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  description: string;
  registryPath?: string;
  registryKey?: string;
  registryValue?: string;
  powershellFix: string;
  gpoPath?: string;
  impactAssessment: string;
}
