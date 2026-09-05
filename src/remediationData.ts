import { RemediationGuide, Endpoint } from './types';

export const remediations: RemediationGuide[] = [
  {
    id: 'rem-smb1-disable',
    title: 'Disable SMBv1 Protocol',
    category: 'SMB',
    severity: 'Critical',
    description: 'SMBv1 is an extremely old, deprecated network sharing protocol. It is highly vulnerable to remote code execution (e.g., EternalBlue, Wannacry) and lacks modern security mechanism mitigations.',
    registryPath: 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters',
    registryKey: 'SMB1',
    registryValue: '0 (DWORD)',
    powershellFix: `# Disable SMBv1 server configuration\nSet-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n\n# Optional: Remove Windows feature (requires server reboot)\nif (Get-WindowsFeature -Name FS-SMB1 -ErrorAction SilentlyContinue) {\n    Uninstall-WindowsFeature -Name FS-SMB1 -Remove\n}`,
    gpoPath: 'Computer Configuration -> Policies -> Administrative Templates -> MS Security Guide -> Configure SMBv1 Server (Set to Disabled)',
    impactAssessment: 'Low in modern environments. Very old legacy printers, scanners, or pre-2008 servers might fail to communicate with this endpoint via legacy shares.'
  },
  {
    id: 'rem-smb-sign-require',
    title: 'Enforce SMB Signing Requirements',
    category: 'SMB',
    severity: 'High',
    description: 'Enforcing SMB signing prevents attackers from performing active NTLM Relay attacks on the local subnet. When signing is required, the integrity of each packet is cryptographically proven.',
    registryPath: 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters',
    registryKey: 'RequireSecuritySignature',
    registryValue: '1 (DWORD)',
    powershellFix: `# Configure registry to require SMB server signing\nSet-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord\n\n# Configure global client SMB signing requirements\nSet-SmbClientConfiguration -RequireSecuritySignature $true -Force`,
    gpoPath: 'Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Microsoft network server: Digitally sign communications (always)',
    impactAssessment: 'Minimal memory overhead (<2% host CPU) to perform cryptographic signatures. Safe for all modern corporate setups.'
  },
  {
    id: 'rem-tls10-disable',
    title: 'Disable SSL 3.0, TLS 1.0, and TLS 1.1 Protocols',
    category: 'SSL/TLS',
    severity: 'High',
    description: 'Legacy cryptoprotocols (SSL 3.0, TLS 1.0, TLS 1.1) are deprecated due to deep structural bugs (BEAST, POODLE, ROBOT). Disabling these forces client networks to switch to TLS 1.2 or TLS 1.3.',
    registryPath: 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server',
    registryKey: 'Enabled',
    registryValue: '0 (DWORD)',
    powershellFix: `# Disable TLS 1.0 both Server and Client roles\nNew-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server" -Force\nNew-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server" -Name "Enabled" -Value 0 -PropertyType DWORD -Force\nNew-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server" -Name "DisabledByDefault" -Value 1 -PropertyType DWORD -Force\n\n# Disable TLS 1.1\nNew-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server" -Force\nNew-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server" -Name "Enabled" -Value 0 -PropertyType DWORD -Force`,
    gpoPath: 'Computer Configuration -> Administrative Templates -> Network -> SSL Configuration Settings -> SSL Cipher Suite Order',
    impactAssessment: 'Medium. Users accessing old web apps, legacy IIS/Exchange environments, or using extremely old operating systems (Windows XP/Vista, older Linux/embedded clients) might lose secure connection portals.'
  },
  {
    id: 'rem-ntlm-lvl-5',
    title: 'Restrict LM and NTLMv1 (Raise LMCompatibilityLevel to 5)',
    category: 'NTLM',
    severity: 'High',
    description: 'By raising the LmCompatibilityLevel to 5, the operating system stops responding to legacy LM and NTLMv1 authentication attempts. These protocols have very low complexity limits and can be cracked offline in minutes or hours if captured.',
    registryPath: 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
    registryKey: 'LmCompatibilityLevel',
    registryValue: '5 (DWORD)',
    powershellFix: `# Set LMCompatibilityLevel to 5 (Send NTLMv2 session authentication only. Refuse LM & NTLM)\nSet-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord`,
    gpoPath: 'Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Network security: LAN Manager authentication level (Set to "Send NTLMv2 response only. Refuse LM & NTLM")',
    impactAssessment: 'Medium. Legitimate client workstations that rely on legacy local authentication (non-Domain, or running Windows 7/Server 2008 without updates) may fail to authenticate to resource shares.'
  },
  {
    id: 'rem-anonymous-shares',
    title: 'Block Anonymous Null Session Shares',
    category: 'NTLM',
    severity: 'Medium',
    description: 'Anonymous users (Null Sessions) should not be allowed to probe shared ports or request details about network interfaces under active work directories.',
    registryPath: 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
    registryKey: 'RestrictAnonymous',
    registryValue: '1 (DWORD)',
    powershellFix: `# Set RestrictAnonymous registry to block null sessions\nSet-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord\n\n# Set RestrictAnonymousSAM as well\nSet-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord`,
    gpoPath: 'Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Network security: Restrict anonymous access to Named Pipes and Shares',
    impactAssessment: 'Low. Highly secure; rarely impacts modern domain operations except for legacy discovery protocols.'
  },
  {
    id: 'rem-smb-encrypt',
    title: 'Enable SMB Payload Encryption',
    category: 'SMB',
    severity: 'Medium',
    description: 'Activating SMB encryption safeguards all transaction data and file transport on transit paths from eavesdropping/hostile sniffing. Suitable for high-density environments parsing delicate corporate credentials.',
    registryPath: 'N/A (Active Smb Configuration)',
    powershellFix: `# Enforce global SMB Server Encrypted communications (Server 2012+)\nSet-SmbServerConfiguration -EncryptData $true -Force`,
    gpoPath: 'Computer Configuration -> Policies -> Administrative Templates -> Network -> Lanman Server -> Require Encryption (Set to Enabled)',
    impactAssessment: 'Low-Medium. Legacy clients that do not support SMBv3 (e.g. Windows Server 2008 R2 / Windows 7 or older) will be fully blocked from connecting to these shares.'
  },
  {
    id: 'rem-cred-guard',
    title: 'Enable Windows Defender Credential Guard',
    category: 'General',
    severity: 'Medium',
    description: 'Credential Guard uses virtualization-based security (VBS) to isolate secrets (like NTLM hashes, Kerberos tickets) inside a separate, protected container. This prevents LSASS memory reading exploits (e.g., Mimikatz).',
    registryPath: 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
    registryKey: 'LsaCfgFlags',
    registryValue: '1 (DWORD)',
    powershellFix: `# Enable Credential Guard with UEFI lock\nNew-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Force\nSet-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "LsaCfgFlags" -Value 1 -Type DWord\n\n# Turn on Virtualization Based Security dependencies\nNew-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard" -Force\nSet-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord`,
    gpoPath: 'Computer Configuration -> Administrative Templates -> System -> Device Guard -> Turn On Virtualization Based Security -> Credential Guard Configuration (Set to Enabled with UEFI lock)',
    impactAssessment: 'Low. System hardware must support Virtualization extensions (Intel VT-x/AMD-V) and TPM 2.0. Recommended for modern endpoint fleets.'
  },
  {
    id: 'rem-rdp-nla',
    title: 'Require Network Level Authentication (NLA) for RDP',
    category: 'General',
    severity: 'Medium',
    description: 'NLA requires users to pass corporate authentication hashes and credentials before creating a full visual RDP terminal sandbox. This isolates remote exploits (e.g., BlueKeep) from executing against the unauthenticated graphical shell.',
    registryPath: 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp',
    registryKey: 'UserAuthentication',
    registryValue: '1 (DWORD)',
    powershellFix: `# Enforce RDP Network Level Authentication (NLA) requirement\nSet-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Type DWord`,
    gpoPath: 'Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security -> Require user authentication for remote connections by using Network Level Authentication (Set to Enabled)',
    impactAssessment: 'Low. Non-Windows third-party local RDP terminal wrappers or extremely outdated RDP legacy client consoles may fail to trigger authentication.'
  }
];

export const mockEndpoints: Endpoint[] = [
  {
    id: 'file-srv-01',
    name: 'CORP-FILE-SRV01',
    deviceType: 'Server',
    os: 'Windows Server 2019 Standard',
    ip: '10.140.10.45',
    department: 'Enterprise File Repository',
    bitLocker: 'Encrypted',
    defenderEdr: 'Active',
    patchLevel: 'Up-to-Date',
    smbStatusText: 'SMBv1: Disabled (Safe)',
    lastScanned: '2026-06-22 17:30:12',
    overallScore: 100,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    status: 'secure',
    connectionStatus: 'connected',
    connectionReason: 'Active WinRM / WMI handshake established',
    rdpPortStatus: 'Open (3389)',
    winRmStatus: 'Active',
    rdpStatus: 'connected',
    storageHealth: [
      { driveLetter: 'C:', mediaType: 'NVMe', healthStatus: 'Healthy', smartStatus: 'Passed', freeSpaceGB: 280, totalSpaceGB: 512, freeSpacePercent: 54.6, bitLockerStatus: 'Fully Encrypted', friendlyName: 'Samsung SSD 980 PRO 512GB', temperatureC: 38, wearLevelPercent: 96, operationalStatus: 'OK', busType: 'NVMe', serialNumber: 'S5GXNF0R102938' },
      { driveLetter: 'D:', mediaType: 'SSD', healthStatus: 'Healthy', smartStatus: 'Passed', freeSpaceGB: 1200, totalSpaceGB: 2048, freeSpacePercent: 58.5, bitLockerStatus: 'Fully Encrypted', friendlyName: 'Seagate Exos Enterprise 2TB SSD', temperatureC: 41, wearLevelPercent: 99, operationalStatus: 'OK', busType: 'SATA', serialNumber: 'ZAD29481X' }
    ],
    physicalDrives: [
      { friendlyName: 'Samsung SSD 980 PRO 512GB', mediaType: 'NVMe', healthStatus: 'Healthy', operationalStatus: 'OK', busType: 'NVMe', sizeGB: 512, temperatureC: 38, wearLevelPercent: 96, smartStatus: 'Passed', serialNumber: 'S5GXNF0R102938' },
      { friendlyName: 'Seagate Exos Enterprise 2TB SSD', mediaType: 'SSD', healthStatus: 'Healthy', operationalStatus: 'OK', busType: 'SATA', sizeGB: 2048, temperatureC: 41, wearLevelPercent: 99, smartStatus: 'Passed', serialNumber: 'ZAD29481X' }
    ],
    scanData: {
      hostname: 'CORP-FILE-SRV01',
      osName: 'Windows Server 2019 Standard',
      scanTime: '2026-06-22 17:30:12',
      ipAddresses: ['10.140.10.45'],
      privileges: 'Administrator (Root)',
      physicalDisks: [
        { friendlyName: 'Samsung SSD 980 PRO 512GB', mediaType: 'NVMe', healthStatus: 'Healthy', operationalStatus: 'OK', busType: 'NVMe', sizeGB: 512, temperatureC: 38, wearLevelPercent: 96, smartStatus: 'Passed', serialNumber: 'S5GXNF0R102938' },
        { friendlyName: 'Seagate Exos Enterprise 2TB SSD', mediaType: 'SSD', healthStatus: 'Healthy', operationalStatus: 'OK', busType: 'SATA', sizeGB: 2048, temperatureC: 41, wearLevelPercent: 99, smartStatus: 'Passed', serialNumber: 'ZAD29481X' }
      ],
      smb: {
        smb1Enabled: {
          status: 'passed',
          value: 'Disabled (Safe)',
          details: 'SMBv1 is inactive and verified safe.'
        },
        smbSigningRequired: {
          status: 'passed',
          value: 'Required',
          details: 'SMB Signing is enforced on this server.'
        },
        smbEncryptionEnabled: {
          status: 'passed',
          value: 'Enabled',
          details: 'SMB payload encryption is active.'
        }
      },
      sslTls: {
        tls10Enabled: { status: 'passed', value: 'Disabled', details: 'TLS 1.0 is disabled.' },
        tls11Enabled: { status: 'passed', value: 'Disabled', details: 'TLS 1.1 is disabled.' },
        tls12Enabled: { status: 'passed', value: 'Enabled', details: 'TLS 1.2 is enabled.' },
        tls13Enabled: { status: 'passed', value: 'Enabled', details: 'TLS 1.3 is enabled.' },
        weakCipherSuites: { status: 'passed', value: 'Strict list', details: 'No weak ciphers present.' }
      },
      ntlm: {
        lmCompatibilityLevel: { status: 'passed', value: 'Level 5', details: 'Refuse LM & NTLMv1.' },
        restrictNtlmTraffic: { status: 'passed', value: 'Restricted', details: 'NTLM traffic restricted.' },
        anonymousAccess: { status: 'passed', value: 'Disabled', details: 'Anonymous access prohibited.' }
      },
      additional: {
        firewallEnabled: { status: 'passed', value: 'Enabled', details: 'Firewall active on all profiles.' },
        rdpNlaEnabled: { status: 'passed', value: 'NLA Required', details: 'NLA enforced on RDP.' },
        credentialGuard: { status: 'passed', value: 'Enabled', details: 'Credential Guard active.' }
      },
      users: {
        activeUsers: [
          { username: 'Administrator', status: 'Active', lastPasswordChange: '2026-06-10 09:12:33', passwordAgeDays: 14, passwordNeverExpires: false },
          { username: 'LocalAdmin', status: 'Active', lastPasswordChange: '2026-06-12 11:30:00', passwordAgeDays: 11, passwordNeverExpires: false }
        ],
        passwordPolicy: { minimumLength: 14, complexityEnabled: true, maximumAgeDays: 90, minimumAgeDays: 1, historyCount: 24 },
        isDomainController: false
      },
      removableDevices: {
        usbStorage: { status: 'passed', value: 'BLOCKED', details: 'USB Storage disabled.' }
      },
      ntpTime: { enabled: 'Yes', details: 'Time synced via domain hierarchy.', status: 'passed' },
      ports: [
        { port: 22, protocol: 'TCP', service: 'SSH', status: 'Closed', severity: 'Secure' },
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
  },
  {
    id: 'corp-dc-01',
    name: 'CORP-AD-DC-01',
    deviceType: 'Server',
    os: 'Windows Server 2022 Active Directory DC',
    ip: '10.140.10.10',
    department: 'Domain Identity / Core AD',
    bitLocker: 'Encrypted',
    defenderEdr: 'Active',
    patchLevel: 'Up-to-Date',
    smbStatusText: 'SMBv1: Disabled (Safe)',
    lastScanned: '2026-06-23 06:10:05',
    overallScore: 92,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 2,
    lowCount: 1,
    status: 'secure',
    rdpStatus: 'connected',
    storageHealth: [
      { driveLetter: 'C:', mediaType: 'NVMe', healthStatus: 'Healthy', smartStatus: 'Passed', freeSpaceGB: 410, totalSpaceGB: 1024, freeSpacePercent: 40.0, bitLockerStatus: 'Fully Encrypted', friendlyName: 'Intel Optane SSD P5800X 1TB', temperatureC: 34, wearLevelPercent: 98, operationalStatus: 'OK', busType: 'NVMe', serialNumber: 'PHKC2019481' }
    ],
    physicalDrives: [
      { friendlyName: 'Intel Optane SSD P5800X 1TB', mediaType: 'NVMe', healthStatus: 'Healthy', operationalStatus: 'OK', busType: 'NVMe', sizeGB: 1024, temperatureC: 34, wearLevelPercent: 98, smartStatus: 'Passed', serialNumber: 'PHKC2019481' }
    ],
    scanData: {
      hostname: 'CORP-AD-DC-01',
      osName: 'Windows Server 2022 Active Directory DC',
      scanTime: '2026-06-23 06:10:05',
      ipAddresses: ['10.140.10.10'],
      privileges: 'Enterprise Administrator (Primary DC)',
      physicalDisks: [
        { friendlyName: 'Intel Optane SSD P5800X 1TB', mediaType: 'NVMe', healthStatus: 'Healthy', operationalStatus: 'OK', busType: 'NVMe', sizeGB: 1024, temperatureC: 34, wearLevelPercent: 98, smartStatus: 'Passed', serialNumber: 'PHKC2019481' }
      ],
      smb: {
        smb1Enabled: {
          status: 'passed',
          value: 'Disabled (Safe)',
          details: 'SMBv1 is disabled completely across standard DC configurations.'
        },
        smbSigningRequired: {
          status: 'passed',
          value: 'Required (DC GPO Policy)',
          details: 'SMB Signing is demanded on the DC to authenticate file-sharing requests securely.'
        },
        smbEncryptionEnabled: {
          status: 'warning',
          value: 'Disabled',
          details: 'SMB packet encryption is disabled, recommended to enforce for secure Sysvol sharing.'
        }
      },
      sslTls: {
        tls10Enabled: { status: 'passed', value: 'Disabled', details: 'TLS 1.0 is disabled, protecting Active Directory LDAP/S channels.' },
        tls11Enabled: { status: 'passed', value: 'Disabled', details: 'TLS 1.1 is audited as inactive.' },
        tls12Enabled: { status: 'passed', value: 'Enabled', details: 'TLS 1.2 is active as standard communication wrapper.' },
        tls13Enabled: { status: 'passed', value: 'Enabled', details: 'TLS 1.3 is enabled in AD SCHANNEL parameters.' },
        weakCipherSuites: { status: 'passed', value: 'Pristine cryptoproviders', details: 'Only secure cipher suites are permitted.' }
      },
      ntlm: {
        lmCompatibilityLevel: { status: 'passed', value: 'Level 5: Refuse LM & NTLMv1, accept only NTLMv2 (Secure)', details: 'Active Directory enforces Level 5 blocks.' },
        restrictNtlmTraffic: { status: 'warning', value: 'Not Restricted', details: 'NTLM fallback traffic is still allowed on the domain path.' },
        anonymousAccess: { status: 'passed', value: 'Disabled', details: 'Anonymous access to Active Directory domain controller discovery interfaces is locked.' }
      },
      additional: {
        firewallEnabled: { status: 'passed', value: 'Enabled', details: 'Domain controller policies enforce rigorous inbound rules block.' },
        rdpNlaEnabled: { status: 'passed', value: 'NLA Required', details: 'RDP is protected via network level authentication gating.' },
        credentialGuard: { status: 'passed', value: 'Enabled (LSA Isolation)', details: 'Active Directory credentials isolated in secure hypervisor container.' }
      },
      users: {
        activeUsers: [
          { username: 'DomainAdmin', status: 'Active', lastPasswordChange: '2026-06-15 08:00:00', passwordAgeDays: 8, passwordNeverExpires: false },
          { username: 'EnterpriseSvc', status: 'Active', lastPasswordChange: '2025-05-30 11:22:00', passwordAgeDays: 389, passwordNeverExpires: true }
        ],
        passwordPolicy: { minimumLength: 14, complexityEnabled: true, maximumAgeDays: 90, minimumAgeDays: 1, historyCount: 24 },
        isDomainController: true,
        domainPolicyDetails: 'AD Default Domain Password Policy enforces strong password filters.'
      },
      removableDevices: {
        usbStorage: { status: 'passed', value: 'FULLY RESTRICTED', details: 'GPO registry locks block USB drives entirely on AD limits.' }
      },
      ntpTime: { enabled: 'Yes', details: 'NTP Time Sync is Active (Yes). Synchronizing with GPS Hardware Master Clock NTP source.', status: 'passed' },
      ports: [
        { port: 53, protocol: 'UDP', service: 'domain', status: 'Open', severity: 'Secure', vulnerabilityDetails: 'Active Directory DNS Resolver is active.' },
        { port: 88, protocol: 'TCP', service: 'kerberos', status: 'Open', severity: 'Secure', vulnerabilityDetails: 'Domain-wide Kerberos Key Distribution Center is active.' },
        { port: 135, protocol: 'TCP', service: 'msrpc', status: 'Open', severity: 'Secure' },
        { port: 389, protocol: 'TCP', service: 'ldap', status: 'Open', severity: 'Weak', vulnerabilityDetails: 'Unencrypted LDAP service active. Group policies should enforce LDAP signing.' },
        { port: 445, protocol: 'TCP', service: 'microsoft-ds', status: 'Open', severity: 'Secure', vulnerabilityDetails: 'Active Directory SYSVOL and Netlogon shares. Pre-req SMBsigning holds secure.' },
        { port: 636, protocol: 'TCP', service: 'ldaps', status: 'Open', severity: 'Secure', vulnerabilityDetails: 'LDAP over TLS (Secure LDAP) is active.' }
      ],
      browserSecurity: {
        chromePasswordStore: { status: 'passed', value: 'DISABLED', details: 'Chrome password vaults locked down by AD GPO Registry configuration.' },
        chromeHistoryAllowed: { status: 'passed', value: 'DISABLED', details: 'Chrome history and cache deletion on close is successfully enforced.' },
        edgePasswordStore: { status: 'passed', value: 'DISABLED', details: 'Microsoft Edge password caching deactivated globally.' },
        edgeHistoryAllowed: { status: 'passed', value: 'DISABLED', details: 'Edge history logging disabled completely for Active Directory users.' },
        firefoxPasswordStore: { status: 'passed', value: 'DISABLED', details: 'Mozilla Firefox policies loaded via policies.json.' },
        firefoxHistoryAllowed: { status: 'passed', value: 'DISABLED', details: 'Firefox browsing history logging disabled.' }
      },
      ldapSpnAudit: {
        status: 'warning',
        details: 'Active Directory LDAP query identified 3 accounts configured with Service Principal Names (SPNs). Potential Kerberoasting target surface.',
        commandExecuted: 'Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires | Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet, PasswordNeverExpires',
        accounts: [
          { samAccountName: 'svc_mssql_prod', servicePrincipalName: 'MSSQLSvc/CORP-DB-SRV-PRD12.corp.domain.com:1433', passwordLastSet: '2024-01-15 10:20:00', passwordNeverExpires: true },
          { samAccountName: 'EnterpriseSvc', servicePrincipalName: 'HTTP/sso.corp.domain.com, HOST/sso.corp.domain.com', passwordLastSet: '2023-11-02 14:05:12', passwordNeverExpires: true },
          { samAccountName: 'svc_iis_apppool', servicePrincipalName: 'HTTP/app.corp.domain.com', passwordLastSet: '2025-06-10 09:12:00', passwordNeverExpires: false }
        ]
      }
    }
  },
  {
    id: 'db-srv-prd-12',
    name: 'CORP-DB-SRV-PRD12',
    deviceType: 'Server',
    os: 'Windows Server 2022 Datacenter',
    ip: '10.140.10.82',
    department: 'Database Operations',
    bitLocker: 'Encrypted',
    defenderEdr: 'Active',
    patchLevel: 'Up-to-Date',
    smbStatusText: 'SMBv1: Disabled (Safe)',
    lastScanned: '2026-06-23 01:15:44',
    overallScore: 88,
    criticalCount: 0,
    highCount: 1,
    mediumCount: 2,
    lowCount: 1,
    status: 'warning',
    rdpStatus: 'connected',
    storageHealth: [
      { driveLetter: 'C:', mediaType: 'NVMe', healthStatus: 'Healthy', smartStatus: 'Passed', freeSpaceGB: 180, totalSpaceGB: 512, freeSpacePercent: 35.1, bitLockerStatus: 'Fully Encrypted', friendlyName: 'Micron 7450 PRO 512GB NVMe', temperatureC: 44, wearLevelPercent: 91, operationalStatus: 'OK', busType: 'NVMe', serialNumber: '22143F291B01' },
      { driveLetter: 'E:', mediaType: 'HDD', healthStatus: 'Warning', smartStatus: 'Degraded', freeSpaceGB: 450, totalSpaceGB: 4096, freeSpacePercent: 11.0, bitLockerStatus: 'Fully Encrypted', friendlyName: 'WD Gold 4TB Enterprise HDD', temperatureC: 49, wearLevelPercent: 78, operationalStatus: 'Degraded, Predictive Failure', busType: 'SAS', serialNumber: 'WCC7K5DFR102' }
    ],
    physicalDrives: [
      { friendlyName: 'Micron 7450 PRO 512GB NVMe', mediaType: 'NVMe', healthStatus: 'Healthy', operationalStatus: 'OK', busType: 'NVMe', sizeGB: 512, temperatureC: 44, wearLevelPercent: 91, smartStatus: 'Passed', serialNumber: '22143F291B01' },
      { friendlyName: 'WD Gold 4TB Enterprise HDD', mediaType: 'HDD', healthStatus: 'Warning', operationalStatus: 'Degraded, Predictive Failure', busType: 'SAS', sizeGB: 4096, temperatureC: 49, wearLevelPercent: 78, smartStatus: 'Degraded', serialNumber: 'WCC7K5DFR102' }
    ],
    scanData: {
      hostname: 'CORP-DB-SRV-PRD12',
      osName: 'Windows Server 2022 Datacenter',
      scanTime: '2026-06-23 01:15:44',
      ipAddresses: ['10.140.10.82'],
      privileges: 'Administrator (Root)',
      physicalDisks: [
        { friendlyName: 'Micron 7450 PRO 512GB NVMe', mediaType: 'NVMe', healthStatus: 'Healthy', operationalStatus: 'OK', busType: 'NVMe', sizeGB: 512, temperatureC: 44, wearLevelPercent: 91, smartStatus: 'Passed', serialNumber: '22143F291B01' },
        { friendlyName: 'WD Gold 4TB Enterprise HDD', mediaType: 'HDD', healthStatus: 'Warning', operationalStatus: 'Degraded, Predictive Failure', busType: 'SAS', sizeGB: 4096, temperatureC: 49, wearLevelPercent: 78, smartStatus: 'Degraded', serialNumber: 'WCC7K5DFR102' }
      ],
      smb: {
        smb1Enabled: { status: 'passed', value: 'Disabled (Safe)', details: 'SMBv1 is inactive.' },
        smbSigningRequired: { status: 'passed', value: 'Required', details: 'SMB Signing is required on this system.' },
        smbEncryptionEnabled: { status: 'warning', value: 'Disabled', details: 'SMB payload encryption is disabled.' }
      },
      sslTls: {
        tls10Enabled: { status: 'passed', value: 'Disabled', details: 'TLS 1.0 is disabled.' },
        tls11Enabled: { status: 'passed', value: 'Disabled', details: 'TLS 1.1 is audited as inactive.' },
        tls12Enabled: { status: 'passed', value: 'Enabled', details: 'TLS 1.2 is enabled.' },
        tls13Enabled: { status: 'passed', value: 'Enabled', details: 'TLS 1.3 is enabled.' },
        weakCipherSuites: { status: 'passed', value: 'Strict cipher suite list active', details: 'No legacy cipher suites loaded.' }
      },
      ntlm: {
        lmCompatibilityLevel: { status: 'warning', value: 'Level 3: Send NTLMv2 only', details: 'NTLMv1 may still be accepted by the endpoint.' },
        restrictNtlmTraffic: { status: 'warning', value: 'Not Restricted', details: 'NTLM allowed outbound.' },
        anonymousAccess: { status: 'passed', value: 'Disabled', details: 'Anonymous remote null session shares prohibited.' }
      },
      additional: {
        firewallEnabled: { status: 'passed', value: 'Enabled', details: 'Host Defender Firewall active.' },
        rdpNlaEnabled: { status: 'passed', value: 'NLA Required', details: 'RDP requires NLA.' },
        credentialGuard: { status: 'passed', value: 'Enabled (LSA Isolation)', details: 'Credential Guard isolates secrets.' }
      },
      users: {
        activeUsers: [
          { username: 'DbaAdmin', status: 'Active', lastPasswordChange: '2026-06-11 08:44:11', passwordAgeDays: 12, passwordNeverExpires: false },
          { username: 'SvcDbConnector', status: 'Active', lastPasswordChange: '2025-05-19 12:00:00', passwordAgeDays: 400, passwordNeverExpires: true }
        ],
        passwordPolicy: { minimumLength: 14, complexityEnabled: true, maximumAgeDays: 60, minimumAgeDays: 1, historyCount: 24 },
        isDomainController: false
      },
      removableDevices: {
        usbStorage: { status: 'passed', value: 'BLOCKED', details: 'USB storage blocked.' }
      },
      ntpTime: { enabled: 'Yes', details: 'NTP Time Sync active.', status: 'passed' },
      ports: [
        { port: 21, protocol: 'TCP', service: 'FTP', status: 'Closed', severity: 'Secure' },
        { port: 22, protocol: 'TCP', service: 'SSH', status: 'Open', severity: 'Secure' },
        { port: 1433, protocol: 'TCP', service: 'ms-sql-s', status: 'Open', severity: 'Secure' }
      ],
      browserSecurity: {
        chromePasswordStore: { status: 'passed', value: 'DISABLED', details: 'Chrome password store disabled.' },
        chromeHistoryAllowed: { status: 'failed', value: 'ALLOWED', details: 'Chrome history active.' },
        edgePasswordStore: { status: 'passed', value: 'DISABLED', details: 'Edge password store disabled.' },
        edgeHistoryAllowed: { status: 'passed', value: 'DISABLED', details: 'Edge history deletion enforced.' },
        firefoxPasswordStore: { status: 'failed', value: 'ENABLED', details: 'Firefox password store active.' },
        firefoxHistoryAllowed: { status: 'failed', value: 'ALLOWED', details: 'Firefox history active.' }
      }
    }
  },
  {
    id: 'win-ws-104',
    name: 'CORP-WIN10-WS104',
    deviceType: 'Workstation',
    os: 'Windows 10 Enterprise',
    ip: '10.140.20.104',
    department: 'Corporate Endpoints',
    bitLocker: 'Unencrypted',
    defenderEdr: 'Outdated',
    patchLevel: 'Pending Updates',
    smbStatusText: 'SMBv1: ENABLED (Vuln)',
    lastScanned: '2026-06-23 05:22:10',
    overallScore: 68,
    criticalCount: 1,
    highCount: 1,
    mediumCount: 4,
    lowCount: 1,
    status: 'warning',
    rdpStatus: 'failed',
    storageHealth: [
      { driveLetter: 'C:', mediaType: 'SSD', healthStatus: 'Warning', smartStatus: 'Degraded', freeSpaceGB: 85, totalSpaceGB: 256, freeSpacePercent: 33.2, bitLockerStatus: 'Protection Off', friendlyName: 'Kingston A400 256GB SSD', temperatureC: 48, wearLevelPercent: 42, operationalStatus: 'OK', busType: 'SATA', serialNumber: '50026B768391' }
    ],
    physicalDrives: [
      { friendlyName: 'Kingston A400 256GB SSD', mediaType: 'SSD', healthStatus: 'Warning', operationalStatus: 'OK', busType: 'SATA', sizeGB: 256, temperatureC: 48, wearLevelPercent: 42, smartStatus: 'Degraded', serialNumber: '50026B768391' }
    ],
    scanData: {
      hostname: 'CORP-WIN10-WS104',
      osName: 'Windows 10 Enterprise',
      scanTime: '2026-06-23 05:22:10',
      ipAddresses: ['10.140.20.104'],
      privileges: 'Standard User (Limited)',
      physicalDisks: [
        { friendlyName: 'Kingston A400 256GB SSD', mediaType: 'SSD', healthStatus: 'Warning', operationalStatus: 'OK', busType: 'SATA', sizeGB: 256, temperatureC: 48, wearLevelPercent: 42, smartStatus: 'Degraded', serialNumber: '50026B768391' }
      ],
      smb: {
        smb1Enabled: {
          status: 'failed',
          value: 'Enabled',
          details: 'SMBv1 is active. This outdated protocol is vulnerable to Wannacry, EternalBlue, and remote code execution.'
        },
        smbSigningRequired: {
          status: 'warning',
          value: 'Not Required',
          details: 'SMB Signing is not enforced. An attacker could intercept and relay your SMB credentials.'
        },
        smbEncryptionEnabled: {
          status: 'warning',
          value: 'Disabled',
          details: 'SMB payload encryption is disabled, making files sent over the wire readable in plain text.'
        }
      },
      sslTls: {
        tls10Enabled: { status: 'passed', value: 'Disabled', details: 'TLS 1.0 is disabled.' },
        tls11Enabled: { status: 'passed', value: 'Disabled', details: 'TLS 1.1 is active.' },
        tls12Enabled: { status: 'passed', value: 'Enabled', details: 'TLS 1.2 is enabled.' },
        tls13Enabled: { status: 'warning', value: 'Disabled by Default', details: 'TLS 1.3 not configured.' },
        weakCipherSuites: { status: 'passed', value: 'No weak ciphers active', details: 'No legacy cipher suites loaded.' }
      },
      ntlm: {
        lmCompatibilityLevel: { status: 'warning', value: 'Level 3: Send NTLMv2 only', details: 'NTLMv1 may still be accepted.' },
        restrictNtlmTraffic: { status: 'warning', value: 'Not Restricted', details: 'NTLM allowed.' },
        anonymousAccess: { status: 'passed', value: 'Disabled', details: 'Anonymous access prohibited.' }
      },
      additional: {
        firewallEnabled: { status: 'warning', value: 'Disabled Profiles: Public', details: 'Windows Firewall profile deactivated.' },
        rdpNlaEnabled: { status: 'passed', value: 'NLA Required', details: 'Remote Desktop requires NLA.' },
        credentialGuard: { status: 'warning', value: 'Disabled', details: 'Credential Guard inactive.' }
      },
      users: {
        activeUsers: [
          { username: 'UserWorkstation', status: 'Active', lastPasswordChange: '2026-01-15 10:20:00', passwordAgeDays: 159, passwordNeverExpires: false },
          { username: 'TikUserStandard', status: 'Active', lastPasswordChange: '2026-05-19 14:02:11', passwordAgeDays: 35, passwordNeverExpires: true }
        ],
        passwordPolicy: { minimumLength: 7, complexityEnabled: false, maximumAgeDays: 42, minimumAgeDays: 0, historyCount: 0 },
        isDomainController: false
      },
      removableDevices: {
        usbStorage: { status: 'warning', value: 'READ-ONLY', details: 'USB storage restricted to Read-Only.' }
      },
      ntpTime: { enabled: 'Yes', details: 'Clock synced via time.windows.com.', status: 'passed' },
      ports: [
        { port: 80, protocol: 'TCP', service: 'HTTP', status: 'Open', severity: 'Weak', vulnerabilityDetails: 'Local web server running IIS.' },
        { port: 445, protocol: 'TCP', service: 'microsoft-ds', status: 'Open', severity: 'Secure' }
      ],
      browserSecurity: {
        chromePasswordStore: { status: 'failed', value: 'ENABLED', details: 'Chrome allows credential retention.' },
        chromeHistoryAllowed: { status: 'failed', value: 'ALLOWED', details: 'Standard history records active.' },
        edgePasswordStore: { status: 'failed', value: 'ENABLED', details: 'Edge password manager enabled.' },
        edgeHistoryAllowed: { status: 'failed', value: 'ALLOWED', details: 'Edge history logs allowed.' },
        firefoxPasswordStore: { status: 'failed', value: 'ENABLED', details: 'Firefox credentials saving permitted.' },
        firefoxHistoryAllowed: { status: 'failed', value: 'ALLOWED', details: 'Firefox history tracking enabled.' }
      }
    }
  }
];

export function calculateEndpointScore(data: Endpoint['scanData']): number {
  let scoreOfItem = 100;
  
  // Weights of failing crucial checks
  if (data.smb.smb1Enabled.status === 'failed') scoreOfItem -= 20;
  if (data.smb.smbSigningRequired.status === 'warning') scoreOfItem -= 15;
  if (data.smb.smbEncryptionEnabled.status === 'warning') scoreOfItem -= 5;
  
  if (data.sslTls.tls10Enabled.status === 'failed') scoreOfItem -= 15;
  if (data.sslTls.tls11Enabled.status === 'failed') scoreOfItem -= 10;
  if (data.sslTls.weakCipherSuites.status === 'failed') scoreOfItem -= 15;
  if (data.sslTls.tls12Enabled.status === 'warning') scoreOfItem -= 5;
  
  // Ntlm
  if (data.ntlm.lmCompatibilityLevel.status === 'failed') {
    scoreOfItem -= 20;
  } else if (data.ntlm.lmCompatibilityLevel.status === 'warning') {
    scoreOfItem -= 8;
  }
  if (data.ntlm.restrictNtlmTraffic.status === 'warning') scoreOfItem -= 5;
  if (data.ntlm.anonymousAccess.status === 'failed') scoreOfItem -= 10;
  
  // Additional
  if (data.additional.firewallEnabled.status === 'warning') scoreOfItem -= 10;
  if (data.additional.rdpNlaEnabled.status === 'warning') scoreOfItem -= 8;
  if (data.additional.credentialGuard.status === 'warning') scoreOfItem -= 7;

  // New audits impact
  if (data.removableDevices && data.removableDevices.usbStorage.status === 'failed') scoreOfItem -= 8;
  if (data.ntpTime && data.ntpTime.status === 'failed') scoreOfItem -= 5;

  // Browser security impact
  if (data.browserSecurity) {
    if (data.browserSecurity.chromePasswordStore.status === 'failed') scoreOfItem -= 8;
    if (data.browserSecurity.chromeHistoryAllowed.status === 'failed') scoreOfItem -= 5;
    if (data.browserSecurity.edgePasswordStore.status === 'failed') scoreOfItem -= 8;
    if (data.browserSecurity.edgeHistoryAllowed.status === 'failed') scoreOfItem -= 5;
    if (data.browserSecurity.firefoxPasswordStore.status === 'failed') scoreOfItem -= 8;
    if (data.browserSecurity.firefoxHistoryAllowed.status === 'failed') scoreOfItem -= 5;
  }

  // Password policy checks
  if (data.users && data.users.passwordPolicy.minimumLength < 8) scoreOfItem -= 5;
  if (data.users && !data.users.passwordPolicy.complexityEnabled) scoreOfItem -= 5;

  return Math.max(0, scoreOfItem);
}

export function parseCounts(data: Endpoint['scanData']) {
  let crits = 0;
  let highs = 0;
  let meds = 0;
  let lows = 0;

  // SMB1, TLS 1.0, LM Level <=1 represent critical exploits
  if (data.smb.smb1Enabled.status === 'failed') crits++;
  if (data.sslTls.tls10Enabled.status === 'failed') crits++;
  if (data.ntlm.lmCompatibilityLevel.status === 'failed') crits++;

  // SMB signing, weak cipher, RDP without NLA, LM Level warning, USB allowed, browser password storage
  if (data.smb.smbSigningRequired.status === 'warning') highs++;
  if (data.sslTls.tls11Enabled.status === 'failed') highs++;
  if (data.sslTls.weakCipherSuites.status === 'failed') highs++;
  if (data.ntlm.restrictNtlmTraffic.status === 'warning') highs++;
  if (data.removableDevices?.usbStorage.status === 'failed') highs++;
  
  if (data.browserSecurity) {
    if (data.browserSecurity.chromePasswordStore.status === 'failed') highs++;
    if (data.browserSecurity.edgePasswordStore.status === 'failed') highs++;
    if (data.browserSecurity.firefoxPasswordStore.status === 'failed') highs++;
  }

  // SMB encrypt, Credential guard, RDP NLA warn, USB read-only, NTP missing, browser history allowed
  if (data.additional.rdpNlaEnabled.status === 'warning') meds++;
  if (data.additional.credentialGuard.status === 'warning') meds++;
  if (data.additional.firewallEnabled.status === 'warning') meds++;
  if (data.ntpTime?.status === 'failed') meds++;

  if (data.browserSecurity) {
    if (data.browserSecurity.chromeHistoryAllowed.status === 'failed') meds++;
    if (data.browserSecurity.edgeHistoryAllowed.status === 'failed') meds++;
    if (data.browserSecurity.firefoxHistoryAllowed.status === 'failed') meds++;
  }

  // Anonymous shares, TLS 1.3 missing
  if (data.sslTls.tls13Enabled.status === 'warning') lows++;
  if (data.smb.smbEncryptionEnabled.status === 'warning') lows++;

  return { crits, highs, meds, lows };
}
