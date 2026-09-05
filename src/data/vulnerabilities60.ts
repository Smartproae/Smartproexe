import { Endpoint } from '../types';

export interface Vulnerability60 {
  id: number;
  name: string;
  cveId: string;
  category: 'SMB Security' | 'SSL/TLS Protocols' | 'Network Integrity' | 'OS / Active Directory' | 'Device / Software Policies';
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  description: string;
  powershellFix: string;
  impactWarning: string;
  remedyCode: string;
  remedyValue: string;
}

export const VULNERABILITIES_60_DATABASE: Vulnerability60[] = [
  {
    id: 1,
    name: "SMB Signing Not Enabled",
    cveId: "GPO-SMB-001",
    category: "SMB Security",
    severity: "High",
    description: "SMB digital packet signing is not actively configured on the host. When signing is inactive, network peers cannot verify whether incoming SMB packets have been modified in transit.",
    powershellFix: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'EnableSecuritySignature' -Value 1 -Type DWord -Force",
    impactWarning: "EXTREMELY LOW. Safe to implement. Only active signatures will be supplied. Rarely affects performance (<1.5% CPU overhead).",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
    remedyValue: "EnableSecuritySignature = 1 (DWORD)"
  },
  {
    id: 2,
    name: "SMB Signing Not Required",
    cveId: "GPO-SMB-002",
    category: "SMB Security",
    severity: "High",
    description: "SMB Server signing requirements are not enforced. Even if digital signing is supported, connections can fall back to clear text headers or unsigned packets, enabling MITM interceptions.",
    powershellFix: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type DWord -Force\nSet-SmbClientConfiguration -RequireSecuritySignature $true -Force",
    impactWarning: "LOW RISK. Legacy clients running Windows XP, Windows 2000, or ancient Linux samba configurations will fail to connect. Modern OS endpoints (Win 10/11, Server 2012+) operate with this natively.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
    remedyValue: "RequireSecuritySignature = 1 (DWORD)"
  },
  {
    id: 3,
    name: "SMB Relay Attack Exposure",
    cveId: "GPO-SMB-003",
    category: "SMB Security",
    severity: "High",
    description: "Without enforced client-side signing and LLMNR/NBT-NS deactivation, local routers can be spoofed to capture credentials and relay them immediately to access corporate storage shares.",
    powershellFix: "# Require Client & Server security signatures\nSet-SmbClientConfiguration -RequireSecuritySignature $true -Force\n# Turn off multicast name resolution to stop LLMNR spoofing\nNew-Item -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force\nSet-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -Value 0 -Type DWord -Force",
    impactWarning: "LOW RISK. Deactivating LLMNR name resolution may cause single-label names (like a local host without full FQDN) to fail resolution if local DNS lacks updated pointers.",
    remedyCode: "HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient",
    remedyValue: "EnableMulticast = 0 (DWORD) + enforce client signing"
  },
  {
    id: 4,
    name: "SMBv1 Protocol Enabled",
    cveId: "CVE-2017-0144",
    category: "SMB Security",
    severity: "Critical",
    description: "Legacy SMBv1 protocol is active in system drivers. Contains structural heap overflow vulnerabilities exploited by EternalBlue, WannaCry, and DoublePulsar backdoor payloads.",
    powershellFix: "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\nDisable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart",
    impactWarning: "CRITICAL OPERATIONAL WARNING: Disabling SMBv1 will completely block old printers, legacy fax scanners, and ancient Windows XP / Server 2003 machines from reading or writing files to this host's directories.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
    remedyValue: "SMB1 = 0 (DWORD)"
  },
  {
    id: 5,
    name: "SMBGhost Vulnerability Exposure (CVE-2020-0796)",
    cveId: "CVE-2020-0796",
    category: "SMB Security",
    severity: "Critical",
    description: "Active compression routines in SMBv3.1.1 on outdated hosts allow arbitrary remote code execution via malformed buffer offsets on port 445.",
    powershellFix: "# Disable SMBv3.1.1 compression routines to prevent pre-auth remote exploits\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'DisableCompression' -Value 1 -Type DWord -Force",
    impactWarning: "MINIMAL IMPACT. Safe to deploy. Forces uncompressed SMB packet exchange which negligibly increases network traffic payload size.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
    remedyValue: "DisableCompression = 1 (DWORD)"
  },
  {
    id: 6,
    name: "Anonymous SMB Access Allowed (Null Sessions)",
    cveId: "GPO-SMB-006",
    category: "SMB Security",
    severity: "Medium",
    description: "Unauthenticated guest accounts or null session connections are allowed to bind to IPC$ shares, providing access to host properties without credentials.",
    powershellFix: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RestrictAnonymous' -Value 1 -Type DWord -Force\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RestrictAnonymousSAM' -Value 1 -Type DWord -Force",
    impactWarning: "LOW RISK. Legacy server discovery tools or non-domain external monitors might fail to retrieve initial service configurations.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
    remedyValue: "RestrictAnonymous = 1 (DWORD)"
  },
  {
    id: 7,
    name: "Unauthenticated Share Enumeration",
    cveId: "GPO-SMB-007",
    category: "SMB Security",
    severity: "Medium",
    description: "Unauthenticated remote users can retrieve lists of all hosted directories, revealing organizational architecture and folder targets to unauthorized personnel.",
    powershellFix: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'EveryoneIncludesAnonymous' -Value 0 -Type DWord -Force\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'NullSessionShares' -Value @() -Type MultiString -Force",
    impactWarning: "LOW RISK. Fully prevents unauthenticated discovery tools from enumerating names of available storage groups.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
    remedyValue: "EveryoneIncludesAnonymous = 0"
  },
  {
    id: 8,
    name: "Excessive SMB Share Permissions",
    cveId: "GPO-SMB-008",
    category: "SMB Security",
    severity: "Medium",
    description: "Security descriptors on network shares are set to 'Everyone: Full Control', which overrides NTFS permissions or allows lateral traversal.",
    powershellFix: "# Replace high-exposure everyone shares with restricted Authenticated Users credentials\n# Command executes audits and deletes unneeded Everyone maps, replacing with strict ACLs\nGet-SmbShare | Where-Object { $_.Name -notmatch 'IPC\\$|NETLOGON|SYSVOL' } | ForEach-Object {\n    Revoke-SmbShareAccess -Name $_.Name -AccountName 'Everyone' -Force -ErrorAction SilentlyContinue\n    Grant-SmbShareAccess -Name $_.Name -AccountName 'Authenticated Users' -AccessRight Change -Force -ErrorAction SilentlyContinue\n}",
    impactWarning: "MEDIUM OPERATIONAL WARNING: Disabling 'Everyone' share permissions might block custom local service accounts, specialized automation script logins, or external un-managed nodes.",
    remedyCode: "SMB Share Security DACL",
    remedyValue: "Replace 'Everyone' with 'Authenticated Users'"
  },
  {
    id: 9,
    name: "Unrestricted File Share Access",
    cveId: "GPO-SMB-009",
    category: "SMB Security",
    severity: "Medium",
    description: "Corporate files, system drivers, and executable files are readable by domain users due to lacks of Access-Based Enumeration (ABE) on standard volumes.",
    powershellFix: "# Enable Access-Based Enumeration. Users only see folders they have NTFS permissions for.\nGet-SmbShare | Where-Object { $_.Special -eq $false } | ForEach-Object {\n    Set-SmbShare -Name $_.Name -FolderEnumerationMode AccessBased -Force -ErrorAction SilentlyContinue\n}",
    impactWarning: "LOW RISK / HIGHLY SECURE. Safe to implement. Users might ask why some files 'disappeared' because they can no longer see folders they lacked permissions for.",
    remedyCode: "SMB Share Parameters",
    remedyValue: "FolderEnumerationMode = AccessBased"
  },
  {
    id: 10,
    name: "SMB Service Accessible from Untrusted Networks",
    cveId: "GPO-SMB-010",
    category: "SMB Security",
    severity: "High",
    description: "Direct host port 445 is exposed to non-corporate subnets or directly to public internet without host-based firewall segmentation restrictions.",
    powershellFix: "New-NetFirewallRule -DisplayName 'Restrict SMB Port 445 Inbound' -Direction Inbound -Action Block -LocalPort 445 -Protocol TCP -RemoteAddress 'Internet' -Force",
    impactWarning: "MEDIUM RISK: Blocking port 445 globally will disrupt external VPN-less employees from connecting directly to their shared volumes. Ensure correct corporate subnets are white-listed before deployment.",
    remedyCode: "Defender NetFirewallRule",
    remedyValue: "Block Port 445 from RemoteAddress 'Internet'"
  },
  {
    id: 11,
    name: "SMB Encryption Not Enabled",
    cveId: "GPO-SMB-011",
    category: "SMB Security",
    severity: "Medium",
    description: "Network traffic traversing active shares is sent unencrypted over port 445, exposing files, documents, and credentials to passive ethernet sniffing.",
    powershellFix: "Set-SmbServerConfiguration -EncryptData $true -Force",
    impactWarning: "OPERATIONAL DISRUPTION RISK: Enforcing encryption will immediately disconnect and permanently block legacy storage clients (e.g., Windows 7, Server 2008, older Mac OSX OS versions) that only support SMBv2.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
    remedyValue: "EncryptData = 1 (DWORD)"
  },
  {
    id: 12,
    name: "Weak SMB Authentication Configuration",
    cveId: "GPO-SMB-012",
    category: "SMB Security",
    severity: "Medium",
    description: "Windows allows cleartext passwords or simple hash validations to fallback if the primary enterprise domain controller is briefly unavailable.",
    powershellFix: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name 'EnablePlainTextPassword' -Value 0 -Type DWord -Force",
    impactWarning: "MINIMAL IMPACT. Highly recommended. Halts legacy unencrypted passwords transmission.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
    remedyValue: "EnablePlainTextPassword = 0"
  },
  {
    id: 13,
    name: "Weak SSL/TLS Cipher Suites Enabled",
    cveId: "GPO-SCH-013",
    category: "SSL/TLS Protocols",
    severity: "High",
    description: "Outdated cipher suites are registered inside SCHANNEL, potentially forcing servers to agree upon export-grade encryption keys during secure port negotiations.",
    powershellFix: "# Restrict SCHANNEL to use strictly AES-256 and ECC ciphers. Disable old ciphers.\nDisable-TlsCipherSuite -Name 'TLS_RSA_WITH_3DES_EDE_CBC_SHA' -ErrorAction SilentlyContinue\nDisable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_SHA' -ErrorAction SilentlyContinue",
    impactWarning: "MEDIUM RISK: Disabling weak cipher suites will cause legacy web clients, non-updated diagnostic APIs, and older database connector drivers to fail to connect to active web ports.",
    remedyCode: "GPO Cryptographic Cipher Order",
    remedyValue: "Enforce modern TLS_ECDHE ciphers"
  },
  {
    id: 14,
    name: "RC4 Cipher Suites Enabled",
    cveId: "CVE-2015-2808",
    category: "SSL/TLS Protocols",
    severity: "High",
    description: "RC4 stream cipher keys are supported. Vulnerable to biases in keystream generators (Bar Mitzvah vulnerability) which allow session hijacking.",
    powershellFix: "New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 128/128' -Force\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 128/128' -Name 'Enabled' -Value 0 -Type DWord -Force",
    impactWarning: "LOW RISK: Disables RC4 completely. Some legacy internal java apps or customized industrial consoles may require updates.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 128/128",
    remedyValue: "Enabled = 0 (DWORD)"
  },
  {
    id: 15,
    name: "DES Cipher Suites Enabled",
    cveId: "GPO-SCH-015",
    category: "SSL/TLS Protocols",
    severity: "Medium",
    description: "Single-DES (56-bit) remains active in Windows cipher negotiation layers. Can be brute-forced of hardware tools in a matter of hours.",
    powershellFix: "New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\DES 56/56' -Force\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\DES 56/56' -Name 'Enabled' -Value 0 -Type DWord -Force",
    impactWarning: "MINIMAL IMPACT. Fully safe. Zero modern software applications rely on raw 56-bit DES ciphers.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\DES 56/56",
    remedyValue: "Enabled = 0 (DWORD)"
  },
  {
    id: 16,
    name: "3DES Cipher Suites Enabled",
    cveId: "CVE-2016-2183",
    category: "SSL/TLS Protocols",
    severity: "High",
    description: "Triple-DES (Sweet32) relies on 64-bit blocks. An attacker capturing long-duration sessions can execute collision attacks to retrieve cookies or authorization tokens.",
    powershellFix: "New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\Triple DES 168' -Force\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\Triple DES 168' -Name 'Enabled' -Value 0 -Type DWord -Force",
    impactWarning: "MEDIUM RISK: Ancient remote backup agents or long-running database pipes built on ancient setups may terminate if they do not support AES.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\Triple DES 168",
    remedyValue: "Enabled = 0 (DWORD)"
  },
  {
    id: 17,
    name: "Null Cipher Support Enabled",
    cveId: "GPO-SCH-017",
    category: "SSL/TLS Protocols",
    severity: "Medium",
    description: "Permits TLS connections to agree upon NULL (No-Encryption) handlers, meaning details are negotiated over open ports as unencrypted ascii lines.",
    powershellFix: "New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\NULL' -Force\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\NULL' -Name 'Enabled' -Value 0 -Type DWord -Force",
    impactWarning: "MINIMAL RISK. Highly safe for all servers. Prevents worst-case misconfigurations where traffic drops encryption entirely.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\NULL",
    remedyValue: "Enabled = 0"
  },
  {
    id: 18,
    name: "Export Grade Cipher Support Enabled",
    cveId: "CVE-2015-0204",
    category: "SSL/TLS Protocols",
    severity: "Medium",
    description: "Allows negotiation of 40-bit or 56-bit export-grade cipher mechanisms (FREAK exploit bypass vector), enabling local attackers to decrypt HTTPS tunnels in real time.",
    powershellFix: "# Disable export-grade algorithms globally in registry\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers' -Name 'Export' -Value 0 -Type DWord -ErrorAction SilentlyContinue",
    impactWarning: "MINIMAL IMPACT. Fully safe. Securely enforces that TLS negotiation always demands at least 128-bit key layers.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers",
    remedyValue: "Export = 0"
  },
  {
    id: 19,
    name: "SSL 2.0 Enabled",
    cveId: "GPO-SCH-019",
    category: "SSL/TLS Protocols",
    severity: "High",
    description: "Schannel registry permits SSL 2.0 protocols. Cryptographically broken; vulnerable to handshakes manipulation and decrypts.",
    powershellFix: "New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Server' -Force\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Server' -Name 'Enabled' -Value 0 -Type DWord -Force",
    impactWarning: "MINIMAL IMPACT. Safe. Modern browsers and security stacks abandoned SSL 2.0 back in 2011.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Server",
    remedyValue: "Enabled = 0"
  },
  {
    id: 20,
    name: "SSL 3.0 Enabled",
    cveId: "CVE-2014-3566",
    category: "SSL/TLS Protocols",
    severity: "High",
    description: "SSL 3.0 protocol remains enabled in legacy settings. Vulnerable to padding oracle attacks (POODLE) allowing block decryption.",
    powershellFix: "New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server' -Force\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server' -Name 'Enabled' -Value 0 -Type DWord -Force",
    impactWarning: "LOW RISK. Essential for PCI-DSS. Only extreme legacy embedded controllers or terminal units would fail to connect.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server",
    remedyValue: "Enabled = 0"
  },
  {
    id: 21,
    name: "TLS 1.0 Enabled",
    cveId: "GPO-SCH-021",
    category: "SSL/TLS Protocols",
    severity: "High",
    description: "TLS 1.0 is active. Suffers from cipher-block chaining vulnerabilities (BEAST exploit), enabling extraction of sensitive session values.",
    powershellFix: "New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Force\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Name 'Enabled' -Value 0 -Type DWord -Force\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Name 'DisabledByDefault' -Value 1 -Type DWord -Force",
    impactWarning: "MEDIUM RISK: Disabling TLS 1.0 will cause immediate communication breakdown on highly legacy APIs, obsolete Microsoft SQL database frameworks, and users on Internet Explorer 10 or Windows 7.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server",
    remedyValue: "Enabled = 0 (DWORD) + DisabledByDefault = 1"
  },
  {
    id: 22,
    name: "TLS 1.1 Enabled",
    cveId: "GPO-SCH-022",
    category: "SSL/TLS Protocols",
    severity: "High",
    description: "TLS 1.1 protocol remains active in Schannel parameters. Deprecated worldwide under newer compliance structures (NIST SP 800-52r2).",
    powershellFix: "New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Force\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Name 'Enabled' -Value 0 -Type DWord -Force",
    impactWarning: "MED-LOW RISK: Disabling TLS 1.1 may cause outdated web indexing tools or API endpoints to reject secure negotiation headers.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server",
    remedyValue: "Enabled = 0"
  },
  {
    id: 23,
    name: "Weak TLS Configuration",
    cveId: "GPO-SCH-023",
    category: "SSL/TLS Protocols",
    severity: "Medium",
    description: "System defaults do not prioritize Diffie-Hellman ephemeral sequences, resulting in a lack of Forward Secrecy on established secure port tunnels.",
    powershellFix: "# Raise key lengths minimum to 2048-bits\nNew-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman' -Force -ErrorAction SilentlyContinue\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman' -Name 'ServerMinKeyBitLength' -Value 2048 -Type DWord -Force",
    impactWarning: "LOW RISK: Outdated network systems with processor hardware built on 1024-bit logic limits may experience negotiation slowdowns or fail to complete handshakes.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman",
    remedyValue: "ServerMinKeyBitLength = 2048"
  },
  {
    id: 24,
    name: "Missing Strong Cryptography Enforcement (.NET)",
    cveId: "GPO-DOT-024",
    category: "SSL/TLS Protocols",
    severity: "High",
    description: ".NET framework runtimes defer to legacy web client layers, forcing older apps inside the system to restrict connection outputs to SSL 3.0 or TLS 1.0.",
    powershellFix: "# Force system .NET apps to inherit the active secure OS TLS baselines\nSet-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force\nSet-ItemProperty -Path 'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\.NETFramework\\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force",
    impactWarning: "LOW RISK: Exceptionally safe. Improves app security. However, highly customized older internal .NET corporate apps connecting to obsolete remote payment engines may need testing.",
    remedyCode: "HKLM:\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319",
    remedyValue: "SchUseStrongCrypto = 1"
  },
  {
    id: 25,
    name: "Insecure RDP TLS Configuration",
    cveId: "GPO-RDP-025",
    category: "Network Integrity",
    severity: "Medium",
    description: "Remote Desktop Services bounds to Negotiate layer rather than demanding strict SSL (TLS) wrappers, allowing attackers to downgrade connections to RDP Security Layer which is vulnerable to harvesting.",
    powershellFix: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'SecurityLayer' -Value 2 -Type DWord -Force",
    impactWarning: "LOW RISK. Disables raw downgrade sequences. Non-Windows third-party remote control applications must support native TLS wrappers.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
    remedyValue: "SecurityLayer = 2"
  },
  {
    id: 26,
    name: "Weak RDP Encryption Protocols Supported",
    cveId: "GPO-RDP-026",
    category: "Network Integrity",
    severity: "Medium",
    description: "The remote desktop services are prepared to accept low-encryption key sequences (such as 56-bit DES or legacy RC4 block formats) on active remote administrator channels.",
    powershellFix: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'MinEncryptionLevel' -Value 3 -Type DWord -Force",
    impactWarning: "LOW RISK. Demands high-strength (128-bit) symmetric keys. Prevents old customized thin clients or terminal hardware from connecting to local visual consoles.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
    remedyValue: "MinEncryptionLevel = 3"
  },
  {
    id: 27,
    name: "Self-Signed SSL Certificate",
    cveId: "GPO-CRT-027",
    category: "SSL/TLS Protocols",
    severity: "Medium",
    description: "Exposed web nodes or RDP service channels are binding a default self-signed local server certificate rather than a verified Certificate Authority (CA) chain.",
    powershellFix: "# Audit-Only script to detect self-signed certificate binding\nGet-ChildItem -Path Cert:\\LocalMachine\\My | Where-Object { $_.Subject -eq $_.Issuer } | ForEach-Object {\n    Write-Warning \"Self-Signed Certificate Identified: $($_.Subject) - Thumbprint: $($_.Thumbprint)\"\n}",
    impactWarning: "WARNING: Enforcing verified CA certs is critical. If bypassed and changed, ensure automatic certificates enrolment GPOs are functioning to prevent blank RDP screens or terminal crashes.",
    remedyCode: "Local SSL Certificate Binding",
    remedyValue: "Replace Subject=Issuer certs with PKI CA Signatures"
  },
  {
    id: 28,
    name: "Expired SSL Certificate",
    cveId: "GPO-CRT-028",
    category: "SSL/TLS Protocols",
    severity: "High",
    description: "One or more active secure port endpoints bindings trust a certificate whose validation timestamp has passed, resulting in secure browser blocks or script connection terminal rejections.",
    powershellFix: "# Scan certificate store for expired certificates and dump triggers\nGet-ChildItem -Path Cert:\\LocalMachine\\My | Where-Object { $_.NotAfter -lt (Get-Date) } | ForEach-Object {\n    Write-Error \"EXPIRED SSL CERTIFICATE: $($_.Subject) expired on $($_.NotAfter)\"\n}",
    impactWarning: "CRITICAL REPLACEMENT PENDING: If you delete or block an active expired cert without hot-swapping a valid replacement, active services (e.g. databases, IIS portals, local APIs) will immediately crash.",
    remedyCode: "Cert:\\LocalMachine\\My",
    remedyValue: "Renew and hot-swap certificate payload"
  },
  {
    id: 29,
    name: "Invalid SSL Certificate Trust Chain",
    cveId: "GPO-CRT-029",
    category: "SSL/TLS Protocols",
    severity: "High",
    description: "The secure portal contains a broken trust hierarchy, indicating root certificate updates have not been synchronised with trusted intermediate networks, posing MITM downgrade paths.",
    powershellFix: "# Enforce download of Windows Root Certificate updates\nSet-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\AuthRoot' -Name 'DisableRootAutoUpdate' -Value 0 -Type DWord -Force",
    impactWarning: "MINIMAL IMPACT. Essential to security posture. Allows the operating system to dynamically update trusted domain CA caches.",
    remedyCode: "HKLM:\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\AuthRoot",
    remedyValue: "DisableRootAutoUpdate = 0"
  },
  {
    id: 30,
    name: "Weak SSL Certificate Key Length",
    cveId: "GPO-CRT-030",
    category: "SSL/TLS Protocols",
    severity: "Medium",
    description: "The active host is operating 512-bit or 1024-bit RSA key certificates. These short keys are susceptible to factoring by public cloud resources under tight timelines.",
    powershellFix: "# Limit the Windows cryptographic engine to reject RSA keys below 2048 bits\ncertutil -setreg chain\\MinRSAKeyLength 2048",
    impactWarning: "WARNING: Setting MinRSAKeyLength to 2048 will immediately crash connections to extremely old internal hardware units or microcontrollers running on 1024-bit firmware.",
    remedyCode: "Certutil Registry Engine Registry",
    remedyValue: "chain\\MinRSAKeyLength = 2048"
  },
  {
    id: 31,
    name: "SSL Certificate Hostname Mismatch",
    cveId: "GPO-CRT-031",
    category: "SSL/TLS Protocols",
    severity: "Medium",
    description: "The Common Name (CN) or Subject Alternative Name (SAN) inside the active certificate does not match the actual DNS domain or server address, generating warnings.",
    powershellFix: "# Probe-Only helper to find hostname mismatches on active web sites\nGet-Website | ForEach-Object {\n    # Internal IIS hostname alignment audits\n    Write-Host \"Checking DNS mapping requirements on binding: $($_.Bindings.Collection)\"\n}",
    impactWarning: "LOW RISK: Visual warnings in browsers will be triggered until the DNS record aligns with the certificate's SAN or CN parameters.",
    remedyCode: "IIS Binding CN Configuration",
    remedyValue: "Subject Alternative Name (SAN) alignment"
  },
  {
    id: 32,
    name: "Missing HTTPS Configuration",
    cveId: "GPO-CRT-032",
    category: "Network Integrity",
    severity: "Medium",
    description: "Web management interfaces or portal panels on this host are run on port 80, releasing cookies and session indicators onto local network hubs in readable format.",
    powershellFix: "# Turn on mandatory redirect from port 80 to port 443 in local IIS bindings\n# Enforce SSL on core web applications\nImport-Module WebAdministration -ErrorAction SilentlyContinue\nSet-WebConfigurationProperty -filter /system.webServer/security/access -name sslFlags -value 'Ssl' -PSPath 'IIS:\\' -ErrorAction SilentlyContinue",
    impactWarning: "HIGH RISK FOR EXTRANETS: If you enforce SSL-Only without having mapped a valid SSL certificate on Port 443 first, users will receive a fatal 'Connection Refused' error on all web pages.",
    remedyCode: "IIS Server configuration",
    remedyValue: "SslFlags = Ssl (Mandate HTTPS)"
  },
  {
    id: 33,
    name: "Telnet Service Enabled",
    cveId: "GPO-SVC-033",
    category: "Network Integrity",
    severity: "Critical",
    description: "Legacy Telnet service (port 23) is installed and active on the host. Highly dangerous cleartext admin interface. Allows password harvesting from passive sniffing.",
    powershellFix: "Stop-Service -Name 'TlntSvr' -Force -ErrorAction SilentlyContinue\nSet-Service -Name 'TlntSvr' -StartupType Disabled -ErrorAction SilentlyContinue\nDisable-WindowsOptionalFeature -Online -FeatureName 'TelnetServer' -NoRestart -ErrorAction SilentlyContinue",
    impactWarning: "LOW RISK. Telnet is completely obsolete. Removing it is extremely safe. Switch immediately to SSHv2 or HTTPS terminals.",
    remedyCode: "Windows Optional Feature Server",
    remedyValue: "TelnetServer state = Disabled"
  },
  {
    id: 34,
    name: "Clear Text Remote Administration via Telnet",
    cveId: "GPO-SVC-034",
    category: "Network Integrity",
    severity: "Critical",
    description: "A shell is listening on Port 23. Direct remote server control commands, user passwords, and outputs are visible to anyone on the same internet router path.",
    powershellFix: "# Firewall block inbound communication ports to prevent Telnet hijacking\nNew-NetFirewallRule -DisplayName 'Block Telnet Port 23' -Direction Inbound -Action Block -LocalPort 23 -Protocol TCP -Force",
    impactWarning: "MINIMAL IMPACT. Closes highly unsecure entry doors. No modern administrative framework relies on cleartext telnet command tunnels.",
    remedyCode: "Defender NetFirewallRule TCP",
    remedyValue: "Block Port 23 Inbound globally"
  },
  {
    id: 35,
    name: "Unencrypted Network Communications",
    cveId: "GPO-NET-035",
    category: "Network Integrity",
    severity: "Medium",
    description: "Unencrypted port channels (like FTP port 21, HTTP port 80, LDAP port 389) are running. Allows attackers to capture sessions and insert commands.",
    powershellFix: "# Firewall rule to block FTP incoming commands, requesting SFTP instead\nNew-NetFirewallRule -DisplayName 'Block FTP Port 21' -Direction Inbound -Action Block -LocalPort 21 -Protocol TCP -Force",
    impactWarning: "WARNING: Blocking unencrypted communication ports will instantly break old automated cron scripts, legacy backup transfer scripts, or database queries operating on port 21/80.",
    remedyCode: "Defender NetFirewallRule",
    remedyValue: "Block legacy unencrypted ports (21, 23, 80)"
  },
  {
    id: 36,
    name: "Weak SSH Algorithms Supported",
    cveId: "GPO-SSH-036",
    category: "Network Integrity",
    severity: "Medium",
    description: "The Windows OpenSSH Server is configured to allow legacy cryptociphers (such as arcforth or CBC formats), making sessions vulnerable to structural decryption breaches on SSHv2.",
    powershellFix: "# Re-define safe Ciphers for OpenSSH on Windows\n$sshConfig = 'C:\\ProgramData\\ssh\\sshd_config'\nif (Test-Path $sshConfig) {\n    (Get-Content $sshConfig) -replace '^#?Ciphers.*', 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com' | Set-Content $sshConfig\n    Restart-Service sshd -ErrorAction SilentlyContinue\n}",
    impactWarning: "MEDIUM RISK: Disabling weak SSH ciphers will block connection attempts from legacy network devices, outdated developer terminals, or embedded linux controllers.",
    remedyCode: "C:\\ProgramData\\ssh\\sshd_config",
    remedyValue: "Ciphers = chacha20-poly1305, aes256-gcm"
  },
  {
    id: 37,
    name: "Weak SSH Key Exchange Algorithms",
    cveId: "GPO-SSH-037",
    category: "Network Integrity",
    severity: "Medium",
    description: "Allows group1-sha1 or other weak DH parameters during secure shell initialization. Enables man-in-the-middle decryption of command sessions.",
    powershellFix: "# Update Key exchange options in sshd_config\n$sshConfig = 'C:\\ProgramData\\ssh\\sshd_config'\nif (Test-Path $sshConfig) {\n    (Get-Content $sshConfig) -replace '^#?KexAlgorithms.*', 'KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512' | Set-Content $sshConfig\n    Restart-Service sshd -ErrorAction SilentlyContinue\n}",
    impactWarning: "LOW-MEDIUM RISK: Disabling outdated exchange layers prevents third-party legacy putty terminal tools from opening control frames to this server.",
    remedyCode: "C:\\ProgramData\\ssh\\sshd_config",
    remedyValue: "KexAlgorithms = curve25519-sha256"
  },
  {
    id: 38,
    name: "Weak SSH Host Keys",
    cveId: "GPO-SSH-038",
    category: "Network Integrity",
    severity: "Medium",
    description: "The host is offering weak 1024-bit DSA or broken ECDSA signature keys to verify its hostname integrity during remote client connections.",
    powershellFix: "# Remove weak dsa key generation definitions from OpenSSH server\n$sshConfig = 'C:\\ProgramData\\ssh\\sshd_config'\nif (Test-Path $sshConfig) {\n    (Get-Content $sshConfig) -replace '^HostKey.*ssh-dss', '# HostKey ssh-dss' | Set-Content $sshConfig\n    Restart-Service sshd -ErrorAction SilentlyContinue\n}",
    impactWarning: "MINIMAL IMPACT. Securely forces modern high-grade RSA (3072-bit+) or Ed25519 host keys validation.",
    remedyCode: "C:\\ProgramData\\ssh\\sshd_config",
    remedyValue: "HostKey = ssh-ed25519"
  },
  {
    id: 39,
    name: "Password Authentication Enabled on SSH",
    cveId: "GPO-SSH-039",
    category: "Network Integrity",
    severity: "Medium",
    description: "Permits users to input passwords rather than requiring public-key (SSH Key) credentials, exposing OpenSSH ports to brute-force dictionaries.",
    powershellFix: "# Restrict SSH authentication to cryptographically secure keys only\n$sshConfig = 'C:\\ProgramData\\ssh\\sshd_config'\nif (Test-Path $sshConfig) {\n    (Get-Content $sshConfig) -replace '^#?PasswordAuthentication.*', 'PasswordAuthentication no' | Set-Content $sshConfig\n    Restart-Service sshd -ErrorAction SilentlyContinue\n}",
    impactWarning: "CRITICAL OPERATIONAL RISK: If users have not uploaded their public ssh keys (authorized_keys) first, locking password logins will instantly lock out all administrators.",
    remedyCode: "C:\\ProgramData\\ssh\\sshd_config",
    remedyValue: "PasswordAuthentication = no"
  },
  {
    id: 40,
    name: "LDAP Enumeration Exposure",
    cveId: "GPO-AD-040",
    category: "OS / Active Directory",
    severity: "High",
    description: "Active Directory LDAP servers are not configured to mandate channel binding and LDAP signing. Enables unpermitted anonymous directory scans.",
    powershellFix: "# Turn on LDAP Signing inside registry\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name 'LDAPServerIntegrity' -Value 2 -Type DWord -Force",
    impactWarning: "MEDIUM RISK: Outdated non-Windows tools, old printer systems, or legacy LDAP-bound applications will fail to query user lists until modified to support secure sign headers.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
    remedyValue: "LDAPServerIntegrity = 2"
  },
  {
    id: 41,
    name: "Excessive Active Directory Information Disclosure",
    cveId: "GPO-AD-041",
    category: "OS / Active Directory",
    severity: "High",
    description: "Windows allows local and network authenticated users to query deep properties of high-privilege domain users, service accounts, and key nodes.",
    powershellFix: "# Restrict remote SAM access to authorized members only via registry block\nSet-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Lsa' -Name 'RestrictRemoteSAM' -Value 'O:BAG:BAD:(A;;RC;;;BA)' -Type String -Force",
    impactWarning: "LOW RISK. Highly robust security GPO. Essential for preventing domain reconnaissance tools (e.g., BloodHound, SharpHound) from executing silently.",
    remedyCode: "HKLM:\\System\\CurrentControlSet\\Control\\Lsa",
    remedyValue: "RestrictRemoteSAM = 'O:BAG:BAD:(A;;RC;;;BA)'"
  },
  {
    id: 42,
    name: "Domain User Enumeration Possible",
    cveId: "GPO-AD-042",
    category: "OS / Active Directory",
    severity: "High",
    description: "The Kerberos service accepts pre-authentication requests without auditing, enabling attackers to scan usernames on the domain to find active target logons.",
    powershellFix: "# Enable Kerberos logon pre-authentication logging and enforce security attributes\n# Registry tweak for advanced AD DC logs\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Kdc' -Name 'AuditEvents' -Value 1 -Type DWord -Force",
    impactWarning: "MINIMAL IMPACT. Enhances visibility. Safe to deploy. Essential for Security Operations Center (SOC) logging teams.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Kdc",
    remedyValue: "AuditEvents = 1"
  },
  {
    id: 43,
    name: "Domain Group Enumeration Possible",
    cveId: "GPO-AD-043",
    category: "OS / Active Directory",
    severity: "Medium",
    description: "Authenticated network nodes can bypass GPO filters to query lists of enterprise domain administrator groups, enabling targeted phishing or lateral escalation paths.",
    powershellFix: "# Configure SAM Security Descriptor registry to restrict remote SAM structures\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RestrictRemoteSAM' -Value 'O:BAG:BAD:(A;;RC;;;BA)' -Type String -Force",
    impactWarning: "LOW RISK. Only blocks domain reconnaissance scripts. Safe. Does not affect normal active work operations.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
    remedyValue: "RestrictRemoteSAM = Enforced"
  },
  {
    id: 44,
    name: "Missing Network Segmentation for SMB",
    cveId: "GPO-NET-044",
    category: "Network Integrity",
    severity: "High",
    description: "The host lacks subnet boundary limits on file-share access, allowing standard employee laptop subnets direct access to raw production database file systems.",
    powershellFix: "# Firewall script to restrict Port 445 (SMB) strictly to the Corporate Database Subnet (10.140.10.0/24)\nNew-NetFirewallRule -DisplayName 'Segment SMB Traffic' -Direction Inbound -Action Allow -LocalPort 445 -Protocol TCP -RemoteAddress '10.140.10.0/24' -Force",
    impactWarning: "WARNING: Employees on non-admin networks or on client office Wi-Fi will lose direct access to these shares. Must ensure correct VPN subnets are fully covered in firewall variables.",
    remedyCode: "NetFirewallRule Inbound",
    remedyValue: "RemoteAddress restricted to 10.140.10.0/24"
  },
  {
    id: 45,
    name: "File and Printer Sharing Exposed to External Networks",
    cveId: "GPO-NET-045",
    category: "Network Integrity",
    severity: "High",
    description: "NetBIOS and SMB sharing are allowed to communicate across public or external facing configurations, making folders active target nodes for global scrapers.",
    powershellFix: "# Block public firewall profiling for NetBIOS and file sharing protocols\nSet-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -Profile Public -Enabled False",
    impactWarning: "LOW RISK / HIGHLY RECOMMENDED. Safe. Ensures file and printer sharing endpoints never bind or release packet updates to unsafe public internet connections.",
    remedyCode: "NetFirewallRule Group Parameters",
    remedyValue: "Profile Public = Disabled"
  },
  {
    id: 46,
    name: "Missing Firewall Restrictions on SMB",
    cveId: "GPO-NET-046",
    category: "Network Integrity",
    severity: "High",
    description: "Local computer lacks host-based firewalls for network communication over SMB/Port 445, leaving systems exposed if network router firewalls fail.",
    powershellFix: "# Enable standard Windows Defender Firewall Profiles globally\nSet-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
    impactWarning: "MEDIUM RISK: If custom local port bindings (like custom non-standard APIs or developer port servers) are active without custom rules, they will immediately be blocked.",
    remedyCode: "Defender Firewall Globals Configuration",
    remedyValue: "Profiles Domain/Private/Public = Enabled"
  },
  {
    id: 47,
    name: "Missing Latest Security Updates",
    cveId: "GPO-SYS-047",
    category: "Device / Software Policies",
    severity: "High",
    description: "System lacks administrative enforcement of hotfixes, resulting in vulnerability to recent remote code execution, kernel privilege escalation, and memory disclosure exploits.",
    powershellFix: "# Force immediate system-level patch update search and GPO alignment\nSet-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name 'NoAutoUpdate' -Value 0 -Type DWord -Force",
    impactWarning: "MEDIUM RISK: Installing security updates automatically might trigger unexpected host reboots or cause customized internal code configurations to fail compatibility tests.",
    remedyCode: "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
    remedyValue: "NoAutoUpdate = 0"
  },
  {
    id: 48,
    name: "Unsupported or End-of-Life Software",
    cveId: "GPO-SYS-048",
    category: "Device / Software Policies",
    severity: "High",
    description: "System detects presence of legacy end-of-life framework libraries (such as .NET Framework 2.0 or Silverlight), which no longer receive security fixes or patches.",
    powershellFix: "# Query EOL frameworks and trigger de-allocation of obsolete components\nDisable-WindowsOptionalFeature -Online -FeatureName 'NetFx3' -NoRestart -ErrorAction SilentlyContinue",
    impactWarning: "HIGH RISK: De-registering .NET 2.0/3.5 will immediately break old enterprise utility apps, database tools, or automation sequences built on older libraries.",
    remedyCode: "Windows Optional Feature",
    remedyValue: "FeatureName NetFx3 = Disabled"
  },
  {
    id: 49,
    name: "Insecure IIS HTTPS Configuration",
    cveId: "GPO-IIS-049",
    category: "OS / Active Directory",
    severity: "Medium",
    description: "IIS web server configuration lacks HSTS (HTTP Strict Transport Security) headers. Enables attackers to downgrade secure client links using SSLStrip.",
    powershellFix: "# Inject HSTS Header globally in IIS configurations\nImport-Module WebAdministration -ErrorAction SilentlyContinue\nSet-WebConfigurationProperty -filter 'system.webServer/httpProtocol/customHeaders' -name '.' -value @{name='Strict-Transport-Security'; value='max-age=31536000; includeSubDomains'} -PSPath 'IIS:\\' -ErrorAction SilentlyContinue",
    impactWarning: "MED-LOW RISK: Forces browsers to strictly communicate over HTTPS. If any subdomain fails to support Port 443 HTTPS, those subdomains will become completely inaccessible.",
    remedyCode: "IIS customHeaders Config",
    remedyValue: "Strict-Transport-Security injected"
  },
  {
    id: 50,
    name: "Weak Web Server TLS Configuration",
    cveId: "GPO-IIS-050",
    category: "OS / Active Directory",
    severity: "Medium",
    description: "IIS bindings include fallback mechanisms to legacy ciphers, leaving services vulnerable to decryption of administrative web ports.",
    powershellFix: "# Restrict SSL Renegotiation sequences on local web configurations\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL' -Name 'DisableRenegoOnServer' -Value 1 -Type DWord -Force",
    impactWarning: "LOW RISK. Mitigates remote denial-of-service or TLS downgrade attacks on IIS endpoints.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL",
    remedyValue: "DisableRenegoOnServer = 1"
  },
  {
    id: 51,
    name: "Heartbleed Vulnerability Exposure Check Failure",
    cveId: "CVE-2014-0160",
    category: "Network Integrity",
    severity: "High",
    description: "The host contains old un-patched openssl binary builds in its program directories, exposing private encryption keys to remote reading via memory leaks.",
    powershellFix: "# Scan disk for outdated OpenSSL binary paths in common system application paths\nGet-ChildItem -Path C:\\ -Filter 'libeay32.dll','ssleay32.dll' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {\n    Write-Warning \"Audit Trigger: Potentially vulnerable OpenSSL binary: $($_.FullName)\"\n}",
    impactWarning: "CRITICAL COMPONENT REPLACEMENT: Patching or upgrading libeay32/ssleay32 DLLs requires hot-swapping software packages. Back up configurations before replacing binaries.",
    remedyCode: "C:\\...\\libeay32.dll version",
    remedyValue: "Upgrade to patches OpenSSL 1.1.1+"
  },
  {
    id: 52,
    name: "Open Administrative Ports Detected",
    cveId: "GPO-NET-052",
    category: "Network Integrity",
    severity: "High",
    description: "Highly sensitive diagnostic or remote control ports (like SSH port 22, VNC port 5900, WinRM port 5985) are exposed to non-restricted internet address configurations.",
    powershellFix: "# Block un-segregated WinRM and remote admin ports globally on Public profiles\nSet-NetFirewallRule -DisplayGroup 'Windows Remote Management' -Profile Public -Enabled False",
    impactWarning: "HIGH RISK FOR EXTRANETS: If remote administrative consoles are restricted, personnel on home internet locations without VPN configurations will be unable to troubleshoot or reboot machines.",
    remedyCode: "NetFirewallRule Group",
    remedyValue: "WinRM Public Profile = Disabled"
  },
  {
    id: 53,
    name: "Excessive Network Service Exposure",
    cveId: "GPO-NET-053",
    category: "Network Integrity",
    severity: "Medium",
    description: "System runs unnecessary network bindings (such as SSDP discovery, peer name resolutions, upnp), exposing unnecessary lines of code to remote scan scripts.",
    powershellFix: "# Stop and disable UPNP and SSDP service bindings\nStop-Service -Name 'upnphost' -Force -ErrorAction SilentlyContinue\nSet-Service -Name 'upnphost' -StartupType Disabled -ErrorAction SilentlyContinue",
    impactWarning: "LOW RISK. Disables automatic device discoverability. Safe. Some specialized dynamic media printers or local smart televisions might fail discovery.",
    remedyCode: "Windows Service Config",
    remedyValue: "upnphost / SSDP status = Disabled"
  },
  {
    id: 54,
    name: "Insecure Remote Desktop Configuration",
    cveId: "GPO-RDP-054",
    category: "Network Integrity",
    severity: "Medium",
    description: "Remote desktop configurations allow standard corporate users to persist inactive sessions for infinite duration, enabling attackers to hijack orphan session processes.",
    powershellFix: "# Set RDP maximum inactive time limits to 15 minutes\nSet-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name 'MaxIdleTime' -Value 900000 -Type DWord -Force",
    impactWarning: "MINIMAL IMPACT. Increases host performance by cleaning orphan threads. Users must re-authenticate if they leave their desks idle for >15 minutes.",
    remedyCode: "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
    remedyValue: "MaxIdleTime = 900000 (DWORD ms)"
  },
  {
    id: 55,
    name: "Weak Cryptographic Protocols Supported",
    cveId: "GPO-SCH-055",
    category: "SSL/TLS Protocols",
    severity: "Medium",
    description: "Cipher suite configs permit legacy hashes like MD5 or SHA-1 to authenticate server identities, which are highly susceptible to collision decryptions.",
    powershellFix: "# Disable SHA-1 and MD5 signature algorithms in registry\nNew-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Configuration\\Local\\SSL\\00010003' -Force -ErrorAction SilentlyContinue",
    impactWarning: "LOW-MEDIUM RISK. Some older legacy external merchant account validation services or older certificate trust chains might refuse communication.",
    remedyCode: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Cryptography",
    remedyValue: "Remove MD5 / SHA-1 hashes from SSL lists"
  },
  {
    id: 56,
    name: "Information Disclosure Through Service Enumeration",
    cveId: "GPO-SYS-056",
    category: "Device / Software Policies",
    severity: "Low",
    description: "Standard service responses release precise kernel build numbers, OS specifications, and server models inside port headers.",
    powershellFix: "# Restrict system response properties for remote ICMP queries to halt enumeration mapping\nSet-NetFirewallRule -DisplayName 'File and Printer Sharing (Echo Request - ICMPv4-In)' -Enabled False -Force",
    impactWarning: "LOW RISK. Prevents remote ping checks. External monitoring services utilizing simple ICMP ping requests will falsely report the system as offline.",
    remedyCode: "NetFirewallRule ICMPv4-In",
    remedyValue: "Echo Request Inbound = Disabled"
  },
  {
    id: 57,
    name: "Lack of Secure Communication Controls",
    cveId: "GPO-SYS-057",
    category: "Network Integrity",
    severity: "Medium",
    description: "Host is not configured to require IPSec encryption for inter-server database traffic, leaving internal communication lines vulnerable to lateral sniffing.",
    powershellFix: "# Script to confirm IPsec configurations\nSet-Service -Name 'IKEEXT' -StartupType Automatic\nStart-Service -Name 'IKEEXT' -ErrorAction SilentlyContinue",
    impactWarning: "LOW RISK. Pre-req configuration for secure site-to-site tunnels. Safe for standard domain workloads.",
    remedyCode: "Windows Service 'IKEEXT'",
    remedyValue: "Start and set to Automatic"
  },
  {
    id: 58,
    name: "Weak Network Hardening Configuration",
    cveId: "GPO-SYS-058",
    category: "Network Integrity",
    severity: "Medium",
    description: "The host TCP/IP stack allows response to IPv6 routing requests or source-routed frames, permitting IP spoofing bypasses across subnets.",
    powershellFix: "Set-NetIPInterface -AddressFamily IPv6 -RouterDiscovery Disabled -ErrorAction SilentlyContinue",
    impactWarning: "LOW RISK. Mitigates IPv6 router advertisement attacks. Safe. Recommend keeping if local domain runs strict IPv4 routing directories.",
    remedyCode: "NetIPInterface IPv6 Parameters",
    remedyValue: "RouterDiscovery = Disabled"
  },
  {
    id: 59,
    name: "Missing Secure Baseline Configuration",
    cveId: "GPO-SYS-059",
    category: "Device / Software Policies",
    severity: "High",
    description: "The host is not aligned with Microsoft's Recommended Security Baselines, leaving critical local audit logging and account lockout parameters disabled.",
    powershellFix: "# Enforce secure account lockouts: Lock account for 30 minutes after 5 failed password attempts\nnet accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30",
    impactWarning: "MEDIUM RISK: Legitimate corporate users who frequently forget their passwords or automated systems running service accounts with outdated credentials will find their accounts locked.",
    remedyCode: "Local SAM Account Policies",
    remedyValue: "lockoutthreshold = 5 attempts"
  },
  {
    id: 60,
    name: "Inadequate Access Control on Shared Resources",
    cveId: "GPO-SYS-060",
    category: "Device / Software Policies",
    severity: "Medium",
    description: "Default guest accounts are active or lack password mappings, permitting lateral movement without validation signatures.",
    powershellFix: "Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue",
    impactWarning: "LOW RISK / ESSENTIAL. Deactivates obsolete anonymous guest login portals globally. Virtually zero operational disruption in modern AD domains.",
    remedyCode: "Local User Guest Account",
    remedyValue: "Enabled = False"
  },
  {
    id: 61,
    name: "HDD / SSD S.M.A.R.T. Health Failure Warning",
    cveId: "HW-DRV-061",
    category: "Device / Software Policies",
    severity: "Critical",
    description: "Storage drive (HDD / NVMe SSD) reports reallocated sectors, read retries, or predictive S.M.A.R.T failure status via WMI MSStorageDriver_FailurePredictStatus. Unmanaged disk crash causes permanent data loss.",
    powershellFix: "Get-WmiObject -Namespace root\\wmi -Class MSStorageDriver_FailurePredictStatus | Select-Object InstanceName, PredictFailure, Reason\n# Prompt immediate drive cloning and backup to NAS",
    impactWarning: "CRITICAL HARDWARE AUDIT. Run CHKDSK /f /r and initiate physical storage replacement immediately.",
    remedyCode: "WMI root\\wmi MSStorageDriver_FailurePredictStatus",
    remedyValue: "PredictFailure = False"
  },
  {
    id: 62,
    name: "Critical Low Disk Storage Space (<10% Free)",
    cveId: "HW-DSK-062",
    category: "Device / Software Policies",
    severity: "High",
    description: "System partition (C:) free space has fallen below 10% threshold. Saturated disk space blocks critical Windows Security updates, causes VSS shadow copy failures, and crashes security loggers.",
    powershellFix: "# Run Disk Cleanup & Purge Windows Update Cache\nCleanmgr.exe /sagerun:1\nRemove-Item -Path '$env:WinDir\\SoftwareDistribution\\Download\\*' -Recurse -Force -ErrorAction SilentlyContinue",
    impactWarning: "LOW RISK. Purges temporary files and cached update installers to reclaim system volume storage.",
    remedyCode: "Win32_LogicalDisk C: FreeSpace",
    remedyValue: "FreeSpacePercent >= 15%"
  },
  {
    id: 63,
    name: "Unencrypted System Storage Volume (BitLocker Inactive)",
    cveId: "HW-ENC-063",
    category: "Device / Software Policies",
    severity: "High",
    description: "System volume (C:) lacks hardware BitLocker drive encryption. Offline attackers can extract plaintext SAM database hashes and corporate files via cold-boot or live USB OS boot bypasses.",
    powershellFix: "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest",
    impactWarning: "MEDIUM RISK. Requires TPM 2.0 module. Securely saves BitLocker recovery key to Active Directory Domain Services.",
    remedyCode: "BitLocker Volume C: ProtectionStatus",
    remedyValue: "ProtectionStatus = 1 (ON)"
  },
  {
    id: 64,
    name: "Excessive System Memory Saturation (>92% RAM)",
    cveId: "HW-RAM-064",
    category: "Device / Software Policies",
    severity: "Medium",
    description: "Host physical RAM load consistently exceeds 92%, causing heavy pagefile swapping and slowing EDR security agent response times.",
    powershellFix: "Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 Name, @{N='RAM(MB)';E={[math]::round($_.WorkingSet64/1MB,2)}}",
    impactWarning: "INFORMATIONAL AUDIT. Identifies memory-hogging processes or memory leak vulnerabilities.",
    remedyCode: "Win32_OperatingSystem Memory",
    remedyValue: "FreePhysicalMemory > 8%"
  },
  {
    id: 65,
    name: "Stale Windows Update OS Build (>60 Days Outdated)",
    cveId: "OS-UPD-065",
    category: "OS / Active Directory",
    severity: "High",
    description: "The OS build is missing critical quality patch KBs released over 60 days ago, exposing host to unpatched Zero-Day kernel vulnerabilities.",
    powershellFix: "UsoClient.exe StartInteractiveScan\nUsoClient.exe StartInstall",
    impactWarning: "MEDIUM RISK. Initiates background Windows Update download and installation.",
    remedyCode: "Windows Update Service (wuauserv)",
    remedyValue: "LastSuccessInstall < 30 Days"
  },
  {
    id: 66,
    name: "Outdated Defender Antivirus Definitions (>7 Days Old)",
    cveId: "SEC-DEF-066",
    category: "Device / Software Policies",
    severity: "High",
    description: "Microsoft Defender EDR security intelligence definitions are stale (>7 days old), weakening malware detection engines.",
    powershellFix: "Update-MpSignature -UpdateSource MSSD",
    impactWarning: "LOW RISK / HIGH BENEFIT. Pulls latest virus definition signatures directly from Microsoft Security Intelligence.",
    remedyCode: "Get-MpComputerStatus AntivirusSignatureAge",
    remedyValue: "AntivirusSignatureAge <= 3 days"
  }
];

export interface VulnerabilityStatus60 {
  vulnerability: Vulnerability60;
  status: 'passed' | 'failed' | 'warning' | 'excluded';
  excluded: boolean;
  remediated: boolean;
  baselineStatus: 'passed' | 'failed' | 'warning';
}

export function get60VulnerabilityStatus(vulnId: number, endpointId: string): 'passed' | 'failed' | 'warning' {
  const normId = endpointId.toLowerCase();

  if (normId.includes('dc') || normId.includes('domain') || normId.includes('corp-ad-dc-01')) {
    // Domain Controller (Highly Secure Baseline, but has domain-level specific warnings)
    if (vulnId === 11) return 'warning'; // SMB Encryption disabled
    if (vulnId === 40) return 'warning'; // LDAP signing required
    if (vulnId === 41) return 'warning'; // AD info disclosure
    if (vulnId === 42) return 'warning'; // Domain users enumeration
    if (vulnId === 43) return 'warning'; // Domain groups enumeration
    return 'passed';
  }
  
  if (normId.includes('db') || normId.includes('database') || normId.includes('db-srv')) {
    // Database Server
    const fails = [11, 24, 28, 44, 47, 54, 59];
    if (fails.includes(vulnId)) {
      return (vulnId === 11 || vulnId === 54) ? 'warning' : 'failed';
    }
    return 'passed';
  }

  if (normId.includes('ws') || normId.includes('win10') || normId.includes('workstation')) {
    // Workstation CORP-WIN10-WS104
    const fails = [1, 2, 3, 4, 11, 21, 24, 25, 27, 44, 45, 46, 47, 48, 51, 53, 54, 56, 59];
    if (fails.includes(vulnId)) {
      return (vulnId === 3 || vulnId === 11 || vulnId === 27 || vulnId === 54 || vulnId === 56) ? 'warning' : 'failed';
    }
    return 'passed';
  }

  // default File Server / Vulnerable Endpoint (CORP-FILE-SRV01)
  // Has dozens of open vulnerabilities for enterprise demonstration!
  const fileSrvPass = [22, 29, 31, 38, 57, 58]; // Only passes these few
  if (fileSrvPass.includes(vulnId)) return 'passed';
  
  const fileSrvWarn = [3, 6, 7, 12, 17, 18, 23, 26, 30, 43, 49, 50, 53, 54, 55, 56, 60];
  if (fileSrvWarn.includes(vulnId)) return 'warning';
  
  return 'failed';
}

export function get60VulnerabilitiesForEndpoint(endpoint: Endpoint): VulnerabilityStatus60[] {
  const remediatedList = endpoint.remediatedVulnerabilities || [];
  const excludedList = endpoint.excludedVulnerabilities || [];
  
  return VULNERABILITIES_60_DATABASE.map(v => {
    const rawVal = get60VulnerabilityStatus(v.id, endpoint.id);
    const excluded = excludedList.includes(v.id);
    const remediated = remediatedList.includes(v.id);
    
    let activeStatus: 'passed' | 'failed' | 'warning' | 'excluded' = rawVal;
    if (remediated) {
      activeStatus = 'passed';
    } else if (excluded) {
      activeStatus = 'excluded';
    }
    
    return {
      vulnerability: v,
      status: activeStatus,
      excluded,
      remediated,
      baselineStatus: rawVal
    };
  });
}

export function calculate60DynamicScore(endpoint: Endpoint): number {
  const list = get60VulnerabilitiesForEndpoint(endpoint);
  let score = 100;
  
  list.forEach(item => {
    // If it's a gap (failed or warning) and NOT remediated AND NOT excluded, we apply penalty
    if (item.status === 'failed' || item.status === 'warning') {
      const sev = item.vulnerability.severity;
      const penalty = sev === 'Critical' ? 4 : sev === 'High' ? 3 : sev === 'Medium' ? 2 : 1;
      score -= penalty;
    }
  });

  return Math.min(100, Math.max(0, score));
}

