export type UserRole = 'superadmin' | 'admin' | 'enduser';

export interface UserPermissions {
  canRunLiveScan: boolean;
  canExecuteAutoFix: boolean;
  canDownloadScripts: boolean;
  canUploadAuditLogs: boolean;
  canEditDeleteEndpoints: boolean;
  canDeployExe: boolean;
  canAccessWinUtil: boolean;
  canManageUsers: boolean;
  canExportSyncConfig: boolean;
}

export interface LoginHistoryEntry {
  id: string;
  timestamp: string;
  ipAddress: string;
  userAgent: string;
  status: 'Success' | 'Failed Password';
}

export interface StaffUser {
  id: string;
  username: string;
  password: string;
  fullName: string;
  email: string;
  role: UserRole;
  isActive: boolean;
  loginCount: number;
  lastLoginTime: string;
  permissions: UserPermissions;
  history: LoginHistoryEntry[];
}

export const DEFAULT_PERMISSIONS_BY_ROLE: Record<UserRole, UserPermissions> = {
  superadmin: {
    canRunLiveScan: true,
    canExecuteAutoFix: true,
    canDownloadScripts: true,
    canUploadAuditLogs: true,
    canEditDeleteEndpoints: true,
    canDeployExe: true,
    canAccessWinUtil: true,
    canManageUsers: true,
    canExportSyncConfig: true,
  },
  admin: {
    canRunLiveScan: true,
    canExecuteAutoFix: true,
    canDownloadScripts: true,
    canUploadAuditLogs: true,
    canEditDeleteEndpoints: false,
    canDeployExe: false,
    canAccessWinUtil: false,
    canManageUsers: false,
    canExportSyncConfig: true,
  },
  enduser: {
    canRunLiveScan: false,
    canExecuteAutoFix: false,
    canDownloadScripts: true,
    canUploadAuditLogs: false,
    canEditDeleteEndpoints: false,
    canDeployExe: false,
    canAccessWinUtil: false,
    canManageUsers: false,
    canExportSyncConfig: false,
  },
};
