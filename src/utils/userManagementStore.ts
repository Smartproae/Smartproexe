import { StaffUser, UserRole, DEFAULT_PERMISSIONS_BY_ROLE, LoginHistoryEntry } from '../types/userManagement';

const USERS_STORAGE_KEY = 'smartpro_secops_staff_users_v1';
const CURRENT_USER_KEY = 'smartpro_secops_current_session_v1';

export const INITIAL_DEFAULT_USERS: StaffUser[] = [
  {
    id: 'user-super-01',
    username: 'superadmin',
    password: 'SuperAdmin@2026!',
    fullName: 'Global Security Director',
    email: 'ciso@smartpro.sec',
    role: 'superadmin',
    isActive: true,
    loginCount: 18,
    lastLoginTime: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
    permissions: { ...DEFAULT_PERMISSIONS_BY_ROLE.superadmin },
    history: [
      {
        id: 'log-1',
        timestamp: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
        ipAddress: '192.168.1.10 (Local Admin Terminal)',
        userAgent: 'SmartPro SecOps Terminal v2.4 (SuperAdmin)',
        status: 'Success'
      },
      {
        id: 'log-2',
        timestamp: new Date(Date.now() - 1000 * 60 * 60 * 12).toISOString(),
        ipAddress: '192.168.1.10 (Local Admin Terminal)',
        userAgent: 'SmartPro SecOps Terminal v2.4 (SuperAdmin)',
        status: 'Success'
      }
    ]
  },
  {
    id: 'user-admin-02',
    username: 'admin',
    password: 'Admin@2026!',
    fullName: 'IT SecOps Manager',
    email: 'admin@smartpro.sec',
    role: 'admin',
    isActive: true,
    loginCount: 9,
    lastLoginTime: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
    permissions: { ...DEFAULT_PERMISSIONS_BY_ROLE.admin },
    history: [
      {
        id: 'log-3',
        timestamp: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
        ipAddress: '192.168.1.45 (SOC Console)',
        userAgent: 'SmartPro SecOps Client v2.4 (Admin)',
        status: 'Success'
      }
    ]
  },
  {
    id: 'user-enduser-03',
    username: 'enduser',
    password: 'User@2026!',
    fullName: 'Junior Security Analyst',
    email: 'analyst@smartpro.sec',
    role: 'enduser',
    isActive: true,
    loginCount: 5,
    lastLoginTime: new Date(Date.now() - 1000 * 60 * 1440).toISOString(),
    permissions: { ...DEFAULT_PERMISSIONS_BY_ROLE.enduser },
    history: [
      {
        id: 'log-4',
        timestamp: new Date(Date.now() - 1000 * 60 * 1440).toISOString(),
        ipAddress: '192.168.1.88 (Audit Workstation)',
        userAgent: 'SmartPro SecOps Inspector v2.4 (EndUser)',
        status: 'Success'
      }
    ]
  }
];

export function getStoredUsers(): StaffUser[] {
  try {
    const raw = localStorage.getItem(USERS_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) {
        return parsed;
      }
    }
  } catch (e) {
    console.warn('Failed to parse stored users, resetting to default', e);
  }
  localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(INITIAL_DEFAULT_USERS));
  return INITIAL_DEFAULT_USERS;
}

export function saveStoredUsers(users: StaffUser[]): void {
  localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(users));
}

export function getCurrentSessionUser(): StaffUser | null {
  try {
    const raw = localStorage.getItem(CURRENT_USER_KEY);
    if (raw) {
      const current: StaffUser = JSON.parse(raw);
      // Re-verify against current database
      const users = getStoredUsers();
      const matched = users.find(u => u.id === current.id);
      if (matched && matched.isActive) {
        return matched;
      }
    }
  } catch (e) {
    console.warn('Failed to parse session user', e);
  }
  // Default session to superadmin if first launch
  const users = getStoredUsers();
  if (users[0]) {
    localStorage.setItem(CURRENT_USER_KEY, JSON.stringify(users[0]));
    return users[0];
  }
  return null;
}

export function loginUser(usernameInput: string, passwordInput: string): { success: boolean; user?: StaffUser; message?: string } {
  const users = getStoredUsers();
  const matchedIndex = users.findIndex(u => u.username.toLowerCase() === usernameInput.trim().toLowerCase());

  if (matchedIndex === -1) {
    return { success: false, message: `Account '${usernameInput}' not found in staff user directory.` };
  }

  const user = users[matchedIndex];

  if (!user.isActive) {
    return { success: false, message: `Account '${user.username}' is disabled by SuperAdmin.` };
  }

  if (user.password !== passwordInput) {
    // Record failed login attempt history entry
    const failedLog: LoginHistoryEntry = {
      id: `log-fail-${Date.now()}`,
      timestamp: new Date().toISOString(),
      ipAddress: '192.168.1.x (Client Login Window)',
      userAgent: navigator.userAgent,
      status: 'Failed Password'
    };
    user.history = [failedLog, ...user.history].slice(0, 25);
    users[matchedIndex] = user;
    saveStoredUsers(users);

    return { success: false, message: 'Invalid password. Please check credentials or contact SuperAdmin.' };
  }

  // Record successful login attempt
  const successLog: LoginHistoryEntry = {
    id: `log-${Date.now()}`,
    timestamp: new Date().toISOString(),
    ipAddress: '192.168.1.100 (Authenticated Web Console)',
    userAgent: navigator.userAgent,
    status: 'Success'
  };

  const updatedUser: StaffUser = {
    ...user,
    loginCount: user.loginCount + 1,
    lastLoginTime: new Date().toISOString(),
    history: [successLog, ...user.history].slice(0, 25)
  };

  users[matchedIndex] = updatedUser;
  saveStoredUsers(users);
  localStorage.setItem(CURRENT_USER_KEY, JSON.stringify(updatedUser));

  return { success: true, user: updatedUser };
}

export function logoutUser(): void {
  localStorage.removeItem(CURRENT_USER_KEY);
}

export function setSessionUser(user: StaffUser): void {
  localStorage.setItem(CURRENT_USER_KEY, JSON.stringify(user));
}
