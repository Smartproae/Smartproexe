import React, { useState } from 'react';
import { Users, Shield, Key, Lock, UserPlus, CheckCircle2, AlertCircle, Clock, Activity, Settings, Trash2, Edit2, ShieldCheck, ShieldAlert, X, Eye, EyeOff, FileText, Check, Plus, LogIn, LogOut, UserCheck } from 'lucide-react';
import { StaffUser, UserRole, DEFAULT_PERMISSIONS_BY_ROLE, UserPermissions } from '../types/userManagement';
import { getStoredUsers, saveStoredUsers, setSessionUser, loginUser } from '../utils/userManagementStore';

interface Props {
  isOpen: boolean;
  currentUser: StaffUser;
  onClose: () => void;
  onUpdateCurrentUser: (updatedUser: StaffUser) => void;
  onOpenLogin: () => void;
  onLogout?: () => void;
}

export default function UserManagementModal({
  isOpen,
  currentUser,
  onClose,
  onUpdateCurrentUser,
  onOpenLogin,
  onLogout
}: Props) {
  const [users, setUsers] = useState<StaffUser[]>(getStoredUsers());
  const [activeTab, setActiveTab] = useState<'directory' | 'permissions' | 'history'>('directory');
  
  // Add/Edit User Modal State
  const [isEditingUser, setIsEditingUser] = useState(false);
  const [editingUserId, setEditingUserId] = useState<string | null>(null);
  const [formUsername, setFormUsername] = useState('');
  const [formPassword, setFormPassword] = useState('');
  const [formFullName, setFormFullName] = useState('');
  const [formEmail, setFormEmail] = useState('');
  const [formRole, setFormRole] = useState<UserRole>('enduser');
  const [formIsActive, setFormIsActive] = useState(true);
  const [formPermissions, setFormPermissions] = useState<UserPermissions>({ ...DEFAULT_PERMISSIONS_BY_ROLE.enduser });
  const [showPassword, setShowPassword] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // History search filter
  const [historySearch, setHistorySearch] = useState('');
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  if (!isOpen) return null;

  const showTemporaryNotice = (msg: string) => {
    setActionNotice(msg);
    setTimeout(() => setActionNotice(null), 4000);
  };

  const refreshUsers = () => {
    const updated = getStoredUsers();
    setUsers(updated);
  };

  const handleQuickSwitchUser = (targetUser: StaffUser) => {
    if (!targetUser.isActive) {
      alert(`Account '${targetUser.username}' is disabled. Please enable it before logging in.`);
      return;
    }

    const res = loginUser(targetUser.username, targetUser.password);
    if (res.success && res.user) {
      onUpdateCurrentUser(res.user);
      setUsers(getStoredUsers());
      showTemporaryNotice(`Successfully logged in as ${res.user.fullName} (${res.user.role.toUpperCase()})`);
    } else {
      alert(res.message || 'Login failed.');
    }
  };

  const handleOpenAddUser = () => {
    if (currentUser.role !== 'superadmin') {
      if (window.confirm("Adding new staff users requires SuperAdmin privileges. Would you like to switch to SuperAdmin login now?")) {
        onOpenLogin();
      }
      return;
    }
    setEditingUserId(null);
    setFormUsername('');
    setFormPassword('');
    setFormFullName('');
    setFormEmail('');
    setFormRole('enduser');
    setFormIsActive(true);
    setFormPermissions({ ...DEFAULT_PERMISSIONS_BY_ROLE.enduser });
    setFormError(null);
    setIsEditingUser(true);
  };

  const handleOpenEditUser = (user: StaffUser) => {
    if (currentUser.role !== 'superadmin') {
      if (window.confirm("Editing staff account credentials requires SuperAdmin privileges. Would you like to switch to SuperAdmin login now?")) {
        onOpenLogin();
      }
      return;
    }
    setEditingUserId(user.id);
    setFormUsername(user.username);
    setFormPassword(user.password);
    setFormFullName(user.fullName);
    setFormEmail(user.email);
    setFormRole(user.role);
    setFormIsActive(user.isActive);
    setFormPermissions({ ...user.permissions });
    setFormError(null);
    setIsEditingUser(true);
  };

  const handleRoleChangeInForm = (newRole: UserRole) => {
    setFormRole(newRole);
    setFormPermissions({ ...DEFAULT_PERMISSIONS_BY_ROLE[newRole] });
  };

  const handleSaveUserSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!formUsername.trim() || !formPassword.trim()) {
      setFormError('Username and password are required.');
      return;
    }

    const currentUsers = getStoredUsers();

    if (editingUserId) {
      // Edit existing user
      const existingIdx = currentUsers.findIndex(u => u.id === editingUserId);
      if (existingIdx !== -1) {
        // Check duplicate username if changed
        const duplicate = currentUsers.find(u => u.username.toLowerCase() === formUsername.trim().toLowerCase() && u.id !== editingUserId);
        if (duplicate) {
          setFormError(`Username '${formUsername}' is already taken.`);
          return;
        }

        const updated: StaffUser = {
          ...currentUsers[existingIdx],
          username: formUsername.trim(),
          password: formPassword,
          fullName: formFullName.trim() || formUsername.trim(),
          email: formEmail.trim() || `${formUsername.trim()}@smartpro.sec`,
          role: formRole,
          isActive: formIsActive,
          permissions: { ...formPermissions }
        };

        currentUsers[existingIdx] = updated;
        saveStoredUsers(currentUsers);
        setUsers(currentUsers);

        if (updated.id === currentUser.id) {
          onUpdateCurrentUser(updated);
          setSessionUser(updated);
        }
      }
    } else {
      // Add new user
      const duplicate = currentUsers.find(u => u.username.toLowerCase() === formUsername.trim().toLowerCase());
      if (duplicate) {
        setFormError(`Username '${formUsername}' is already taken.`);
        return;
      }

      const newUser: StaffUser = {
        id: `user-${Date.now()}`,
        username: formUsername.trim(),
        password: formPassword,
        fullName: formFullName.trim() || formUsername.trim(),
        email: formEmail.trim() || `${formUsername.trim()}@smartpro.sec`,
        role: formRole,
        isActive: formIsActive,
        loginCount: 0,
        lastLoginTime: new Date().toISOString(),
        permissions: { ...formPermissions },
        history: [{
          id: `log-created-${Date.now()}`,
          timestamp: new Date().toISOString(),
          ipAddress: 'Account Created',
          userAgent: 'Created by SuperAdmin',
          status: 'Success'
        }]
      };

      const newList = [...currentUsers, newUser];
      saveStoredUsers(newList);
      setUsers(newList);
    }

    setIsEditingUser(false);
  };

  const handleToggleActive = (user: StaffUser) => {
    if (currentUser.role !== 'superadmin') {
      if (window.confirm("Modifying account status requires SuperAdmin privileges. Would you like to switch to SuperAdmin login now?")) {
        onOpenLogin();
      }
      return;
    }
    if (user.role === 'superadmin' && user.id === currentUser.id) {
      alert("Cannot disable your own active SuperAdmin session.");
      return;
    }
    const currentUsers = getStoredUsers();
    const idx = currentUsers.findIndex(u => u.id === user.id);
    if (idx !== -1) {
      currentUsers[idx].isActive = !currentUsers[idx].isActive;
      saveStoredUsers(currentUsers);
      setUsers(currentUsers);
      showTemporaryNotice(`Account '${user.username}' is now ${currentUsers[idx].isActive ? 'ACTIVE' : 'DISABLED'}.`);
    }
  };

  const handleDeleteUser = (user: StaffUser) => {
    if (currentUser.role !== 'superadmin') {
      if (window.confirm("Deleting staff accounts requires SuperAdmin privileges. Would you like to switch to SuperAdmin login now?")) {
        onOpenLogin();
      }
      return;
    }
    if (user.id === currentUser.id) {
      alert("Cannot delete the currently logged in session user.");
      return;
    }
    if (user.username === 'superadmin') {
      alert("Default 'superadmin' root account cannot be deleted.");
      return;
    }

    if (window.confirm(`Are you sure you want to delete staff user '${user.username}' (${user.fullName})?`)) {
      const currentUsers = getStoredUsers().filter(u => u.id !== user.id);
      saveStoredUsers(currentUsers);
      setUsers(currentUsers);
      showTemporaryNotice(`Staff user '${user.username}' has been deleted.`);
    }
  };

  const handleClearHistory = () => {
    if (window.confirm("Clear all historical login logs across staff accounts?")) {
      const currentUsers = getStoredUsers().map(u => ({ ...u, history: [] }));
      saveStoredUsers(currentUsers);
      setUsers(currentUsers);
    }
  };

  // Compile all history logs
  const allHistoryLogs = users.flatMap(u => 
    u.history.map(h => ({ ...h, username: u.username, role: u.role, fullName: u.fullName }))
  ).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  const filteredHistory = allHistoryLogs.filter(h => 
    h.username.toLowerCase().includes(historySearch.toLowerCase()) ||
    h.role.toLowerCase().includes(historySearch.toLowerCase()) ||
    h.ipAddress.toLowerCase().includes(historySearch.toLowerCase())
  );

  const getRoleBadge = (role: UserRole) => {
    if (role === 'superadmin') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-black font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 uppercase">
          <ShieldCheck className="w-3 h-3 text-emerald-400" />
          SuperAdmin
        </span>
      );
    }
    if (role === 'admin') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-black font-mono bg-blue-500/20 text-blue-300 border border-blue-500/40 uppercase">
          <Shield className="w-3 h-3 text-blue-400" />
          Admin
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-black font-mono bg-amber-500/20 text-amber-300 border border-amber-500/40 uppercase">
        <Users className="w-3 h-3 text-amber-400" />
        EndUser
      </span>
    );
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-fade-in font-sans">
      <div className="relative w-full max-w-5xl bg-[#0F172A] border-2 border-cyan-500/40 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        
        {/* Header Bar */}
        <div className="bg-gradient-to-r from-slate-900 via-cyan-950 to-slate-900 px-6 py-4 border-b border-cyan-500/30 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-cyan-500/20 border border-cyan-400/40 text-cyan-300">
              <Users className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-lg font-black tracking-wide uppercase text-cyan-200">
                Staff User Management & 3-Tier Privilege Control
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Manage Staff Credentials • Privilege Levels (SuperAdmin / Admin / EndUser) • Audit Run History
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Current Active Session Bar */}
        <div className="bg-slate-900/90 px-6 py-2.5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-slate-400">Active Staff Session:</span>
            <strong className="text-white font-bold">{currentUser.fullName} ({currentUser.username})</strong>
            {getRoleBadge(currentUser.role)}
          </div>

          <div className="flex items-center gap-3 text-slate-300">
            <span className="flex items-center gap-1">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              Login Run Count: <strong className="text-cyan-300 font-bold">{currentUser.loginCount} times</strong>
            </span>
            
            <button
              onClick={onOpenLogin}
              className="px-2.5 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-[11px] font-bold uppercase transition cursor-pointer flex items-center gap-1"
              title="Open Staff Authentication Portal"
            >
              <LogIn className="w-3.5 h-3.5" />
              Login / Switch Account
            </button>

            {onLogout && (
              <button
                onClick={() => {
                  onLogout();
                  onClose();
                }}
                className="px-2.5 py-1 rounded bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 text-[11px] font-bold uppercase transition cursor-pointer flex items-center gap-1"
                title="Log out current session user"
              >
                <LogOut className="w-3.5 h-3.5" />
                Log Out
              </button>
            )}
          </div>
        </div>

        {actionNotice && (
          <div className="bg-emerald-500/20 border-b border-emerald-500/40 px-6 py-2 text-xs font-mono text-emerald-300 flex items-center gap-2 animate-fade-in">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>{actionNotice}</span>
          </div>
        )}

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-800 bg-slate-950/60 px-6 font-mono text-xs">
          <button
            onClick={() => setActiveTab('directory')}
            className={`py-3 px-4 font-bold border-b-2 transition flex items-center gap-2 cursor-pointer ${
              activeTab === 'directory'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-500/10'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            <Users className="w-4 h-4" />
            Staff Accounts Directory ({users.length})
          </button>

          <button
            onClick={() => setActiveTab('permissions')}
            className={`py-3 px-4 font-bold border-b-2 transition flex items-center gap-2 cursor-pointer ${
              activeTab === 'permissions'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-500/10'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            <Shield className="w-4 h-4" />
            3-Tier Privilege Matrix
          </button>

          <button
            onClick={() => setActiveTab('history')}
            className={`py-3 px-4 font-bold border-b-2 transition flex items-center gap-2 cursor-pointer ${
              activeTab === 'history'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-500/10'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            <Clock className="w-4 h-4" />
            Login History & Run Logs ({allHistoryLogs.length})
          </button>
        </div>

        {/* Body Content */}
        <div className="p-6 overflow-y-auto flex-1 space-y-6">

          {/* TAB 1: STAFF DIRECTORY */}
          {activeTab === 'directory' && (
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <div>
                  <h4 className="text-sm font-black uppercase text-cyan-200">Registered Staff Accounts</h4>
                  <p className="text-xs text-slate-400 font-mono">SuperAdmin has unlimited privileges to edit staff credentials & levels.</p>
                </div>

                <button
                  onClick={handleOpenAddUser}
                  className="inline-flex items-center gap-1.5 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold px-3 py-1.5 rounded-lg text-xs font-mono uppercase tracking-wider shadow transition cursor-pointer"
                  title="Create new staff user account"
                >
                  <UserPlus className="w-4 h-4" />
                  Add Staff User
                </button>
              </div>

              {/* Staff Table */}
              <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-800">
                    <tr>
                      <th className="py-3 px-4">Staff User</th>
                      <th className="py-3 px-4">Role Level</th>
                      <th className="py-3 px-4">Account Status</th>
                      <th className="py-3 px-4 text-center">Login Run Count</th>
                      <th className="py-3 px-4">Last Active</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {users.map((u) => (
                      <tr key={u.id} className="hover:bg-slate-800/50 transition">
                        <td className="py-3 px-4">
                          <div className="font-bold text-slate-100">{u.fullName}</div>
                          <div className="text-[11px] text-cyan-400">@{u.username} • {u.email}</div>
                        </td>
                        <td className="py-3 px-4">
                          {getRoleBadge(u.role)}
                        </td>
                        <td className="py-3 px-4">
                          {u.isActive ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                              Active
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/15 text-red-400 border border-red-500/30">
                              Disabled
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-center font-bold text-cyan-300">
                          {u.loginCount} runs
                        </td>
                        <td className="py-3 px-4 text-slate-400 text-[11px]">
                          {u.lastLoginTime ? new Date(u.lastLoginTime).toLocaleString() : 'Never'}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end gap-1.5 flex-wrap">
                            {u.id === currentUser.id ? (
                              <span className="px-2 py-1 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[10px] font-bold uppercase inline-flex items-center gap-1" title="Currently active session">
                                <UserCheck className="w-3 h-3 text-emerald-400" />
                                Active
                              </span>
                            ) : (
                              <button
                                onClick={() => handleQuickSwitchUser(u)}
                                className="px-2 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-[10px] font-bold uppercase transition cursor-pointer inline-flex items-center gap-1"
                                title={`Log in as ${u.fullName} (@${u.username})`}
                              >
                                <LogIn className="w-3 h-3 text-cyan-400" />
                                Log In As
                              </button>
                            )}

                            <button
                              onClick={() => handleOpenEditUser(u)}
                              className="px-2 py-1 rounded bg-blue-500/20 hover:bg-blue-500/30 text-blue-300 border border-blue-500/40 text-[10px] font-bold uppercase transition cursor-pointer inline-flex items-center gap-1"
                              title="Edit credentials or role level"
                            >
                              <Edit2 className="w-3 h-3" />
                              Edit / Pass
                            </button>

                            <button
                              onClick={() => handleToggleActive(u)}
                              className={`px-2 py-1 rounded text-[10px] font-bold uppercase border transition cursor-pointer ${
                                u.isActive 
                                  ? 'bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border-amber-500/40' 
                                  : 'bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border-emerald-500/40'
                              }`}
                              title="Toggle Active / Disabled"
                            >
                              {u.isActive ? 'Disable' : 'Enable'}
                            </button>

                            {u.username !== 'superadmin' && (
                              <button
                                onClick={() => handleDeleteUser(u)}
                                className="p-1.5 rounded bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 transition cursor-pointer"
                                title="Delete User"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 2: PRIVILEGE MATRIX */}
          {activeTab === 'permissions' && (
            <div className="space-y-4 font-mono">
              <div>
                <h4 className="text-sm font-black uppercase text-cyan-200">3-Tier Access Level Setup</h4>
                <p className="text-xs text-slate-400">Comparison of functional capabilities across SuperAdmin, Admin, and EndUser accounts.</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* SuperAdmin Card */}
                <div className="bg-slate-900 border-2 border-emerald-500/40 rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between pb-2 border-b border-emerald-500/30">
                    <span className="text-xs font-black uppercase text-emerald-400 flex items-center gap-1.5">
                      <ShieldCheck className="w-4 h-4" />
                      SuperAdmin Level
                    </span>
                    <span className="text-[10px] font-bold bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded border border-emerald-500/40">
                      NO ACCESS LIMIT
                    </span>
                  </div>
                  <ul className="text-xs space-y-2 text-slate-300">
                    <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Full Endpoint Live Scanning</li>
                    <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Automated 60-Item Vulnerability AutoFix</li>
                    <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> PS1 Hardening Script Downloads</li>
                    <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Terminal JSON Log Upload</li>
                    <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> EXE Deployment & WinUtil Fix</li>
                    <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Staff Credential & Password Management</li>
                    <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Database Reset & GitHub Sync</li>
                  </ul>
                </div>

                {/* Admin Card */}
                <div className="bg-slate-900 border-2 border-blue-500/40 rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between pb-2 border-b border-blue-500/30">
                    <span className="text-xs font-black uppercase text-blue-400 flex items-center gap-1.5">
                      <Shield className="w-4 h-4" />
                      Admin Level
                    </span>
                    <span className="text-[10px] font-bold bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded border border-blue-500/40">
                      OPS / SEC TEAM
                    </span>
                  </div>
                  <ul className="text-xs space-y-2 text-slate-300">
                    <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Full Endpoint Live Scanning</li>
                    <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Automated Vulnerability AutoFix</li>
                    <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> PS1 Hardening Script Downloads</li>
                    <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Terminal JSON Log Upload</li>
                    <li className="flex items-center gap-2 text-slate-500 line-through"><X className="w-4 h-4 text-red-400" /> EXE Deployment & WinUtil (Restricted)</li>
                    <li className="flex items-center gap-2 text-slate-500 line-through"><X className="w-4 h-4 text-red-400" /> Staff User Management (Restricted)</li>
                  </ul>
                </div>

                {/* EndUser Card */}
                <div className="bg-slate-900 border-2 border-amber-500/40 rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between pb-2 border-b border-amber-500/30">
                    <span className="text-xs font-black uppercase text-amber-400 flex items-center gap-1.5">
                      <Users className="w-4 h-4" />
                      EndUser Level
                    </span>
                    <span className="text-[10px] font-bold bg-amber-500/20 text-amber-300 px-2 py-0.5 rounded border border-amber-500/40">
                      AUDIT & READ-ONLY
                    </span>
                  </div>
                  <ul className="text-xs space-y-2 text-slate-300">
                    <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> View Endpoint Security Dashboard</li>
                    <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> View Remediation Guides & CVEs</li>
                    <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Download PS1 Hardening Scripts</li>
                    <li className="flex items-center gap-2 text-slate-500 line-through"><X className="w-4 h-4 text-red-400" /> Run Live IP Probe (Restricted)</li>
                    <li className="flex items-center gap-2 text-slate-500 line-through"><X className="w-4 h-4 text-red-400" /> Run AutoFix (Restricted)</li>
                    <li className="flex items-center gap-2 text-slate-500 line-through"><X className="w-4 h-4 text-red-400" /> Add / Delete Endpoints (Restricted)</li>
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: LOGIN HISTORY */}
          {activeTab === 'history' && (
            <div className="space-y-4 font-mono">
              <div className="flex justify-between items-center">
                <div>
                  <h4 className="text-sm font-black uppercase text-cyan-200">Staff Login History & Session Logs</h4>
                  <p className="text-xs text-slate-400">Tracks how many times staff members run the portal and authenticate.</p>
                </div>

                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    placeholder="Search history by username / IP..."
                    value={historySearch}
                    onChange={(e) => setHistorySearch(e.target.value)}
                    className="bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-xs text-slate-200 outline-none focus:border-cyan-400"
                  />

                  {currentUser.role === 'superadmin' && (
                    <button
                      onClick={handleClearHistory}
                      className="px-2.5 py-1 rounded bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 text-xs font-bold uppercase transition cursor-pointer"
                    >
                      Clear Logs
                    </button>
                  )}
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-4">Timestamp</th>
                      <th className="py-2.5 px-4">Staff User</th>
                      <th className="py-2.5 px-4">Role Level</th>
                      <th className="py-2.5 px-4">Client Terminal / IP</th>
                      <th className="py-2.5 px-4 text-center">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {filteredHistory.length > 0 ? (
                      filteredHistory.map((log) => (
                        <tr key={log.id} className="hover:bg-slate-800/50 transition">
                          <td className="py-2.5 px-4 text-slate-300">
                            {new Date(log.timestamp).toLocaleString()}
                          </td>
                          <td className="py-2.5 px-4 font-bold text-cyan-300">
                            {log.fullName} (@{log.username})
                          </td>
                          <td className="py-2.5 px-4">
                            {getRoleBadge(log.role as UserRole)}
                          </td>
                          <td className="py-2.5 px-4 text-slate-400 text-[11px]">
                            {log.ipAddress}
                          </td>
                          <td className="py-2.5 px-4 text-center">
                            {log.status === 'Success' ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                                Authenticated
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/15 text-red-400 border border-red-500/30">
                                Password Error
                              </span>
                            )}
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={5} className="py-6 text-center text-slate-500">
                          No login history entries match search filter.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

        </div>

        {/* Edit / Add User Modal Sub-Dialog */}
        {isEditingUser && (
          <div className="fixed inset-0 z-[100] bg-black/85 backdrop-blur-md flex items-center justify-center p-4 overflow-y-auto">
            <div className="w-full max-w-lg bg-[#0F172A] border-2 border-cyan-500/50 rounded-xl p-6 shadow-2xl space-y-4 font-mono my-auto">
              <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                <h4 className="text-sm font-black uppercase text-cyan-300">
                  {editingUserId ? `Edit Staff Account (@${formUsername})` : 'Create New Staff Account'}
                </h4>
                <button onClick={() => setIsEditingUser(false)} className="text-slate-400 hover:text-white">
                  <X className="w-5 h-5" />
                </button>
              </div>

              {formError && (
                <div className="p-2.5 rounded bg-red-500/20 border border-red-500/40 text-red-300 text-xs">
                  {formError}
                </div>
              )}

              <form onSubmit={handleSaveUserSubmit} className="space-y-3 text-xs">
                <div>
                  <label className="block text-slate-300 font-bold mb-1">Username</label>
                  <input
                    type="text"
                    required
                    value={formUsername}
                    onChange={(e) => setFormUsername(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-100 outline-none focus:border-cyan-400"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-bold mb-1">Password</label>
                  <div className="relative">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      value={formPassword}
                      onChange={(e) => setFormPassword(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-100 outline-none focus:border-cyan-400 pr-9"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-2.5 top-2 text-slate-400 hover:text-white"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-300 font-bold mb-1">Full Name</label>
                    <input
                      type="text"
                      value={formFullName}
                      onChange={(e) => setFormFullName(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-100 outline-none focus:border-cyan-400"
                    />
                  </div>

                  <div>
                    <label className="block text-slate-300 font-bold mb-1">Email Address</label>
                    <input
                      type="email"
                      value={formEmail}
                      onChange={(e) => setFormEmail(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-100 outline-none focus:border-cyan-400"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-slate-300 font-bold mb-1">Privilege Level (Role)</label>
                  <select
                    value={formRole}
                    onChange={(e) => handleRoleChangeInForm(e.target.value as UserRole)}
                    className="w-full bg-slate-900 border border-cyan-500/50 rounded px-3 py-1.5 text-cyan-300 font-bold outline-none"
                  >
                    <option value="superadmin">🟢 SUPERADMIN (Unrestricted Full Access)</option>
                    <option value="admin">🔵 ADMIN (Ops, Scans, PS1 Scripts, Log Upload)</option>
                    <option value="enduser">🟡 ENDUSER (Audit View & Read-Only)</option>
                  </select>
                </div>

                <div className="flex items-center gap-2 pt-1">
                  <input
                    type="checkbox"
                    id="isActiveCheck"
                    checked={formIsActive}
                    onChange={(e) => setFormIsActive(e.target.checked)}
                    className="rounded bg-slate-900 border-slate-700 text-cyan-500"
                  />
                  <label htmlFor="isActiveCheck" className="text-slate-300 font-bold cursor-pointer">
                    Account Active & Permitted to Login
                  </label>
                </div>

                <div className="flex gap-2 pt-3">
                  <button
                    type="button"
                    onClick={() => setIsEditingUser(false)}
                    className="flex-1 bg-slate-800 hover:bg-slate-700 text-slate-300 py-2 rounded font-bold uppercase"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="flex-1 bg-cyan-600 hover:bg-cyan-500 text-white py-2 rounded font-bold uppercase shadow"
                  >
                    Save Account
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="bg-slate-900/90 px-6 py-3 border-t border-slate-800 flex justify-between items-center text-xs font-mono text-slate-400">
          <span>Role Levels: SuperAdmin (Unrestricted) • Admin (Ops) • EndUser (Audit)</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold uppercase transition cursor-pointer"
          >
            Close Window
          </button>
        </div>

      </div>
    </div>
  );
}
