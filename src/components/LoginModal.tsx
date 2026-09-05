import React, { useState } from 'react';
import { Shield, Key, User, Lock, CheckCircle2, AlertCircle, ArrowRight, ShieldAlert, Sparkles, UserCheck } from 'lucide-react';
import { StaffUser } from '../types/userManagement';
import { loginUser } from '../utils/userManagementStore';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onLoginSuccess: (user: StaffUser) => void;
  currentUser?: StaffUser;
  onLogout?: () => void;
}

export default function LoginModal({ isOpen, onClose, onLoginSuccess, currentUser, onLogout }: Props) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    const result = loginUser(username, password);
    if (result.success && result.user) {
      onLoginSuccess(result.user);
      onClose();
    } else {
      setErrorMsg(result.message || 'Authentication failed. Please verify username and password.');
    }
  };

  const handleQuickDemoFill = (role: 'superadmin' | 'admin' | 'enduser') => {
    if (role === 'superadmin') {
      setUsername('superadmin');
      setPassword('SuperAdmin@2026!');
    } else if (role === 'admin') {
      setUsername('admin');
      setPassword('Admin@2026!');
    } else {
      setUsername('enduser');
      setPassword('User@2026!');
    }
    setErrorMsg(null);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-lg bg-[#0F172A] border-2 border-cyan-500/40 rounded-xl shadow-2xl overflow-hidden font-sans">
        
        {/* Header Banner */}
        <div className="bg-gradient-to-r from-slate-900 via-cyan-950 to-slate-900 px-6 py-5 border-b border-cyan-500/30 text-white">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-cyan-500/20 border border-cyan-400/40 text-cyan-300">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-lg font-black tracking-wide uppercase text-cyan-200">
                Staff Authentication & Access Portal
              </h3>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Multi-Level Role Security (SuperAdmin • Admin • EndUser)
              </p>
            </div>
          </div>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-5">
          {errorMsg && (
            <div className="flex items-start gap-2.5 p-3 rounded.lg bg-red-500/15 border border-red-500/30 text-red-300 text-xs font-mono animate-shake">
              <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <strong className="font-bold text-red-200">Access Denied:</strong> {errorMsg}
              </div>
            </div>
          )}

          <form onSubmit={handleFormSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-mono font-bold uppercase text-slate-300 mb-1.5">
                Staff Username
              </label>
              <div className="relative">
                <User className="w-4 h-4 absolute left-3 top-2.5 text-cyan-400" />
                <input
                  type="text"
                  required
                  placeholder="e.g. superadmin, admin, enduser"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 outline-none font-mono"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-mono font-bold uppercase text-slate-300 mb-1.5">
                Password
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 absolute left-3 top-2.5 text-cyan-400" />
                <input
                  type="password"
                  required
                  placeholder="Enter account password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 outline-none font-mono"
                />
              </div>
            </div>

            <button
              type="submit"
              className="w-full bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold py-2.5 rounded-lg shadow-lg border border-cyan-400/40 transition flex items-center justify-center gap-2 cursor-pointer uppercase tracking-wider text-xs"
            >
              <UserCheck className="w-4 h-4 text-cyan-200" />
              Sign In to SmartPro SecOps
            </button>
          </form>

          {/* Quick Demo Pre-fills for Testing Staff Levels */}
          <div className="pt-3 border-t border-slate-800">
            <div className="flex items-center gap-1.5 mb-2.5 text-[11px] font-mono text-cyan-400 uppercase font-bold">
              <Sparkles className="w-3.5 h-3.5 text-amber-400" />
              Quick Select Staff Access Tier (Demo Credentials)
            </div>

            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => handleQuickDemoFill('superadmin')}
                className="p-2.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-left transition cursor-pointer group"
              >
                <span className="block text-[10px] font-mono font-bold text-emerald-400 uppercase">SUPERADMIN</span>
                <span className="block text-[11px] text-slate-300 font-semibold group-hover:text-white">Full Access</span>
                <span className="block text-[9px] font-mono text-slate-500 mt-0.5">superadmin / SuperAdmin@2026!</span>
              </button>

              <button
                type="button"
                onClick={() => handleQuickDemoFill('admin')}
                className="p-2.5 rounded-lg bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30 text-left transition cursor-pointer group"
              >
                <span className="block text-[10px] font-mono font-bold text-blue-400 uppercase">ADMIN</span>
                <span className="block text-[11px] text-slate-300 font-semibold group-hover:text-white">Ops & Scans</span>
                <span className="block text-[9px] font-mono text-slate-500 mt-0.5">admin / Admin@2026!</span>
              </button>

              <button
                type="button"
                onClick={() => handleQuickDemoFill('enduser')}
                className="p-2.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-left transition cursor-pointer group"
              >
                <span className="block text-[10px] font-mono font-bold text-amber-400 uppercase">ENDUSER</span>
                <span className="block text-[11px] text-slate-300 font-semibold group-hover:text-white">View & Audit</span>
                <span className="block text-[9px] font-mono text-slate-500 mt-0.5">enduser / User@2026!</span>
              </button>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="bg-slate-900/90 px-6 py-3 border-t border-slate-800 text-[11px] text-slate-400 flex flex-wrap justify-between items-center gap-2 font-mono">
          <div className="flex items-center gap-2">
            <span>SmartPro SecOps v2.4 RBAC Engine</span>
            {currentUser && (
              <span className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 text-[10px]">
                Active: <strong className="text-white">@{currentUser.username}</strong> ({currentUser.role})
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            {onLogout && (
              <button
                type="button"
                onClick={onLogout}
                className="px-2 py-0.5 rounded bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 text-[10px] font-bold uppercase transition"
              >
                Log Out
              </button>
            )}
            <button
              type="button"
              onClick={onClose}
              className="text-slate-400 hover:text-white transition underline"
            >
              Continue to Dashboard
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
