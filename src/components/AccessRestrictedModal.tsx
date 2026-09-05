import React from 'react';
import { ShieldAlert, Lock, ArrowRight, UserCheck } from 'lucide-react';
import { StaffUser } from '../types/userManagement';

interface Props {
  isOpen: boolean;
  requiredRole: 'superadmin' | 'admin';
  actionName: string;
  currentUser: StaffUser | null;
  onClose: () => void;
  onOpenLogin: () => void;
}

export default function AccessRestrictedModal({
  isOpen,
  requiredRole,
  actionName,
  currentUser,
  onClose,
  onOpenLogin
}: Props) {
  if (!isOpen) return null;

  const currentRoleUpper = (currentUser?.role || 'enduser').toUpperCase();
  const requiredRoleUpper = requiredRole.toUpperCase();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in font-sans">
      <div className="relative w-full max-w-md bg-[#0F172A] border-2 border-red-500/50 rounded-xl shadow-2xl overflow-hidden">
        
        {/* Header */}
        <div className="bg-red-950/60 px-6 py-4 border-b border-red-500/30 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-red-500/20 text-red-400 border border-red-500/40">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-black uppercase text-red-200 tracking-wide">
              Action Privilege Restricted
            </h3>
            <p className="text-xs text-red-300/80 font-mono">
              Role Level Access Control Violation
            </p>
          </div>
        </div>

        {/* Body */}
        <div className="p-6 space-y-4">
          <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
            <div className="flex justify-between items-center text-xs font-mono">
              <span className="text-slate-400">Attempted Action:</span>
              <span className="font-bold text-amber-300">{actionName}</span>
            </div>
            <div className="flex justify-between items-center text-xs font-mono">
              <span className="text-slate-400">Your Current Level:</span>
              <span className="font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                {currentRoleUpper}
              </span>
            </div>
            <div className="flex justify-between items-center text-xs font-mono">
              <span className="text-slate-400">Required Privilege:</span>
              <span className="font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                {requiredRoleUpper} OR HIGHER
              </span>
            </div>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed">
            Your current staff account <strong className="text-white font-mono">({currentUser?.username || 'enduser'})</strong> has restricted execution privileges. To run <span className="text-cyan-300 font-semibold">{actionName}</span>, please switch to a <strong className="text-emerald-400">{requiredRoleUpper}</strong> account or request your SuperAdmin to update your privilege permissions.
          </p>

          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold py-2 rounded-lg text-xs uppercase tracking-wider transition cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => {
                onClose();
                onOpenLogin();
              }}
              className="flex-1 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold py-2 rounded-lg text-xs uppercase tracking-wider shadow border border-cyan-400/40 transition flex items-center justify-center gap-1.5 cursor-pointer"
            >
              <UserCheck className="w-4 h-4 text-cyan-200" />
              Switch Account
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
