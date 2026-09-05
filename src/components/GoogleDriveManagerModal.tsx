import React, { useState, useEffect } from 'react';
import { HardDrive, Cloud, CheckCircle2, AlertCircle, RefreshCw, UploadCloud, DownloadCloud, LogOut, X, Loader2, ExternalLink, ShieldCheck } from 'lucide-react';
import { connectGoogleDrive, disconnectGoogleDrive, backupPosturesToDrive, listDriveBackups, restoreFromDriveBackup, DriveBackupFile, auth, getDriveStorageQuota, StorageQuota } from '../lib/googleDriveService';
import { onAuthStateChanged, User } from 'firebase/auth';
import { Endpoint } from '../types';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  endpoints: Endpoint[];
  onRestoreEndpoints: (endpoints: Endpoint[]) => void;
}

export default function GoogleDriveManagerModal({ isOpen, onClose, endpoints, onRestoreEndpoints }: Props) {
  const [user, setUser] = useState<User | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [backups, setBackups] = useState<DriveBackupFile[]>([]);
  const [fetchingBackups, setFetchingBackups] = useState(false);
  const [statusMsg, setStatusMsg] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);
  
  // Storage quota states
  const [quota, setQuota] = useState<StorageQuota | null>(null);
  const [fetchingQuota, setFetchingQuota] = useState(false);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
      setUser(currentUser);
    });
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    if (accessToken && isOpen) {
      handleListBackups();
      handleFetchQuota();
    }
  }, [accessToken, isOpen]);

  if (!isOpen) return null;

  const handleConnect = async () => {
    setLoading(true);
    setStatusMsg(null);
    try {
      const res = await connectGoogleDrive();
      setUser(res.user);
      setAccessToken(res.accessToken);
      setStatusMsg({ type: 'success', text: `Connected to Google Drive account: ${res.user.displayName || res.user.email}` });
    } catch (err: any) {
      console.error(err);
      setStatusMsg({ type: 'error', text: `Google Auth Error: ${err.message || 'Failed to authenticate popup.'}` });
    } finally {
      setLoading(false);
    }
  };

  const handleDisconnect = async () => {
    setLoading(true);
    try {
      await disconnectGoogleDrive();
      setUser(null);
      setAccessToken(null);
      setBackups([]);
      setQuota(null);
      setStatusMsg({ type: 'info', text: 'Disconnected from Google Drive.' });
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: err.message });
    } finally {
      setLoading(false);
    }
  };

  const handleFetchQuota = async () => {
    if (!accessToken) return;
    setFetchingQuota(true);
    try {
      const q = await getDriveStorageQuota(accessToken);
      setQuota(q);
    } catch (err: any) {
      console.error("Could not fetch Google Drive quota limit:", err);
    } finally {
      setFetchingQuota(false);
    }
  };

  const handleListBackups = async () => {
    if (!accessToken) return;
    setFetchingBackups(true);
    try {
      const files = await listDriveBackups(accessToken);
      setBackups(files);
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: `Could not load backup history: ${err.message}` });
    } finally {
      setFetchingBackups(false);
    }
  };

  const handleTriggerBackup = async () => {
    if (!accessToken) {
      setStatusMsg({ type: 'error', text: 'Please connect Google Drive first.' });
      return;
    }
    setLoading(true);
    setStatusMsg({ type: 'info', text: 'Uploading posture configuration JSON to Google Drive...' });
    try {
      const res = await backupPosturesToDrive(accessToken, endpoints);
      setStatusMsg({ type: 'success', text: `Successfully saved backup: ${res.name}` });
      handleListBackups();
      handleFetchQuota(); // refresh space limits
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: `Backup upload error: ${err.message}` });
    } finally {
      setLoading(false);
    }
  };

  const handleRestoreFile = async (fileId: string, fileName: string) => {
    if (!accessToken) return;
    setLoading(true);
    setStatusMsg({ type: 'info', text: `Downloading & applying backup ${fileName}...` });
    try {
      const data = await restoreFromDriveBackup(accessToken, fileId);
      if (data && Array.isArray(data.endpoints)) {
        onRestoreEndpoints(data.endpoints);
        setStatusMsg({ type: 'success', text: `Restored ${data.endpoints.length} endpoints postures from ${fileName}!` });
      } else {
        throw new Error('Invalid backup schema format');
      }
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: `Restore failed: ${err.message}` });
    } finally {
      setLoading(false);
    }
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const calculatePercentage = (used: number, limit: number): number => {
    if (!limit) return 0;
    return Math.min(parseFloat(((used / limit) * 100).toFixed(2)), 100);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 font-sans animate-fadeIn">
      <div className="bg-[#0f0f0f] border border-amber-500/40 rounded-2xl max-w-xl w-full overflow-hidden shadow-2xl shadow-amber-950/30 flex flex-col max-h-[90vh]">
        
        {/* Modal Header */}
        <div className="bg-gradient-to-r from-[#0c2440] to-[#0d1b2a] p-5 border-b border-amber-500/30 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-amber-400/10 border border-amber-400/30 rounded-xl text-amber-400">
              <Cloud className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                Google Drive Enterprise Backup
                <span className="text-[10px] bg-amber-400 text-black px-1.5 py-0.5 rounded font-black uppercase font-mono">v2.4</span>
              </h3>
              <p className="text-xs text-white/60">Securely sync SecOps GPO configuration baselines to Google Cloud</p>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="p-2 text-white/50 hover:text-white hover:bg-white/10 rounded-lg transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 overflow-y-auto flex-1">
          
          {/* Status Alert Banner */}
          {statusMsg && (
            <div className={`p-4 rounded-xl text-xs font-medium flex items-center gap-3 border ${
              statusMsg.type === 'success' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' :
              statusMsg.type === 'error' ? 'bg-red-500/10 border-red-500/30 text-red-400' :
              'bg-blue-500/10 border-blue-500/30 text-blue-400'
            }`}>
              {statusMsg.type === 'success' ? <CheckCircle2 className="w-4 h-4 shrink-0" /> : <AlertCircle className="w-4 h-4 shrink-0" />}
              <span className="leading-relaxed">{statusMsg.text}</span>
            </div>
          )}

          {/* Account Connection State */}
          <div className="bg-black/50 border border-white/10 p-5 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3.5">
              <div className="w-10 h-10 rounded-full bg-white/5 border border-white/15 flex items-center justify-center text-white font-bold shrink-0">
                {user && user.photoURL ? (
                  <img src={user.photoURL} alt="Avatar" className="w-full h-full rounded-full object-cover" referrerPolicy="no-referrer" />
                ) : (
                  <HardDrive className="w-5 h-5 text-amber-400" />
                )}
              </div>
              <div>
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                  {user ? 'Cloud Session Active' : 'No Account Linked'}
                </h4>
                <p className="text-[11px] text-white/50 truncate max-w-[220px] sm:max-w-[260px] font-mono">
                  {user ? user.email : 'Authenticate with Google Workspace Picker'}
                </p>
              </div>
            </div>

            {user && accessToken ? (
              <button
                onClick={handleDisconnect}
                disabled={loading}
                className="px-3.5 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg text-xs font-bold transition flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50 shrink-0"
              >
                <LogOut className="w-3.5 h-3.5" />
                Disconnect
              </button>
            ) : (
              <button
                onClick={handleConnect}
                disabled={loading}
                className="px-4 py-2.5 bg-[#4285F4] hover:bg-[#357ae8] text-white rounded-lg text-xs font-bold transition flex items-center justify-center gap-2 cursor-pointer shadow-lg shadow-blue-900/30 disabled:opacity-50 shrink-0"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : (
                  <svg className="w-4 h-4 bg-white rounded p-0.5" viewBox="0 0 48 48">
                    <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"></path>
                    <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"></path>
                    <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"></path>
                    <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"></path>
                  </svg>
                )}
                Sign in with Google
              </button>
            )}
          </div>

          {/* Google Drive Storage Status & Limits */}
          {user && accessToken && (
            <div className="bg-[#141414] border border-white/10 p-5 rounded-xl space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <HardDrive className="w-4 h-4 text-amber-400" />
                  <span className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                    Google Drive Storage Status & Limits
                  </span>
                </div>
                <button
                  onClick={handleFetchQuota}
                  disabled={fetchingQuota}
                  className="p-1 text-white/50 hover:text-white hover:bg-white/10 rounded transition cursor-pointer"
                  title="Refresh space limits"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${fetchingQuota ? 'animate-spin text-amber-400' : ''}`} />
                </button>
              </div>

              {fetchingQuota && !quota ? (
                <div className="flex items-center gap-2 text-xs text-white/50 py-2">
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-amber-400" />
                  <span>Retrieving cloud limit status...</span>
                </div>
              ) : quota ? (
                <div className="space-y-2">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-white/70">Used: <strong className="text-white">{formatBytes(quota.usage)}</strong></span>
                    <span className="text-white/50">Total Limit: <strong className="text-white">{quota.limit > 0 ? formatBytes(quota.limit) : 'Unlimited'}</strong></span>
                  </div>

                  {quota.limit > 0 ? (
                    <div>
                      <div className="w-full bg-white/10 h-2.5 rounded-full overflow-hidden">
                        <div 
                          className="bg-gradient-to-r from-amber-500 to-amber-300 h-full rounded-full transition-all duration-500"
                          style={{ width: `${calculatePercentage(quota.usage, quota.limit)}%` }}
                        />
                      </div>
                      <div className="flex justify-between items-center mt-1.5 text-[10px] text-white/40 font-mono">
                        <span>{calculatePercentage(quota.usage, quota.limit)}% of storage capacity used</span>
                        <span className="text-emerald-400">Secure Cloud Connection Verified</span>
                      </div>
                    </div>
                  ) : (
                    <p className="text-[10px] text-white/40 italic">Google Drive workspace storage limit is unlimited for this corporate session.</p>
                  )}
                </div>
              ) : (
                <div className="text-xs text-red-400 flex items-center gap-1.5">
                  <AlertCircle className="w-3.5 h-3.5" />
                  <span>Failed to retrieve storage limits. Try refreshing or re-linking your account.</span>
                </div>
              )}
            </div>
          )}

          {/* Backup Action Wrapper */}
          <div className="bg-gradient-to-br from-amber-500/10 via-yellow-500/5 to-transparent border border-amber-500/30 p-5 rounded-xl space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="text-sm font-bold text-white tracking-wide">Backup Active Baselines</h4>
                <p className="text-[11px] text-white/60 mt-0.5">Saves all {endpoints.length} scanned endpoint audit records & GPO scores</p>
              </div>
              <ShieldCheck className="w-8 h-8 text-amber-400/60" />
            </div>

            <button
              onClick={handleTriggerBackup}
              disabled={loading || !accessToken}
              className="w-full py-3 bg-gradient-to-r from-amber-500 to-yellow-600 hover:from-amber-600 hover:to-yellow-700 text-black font-extrabold text-xs uppercase tracking-wider rounded-xl shadow-lg shadow-amber-950/40 transition flex items-center justify-center gap-2 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin text-black" /> : <UploadCloud className="w-4 h-4 text-black" />}
              Take Instant Google Drive Backup
            </button>
          </div>

          {/* Backup History & Restore */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-black uppercase tracking-widest text-white/70 font-mono">
                📜 Drive Backup Archive History
              </h4>
              {accessToken && (
                <button
                  onClick={handleListBackups}
                  disabled={fetchingBackups}
                  className="text-[11px] text-amber-400 hover:text-amber-300 flex items-center gap-1 font-mono transition cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`w-3 h-3 ${fetchingBackups ? 'animate-spin' : ''}`} />
                  Refresh List
                </button>
              )}
            </div>

            <div className="bg-black/40 border border-white/10 rounded-xl overflow-hidden divide-y divide-white/5 max-h-48 overflow-y-auto">
              {!accessToken ? (
                <div className="p-8 text-center text-white/40 text-xs font-mono">
                  Sign in with Google above to view saved cloud backups
                </div>
              ) : fetchingBackups ? (
                <div className="p-8 text-center text-white/50 text-xs flex items-center justify-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin text-amber-400" />
                  Searching Google Drive for SmartPro backups...
                </div>
              ) : backups.length === 0 ? (
                <div className="p-8 text-center text-white/40 text-xs font-mono">
                  No previous backup files found in this Google Drive account.
                </div>
              ) : (
                backups.map((file) => (
                  <div key={file.id} className="p-3.5 hover:bg-white/5 transition flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <HardDrive className="w-4 h-4 text-amber-400 shrink-0" />
                      <div className="min-w-0">
                        <p className="text-xs font-medium text-white truncate font-mono">{file.name}</p>
                        <p className="text-[10px] text-white/40">Saved: {new Date(file.createdTime).toLocaleString()}</p>
                      </div>
                    </div>

                    <button
                      onClick={() => handleRestoreFile(file.id, file.name)}
                      disabled={loading}
                      className="px-2.5 py-1.5 bg-white/10 hover:bg-white/20 text-white rounded text-[11px] font-bold transition flex items-center gap-1.5 shrink-0 cursor-pointer disabled:opacity-50"
                      title="Restore configuration from this backup"
                    >
                      <DownloadCloud className="w-3.5 h-3.5 text-amber-400" />
                      Restore
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>

        </div>

        {/* Modal Footer */}
        <div className="bg-black/80 p-4 border-t border-white/10 text-center">
          <p className="text-[11px] text-white/40 font-mono">
            🔒 Uses OAuth 2.0 Scope: `https://www.googleapis.com/auth/drive.file` (Restricted access to app-created files only).
          </p>
        </div>

      </div>
    </div>
  );
}
