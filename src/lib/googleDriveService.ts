import { initializeApp, getApps } from 'firebase/app';
import { getAuth, signInWithPopup, GoogleAuthProvider, signOut, User } from 'firebase/auth';
import firebaseConfig from '../../firebase-applet-config.json';

// Initialize Firebase App singleton
const app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApps()[0];
export const auth = getAuth(app);

const driveScope = 'https://www.googleapis.com/auth/drive.file';

let cachedAccessToken: string | null = null;

export async function connectGoogleDrive(): Promise<{ user: User; accessToken: string }> {
  const provider = new GoogleAuthProvider();
  provider.addScope(driveScope);
  provider.setCustomParameters({ prompt: 'consent select_account' });

  const result = await signInWithPopup(auth, provider);
  const credential = GoogleAuthProvider.credentialFromResult(result);
  
  if (!credential || !credential.accessToken) {
    throw new Error('Could not retrieve access token from Google Auth Provider.');
  }

  cachedAccessToken = credential.accessToken;
  return { user: result.user, accessToken: cachedAccessToken };
}

export function getCachedToken(): string | null {
  return cachedAccessToken;
}

export async function disconnectGoogleDrive(): Promise<void> {
  await signOut(auth);
  cachedAccessToken = null;
}

export interface DriveBackupFile {
  id: string;
  name: string;
  createdTime: string;
}

export async function backupPosturesToDrive(accessToken: string, endpointsData: any): Promise<{ id: string; name: string; webViewLink?: string }> {
  const fileName = `SmartPro_Security_Postures_Backup_${new Date().toISOString().slice(0, 10)}.json`;
  const fileContent = JSON.stringify({
    version: '2.4',
    timestamp: new Date().toISOString(),
    generator: 'SmartPro Endpoint Guard Enterprise Suite',
    endpointsCount: endpointsData.length,
    endpoints: endpointsData
  }, null, 2);

  const metadata = {
    name: fileName,
    mimeType: 'application/json',
    description: 'Enterprise Security Hardening Posture Configuration Backup'
  };

  const boundary = '-------314159265358979323846';
  const delimiter = "\r\n--" + boundary + "\r\n";
  const close_delim = "\r\n--" + boundary + "--";

  const multipartBody =
    delimiter +
    'Content-Type: application/json; charset=UTF-8\r\n\r\n' +
    JSON.stringify(metadata) +
    delimiter +
    'Content-Type: application/json\r\n\r\n' +
    fileContent +
    close_delim;

  const response = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,webViewLink', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': `multipart/related; boundary=${boundary}`
    },
    body: multipartBody
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Google Drive API Upload failed (${response.status}): ${errorText}`);
  }

  return await response.json();
}

export async function listDriveBackups(accessToken: string): Promise<DriveBackupFile[]> {
  const query = encodeURIComponent('name contains "SmartPro_Security_Postures_Backup" and trashed = false');
  const response = await fetch(`https://www.googleapis.com/drive/v3/files?q=${query}&orderBy=createdTime desc&fields=files(id,name,createdTime)`, {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });

  if (!response.ok) {
    throw new Error(`Failed to list backups: ${response.statusText}`);
  }

  const data = await response.json();
  return data.files || [];
}

export async function restoreFromDriveBackup(accessToken: string, fileId: string): Promise<any> {
  const response = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`, {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });

  if (!response.ok) {
    throw new Error(`Failed to restore backup file content: ${response.statusText}`);
  }

  return await response.json();
}

export interface StorageQuota {
  limit: number;
  usage: number;
}

export async function getDriveStorageQuota(accessToken: string): Promise<StorageQuota> {
  const response = await fetch('https://www.googleapis.com/drive/v3/about?fields=storageQuota', {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });

  if (!response.ok) {
    throw new Error(`Failed to retrieve storage quota: ${response.statusText}`);
  }

  const data = await response.json();
  return {
    limit: data.storageQuota?.limit ? parseInt(data.storageQuota.limit, 10) : 0,
    usage: data.storageQuota?.usage ? parseInt(data.storageQuota.usage, 10) : 0
  };
}
