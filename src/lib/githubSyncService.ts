// SmartPro SecOps - GitHub Live Sync & Direct Upload Service

export interface GitHubSyncConfig {
  token: string;
  owner: string;
  repo: string;
  branch: string;
  autoSyncEnabled: boolean;
  autoSyncIntervalMinutes: number; // e.g. 5
  syncTargets: {
    auditScript: boolean;
    dashboardConfig: boolean;
    postureReport: boolean;
    vulnerabilitiesCatalog: boolean;
  };
  lastSyncedAt?: string;
}

export interface SyncHistoryItem {
  id: string;
  timestamp: string;
  fileName: string;
  repo: string;
  branch: string;
  commitSha: string;
  commitUrl: string;
  status: 'SUCCESS' | 'FAILED';
  type: 'COMMIT' | 'GIST';
  message: string;
}

const STORAGE_KEY_CONFIG = 'smartpro_github_config';
const STORAGE_KEY_HISTORY = 'smartpro_github_history';

export const DEFAULT_GITHUB_CONFIG: GitHubSyncConfig = {
  token: '',
  owner: 'SmartPro-SecOps',
  repo: 'endpoint-guard-scripts',
  branch: 'main',
  autoSyncEnabled: false,
  autoSyncIntervalMinutes: 5,
  syncTargets: {
    auditScript: true,
    dashboardConfig: true,
    postureReport: true,
    vulnerabilitiesCatalog: false,
  }
};

export function loadGitHubConfig(): GitHubSyncConfig {
  try {
    const stored = localStorage.getItem(STORAGE_KEY_CONFIG);
    if (stored) {
      return { ...DEFAULT_GITHUB_CONFIG, ...JSON.parse(stored) };
    }
  } catch (e) {
    console.error('Failed to parse GitHub config:', e);
  }
  return DEFAULT_GITHUB_CONFIG;
}

export function saveGitHubConfig(config: GitHubSyncConfig): void {
  try {
    localStorage.setItem(STORAGE_KEY_CONFIG, JSON.stringify(config));
  } catch (e) {
    console.error('Failed to save GitHub config:', e);
  }
}

export function loadSyncHistory(): SyncHistoryItem[] {
  try {
    const stored = localStorage.getItem(STORAGE_KEY_HISTORY);
    if (stored) {
      return JSON.parse(stored);
    }
  } catch (e) {
    console.error('Failed to load sync history:', e);
  }
  return [];
}

export function addSyncHistoryItem(item: Omit<SyncHistoryItem, 'id' | 'timestamp'>): SyncHistoryItem {
  const history = loadSyncHistory();
  const newItem: SyncHistoryItem = {
    ...item,
    id: 'sync_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
    timestamp: new Date().toISOString()
  };
  const updated = [newItem, ...history].slice(0, 20); // Keep last 20 entries
  try {
    localStorage.setItem(STORAGE_KEY_HISTORY, JSON.stringify(updated));
  } catch (e) {
    console.error('Failed to save sync history:', e);
  }
  return newItem;
}

export async function verifyGitHubToken(token: string): Promise<{ valid: boolean; username?: string; avatarUrl?: string; error?: string }> {
  if (!token.trim()) {
    return { valid: false, error: 'Token is empty' };
  }

  try {
    const response = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `Bearer ${token.trim()}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    });

    if (response.ok) {
      const data = await response.json();
      return { valid: true, username: data.login, avatarUrl: data.avatar_url };
    } else {
      const errData = await response.json().catch(() => ({}));
      return { valid: false, error: errData.message || `HTTP ${response.status}: Unauthorized` };
    }
  } catch (err: any) {
    return { valid: false, error: err.message || 'Network connection failed' };
  }
}

export async function commitFileToGitHub(params: {
  token: string;
  owner: string;
  repo: string;
  branch?: string;
  filePath: string;
  content: string;
  commitMessage: string;
}): Promise<{ success: boolean; commitSha?: string; htmlUrl?: string; error?: string }> {
  const { token, owner, repo, branch = 'main', filePath, content, commitMessage } = params;

  if (!token.trim()) {
    // If no token provided, create simulated commit response for offline/preview usability
    const mockSha = Math.random().toString(36).substring(2, 12) + Math.random().toString(36).substring(2, 10);
    const mockUrl = `https://github.com/${owner}/${repo}/blob/${branch}/${filePath}`;
    
    addSyncHistoryItem({
      fileName: filePath,
      repo: `${owner}/${repo}`,
      branch,
      commitSha: mockSha.substring(0, 7),
      commitUrl: mockUrl,
      status: 'SUCCESS',
      type: 'COMMIT',
      message: `${commitMessage} (Offline Preview Simulated)`
    });

    return {
      success: true,
      commitSha: mockSha.substring(0, 7),
      htmlUrl: mockUrl
    };
  }

  const cleanPath = filePath.startsWith('/') ? filePath.slice(1) : filePath;
  const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${cleanPath}`;

  try {
    // Check if file already exists to get SHA
    let existingSha: string | undefined = undefined;
    const getRes = await fetch(`${apiUrl}?ref=${branch}`, {
      headers: {
        'Authorization': `Bearer ${token.trim()}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    });

    if (getRes.ok) {
      const existingData = await getRes.json();
      existingSha = existingData.sha;
    }

    // Base64 encode content handling UTF-8 properly
    const base64Content = btoa(unescape(encodeURIComponent(content)));

    const body: any = {
      message: commitMessage,
      content: base64Content,
      branch: branch
    };

    if (existingSha) {
      body.sha = existingSha;
    }

    const putRes = await fetch(apiUrl, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${token.trim()}`,
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });

    if (putRes.ok) {
      const result = await putRes.json();
      const commitSha = result.commit?.sha ? result.commit.sha.substring(0, 7) : 'head';
      const htmlUrl = result.content?.html_url || `https://github.com/${owner}/${repo}/blob/${branch}/${cleanPath}`;

      addSyncHistoryItem({
        fileName: cleanPath,
        repo: `${owner}/${repo}`,
        branch,
        commitSha,
        commitUrl: htmlUrl,
        status: 'SUCCESS',
        type: 'COMMIT',
        message: commitMessage
      });

      return { success: true, commitSha, htmlUrl };
    } else {
      const errJson = await putRes.json().catch(() => ({}));
      const errorMsg = errJson.message || `HTTP ${putRes.status} Error updating repository`;

      addSyncHistoryItem({
        fileName: cleanPath,
        repo: `${owner}/${repo}`,
        branch,
        commitSha: 'failed',
        commitUrl: '#',
        status: 'FAILED',
        type: 'COMMIT',
        message: errorMsg
      });

      return { success: false, error: errorMsg };
    }
  } catch (err: any) {
    return { success: false, error: err.message || 'Failed to communicate with GitHub API' };
  }
}

export async function createGitHubGist(params: {
  token: string;
  description: string;
  filename: string;
  content: string;
  isPublic?: boolean;
}): Promise<{ success: boolean; gistUrl?: string; rawUrl?: string; error?: string }> {
  const { token, description, filename, content, isPublic = false } = params;

  if (!token.trim()) {
    const mockGistId = Math.random().toString(36).substring(2, 12);
    const mockGistUrl = `https://gist.github.com/smartpro-secops/${mockGistId}`;
    
    addSyncHistoryItem({
      fileName: filename,
      repo: 'GitHub Gist',
      branch: 'gist',
      commitSha: mockGistId.substring(0, 7),
      commitUrl: mockGistUrl,
      status: 'SUCCESS',
      type: 'GIST',
      message: `${description} (Simulated Gist)`
    });

    return {
      success: true,
      gistUrl: mockGistUrl,
      rawUrl: `${mockGistUrl}/raw/${filename}`
    };
  }

  try {
    const res = await fetch('https://api.github.com/gists', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token.trim()}`,
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        description: description,
        public: isPublic,
        files: {
          [filename]: {
            content: content
          }
        }
      })
    });

    if (res.ok) {
      const data = await res.json();
      const gistUrl = data.html_url;
      const rawUrl = data.files[filename]?.raw_url || gistUrl;

      addSyncHistoryItem({
        fileName: filename,
        repo: 'GitHub Gist',
        branch: isPublic ? 'public' : 'secret',
        commitSha: data.id ? data.id.substring(0, 7) : 'gist',
        commitUrl: gistUrl,
        status: 'SUCCESS',
        type: 'GIST',
        message: description
      });

      return { success: true, gistUrl, rawUrl };
    } else {
      const err = await res.json().catch(() => ({}));
      return { success: false, error: err.message || 'Failed to create Gist' };
    }
  } catch (err: any) {
    return { success: false, error: err.message || 'Gist creation error' };
  }
}
