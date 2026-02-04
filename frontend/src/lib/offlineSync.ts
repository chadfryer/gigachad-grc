/**
 * Offline Sync Manager
 * Handles offline data caching and background sync using localStorage
 */

// ===========================================
// Types
// ===========================================

interface PendingAction {
  id: string;
  type: 'create' | 'update' | 'delete';
  entity: string;
  data: unknown;
  timestamp: number;
  retryCount: number;
}

interface CachedData {
  key: string;
  data: unknown;
  timestamp: number;
  expiresAt: number;
}

// Storage keys
const PENDING_ACTIONS_KEY = 'grc-offline-pending-actions';
const CACHED_DATA_PREFIX = 'grc-offline-cache-';

// ===========================================
// Pending Actions
// ===========================================

function getStoredActions(): PendingAction[] {
  try {
    const stored = localStorage.getItem(PENDING_ACTIONS_KEY);
    return stored ? JSON.parse(stored) : [];
  } catch {
    return [];
  }
}

function saveActions(actions: PendingAction[]): void {
  try {
    localStorage.setItem(PENDING_ACTIONS_KEY, JSON.stringify(actions));
  } catch (error) {
    console.error('Failed to save actions to localStorage:', error);
  }
}

export function queueAction(type: PendingAction['type'], entity: string, data: unknown): string {
  const id = `${entity}-${Date.now()}-${crypto.randomUUID().split('-')[0]}`;

  const action: PendingAction = {
    id,
    type,
    entity,
    data,
    timestamp: Date.now(),
    retryCount: 0,
  };

  const actions = getStoredActions();
  actions.push(action);
  saveActions(actions);

  // Request background sync if available
  if ('serviceWorker' in navigator && 'sync' in (ServiceWorkerRegistration.prototype as object)) {
    navigator.serviceWorker.ready.then((registration) => {
      (
        registration as ServiceWorkerRegistration & {
          sync?: { register: (tag: string) => Promise<void> };
        }
      ).sync?.register('sync-pending-actions');
    });
  }

  return id;
}

export function getPendingActions(entity?: string): PendingAction[] {
  const actions = getStoredActions();

  if (entity) {
    return actions.filter((a) => a.entity === entity);
  }

  return actions;
}

export function removePendingAction(id: string): void {
  const actions = getStoredActions();
  const filtered = actions.filter((a) => a.id !== id);
  saveActions(filtered);
}

export function clearPendingActions(): void {
  saveActions([]);
}

export function retryPendingAction(id: string): void {
  const actions = getStoredActions();
  const action = actions.find((a) => a.id === id);

  if (action) {
    action.retryCount += 1;
    saveActions(actions);
  }
}

// ===========================================
// Data Caching
// ===========================================

const DEFAULT_CACHE_TTL = 30 * 60 * 1000; // 30 minutes

export function cacheData(key: string, data: unknown, ttl: number = DEFAULT_CACHE_TTL): void {
  const now = Date.now();
  const cacheKey = CACHED_DATA_PREFIX + key;

  const cached: CachedData = {
    key,
    data,
    timestamp: now,
    expiresAt: now + ttl,
  };

  try {
    localStorage.setItem(cacheKey, JSON.stringify(cached));
  } catch (error) {
    console.error('Failed to cache data:', error);
    // Try to make room by cleaning expired cache
    cleanExpiredCache();
  }
}

export function getCachedData<T>(key: string): T | null {
  const cacheKey = CACHED_DATA_PREFIX + key;

  try {
    const stored = localStorage.getItem(cacheKey);
    if (!stored) return null;

    const cached: CachedData = JSON.parse(stored);

    // Check if expired
    if (cached.expiresAt < Date.now()) {
      localStorage.removeItem(cacheKey);
      return null;
    }

    return cached.data as T;
  } catch {
    return null;
  }
}

export function invalidateCache(keyPattern?: string): void {
  if (!keyPattern) {
    // Clear all cache
    const keys = Object.keys(localStorage).filter((k) => k.startsWith(CACHED_DATA_PREFIX));
    keys.forEach((k) => localStorage.removeItem(k));
    return;
  }

  // Clear matching keys
  const keys = Object.keys(localStorage).filter(
    (k) => k.startsWith(CACHED_DATA_PREFIX) && k.includes(keyPattern)
  );
  keys.forEach((k) => localStorage.removeItem(k));
}

export function cleanExpiredCache(): number {
  const now = Date.now();
  let cleaned = 0;

  const keys = Object.keys(localStorage).filter((k) => k.startsWith(CACHED_DATA_PREFIX));

  for (const key of keys) {
    try {
      const stored = localStorage.getItem(key);
      if (stored) {
        const cached: CachedData = JSON.parse(stored);
        if (cached.expiresAt < now) {
          localStorage.removeItem(key);
          cleaned++;
        }
      }
    } catch {
      // Remove invalid entries
      localStorage.removeItem(key);
      cleaned++;
    }
  }

  return cleaned;
}

// ===========================================
// Sync Manager
// ===========================================

type SyncHandler = (action: PendingAction) => Promise<boolean>;
const syncHandlers: Map<string, SyncHandler> = new Map();

export function registerSyncHandler(entity: string, handler: SyncHandler): void {
  syncHandlers.set(entity, handler);
}

export async function syncPendingActions(): Promise<{
  synced: number;
  failed: number;
  remaining: number;
}> {
  const actions = getPendingActions();
  let synced = 0;
  let failed = 0;

  for (const action of actions) {
    const handler = syncHandlers.get(action.entity);

    if (!handler) {
      continue;
    }

    try {
      const success = await handler(action);

      if (success) {
        removePendingAction(action.id);
        synced++;
      } else {
        retryPendingAction(action.id);
        failed++;
      }
    } catch {
      retryPendingAction(action.id);
      failed++;
    }
  }

  const remaining = getPendingActions().length;

  return { synced, failed, remaining };
}

// ===========================================
// Online/Offline Detection
// ===========================================

let isOnline = typeof navigator !== 'undefined' ? navigator.onLine : true;
const onlineCallbacks: Set<(online: boolean) => void> = new Set();

export function getOnlineStatus(): boolean {
  return isOnline;
}

export function onOnlineStatusChange(callback: (online: boolean) => void): () => void {
  onlineCallbacks.add(callback);
  return () => onlineCallbacks.delete(callback);
}

// Initialize online/offline listeners
if (typeof window !== 'undefined') {
  window.addEventListener('online', async () => {
    isOnline = true;
    onlineCallbacks.forEach((cb) => cb(true));

    // Auto-sync when coming back online
    await syncPendingActions();
  });

  window.addEventListener('offline', () => {
    isOnline = false;
    onlineCallbacks.forEach((cb) => cb(false));
  });
}

// ===========================================
// Storage Stats
// ===========================================

export function getStorageStats(): {
  pendingActions: number;
  cachedItems: number;
  estimatedSize: string;
} {
  const pendingCount = getPendingActions().length;
  const cachedKeys = Object.keys(localStorage).filter((k) => k.startsWith(CACHED_DATA_PREFIX));

  // Estimate storage used
  let totalSize = 0;
  for (const key of Object.keys(localStorage)) {
    const value = localStorage.getItem(key);
    if (value) {
      totalSize += key.length + value.length;
    }
  }

  const kb = totalSize / 1024;
  const estimatedSize = kb < 1024 ? `${kb.toFixed(1)} KB` : `${(kb / 1024).toFixed(2)} MB`;

  return {
    pendingActions: pendingCount,
    cachedItems: cachedKeys.length,
    estimatedSize,
  };
}

// ===========================================
// Export
// ===========================================

export default {
  queueAction,
  getPendingActions,
  removePendingAction,
  clearPendingActions,
  cacheData,
  getCachedData,
  invalidateCache,
  cleanExpiredCache,
  registerSyncHandler,
  syncPendingActions,
  getOnlineStatus,
  onOnlineStatusChange,
  getStorageStats,
};
