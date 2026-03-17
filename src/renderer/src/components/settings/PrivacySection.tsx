import React, { useState } from 'react';
import { cn } from '../../lib/utils';

const inputClass = 'w-full h-9 bg-[color:var(--st-bg-base)] border border-[color:var(--st-border)] rounded-xl px-3 text-[13px] text-[color:var(--st-text-primary)] placeholder:text-[color:var(--st-text-muted)] outline-none focus:border-[color:var(--st-accent)] focus:shadow-[0_0_0_3px_var(--st-accent-glow)] transition-all duration-200';

export function PrivacySection() {
  // Sync
  const [syncKey, setSyncKey] = useState('');
  const [showSyncKey, setShowSyncKey] = useState(false);
  const [syncSaving, setSyncSaving] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const handleSetSyncKey = async () => {
    if (!syncKey.trim()) return;
    setSyncSaving(true);
    setSyncMsg(null);
    try {
      const result = await window.shieldtier.auth.setSyncKey(syncKey.trim());
      setSyncMsg(result.success
        ? { type: 'success', text: 'Sync key saved.' }
        : { type: 'error', text: result.error || 'Failed.' });
    } catch (err: any) {
      setSyncMsg({ type: 'error', text: err.message || 'Failed.' });
    }
    setSyncSaving(false);
  };

  const handleSyncNow = async () => {
    setSyncing(true);
    setSyncMsg(null);
    try {
      const result = await window.shieldtier.auth.syncCases([]);
      setSyncMsg(result.success
        ? { type: 'success', text: 'Sync complete.' }
        : { type: 'error', text: result.error || 'Sync failed.' });
    } catch (err: any) {
      setSyncMsg({ type: 'error', text: err.message || 'Sync failed.' });
    }
    setSyncing(false);
  };

  return (
    <div className="space-y-5">
      {/* Section header */}
      <div>
        <h2 className="text-[15px] font-semibold text-[color:var(--st-text-primary)]">Privacy & Security</h2>
        <p className="text-[11px] text-[color:var(--st-text-muted)] mt-0.5">Encryption and data sync management.</p>
      </div>

      {/* Unified surface */}
      <div className="rounded-2xl border border-[color:var(--st-border)] bg-[color:var(--st-bg-elevated)] overflow-hidden">

        {/* Section: Encrypted Sync */}
        <div className="px-6 py-5 space-y-4">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className="text-[color:var(--st-text-muted)] shrink-0">
                <path d="M8 1v3M8 12v3M1 8h3M12 8h3M3 3l2 2M11 11l2 2M13 3l-2 2M5 11l-2 2" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
              </svg>
              <label className="text-[11px] font-medium text-[color:var(--st-text-muted)] uppercase tracking-wider">Encrypted Sync</label>
            </div>
            <p className="text-[11px] text-[color:var(--st-text-muted)] ml-[28px] leading-relaxed">
              Your sync key encrypts case data with XChaCha20-Poly1305 before uploading. Without this key, synced data cannot be decrypted.
            </p>
          </div>

          <div>
            <label htmlFor="sync-key" className="text-[11px] text-[color:var(--st-text-muted)] block mb-1">Sync Key</label>
            <div className="relative">
              <input
                id="sync-key"
                type={showSyncKey ? 'text' : 'password'}
                value={syncKey}
                onChange={e => setSyncKey(e.target.value)}
                placeholder="Enter your sync encryption key"
                className={cn(inputClass, 'pr-10 font-mono')}
              />
              <button
                type="button"
                onClick={() => setShowSyncKey(!showSyncKey)}
                aria-pressed={showSyncKey}
                title={showSyncKey ? 'Hide' : 'Show'}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 w-6 h-6 rounded-lg flex items-center justify-center text-[color:var(--st-text-muted)] hover:text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] transition-colors cursor-pointer"
              >
                {showSyncKey ? (
                  <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                    <path d="M2 2l12 12" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
                    <path d="M6.5 6.5a2 2 0 002.8 2.8" stroke="currentColor" strokeWidth="1.2" />
                    <path d="M1 8s2.5-5 7-5c1.2 0 2.3.3 3.2.8" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
                    <path d="M15 8s-2.5 5-7 5c-1.2 0-2.3-.3-3.2-.8" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
                  </svg>
                ) : (
                  <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                    <ellipse cx="8" cy="8" rx="7" ry="5" stroke="currentColor" strokeWidth="1.2" />
                    <circle cx="8" cy="8" r="2" stroke="currentColor" strokeWidth="1.2" />
                  </svg>
                )}
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleSetSyncKey}
              disabled={syncSaving || !syncKey.trim()}
              className={cn(
                'h-8 px-4 rounded-xl text-[12px] font-medium transition-all duration-200 cursor-pointer',
                syncKey.trim()
                  ? 'bg-[color:var(--st-accent)] text-white hover:brightness-110 shadow-[0_0_12px_var(--st-accent-glow)]'
                  : 'bg-[color:var(--st-bg-base)] text-[color:var(--st-text-muted)] border border-[color:var(--st-border)] opacity-50 cursor-not-allowed'
              )}
            >
              {syncSaving ? 'Saving\u2026' : 'Set Key'}
            </button>
            <button
              type="button"
              onClick={handleSyncNow}
              disabled={syncing}
              className="h-8 px-4 rounded-xl text-[12px] font-medium border border-[color:var(--st-border)] text-[color:var(--st-text-secondary)] hover:bg-[color:var(--st-border-subtle)] hover:text-[color:var(--st-text-primary)] disabled:opacity-40 transition-all duration-200 cursor-pointer"
            >
              {syncing ? 'Syncing\u2026' : 'Sync Now'}
            </button>
            {syncMsg && (
              <span className={cn('text-[11px] ml-1', syncMsg.type === 'success' ? 'text-[color:var(--st-success)]' : 'text-[color:var(--st-danger)]')}>
                {syncMsg.text}
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
