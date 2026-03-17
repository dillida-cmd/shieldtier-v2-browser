import React, { useState, useEffect, useCallback } from 'react';
import { Button } from '../ui/button';
import { SettingsCard } from './SettingsCard';
import type { UpdateState } from '../../types';

export function AboutSection() {
  const [updateState, setUpdateState] = useState<UpdateState>({
    status: 'idle',
    currentVersion: '0.0.0',
    availableVersion: null,
    downloadProgress: 0,
    error: null,
  });

  useEffect(() => {
    window.shieldtier.update.getState().then(setUpdateState).catch(() => {});
    const unsub = window.shieldtier.update.onStatus(setUpdateState);
    return unsub;
  }, []);

  const handleCheck = useCallback(() => {
    window.shieldtier.update.check().catch(() => {});
  }, []);

  const handleDownload = useCallback(() => {
    window.shieldtier.update.download().catch(() => {});
  }, []);

  const handleInstall = useCallback(() => {
    window.shieldtier.update.install().catch(() => {});
  }, []);

  return (
    <div className="space-y-4">
      <div className="mb-2">
        <h2 className="text-base font-semibold text-[color:var(--st-text-primary)]">About</h2>
        <p className="text-xs text-[color:var(--st-text-muted)] mt-1">ShieldTier version and information.</p>
      </div>

      {/* ── Card 1: Hero ── */}
      <SettingsCard title="">
        <div className="flex flex-col items-center text-center py-4">
          {/* Shield Logo SVG with gradient */}
          <div className="mb-4">
            <svg width="64" height="64" viewBox="0 0 64 64" fill="none">
              <defs>
                <linearGradient id="shield-grad" x1="16" y1="8" x2="48" y2="56" gradientUnits="userSpaceOnUse">
                  <stop stopColor="var(--st-accent, #3b82f6)" />
                  <stop offset="0.5" stopColor="var(--st-accent-secondary, #8b5cf6)" />
                  <stop offset="1" stopColor="var(--st-accent-tertiary, #06b6d4)" />
                </linearGradient>
              </defs>
              <path
                d="M32 4L8 16v16c0 14.4 10.2 27.2 24 30 13.8-2.8 24-15.6 24-30V16L32 4z"
                stroke="url(#shield-grad)"
                strokeWidth="2.5"
                fill="none"
              />
              <path
                d="M32 14L14 22v10c0 10.8 7.6 20.4 18 22.5 10.4-2.1 18-11.7 18-22.5V22L32 14z"
                fill="url(#shield-grad)"
                opacity="0.15"
              />
              <path
                d="M24 32l5 5 11-11"
                stroke="url(#shield-grad)"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </div>

          <h1 className="text-2xl font-bold text-gradient-brand mb-1">ShieldTier&#8482;</h1>
          <p className="text-xs text-[color:var(--st-text-muted)] mb-4">
            Version {updateState.currentVersion}
          </p>

          {/* Update Controls */}
          <div className="mb-4 flex flex-col items-center gap-2 min-h-[40px]">
            {updateState.status === 'idle' || updateState.status === 'not-available' ? (
              <Button variant="outline" size="sm" onClick={handleCheck}>
                Check for Updates
              </Button>
            ) : updateState.status === 'checking' ? (
              <div className="flex items-center gap-2 text-xs text-[color:var(--st-text-muted)]">
                <svg className="animate-spin h-3.5 w-3.5" viewBox="0 0 24 24" fill="none">
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" opacity="0.25" />
                  <path d="M12 2a10 10 0 019.95 9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
                </svg>
                Checking for updates...
              </div>
            ) : updateState.status === 'available' ? (
              <div className="flex flex-col items-center gap-2">
                <p className="text-xs text-blue-400">
                  v{updateState.availableVersion} available
                </p>
                <Button size="sm" onClick={handleDownload}>
                  Download Update
                </Button>
              </div>
            ) : updateState.status === 'downloading' ? (
              <div className="flex flex-col items-center gap-2 w-full max-w-xs">
                <p className="text-xs text-[color:var(--st-text-muted)]">
                  Downloading... {updateState.downloadProgress}%
                </p>
                <div
                  className="w-full h-1.5 bg-white/10 rounded-full overflow-hidden"
                  role="progressbar"
                  aria-valuenow={updateState.downloadProgress}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-label="Update download progress"
                >
                  <div
                    className="h-full bg-[color:var(--st-accent)] rounded-full transition-all duration-300"
                    style={{ width: `${updateState.downloadProgress}%` }}
                  />
                </div>
              </div>
            ) : updateState.status === 'downloaded' ? (
              <div className="flex flex-col items-center gap-2">
                <p className="text-xs text-emerald-400">Update ready to install</p>
                <Button size="sm" onClick={handleInstall}>
                  Restart &amp; Update
                </Button>
              </div>
            ) : updateState.status === 'error' ? (
              <div className="flex flex-col items-center gap-2">
                <p className="text-xs text-red-400 max-w-xs truncate">
                  {updateState.error}
                </p>
                <Button variant="outline" size="sm" onClick={handleCheck}>
                  Retry
                </Button>
              </div>
            ) : null}

            {updateState.status === 'not-available' && (
              <p className="text-xs text-emerald-400">You're on the latest version</p>
            )}
          </div>

          <p className="text-sm text-[color:var(--st-text-secondary)] max-w-sm leading-relaxed">
            SOC investigation platform with end-to-end encrypted collaboration.
          </p>
        </div>
      </SettingsCard>

      {/* ── Card 2: Tech Stack ── */}
      <SettingsCard title="Tech Stack">
        <div className="grid grid-cols-2 gap-2 text-xs text-[color:var(--st-text-secondary)]">
          <span>Electron</span>
          <span>React</span>
          <span>TypeScript</span>
          <span>Tailwind CSS</span>
        </div>
        <p className="text-[10px] text-[color:var(--st-text-muted)] opacity-70 leading-relaxed pt-2">
          ShieldTier&#8482; is a trademark. All rights reserved.<br />
          Built for security operations teams.
        </p>
      </SettingsCard>
    </div>
  );
}
