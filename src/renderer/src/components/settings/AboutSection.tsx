import React, { useState, useEffect, useCallback } from 'react';
import { Button } from '../ui/button';
import { SettingsCard } from './SettingsCard';
import type { UpdateState } from '../../types';

interface AppInfo {
  version: string;
  buildDate: string;
  platform: string;
  arch: string;
  engine: string;
  website: string;
  support: string;
  github: string;
}

export function AboutSection() {
  const [updateState, setUpdateState] = useState<UpdateState>({
    status: 'idle',
    currentVersion: '2.0.0',
    availableVersion: null,
    downloadProgress: 0,
    error: null,
  });

  const [appInfo, setAppInfo] = useState<AppInfo | null>(null);

  // Feedback form state
  const [fbType, setFbType] = useState<'bug' | 'feature' | 'general'>('general');
  const [fbMessage, setFbMessage] = useState('');
  const [fbEmail, setFbEmail] = useState('');
  const [fbRating, setFbRating] = useState(0);
  const [fbSubmitting, setFbSubmitting] = useState(false);
  const [fbResult, setFbResult] = useState<'success' | 'error' | null>(null);

  useEffect(() => {
    // Load app info
    if ((window.shieldtier as any).getAppInfo) {
      (window.shieldtier as any).getAppInfo().then((info: AppInfo) => {
        if (info) setAppInfo(info);
      }).catch(() => {});
    }

    // Load update state
    window.shieldtier.update.getState().then((s: UpdateState) => {
      if (s) setUpdateState(s);
    }).catch(() => {});
    const unsub = window.shieldtier.update.onStatus(setUpdateState);
    return unsub;
  }, []);

  const handleCheck = useCallback(() => {
    setUpdateState(prev => ({ ...prev, status: 'checking' }));
    window.shieldtier.update.check().then((s: UpdateState) => {
      if (s) setUpdateState(s);
    }).catch(() => {
      setUpdateState(prev => ({ ...prev, status: 'error', error: 'Could not reach update server' }));
    });
  }, []);

  const handleDownload = useCallback(() => {
    window.shieldtier.update.download().catch(() => {});
  }, []);

  const handleInstall = useCallback(() => {
    window.shieldtier.update.install().catch(() => {});
  }, []);

  const handleFeedbackSubmit = useCallback(async () => {
    if (!fbMessage.trim()) return;
    setFbSubmitting(true);
    setFbResult(null);
    try {
      await (window.shieldtier as any).submitFeedback(fbType, fbMessage, fbEmail, fbRating);
      setFbResult('success');
      setFbMessage('');
      setFbRating(0);
    } catch {
      setFbResult('error');
    }
    setFbSubmitting(false);
  }, [fbType, fbMessage, fbEmail, fbRating]);

  return (
    <div className="space-y-4">
      <div className="mb-2">
        <h2 className="text-base font-semibold text-[color:var(--st-text-primary)]">About</h2>
        <p className="text-xs text-[color:var(--st-text-muted)] mt-1">Version, updates, and feedback.</p>
      </div>

      {/* ── Hero ── */}
      <SettingsCard title="">
        <div className="flex flex-col items-center text-center py-4">
          <div className="mb-4">
            <svg width="64" height="64" viewBox="0 0 64 64" fill="none">
              <defs>
                <linearGradient id="shield-grad" x1="16" y1="8" x2="48" y2="56" gradientUnits="userSpaceOnUse">
                  <stop stopColor="var(--st-accent, #3b82f6)" />
                  <stop offset="0.5" stopColor="var(--st-accent-secondary, #8b5cf6)" />
                  <stop offset="1" stopColor="var(--st-accent-tertiary, #06b6d4)" />
                </linearGradient>
              </defs>
              <path d="M32 4L8 16v16c0 14.4 10.2 27.2 24 30 13.8-2.8 24-15.6 24-30V16L32 4z" stroke="url(#shield-grad)" strokeWidth="2.5" fill="none" />
              <path d="M32 14L14 22v10c0 10.8 7.6 20.4 18 22.5 10.4-2.1 18-11.7 18-22.5V22L32 14z" fill="url(#shield-grad)" opacity="0.15" />
              <path d="M24 32l5 5 11-11" stroke="url(#shield-grad)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>

          <h1 className="text-2xl font-bold text-gradient-brand mb-1">ShieldTier&#8482;</h1>
          <p className="text-xs text-[color:var(--st-text-muted)] mb-1">
            Version {appInfo?.version || updateState.currentVersion}
          </p>
          {appInfo && (
            <p className="text-[10px] text-[color:var(--st-text-muted)] mb-4">
              {appInfo.platform} {appInfo.arch} &middot; Built {appInfo.buildDate}
            </p>
          )}

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
                <p className="text-xs text-blue-400">v{updateState.availableVersion} available</p>
                <Button size="sm" onClick={handleDownload}>Download Update</Button>
              </div>
            ) : updateState.status === 'downloading' ? (
              <div className="flex flex-col items-center gap-2 w-full max-w-xs">
                <p className="text-xs text-[color:var(--st-text-muted)]">Downloading... {updateState.downloadProgress}%</p>
                <div className="w-full h-1.5 bg-white/10 rounded-full overflow-hidden">
                  <div className="h-full bg-[color:var(--st-accent)] rounded-full transition-all duration-300" style={{ width: `${updateState.downloadProgress}%` }} />
                </div>
              </div>
            ) : updateState.status === 'downloaded' ? (
              <div className="flex flex-col items-center gap-2">
                <p className="text-xs text-emerald-400">Update ready to install</p>
                <Button size="sm" onClick={handleInstall}>Restart &amp; Update</Button>
              </div>
            ) : updateState.status === 'error' ? (
              <div className="flex flex-col items-center gap-2">
                <p className="text-xs text-red-400 max-w-xs truncate">{updateState.error}</p>
                <Button variant="outline" size="sm" onClick={handleCheck}>Retry</Button>
              </div>
            ) : null}

            {updateState.status === 'not-available' && (
              <p className="text-xs text-emerald-400">You're on the latest version</p>
            )}
          </div>

          <p className="text-sm text-[color:var(--st-text-secondary)] max-w-sm leading-relaxed">
            SOC investigation platform with sandboxed browsing, MITRE ATT&CK detection, and end-to-end encrypted collaboration.
          </p>
        </div>
      </SettingsCard>

      {/* ── Feedback ── */}
      <SettingsCard title="Send Feedback">
        <div className="space-y-3">
          {/* Type selector */}
          <div className="flex gap-2">
            {(['general', 'bug', 'feature'] as const).map(t => (
              <button
                key={t}
                onClick={() => setFbType(t)}
                className={`px-3 py-1 rounded-full text-[10px] capitalize transition-colors border ${
                  fbType === t
                    ? 'bg-[color:var(--st-accent-dim)] text-[color:var(--st-text-primary)] border-blue-500/30'
                    : 'text-[color:var(--st-text-muted)] border-transparent hover:text-[color:var(--st-text-secondary)]'
                }`}
              >
                {t === 'bug' ? 'Bug Report' : t === 'feature' ? 'Feature Request' : 'General'}
              </button>
            ))}
          </div>

          {/* Rating */}
          <div className="flex items-center gap-1">
            <span className="text-[10px] text-[color:var(--st-text-muted)] mr-2">Rating:</span>
            {[1, 2, 3, 4, 5].map(star => (
              <button
                key={star}
                onClick={() => setFbRating(star === fbRating ? 0 : star)}
                className="text-lg transition-colors"
              >
                <span className={star <= fbRating ? 'text-yellow-400' : 'text-gray-600'}>
                  {star <= fbRating ? '\u2605' : '\u2606'}
                </span>
              </button>
            ))}
          </div>

          {/* Message */}
          <textarea
            value={fbMessage}
            onChange={e => setFbMessage(e.target.value)}
            placeholder={fbType === 'bug' ? 'Describe the bug, steps to reproduce...' : fbType === 'feature' ? 'Describe the feature you would like...' : 'Your feedback...'}
            className="w-full bg-[color:var(--st-bg-panel)] border border-[color:var(--st-border)] rounded-md px-3 py-2 text-xs text-[color:var(--st-text-primary)] placeholder-[color:var(--st-text-muted)] focus:border-blue-500/50 outline-none resize-none"
            rows={4}
          />

          {/* Email (optional) */}
          <input
            type="email"
            value={fbEmail}
            onChange={e => setFbEmail(e.target.value)}
            placeholder="Your email (optional, for follow-up)"
            className="w-full bg-[color:var(--st-bg-panel)] border border-[color:var(--st-border)] rounded-md px-3 py-1.5 text-xs text-[color:var(--st-text-primary)] placeholder-[color:var(--st-text-muted)] focus:border-blue-500/50 outline-none"
          />

          {/* Submit */}
          <div className="flex items-center gap-3">
            <Button
              size="sm"
              onClick={handleFeedbackSubmit}
              disabled={fbSubmitting || !fbMessage.trim()}
            >
              {fbSubmitting ? 'Submitting...' : 'Submit Feedback'}
            </Button>
            {fbResult === 'success' && (
              <span className="text-xs text-emerald-400">Thank you for your feedback!</span>
            )}
            {fbResult === 'error' && (
              <span className="text-xs text-red-400">Failed to submit. Please try again.</span>
            )}
          </div>
        </div>
      </SettingsCard>

      {/* ── Links ── */}
      <SettingsCard title="Resources">
        <div className="space-y-2 text-xs">
          <div className="flex justify-between">
            <span className="text-[color:var(--st-text-muted)]">Website</span>
            <span className="text-blue-400">{appInfo?.website || 'https://socbrowser.com'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-[color:var(--st-text-muted)]">Support</span>
            <span className="text-blue-400">{appInfo?.support || 'support@socbrowser.com'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-[color:var(--st-text-muted)]">GitHub</span>
            <span className="text-blue-400">{appInfo?.github || 'github.com/dillida/shieldtier-v2-browser'}</span>
          </div>
        </div>
      </SettingsCard>

      {/* ── Tech Stack ── */}
      <SettingsCard title="Tech Stack">
        <div className="grid grid-cols-2 gap-2 text-xs text-[color:var(--st-text-secondary)]">
          <span>CEF (Chromium)</span>
          <span>React 19</span>
          <span>C++ / TypeScript</span>
          <span>Tailwind CSS 4</span>
        </div>
        <p className="text-[10px] text-[color:var(--st-text-muted)] opacity-70 leading-relaxed pt-2">
          ShieldTier&#8482; is a trademark. All rights reserved.<br />
          Built for security operations teams.
        </p>
      </SettingsCard>
    </div>
  );
}
